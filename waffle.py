#!/usr/bin/env python3
"""
██╗    ██╗ █████╗ ███████╗███████╗██╗     ███████╗
██║    ██║██╔══██╗██╔════╝██╔════╝██║     ██╔════╝
██║ █╗ ██║███████║█████╗  █████╗  ██║     █████╗
██║███╗██║██╔══██║██╔══╝  ██╔══╝  ██║     ██╔══╝
╚███╔███╔╝██║  ██║██║     ██║     ███████╗███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚══════╝

WAFFLE - Web Access Filter & Firewall for Local Environments
v1.4.0 — full type annotations | openssl-first cert backend

Cert generation strategy (inspired by starter code approach):
  1. openssl CLI — always available on Linux/macOS, zero pip deps
  2. cryptography — used as fallback if openssl not on PATH
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import logging
import logging.handlers
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional

# ── Version & App identity ────────────────────────────────────────────────────

__version__: str = "1.4.0"
APP_NAME: str    = "WAFFLE"

# ── File paths ────────────────────────────────────────────────────────────────

CONFIG_DIR:   Path = Path.home() / ".config" / "waffle"
CONFIG_PATH:  Path = CONFIG_DIR / "waffle.conf"
PID_FILE:     Path = CONFIG_DIR / "waffle.pid"
LOG_FILE:     Path = CONFIG_DIR / "waffle.log"
CERTS_DIR:    Path = CONFIG_DIR / "certs"
CA_CERT_PATH: Path = CONFIG_DIR / "ca.crt"
CA_KEY_PATH:  Path = CONFIG_DIR / "ca.key"
CA_CSR_PATH:  Path = CONFIG_DIR / "ca.csr"     # openssl intermediate

# ── Network constants ─────────────────────────────────────────────────────────

PROXY_HOST:   str = "127.0.0.1"
PROXY_PORT:   int = 8080
BUFFER_SIZE:  int = 65536   # 64 KB per read/write
TIMEOUT_S:    int = 15      # upstream TCP connect timeout (seconds)
PIPE_TIMEOUT: int = 120     # idle bidirectional pipe timeout (seconds)

# ── Block-page HTML & pre-built HTTP response ─────────────────────────────────

BLOCKED_HTML: bytes = (
    b"<html><head><title>Blocked by WAFFLE</title>"
    b"<style>"
    b"*{box-sizing:border-box;margin:0;padding:0}"
    b"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    b"background:#0f0f1a;display:flex;align-items:center;justify-content:center;"
    b"min-height:100vh;color:#ccc}"
    b".card{background:#1a1a2e;border:1px solid #e9456022;border-radius:16px;"
    b"padding:48px 56px;text-align:center;max-width:480px;"
    b"box-shadow:0 8px 32px #0008}"
    b".icon{font-size:3.5rem;margin-bottom:16px}"
    b"h1{color:#e94560;font-size:1.6rem;margin-bottom:12px;font-weight:700}"
    b".url{background:#0f0f1a;border-radius:8px;padding:10px 16px;"
    b"font-size:.85rem;color:#888;margin:16px 0;word-break:break-all;"
    b"border:1px solid #333}"
    b"p{color:#888;font-size:.9rem;line-height:1.6}"
    b".brand{margin-top:28px;font-size:.75rem;color:#444;letter-spacing:.05em}"
    b".brand span{color:#e94560}"
    b"</style></head>"
    b"<body><div class='card'>"
    b"<div class='icon'>&#x1F9C7;</div>"
    b"<h1>Access Blocked</h1>"
    b"<div class='url' id='u'></div>"
    b"<p>This site is on your WAFFLE blocklist.</p>"
    b"<div class='brand'><span>WAFFLE</span> &mdash; "
    b"Web Access Filter &amp; Firewall</div>"
    b"</div>"
    b"<script>document.getElementById('u').textContent=location.href</script>"
    b"</body></html>"
)

BLOCKED_RESPONSE: bytes = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: " + str(len(BLOCKED_HTML)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n"
    + BLOCKED_HTML
)

# ── ANSI colour helpers ───────────────────────────────────────────────────────

def _c(code: str, text: str) -> str:
    """Wrap text in an ANSI escape code, only when stdout is a TTY."""
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

# Colour callables — each takes a str and returns a (possibly coloured) str
RED    = lambda t: _c("91", t)   # noqa: E731
GREEN  = lambda t: _c("92", t)   # noqa: E731
YELLOW = lambda t: _c("93", t)   # noqa: E731
CYAN   = lambda t: _c("96", t)   # noqa: E731
BOLD   = lambda t: _c("1",  t)   # noqa: E731
DIM    = lambda t: _c("2",  t)   # noqa: E731

# ── URL normalisation helpers ─────────────────────────────────────────────────

def _normalize(url: str) -> str:
    """
    Lower-case scheme+host and strip trailing slash.

    Example:
        "HTTPS://Example.COM/path/" -> "https://example.com/path"
    """
    url    = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme and parsed.netloc:
        url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
        if parsed.query:
            url += "?" + parsed.query
    return url.rstrip("/")


def _toggle_www(url: str) -> Optional[str]:
    """
    Return the www-toggled variant of a URL, or None if netloc is absent.

    Examples:
        "https://example.com"     -> "https://www.example.com"
        "https://www.example.com" -> "https://example.com"
    """
    parsed: urllib.parse.ParseResult = urllib.parse.urlparse(url)
    if not parsed.netloc:
        return None
    host: str     = parsed.netloc.lower()
    new_host: str = host[4:] if host.startswith("www.") else "www." + host
    return urllib.parse.urlunparse(parsed._replace(netloc=new_host)).rstrip("/")


# ── URL Trie ──────────────────────────────────────────────────────────────────

class _TrieNode:
    """
    Single character node in the URL prefix trie.
    Uses __slots__ for minimal memory footprint.
    """
    __slots__ = ("children", "is_end")

    def __init__(self) -> None:
        self.children: dict[str, _TrieNode] = {}
        self.is_end:   bool                 = False


class URLTrie:
    """
    Prefix trie for O(k) URL matching (k = URL length).

    Blocking is prefix-based:  inserting "https://example.com" blocks
    any URL that starts with that string, including all subpaths.
    Automatically checks both www. and non-www. variants.
    """

    def __init__(self) -> None:
        self._root:  _TrieNode = _TrieNode()
        self._count: int       = 0

    # ── public interface ──────────────────────────────────────────────────

    def insert(self, url: str) -> None:
        """Insert a URL prefix into the trie. Normalises before inserting."""
        url  = _normalize(url)
        node = self._root
        for ch in url:
            if ch not in node.children:
                node.children[ch] = _TrieNode()
            node = node.children[ch]
        if not node.is_end:
            node.is_end  = True
            self._count += 1

    def remove(self, url: str) -> bool:
        """Remove a URL prefix. Returns True if it existed and was removed."""
        return self._delete(self._root, _normalize(url), depth=0)

    def is_blocked(self, url: str) -> bool:
        """
        Return True if url (or its www/non-www counterpart) matches any
        stored prefix.
        """
        return self._check(url) or bool(
            (alt := _toggle_www(url)) and self._check(alt)
        )

    @property
    def count(self) -> int:
        """Number of distinct URL prefixes currently stored."""
        return self._count

    # ── internal helpers ──────────────────────────────────────────────────

    def _check(self, url: str) -> bool:
        """Raw prefix check — no www toggling."""
        url  = _normalize(url)
        node = self._root
        for ch in url:
            if node.is_end:              # stored prefix is shorter -> match
                return True
            if ch not in node.children:
                return False
            node = node.children[ch]
        return node.is_end               # exact-length match

    def _delete(self, node: _TrieNode, url: str, depth: int) -> bool:
        """Recursive deletion with dead-branch pruning."""
        if depth == len(url):
            if not node.is_end:
                return False
            node.is_end  = False
            self._count -= 1
            return True
        ch: str = url[depth]
        if ch not in node.children:
            return False
        deleted: bool = self._delete(node.children[ch], url, depth + 1)
        # Prune empty leaf nodes to keep memory compact
        if deleted \
                and not node.children[ch].children \
                and not node.children[ch].is_end:
            del node.children[ch]
        return deleted


# ── Config I/O ────────────────────────────────────────────────────────────────

def load_urls() -> list[str]:
    """
    Read blocklist from CONFIG_PATH.
    Skips blank lines, comment lines (#), and non-http(s) entries.
    """
    if not CONFIG_PATH.exists():
        return []
    lines: list[str] = CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    return [
        ln.strip() for ln in lines
        if ln.strip()
        and ln.strip().startswith(("http://", "https://"))
        and not ln.strip().startswith("#")
    ]


def save_urls(urls: list[str]) -> None:
    """Deduplicate, normalise, sort and write urls to CONFIG_PATH."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    unique: list[str] = sorted(set(_normalize(u) for u in urls if u.strip()))
    CONFIG_PATH.write_text(
        "\n".join(unique) + ("\n" if unique else ""),
        encoding="utf-8",
    )


def build_trie(urls: list[str]) -> URLTrie:
    """Build a fresh URLTrie from a list of URL strings."""
    trie: URLTrie = URLTrie()
    for url in urls:
        trie.insert(url)
    return trie


# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Initialise the 'waffle' logger with:
      - Rotating file handler (2 MB × 3 backups)
      - Console handler (INFO+ only)
    Safe to call multiple times — handlers are only added once.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("waffle")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        fh: logging.Handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)

        ch: logging.Handler = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(ch)

    return logger


# ── SSL / CA helpers ──────────────────────────────────────────────────────────

def _ca_available() -> bool:
    """Return True when both the CA cert and key files exist on disk."""
    return CA_CERT_PATH.exists() and CA_KEY_PATH.exists()


def _openssl_available() -> bool:
    """Return True when the openssl binary is reachable on PATH."""
    return shutil.which("openssl") is not None


# In-memory host-cert cache: hostname -> ssl.SSLContext
# Avoids regenerating certs on every request for the same host.
_cert_cache: dict[str, ssl.SSLContext] = {}


# ── CA generation — openssl-first, cryptography fallback ─────────────────────

def _generate_ca_openssl() -> None:
    """
    Generate CA cert + key using the system openssl CLI.
    Inspired by the starter-code approach of shelling out to openssl.

    openssl is preferred because:
      - Available on every Linux/macOS system
      - No pip dependencies
      - Battle-tested key generation
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    print(DIM("  Using openssl CLI to generate CA…"))

    # Step 1 — generate 2048-bit RSA private key
    _run_openssl([
        "genrsa", "-out", str(CA_KEY_PATH), "2048",
    ], "CA key generation")
    CA_KEY_PATH.chmod(0o600)

    # Write an explicit openssl config so the v3_ca extensions are always
    # applied regardless of the system openssl.cnf.
    # Chrome/NSS requires subjectKeyIdentifier + authorityKeyIdentifier.
    ca_cfg: Path = CONFIG_DIR / "waffle_ca.cfg"
    ca_cfg.write_text(
        "[req]\ndistinguished_name = req_dn\n"
        "[req_dn]\n"
        "[v3_ca]\n"
        "basicConstraints       = critical,CA:TRUE\n"
        "subjectKeyIdentifier   = hash\n"
        "authorityKeyIdentifier = keyid:always,issuer\n"
        "keyUsage               = critical,keyCertSign,cRLSign\n",
        encoding="utf-8",
    )

    # Step 2 — self-sign a CA certificate (10-year validity)
    _run_openssl([
        "req", "-new", "-x509",
        "-key",        str(CA_KEY_PATH),
        "-out",        str(CA_CERT_PATH),
        "-days",       "3650",
        "-subj",       "/CN=WAFFLE Local CA/O=WAFFLE/OU=Local Filter",
        "-config",     str(ca_cfg),
        "-extensions", "v3_ca",
    ], "CA cert self-sign")


def _generate_ca_cryptography() -> None:
    """
    Fallback CA generation using the 'cryptography' pip package.
    Used when openssl is not on PATH.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print(RED("  ✖  Neither openssl nor 'cryptography' are available."))
        print(DIM("     Install one:  sudo pacman -S openssl"))
        print(DIM("                   pip install cryptography"))
        sys.exit(1)

    print(DIM("  Using cryptography library to generate CA…"))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "WAFFLE Local CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WAFFLE"),
    ])

    # Chrome/NSS requires subjectKeyIdentifier + authorityKeyIdentifier on CAs
    pub = key.public_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,  key_cert_sign=True,  crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False,  key_agreement=False,
                encipher_only=False,      decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pub), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CA_KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    CA_KEY_PATH.chmod(0o600)
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def cmd_generate_ca() -> None:
    """CLI command: generate a local CA cert + key."""
    if CA_CERT_PATH.exists():
        ans: str = input("  CA already exists. Overwrite? [y/N]  ").strip().lower()
        if ans not in ("y", "yes"):
            print(DIM("  Cancelled."))
            return

    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    # Prefer openssl CLI (inspired by starter code), fall back to cryptography
    if _openssl_available():
        _generate_ca_openssl()
    else:
        _generate_ca_cryptography()

    print(GREEN("  ✔  CA certificate generated"))
    print(DIM(f"     Cert : {CA_CERT_PATH}"))
    print(DIM(f"     Key  : {CA_KEY_PATH}"))
    print()
    print(YELLOW("  Next: install the CA in Chrome"))
    print(f"  Run:  {CYAN('python waffle.py --install-ca')}")
    print(f"  Or:   {CYAN('chrome://settings/certificates')}")
    print(f"        Authorities → Import → {CA_CERT_PATH}")
    print(f"        ✅ Trust for identifying websites → OK")
    print()


# ── Per-host cert generation (SSL bump) ──────────────────────────────────────

def _generate_host_cert_openssl(hostname: str, pem_path: Path) -> None:
    """
    Generate a host certificate signed by the WAFFLE CA using openssl CLI.

    Writes combined cert+key PEM to pem_path.
    Covers both bare hostname and www. variant via SAN.
    """
    key_path: Path = pem_path.with_suffix(".key")
    csr_path: Path = pem_path.with_suffix(".csr")
    crt_path: Path = pem_path.with_suffix(".crt")
    ext_path: Path = pem_path.with_suffix(".ext")

    # Generate host key
    _run_openssl(["genrsa", "-out", str(key_path), "2048"], "host key")
    key_path.chmod(0o600)

    # Generate CSR
    _run_openssl([
        "req", "-new",
        "-key",  str(key_path),
        "-out",  str(csr_path),
        "-subj", f"/CN={hostname}",
    ], "CSR")

    # Build SAN extension file — cover both www. and bare hostname
    www_variant: str = hostname[4:] if hostname.startswith("www.") else "www." + hostname
    ext_path.write_text(
        "[SAN]\n"
        f"subjectAltName=DNS:{hostname},DNS:{www_variant}\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
        encoding="utf-8",
    )

    # Sign with CA
    _run_openssl([
        "x509", "-req",
        "-in",       str(csr_path),
        "-CA",       str(CA_CERT_PATH),
        "-CAkey",    str(CA_KEY_PATH),
        "-CAcreateserial",
        "-out",      str(crt_path),
        "-days",     "397",
        "-extfile",  str(ext_path),
        "-extensions", "SAN",
    ], "host cert signing")

    # Combine cert + key into single PEM (what ssl.SSLContext expects)
    pem_path.write_bytes(
        crt_path.read_bytes() + key_path.read_bytes()
    )
    pem_path.chmod(0o600)

    # Clean up intermediates
    for tmp in (key_path, csr_path, crt_path, ext_path):
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _generate_host_cert_cryptography(hostname: str, pem_path: Path) -> None:
    """
    Fallback host cert generation via the cryptography library.
    Used when openssl CLI is not available.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509.oid import NameOID

    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    ca_key  = load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)

    www_variant: str = hostname[4:] if hostname.startswith("www.") else "www." + hostname
    san: list[x509.GeneralName] = [
        x509.DNSName(hostname),
        x509.DNSName(www_variant),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname)
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=60))
        .not_valid_after(now + datetime.timedelta(days=397))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    pem_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    pem_path.chmod(0o600)


def _get_ssl_ctx(hostname: str) -> ssl.SSLContext:
    """
    Return a server-side SSLContext for hostname, generating and caching a
    fake certificate on first call.

    Certificate is signed by the WAFFLE CA — trusted by Chrome after
    running --generate-ca + --install-ca.
    """
    if hostname in _cert_cache:
        return _cert_cache[hostname]

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name: str = hostname.replace("*", "_wildcard_")
    pem_path:  Path = CERTS_DIR / f"{safe_name}.pem"

    if not pem_path.exists():
        if _openssl_available():
            _generate_host_cert_openssl(hostname, pem_path)
        else:
            _generate_host_cert_cryptography(hostname, pem_path)

    ctx: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pem_path))
    _cert_cache[hostname] = ctx
    return ctx


def _run_openssl(args: list[str], step: str = "") -> None:
    """
    Execute an openssl sub-command, raising RuntimeError on failure.

    Args:
        args:  Argument list (without the 'openssl' binary itself).
        step:  Human-readable step name for error messages.
    """
    result: subprocess.CompletedProcess[str] = subprocess.run(
        ["openssl"] + args,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl {step} failed:\n{result.stderr.strip()}"
        )


# ── CA install helpers ────────────────────────────────────────────────────────

def cmd_install_ca() -> None:
    """CLI command: install the WAFFLE CA into Chrome's NSS store and system trust."""
    if not CA_CERT_PATH.exists():
        print(RED("  ✖  No CA cert found. Run: python waffle.py --generate-ca"))
        sys.exit(1)

    installed: bool = False
    certutil: Optional[str] = shutil.which("certutil")

    # ── 1. Chrome / Chromium NSS stores via certutil ──────────────────────────
    if certutil:
        nss_candidates: list[Path] = [
            Path.home() / ".config" / "google-chrome" / "Default",
            Path.home() / ".config" / "chromium" / "Default",
            Path.home() / ".pki" / "nssdb",
        ]
        chrome_root: Path = Path.home() / ".config" / "google-chrome"
        if chrome_root.exists():
            for entry in chrome_root.iterdir():
                if entry.is_dir() and (entry / "cert9.db").exists():
                    nss_candidates.append(entry)

        seen: set[str] = set()
        nss_dirs: list[Path] = []
        for p in nss_candidates:
            key: str = str(p)
            if key not in seen:
                seen.add(key)
                nss_dirs.append(p)

        for nss_dir in nss_dirs:
            if not nss_dir.exists():
                continue
            prefix: str = "sql:" if (nss_dir / "cert9.db").exists() else "dbm:"
            # Remove any stale copy first so re-installs are clean
            subprocess.run(
                [certutil, "-D", "-d", f"{prefix}{nss_dir}", "-n", "WAFFLE Local CA"],
                capture_output=True, text=True,
            )
            result: subprocess.CompletedProcess[str] = subprocess.run(
                [
                    certutil, "-A",
                    "-d", f"{prefix}{nss_dir}",
                    "-n", "WAFFLE Local CA",
                    "-t", "CT,,",
                    "-i", str(CA_CERT_PATH),
                ],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(GREEN(f"  ✔  Installed → {nss_dir}"))
                installed = True
            else:
                print(DIM(f"     skip  → {nss_dir}  ({result.stderr.strip()})"))
    else:
        print(YELLOW("  !  certutil not found — install it:  sudo apt install libnss3-tools"))
        print(YELLOW("                                   or:  sudo pacman -S nss"))

    # ── 2. System-wide trust store (makes curl, wget, and other apps work too) ─
    update_ca: Optional[str] = shutil.which("update-ca-certificates")
    if update_ca:
        sys_dest: Path = Path("/usr/local/share/ca-certificates/waffle-local-ca.crt")
        try:
            import shutil as _sh
            _sh.copy2(str(CA_CERT_PATH), str(sys_dest))
            subprocess.run([update_ca], capture_output=True, check=False)
            print(GREEN("  ✔  Installed to system trust store (/usr/local/share/ca-certificates/)"))
            installed = True
        except PermissionError:
            print(YELLOW(
                f"  !  To install system-wide (curl, wget, etc.) run as root:\n"
                f"     sudo cp {CA_CERT_PATH} {sys_dest}\n"
                f"     sudo update-ca-certificates"
            ))

    # ── 3. Always print the manual Chrome fallback ────────────────────────────
    if not installed:
        print()
    print(BOLD("  Manual Chrome install (always works):"))
    print(f"  1.  Open  {CYAN('chrome://settings/certificates')}")
    print(f"  2.  Authorities  →  Import")
    print(f"  3.  Select: {CYAN(str(CA_CERT_PATH))}")
    print(f"  4.  ✅ Trust for identifying websites  →  OK")
    print(f"  5.  Restart Chrome fully (Ctrl+Q, then reopen)")
    print()
    print(DIM("  Tip: after installing, restart Chrome and revisit the blocked site."))
    print(DIM(f"  Verify with:  python waffle.py --check-ca"))
    print()


# ── Async proxy core ──────────────────────────────────────────────────────────

class WaffleProxy:
    """
    Asyncio-based HTTP/HTTPS forward proxy.

    HTTP  → parse Host + path → block (403) or forward to origin.
    HTTPS → CONNECT method:
        blocked + CA present  → SSL bump  → serve block page over TLS.
        blocked + no CA       → send 403  → browser shows error page.
        allowed               → TCP tunnel → transparent passthrough.
    """

    def __init__(
        self,
        host:     str,
        port:     int,
        trie:     URLTrie,
        logger:   logging.Logger,
        ssl_bump: bool = False,
    ) -> None:
        self.host:     str            = host
        self.port:     int            = port
        self.trie:     URLTrie        = trie
        self.log:      logging.Logger = logger
        self.ssl_bump: bool           = ssl_bump

    # ── connection entry point ────────────────────────────────────────────

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Dispatch an incoming connection to the correct handler."""
        try:
            first: bytes = await asyncio.wait_for(
                reader.readline(), timeout=TIMEOUT_S
            )
            if not first:
                return

            line:   str       = first.decode("utf-8", errors="replace").strip()
            parts:  list[str] = line.split(" ", 2)
            if len(parts) < 2:
                return

            method: str = parts[0].upper()
            target: str = parts[1]

            if method == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_http(reader, writer, method, target, first)

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            self.log.debug(f"handler error: {exc}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── HTTPS CONNECT ─────────────────────────────────────────────────────

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
    ) -> None:
        """
        Handle a CONNECT tunnel request.

        Blocked + SSL bump  → intercept TLS, serve block page.
        Blocked + no bump   → 403 immediately, zero upstream bandwidth.
        Allowed             → open upstream TCP, relay bytes both ways.
        """
        await _drain_headers(reader)

        host: str
        port: int
        host, port = _split_host_port(target, default_port=443)
        host_lower: str  = host.lower()
        # Block regardless of which scheme the entry was saved with —
        # CONNECT is always HTTPS, but a user may have typed http:// when adding.
        if self.trie.is_blocked(f"https://{host_lower}") \
                or self.trie.is_blocked(f"http://{host_lower}"):
            self.log.info(f"  BLOCKED  CONNECT  {target}")
            if self.ssl_bump:
                await self._ssl_bump_block(writer, host)
            else:
                writer.write(BLOCKED_RESPONSE)
                await writer.drain()
            return

        # ── allowed — tunnel to upstream ──────────────────────────────────
        try:
            up_r: asyncio.StreamReader
            up_w: asyncio.StreamWriter
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TIMEOUT_S
            )
        except Exception as exc:
            self.log.debug(f"  FAILED CONNECT {target}: {exc}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        self.log.debug(f"  TUNNEL  CONNECT  {target}")

        try:
            await asyncio.gather(
                _pipe(reader, up_w, PIPE_TIMEOUT),
                _pipe(up_r,  writer, PIPE_TIMEOUT),
                return_exceptions=True,
            )
        finally:
            # Only close the upstream connection here.
            # writer (client <-> WAFFLE) is closed by handle()'s finally block,
            # which keeps the client connection alive long enough for Chrome to
            # issue a second request (refresh) without getting a connection reset.
            try:
                up_w.close()
            except Exception:
                pass

    # ── SSL interception ──────────────────────────────────────────────────

    async def _ssl_bump_block(
        self,
        writer:   asyncio.StreamWriter,
        hostname: str,
    ) -> None:
        """
        Intercept a blocked HTTPS connection and serve the WAFFLE block page:

          1. Confirm tunnel (200) so the client proceeds with TLS.
          2. Dup the raw socket before closing asyncio transport.
          3. TLS handshake (server-side) using a dynamically-signed fake cert.
          4. Drain the client's inner HTTP request.
          5. Write BLOCKED_RESPONSE over TLS → browser shows the block page.

        Inspired by the starter code's concept of wrapping the socket with
        ssl.wrap_socket() — we do the same idea but async and per-hostname.
        """
        # Step 1 — open tunnel
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Step 2 — dup socket so closing the asyncio writer doesn't kill it
        raw_sock: Optional[socket.socket] = writer.get_extra_info("socket")
        if raw_sock is None:
            return
        raw_sock = raw_sock.dup()
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass

        # Step 3 — get (or generate) a fake cert SSLContext for this hostname
        try:
            ctx: ssl.SSLContext = _get_ssl_ctx(hostname)
        except Exception as exc:
            self.log.debug(f"  SSL cert gen failed {hostname}: {exc}")
            raw_sock.close()
            return

        # Step 4 — TLS handshake server-side
        try:
            ssl_r: asyncio.StreamReader
            ssl_w: asyncio.StreamWriter
            ssl_r, ssl_w = await asyncio.wait_for(
                asyncio.open_connection(
                    sock=raw_sock,
                    ssl=ctx,
                    server_side=True,
                    server_hostname=None,
                ),
                timeout=TIMEOUT_S,
            )
        except Exception as exc:
            self.log.debug(f"  SSL handshake failed {hostname}: {exc}")
            raw_sock.close()
            return

        # Step 5 — drain the browser's inner HTTP request then serve block page
        try:
            await asyncio.wait_for(_drain_request(ssl_r), timeout=TIMEOUT_S)
        except Exception:
            pass

        try:
            ssl_w.write(BLOCKED_RESPONSE)
            await ssl_w.drain()
        except Exception:
            pass
        finally:
            try:
                ssl_w.close()
                await asyncio.wait_for(ssl_w.wait_closed(), timeout=2)
            except Exception:
                pass

    # ── plain HTTP ────────────────────────────────────────────────────────

    async def _handle_http(
        self,
        reader:     asyncio.StreamReader,
        writer:     asyncio.StreamWriter,
        method:     str,
        target:     str,
        first_line: bytes,
    ) -> None:
        """Forward or block a plain HTTP request."""
        headers:  list[bytes]    = []
        host_hdr: Optional[str]  = None

        try:
            async for raw_line in _iter_headers(reader):
                headers.append(raw_line)
                key: bytes
                val: bytes
                key, _, val = raw_line.partition(b":")
                if key.strip().lower() == b"host":
                    host_hdr = val.strip().decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            writer.write(
                b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return

        host: str
        port: int
        path: str

        if target.lower().startswith("http://"):
            parsed: urllib.parse.ParseResult = urllib.parse.urlparse(target)
            host = parsed.hostname or host_hdr or ""
            port = parsed.port or 80
            path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        else:
            if not host_hdr:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            host, port = _split_host_port(host_hdr, default_port=80)
            path = target

        _h:  str = f"http://{host.lower()}"
        _hs: str = f"https://{host.lower()}"
        if (self.trie.is_blocked(_h)  or self.trie.is_blocked(f"{_h}{path}")
                or self.trie.is_blocked(_hs) or self.trie.is_blocked(f"{_hs}{path}")):
            self.log.info(f"  BLOCKED  {method:7s}  http://{host}{path}")
            writer.write(BLOCKED_RESPONSE)
            await writer.drain()
            return

        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TIMEOUT_S
            )
        except Exception as exc:
            self.log.debug(f"  FAILED {method} http://{host}{path}: {exc}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        self.log.debug(f"  ALLOW   {method:7s}  http://{host}{path}")
        up_w.write(
            f"{method} {path} HTTP/1.1\r\n".encode()
            + _filter_proxy_headers(headers)
            + b"\r\n"
        )
        await up_w.drain()

        try:
            await asyncio.gather(
                _pipe(reader, up_w, PIPE_TIMEOUT),
                _pipe(up_r,  writer, PIPE_TIMEOUT),
                return_exceptions=True,
            )
        finally:
            for w in (up_w, writer):
                try:
                    w.close()
                except Exception:
                    pass

    # ── server lifecycle ──────────────────────────────────────────────────

    async def run(self) -> None:
        """Start the asyncio TCP server and serve until cancelled."""
        server: asyncio.Server = await asyncio.start_server(
            self.handle, self.host, self.port, limit=BUFFER_SIZE,
        )
        addr: tuple[str, int] = server.sockets[0].getsockname()
        self.log.info(
            f"WAFFLE proxy active  →  {addr[0]}:{addr[1]}"
            + (" [SSL bump ON]" if self.ssl_bump else "")
        )
        async with server:
            await server.serve_forever()


# ── Async I/O helpers ─────────────────────────────────────────────────────────

async def _drain_headers(reader: asyncio.StreamReader) -> None:
    """Read and discard HTTP headers until the blank line."""
    while True:
        line: bytes = await asyncio.wait_for(reader.readline(), timeout=TIMEOUT_S)
        if line in (b"\r\n", b"\n", b""):
            break


async def _drain_request(reader: asyncio.StreamReader) -> None:
    """Drain a full HTTP request: request-line + headers."""
    try:
        await asyncio.wait_for(reader.readline(), timeout=TIMEOUT_S)
    except Exception:
        return
    await _drain_headers(reader)


async def _iter_headers(reader: asyncio.StreamReader):
    """Async generator — yield HTTP header lines until the blank line."""
    while True:
        line: bytes = await asyncio.wait_for(reader.readline(), timeout=TIMEOUT_S)
        if line in (b"\r\n", b"\n", b"") or not line:
            return
        yield line


async def _pipe(
    reader:  asyncio.StreamReader,
    writer:  asyncio.StreamWriter,
    timeout: float,
) -> None:
    """
    Forward raw bytes from reader → writer until EOF or timeout.

    On EOF from reader, sends a half-close (write_eof) to writer so the
    remote end knows this direction is done — but does NOT close the writer.
    This lets the other direction of a bidirectional tunnel finish cleanly
    before the caller tears everything down, preventing Chrome connection-reset
    on page refresh.
    """
    try:
        while True:
            data: bytes = await asyncio.wait_for(
                reader.read(BUFFER_SIZE), timeout=timeout
            )
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        # Half-close only — signal EOF to the remote without destroying the
        # socket. The tunnel caller closes both ends after gather() returns.
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    """
    Split a 'host:port' string into (host, port).
    Returns (target, default_port) if no colon is present or port is invalid.
    """
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return target, default_port


def _filter_proxy_headers(headers: list[bytes]) -> bytes:
    """
    Remove Proxy-* headers and rewrite Proxy-Connection → Connection.
    Prevents proxy credentials leaking to upstream servers.
    """
    out: bytearray = bytearray()
    for h in headers:
        key: bytes
        val: bytes
        key, _, val = h.partition(b":")
        k: bytes = key.strip().lower()
        if k == b"proxy-connection":
            out += b"Connection:" + val + (b"\r\n" if not val.endswith(b"\r\n") else b"")
        elif k.startswith(b"proxy-"):
            continue          # drop Proxy-Authorization etc.
        else:
            out += h if h.endswith(b"\r\n") else h + b"\r\n"
    return bytes(out)


# ── PID / process management ──────────────────────────────────────────────────

def _read_pid() -> Optional[int]:
    """Read the daemon PID from PID_FILE, or return None on failure."""
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def _write_pid(pid: int) -> None:
    """Write pid to PID_FILE, creating parent directories as needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(pid))


def _clear_pid() -> None:
    """Delete PID_FILE if it exists."""
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def _is_running(pid: Optional[int]) -> bool:
    """
    Return True if a process with the given PID exists.
    Uses signal 0 (existence check) — no signal is actually sent.
    """
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _port_in_use(port: int) -> bool:
    """Return True if PROXY_HOST:port is already bound by another process."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((PROXY_HOST, port))
            return False
        except OSError:
            return True


# ── System proxy configuration ────────────────────────────────────────────────

def _set_system_proxy(enable: bool) -> None:
    """Configure (or clear) the OS-level HTTP proxy setting."""
    h: str = PROXY_HOST
    p: str = str(PROXY_PORT)
    if sys.platform == "darwin":
        _macos_proxy(enable, h, p)
    else:
        _linux_proxy_env(enable, h, p)


def _macos_proxy(enable: bool, host: str, port: str) -> None:
    """Set/unset proxy via macOS networksetup CLI."""
    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True,
        )
        services: list[str] = [
            ln.strip() for ln in result.stdout.splitlines()
            if ln.strip() and not ln.startswith("*") and "asterisk" not in ln
        ]
        for svc in services:
            if enable:
                subprocess.run(["networksetup", "-setwebproxy",            svc, host, port], check=False)
                subprocess.run(["networksetup", "-setsecurewebproxy",      svc, host, port], check=False)
                subprocess.run(["networksetup", "-setwebproxystate",       svc, "on"],        check=False)
                subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "on"],        check=False)
            else:
                subprocess.run(["networksetup", "-setwebproxystate",       svc, "off"],       check=False)
                subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"],       check=False)
    except FileNotFoundError:
        pass


def _detect_shell() -> str:
    """
    Heuristic shell detection: checks FISH_VERSION env var, then
    /proc/<ppid>/comm, then $SHELL. Returns 'fish', 'zsh', 'bash', or 'sh'.
    """
    if os.environ.get("FISH_VERSION"):
        return "fish"
    try:
        comm: str = Path(f"/proc/{os.getppid()}/comm").read_text().strip()
        for name in ("fish", "zsh", "bash"):
            if name in comm:
                return name
    except Exception:
        pass
    for name in ("fish", "zsh", "bash"):
        if name in os.environ.get("SHELL", ""):
            return name
    return "sh"


def _write_fish_env_file(enable: bool, host: str, port: str) -> Path:
    """
    Write (or overwrite) ~/.config/waffle/waffle.fish with fish-syntax
    set/unset commands for proxy env vars.
    Returns the path of the written file.
    """
    fish_file: Path = CONFIG_DIR / "waffle.fish"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    proxy_url: str = f"http://{host}:{port}"
    vars_: tuple[str, ...] = (
        "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"
    )
    if enable:
        fish_file.write_text(
            "# WAFFLE proxy environment — source to activate\n"
            + "\n".join(f"set -x {v} {proxy_url}" for v in vars_)
            + "\n",
            encoding="utf-8",
        )
    else:
        fish_file.write_text(
            "# WAFFLE proxy cleared\n"
            + "\n".join(f"set -e {v}" for v in vars_)
            + "\n",
            encoding="utf-8",
        )
    return fish_file


def _gsettings_set(key: str, *args: str) -> bool:
    """Run a single gsettings set/set call. Returns True on success."""
    result = subprocess.run(
        ["gsettings", "set", "org.gnome.system.proxy", key, *args],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def _linux_proxy_env(enable: bool, host: str, port: str) -> None:
    """
    Set or clear the system proxy.

    Strategy (in order):
      1. gsettings  — works on GNOME/Ubuntu/Pop!_OS; Chrome, Firefox, curl all
                      respect it immediately without a shell restart.
      2. env-var fallback — print export/unset commands the user can paste,
                      and write a sourceable file for scripting.
    """
    gsettings: Optional[str] = shutil.which("gsettings")

    if gsettings:
        if enable:
            # Set mode to manual + configure http + https proxy
            _gsettings_set("mode", "'manual'")
            _gsettings_set("org.gnome.system.proxy.http",  "host", f"'{host}'")
            _gsettings_set("org.gnome.system.proxy.http",  "port", port)
            _gsettings_set("org.gnome.system.proxy.https", "host", f"'{host}'")
            _gsettings_set("org.gnome.system.proxy.https", "port", port)
            # gsettings subkeys use a different schema path
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.http",
                 "host", host], capture_output=True,
            )
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.http",
                 "port", port], capture_output=True,
            )
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.https",
                 "host", host], capture_output=True,
            )
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.https",
                 "port", port], capture_output=True,
            )
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy",
                 "mode", "manual"], capture_output=True,
            )
            print(DIM(f"  System proxy set via gsettings → {host}:{port}"))
        else:
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy",
                 "mode", "none"], capture_output=True,
            )
            print(DIM("  System proxy cleared via gsettings"))
        return

    # ── fallback: no gsettings (non-GNOME desktop) ────────────────────────────
    shell: str     = _detect_shell()
    proxy_url: str = f"http://{host}:{port}"
    vars_: tuple[str, ...] = (
        "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
    )
    if enable:
        if shell == "fish":
            f: Path = _write_fish_env_file(True, host, port)
            print(DIM("\n  # Fish — source this file to activate proxy:"))
            print(CYAN(f"  source {f}"))
        else:
            print(DIM("\n  # Paste into your shell to activate proxy:"))
            for v in vars_:
                print(CYAN(f"  export {v}={proxy_url}"))
        print()
    else:
        if shell == "fish":
            f = _write_fish_env_file(False, host, port)
            print(CYAN(f"\n  source {f}  # clears proxy vars\n"))
        else:
            print(CYAN("\n  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY\n"))


# ── CLI commands ──────────────────────────────────────────────────────────────

def cmd_check_ca() -> None:
    """
    Diagnostic: verify that the WAFFLE CA exists, is structurally valid,
    and appears to be installed in Chrome's NSS store.
    """
    print(f"\n  {BOLD('WAFFLE CA diagnostic')}\n")

    # 1. Files exist?
    cert_ok: bool = CA_CERT_PATH.exists()
    key_ok:  bool = CA_KEY_PATH.exists()
    print(f"  CA cert  : {(GREEN('✔  ' + str(CA_CERT_PATH))) if cert_ok else RED('✖  not found — run --generate-ca')}")
    print(f"  CA key   : {(GREEN('✔  ' + str(CA_KEY_PATH)))  if key_ok  else RED('✖  not found — run --generate-ca')}")

    if not cert_ok:
        print()
        return

    # 2. Decode the cert with openssl text
    openssl: Optional[str] = shutil.which("openssl")
    if openssl:
        r: subprocess.CompletedProcess[str] = subprocess.run(
            [openssl, "x509", "-in", str(CA_CERT_PATH), "-noout",
             "-subject", "-issuer", "-dates", "-ext", "basicConstraints,subjectKeyIdentifier"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            for ln in r.stdout.strip().splitlines():
                print(f"  {DIM(ln.strip())}")
        else:
            print(RED(f"  ✖  openssl could not parse cert: {r.stderr.strip()}"))

    # 3. Check NSS stores
    certutil: Optional[str] = shutil.which("certutil")
    if certutil:
        nss_candidates: list[Path] = [
            Path.home() / ".config" / "google-chrome" / "Default",
            Path.home() / ".config" / "chromium" / "Default",
            Path.home() / ".pki" / "nssdb",
        ]
        chrome_root: Path = Path.home() / ".config" / "google-chrome"
        if chrome_root.exists():
            for entry in chrome_root.iterdir():
                if entry.is_dir() and (entry / "cert9.db").exists():
                    nss_candidates.append(entry)

        print(f"\n  {BOLD('NSS store check')}:")
        any_nss: bool = False
        for nss_dir in nss_candidates:
            if not nss_dir.exists():
                continue
            prefix: str = "sql:" if (nss_dir / "cert9.db").exists() else "dbm:"
            r2: subprocess.CompletedProcess[str] = subprocess.run(
                [certutil, "-L", "-d", f"{prefix}{nss_dir}", "-n", "WAFFLE Local CA"],
                capture_output=True, text=True,
            )
            if r2.returncode == 0:
                print(GREEN(f"  ✔  Trusted in  {nss_dir}"))
                any_nss = True
            else:
                print(YELLOW(f"  ✖  Not found in {nss_dir}"))
        if not any_nss:
            print(RED("\n  CA not installed in any Chrome NSS store."))
            print(DIM("  Run:  python waffle.py --install-ca"))
    else:
        print(YELLOW("\n  certutil not found — cannot verify NSS stores."))
        print(DIM("  Install:  sudo apt install libnss3-tools"))

    print()


def _find_chrome_desktop() -> Optional[Path]:
    """
    Find the Chrome/Chromium .desktop file in common locations.
    Returns the first writable one found, or None.
    """
    candidates: list[Path] = [
        Path.home() / ".local/share/applications/google-chrome.desktop",
        Path.home() / ".local/share/applications/google-chrome-stable.desktop",
        Path.home() / ".local/share/applications/chromium.desktop",
        Path("/usr/share/applications/google-chrome.desktop"),
        Path("/usr/share/applications/google-chrome-stable.desktop"),
        Path("/usr/share/applications/chromium.desktop"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _patch_chrome_desktop(enable: bool) -> None:
    """
    Patch the Chrome .desktop file to add/remove --proxy-server flag.

    On Hyprland and other non-GNOME compositors Chrome ignores gsettings,
    so patching the .desktop Exec= line is the only reliable way to
    inject the proxy flag for every Chrome window.
    """
    PROXY_FLAG: str = f"--proxy-server={PROXY_HOST}:{PROXY_PORT}"

    src: Optional[Path] = _find_chrome_desktop()
    if src is None:
        print(YELLOW("  !  Chrome .desktop file not found — skipping desktop patch"))
        print(DIM(f"     Launch Chrome manually with: google-chrome-stable {PROXY_FLAG}"))
        return

    # If the system file isn't user-writable, copy it to ~/.local first
    dst: Path = Path.home() / ".local/share/applications" / src.name
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        import shutil as _sh
        _sh.copy2(str(src), str(dst))

    lines:   list[str] = dst.read_text(encoding="utf-8").splitlines()
    updated: list[str] = []
    changed: bool      = False

    for line in lines:
        if line.startswith("Exec="):
            if enable:
                if PROXY_FLAG not in line:
                    # Insert flag right after the binary (before any %U/%F args)
                    line = line.replace("Exec=", "Exec=", 1)
                    parts = line.split(" ", 2)
                    # parts[0] = "Exec=binary", parts[1:] = rest
                    binary = parts[0]
                    rest   = " ".join(parts[1:]) if len(parts) > 1 else ""
                    line   = f"{binary} {PROXY_FLAG} {rest}".strip()
                    changed = True
            else:
                if PROXY_FLAG in line:
                    line    = line.replace(f" {PROXY_FLAG}", "").replace(PROXY_FLAG, "")
                    changed = True
        updated.append(line)

    dst.write_text("\n".join(updated) + "\n", encoding="utf-8")

    if changed:
        # Refresh desktop database so the change is picked up immediately
        subprocess.run(
            ["update-desktop-database",
             str(Path.home() / ".local/share/applications")],
            capture_output=True,
        )
        action = "injected into" if enable else "removed from"
        print(DIM(f"  Proxy flag {action} {dst.name}"))
    else:
        state = "already present" if enable else "already absent"
        print(DIM(f"  Proxy flag {state} in {dst.name}"))


def cmd_activate() -> None:
    """Start the WAFFLE proxy daemon in the background."""
    pid: Optional[int] = _read_pid()
    if _is_running(pid):
        print(YELLOW(f"  !  WAFFLE is already running  (PID {pid})"))
        return
    if _port_in_use(PROXY_PORT):
        print(RED(f"  ✖  Port {PROXY_PORT} is already in use."))
        print(DIM(f"     Free it:  fuser -k {PROXY_PORT}/tcp"))
        sys.exit(1)

    ssl_on: bool        = _ca_available()
    script: str         = str(Path(__file__).resolve())
    proc: subprocess.Popen[bytes] = subprocess.Popen(
        [sys.executable, script, "--_daemon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )

    # Wait for daemon to write its own PID (up to 2 s)
    for _ in range(20):
        time.sleep(0.1)
        if PID_FILE.exists():
            break

    child_pid: int = _read_pid() or proc.pid
    ssl_str: str   = (
        GREEN("ON") if ssl_on
        else YELLOW("OFF  (run --generate-ca to enable)")
    )
    print(GREEN(f"  ✔  WAFFLE activated  →  PID {child_pid}  port {PROXY_PORT}"))
    print(f"  SSL bump : {ssl_str}")
    print(DIM(f"  Python   : {sys.executable}"))
    print(DIM(f"  Log      : {LOG_FILE}"))
    _set_system_proxy(True)
    _patch_chrome_desktop(True)


def run_daemon() -> None:
    """
    Hidden daemon entry point — called via subprocess by cmd_activate.
    Writes its own PID, loads config, starts the async proxy event loop.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _write_pid(os.getpid())

    logger: logging.Logger = _setup_logging()
    urls:   list[str]      = load_urls()
    trie:   URLTrie        = build_trie(urls)
    ssl_bump: bool         = _ca_available()
    proxy: WaffleProxy     = WaffleProxy(
        PROXY_HOST, PROXY_PORT, trie, logger, ssl_bump=ssl_bump
    )

    logger.info(
        f"WAFFLE {__version__} daemon started  (PID {os.getpid()})  "
        f"--  {len(urls)} blocked URLs  "
        f"--  SSL bump {'ON' if ssl_bump else 'OFF'}"
    )

    def _sighup(*_: object) -> None:
        """Reload blocklist config on SIGHUP — no restart needed."""
        new_urls: list[str] = load_urls()
        proxy.trie = build_trie(new_urls)
        logger.info(f"Config reloaded -- {len(new_urls)} blocked URLs")

    signal.signal(signal.SIGHUP, _sighup)

    try:
        asyncio.run(proxy.run())
    except Exception as exc:
        logger.error(f"Proxy crashed: {exc}")
    finally:
        _clear_pid()


def cmd_deactivate() -> None:
    """Stop the running WAFFLE proxy daemon."""
    pid: Optional[int] = _read_pid()
    if not _is_running(pid):
        print(YELLOW("  !  WAFFLE is not running"))
        _clear_pid()
        return
    try:
        os.kill(pid, signal.SIGTERM)  # type: ignore[arg-type]
        # Wait up to 5 s for the process to actually exit
        for _ in range(50):
            time.sleep(0.1)
            if not _is_running(pid):
                break
        else:
            # Force kill if it didn't exit cleanly
            try:
                os.kill(pid, signal.SIGKILL)  # type: ignore[arg-type]
            except Exception:
                pass
        _clear_pid()
        _set_system_proxy(False)
        _patch_chrome_desktop(False)
        print(GREEN(f"  ✔  WAFFLE deactivated  (PID {pid} terminated)"))
    except Exception as exc:
        print(RED(f"  ✖  Failed to stop WAFFLE: {exc}"))


def cmd_toggle() -> None:
    """Activate if stopped, deactivate if running."""
    if _is_running(_read_pid()):
        cmd_deactivate()
    else:
        cmd_activate()


def cmd_status() -> None:
    """Print a summary of current WAFFLE state."""
    pid:     Optional[int] = _read_pid()
    running: bool          = _is_running(pid)
    urls:    list[str]     = load_urls()

    print(f"\n  {BOLD('WAFFLE')}  v{__version__}")
    print(
        f"  Status   : {GREEN('● RUNNING') if running else RED('○ STOPPED')}"
        + (f"  (PID {pid})" if running else "")
    )
    print(f"  Proxy    : {CYAN(PROXY_HOST)}:{CYAN(str(PROXY_PORT))}")
    print(
        f"  SSL bump : "
        + (GREEN("✔ enabled") if _ca_available()
           else YELLOW("✖ no CA  (run --generate-ca)"))
    )
    print(f"  Blocked  : {BOLD(str(len(urls)))} URL(s)")
    print(f"  Config   : {DIM(str(CONFIG_PATH))}")
    print(f"  CA cert  : {DIM(str(CA_CERT_PATH))}")
    print(f"  Log      : {DIM(str(LOG_FILE))}\n")


def _coerce_url(raw: str) -> str:
    """
    Turn any user input into a valid https:// URL.

    Examples:
        "example.com"          -> "https://example.com"
        "www.example.com/path" -> "https://www.example.com/path"
        "http://example.com"   -> "http://example.com"   (kept as-is)
        "https://example.com"  -> "https://example.com"  (kept as-is)
    """
    raw = raw.strip().rstrip("/")
    if raw.startswith(("http://", "https://")):
        return raw
    # bare domain / path — prepend https://
    return "https://" + raw


def cmd_add(url: str) -> None:
    """Add a URL to the blocklist (with confirmation prompt)."""
    url  = _coerce_url(url)
    norm: str       = _normalize(url)
    urls: list[str] = load_urls()

    if norm in [_normalize(u) for u in urls]:
        print(YELLOW(f"  !  Already blocked: {url}"))
        return

    ans: str = input(f"  Add to blocklist: {BOLD(url)}?  [Y/n]  ").strip().lower()
    if ans in ("", "y", "yes"):
        urls.append(norm)
        save_urls(urls)
        print(GREEN(f"  ✔  Added: {url}"))
        _reload_proxy()
    else:
        print(DIM("  Cancelled."))


def cmd_remove(url: str) -> None:
    """Remove a URL from the blocklist (with confirmation prompt)."""
    url:  str       = _coerce_url(url)
    urls: list[str] = load_urls()
    norm: str       = _normalize(url)

    if not any(_normalize(u) == norm for u in urls):
        print(YELLOW(f"  !  Not in blocklist: {url}"))
        return

    ans: str = input(
        f"  Remove from blocklist: {BOLD(url)}?  [Y/n]  "
    ).strip().lower()
    if ans in ("", "y", "yes"):
        save_urls([u for u in urls if _normalize(u) != norm])
        print(GREEN(f"  ✔  Removed: {url}"))
        _reload_proxy()
    else:
        print(DIM("  Cancelled."))


def cmd_reload() -> None:
    """
    Gracefully restart the WAFFLE daemon.

    Waits up to 3 seconds for the port to free after deactivating before
    reactivating, avoiding the 'port already in use' race condition that
    occurs when the OS hasn't released the socket yet.
    """
    cmd_deactivate()

    # Wait for the OS to release the port — SIGTERM is async, the socket
    # lingers briefly in TIME_WAIT state before becoming bindable again.
    for _ in range(30):          # up to 3 seconds (30 x 0.1 s)
        time.sleep(0.1)
        if not _port_in_use(PROXY_PORT):
            break
    else:
        print(YELLOW(f"  !  Port {PROXY_PORT} still busy after 3 s — trying anyway"))

    cmd_activate()


def cmd_list() -> None:
    """Print all blocked URLs to stdout."""
    urls: list[str] = load_urls()
    if not urls:
        print(DIM("  Blocklist is empty."))
        return
    print(f"\n  {BOLD('Blocked URLs')}  ({len(urls)} total)")
    print("  " + "─" * 52)
    for i, url in enumerate(sorted(urls), 1):
        print(f"  {DIM(str(i).rjust(3))}  {url}")
    print()


def _reload_proxy() -> None:
    """Send SIGHUP to the running daemon to reload config without restarting."""
    pid: Optional[int] = _read_pid()
    if _is_running(pid):
        try:
            os.kill(pid, signal.SIGHUP)  # type: ignore[arg-type]
            print(DIM("  Config reloaded in running proxy."))
        except Exception:
            pass


def _print_help() -> None:
    """Print the formatted help/usage screen."""
    ssl_status: str = (
        GREEN("✔ CA found") if _ca_available()
        else YELLOW("✖ run --generate-ca")
    )
    print(f"""
  {BOLD(CYAN('WAFFLE'))} — Web Access Filter & Firewall for Local Environments
  Version {__version__}  |  SSL bump: {ssl_status}

  {BOLD('SERVICE')}
    {GREEN('-o, --activate')}            Start proxy daemon
    {GREEN('-d, --deactivate')}          Stop proxy daemon
    {GREEN('-t, --toggle')}              Toggle on / off
    {GREEN('-s, --status')}              Show status
    {GREEN('-e, --reload')}              Restart daemon (safe reload)

  {BOLD('BLOCKLIST')}
    {GREEN('-a, --add')}    <URL>        Add URL to blocklist
    {GREEN('-r, --remove')} <URL>        Remove URL from blocklist
    {GREEN('-l, --list')}                List all blocked URLs

  {BOLD('SSL INTERCEPTION')}  (shows WAFFLE block page for HTTPS)
    {GREEN('--generate-ca')}             Create local CA cert (one-time)
    {GREEN('--install-ca')}              Install CA into Chrome / system
    {GREEN('--check-ca')}               Verify CA install & NSS trust status

  {BOLD('INFO')}
    {GREEN('-v, --version')}
    {GREEN('-h, --help')}

  {BOLD('PROXY')}  {CYAN(PROXY_HOST)}:{CYAN(str(PROXY_PORT))}

  {BOLD('SSL SETUP  (one time only)')}
    python waffle.py --generate-ca
    python waffle.py --install-ca
    python waffle.py --deactivate && python waffle.py --activate
""")


def _print_version() -> None:
    """Print version string with SSL status."""
    ssl_str: str = (
        "SSL bump ON" if _ca_available()
        else "SSL bump OFF  (run --generate-ca)"
    )
    print(f"WAFFLE v{__version__}  —  {ssl_str}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate command."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="waffle",
        description="WAFFLE — Web Access Filter & Firewall",
        add_help=False,
    )
    parser.add_argument("-o", "--activate",   action="store_true")
    parser.add_argument("-d", "--deactivate", action="store_true")
    parser.add_argument("-t", "--toggle",     action="store_true")
    parser.add_argument("-s", "--status",     action="store_true")
    parser.add_argument("-a", "--add",        metavar="URL")
    parser.add_argument("-r", "--remove",     metavar="URL")
    parser.add_argument("-l", "--list",       action="store_true")
    parser.add_argument("-v", "--version",    action="store_true")
    parser.add_argument("-h", "--help",       action="store_true")
    parser.add_argument("--generate-ca",      action="store_true")
    parser.add_argument("--install-ca",       action="store_true")
    parser.add_argument("--check-ca",         action="store_true")
    parser.add_argument("-e", "--reload",      action="store_true")
    # Internal flag — subprocess daemon uses this, not exposed in help
    parser.add_argument("--_daemon",          action="store_true",
                        help=argparse.SUPPRESS)

    args: argparse.Namespace = parser.parse_args()

    # Dispatch table (order matters — daemon check must be first)
    if getattr(args, "_daemon", False): run_daemon()
    elif args.help or len(sys.argv)==1: _print_help()
    elif args.version:                  _print_version()
    elif args.generate_ca:              cmd_generate_ca()
    elif args.install_ca:               cmd_install_ca()
    elif args.check_ca:                 cmd_check_ca()
    elif args.activate:                 cmd_activate()
    elif args.deactivate:               cmd_deactivate()
    elif args.toggle:                   cmd_toggle()
    elif args.status:                   cmd_status()
    elif args.add:                      cmd_add(args.add)
    elif args.remove:                   cmd_remove(args.remove)
    elif args.list:                     cmd_list()
    elif args.reload:                   cmd_reload()
    else:                               _print_help()


if __name__ == "__main__":
    main()