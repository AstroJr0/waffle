use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

pub const PROXY_HOST: &str = "127.0.0.1";
pub const PROXY_PORT: u16 = 8080;
pub const DAEMON_ARG: &str = "--daemon";

const CA_NAME: &str = "WAFFLE Local CA";
const CONFIG_FILE: &str = "waffle.json";
const PID_FILE: &str = "waffle.pid";
const LOG_FILE: &str = "waffle.log";
const CA_CERT: &str = "ca.crt";
const CA_KEY: &str = "ca.key";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const RELAY_BUF: usize = 32 * 1024;
const HEAD_MAX: usize = 64 * 1024;
const MAX_HEADERS: usize = 96;
const LOG_MAX: u64 = 2 * 1024 * 1024;

const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

static HOME: LazyLock<PathBuf> =
    LazyLock::new(|| std::env::home_dir().expect("home directory not found"));
static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| HOME.join(".config/waffle"));

fn config_path(name: &str) -> PathBuf {
    CONFIG_DIR.join(name)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub url: String,
    #[serde(default = "whole_site")]
    pub partial_block: Vec<String>,
}

fn whole_site() -> Vec<String> {
    vec!["none".into()]
}

enum Rule {
    Whole,
    Path(Box<str>),
    Sub(Box<str>),
}

impl FromStr for Rule {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim().to_ascii_lowercase();
        if s == "none" {
            return Ok(Self::Whole);
        }
        if s.starts_with('/') {
            let path = s.trim_end_matches('/');
            return Ok(if path.is_empty() {
                Self::Whole
            } else {
                Self::Path(path.into())
            });
        }
        if s.len() > 1 && s.ends_with('.') && !s.contains(['/', ' ']) {
            return Ok(Self::Sub(s.into()));
        }
        bail!("invalid partial_block rule {s:?}, expected \"none\", \"/path\" or \"sub.\"")
    }
}

#[derive(Default)]
struct Site {
    whole: bool,
    paths: Vec<Box<str>>,
    subs: Vec<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    Inspect,
}

pub struct Blocklist {
    sites: HashMap<String, Site>,
}

impl Blocklist {
    pub fn build(entries: &[Entry]) -> Result<Self> {
        let mut sites: HashMap<String, Site> = HashMap::with_capacity(entries.len());
        for entry in entries {
            let (host, url_path) =
                split_url(&entry.url).with_context(|| format!("bad url {:?}", entry.url))?;
            let url_path = url_path.trim_end_matches('/').to_ascii_lowercase();
            let mut rules = entry
                .partial_block
                .iter()
                .map(|rule| rule.parse::<Rule>())
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("in entry {:?}", entry.url))?;
            if rules.is_empty() {
                rules.push(Rule::Whole);
            }
            let site = sites.entry(host).or_default();
            for rule in rules {
                match rule {
                    Rule::Whole if url_path.is_empty() => site.whole = true,
                    Rule::Whole => site.paths.push(url_path.as_str().into()),
                    Rule::Path(path) => site.paths.push(path),
                    Rule::Sub(sub) => site.subs.push(sub),
                }
            }
        }
        Ok(Self { sites })
    }

    pub fn verdict(&self, host: &str, path: Option<&str>) -> Verdict {
        if self.sites.is_empty() {
            return Verdict::Allow;
        }
        let host = host.trim_end_matches('.');
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.verdict(&host.to_ascii_lowercase(), path);
        }
        let bare = host.strip_prefix("www.").unwrap_or(host);
        let mut verdict = Verdict::Allow;
        let mut suffix = host;
        loop {
            if let Some(site) = self.sites.get(suffix) {
                if suffix == bare {
                    if site.whole {
                        return Verdict::Block;
                    }
                    match path {
                        Some(path) if site.paths.iter().any(|rule| path_matches(path, rule)) => {
                            return Verdict::Block;
                        }
                        None if !site.paths.is_empty() => verdict = Verdict::Inspect,
                        _ => {}
                    }
                } else {
                    let labels = &host[..host.len() - suffix.len()];
                    let hit = site.subs.iter().any(|sub| {
                        labels
                            .strip_suffix(&**sub)
                            .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
                    });
                    if hit {
                        return Verdict::Block;
                    }
                }
            }
            match suffix.split_once('.') {
                Some((_, rest)) => suffix = rest,
                None => return verdict,
            }
        }
    }
}

fn path_matches(path: &str, rule: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    path.get(..rule.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(rule))
        && matches!(path.as_bytes().get(rule.len()), None | Some(b'/'))
}

fn split_url(url: &str) -> Result<(String, &str)> {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, _) = split_host_port(authority, 0);
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    ensure!(!host.is_empty(), "empty host");
    let path = tail.split(['?', '#']).next().unwrap_or_default();
    Ok((host, path))
}

fn split_host_port(target: &str, default: u16) -> (&str, u16) {
    if let Some((host, tail)) = target.strip_prefix('[').and_then(|r| r.split_once(']')) {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (host, port.unwrap_or(default));
    }
    match target.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            port.parse().map_or((target, default), |port| (host, port))
        }
        _ => (target, default),
    }
}

fn toggle_www(host: &str) -> String {
    host.strip_prefix("www.")
        .map_or_else(|| format!("www.{host}"), str::to_owned)
}

pub fn load_entries() -> Result<Vec<Entry>> {
    let path = config_path(CONFIG_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("read {}", path.display()))),
    };
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

pub fn save_entries(entries: &[Entry]) -> Result<()> {
    Blocklist::build(entries)?;
    let mut merged: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for entry in entries {
        merged
            .entry(entry.url.trim())
            .or_default()
            .extend(entry.partial_block.iter().map(String::as_str));
    }
    let out: Vec<Entry> = merged
        .into_iter()
        .map(|(url, mut rules)| {
            rules.sort_unstable();
            rules.dedup();
            Entry {
                url: url.to_owned(),
                partial_block: if rules.is_empty() {
                    whole_site()
                } else {
                    rules.into_iter().map(str::to_owned).collect()
                },
            }
        })
        .collect();

    fs::create_dir_all(&*CONFIG_DIR)?;
    let path = config_path(CONFIG_FILE);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&out)? + "\n")
        .with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))
}

pub fn load_blocklist() -> Result<Blocklist> {
    Blocklist::build(&load_entries()?)
}

const BLOCK_PAGE: &str = r#"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blocked</title>
<style>
*{margin:0;box-sizing:border-box;border-radius:0}
body{min-height:100vh;display:grid;place-items:center;padding:24px;background:#020c03;color:#3dff5e;font:16px/1.5 Tahoma,Verdana,"DejaVu Sans",sans-serif}
main{width:100%;max-width:560px;padding:40px;border:3px solid #3dff5e}
h1{font-size:28px;letter-spacing:.24em;text-transform:uppercase}
p{margin-top:16px;color:#22a83c;word-break:break-all}
</style>
<main><h1>Blocked</h1><p id="url"></p></main>
<script>document.getElementById("url").textContent=location.href</script>
"#;

static BLOCK_RESPONSE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut out = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        BLOCK_PAGE.len()
    )
    .into_bytes();
    out.extend_from_slice(BLOCK_PAGE.as_bytes());
    out
});

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, CA_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "WAFFLE");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::days(3650);
    params
}

pub fn ca_available() -> bool {
    config_path(CA_CERT).exists() && config_path(CA_KEY).exists()
}

pub fn generate_ca() -> Result<()> {
    fs::create_dir_all(&*CONFIG_DIR)?;
    let key = KeyPair::generate()?;
    let cert = ca_params().self_signed(&key)?;
    fs::write(config_path(CA_CERT), cert.pem()).context("write CA certificate")?;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(config_path(CA_KEY))?
        .write_all(key.serialize_pem().as_bytes())
        .context("write CA key")
}

struct Ca {
    key_pem: String,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<HashMap<String, TlsAcceptor>>,
}

impl Ca {
    fn load(provider: Arc<CryptoProvider>) -> Result<Option<Self>> {
        if !ca_available() {
            return Ok(None);
        }
        let key_pem = fs::read_to_string(config_path(CA_KEY)).context("read CA key")?;
        KeyPair::from_pem(&key_pem).context("parse CA key")?;
        Ok(Some(Self {
            key_pem,
            provider,
            leaves: Mutex::default(),
        }))
    }

    fn acceptor(&self, host: &str) -> Result<TlsAcceptor> {
        let mut leaves = self.leaves.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(acceptor) = leaves.get(host) {
            return Ok(acceptor.clone());
        }
        let acceptor = self.issue(host)?;
        leaves.insert(host.to_owned(), acceptor.clone());
        Ok(acceptor)
    }

    fn issue(&self, host: &str) -> Result<TlsAcceptor> {
        let issuer = Issuer::new(ca_params(), KeyPair::from_pem(&self.key_pem)?);
        let ip = host.parse::<IpAddr>().ok();
        let names = if ip.is_some() {
            Vec::new()
        } else {
            vec![host.to_owned(), toggle_www(host)]
        };
        let mut params = CertificateParams::new(names)?;
        params.subject_alt_names.extend(ip.map(SanType::IpAddress));
        params.distinguished_name.push(DnType::CommonName, host);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::days(397);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &issuer)?;
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

fn succeeded(cmd: &mut Command) -> bool {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn nss_dirs() -> Vec<PathBuf> {
    [
        ".pki/nssdb",
        ".var/app/com.google.Chrome/.pki/nssdb",
        ".var/app/org.chromium.Chromium/.pki/nssdb",
        ".var/app/com.brave.Browser/.pki/nssdb",
        ".var/app/com.microsoft.Edge/.pki/nssdb",
        "snap/chromium/current/.pki/nssdb",
    ]
    .iter()
    .map(|dir| HOME.join(dir))
    .collect()
}

pub struct Install {
    pub nss: Vec<PathBuf>,
    pub system: bool,
}

pub fn install_ca() -> Result<Install> {
    let cert = config_path(CA_CERT);
    ensure!(cert.exists(), "no CA certificate, generate one first");

    let shared = HOME.join(".pki/nssdb");
    if !shared.exists() {
        fs::create_dir_all(&shared)?;
        let db = format!("sql:{}", shared.display());
        succeeded(Command::new("certutil").args(["-N", "--empty-password", "-d", db.as_str()]));
    }

    let mut nss = Vec::new();
    for dir in nss_dirs().into_iter().filter(|dir| dir.exists()) {
        let db = format!("sql:{}", dir.display());
        succeeded(Command::new("certutil").args(["-D", "-d", db.as_str(), "-n", CA_NAME]));
        let added = succeeded(
            Command::new("certutil")
                .args(["-A", "-d", db.as_str(), "-n", CA_NAME, "-t", "C,,", "-i"])
                .arg(&cert),
        );
        if added {
            nss.push(dir);
        }
    }
    Ok(Install {
        nss,
        system: install_system(&cert),
    })
}

fn install_system(cert: &Path) -> bool {
    let debian = Path::new("/usr/local/share/ca-certificates");
    if debian.is_dir() {
        return fs::copy(cert, debian.join("waffle-local-ca.crt")).is_ok()
            && succeeded(&mut Command::new("update-ca-certificates"));
    }
    succeeded(Command::new("trust").args(["anchor", "--store"]).arg(cert))
}

pub struct CaStatus {
    pub cert: bool,
    pub key: bool,
    pub nss: Vec<(PathBuf, bool)>,
}

pub fn ca_status() -> CaStatus {
    let nss = nss_dirs()
        .into_iter()
        .filter(|dir| dir.exists())
        .map(|dir| {
            let db = format!("sql:{}", dir.display());
            let trusted =
                succeeded(Command::new("certutil").args(["-L", "-d", db.as_str(), "-n", CA_NAME]));
            (dir, trusted)
        })
        .collect();
    CaStatus {
        cert: config_path(CA_CERT).exists(),
        key: config_path(CA_KEY).exists(),
        nss,
    }
}

pub enum SystemProxy {
    Applied,
    EnvFiles { fish: PathBuf, sh: PathBuf },
}

pub fn set_system_proxy(enable: bool) -> Result<SystemProxy> {
    let port = PROXY_PORT.to_string();
    if cfg!(target_os = "macos") {
        macos_proxy(enable, &port);
        return Ok(SystemProxy::Applied);
    }
    if gnome_proxy(enable, &port) {
        return Ok(SystemProxy::Applied);
    }
    env_files(enable)
}

fn macos_proxy(enable: bool, port: &str) {
    let Ok(output) = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
    else {
        return;
    };
    let listing = String::from_utf8_lossy(&output.stdout);
    let state = if enable { "on" } else { "off" };
    for service in listing
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
    {
        if enable {
            for flag in ["-setwebproxy", "-setsecurewebproxy"] {
                succeeded(Command::new("networksetup").args([flag, service, PROXY_HOST, port]));
            }
        }
        for flag in ["-setwebproxystate", "-setsecurewebproxystate"] {
            succeeded(Command::new("networksetup").args([flag, service, state]));
        }
    }
}

fn gnome_proxy(enable: bool, port: &str) -> bool {
    let set = |schema: &str, key: &str, value: &str| {
        succeeded(Command::new("gsettings").args(["set", schema, key, value]))
    };
    if !succeeded(Command::new("gsettings").arg("--version")) {
        return false;
    }
    if !enable {
        return set("org.gnome.system.proxy", "mode", "none");
    }
    let mut ok = true;
    for scheme in ["http", "https"] {
        let schema = format!("org.gnome.system.proxy.{scheme}");
        ok &= set(&schema, "host", PROXY_HOST);
        ok &= set(&schema, "port", port);
    }
    ok & set("org.gnome.system.proxy", "mode", "manual")
}

fn env_files(enable: bool) -> Result<SystemProxy> {
    fs::create_dir_all(&*CONFIG_DIR)?;
    let url = format!("http://{PROXY_HOST}:{PROXY_PORT}");
    let names = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"];
    let (fish, sh) = if enable {
        (
            names.map(|n| format!("set -x {n} {url}\n")).concat(),
            names.map(|n| format!("export {n}={url}\n")).concat(),
        )
    } else {
        (
            names.map(|n| format!("set -e {n}\n")).concat(),
            names.map(|n| format!("unset {n}\n")).concat(),
        )
    };
    let (fish_path, sh_path) = (config_path("waffle.fish"), config_path("waffle.sh"));
    fs::write(&fish_path, fish)?;
    fs::write(&sh_path, sh)?;
    Ok(SystemProxy::EnvFiles {
        fish: fish_path,
        sh: sh_path,
    })
}

const BROWSER_DESKTOP_FILES: [&str; 7] = [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "microsoft-edge",
    "vivaldi-stable",
];

pub fn patch_browsers(enable: bool) -> Result<Vec<PathBuf>> {
    let user_dir = HOME.join(".local/share/applications");
    let flag = format!("--proxy-server={PROXY_HOST}:{PROXY_PORT}");
    let mut patched = Vec::new();
    for name in BROWSER_DESKTOP_FILES {
        let file = format!("{name}.desktop");
        let dst = user_dir.join(&file);
        if !dst.exists() {
            let system = Path::new("/usr/share/applications").join(&file);
            if !enable || !system.exists() {
                continue;
            }
            fs::create_dir_all(&user_dir)?;
            fs::copy(&system, &dst)?;
        }
        let text = fs::read_to_string(&dst)?;
        let updated = rewrite_exec(&text, &flag, enable);
        if updated.trim_end() != text.trim_end() {
            fs::write(&dst, updated)?;
            patched.push(dst);
        }
    }
    if !patched.is_empty() {
        succeeded(Command::new("update-desktop-database").arg(&user_dir));
    }
    Ok(patched)
}

fn rewrite_exec(text: &str, flag: &str, enable: bool) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.lines() {
        match line.strip_prefix("Exec=") {
            Some(cmd) if enable && !cmd.contains(flag) => {
                let (bin, rest) = cmd.split_once(' ').unwrap_or((cmd, ""));
                out.push_str(&format!("Exec={bin} {flag} {rest}"));
            }
            Some(cmd) if !enable && cmd.contains(flag) => {
                out.push_str("Exec=");
                out.push_str(&cmd.replace(&format!(" {flag}"), ""));
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

fn read_pid() -> Option<u32> {
    fs::read_to_string(config_path(PID_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn alive(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(|pid| kill(Pid::from_raw(pid), None).is_ok())
}

fn running_pid() -> Option<u32> {
    read_pid().filter(|&pid| alive(pid))
}

fn send_signal(pid: u32, sig: Signal) -> Result<()> {
    kill(Pid::from_raw(i32::try_from(pid)?), sig)?;
    Ok(())
}

pub struct Status {
    pub pid: Option<u32>,
    pub ssl_bump: bool,
    pub blocked: usize,
}

pub fn status() -> Result<Status> {
    Ok(Status {
        pid: running_pid(),
        ssl_bump: ca_available(),
        blocked: load_entries()?.len(),
    })
}

pub struct Activated {
    pub pid: u32,
    pub proxy: SystemProxy,
    pub browsers: Vec<PathBuf>,
}

pub fn activate() -> Result<Activated> {
    if let Some(pid) = running_pid() {
        bail!("already running (pid {pid})");
    }
    ensure!(
        std::net::TcpListener::bind((PROXY_HOST, PROXY_PORT)).is_ok(),
        "port {PROXY_PORT} is already in use"
    );
    fs::create_dir_all(&*CONFIG_DIR)?;

    let log_path = config_path(LOG_FILE);
    if fs::metadata(&log_path).is_ok_and(|meta| meta.len() > LOG_MAX) {
        fs::rename(&log_path, log_path.with_extension("log.1"))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let _ = fs::remove_file(config_path(PID_FILE));

    Command::new(std::env::current_exe()?)
        .arg(DAEMON_ARG)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .context("spawn daemon")?;

    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        if let Some(pid) = running_pid() {
            return Ok(Activated {
                pid,
                proxy: set_system_proxy(true)?,
                browsers: patch_browsers(true)?,
            });
        }
    }
    bail!("daemon did not start, see {}", log_path.display())
}

pub fn deactivate() -> Result<SystemProxy> {
    let Some(pid) = running_pid() else {
        let _ = fs::remove_file(config_path(PID_FILE));
        bail!("not running");
    };
    send_signal(pid, Signal::SIGTERM)?;
    let stopped = (0..50).any(|_| {
        thread::sleep(Duration::from_millis(100));
        !alive(pid)
    });
    if !stopped {
        send_signal(pid, Signal::SIGKILL)?;
    }
    let _ = fs::remove_file(config_path(PID_FILE));
    patch_browsers(false)?;
    set_system_proxy(false)
}

pub fn reload() -> Result<()> {
    let pid = running_pid().context("not running")?;
    send_signal(pid, Signal::SIGHUP)
}

struct PidGuard;

impl PidGuard {
    fn create() -> std::io::Result<Self> {
        fs::write(config_path(PID_FILE), std::process::id().to_string())?;
        Ok(Self)
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(config_path(PID_FILE));
    }
}

pub fn run_daemon() -> Result<()> {
    let level = match std::env::var("WAFFLE_LOG").as_deref() {
        Ok("debug") => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_target(false)
        .try_init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(daemon())
}

async fn daemon() -> Result<()> {
    let entries = load_entries()?;
    let proxy = Arc::new(Proxy::new(Blocklist::build(&entries)?)?);
    let listener = TcpListener::bind((PROXY_HOST, PROXY_PORT))
        .await
        .with_context(|| format!("bind {PROXY_HOST}:{PROXY_PORT}"))?;
    let _pid = PidGuard::create()?;
    info!(
        "listening on {PROXY_HOST}:{PROXY_PORT}, {} entries, ssl bump {}",
        entries.len(),
        if proxy.ca.is_some() { "on" } else { "off" }
    );

    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let reloader = proxy.clone();
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            reloader.reload();
        }
    });

    tokio::select! {
        () = proxy.clone().serve(listener) => {}
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

struct Proxy {
    list: watch::Sender<Arc<Blocklist>>,
    ca: Option<Ca>,
    connector: TlsConnector,
}

impl Proxy {
    fn new(list: Blocklist) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca = Ca::load(provider.clone())?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            list: watch::channel(Arc::new(list)).0,
            ca,
            connector: TlsConnector::from(Arc::new(client)),
        })
    }

    fn list(&self) -> Arc<Blocklist> {
        self.list.borrow().clone()
    }

    fn reload(&self) {
        match load_blocklist() {
            Ok(list) => {
                self.list.send_replace(Arc::new(list));
                info!("blocklist reloaded");
            }
            Err(e) => warn!("reload failed, keeping previous blocklist: {e:#}"),
        }
    }

    async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle(stream).await {
                            debug!("{peer}: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle(&self, mut client: TcpStream) -> Result<()> {
        client.set_nodelay(true)?;
        let (buf, end) = read_head(&mut client).await?;
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(&buf[..end])?;
        let target = req.path.context("missing request target")?;
        if req
            .method
            .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
        {
            self.connect(client, target).await
        } else {
            self.http(client, &req, target, &buf[end..]).await
        }
    }

    async fn connect(&self, mut client: TcpStream, target: &str) -> Result<()> {
        let (host, port) = split_host_port(target, 443);
        let list = self.list();
        match (list.verdict(host, None), &self.ca) {
            (Verdict::Block, Some(ca)) => {
                info!("blocked CONNECT {target}");
                client.write_all(CONNECTED).await?;
                let mut tls = accept(ca, host, client).await?;
                read_head(&mut tls).await?;
                tls.write_all(&BLOCK_RESPONSE).await?;
                tls.shutdown().await?;
                Ok(())
            }
            (Verdict::Block, None) => {
                info!("blocked CONNECT {target}");
                client.write_all(&BLOCK_RESPONSE).await?;
                Ok(())
            }
            (Verdict::Inspect, Some(ca)) => self.inspect(ca, client, host, port, &list).await,
            (verdict, _) => {
                if verdict == Verdict::Inspect {
                    warn!("{host}: path rules need the CA, tunnelling unfiltered");
                }
                let upstream = dial_or_502(&mut client, host, port).await?;
                client.write_all(CONNECTED).await?;
                relay(client, upstream).await
            }
        }
    }

    async fn inspect(
        &self,
        ca: &Ca,
        mut client: TcpStream,
        host: &str,
        port: u16,
        list: &Blocklist,
    ) -> Result<()> {
        client.write_all(CONNECTED).await?;
        let mut tls = accept(ca, host, client).await?;
        let (buf, end) = read_head(&mut tls).await?;
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(&buf[..end])?;
        let path = req.path.context("missing request target")?;

        if list.verdict(host, Some(path)) == Verdict::Block {
            info!("blocked https://{host}{path}");
            tls.write_all(&BLOCK_RESPONSE).await?;
            tls.shutdown().await?;
            return Ok(());
        }
        let mut upstream = match self.upstream(host, port).await {
            Ok(upstream) => upstream,
            Err(e) => {
                tls.write_all(BAD_GATEWAY).await?;
                return Err(e);
            }
        };
        upstream.write_all(&forward_head(&req, path)).await?;
        upstream.write_all(&buf[end..]).await?;
        relay(tls, upstream).await
    }

    async fn upstream(
        &self,
        host: &str,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = dial(host, port).await?;
        let name = ServerName::try_from(host.to_owned())?;
        let tls = timeout(CONNECT_TIMEOUT, self.connector.connect(name, tcp)).await??;
        Ok(tls)
    }

    async fn http(
        &self,
        mut client: TcpStream,
        req: &httparse::Request<'_, '_>,
        target: &str,
        body: &[u8],
    ) -> Result<()> {
        let (host, port, path) = match absolute_target(target) {
            Some(parts) => parts,
            None => {
                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .context("missing host header")?;
                let (host, port) = split_host_port(host, 80);
                (host, port, Cow::Borrowed(target))
            }
        };
        if self.list().verdict(host, Some(&*path)) == Verdict::Block {
            info!("blocked http://{host}{path}");
            client.write_all(&BLOCK_RESPONSE).await?;
            return Ok(());
        }
        let mut upstream = dial_or_502(&mut client, host, port).await?;
        upstream.write_all(&forward_head(req, &path)).await?;
        upstream.write_all(body).await?;
        relay(client, upstream).await
    }
}

async fn accept(
    ca: &Ca,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    let acceptor = ca.acceptor(host)?;
    let tls = timeout(CONNECT_TIMEOUT, acceptor.accept(stream)).await??;
    Ok(tls)
}

async fn dial(host: &str, port: u16) -> Result<TcpStream> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect {host}:{port} timed out"))?
        .with_context(|| format!("connect {host}:{port}"))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn dial_or_502(client: &mut TcpStream, host: &str, port: u16) -> Result<TcpStream> {
    match dial(host, port).await {
        Ok(stream) => Ok(stream),
        Err(e) => {
            client.write_all(BAD_GATEWAY).await?;
            Err(e)
        }
    }
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity(2048);
    loop {
        let scanned = buf.len().saturating_sub(3);
        let read = timeout(CONNECT_TIMEOUT, stream.read_buf(&mut buf)).await??;
        ensure!(read > 0, "connection closed before request head");
        if let Some(i) = buf[scanned..].windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok((buf, scanned + i + 4));
        }
        ensure!(buf.len() < HEAD_MAX, "request head too large");
    }
}

async fn relay<A, B>(a: A, b: B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let (up, down) = tokio::join!(pipe(a_read, b_write), pipe(b_read, a_write));
    up.and(down)?;
    Ok(())
}

async fn pipe<R, W>(mut from: R, mut to: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let read = timeout(IDLE_TIMEOUT, from.read(&mut buf)).await??;
        if read == 0 {
            return to.shutdown().await;
        }
        to.write_all(&buf[..read]).await?;
    }
}

fn absolute_target(target: &str) -> Option<(&str, u16, Cow<'_, str>)> {
    let rest = target
        .get(7..)
        .filter(|_| target[..7].eq_ignore_ascii_case("http://"))?;
    let (authority, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = split_host_port(authority, 80);
    let path = if tail.starts_with('/') {
        Cow::Borrowed(tail)
    } else {
        Cow::Owned(format!("/{tail}"))
    };
    Some((host, port, path))
}

fn forward_head(req: &httparse::Request<'_, '_>, target: &str) -> Vec<u8> {
    let upgrade = req
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"));
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(req.method.unwrap_or("GET").as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for header in req.headers.iter() {
        let name = header.name;
        let proxy_only = name
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("proxy-"));
        let hop_by_hop = !upgrade
            && (name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("keep-alive"));
        if proxy_only || hop_by_hop {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value);
        out.extend_from_slice(b"\r\n");
    }
    if !upgrade {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[(&str, &[&str])]) -> Blocklist {
        let entries: Vec<Entry> = entries
            .iter()
            .map(|(url, rules)| Entry {
                url: (*url).into(),
                partial_block: rules.iter().map(|r| (*r).into()).collect(),
            })
            .collect();
        Blocklist::build(&entries).unwrap()
    }

    #[test]
    fn whole_site_covers_apex_and_www_only() {
        let l = list(&[("https://Example.com/", &["none"])]);
        assert_eq!(l.verdict("example.com", None), Verdict::Block);
        assert_eq!(l.verdict("www.example.com", None), Verdict::Block);
        assert_eq!(l.verdict("EXAMPLE.com", Some("/x")), Verdict::Block);
        assert_eq!(l.verdict("sub.example.com", None), Verdict::Allow);
        assert_eq!(l.verdict("notexample.com", None), Verdict::Allow);
        assert_eq!(l.verdict("example.com.evil.org", None), Verdict::Allow);
    }

    #[test]
    fn subdomain_rule_blocks_only_that_subtree() {
        let l = list(&[("haramsite.com", &["something."])]);
        assert_eq!(l.verdict("something.haramsite.com", None), Verdict::Block);
        assert_eq!(
            l.verdict("a.b.something.haramsite.com", None),
            Verdict::Block
        );
        assert_eq!(l.verdict("haramsite.com", None), Verdict::Allow);
        assert_eq!(l.verdict("www.haramsite.com", Some("/")), Verdict::Allow);
        assert_eq!(l.verdict("other.haramsite.com", None), Verdict::Allow);
        assert_eq!(l.verdict("xsomething.haramsite.com", None), Verdict::Allow);
    }

    #[test]
    fn path_rule_needs_inspection_then_matches_on_segments() {
        let l = list(&[("example.com", &["/ads/"])]);
        assert_eq!(l.verdict("example.com", None), Verdict::Inspect);
        assert_eq!(l.verdict("www.example.com", None), Verdict::Inspect);
        assert_eq!(l.verdict("example.com", Some("/ads")), Verdict::Block);
        assert_eq!(l.verdict("example.com", Some("/ads/x/y")), Verdict::Block);
        assert_eq!(l.verdict("example.com", Some("/ads?id=1")), Verdict::Block);
        assert_eq!(l.verdict("example.com", Some("/ADS")), Verdict::Block);
        assert_eq!(l.verdict("example.com", Some("/adserver")), Verdict::Allow);
        assert_eq!(l.verdict("example.com", Some("/")), Verdict::Allow);
        assert_eq!(
            l.verdict("example.com", Some("/x?next=/ads")),
            Verdict::Allow
        );
    }

    #[test]
    fn url_path_acts_as_prefix_rule() {
        let l = list(&[("https://example.com/foo/", &["none"])]);
        assert_eq!(l.verdict("example.com", None), Verdict::Inspect);
        assert_eq!(l.verdict("example.com", Some("/foo/bar")), Verdict::Block);
        assert_eq!(l.verdict("example.com", Some("/")), Verdict::Allow);
    }

    #[test]
    fn rules_combine_and_slash_means_whole_site() {
        let l = list(&[("a.com", &["/x", "m."]), ("b.com", &["/"]), ("c.com", &[])]);
        assert_eq!(l.verdict("m.a.com", None), Verdict::Block);
        assert_eq!(l.verdict("a.com", Some("/x")), Verdict::Block);
        assert_eq!(l.verdict("a.com", Some("/y")), Verdict::Allow);
        assert_eq!(l.verdict("b.com", None), Verdict::Block);
        assert_eq!(l.verdict("c.com", None), Verdict::Block);
    }

    #[test]
    fn invalid_rules_are_rejected() {
        let bad = |rule: &str| {
            Blocklist::build(&[Entry {
                url: "a.com".into(),
                partial_block: vec![rule.into()],
            }])
            .is_err()
        };
        assert!(bad("foo"));
        assert!(bad("."));
        assert!(bad("a/b."));
        assert!(!bad("NONE"));
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(
            split_host_port("example.com:8443", 443),
            ("example.com", 8443)
        );
        assert_eq!(split_host_port("example.com", 443), ("example.com", 443));
        assert_eq!(split_host_port("[::1]:8080", 443), ("::1", 8080));
        assert_eq!(split_host_port("[::1]", 443), ("::1", 443));
        assert_eq!(split_host_port("::1", 443), ("::1", 443));
    }

    #[test]
    fn absolute_targets() {
        let (host, port, path) = absolute_target("HTTP://Example.com:81/a?b").unwrap();
        assert_eq!((host, port, &*path), ("Example.com", 81, "/a?b"));
        let (host, port, path) = absolute_target("http://h?x").unwrap();
        assert_eq!((host, port, &*path), ("h", 80, "/?x"));
        assert!(absolute_target("/path").is_none());
        assert!(absolute_target("https://h/").is_none());
        assert!(absolute_target("ht").is_none());
    }

    #[test]
    fn desktop_exec_patching_is_idempotent_and_reversible() {
        let flag = "--proxy-server=127.0.0.1:8080";
        let src = "[Desktop Entry]\nExec=chrome %U\n[Action x]\nExec=chrome --incognito\n";
        let on = rewrite_exec(src, flag, true);
        assert!(on.contains("Exec=chrome --proxy-server=127.0.0.1:8080 %U\n"));
        assert!(on.contains("Exec=chrome --proxy-server=127.0.0.1:8080 --incognito\n"));
        assert_eq!(rewrite_exec(&on, flag, true), on);
        assert_eq!(rewrite_exec(&on, flag, false), src);
    }
}
