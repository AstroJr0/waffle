use std::borrow::Cow;
use std::collections::HashMap;
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
use std::{fmt, io};

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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

pub const PROXY_HOST: &str = "127.0.0.1"; // proxy server ip. add this inside your browser.
pub const PROXY_PORT: u16 = 8080;
pub const DAEMON_ARG: &str = "--daemon";

const CA_NAME: &str = "WAFFLE Local CA";
const SETTINGS_FILE: &str = "settings.json";
const DEFAULT_DB_FILE: &str = "waffle.json";
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

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .and_then(|mut file| file.write_all(data))
        .with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))
}

fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("read {}", path.display()))),
    };
    if text.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    host: String,
    path: Option<String>,
}

impl FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let input = input.trim();
        let rest = match input.split_once("://") {
            Some((scheme, rest)) => {
                ensure!(
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"),
                    "unsupported protocol {scheme:?}, only http and https are accepted"
                );
                rest
            }
            None => input,
        };
        let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
        ensure!(
            !authority.contains('@'),
            "credentials in a url are not supported"
        );
        ensure!(
            !authority.contains(':'),
            "ports and non-web protocols are not supported"
        );
        let host = authority.trim_end_matches('.').to_ascii_lowercase();
        let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
        validate_host(&host)?;

        let path = tail
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_ascii_lowercase();
        ensure!(!path.contains(char::is_whitespace), "whitespace in path");
        Ok(Self {
            host,
            path: (!path.is_empty()).then_some(path),
        })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host)?;
        f.write_str(self.path.as_deref().unwrap_or_default())
    }
}

fn validate_host(host: &str) -> Result<()> {
    ensure!(
        host.len() <= 253 && host.contains('.'),
        "{host:?} is not a public domain name"
    );
    ensure!(
        host.parse::<IpAddr>().is_err(),
        "IP addresses are not supported"
    );
    ensure!(
        !host.ends_with(".localhost") && !host.ends_with(".local"),
        "{host:?} is a local name"
    );
    for label in host.split('.') {
        let valid = (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        ensure!(
            valid,
            "invalid label {label:?} in {host:?} (non-ASCII names must be punycode)"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    Inspect,
}

#[derive(Default)]
struct Site {
    whole: bool,
    paths: Vec<Box<str>>,
}

pub struct Blocklist {
    sites: HashMap<Box<str>, Site>,
}

impl Blocklist {
    pub fn build<S: AsRef<str>>(urls: &[S]) -> Result<Self> {
        let mut sites: HashMap<Box<str>, Site> = HashMap::with_capacity(urls.len());
        for url in urls {
            let url = url.as_ref();
            let target: Target = url.parse().with_context(|| format!("bad entry {url:?}"))?;
            let site = sites.entry(target.host.into()).or_default();
            match target.path {
                Some(path) => site.paths.push(path.into()),
                None => site.whole = true,
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
        let Some(site) = self.sites.get(host.strip_prefix("www.").unwrap_or(host)) else {
            return Verdict::Allow;
        };
        if site.whole {
            return Verdict::Block;
        }
        match path {
            Some(path) if site.paths.iter().any(|rule| path_matches(path, rule)) => Verdict::Block,
            Some(_) => Verdict::Allow,
            None => Verdict::Inspect,
        }
    }
}

fn path_matches(path: &str, rule: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    path.get(..rule.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(rule))
        && matches!(path.as_bytes().get(rule.len()), None | Some(b'/'))
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

// haramsite.com -> www.haramsite.com
fn toggle_www(host: &str) -> String {
    host.strip_prefix("www.")
        .map_or_else(|| format!("www.{host}"), str::to_owned)
}

#[derive(Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Settings {
    pub fn load() -> Result<Self> {
        read_json(&config_path(SETTINGS_FILE))
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)? + "\n";
        write_atomic(&config_path(SETTINGS_FILE), json.as_bytes(), 0o600)
    }

    pub fn db_path(&self) -> PathBuf {
        self.db
            .clone()
            .unwrap_or_else(|| config_path(DEFAULT_DB_FILE))
    }
}

// this is the json database
// waffle saves the blocked sites inside this
#[derive(Default, Serialize, Deserialize)]
pub struct Db {
    pub urls: Vec<String>,
}

impl Db {
    pub fn load(path: &Path) -> Result<Self> {
        read_json(path)
    }

    pub fn blocklist(&self) -> Result<Blocklist> {
        Blocklist::build(&self.urls)
    }

    pub fn insert(&mut self, target: &Target) -> bool {
        let url = target.to_string();
        let new = !self.urls.contains(&url);
        if new {
            self.urls.push(url);
        }
        new
    }

    pub fn remove(&mut self, target: &Target) -> bool {
        let url = target.to_string();
        let before = self.urls.len();
        self.urls.retain(|u| *u != url);
        self.urls.len() != before
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.blocklist()?;
        let mut urls = self.urls.clone();
        urls.sort_unstable();
        urls.dedup();
        let json = serde_json::to_string_pretty(&Self { urls })? + "\n";
        write_atomic(path, json.as_bytes(), 0o644)
    }
}

pub fn load_blocklist() -> Result<Blocklist> {
    Db::load(&Settings::load()?.db_path())?.blocklist()
}

const BLOCK_PAGE: &str = r#"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blocked</title>
<style>
*{margin:0;box-sizing:border-box;border-radius:0}
body{min-height:100vh;display:grid;place-items:center;padding:24px;background:#020c03;color:#3dff5e;font:16px/1.5 Tahoma,Verdana,"DejaVu Sans",sans-serif}
main{width:100%;max-width:560px;padding:40px;border:4px solid #3dff5e}
h1{font-size:28px;letter-spacing:.24em;}
p{margin-top:16px;color:#22a83c;word-break:break-all}
</style>
<main><h1>This site is blocked by WAFFLE :(</h1><p id="url"></p></main>
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
    let some_var = Path::new("/usr/local/share/ca-certificates");
    if some_var.is_dir() {
        return fs::copy(cert, some_var.join("waffle-local-ca.crt")).is_ok()
            && succeeded(&mut Command::new("update-ca-certificates"));
    }
    succeeded(Command::new("trust").args(["anchor", "--store"]).arg(cert))
}

fn set_system_proxy(enable: bool) -> bool {
    let port = PROXY_PORT.to_string();
    if cfg!(target_os = "macos") {
        macos_proxy(enable, &port);
        return true;
    }
    gnome_proxy(enable, &port)
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

const MARK_BEGIN: &str = "# >>> waffle >>>";
const MARK_END: &str = "# <<< waffle <<<";

fn strip_block(text: &str) -> String {
    match (text.find(MARK_BEGIN), text.find(MARK_END)) {
        (Some(start), Some(end)) if start < end => {
            let after = &text[end + MARK_END.len()..];
            format!(
                "{}{}",
                &text[..start],
                after.strip_prefix('\n').unwrap_or(after)
            )
        }
        _ => text.to_owned(),
    }
}

fn edit_block(path: &Path, body: Option<&str>, create: bool) -> Result<bool> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound && create && body.is_some() => String::new(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("read {}", path.display()))),
    };
    let mut updated = strip_block(&text);
    if let Some(body) = body {
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(&format!("{MARK_BEGIN}\n{body}\n{MARK_END}\n"));
    }
    if updated == text {
        return Ok(false);
    }
    fs::write(path, updated).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn inject_cli_tools(enable: bool) -> Result<Vec<PathBuf>> {
    let url = format!("http://{PROXY_HOST}:{PROXY_PORT}");
    let skip = "localhost,127.0.0.1,::1";
    let names = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"];
    let sh = enable.then(|| {
        let exports = names.map(|n| format!("export {n}={url}\n")).concat();
        format!("{exports}export no_proxy={skip}\nexport NO_PROXY={skip}")
    });
    let fish = enable.then(|| {
        let sets = names.map(|n| format!("set -gx {n} {url}\n")).concat();
        format!("{sets}set -gx no_proxy {skip}\nset -gx NO_PROXY {skip}")
    });
    let curl = enable.then(|| format!("proxy = \"{url}\"\nnoproxy = \"localhost,127.0.0.1\""));

    let fish_path = HOME.join(".config/fish/conf.d/waffle.fish");
    let fish_dir = fish_path.parent().is_some_and(Path::is_dir);
    let targets = [
        (HOME.join(".curlrc"), curl.as_deref(), true),
        (HOME.join(".bashrc"), sh.as_deref(), false),
        (HOME.join(".zshrc"), sh.as_deref(), false),
        (fish_path, fish.as_deref(), fish_dir),
    ];
    let mut touched = Vec::new();
    for (path, body, create) in targets {
        if edit_block(&path, body, create)? {
            touched.push(path);
        }
    }
    Ok(touched)
}

const UNIT_FILE: &str = "waffle.service"; // the actuall service

// system will give the service a go
// so no need to add something in your DE/Compositor
fn set_autostart(enable: bool) -> Result<bool> {
    if !succeeded(Command::new("systemctl").args(["--user", "--version"])) {
        return Ok(false);
    }
    // this service will be available for one user only
    let dir = HOME.join(".config/systemd/user");
    let unit = dir.join(UNIT_FILE);
    if !enable {
        let existed = unit.exists();
        succeeded(Command::new("systemctl").args(["--user", "disable", UNIT_FILE]));
        if existed {
            fs::remove_file(&unit)?;
            succeeded(Command::new("systemctl").args(["--user", "daemon-reload"]));
        }
        return Ok(existed);
    }
    let exe = std::env::current_exe()?;
    fs::create_dir_all(&dir)?;
    fs::write(
        &unit,
        format!(
            "[Unit]\nDescription=WAFFLE site blocker\n\n[Service]\nExecStart=\"{}\" {DAEMON_ARG}\n\
             Restart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        ),
    )?;
    succeeded(Command::new("systemctl").args(["--user", "daemon-reload"]));
    Ok(succeeded(
        Command::new("systemctl").args(["--user", "enable", UNIT_FILE]),
    ))
}

pub struct Integration {
    pub system_proxy: bool,
    pub autostart: bool,
    pub browsers: Vec<PathBuf>,
    pub tools: Vec<PathBuf>,
}

pub fn integrate(enable: bool) -> Result<Integration> {
    Ok(Integration {
        system_proxy: set_system_proxy(enable),
        autostart: set_autostart(enable)?,
        browsers: patch_browsers(enable)?,
        tools: inject_cli_tools(enable)?,
    })
}

// i was tired of handling proxies for chomium 
// based browsers. Firfox and it's fork are so calm 
// about it
const BROWSER_DESKTOP_FILES: [&str; 6] = [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "vivaldi-stable",
];

fn patch_browsers(enable: bool) -> Result<Vec<PathBuf>> {
    let user_dir = HOME.join(".local/share/applications");
    // chromium based browsers mostly use
    // `--proxy-server` to add a proxy inside the broswer config
    // so we inject that into the desktop files
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

// we set the `Exec=`. taking helium browser for example:
// Exec= helium-browser --proxt-server 127.0.0.1
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

pub fn running() -> Option<u32> {
    read_pid().filter(|&pid| alive(pid))
}

fn send_signal(pid: u32, sig: Signal) -> Result<()> {
    kill(Pid::from_raw(i32::try_from(pid)?), sig)?;
    Ok(())
}

pub fn activate() -> Result<u32> {
    if let Some(pid) = running() {
        return Ok(pid);
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
        if let Some(pid) = running() {
            return Ok(pid);
        }
    }
    bail!("daemon did not start, see {}", log_path.display())
}

pub fn deactivate() -> Result<bool> {
    let Some(pid) = running() else {
        let _ = fs::remove_file(config_path(PID_FILE));
        return Ok(false);
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
    Ok(true)
}

pub fn reload() -> Result<bool> {
    let Some(pid) = running() else {
        return Ok(false);
    };
    send_signal(pid, Signal::SIGHUP)?;
    Ok(true)
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
    let db = Db::load(&Settings::load()?.db_path())?;
    let proxy = Arc::new(Proxy::new(db.blocklist()?)?);
    let listener = TcpListener::bind((PROXY_HOST, PROXY_PORT))
        .await
        .with_context(|| format!("bind {PROXY_HOST}:{PROXY_PORT}"))?;
    let _pid = PidGuard::create()?;
    info!(
        "listening on {PROXY_HOST}:{PROXY_PORT}, {} entries, ssl bump {}",
        db.urls.len(),
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

    fn list(urls: &[&str]) -> Blocklist {
        Blocklist::build(urls).unwrap()
    }

    fn target(input: &str) -> Result<Target> {
        input.parse()
    }

    #[test]
    fn whole_host_covers_apex_and_www_only() {
        let l = list(&["example.com"]);
        assert_eq!(l.verdict("example.com", None), Verdict::Block);
        assert_eq!(l.verdict("www.example.com", None), Verdict::Block);
        assert_eq!(l.verdict("EXAMPLE.com.", Some("/x")), Verdict::Block);
        assert_eq!(l.verdict("sub.example.com", None), Verdict::Allow);
        assert_eq!(l.verdict("notexample.com", None), Verdict::Allow);
        assert_eq!(l.verdict("example.com.evil.org", None), Verdict::Allow);
    }

    #[test]
    fn subdomain_entry_leaves_the_apex_open() {
        let l = list(&["something.haramsite.com"]);
        assert_eq!(l.verdict("something.haramsite.com", None), Verdict::Block);
        assert_eq!(l.verdict("haramsite.com", None), Verdict::Allow); // lets just say its an example
        assert_eq!(l.verdict("www.haramsite.com", Some("/")), Verdict::Allow);
        assert_eq!(l.verdict("other.haramsite.com", None), Verdict::Allow);
        assert_eq!(l.verdict("a.something.haramsite.com", None), Verdict::Allow);
    }

    #[test]
    fn path_entry_needs_inspection_then_matches_on_segments() {
        let l = list(&["example.com/ads", "shop.example.com/cart"]);
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
        assert_eq!(
            l.verdict("shop.example.com", Some("/cart/1")),
            Verdict::Block
        );
        assert_eq!(l.verdict("shop.example.com", Some("/ads")), Verdict::Allow);
    }

    #[test]
    fn whole_entry_wins_over_path_entry() {
        let l = list(&["example.com/ads", "example.com"]);
        assert_eq!(l.verdict("example.com", None), Verdict::Block);
    }

    #[test]
    fn targets_are_normalised() {
        let norm = |s: &str| target(s).unwrap().to_string();
        assert_eq!(
            norm("HTTPS://WWW.Example.com/Foo/?q=1#x"),
            "example.com/foo"
        );
        assert_eq!(norm("example.com/"), "example.com");
        assert_eq!(norm("http://example.com?x=1"), "example.com");
        assert_eq!(
            norm("  Something.HaramSite.com/A/b/ "),
            "something.haramsite.com/a/b"
        );
        assert_eq!(norm("example.com."), "example.com");
    }

    #[test]
    fn non_web_and_local_targets_are_rejected() {
        let bad = [
            "chrome://settings",
            "file:///etc/passwd",
            "view-source:https://example.com",
            "about:blank",
            "javascript:alert(1)",
            "ftp://example.com",
            "socks5://127.0.0.1:1080",
            "localhost",
            "localhost:3000",
            "http://localhost:8080",
            "127.0.0.1:8080",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "https://[::1]/",
            "foo.localhost",
            "printer.local",
            "user@example.com",
            "http://example.com@evil.com",
            "example.com:8080",
            "https://example.com:443",
            "exämple.com",
            "-bad.com",
            "a..com",
            "example.com/a b",
            "",
            "   ",
        ];
        for input in bad {
            assert!(target(input).is_err(), "{input:?} should be rejected");
        }
    }

    #[test]
    fn web_targets_are_accepted() {
        for input in [
            "example.com",
            "http://example.com",
            "https://something.haramsite.com/path",
            "EXAMPLE.com/Path/",
            "xn--mnchen-3ya.de",
        ] {
            assert!(target(input).is_ok(), "{input:?} should be accepted");
        }
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

    #[test]
    fn managed_block_is_removed_cleanly() {
        let text = format!("keep\n{MARK_BEGIN}\nx\n{MARK_END}\ntail\n");
        assert_eq!(strip_block(&text), "keep\ntail\n");
        assert_eq!(strip_block("plain\n"), "plain\n");
    }
}
