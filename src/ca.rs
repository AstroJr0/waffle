use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use tokio_rustls::TlsAcceptor;

use crate::config::{CONFIG_DIR, HOME, config_path};
use crate::sys::succeeded;

const CA_NAME: &str = "WAFFLE Local CA";
const CA_CERT: &str = "ca.crt";
const CA_KEY: &str = "ca.key";

fn toggle_www(host: &str) -> String {
    host.strip_prefix("www.")
        .map_or_else(|| format!("www.{host}"), str::to_owned)
}

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

pub(crate) struct Ca {
    key_pem: String,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<HashMap<String, TlsAcceptor>>,
}

impl Ca {
    pub(crate) fn load(provider: Arc<CryptoProvider>) -> Result<Option<Self>> {
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

    pub(crate) fn acceptor(&self, host: &str) -> Result<TlsAcceptor> {
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
