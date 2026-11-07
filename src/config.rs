use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::blocklist::{Blocklist, Target};

const SETTINGS_FILE: &str = "settings.json";
const DEFAULT_DB_FILE: &str = "waffle.json";

pub(crate) static HOME: LazyLock<PathBuf> =
    LazyLock::new(|| std::env::home_dir().expect("home directory not found"));
pub(crate) static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| HOME.join(".config/waffle"));

pub(crate) fn config_path(name: &str) -> PathBuf {
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