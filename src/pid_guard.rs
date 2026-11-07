use std::fs;

use crate::config::config_path;

pub(crate) const PID_FILE: &str = "waffle.pid";

pub(crate) struct PidGuard;

impl PidGuard {
    pub(crate) fn create() -> std::io::Result<Self> {
        fs::write(config_path(PID_FILE), std::process::id().to_string())?;
        Ok(Self)
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(config_path(PID_FILE));
    }
}