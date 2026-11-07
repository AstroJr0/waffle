use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

use crate::config::{CONFIG_DIR, Db, Settings, config_path};
use crate::pid_guard::{PID_FILE, PidGuard};
use crate::proxy::{PROXY_HOST, PROXY_PORT, Proxy};

pub const DAEMON_ARG: &str = "--daemon";
const LOG_FILE: &str = "waffle.log";
const LOG_MAX: u64 = 2 * 1024 * 1024;

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