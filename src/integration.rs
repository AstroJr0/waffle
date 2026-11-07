use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::config::HOME;
use crate::daemon::DAEMON_ARG;
use crate::edit::{edit_block, rewrite_exec};
use crate::proxy::{PROXY_HOST, PROXY_PORT};
use crate::sys::succeeded;

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

const UNIT_FILE: &str = "waffle.service";

fn set_autostart(enable: bool) -> Result<bool> {
    if !succeeded(Command::new("systemctl").args(["--user", "--version"])) {
        return Ok(false);
    }
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

const BROWSER_DESKTOP_FILES: [&str; 7] = [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "microsoft-edge",
    "vivaldi-stable",
];

fn patch_browsers(enable: bool) -> Result<Vec<PathBuf>> {
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
