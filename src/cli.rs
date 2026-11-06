use std::fmt::Display;
use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use waffle::{Db, Settings, Target};

const MAX_TRIES: u32 = 3;
const MIN_PASSWORD: usize = 6;

const USAGE: &str = "\
usage: waffle <command>

  add <url>...       block a site, subdomain or path        (password)
  remove <url>...    unblock                                (password)
  init               set up certificates, proxy, and start blocking
  reload             re-read the blocklist
  close              stop blocking everything               (password)
  change-db <path>   move the blocklist file                (password)

url forms:
  example.com                whole site (and www.)
  sub.example.com            that subdomain only
  example.com/path           a path on the site
  sub.example.com/path       a path on that subdomain
";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some(waffle::DAEMON_ARG) => waffle::run_daemon(),
        Some("add") => add(&args.collect::<Vec<_>>()),
        Some("remove") => remove(&args.collect::<Vec<_>>()),
        Some("init") => init(),
        Some("reload") => reload(),
        Some("close") => close(),
        Some("change-db") => change_db(args.next()),
        Some("-V" | "--version") => {
            println!("waffle {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("-h" | "--help" | "help") | None => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(anyhow!("unknown command {other:?}, try `waffle help`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e:#}", paint("91", "✖"));
            ExitCode::FAILURE
        }
    }
}

fn paint(code: &str, text: &str) -> String {
    if io::stdout().is_terminal() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

fn ok(msg: impl Display) {
    println!("{} {msg}", paint("92", "✔"));
}

fn note(msg: impl Display) {
    println!("{} {msg}", paint("93", "!"));
}

fn parse_all(inputs: &[String]) -> Result<Vec<Target>> {
    ensure!(!inputs.is_empty(), "give at least one url");
    inputs
        .iter()
        .map(|input| input.parse().with_context(|| format!("{input:?}")))
        .collect()
}

fn read_password(prompt: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        return Ok(rpassword::prompt_password(prompt)?);
    }
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn authenticate() -> Result<Settings> {
    let settings = Settings::load()?;
    let stored = settings
        .password
        .as_deref()
        .context("not set up yet, run `waffle init`")?;
    let hash = PasswordHash::new(stored).context("stored password hash is corrupt")?;
    for attempt in 1..=MAX_TRIES {
        let input = read_password("password: ")?;
        if Argon2::default()
            .verify_password(input.as_bytes(), &hash)
            .is_ok()
        {
            return Ok(settings);
        }
        eprintln!("{} wrong password", paint("91", "✖"));
        if attempt < MAX_TRIES {
            thread::sleep(Duration::from_secs(1));
        }
    }
    bail!("too many wrong attempts")
}

fn new_password() -> Result<String> {
    let first = read_password("new password: ")?;
    ensure!(
        first.chars().count() >= MIN_PASSWORD,
        "password must be at least {MIN_PASSWORD} characters"
    );
    let again = read_password("repeat password: ")?;
    ensure!(first == again, "passwords do not match");
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(first.as_bytes(), &salt)?
        .to_string())
}

fn reload_if_running() -> Result<()> {
    if waffle::reload()? {
        ok("blocklist reloaded");
    } else {
        note("not running, `waffle init` starts it");
    }
    Ok(())
}

fn add(inputs: &[String]) -> Result<()> {
    let targets = parse_all(inputs)?;
    let settings = authenticate()?;
    let path = settings.db_path();
    let mut db = Db::load(&path)?;
    let mut added = false;
    for target in &targets {
        if db.insert(target) {
            ok(format!("blocked {target}"));
            added = true;
        } else {
            note(format!("{target} is already blocked"));
        }
    }
    if added {
        db.save(&path)?;
        reload_if_running()?;
    }
    Ok(())
}

fn remove(inputs: &[String]) -> Result<()> {
    let targets = parse_all(inputs)?;
    let settings = authenticate()?;
    let path = settings.db_path();
    let mut db = Db::load(&path)?;
    let mut removed = false;
    for target in &targets {
        if db.remove(target) {
            ok(format!("unblocked {target}"));
            removed = true;
        } else {
            note(format!("{target} is not in the list"));
        }
    }
    ensure!(removed, "nothing removed");
    db.save(&path)?;
    reload_if_running()
}

fn init() -> Result<()> {
    let mut settings = Settings::load()?;
    if settings.password.is_none() {
        settings.password = Some(new_password()?);
        settings.save()?;
        ok("password set");
    }

    if !waffle::ca_available() {
        waffle::generate_ca()?;
        ok("certificate authority created");
    }
    let install = waffle::install_ca()?;
    if install.nss.is_empty() {
        note(
            "no browser certificate store found, install certutil (nss-tools / libnss3-tools) and rerun",
        );
    } else {
        ok(format!(
            "certificate trusted in {} browser store(s)",
            install.nss.len()
        ));
    }
    if !install.system {
        note("system trust store untouched (needs root); only affects curl/wget on blocked sites");
    }

    let already = waffle::running().is_some();
    let pid = waffle::activate()?;
    ok(format!(
        "{} (pid {pid})",
        if already {
            "already running"
        } else {
            "running"
        }
    ));

    let integration = waffle::integrate(true)?;
    if integration.system_proxy {
        ok("system proxy set");
    } else {
        note("no desktop proxy backend found, system proxy not set");
    }
    if integration.autostart {
        ok("autostart enabled (systemd user unit)");
    } else {
        note("no systemd user session, run `waffle init` again after each reboot");
    }
    for path in integration.browsers.iter().chain(&integration.tools) {
        ok(format!("proxy injected into {}", path.display()));
    }
    if !integration.browsers.is_empty() {
        note("restart your browsers completely for the proxy flag to apply");
    }
    Ok(())
}

fn reload() -> Result<()> {
    ensure!(waffle::reload()?, "not running, run `waffle init`");
    ok("blocklist reloaded");
    Ok(())
}

fn close() -> Result<()> {
    authenticate()?;
    let stopped = waffle::deactivate()?;
    waffle::integrate(false)?;
    ok(if stopped {
        "stopped, every site is allowed now"
    } else {
        "was not running, proxy settings removed"
    });
    Ok(())
}

fn change_db(arg: Option<String>) -> Result<()> {
    let arg = arg.context("usage: waffle change-db <path>")?;
    let new = std::path::absolute(&arg)?;
    let mut settings = authenticate()?;
    let old = settings.db_path();
    ensure!(new != old, "already using {}", new.display());

    if new.exists() {
        Db::load(&new)?.blocklist()?;
        note(format!("using existing file {}", new.display()));
    } else {
        Db::load(&old)?.save(&new)?;
        ok(format!("blocklist copied to {}", new.display()));
    }
    settings.db = Some(new);
    settings.save()?;
    reload_if_running()
}
