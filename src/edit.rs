use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result};

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

pub(crate) fn edit_block(path: &Path, body: Option<&str>, create: bool) -> Result<bool> {
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

pub(crate) fn rewrite_exec(text: &str, flag: &str, enable: bool) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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
