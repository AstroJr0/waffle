use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, Result, ensure};

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
        assert_eq!(l.verdict("haramsite.com", None), Verdict::Allow);
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
}