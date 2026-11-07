use std::borrow::Cow;

pub(crate) fn split_host_port(target: &str, default: u16) -> (&str, u16) {
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

pub(crate) fn absolute_target(target: &str) -> Option<(&str, u16, Cow<'_, str>)> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
