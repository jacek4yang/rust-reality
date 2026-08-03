//! REALITY server-name pattern validation and matching.

use std::net::IpAddr;

/// Returns whether `value` is one concrete ASCII DNS name accepted in SNI.
pub(crate) fn is_concrete_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(is_dns_label)
}

/// Returns whether `value` is a concrete name or one leftmost-label wildcard.
///
/// A wildcard such as `*.lmu.edu` requires at least two suffix labels and
/// matches exactly one concrete label. Wildcards in any other position are
/// rejected.
pub(crate) fn is_server_name_pattern(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("*.") else {
        return is_concrete_server_name(value);
    };
    value.len() <= 253
        && suffix.contains('.')
        && !suffix.contains('*')
        && is_concrete_server_name(suffix)
}

/// Matches a concrete ClientHello SNI against one validated configuration pattern.
pub(crate) fn server_name_matches(pattern: &str, candidate: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if !is_concrete_server_name(candidate) {
            return false;
        }
        let Some((label, candidate_suffix)) = candidate.split_once('.') else {
            return false;
        };
        return is_dns_label(label) && candidate_suffix.eq_ignore_ascii_case(suffix);
    }
    pattern.eq_ignore_ascii_case(candidate)
}

/// Selects a concrete probe SNI for a configured pattern and REALITY target.
///
/// Exact configured names are returned directly. A wildcard can be probed only
/// when the target itself uses a matching concrete DNS hostname.
pub(crate) fn concrete_probe_name<'a>(target: &'a str, pattern: &'a str) -> Option<&'a str> {
    if !pattern.starts_with("*.") {
        return Some(pattern);
    }
    let (host, port) = target.rsplit_once(':')?;
    if host.contains(':') || port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
        return None;
    }
    server_name_matches(pattern, host).then_some(host)
}

fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{concrete_probe_name, is_server_name_pattern, server_name_matches};

    #[test]
    fn validates_only_leftmost_single_label_wildcards() {
        assert!(is_server_name_pattern("www.lmu.edu"));
        assert!(is_server_name_pattern("*.lmu.edu"));
        assert!(!is_server_name_pattern("*.edu"));
        assert!(!is_server_name_pattern("www.*.edu"));
        assert!(!is_server_name_pattern("*.*.edu"));
        assert!(!is_server_name_pattern("127.0.0.1"));
    }

    #[test]
    fn wildcard_matches_exactly_one_concrete_dns_label() {
        assert!(server_name_matches("*.lmu.edu", "www.lmu.edu"));
        assert!(server_name_matches("*.LMU.EDU", "WWW.lmu.edu"));
        assert!(!server_name_matches("*.lmu.edu", "lmu.edu"));
        assert!(!server_name_matches("*.lmu.edu", "a.b.lmu.edu"));
        assert!(!server_name_matches("*.lmu.edu", "*.lmu.edu"));
        assert!(!server_name_matches("*.lmu.edu", "127.0.0.1"));
    }

    #[test]
    fn wildcard_probe_uses_only_a_matching_target_hostname() {
        assert_eq!(
            concrete_probe_name("www.lmu.edu:443", "*.lmu.edu"),
            Some("www.lmu.edu")
        );
        assert_eq!(concrete_probe_name("other.example:443", "*.lmu.edu"), None);
        assert_eq!(concrete_probe_name("[2001:db8::1]:443", "*.lmu.edu"), None);
        assert_eq!(
            concrete_probe_name("www.lmu.edu:443", "api.lmu.edu"),
            Some("api.lmu.edu")
        );
    }
}
