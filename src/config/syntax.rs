//! Syntax rules for individual configuration values.
//!
//! These are pure predicates over one string: is this a UUID, a DNS name, a
//! `host:port` endpoint, a routing matcher, a 32-byte key. They own the rule
//! *and* the wording of the failure, so a message an operator learns to
//! recognise means the same thing wherever it appears. Attaching that failure
//! to a configuration path is the caller's job.
//!
//! Nothing here reads the file system, resolves a name, or opens a socket:
//! `check` must stay offline, and these rules are what makes that possible.

use std::{net::IpAddr, path::Component};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

/// Length of every key the configuration accepts, in bytes.
pub(super) const KEY_BYTES: usize = 32;

/// Returns whether `value` is a canonical hyphenated UUID.
pub(super) fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// Returns whether `value` is a valid ASCII DNS name.
pub(super) fn is_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Returns whether `value` is a DNS name or an IP address literal.
pub(super) fn is_hostname_or_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || is_hostname(value)
}

/// Returns whether `value` is a REALITY short ID.
///
/// Two to sixteen hexadecimal characters, an even number of them, because the
/// value is carried on the wire as bytes.
pub(super) fn is_short_id(value: &str) -> bool {
    (2..=16).contains(&value.len())
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Decodes a [`KEY_BYTES`]-byte key from URL-safe unpadded base64.
///
/// The decoded material is zeroed on drop. Returns `None` for anything that is
/// not exactly one key, without saying which way it was wrong: the caller
/// reports the rule, not the observation, so the message cannot leak the shape
/// of a secret.
pub(super) fn decode_key(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    let decoded = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.decode(value).ok()?);
    (decoded.len() == KEY_BYTES).then_some(decoded)
}

/// The rule a key must satisfy, for use in a diagnostic.
pub(super) const KEY_RULE: &str = "must be URL-safe unpadded base64 decoding to exactly 32 bytes";

/// Checks a `host:port` endpoint.
///
/// # Errors
///
/// Returns the rule that was broken.
pub(super) fn check_endpoint(value: &str) -> Result<(), &'static str> {
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(());
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err("must be host:port");
    };
    if host.contains(':') {
        return Err("IPv6 addresses must use bracketed host:port syntax");
    }
    if !is_hostname_or_ip(host) {
        return Err("host must be a valid ASCII DNS name or IP address");
    }
    check_port(port)
}

/// Checks one port written as text.
///
/// # Errors
///
/// Returns the rule that was broken.
pub(super) fn check_port(value: &str) -> Result<(), &'static str> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .map(|_| ())
        .ok_or("port must be between 1 and 65535")
}

/// Checks one routing domain condition.
///
/// # Errors
///
/// Returns the rule that was broken.
pub(super) fn check_domain_matcher(value: &str) -> Result<(), &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Err("must not be empty");
    }
    if let Some(rest) = value.strip_prefix("ext:") {
        return check_external_matcher(rest);
    }
    for prefix in ["domain:", "full:", "keyword:", "regexp:", "geosite:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return if rest.is_empty() {
                Err("matcher value must not be empty")
            } else {
                Ok(())
            };
        }
    }
    if is_hostname(value) {
        Ok(())
    } else {
        Err("must be a domain, or a domain:, full:, keyword:, regexp:, geosite:, or ext: matcher")
    }
}

/// Checks one routing address condition.
///
/// # Errors
///
/// Returns the rule that was broken.
pub(super) fn check_ip_matcher(value: &str) -> Result<(), &'static str> {
    if let Some(label) = value.strip_prefix("geoip:") {
        return if label.is_empty() {
            Err("GeoIP label must not be empty")
        } else {
            Ok(())
        };
    }
    if let Some(rest) = value.strip_prefix("ext:") {
        return check_external_matcher(rest);
    }
    if let Some((address, prefix)) = value.split_once('/') {
        let Ok(address) = address.parse::<IpAddr>() else {
            return Err("CIDR address is invalid");
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            return Err("CIDR prefix is invalid");
        };
        return if prefix > if address.is_ipv4() { 32 } else { 128 } {
            Err("CIDR prefix is wider than the address family allows")
        } else {
            Ok(())
        };
    }
    if value.parse::<IpAddr>().is_ok() {
        Ok(())
    } else {
        Err("must be an IP address, a CIDR block, geoip:tag, or ext:file:tag")
    }
}

/// Checks one routing port condition: a port or an inclusive `from-to` range.
///
/// # Errors
///
/// Returns the rule that was broken.
pub(super) fn check_port_matcher(value: &str) -> Result<(), &'static str> {
    let Some((start, end)) = value.split_once('-') else {
        return check_port(value);
    };
    check_port(start)?;
    check_port(end)?;
    // Both parsed, so both fit in a u16.
    let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
        return Err("port must be between 1 and 65535");
    };
    if start > end {
        return Err("port range must not start above where it ends");
    }
    Ok(())
}

/// Checks an `ext:file:tag` matcher body, after the `ext:` prefix.
fn check_external_matcher(rest: &str) -> Result<(), &'static str> {
    let Some((file, tag)) = rest.split_once(':') else {
        return Err("external matcher must be ext:file:tag");
    };
    if file.is_empty() || tag.is_empty() || tag.contains(':') {
        return Err("external matcher must name one file and one tag");
    }
    let path = std::path::Path::new(file);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("external matcher file must be a relative path without traversal");
    }
    Ok(())
}

/// Checks an asset source URL.
///
/// # Errors
///
/// Returns the rule that was broken.
pub(super) fn check_asset_url(value: &str) -> Result<(), &'static str> {
    let Some(rest) = value.strip_prefix("https://") else {
        return Err("must be an https:// URL");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("must not embed credentials in the URL");
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    if host.is_empty() || !is_hostname_or_ip(host) {
        return Err("must be an https:// URL with a valid host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_BYTES, check_asset_url, check_domain_matcher, check_endpoint, check_ip_matcher,
        check_port_matcher, decode_key, is_hostname, is_hostname_or_ip, is_short_id, is_uuid,
    };
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    #[test]
    fn uuids_must_be_canonical_and_hyphenated() {
        assert!(is_uuid("11111111-1111-4111-8111-111111111111"));
        assert!(is_uuid("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"));
        assert!(!is_uuid("11111111111141118111111111111111"));
        assert!(!is_uuid("11111111-1111-4111-8111-11111111111"));
        assert!(!is_uuid("11111111-1111-4111-8111-11111111111g"));
        assert!(!is_uuid(""));
    }

    #[test]
    fn hostnames_follow_dns_label_rules() {
        assert!(is_hostname("www.example.com"));
        assert!(is_hostname("a"));
        assert!(is_hostname("xn--80ak6aa92e.com"));
        assert!(!is_hostname(""));
        assert!(!is_hostname("example..com"));
        assert!(!is_hostname("-example.com"));
        assert!(!is_hostname("example-.com"));
        assert!(!is_hostname(&"a".repeat(64)));
        assert!(!is_hostname("under_score.com"));
        assert!(is_hostname_or_ip("2001:db8::1"));
        assert!(is_hostname_or_ip("10.0.0.1"));
    }

    #[test]
    fn short_ids_are_even_length_hex_within_bounds() {
        assert!(is_short_id("ab"));
        assert!(is_short_id("0123456789abcdef"));
        assert!(!is_short_id("a"), "odd length");
        assert!(!is_short_id("abc"), "odd length");
        assert!(!is_short_id("0123456789abcdef0"), "too long");
        assert!(!is_short_id("gg"), "not hex");
        assert!(!is_short_id(""));
    }

    #[test]
    fn keys_decode_only_at_exactly_the_key_length() {
        let key = BASE64_URL_SAFE_NO_PAD.encode([7u8; KEY_BYTES]);
        let decoded = decode_key(&key).expect("a 32-byte key must decode");
        assert_eq!(decoded.len(), KEY_BYTES);

        assert!(decode_key(&BASE64_URL_SAFE_NO_PAD.encode([7u8; 31])).is_none());
        assert!(decode_key(&BASE64_URL_SAFE_NO_PAD.encode([7u8; 33])).is_none());
        assert!(decode_key("not base64!").is_none());
        assert!(decode_key("").is_none());
        assert!(
            decode_key(&base64::prelude::BASE64_STANDARD.encode([255u8; KEY_BYTES])).is_none(),
            "standard-alphabet base64 with padding is not the accepted encoding"
        );
    }

    #[test]
    fn endpoints_require_a_host_and_a_usable_port() {
        assert!(check_endpoint("www.example.com:443").is_ok());
        assert!(check_endpoint("10.0.0.1:443").is_ok());
        assert!(check_endpoint("[2001:db8::1]:443").is_ok());
        assert_eq!(check_endpoint("www.example.com"), Err("must be host:port"));
        assert_eq!(
            check_endpoint("2001:db8::1:443"),
            Err("IPv6 addresses must use bracketed host:port syntax")
        );
        assert!(check_endpoint("www.example.com:0").is_err());
        assert!(check_endpoint("www.example.com:70000").is_err());
        assert!(check_endpoint("-bad-.example.com:443").is_err());
    }

    #[test]
    fn domain_matchers_accept_the_documented_prefixes() {
        for accepted in [
            "example.com",
            "domain:example.com",
            "full:www.example.com",
            "keyword:ads",
            "regexp:^ads\\.",
            "geosite:cn",
            "ext:custom.dat:cn",
        ] {
            assert!(
                check_domain_matcher(accepted).is_ok(),
                "{accepted} must be accepted"
            );
        }
        assert!(check_domain_matcher("").is_err());
        assert!(check_domain_matcher("geosite:").is_err());
        assert!(check_domain_matcher("ext:custom.dat").is_err());
        assert!(
            check_domain_matcher("ext:/etc/passwd:cn").is_err(),
            "an absolute external path must be refused"
        );
        assert!(
            check_domain_matcher("ext:../../etc/passwd:cn").is_err(),
            "traversal must be refused"
        );
    }

    #[test]
    fn ip_matchers_accept_addresses_cidrs_and_tags() {
        for accepted in [
            "10.0.0.1",
            "2001:db8::1",
            "10.0.0.0/8",
            "2001:db8::/32",
            "geoip:private",
            "ext:custom.dat:cn",
        ] {
            assert!(
                check_ip_matcher(accepted).is_ok(),
                "{accepted} must be accepted"
            );
        }
        assert!(check_ip_matcher("geoip:").is_err());
        assert!(check_ip_matcher("10.0.0.0/33").is_err());
        assert!(check_ip_matcher("2001:db8::/129").is_err());
        assert!(check_ip_matcher("example.com").is_err());
    }

    #[test]
    fn port_matchers_accept_a_port_or_an_ordered_range() {
        assert!(check_port_matcher("443").is_ok());
        assert!(check_port_matcher("1-65535").is_ok());
        assert!(check_port_matcher("443-443").is_ok());
        assert!(check_port_matcher("0").is_err());
        assert!(check_port_matcher("443-80").is_err());
        assert!(check_port_matcher("80-").is_err());
        assert!(check_port_matcher("a-b").is_err());
    }

    #[test]
    fn asset_urls_must_be_https_with_a_real_host() {
        assert!(check_asset_url("https://example.com/geoip.dat").is_ok());
        assert!(check_asset_url("https://example.com:8443/geoip.dat").is_ok());
        assert!(check_asset_url("http://example.com/geoip.dat").is_err());
        assert!(check_asset_url("https:///geoip.dat").is_err());
        assert!(check_asset_url("example.com/geoip.dat").is_err());
        assert!(
            check_asset_url("https://user:pass@example.com/geoip.dat").is_err(),
            "credentials in an asset URL would be logged wherever the URL is"
        );
    }
}
