//! The non-secret identity of a user.
//!
//! A VLESS UUID is a credential: anyone holding it, plus the public REALITY
//! parameters, can authenticate. It must therefore never be the name a
//! controller uses to refer to a user, appear in a listing, or reach a log.
//!
//! A user handle is `u_` followed by 32 lowercase hexadecimal characters: the
//! first 128 bits of `HMAC-SHA256(k, uuid)`, where `uuid` is the identity's 16
//! bytes and `k` is derived with HKDF-SHA256 from the node's REALITY private
//! key. Three properties follow:
//!
//! - **Stable.** The same identity has the same handle across reloads and
//!   restarts, so an external controller may store it.
//! - **Non-reversible.** Without the private key a handle reveals nothing
//!   about its UUID, even for a low-entropy operator-chosen UUID that a plain
//!   hash would expose to a dictionary search.
//! - **Node-scoped.** Two nodes sharing a UUID give it unrelated handles, and
//!   replacing the REALITY private key — which already requires every client
//!   to be reconfigured — gives every user a new handle.
//!
//! No state is stored: the handle is recomputed from the configuration, so it
//! cannot drift from it.

use std::{collections::HashMap, fmt};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::EntryConfig;

/// HKDF `info` that separates the handle key from every other use of the
/// REALITY private key.
const HANDLE_KEY_INFO: &[u8] = b"rust-reality control user-handle key";

/// The handle prefix, which also makes a handle visibly not a UUID.
pub const HANDLE_PREFIX: &str = "u_";

/// Handle length: the prefix plus 128 bits in hexadecimal.
pub const HANDLE_LEN: usize = HANDLE_PREFIX.len() + 32;

/// The keyed derivation of user handles for one node.
#[derive(Clone)]
pub struct UserHandles {
    template: Hmac<Sha256>,
}

impl fmt::Debug for UserHandles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UserHandles([REDACTED])")
    }
}

impl UserHandles {
    /// Derives the handle key from an entry node's REALITY private key.
    ///
    /// Returns `None` when the key does not decode, which semantic validation
    /// rules out for every configuration a server can be running.
    #[must_use]
    pub fn from_entry(entry: &EntryConfig) -> Option<Self> {
        let decoded = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(entry.reality.private_key.expose())
                .ok()?,
        );
        if decoded.len() != 32 {
            return None;
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(None, decoded.as_slice())
            .expand(HANDLE_KEY_INFO, key.as_mut_slice())
            .ok()?;
        let template = Hmac::<Sha256>::new_from_slice(key.as_slice()).ok()?;
        Some(Self { template })
    }

    /// The handle of one configured identity.
    ///
    /// Returns `None` for a string that is not a UUID, which semantic
    /// validation rules out for every configured user.
    #[must_use]
    pub fn handle(&self, id: &str) -> Option<String> {
        let uuid = Uuid::parse_str(id).ok()?;
        let mut mac = self.template.clone();
        mac.update(uuid.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut handle = String::with_capacity(HANDLE_LEN);
        handle.push_str(HANDLE_PREFIX);
        for byte in &digest[..16] {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            handle.push(char::from(HEX[usize::from(byte >> 4)]));
            handle.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Some(handle)
    }

    /// Whether `value` has the shape of a handle. Says nothing about whether
    /// any user has it.
    #[must_use]
    pub fn is_handle(value: &str) -> bool {
        value.len() == HANDLE_LEN
            && value.starts_with(HANDLE_PREFIX)
            && value[HANDLE_PREFIX.len()..]
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }
}

/// The handle of every configured user of one generation, computed once.
///
/// A generation's users never change, so a read that would otherwise derive
/// one HMAC per configured user per request derives them once per
/// generation and then answers by index.
#[derive(Clone, Debug)]
pub struct HandleIndex {
    handles: Vec<String>,
    positions: HashMap<String, usize>,
}

impl HandleIndex {
    /// Indexes `entry`'s users in configuration order.
    ///
    /// Returns `None` when a configured user has no handle, which semantic
    /// validation rules out.
    #[must_use]
    pub fn build(entry: &EntryConfig, handles: &UserHandles) -> Option<Self> {
        let handles = entry
            .users
            .iter()
            .map(|user| handles.handle(&user.id))
            .collect::<Option<Vec<_>>>()?;
        let positions = handles
            .iter()
            .enumerate()
            .map(|(index, handle)| (handle.clone(), index))
            .collect();
        Some(Self { handles, positions })
    }

    /// The handle of the user at `index` in configuration order.
    #[must_use]
    pub fn handle(&self, index: usize) -> Option<&str> {
        self.handles.get(index).map(String::as_str)
    }

    /// The configuration position of the user with `handle`.
    #[must_use]
    pub fn position(&self, handle: &str) -> Option<usize> {
        self.positions.get(handle).copied()
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    use super::{HANDLE_LEN, UserHandles};
    use crate::config::{EntryConfig, node::fixture};

    const USER: &str = "11111111-1111-4111-8111-111111111111";

    fn entry(private_key: &[u8; 32]) -> EntryConfig {
        let json = format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
  "users": [{{ "id": "{USER}", "shortIds": ["ab"] }}],
  "routing": {{ "default": "direct" }}
}}"#,
            BASE64_URL_SAFE_NO_PAD.encode(private_key)
        );
        fixture::parsed(&json)
            .as_entry()
            .expect("the fixture is an entry node")
            .clone()
    }

    #[test]
    fn a_handle_is_stable_case_insensitive_and_never_contains_the_uuid() {
        let handles = UserHandles::from_entry(&entry(&[7; 32])).expect("key must derive");
        let first = handles.handle(USER).expect("a UUID has a handle");

        assert_eq!(first.len(), HANDLE_LEN);
        assert!(UserHandles::is_handle(&first));
        assert_eq!(handles.handle(USER), Some(first.clone()));
        assert_eq!(
            handles.handle(&USER.to_ascii_uppercase()),
            Some(first.clone()),
            "the handle names the identity, not its spelling"
        );
        assert!(!first.contains("1111"), "{first}");
        assert!(handles.handle("not-a-uuid").is_none());
    }

    #[test]
    fn handles_are_scoped_to_the_node_key() {
        let a = UserHandles::from_entry(&entry(&[7; 32])).expect("key must derive");
        let b = UserHandles::from_entry(&entry(&[8; 32])).expect("key must derive");

        assert_ne!(a.handle(USER), b.handle(USER));
        assert_ne!(
            a.handle(USER),
            a.handle("22222222-2222-4222-8222-222222222222")
        );
    }

    #[test]
    fn the_debug_rendering_reveals_no_key_material() {
        let handles = UserHandles::from_entry(&entry(&[7; 32])).expect("key must derive");

        assert_eq!(format!("{handles:?}"), "UserHandles([REDACTED])");
    }

    #[test]
    fn handle_shape_is_strict() {
        assert!(UserHandles::is_handle(&format!("u_{}", "0".repeat(32))));
        assert!(!UserHandles::is_handle(&format!("u_{}", "A".repeat(32))));
        assert!(!UserHandles::is_handle(&format!("x_{}", "0".repeat(32))));
        assert!(!UserHandles::is_handle(&format!("u_{}", "0".repeat(31))));
        assert!(!UserHandles::is_handle(USER));
    }
}
