//! The protected string type shared by every configuration secret.
//!
//! A secret never appears in a `Debug` rendering, is zeroed on drop, and is
//! exposed only where code explicitly asks for the contents. Configuration
//! diagnostics consult the source map to redact secret spans before building
//! an excerpt, so this type guards the in-memory value and the diagnostic
//! layer guards the rendered one.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string whose debug representation never reveals its contents.
#[derive(Clone, Eq, PartialEq, Deserialize, JsonSchema, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a protected string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Exposes the secret to code that explicitly needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns whether the secret is empty without revealing it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn debug_never_reveals_the_contents() {
        let secret = SecretString::new("super-secret-value");

        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
        assert!(!format!("{secret:?}").contains("super-secret-value"));
        assert_eq!(secret.expose(), "super-secret-value");
        assert!(!secret.is_empty());
        assert!(SecretString::new("").is_empty());
    }

    #[test]
    fn transparent_serde_round_trips_the_bare_string() {
        let json = "\"abc\"";
        let secret: SecretString = serde_json::from_str(json).expect("secret must decode");

        assert_eq!(secret.expose(), "abc");
        assert_eq!(
            serde_json::to_string(&secret).expect("secret must encode"),
            json
        );
    }
}
