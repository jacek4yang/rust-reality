//! The local control endpoint.
//!
//! Absent means the process exposes no control interface at all: there is no
//! default socket path and never a network listener. Present means one Unix
//! domain socket, owner-only, that local programs use to inspect the running
//! generation and to publish users and short IDs into a new one. The protocol
//! itself is documented in the control API reference; this module owns only
//! the operator input.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The local control endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ControlConfig {
    /// Absolute filesystem path of the control Unix domain socket.
    ///
    /// The server creates it at startup with owner-only permissions and
    /// removes a stale socket left at the same path. The parent directory must
    /// already exist and should itself be private to the service account.
    /// Process lifetime: a change requires a restart.
    pub socket: PathBuf,
}

impl ControlConfig {
    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

#[cfg(test)]
mod tests {
    use super::ControlConfig;

    #[test]
    fn a_control_section_names_only_its_socket() {
        let control: ControlConfig =
            serde_json::from_str(r#"{"socket":"/run/rust-reality/control.sock"}"#)
                .expect("control must decode");

        assert_eq!(
            control.socket().to_str(),
            Some("/run/rust-reality/control.sock")
        );
    }

    #[test]
    fn unknown_control_fields_are_rejected() {
        assert!(
            serde_json::from_str::<ControlConfig>(
                r#"{"socket":"/run/c.sock","listen":"0.0.0.0:9"}"#
            )
            .is_err(),
            "there is no network listener to configure"
        );
        assert!(serde_json::from_str::<ControlConfig>("{}").is_err());
    }
}
