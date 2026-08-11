use std::{error::Error, fmt};

use super::{Addons, AddonsDecodeError, Command, Destination, RequestHeader, UserId, VISION_FLOW};
use crate::user_map::AdaptiveUserMap;

/// Stores VLESS users authorized to establish sessions.
#[derive(Clone, Debug, Default)]
pub struct UserRegistry {
    users: AdaptiveUserMap<()>,
}

impl UserRegistry {
    /// Creates a registry from an iterator of authorized user IDs.
    pub fn new(users: impl IntoIterator<Item = UserId>) -> Self {
        Self {
            users: AdaptiveUserMap::from_entries(users.into_iter().map(|user_id| (user_id, ()))),
        }
    }

    /// Returns whether the user ID is registered.
    pub fn contains(&self, user_id: UserId) -> bool {
        self.find(user_id).is_some()
    }

    /// Authorizes an already decoded request for the supported plain TCP mode.
    ///
    /// Within this policy check, user authorization is evaluated before command
    /// and Addons restrictions. Wire-level decoding has already completed before
    /// this method is called.
    pub fn authorize_plain_tcp<'a>(
        &self,
        request: &'a RequestHeader,
    ) -> Result<&'a Destination, RequestValidationError> {
        if !self.contains(request.user_id()) {
            return Err(RequestValidationError::UnauthorizedUser);
        }

        if !request.addons().is_empty() {
            return Err(RequestValidationError::UnsupportedAddons {
                length: request.addons().len(),
            });
        }

        if request.command() != Command::Tcp {
            return Err(RequestValidationError::UnsupportedCommand(
                request.command(),
            ));
        }

        request
            .destination()
            .ok_or(RequestValidationError::MissingDestination)
    }

    fn find(&self, user_id: UserId) -> Option<&()> {
        self.users.get(&user_id)
    }
}

/// Authorizes an Xray-compatible VLESS Vision TCP request after REALITY has
/// authenticated the short ID and resolved its owning UUID.
///
/// The owner UUID is the authorization authority for this request. It comes
/// from the same validated client entry as the short ID, so rebuilding and
/// probing a second UUID registry would duplicate state without strengthening
/// the decision.
pub fn authorize_authenticated_vision_tcp(
    request: &RequestHeader,
    authenticated_user_id: UserId,
) -> Result<&Destination, RequestValidationError> {
    validate_authenticated_vision_fields(
        request.user_id(),
        request.addons(),
        request.command(),
        request.destination().is_some(),
        authenticated_user_id,
    )?;
    request
        .destination()
        .ok_or(RequestValidationError::MissingDestination)
}

pub(crate) fn validate_authenticated_vision_fields(
    request_user_id: UserId,
    addons: &[u8],
    command: Command,
    has_destination: bool,
    authenticated_user_id: UserId,
) -> Result<(), RequestValidationError> {
    if request_user_id != authenticated_user_id {
        return Err(RequestValidationError::ShortIdOwnerMismatch);
    }

    let addons = Addons::parse(addons).map_err(RequestValidationError::Addons)?;
    if addons.flow() != Some(VISION_FLOW) {
        return Err(RequestValidationError::VisionFlowRequired);
    }

    if command != Command::Tcp {
        return Err(RequestValidationError::UnsupportedCommand(command));
    }

    if !has_destination {
        return Err(RequestValidationError::MissingDestination);
    }
    Ok(())
}

/// An error produced while applying the current VLESS request policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestValidationError {
    /// The request user ID is not registered.
    UnauthorizedUser,

    /// The REALITY handshake short ID is not owned by the decoded UUID.
    ShortIdOwnerMismatch,

    /// The current plain VLESS mode does not support request Addons.
    UnsupportedAddons { length: usize },

    /// The request Addons protobuf was malformed.
    Addons(AddonsDecodeError),

    /// The production inbound requires `xtls-rprx-vision` exactly.
    VisionFlowRequired,

    /// The current server implementation does not support the command.
    UnsupportedCommand(Command),

    /// A TCP request did not contain a destination.
    MissingDestination,
}

impl fmt::Display for RequestValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnauthorizedUser => formatter.write_str("VLESS request user is not authorized"),
            Self::ShortIdOwnerMismatch => {
                formatter.write_str("REALITY short ID is not owned by the VLESS user")
            }
            Self::UnsupportedAddons { length } => write!(
                formatter,
                "VLESS request contains {length} unsupported \
                    Addons bytes"
            ),
            Self::Addons(error) => write!(formatter, "invalid VLESS Addons: {error}"),
            Self::VisionFlowRequired => {
                formatter.write_str("VLESS request requires xtls-rprx-vision flow")
            }
            Self::UnsupportedCommand(command) => {
                write!(formatter, "VLESS command {command:?} is not supported")
            }
            Self::MissingDestination => formatter.write_str("VLESS TCP request has no destination"),
        }
    }
}

impl Error for RequestValidationError {}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{RequestValidationError, UserRegistry, authorize_authenticated_vision_tcp};
    use crate::protocol::vless::{Address, Command, Destination, RequestHeader, UserId, VERSION};

    const ALLOWED_USER: UserId = UserId::new([0x11; 16]);
    const UNKNOWN_USER: UserId = UserId::new([0x22; 16]);

    #[test]
    fn authorizes_registered_plain_tcp_request() {
        let registry = registry();

        let request = request_header(ALLOWED_USER, Vec::new(), Command::Tcp, Some(destination()));

        let authorized_destination = registry
            .authorize_plain_tcp(&request)
            .expect("registered TCP request should be authorized");

        assert_eq!(authorized_destination, &destination());
    }

    #[test]
    fn rejects_unknown_user_before_capability_checks() {
        let registry = registry();

        let request = request_header(UNKNOWN_USER, vec![0xaa], Command::Udp, Some(destination()));

        assert_eq!(
            registry.authorize_plain_tcp(&request),
            Err(RequestValidationError::UnauthorizedUser)
        );
    }

    #[test]
    fn rejects_request_addons() {
        let registry = registry();

        let request = request_header(
            ALLOWED_USER,
            vec![0xaa, 0xbb],
            Command::Tcp,
            Some(destination()),
        );

        assert_eq!(
            registry.authorize_plain_tcp(&request),
            Err(RequestValidationError::UnsupportedAddons { length: 2 })
        );
    }

    #[test]
    fn rejects_unsupported_command() {
        let registry = registry();

        let request = request_header(ALLOWED_USER, Vec::new(), Command::Udp, Some(destination()));

        assert_eq!(
            registry.authorize_plain_tcp(&request),
            Err(RequestValidationError::UnsupportedCommand(Command::Udp))
        );
    }

    #[test]
    fn rejects_tcp_request_without_destination() {
        let registry = registry();

        let request = request_header(ALLOWED_USER, Vec::new(), Command::Tcp, None);

        assert_eq!(
            registry.authorize_plain_tcp(&request),
            Err(RequestValidationError::MissingDestination)
        );
    }

    #[test]
    fn authorizes_registered_vision_tcp_request() {
        let request = request_header(
            ALLOWED_USER,
            vision_addons(),
            Command::Tcp,
            Some(destination()),
        );

        let authorized_destination = authorize_authenticated_vision_tcp(&request, ALLOWED_USER)
            .expect("registered Vision TCP request should be authorized");

        assert_eq!(authorized_destination, &destination());
    }

    #[test]
    fn rejects_plain_request_on_vision_inbound() {
        let request = request_header(ALLOWED_USER, Vec::new(), Command::Tcp, Some(destination()));

        assert_eq!(
            authorize_authenticated_vision_tcp(&request, ALLOWED_USER),
            Err(RequestValidationError::VisionFlowRequired)
        );
    }

    #[test]
    fn rejects_malformed_vision_addons() {
        let request = request_header(
            ALLOWED_USER,
            vec![0x0a, 0x20, b'x'],
            Command::Tcp,
            Some(destination()),
        );

        assert_eq!(
            authorize_authenticated_vision_tcp(&request, ALLOWED_USER),
            Err(RequestValidationError::Addons(
                crate::protocol::vless::AddonsDecodeError::Truncated
            ))
        );
    }

    #[test]
    fn rejects_short_id_owned_by_a_different_uuid() {
        let request = request_header(
            ALLOWED_USER,
            vision_addons(),
            Command::Tcp,
            Some(destination()),
        );

        assert_eq!(
            authorize_authenticated_vision_tcp(&request, UNKNOWN_USER),
            Err(RequestValidationError::ShortIdOwnerMismatch)
        );
    }

    fn registry() -> UserRegistry {
        UserRegistry::new([ALLOWED_USER])
    }

    fn destination() -> Destination {
        Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443)
    }

    fn request_header(
        user_id: UserId,
        addons: Vec<u8>,
        command: Command,
        destination: Option<Destination>,
    ) -> RequestHeader {
        RequestHeader::new(VERSION, user_id, addons, command, destination)
    }

    fn vision_addons() -> Vec<u8> {
        let mut addons = vec![0x0a, 0x10];
        addons.extend_from_slice(crate::protocol::vless::VISION_FLOW.as_bytes());
        addons
    }
}
