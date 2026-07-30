use std::{collections::HashSet, error::Error, fmt};

use super::{Command, Destination, RequestHeader, UserId};

/// Stores VLESS users authorized to establish sessions.
#[derive(Clone, Debug, Default)]
pub struct UserRegistry {
    users: HashSet<UserId>,
}

impl UserRegistry {
    /// Creates a registry from an iterator of authorized user IDs.
    pub fn new(users: impl IntoIterator<Item = UserId>) -> Self {
        Self {
            users: users.into_iter().collect(),
        }
    }

    /// Returns whether the user ID is registered.
    pub fn contains(&self, user_id: UserId) -> bool {
        self.users.contains(&user_id)
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
}

/// An error produced while applying the current VLESS request policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestValidationError {
    /// The request user ID is not registered.
    UnauthorizedUser,

    /// The current plain VLESS mode does not support request Addons.
    UnsupportedAddons { length: usize },

    /// The current server implementation does not support the command.
    UnsupportedCommand(Command),

    /// A TCP request did not contain a destination.
    MissingDestination,
}

impl fmt::Display for RequestValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnauthorizedUser => formatter.write_str("VLESS request user is not authorized"),
            Self::UnsupportedAddons { length } => write!(
                formatter,
                "VLESS request contains {length} unsupported \
                    Addons bytes"
            ),
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

    use super::{RequestValidationError, UserRegistry};
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
}
