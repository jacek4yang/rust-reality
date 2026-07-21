use std::net::{Ipv4Addr, Ipv6Addr};

/// VLESS protocol version implemented by current Xray-core releases.
pub const VERSION: u8 = 0;

/// The 16-byte user identifier carried in a VLESS request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UserId([u8; 16]);

impl UserId {
    /// Creates a user identifier from its wire representation.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier's wire representation.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A command carried by a VLESS request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    /// Establish a TCP stream to a destination.
    Tcp = 0x01,

    /// Exchange UDP packets with a destination.
    Udp = 0x02,

    /// Establish a VLESS multiplexed stream.
    Mux = 0x03,

    /// Establish a reverse-proxy stream.
    Reverse = 0x04,
}

impl Command {
    /// Returns the command's wire value.
    pub const fn as_bytes(self) -> u8 {
        self as u8
    }

    /// Returns whether the command is followed by a destination.
    pub const fn requires_destination(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
}

/// A destination address carried by a VLESS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Address {
    /// A four-byte IPv4 address.
    Ipv4(Ipv4Addr),

    /// A Length-prefixed domain name.
    Domain(String),

    /// A sixteen-byte IPv6 address.
    Ipv6(Ipv6Addr),
}

/// A destination address and port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    address: Address,
    port: u16,
}

impl Destination {
    /// Creates a destination.
    pub fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    /// Returns the destination address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the destination port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A decoded VLESS request header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    version: u8,
    user_id: UserId,
    addons: Vec<u8>,
    command: Command,
    destination: Option<Destination>,
}

impl RequestHeader {
    pub(crate) fn new(
        version: u8,
        user_id: UserId,
        addons: Vec<u8>,
        command: Command,
        destination: Option<Destination>,
    ) -> Self {
        Self {
            version,
            user_id,
            addons,
            command,
            destination,
        }
    }

    /// Returns the decoded protocol version.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the user identifier.
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Returns the raw Addons protobuf bytes.
    pub fn addons(&self) -> &[u8] {
        &self.addons
    }

    /// Returns the request command.
    pub const fn command(&self) -> Command {
        self.command
    }

    /// Returns the destination for commands that carry one.
    pub fn destination(&self) -> Option<&Destination> {
        self.destination.as_ref()
    }
}
