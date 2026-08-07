/// Byte counts produced by a completed bidirectional relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayStats {
    inbound_to_outbound: u64,
    outbound_to_inbound: u64,
}

impl RelayStats {
    pub(crate) const fn new(inbound_to_outbound: u64, outbound_to_inbound: u64) -> Self {
        Self {
            inbound_to_outbound,
            outbound_to_inbound,
        }
    }

    /// Returns the bytes copied from the inbound stream to the outbound stream.
    pub fn inbound_to_outbound_bytes(&self) -> u64 {
        self.inbound_to_outbound
    }

    /// Returns the bytes copied from the outbound stream to the inbound stream.
    pub fn outbound_to_inbound_bytes(&self) -> u64 {
        self.outbound_to_inbound
    }
}
