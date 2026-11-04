//! Closed-vocabulary connection diagnostics. No error display text is retained.

use serde::Serialize;

/// The operation that failed, without a destination or user identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    /// A public node selected and connected an outbound.
    OutboundConnect,
    /// LINE connected or wrote its authenticated Handoff transfer.
    HandoffTransfer,
    /// LINE waited for the first resumed TLS downlink byte.
    HandoffFirstDownlink,
    /// LINE relayed a transferred session's ciphertext.
    HandoffRelay,
    /// LANDING accepted a socket but had not yet authenticated the peer.
    ///
    /// Covers pre-auth idle admission, pressure reclaim, descriptor budget at
    /// the LANDING listener, and the pre-auth idle wait timeout. Quiet warm
    /// peer-close / generation retirement stay unprojected (`detail` is
    /// `None`) because they are ordinary lifecycle, not rejections.
    LandingPreAuth,
    /// LANDING authenticated a Handoff/NXR transfer (protocol, replay, clock,
    /// allocation, or auth-body read) before destination dial.
    LandingAuthenticate,
    /// LANDING connected the authenticated destination.
    LandingDestination,
    /// LANDING connected its explicitly configured egress.
    LandingEgress,
    /// An authenticated session relayed application data.
    SessionRelay,
    /// LINE authorized, opened, or relayed an XUDP (Vision UDP) association:
    /// Direct UDP egress, the NXR UDP carrier, or the native Handoff UDP
    /// channel toward LANDING (ADR 0069).
    XudpRelay,
}

/// A bounded local cause. Neither OS error messages nor protocol input appear.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCause {
    /// An operation deadline elapsed.
    Timeout,
    /// A peer refused a TCP connection.
    ConnectionRefused,
    /// A peer reset an existing TCP connection.
    ConnectionReset,
    /// An established connection was aborted.
    ConnectionAborted,
    /// The OS reported no route to the network or host.
    Unreachable,
    /// An OS access policy denied the operation.
    PermissionDenied,
    /// The requested local address was unavailable.
    AddressUnavailable,
    /// A peer ended an incomplete operation.
    UnexpectedEof,
    /// Other I/O failure; numeric errno is retained when available.
    Io,
    /// An admission policy refused new work.
    Admission,
    /// The process descriptor authority refused a socket.
    DescriptorBudget,
    /// A bounded allocation failed.
    Allocation,
    /// The configured route or address policy could not be used.
    Policy,
    /// An authenticated protocol operation failed.
    Protocol,
    /// The local clock could not supply a valid timestamp.
    Clock,
    /// Entropy generation failed.
    Entropy,
    /// The silent Handoff protocol supplied no valid first downlink.
    LandingRejected,
    /// An internal ownership invariant failed.
    Internal,
}

/// Optional failure detail on the existing rejection event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FailureDetail {
    /// Fixed operation category.
    pub stage: FailureStage,
    /// Fixed failure category.
    pub cause: FailureCause,
    /// Raw OS error number, never its potentially sensitive display text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
}
