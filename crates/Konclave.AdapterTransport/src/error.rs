use thiserror::Error;

/// Stable failures produced while establishing an authenticated adapter channel.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdapterTransportError {
    /// The peer offered a protocol version this build does not implement.
    #[error("adapter protocol version is unsupported")]
    UnsupportedVersion,

    /// A frame declared more bytes than its stage permits.
    #[error("adapter frame exceeds its bound")]
    FrameTooLarge,

    /// A frame was empty, truncated, or carried bytes past its last field.
    #[error("adapter frame is malformed")]
    MalformedFrame,

    /// A frame carried a message tag this build does not implement.
    #[error("adapter message kind is unknown")]
    UnknownMessageKind,

    /// A valid message arrived out of handshake order.
    #[error("adapter message arrived out of order")]
    UnexpectedMessage,

    /// The peer answered for a profile this channel was not launched for.
    #[error("adapter channel profile does not match")]
    ProfileMismatch,

    /// The peer did not finish the handshake within its bound.
    #[error("adapter handshake did not complete in time")]
    HandshakeTimeout,

    /// The channel ended before the handshake completed.
    #[error("adapter channel closed")]
    ChannelClosed,

    /// The challenge source cannot issue another non-repeating value.
    #[error("adapter challenge source is exhausted")]
    ChallengeExhausted,

    /// The launch-provided endpoint is empty, oversized, or not a local endpoint.
    #[error("adapter endpoint is invalid")]
    InvalidEndpoint,

    /// The adapter endpoint could not be reached.
    #[error("adapter endpoint is unavailable")]
    EndpointUnavailable,

    /// A request or response value falls outside its declared bound.
    #[error("adapter request is outside its bound")]
    RequestOutOfBounds,

    /// A bounded identifier was empty, oversized, or not printable ASCII.
    #[error("adapter {field} identifier is invalid")]
    InvalidIdentifier { field: &'static str },

    /// The launch capability file is missing, unreadable, or not a plain file.
    #[error("adapter launch capability file is unusable")]
    UnusableCapabilityFile,

    /// The launch capability file is reachable by an account other than the owner.
    #[error("adapter launch capability file is not owner-protected")]
    CapabilityFileNotOwnerProtected,

    /// The launch capability file did not contain one canonical capability value.
    #[error("adapter launch capability file content is malformed")]
    MalformedCapability,

    /// A peer proof did not authenticate the negotiated transcript.
    #[error("adapter channel proof is not authentic")]
    UnauthenticPeer,

    /// The vetted cryptographic provider rejected the keyed operation.
    #[error("adapter channel authentication material is unusable")]
    UnusableKeyMaterial,
}

impl AdapterTransportError {
    /// Returns the stable machine-readable error code.
    ///
    /// A code never includes a challenge, capability, identifier, or path, so it is
    /// safe to log and to return on a failed handshake.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "adapter_unsupported_version",
            Self::FrameTooLarge => "adapter_frame_too_large",
            Self::MalformedFrame => "adapter_malformed_frame",
            Self::UnknownMessageKind => "adapter_unknown_message_kind",
            Self::UnexpectedMessage => "adapter_unexpected_message",
            Self::ProfileMismatch => "adapter_profile_mismatch",
            Self::HandshakeTimeout => "adapter_handshake_timeout",
            Self::ChannelClosed => "adapter_channel_closed",
            Self::ChallengeExhausted => "adapter_challenge_exhausted",
            Self::InvalidEndpoint => "adapter_invalid_endpoint",
            Self::EndpointUnavailable => "adapter_endpoint_unavailable",
            Self::RequestOutOfBounds => "adapter_request_out_of_bounds",
            Self::InvalidIdentifier { .. } => "adapter_invalid_identifier",
            Self::UnusableCapabilityFile => "adapter_unusable_capability_file",
            Self::CapabilityFileNotOwnerProtected => "adapter_capability_not_owner_protected",
            Self::MalformedCapability => "adapter_malformed_capability",
            Self::UnauthenticPeer => "adapter_unauthentic_peer",
            Self::UnusableKeyMaterial => "adapter_unusable_key_material",
        }
    }
}

impl From<KonclaveLocalFraming::FrameError> for AdapterTransportError {
    fn from(error: KonclaveLocalFraming::FrameError) -> Self {
        match error {
            KonclaveLocalFraming::FrameError::TooLarge => Self::FrameTooLarge,
            KonclaveLocalFraming::FrameError::Malformed => Self::MalformedFrame,
            KonclaveLocalFraming::FrameError::Closed => Self::ChannelClosed,
        }
    }
}
