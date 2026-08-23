use thiserror::Error;

/// Stable failures produced while establishing an authenticated adapter channel.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdapterTransportError {
    /// The peer offered a protocol version this build does not implement.
    #[error("adapter protocol version is unsupported")]
    UnsupportedVersion,

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
            Self::InvalidIdentifier { .. } => "adapter_invalid_identifier",
            Self::UnusableCapabilityFile => "adapter_unusable_capability_file",
            Self::CapabilityFileNotOwnerProtected => "adapter_capability_not_owner_protected",
            Self::MalformedCapability => "adapter_malformed_capability",
            Self::UnauthenticPeer => "adapter_unauthentic_peer",
            Self::UnusableKeyMaterial => "adapter_unusable_key_material",
        }
    }
}
