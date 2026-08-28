use KonclaveDomainCore::KonclaveDomainError;
use KonclaveRelayAuthentication::RelayAuthenticationError;
use thiserror::Error;

/// Stable failures while decoding, validating, or encoding protocol contracts.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KonclaveProtocolError {
    /// Encoded bytes exceed the hard limit for the selected contract.
    #[error("{contract} exceeds {maximum} encoded bytes (actual: {actual})")]
    EncodedMessageTooLarge {
        contract: &'static str,
        maximum: usize,
        actual: usize,
    },

    /// Protocol Buffers rejected malformed wire bytes.
    #[error("{contract} is not valid Protocol Buffers: {reason}")]
    Decode {
        contract: &'static str,
        reason: String,
    },

    /// A message-valued field required by the domain contract is absent.
    #[error("required field {field} is missing")]
    MissingField { field: &'static str },

    /// An enum contains an unknown or unspecified value.
    #[error("field {field} has unsupported enum value {value}")]
    UnsupportedEnum { field: &'static str, value: i32 },

    /// A required oneof variant is absent.
    #[error("required oneof {field} is missing")]
    MissingVariant { field: &'static str },

    /// A content-addressed contract does not use its canonical encoding.
    #[error("{contract} is not canonically encoded")]
    NonCanonicalEncoding { contract: &'static str },

    /// A v1 DTO contains a different protocol major version.
    #[error("{contract} requires protocol major version 1 (actual: {actual})")]
    UnsupportedMajor { contract: &'static str, actual: u32 },

    /// Wire values fail domain validation.
    #[error(transparent)]
    Domain(#[from] KonclaveDomainError),

    /// Relay authentication or enrollment values fail validation.
    #[error(transparent)]
    RelayAuthentication(#[from] RelayAuthenticationError),
}

impl KonclaveProtocolError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EncodedMessageTooLarge { .. } => "encoded_message_too_large",
            Self::Decode { .. } => "malformed",
            Self::MissingField { .. } => "missing_field",
            Self::UnsupportedEnum { .. } => "unsupported_enum",
            Self::MissingVariant { .. } => "missing_variant",
            Self::NonCanonicalEncoding { .. } => "non_canonical_encoding",
            Self::UnsupportedMajor { .. } => "unsupported_major",
            Self::Domain(error) => error.code(),
            Self::RelayAuthentication(error) => error.code(),
        }
    }
}
