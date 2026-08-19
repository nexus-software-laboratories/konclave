use KonclaveDomainCore::KonclaveDomainError;
use KonclaveProtocolContracts::KonclaveProtocolError;
use thiserror::Error;

/// Stable relay submission, authorization, sequencing, and storage failures.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayError {
    /// The authenticated principal lacks the requested route permission.
    #[error("principal is not authorized for this relay route")]
    Unauthorized,

    /// An envelope is already expired when submitted.
    #[error("relay envelope is already expired")]
    ExpiredEnvelope,

    /// An idempotency identifier was reused with different envelope content.
    #[error("relay envelope identifier was reused with different content")]
    IdempotencyConflict,

    /// Exact encoded bytes do not represent the supplied validated envelope.
    #[error("encoded relay envelope does not match its validated fields")]
    EnvelopeEncodingMismatch,

    /// Proposal or Commit serialization targeted a stale parent epoch.
    #[error("relay expected parent epoch does not match current route epoch")]
    StaleEpoch,

    /// A cursor or epoch exceeds the SQLite signed-integer range.
    #[error("relay sequence has exhausted its supported range")]
    SequenceExhausted,

    /// An acknowledgment exceeds the highest assigned route cursor.
    #[error("acknowledgment exceeds the highest assigned cursor")]
    InvalidAcknowledgment,

    /// System time is unavailable.
    #[error("relay clock is unavailable")]
    ClockUnavailable,

    /// The persistence backend rejected an operation.
    #[error("relay storage failed during {operation}")]
    StorageFailure { operation: &'static str },

    /// The database was created by an unsupported relay schema.
    #[error("relay database schema version {actual} is unsupported")]
    UnsupportedSchemaVersion { actual: u32 },

    /// Stored data violates the validated relay contract.
    #[error("stored relay data is invalid")]
    InvalidStoredData,

    /// Protocol encoding or decoding rejected an envelope or replay page.
    #[error(transparent)]
    Protocol(#[from] KonclaveProtocolError),

    /// Domain validation rejected relay input or stored data.
    #[error(transparent)]
    Domain(#[from] KonclaveDomainError),
}

impl RelayError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "relay_unauthorized",
            Self::ExpiredEnvelope => "relay_envelope_expired",
            Self::IdempotencyConflict => "relay_idempotency_conflict",
            Self::EnvelopeEncodingMismatch => "relay_envelope_encoding_mismatch",
            Self::StaleEpoch => "relay_stale_epoch",
            Self::SequenceExhausted => "relay_sequence_exhausted",
            Self::InvalidAcknowledgment => "relay_invalid_acknowledgment",
            Self::ClockUnavailable => "relay_clock_unavailable",
            Self::StorageFailure { .. } => "relay_storage_failure",
            Self::UnsupportedSchemaVersion { .. } => "relay_schema_unsupported",
            Self::InvalidStoredData => "relay_invalid_stored_data",
            Self::Protocol(error) => error.code(),
            Self::Domain(error) => error.code(),
        }
    }
}
