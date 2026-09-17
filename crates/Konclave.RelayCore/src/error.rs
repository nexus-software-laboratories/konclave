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

    /// An enrollment request identity conflicts with another principal or request.
    #[error("relay enrollment identity conflicts with an existing registration")]
    EnrollmentConflict,

    /// Dynamic principal registration reached its configured hard bound.
    #[error("relay dynamic principal capacity is exhausted")]
    PrincipalCapacityExceeded,

    /// A pairing rendezvous candidate or stored record is expired.
    #[error("pairing rendezvous record is expired")]
    ExpiredPairingRendezvous,

    /// A rendezvous lookup identifier was reused by another owner or with different content.
    #[error("pairing rendezvous identifier conflicts with an existing record")]
    PairingRendezvousConflict,

    /// A rendezvous record is absent or was already consumed.
    #[error("pairing rendezvous record is unavailable")]
    PairingRendezvousUnavailable,

    /// The relay-wide active rendezvous bound is exhausted.
    #[error("relay pairing rendezvous capacity is exhausted")]
    PairingRendezvousGlobalCapacityExceeded,

    /// One principal's active rendezvous bound is exhausted.
    #[error("relay principal pairing rendezvous capacity is exhausted")]
    PairingRendezvousPrincipalCapacityExceeded,

    /// A short-code attempt deadline exceeds the fixed active lifetime.
    #[error("short-code pairing deadline exceeds the permitted lifetime")]
    InvalidShortCodeDeadline,

    /// A short-code attempt is already expired.
    #[error("short-code pairing attempt is expired")]
    ExpiredShortCodeAttempt,

    /// A short-code identifier or existing stage conflicts with different state.
    #[error("short-code pairing attempt conflicts with existing state")]
    ShortCodeAttemptConflict,

    /// A short-code attempt is absent or intentionally hidden from this caller.
    #[error("short-code pairing attempt is unavailable")]
    ShortCodeAttemptUnavailable,

    /// One principal exhausted its bounded short-code claim window.
    #[error("short-code pairing claim rate is exhausted")]
    ShortCodeClaimRateLimited,

    /// The relay-wide active short-code attempt bound is exhausted.
    #[error("relay short-code pairing capacity is exhausted")]
    ShortCodeGlobalCapacityExceeded,

    /// One creator's active short-code attempt bound is exhausted.
    #[error("relay creator short-code pairing capacity is exhausted")]
    ShortCodeCreatorCapacityExceeded,

    /// An opaque stage was published by the wrong role or out of order.
    #[error("short-code pairing stage is invalid")]
    InvalidShortCodeStage,

    /// A previously registered principal has been revoked.
    #[error("relay principal is revoked")]
    PrincipalRevoked,

    /// Enrollment uses another protocol major version.
    #[error("relay enrollment protocol version is unsupported")]
    UnsupportedEnrollmentVersion,

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
            Self::EnrollmentConflict => "relay_enrollment_conflict",
            Self::PrincipalCapacityExceeded => "relay_principal_capacity",
            Self::ExpiredPairingRendezvous => "relay_pairing_rendezvous_expired",
            Self::PairingRendezvousConflict => "relay_pairing_rendezvous_conflict",
            Self::PairingRendezvousUnavailable => "relay_pairing_rendezvous_unavailable",
            Self::PairingRendezvousGlobalCapacityExceeded => {
                "relay_pairing_rendezvous_global_capacity"
            }
            Self::PairingRendezvousPrincipalCapacityExceeded => {
                "relay_pairing_rendezvous_principal_capacity"
            }
            Self::InvalidShortCodeDeadline => "relay_short_code_pairing_deadline_invalid",
            Self::ExpiredShortCodeAttempt => "relay_short_code_pairing_expired",
            Self::ShortCodeAttemptConflict => "relay_short_code_pairing_conflict",
            Self::ShortCodeAttemptUnavailable => "relay_short_code_pairing_unavailable",
            Self::ShortCodeClaimRateLimited => "relay_short_code_pairing_rate_limited",
            Self::ShortCodeGlobalCapacityExceeded => "relay_short_code_pairing_global_capacity",
            Self::ShortCodeCreatorCapacityExceeded => "relay_short_code_pairing_creator_capacity",
            Self::InvalidShortCodeStage => "relay_short_code_pairing_stage_invalid",
            Self::PrincipalRevoked => "relay_principal_revoked",
            Self::UnsupportedEnrollmentVersion => "relay_enrollment_version_unsupported",
            Self::ClockUnavailable => "relay_clock_unavailable",
            Self::StorageFailure { .. } => "relay_storage_failure",
            Self::UnsupportedSchemaVersion { .. } => "relay_schema_unsupported",
            Self::InvalidStoredData => "relay_invalid_stored_data",
            Self::Protocol(error) => error.code(),
            Self::Domain(error) => error.code(),
        }
    }
}
