use crate::{
    KonclaveDomainError, ProtocolVersion, ShortCodePairingAttemptId, ShortCodePairingLocator,
};

/// Maximum opaque bytes in one short-code relay stage.
pub const MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES: usize = 9 * 1024;
/// Maximum encoded request or single-stage response bytes.
pub const MAX_SHORT_CODE_RELAY_MESSAGE_BYTES: usize = 10 * 1024;
/// Maximum encoded snapshot bytes for all bounded stages.
pub const MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES: usize = 64 * 1024;
/// Maximum stages retained for one short-code attempt.
pub const MAX_SHORT_CODE_RELAY_STAGES: usize = 7;

/// Ordered opaque short-code pairing exchange stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ShortCodeRelayStage {
    /// Claimant's OPAQUE credential request, committed by the atomic claim.
    CredentialRequest = 1,
    /// Creator's OPAQUE credential response.
    CredentialResponse = 2,
    /// Claimant's OPAQUE finalization plus protected identity.
    ClaimantFinalization = 3,
    /// Creator's protected identity.
    CreatorIdentity = 4,
    /// Creator's explicit final-transcript confirmation.
    CreatorConfirmation = 5,
    /// Claimant's explicit final-transcript confirmation.
    ClaimantConfirmation = 6,
    /// Creator's protected member-only pairing capability.
    Capability = 7,
}

/// Creates one bounded short-code attempt at the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortCodeAttemptPublishRequest {
    version: ProtocolVersion,
    locator: ShortCodePairingLocator,
    attempt_id: ShortCodePairingAttemptId,
    deadline_unix_seconds: u64,
}

impl ShortCodeAttemptPublishRequest {
    /// Creates one validated publish request.
    ///
    /// # Errors
    ///
    /// Returns a zero-value error when the deadline is zero.
    pub fn new(
        version: ProtocolVersion,
        locator: ShortCodePairingLocator,
        attempt_id: ShortCodePairingAttemptId,
        deadline_unix_seconds: u64,
    ) -> Result<Self, KonclaveDomainError> {
        if deadline_unix_seconds == 0 {
            return Err(KonclaveDomainError::ZeroValue {
                field: "short_code_pairing_deadline",
            });
        }
        Ok(Self {
            version,
            locator,
            attempt_id,
            deadline_unix_seconds,
        })
    }

    /// Returns the application protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the non-secret code locator.
    #[must_use]
    pub const fn locator(self) -> ShortCodePairingLocator {
        self.locator
    }

    /// Returns the random attempt identifier.
    #[must_use]
    pub const fn attempt_id(self) -> ShortCodePairingAttemptId {
        self.attempt_id
    }

    /// Returns the absolute attempt deadline.
    #[must_use]
    pub const fn deadline_unix_seconds(self) -> u64 {
        self.deadline_unix_seconds
    }
}

/// Atomically claims one code locator with an OPAQUE credential request.
pub struct ShortCodeAttemptClaimRequest {
    version: ProtocolVersion,
    locator: ShortCodePairingLocator,
    payload: Vec<u8>,
}

impl ShortCodeAttemptClaimRequest {
    /// Creates one bounded claim request.
    ///
    /// # Errors
    ///
    /// Returns a size error for empty or oversized OPAQUE request bytes.
    pub fn new(
        version: ProtocolVersion,
        locator: ShortCodePairingLocator,
        payload: Vec<u8>,
    ) -> Result<Self, KonclaveDomainError> {
        validate_payload(&payload)?;
        Ok(Self {
            version,
            locator,
            payload,
        })
    }

    /// Returns the application protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the non-secret code locator.
    #[must_use]
    pub const fn locator(&self) -> ShortCodePairingLocator {
        self.locator
    }

    /// Returns the bounded opaque credential request.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Publishes one exact opaque exchange stage.
pub struct ShortCodeAttemptMessageRequest {
    version: ProtocolVersion,
    attempt_id: ShortCodePairingAttemptId,
    stage: ShortCodeRelayStage,
    payload: Vec<u8>,
}

impl ShortCodeAttemptMessageRequest {
    /// Creates one bounded stage request.
    ///
    /// # Errors
    ///
    /// Returns a size error for empty or oversized stage bytes.
    pub fn new(
        version: ProtocolVersion,
        attempt_id: ShortCodePairingAttemptId,
        stage: ShortCodeRelayStage,
        payload: Vec<u8>,
    ) -> Result<Self, KonclaveDomainError> {
        validate_payload(&payload)?;
        Ok(Self {
            version,
            attempt_id,
            stage,
            payload,
        })
    }

    /// Returns the application protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the target attempt identifier.
    #[must_use]
    pub const fn attempt_id(&self) -> ShortCodePairingAttemptId {
        self.attempt_id
    }

    /// Returns the exchange stage.
    #[must_use]
    pub const fn stage(&self) -> ShortCodeRelayStage {
        self.stage
    }

    /// Returns the bounded opaque stage bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Reads one attempt for its authenticated creator or claimant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortCodeAttemptReadRequest {
    version: ProtocolVersion,
    attempt_id: ShortCodePairingAttemptId,
}

impl ShortCodeAttemptReadRequest {
    /// Creates one participant-scoped read, cancellation, or capability-take request.
    #[must_use]
    pub const fn new(version: ProtocolVersion, attempt_id: ShortCodePairingAttemptId) -> Self {
        Self {
            version,
            attempt_id,
        }
    }

    /// Returns the application protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the target attempt identifier.
    #[must_use]
    pub const fn attempt_id(self) -> ShortCodePairingAttemptId {
        self.attempt_id
    }
}

/// One opaque durable stage returned only to an authenticated participant.
pub struct ShortCodeRelayMessage {
    stage: ShortCodeRelayStage,
    payload: Vec<u8>,
}

impl ShortCodeRelayMessage {
    /// Creates one validated returned stage.
    ///
    /// # Errors
    ///
    /// Returns a size error for empty or oversized stage bytes.
    pub fn new(stage: ShortCodeRelayStage, payload: Vec<u8>) -> Result<Self, KonclaveDomainError> {
        validate_payload(&payload)?;
        Ok(Self { stage, payload })
    }

    /// Returns the exchange stage.
    #[must_use]
    pub const fn stage(&self) -> ShortCodeRelayStage {
        self.stage
    }

    /// Returns the bounded opaque stage bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Authenticated bounded snapshot of one short-code attempt.
pub struct ShortCodeAttemptSnapshot {
    version: ProtocolVersion,
    attempt_id: ShortCodePairingAttemptId,
    deadline_unix_seconds: u64,
    cancelled: bool,
    capability_consumed: bool,
    messages: Vec<ShortCodeRelayMessage>,
}

impl ShortCodeAttemptSnapshot {
    /// Creates one validated snapshot.
    ///
    /// # Errors
    ///
    /// Returns a deadline, stage-count, duplicate-stage, or payload error.
    pub fn new(
        version: ProtocolVersion,
        attempt_id: ShortCodePairingAttemptId,
        deadline_unix_seconds: u64,
        cancelled: bool,
        capability_consumed: bool,
        mut messages: Vec<ShortCodeRelayMessage>,
    ) -> Result<Self, KonclaveDomainError> {
        if deadline_unix_seconds == 0 {
            return Err(KonclaveDomainError::ZeroValue {
                field: "short_code_pairing_deadline",
            });
        }
        if messages.len() > MAX_SHORT_CODE_RELAY_STAGES {
            return Err(KonclaveDomainError::OutOfRange {
                field: "short_code_pairing_stages",
                minimum: 0,
                maximum: MAX_SHORT_CODE_RELAY_STAGES,
                actual: messages.len(),
            });
        }
        messages.sort_by_key(ShortCodeRelayMessage::stage);
        if messages
            .windows(2)
            .any(|pair| pair[0].stage() == pair[1].stage())
        {
            return Err(KonclaveDomainError::DuplicateIdentifier {
                field: "short_code_pairing_stage",
            });
        }
        Ok(Self {
            version,
            attempt_id,
            deadline_unix_seconds,
            cancelled,
            capability_consumed,
            messages,
        })
    }

    /// Returns the application protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the attempt identifier.
    #[must_use]
    pub const fn attempt_id(&self) -> ShortCodePairingAttemptId {
        self.attempt_id
    }

    /// Returns the absolute attempt deadline.
    #[must_use]
    pub const fn deadline_unix_seconds(&self) -> u64 {
        self.deadline_unix_seconds
    }

    /// Reports whether either participant cancelled the attempt.
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Reports whether the claimant already consumed the capability.
    #[must_use]
    pub const fn capability_consumed(&self) -> bool {
        self.capability_consumed
    }

    /// Returns all visible opaque stages in canonical order.
    #[must_use]
    pub fn messages(&self) -> &[ShortCodeRelayMessage] {
        &self.messages
    }

    /// Returns one visible opaque stage when present.
    #[must_use]
    pub fn message(&self, stage: ShortCodeRelayStage) -> Option<&[u8]> {
        self.messages
            .iter()
            .find(|message| message.stage() == stage)
            .map(ShortCodeRelayMessage::payload)
    }
}

fn validate_payload(payload: &[u8]) -> Result<(), KonclaveDomainError> {
    if !(1..=MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES).contains(&payload.len()) {
        return Err(KonclaveDomainError::OutOfRange {
            field: "short_code_pairing_payload",
            minimum: 1,
            maximum: MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
            actual: payload.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_sorts_unique_bounded_stages() {
        let snapshot = ShortCodeAttemptSnapshot::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingAttemptId::from_bytes([1; 16]),
            10,
            false,
            false,
            vec![
                ShortCodeRelayMessage::new(ShortCodeRelayStage::Capability, vec![2]).unwrap(),
                ShortCodeRelayMessage::new(ShortCodeRelayStage::CredentialRequest, vec![1])
                    .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            snapshot.messages()[0].stage(),
            ShortCodeRelayStage::CredentialRequest
        );
        assert!(
            ShortCodeAttemptSnapshot::new(
                ProtocolVersion::application_v1(),
                ShortCodePairingAttemptId::from_bytes([1; 16]),
                10,
                false,
                false,
                vec![
                    ShortCodeRelayMessage::new(ShortCodeRelayStage::CredentialRequest, vec![1],)
                        .unwrap(),
                    ShortCodeRelayMessage::new(ShortCodeRelayStage::CredentialRequest, vec![2],)
                        .unwrap(),
                ],
            )
            .is_err()
        );
    }
}
