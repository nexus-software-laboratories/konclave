use KonclaveDomainCore::{
    DeviceId, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
    MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES, MAX_SHORT_CODE_RELAY_STAGES, ShortCodeAttemptClaimRequest,
    ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest,
    ShortCodeAttemptSnapshot, ShortCodeCapabilityTakeId, ShortCodeCapabilityTakeRequest,
    ShortCodeConfirmationRecord, ShortCodeIdentityRecord, ShortCodePairingAttemptId,
    ShortCodePairingLocator, ShortCodePairingSas, ShortCodePairingTranscriptHash,
    ShortCodeRelayMessage, ShortCodeRelayStage,
};

use super::common::{
    decode_bounded, encode_bounded, require_repeated_field_limits, required, version_from_wire,
    version_to_wire,
};
use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

const PUBLISH_CONTRACT: &str = "ShortCodeAttemptPublishRequest";
const CLAIM_CONTRACT: &str = "ShortCodeAttemptClaimRequest";
const MESSAGE_CONTRACT: &str = "ShortCodeAttemptMessageRequest";
const READ_CONTRACT: &str = "ShortCodeAttemptReadRequest";
const TAKE_CONTRACT: &str = "ShortCodeCapabilityTakeRequest";
const SNAPSHOT_CONTRACT: &str = "ShortCodeAttemptSnapshot";
const CAPABILITY_CONTRACT: &str = "ShortCodeCapabilityResponse";
const PROTECTED_CONTRACT: &str = "ShortCodeProtectedRecord";
const FINALIZATION_CONTRACT: &str = "ShortCodeClaimantFinalizationRecord";
const IDENTITY_CONTRACT: &str = "ShortCodeIdentityRecord";
const CONFIRMATION_CONTRACT: &str = "ShortCodeConfirmationRecord";
const SHORT_CODE_NONCE_BYTES: usize = 12;
const SHORT_CODE_TAG_BYTES: usize = 16;
const MAX_SHORT_CODE_PROTECTED_PLAINTEXT_BYTES: usize = 8 * 1024;
const MAX_SHORT_CODE_PROTECTED_CIPHERTEXT_BYTES: usize =
    MAX_SHORT_CODE_PROTECTED_PLAINTEXT_BYTES + SHORT_CODE_TAG_BYTES;
const MAX_OPAQUE_FINALIZATION_BYTES: usize = 4 * 1024;

/// Encodes one bounded short-code attempt publish request.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds its protocol bound.
pub fn encode_short_code_attempt_publish_request(
    value: ShortCodeAttemptPublishRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeAttemptPublishRequest {
            version: Some(version_to_wire(value.version())),
            locator: Some(locator_to_wire(value.locator())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
            deadline_unix_seconds: value.deadline_unix_seconds(),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        PUBLISH_CONTRACT,
    )
}

/// Decodes and validates one untrusted short-code attempt publish request.
///
/// # Errors
///
/// Returns a protocol, version, identifier, or deadline validation error.
pub fn decode_short_code_attempt_publish_request(
    bytes: &[u8],
) -> Result<ShortCodeAttemptPublishRequest, KonclaveProtocolError> {
    let value: wire::ShortCodeAttemptPublishRequest =
        decode_bounded(bytes, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, PUBLISH_CONTRACT)?;
    Ok(ShortCodeAttemptPublishRequest::new(
        version_from_wire(value.version, PUBLISH_CONTRACT)?,
        locator_from_wire(value.locator)?,
        attempt_id_from_wire(value.attempt_id)?,
        value.deadline_unix_seconds,
    )?)
}

/// Encodes one bounded locator claim request.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds its protocol bound.
pub fn encode_short_code_attempt_claim_request(
    value: &ShortCodeAttemptClaimRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeAttemptClaimRequest {
            version: Some(version_to_wire(value.version())),
            locator: Some(locator_to_wire(value.locator())),
            payload: value.payload().to_vec().into(),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        CLAIM_CONTRACT,
    )
}

/// Decodes and validates one untrusted locator claim request.
///
/// # Errors
///
/// Returns a protocol, version, locator, or payload validation error.
pub fn decode_short_code_attempt_claim_request(
    bytes: &[u8],
) -> Result<ShortCodeAttemptClaimRequest, KonclaveProtocolError> {
    let value: wire::ShortCodeAttemptClaimRequest =
        decode_bounded(bytes, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, CLAIM_CONTRACT)?;
    Ok(ShortCodeAttemptClaimRequest::new(
        version_from_wire(value.version, CLAIM_CONTRACT)?,
        locator_from_wire(value.locator)?,
        bounded_payload(value.payload.to_vec())?,
    )?)
}

/// Encodes one bounded opaque short-code exchange stage.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds its protocol bound.
pub fn encode_short_code_attempt_message_request(
    value: &ShortCodeAttemptMessageRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeAttemptMessageRequest {
            version: Some(version_to_wire(value.version())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
            stage: stage_to_wire(value.stage()) as i32,
            payload: value.payload().to_vec().into(),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        MESSAGE_CONTRACT,
    )
}

/// Decodes and validates one untrusted opaque short-code exchange stage.
///
/// # Errors
///
/// Returns a protocol, version, identifier, stage, or payload validation error.
pub fn decode_short_code_attempt_message_request(
    bytes: &[u8],
) -> Result<ShortCodeAttemptMessageRequest, KonclaveProtocolError> {
    let value: wire::ShortCodeAttemptMessageRequest =
        decode_bounded(bytes, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, MESSAGE_CONTRACT)?;
    Ok(ShortCodeAttemptMessageRequest::new(
        version_from_wire(value.version, MESSAGE_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
        stage_from_wire(value.stage)?,
        bounded_payload(value.payload.to_vec())?,
    )?)
}

/// Encodes one bounded short-code attempt read request.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds its protocol bound.
pub fn encode_short_code_attempt_read_request(
    value: ShortCodeAttemptReadRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeAttemptReadRequest {
            version: Some(version_to_wire(value.version())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        READ_CONTRACT,
    )
}

/// Decodes and validates one untrusted short-code attempt read request.
///
/// # Errors
///
/// Returns a protocol, version, or identifier validation error.
pub fn decode_short_code_attempt_read_request(
    bytes: &[u8],
) -> Result<ShortCodeAttemptReadRequest, KonclaveProtocolError> {
    let value: wire::ShortCodeAttemptReadRequest =
        decode_bounded(bytes, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, READ_CONTRACT)?;
    Ok(ShortCodeAttemptReadRequest::new(
        version_from_wire(value.version, READ_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
    ))
}

/// Encodes one bounded idempotent capability retrieval request.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds its protocol bound.
pub fn encode_short_code_capability_take_request(
    value: ShortCodeCapabilityTakeRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeCapabilityTakeRequest {
            version: Some(version_to_wire(value.version())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
            take_id: Some(take_id_to_wire(value.take_id())),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        TAKE_CONTRACT,
    )
}

/// Decodes and validates one untrusted idempotent capability retrieval request.
///
/// # Errors
///
/// Returns a protocol, version, attempt, or take-identifier validation error.
pub fn decode_short_code_capability_take_request(
    bytes: &[u8],
) -> Result<ShortCodeCapabilityTakeRequest, KonclaveProtocolError> {
    let value: wire::ShortCodeCapabilityTakeRequest =
        decode_bounded(bytes, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, TAKE_CONTRACT)?;
    Ok(ShortCodeCapabilityTakeRequest::new(
        version_from_wire(value.version, TAKE_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
        take_id_from_wire(value.take_id)?,
    ))
}

/// Encodes one capability-filtered short-code attempt snapshot.
///
/// # Errors
///
/// Returns a size error when the encoded snapshot exceeds its protocol bound.
pub fn encode_short_code_attempt_snapshot(
    value: &ShortCodeAttemptSnapshot,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeAttemptSnapshot {
            version: Some(version_to_wire(value.version())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
            deadline_unix_seconds: value.deadline_unix_seconds(),
            cancelled: value.cancelled(),
            capability_consumed: value.capability_consumed(),
            messages: value
                .messages()
                .iter()
                .map(|message| wire::ShortCodeRelayMessage {
                    stage: stage_to_wire(message.stage()) as i32,
                    payload: message.payload().to_vec().into(),
                })
                .collect(),
        },
        MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES,
        SNAPSHOT_CONTRACT,
    )
}

/// Decodes and validates one untrusted short-code attempt snapshot.
///
/// # Errors
///
/// Returns a protocol, version, identifier, stage-count, stage, or payload error.
pub fn decode_short_code_attempt_snapshot(
    bytes: &[u8],
) -> Result<ShortCodeAttemptSnapshot, KonclaveProtocolError> {
    require_repeated_field_limits(
        bytes,
        MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES,
        SNAPSHOT_CONTRACT,
        [(6, MAX_SHORT_CODE_RELAY_STAGES, "short_code_pairing_stages")],
    )?;
    let value: wire::ShortCodeAttemptSnapshot = decode_bounded(
        bytes,
        MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES,
        SNAPSHOT_CONTRACT,
    )?;
    let messages = value
        .messages
        .into_iter()
        .map(|message| {
            Ok(ShortCodeRelayMessage::new(
                stage_from_wire(message.stage)?,
                bounded_payload(message.payload.to_vec())?,
            )?)
        })
        .collect::<Result<Vec<_>, KonclaveProtocolError>>()?;
    Ok(ShortCodeAttemptSnapshot::new(
        version_from_wire(value.version, SNAPSHOT_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
        value.deadline_unix_seconds,
        value.cancelled,
        value.capability_consumed,
        messages,
    )?)
}

/// Encodes one bounded opaque capability response.
///
/// # Errors
///
/// Returns a size or payload validation error.
pub fn encode_short_code_capability_response(
    version: KonclaveDomainCore::ProtocolVersion,
    attempt_id: ShortCodePairingAttemptId,
    payload: &[u8],
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeCapabilityResponse {
            version: Some(version_to_wire(version)),
            attempt_id: Some(attempt_id_to_wire(attempt_id)),
            payload: bounded_payload(payload.to_vec())?.into(),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        CAPABILITY_CONTRACT,
    )
}

/// Decodes and validates one untrusted opaque capability response.
///
/// # Errors
///
/// Returns a protocol, version, identifier, or payload validation error.
pub fn decode_short_code_capability_response(
    bytes: &[u8],
) -> Result<
    (
        KonclaveDomainCore::ProtocolVersion,
        ShortCodePairingAttemptId,
        Vec<u8>,
    ),
    KonclaveProtocolError,
> {
    let value: wire::ShortCodeCapabilityResponse = decode_bounded(
        bytes,
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        CAPABILITY_CONTRACT,
    )?;
    Ok((
        version_from_wire(value.version, CAPABILITY_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
        bounded_payload(value.payload.to_vec())?,
    ))
}

/// Encodes one bounded nonce-bearing encrypted short-code record.
///
/// # Errors
///
/// Returns a nonce, ciphertext, or encoded-size validation error.
pub fn encode_short_code_protected_record(
    nonce: &[u8; SHORT_CODE_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KonclaveProtocolError> {
    validate_protected_ciphertext(ciphertext)?;
    encode_bounded(
        &wire::ShortCodeProtectedRecord {
            nonce: nonce.to_vec().into(),
            ciphertext: ciphertext.to_vec().into(),
        },
        MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
        PROTECTED_CONTRACT,
    )
}

/// Decodes and validates one untrusted encrypted short-code record.
///
/// # Errors
///
/// Returns a nonce, ciphertext, or encoded-size validation error.
pub fn decode_short_code_protected_record(
    bytes: &[u8],
) -> Result<([u8; SHORT_CODE_NONCE_BYTES], Vec<u8>), KonclaveProtocolError> {
    let value: wire::ShortCodeProtectedRecord = decode_bounded(
        bytes,
        MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
        PROTECTED_CONTRACT,
    )?;
    let nonce = value.nonce.as_ref().try_into().map_err(|_| {
        KonclaveDomainCore::KonclaveDomainError::InvalidLength {
            field: "short_code_protected_nonce",
            expected: SHORT_CODE_NONCE_BYTES,
            actual: value.nonce.len(),
        }
    })?;
    let ciphertext = value.ciphertext.to_vec();
    validate_protected_ciphertext(&ciphertext)?;
    Ok((nonce, ciphertext))
}

/// Encodes the claimant's OPAQUE finalization and protected identity as one stage.
///
/// # Errors
///
/// Returns a finalization, protected-record, or encoded-size validation error.
pub fn encode_short_code_claimant_finalization_record(
    finalization: &[u8],
    protected_identity: &[u8],
) -> Result<Vec<u8>, KonclaveProtocolError> {
    validate_finalization(finalization)?;
    decode_short_code_protected_record(protected_identity)?;
    encode_bounded(
        &wire::ShortCodeClaimantFinalizationRecord {
            finalization: finalization.to_vec().into(),
            protected_identity: protected_identity.to_vec().into(),
        },
        MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
        FINALIZATION_CONTRACT,
    )
}

/// Decodes and validates the claimant's combined finalization stage.
///
/// # Errors
///
/// Returns a finalization, protected-record, or encoded-size validation error.
pub fn decode_short_code_claimant_finalization_record(
    bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KonclaveProtocolError> {
    let value: wire::ShortCodeClaimantFinalizationRecord = decode_bounded(
        bytes,
        MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
        FINALIZATION_CONTRACT,
    )?;
    let finalization = value.finalization.to_vec();
    let protected_identity = value.protected_identity.to_vec();
    validate_finalization(&finalization)?;
    decode_short_code_protected_record(&protected_identity)?;
    Ok((finalization, protected_identity))
}

/// Encodes one decrypted short-code identity descriptor.
///
/// # Errors
///
/// Returns an encoded-size validation error.
pub fn encode_short_code_identity_record(
    value: ShortCodeIdentityRecord,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeIdentityRecord {
            version: Some(version_to_wire(value.version())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
            device_id: Some(device_id_to_wire(value.device_id())),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        IDENTITY_CONTRACT,
    )
}

/// Decodes and validates one decrypted short-code identity descriptor.
///
/// # Errors
///
/// Returns a protocol, version, attempt, or device-identifier validation error.
pub fn decode_short_code_identity_record(
    bytes: &[u8],
) -> Result<ShortCodeIdentityRecord, KonclaveProtocolError> {
    let value: wire::ShortCodeIdentityRecord =
        decode_bounded(bytes, MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, IDENTITY_CONTRACT)?;
    Ok(ShortCodeIdentityRecord::new(
        version_from_wire(value.version, IDENTITY_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
        device_id_from_wire(value.device_id)?,
    ))
}

/// Encodes one decrypted explicit short-code transcript confirmation.
///
/// # Errors
///
/// Returns an encoded-size validation error.
pub fn encode_short_code_confirmation_record(
    value: ShortCodeConfirmationRecord,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::ShortCodeConfirmationRecord {
            version: Some(version_to_wire(value.version())),
            attempt_id: Some(attempt_id_to_wire(value.attempt_id())),
            creator_device_id: Some(device_id_to_wire(value.creator_device_id())),
            claimant_device_id: Some(device_id_to_wire(value.claimant_device_id())),
            transcript_hash: value.transcript_hash().as_bytes().to_vec().into(),
            sas: value.sas().value(),
        },
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        CONFIRMATION_CONTRACT,
    )
}

/// Decodes and validates one decrypted explicit short-code transcript confirmation.
///
/// # Errors
///
/// Returns a protocol, identity, transcript, or SAS validation error.
pub fn decode_short_code_confirmation_record(
    bytes: &[u8],
) -> Result<ShortCodeConfirmationRecord, KonclaveProtocolError> {
    let value: wire::ShortCodeConfirmationRecord = decode_bounded(
        bytes,
        MAX_SHORT_CODE_RELAY_MESSAGE_BYTES,
        CONFIRMATION_CONTRACT,
    )?;
    Ok(ShortCodeConfirmationRecord::new(
        version_from_wire(value.version, CONFIRMATION_CONTRACT)?,
        attempt_id_from_wire(value.attempt_id)?,
        device_id_from_wire(value.creator_device_id)?,
        device_id_from_wire(value.claimant_device_id)?,
        ShortCodePairingTranscriptHash::from_slice(&value.transcript_hash)?,
        ShortCodePairingSas::new(value.sas)?,
    ))
}

fn validate_protected_ciphertext(ciphertext: &[u8]) -> Result<(), KonclaveProtocolError> {
    if !(SHORT_CODE_TAG_BYTES..=MAX_SHORT_CODE_PROTECTED_CIPHERTEXT_BYTES)
        .contains(&ciphertext.len())
    {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "short_code_protected_ciphertext",
            minimum: SHORT_CODE_TAG_BYTES,
            maximum: MAX_SHORT_CODE_PROTECTED_CIPHERTEXT_BYTES,
            actual: ciphertext.len(),
        }
        .into());
    }
    Ok(())
}

fn validate_finalization(finalization: &[u8]) -> Result<(), KonclaveProtocolError> {
    if !(1..=MAX_OPAQUE_FINALIZATION_BYTES).contains(&finalization.len()) {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "short_code_opaque_finalization",
            minimum: 1,
            maximum: MAX_OPAQUE_FINALIZATION_BYTES,
            actual: finalization.len(),
        }
        .into());
    }
    Ok(())
}

fn bounded_payload(payload: Vec<u8>) -> Result<Vec<u8>, KonclaveProtocolError> {
    if !(1..=MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES).contains(&payload.len()) {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "short_code_pairing_payload",
            minimum: 1,
            maximum: MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
            actual: payload.len(),
        }
        .into());
    }
    Ok(payload)
}

fn attempt_id_to_wire(value: ShortCodePairingAttemptId) -> wire::ShortCodePairingAttemptId {
    wire::ShortCodePairingAttemptId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn attempt_id_from_wire(
    value: Option<wire::ShortCodePairingAttemptId>,
) -> Result<ShortCodePairingAttemptId, KonclaveProtocolError> {
    Ok(ShortCodePairingAttemptId::from_slice(
        &required(value, "short_code_pairing_attempt_id")?.value,
    )?)
}

fn locator_to_wire(value: ShortCodePairingLocator) -> wire::ShortCodePairingLocator {
    wire::ShortCodePairingLocator {
        value: value.as_bytes().to_vec().into(),
    }
}

fn locator_from_wire(
    value: Option<wire::ShortCodePairingLocator>,
) -> Result<ShortCodePairingLocator, KonclaveProtocolError> {
    Ok(ShortCodePairingLocator::from_slice(
        &required(value, "short_code_pairing_locator")?.value,
    )?)
}

fn device_id_to_wire(value: DeviceId) -> wire::DeviceId {
    wire::DeviceId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn device_id_from_wire(value: Option<wire::DeviceId>) -> Result<DeviceId, KonclaveProtocolError> {
    Ok(DeviceId::from_slice(
        &required(value, "short_code_device_id")?.value,
    )?)
}

fn take_id_to_wire(value: ShortCodeCapabilityTakeId) -> wire::ShortCodeCapabilityTakeId {
    wire::ShortCodeCapabilityTakeId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn take_id_from_wire(
    value: Option<wire::ShortCodeCapabilityTakeId>,
) -> Result<ShortCodeCapabilityTakeId, KonclaveProtocolError> {
    Ok(ShortCodeCapabilityTakeId::from_slice(
        &required(value, "short_code_capability_take_id")?.value,
    )?)
}

const fn stage_to_wire(value: ShortCodeRelayStage) -> wire::ShortCodeRelayStage {
    match value {
        ShortCodeRelayStage::CredentialRequest => wire::ShortCodeRelayStage::CredentialRequest,
        ShortCodeRelayStage::CredentialResponse => wire::ShortCodeRelayStage::CredentialResponse,
        ShortCodeRelayStage::ClaimantFinalization => {
            wire::ShortCodeRelayStage::ClaimantFinalization
        }
        ShortCodeRelayStage::CreatorIdentity => wire::ShortCodeRelayStage::CreatorIdentity,
        ShortCodeRelayStage::CreatorConfirmation => wire::ShortCodeRelayStage::CreatorConfirmation,
        ShortCodeRelayStage::ClaimantConfirmation => {
            wire::ShortCodeRelayStage::ClaimantConfirmation
        }
        ShortCodeRelayStage::Capability => wire::ShortCodeRelayStage::Capability,
    }
}

fn stage_from_wire(value: i32) -> Result<ShortCodeRelayStage, KonclaveProtocolError> {
    match wire::ShortCodeRelayStage::try_from(value) {
        Ok(wire::ShortCodeRelayStage::CredentialRequest) => {
            Ok(ShortCodeRelayStage::CredentialRequest)
        }
        Ok(wire::ShortCodeRelayStage::CredentialResponse) => {
            Ok(ShortCodeRelayStage::CredentialResponse)
        }
        Ok(wire::ShortCodeRelayStage::ClaimantFinalization) => {
            Ok(ShortCodeRelayStage::ClaimantFinalization)
        }
        Ok(wire::ShortCodeRelayStage::CreatorIdentity) => Ok(ShortCodeRelayStage::CreatorIdentity),
        Ok(wire::ShortCodeRelayStage::CreatorConfirmation) => {
            Ok(ShortCodeRelayStage::CreatorConfirmation)
        }
        Ok(wire::ShortCodeRelayStage::ClaimantConfirmation) => {
            Ok(ShortCodeRelayStage::ClaimantConfirmation)
        }
        Ok(wire::ShortCodeRelayStage::Capability) => Ok(ShortCodeRelayStage::Capability),
        _ => Err(KonclaveProtocolError::UnsupportedEnum {
            field: "short_code_relay_stage",
            value,
        }),
    }
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::ProtocolVersion;

    use super::*;

    fn attempt() -> ShortCodePairingAttemptId {
        ShortCodePairingAttemptId::from_bytes([1; 16])
    }

    #[test]
    fn requests_and_snapshot_round_trip() {
        let version = ProtocolVersion::application_v1();
        let publish = ShortCodeAttemptPublishRequest::new(
            version,
            ShortCodePairingLocator::from_bytes([2; 32]),
            attempt(),
            100,
        )
        .unwrap();
        assert_eq!(
            decode_short_code_attempt_publish_request(
                &encode_short_code_attempt_publish_request(publish).unwrap()
            )
            .unwrap(),
            publish
        );
        let claim =
            ShortCodeAttemptClaimRequest::new(version, publish.locator(), vec![3; 32]).unwrap();
        let decoded_claim = decode_short_code_attempt_claim_request(
            &encode_short_code_attempt_claim_request(&claim).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded_claim.payload(), claim.payload());
        let message = ShortCodeAttemptMessageRequest::new(
            version,
            attempt(),
            ShortCodeRelayStage::CredentialResponse,
            vec![4; 32],
        )
        .unwrap();
        let decoded_message = decode_short_code_attempt_message_request(
            &encode_short_code_attempt_message_request(&message).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded_message.stage(), message.stage());
        assert_eq!(decoded_message.payload(), message.payload());
        let snapshot = ShortCodeAttemptSnapshot::new(
            version,
            attempt(),
            100,
            false,
            false,
            vec![ShortCodeRelayMessage::new(message.stage(), vec![4; 32]).unwrap()],
        )
        .unwrap();
        let decoded_snapshot = decode_short_code_attempt_snapshot(
            &encode_short_code_attempt_snapshot(&snapshot).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded_snapshot.attempt_id(), attempt());
        assert_eq!(
            decoded_snapshot.message(ShortCodeRelayStage::CredentialResponse),
            Some(&[4; 32][..])
        );
        let take = ShortCodeCapabilityTakeRequest::new(
            version,
            attempt(),
            ShortCodeCapabilityTakeId::from_bytes([5; 16]),
        );
        assert_eq!(
            decode_short_code_capability_take_request(
                &encode_short_code_capability_take_request(take).unwrap()
            )
            .unwrap(),
            take
        );
        let protected = encode_short_code_protected_record(&[6; 12], &[7; 16]).unwrap();
        assert_eq!(
            decode_short_code_protected_record(&protected).unwrap(),
            ([6; 12], vec![7; 16])
        );
        let finalization =
            encode_short_code_claimant_finalization_record(&[8; 32], &protected).unwrap();
        assert_eq!(
            decode_short_code_claimant_finalization_record(&finalization).unwrap(),
            (vec![8; 32], protected)
        );
        let identity = ShortCodeIdentityRecord::new(
            version,
            attempt(),
            DeviceId::from_bytes([9; DeviceId::LENGTH]),
        );
        assert!(
            decode_short_code_identity_record(
                &encode_short_code_identity_record(identity).unwrap()
            )
            .unwrap()
                == identity
        );
        let confirmation = ShortCodeConfirmationRecord::new(
            version,
            attempt(),
            DeviceId::from_bytes([9; DeviceId::LENGTH]),
            DeviceId::from_bytes([10; DeviceId::LENGTH]),
            ShortCodePairingTranscriptHash::from_bytes(
                [11; ShortCodePairingTranscriptHash::LENGTH],
            ),
            ShortCodePairingSas::new(12).unwrap(),
        );
        let decoded = decode_short_code_confirmation_record(
            &encode_short_code_confirmation_record(confirmation).unwrap(),
        )
        .unwrap();
        assert!(decoded == confirmation);
    }

    #[test]
    fn malformed_stage_payload_and_version_fail_closed() {
        let wire = wire::ShortCodeAttemptMessageRequest {
            version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
            attempt_id: Some(attempt_id_to_wire(attempt())),
            stage: 99,
            payload: vec![1].into(),
        };
        assert!(
            decode_short_code_attempt_message_request(&prost::Message::encode_to_vec(&wire))
                .is_err()
        );
        let wire = wire::ShortCodeAttemptClaimRequest {
            version: Some(wire::ProtocolVersion { major: 2, minor: 0 }),
            locator: Some(locator_to_wire(ShortCodePairingLocator::from_bytes(
                [2; 32],
            ))),
            payload: vec![0; MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES + 1].into(),
        };
        assert!(
            decode_short_code_attempt_claim_request(&prost::Message::encode_to_vec(&wire)).is_err()
        );
        assert!(decode_short_code_protected_record(&[]).is_err());
        assert!(encode_short_code_protected_record(&[0; 12], &[0; 15]).is_err());
        assert!(encode_short_code_claimant_finalization_record(&[], &[0]).is_err());
    }
}
