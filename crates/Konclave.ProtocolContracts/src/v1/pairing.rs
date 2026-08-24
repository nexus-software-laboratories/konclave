use KonclaveDomainCore::{
    MAX_MEMBERS, MAX_PAIRING_CIPHERTEXT_BYTES, MAX_PAIRING_WELCOME_BYTES, MAX_RELAY_PAYLOAD_BYTES,
    PairingControl, PairingEnvelope, PairingInvitationPayload, PairingNonce, PairingSenderRole,
    PairingStage, PairingWelcomePayload,
};

use crate::KonclaveProtocolError;
use crate::v1::common::{
    conversation_id_from_wire, conversation_id_to_wire, decode_bounded, device_id_from_wire,
    device_id_to_wire, encode_bounded, pairing_id_from_wire, pairing_id_to_wire,
    pairing_message_id_from_wire, pairing_message_id_to_wire, public_key_from_bytes,
    public_key_to_bytes, require_repeated_field_limits, required, signature_from_bytes,
    signature_to_bytes, version_from_wire, version_to_wire,
};
use crate::v1::identity::{
    credential_from_wire, credential_to_wire, invitation_from_wire, invitation_to_wire,
};
use crate::wire::v1 as wire;

const PAIRING_ENVELOPE_CONTRACT: &str = "PairingEnvelope";
const PAIRING_INVITATION_CONTRACT: &str = "PairingInvitationPayload";
const PAIRING_WELCOME_CONTRACT: &str = "PairingWelcomePayload";
const PAIRING_CONTROL_CONTRACT: &str = "PairingControl";

/// Encodes one authenticated pairing envelope.
///
/// # Errors
///
/// Returns a size error when the encoded envelope exceeds the relay payload bound.
pub fn encode_pairing_envelope(value: &PairingEnvelope) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = wire::PairingEnvelope {
        version: Some(version_to_wire(value.version())),
        pairing_id: Some(pairing_id_to_wire(value.pairing_id())),
        message_id: Some(pairing_message_id_to_wire(value.message_id())),
        sender: sender_to_wire(value.sender()),
        stage: stage_to_wire(value.stage()),
        in_reply_to: value.in_reply_to().map(pairing_message_id_to_wire),
        expires_at_unix_seconds: value.expires_at_unix_seconds(),
        nonce: prost::bytes::Bytes::copy_from_slice(value.nonce().as_bytes()),
        ciphertext: prost::bytes::Bytes::copy_from_slice(value.ciphertext()),
    };
    encode_bounded(&wire, MAX_RELAY_PAYLOAD_BYTES, PAIRING_ENVELOPE_CONTRACT)
}

/// Decodes and shape-validates one authenticated pairing envelope.
///
/// This function does not authenticate ciphertext. It validates the finite stage
/// grammar and allocation bounds before the cryptographic core opens the record.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_pairing_envelope(bytes: &[u8]) -> Result<PairingEnvelope, KonclaveProtocolError> {
    let value = decode_bounded(bytes, MAX_RELAY_PAYLOAD_BYTES, PAIRING_ENVELOPE_CONTRACT)?;
    pairing_envelope_from_wire(value)
}

/// Encodes inviter-authorized invitation material.
///
/// # Errors
///
/// Returns a size error when the payload exceeds the relay payload bound.
pub fn encode_pairing_invitation(
    value: &PairingInvitationPayload,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::PairingInvitationPayload {
            invitation: Some(invitation_to_wire(value.invitation())),
            issuer_public_key: public_key_to_bytes(value.issuer_public_key()),
            peer_bindings: value
                .peer_bindings()
                .iter()
                .map(credential_to_wire)
                .collect(),
        },
        MAX_RELAY_PAYLOAD_BYTES,
        PAIRING_INVITATION_CONTRACT,
    )
}

/// Decodes and shape-validates inviter-authorized invitation material.
///
/// Signature verification remains the caller's responsibility.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error. Repeated binding count is
/// bounded before protobuf materialization.
pub fn decode_pairing_invitation(
    bytes: &[u8],
) -> Result<PairingInvitationPayload, KonclaveProtocolError> {
    require_repeated_field_limits(
        bytes,
        MAX_RELAY_PAYLOAD_BYTES,
        PAIRING_INVITATION_CONTRACT,
        [(3, MAX_MEMBERS, "pairing_peer_bindings")],
    )?;
    let value: wire::PairingInvitationPayload =
        decode_bounded(bytes, MAX_RELAY_PAYLOAD_BYTES, PAIRING_INVITATION_CONTRACT)?;
    Ok(PairingInvitationPayload::new(
        invitation_from_wire(required(value.invitation, "pairing_invitation.invitation")?)?,
        public_key_from_bytes(&value.issuer_public_key)?,
        value
            .peer_bindings
            .into_iter()
            .map(credential_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}

/// Encodes one opaque Welcome and add-Commit receipt cursor.
///
/// # Errors
///
/// Returns a size error when the payload exceeds the relay payload bound.
pub fn encode_pairing_welcome(
    value: &PairingWelcomePayload,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::PairingWelcomePayload {
            conversation_id: Some(conversation_id_to_wire(value.conversation_id())),
            welcome: prost::bytes::Bytes::copy_from_slice(value.welcome()),
            commit_cursor: value.commit_cursor(),
        },
        MAX_RELAY_PAYLOAD_BYTES,
        PAIRING_WELCOME_CONTRACT,
    )
}

/// Decodes and bounds one opaque Welcome and receipt cursor.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_pairing_welcome(
    bytes: &[u8],
) -> Result<PairingWelcomePayload, KonclaveProtocolError> {
    let value: wire::PairingWelcomePayload =
        decode_bounded(bytes, MAX_RELAY_PAYLOAD_BYTES, PAIRING_WELCOME_CONTRACT)?;
    if value.welcome.len() > MAX_PAIRING_WELCOME_BYTES {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "pairing_welcome",
            minimum: 1,
            maximum: MAX_PAIRING_WELCOME_BYTES,
            actual: value.welcome.len(),
        }
        .into());
    }
    Ok(PairingWelcomePayload::new(
        conversation_id_from_wire(value.conversation_id)?,
        value.welcome.to_vec(),
        value.commit_cursor,
    )?)
}

/// Encodes root-signed pairing completion or cancellation authority.
///
/// # Errors
///
/// Returns a size error when the payload exceeds the relay payload bound.
pub fn encode_pairing_control(value: &PairingControl) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::PairingControl {
            version: Some(version_to_wire(value.version())),
            pairing_id: Some(pairing_id_to_wire(value.pairing_id())),
            message_id: Some(pairing_message_id_to_wire(value.message_id())),
            stage: stage_to_wire(value.stage()),
            in_reply_to: Some(pairing_message_id_to_wire(value.in_reply_to())),
            device_id: Some(device_id_to_wire(value.device_id())),
            conversation_id: Some(conversation_id_to_wire(value.conversation_id())),
            device_signature: signature_to_bytes(value.device_signature()),
        },
        MAX_RELAY_PAYLOAD_BYTES,
        PAIRING_CONTROL_CONTRACT,
    )
}

/// Decodes and shape-validates root-signed pairing control authority.
///
/// Signature verification remains the caller's responsibility.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_pairing_control(bytes: &[u8]) -> Result<PairingControl, KonclaveProtocolError> {
    let value: wire::PairingControl =
        decode_bounded(bytes, MAX_RELAY_PAYLOAD_BYTES, PAIRING_CONTROL_CONTRACT)?;
    Ok(PairingControl::new(
        version_from_wire(value.version, PAIRING_CONTROL_CONTRACT)?,
        pairing_id_from_wire(value.pairing_id)?,
        pairing_message_id_from_wire(value.message_id)?,
        stage_from_wire(value.stage)?,
        pairing_message_id_from_wire(value.in_reply_to)?,
        device_id_from_wire(value.device_id)?,
        conversation_id_from_wire(value.conversation_id)?,
        signature_from_bytes(&value.device_signature)?,
    )?)
}

fn pairing_envelope_from_wire(
    value: wire::PairingEnvelope,
) -> Result<PairingEnvelope, KonclaveProtocolError> {
    if value.ciphertext.len() > MAX_PAIRING_CIPHERTEXT_BYTES {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "pairing_ciphertext",
            minimum: 16,
            maximum: MAX_PAIRING_CIPHERTEXT_BYTES,
            actual: value.ciphertext.len(),
        }
        .into());
    }
    Ok(PairingEnvelope::new(
        version_from_wire(value.version, PAIRING_ENVELOPE_CONTRACT)?,
        pairing_id_from_wire(value.pairing_id)?,
        pairing_message_id_from_wire(value.message_id)?,
        sender_from_wire(value.sender)?,
        stage_from_wire(value.stage)?,
        value
            .in_reply_to
            .map(|identifier| pairing_message_id_from_wire(Some(identifier)))
            .transpose()?,
        value.expires_at_unix_seconds,
        PairingNonce::from_slice(&value.nonce)?,
        value.ciphertext.to_vec(),
    )?)
}

fn sender_to_wire(value: PairingSenderRole) -> i32 {
    match value {
        PairingSenderRole::Joiner => wire::PairingSenderRole::Joiner as i32,
        PairingSenderRole::Inviter => wire::PairingSenderRole::Inviter as i32,
    }
}

fn sender_from_wire(value: i32) -> Result<PairingSenderRole, KonclaveProtocolError> {
    match wire::PairingSenderRole::try_from(value) {
        Ok(wire::PairingSenderRole::Joiner) => Ok(PairingSenderRole::Joiner),
        Ok(wire::PairingSenderRole::Inviter) => Ok(PairingSenderRole::Inviter),
        _ => Err(KonclaveProtocolError::UnsupportedEnum {
            field: "pairing_sender_role",
            value,
        }),
    }
}

fn stage_to_wire(value: PairingStage) -> i32 {
    match value {
        PairingStage::Invitation => wire::PairingStage::Invitation as i32,
        PairingStage::JoinProof => wire::PairingStage::JoinProof as i32,
        PairingStage::Welcome => wire::PairingStage::Welcome as i32,
        PairingStage::Completion => wire::PairingStage::Completion as i32,
        PairingStage::Cancellation => wire::PairingStage::Cancellation as i32,
    }
}

fn stage_from_wire(value: i32) -> Result<PairingStage, KonclaveProtocolError> {
    match wire::PairingStage::try_from(value) {
        Ok(wire::PairingStage::Invitation) => Ok(PairingStage::Invitation),
        Ok(wire::PairingStage::JoinProof) => Ok(PairingStage::JoinProof),
        Ok(wire::PairingStage::Welcome) => Ok(PairingStage::Welcome),
        Ok(wire::PairingStage::Completion) => Ok(PairingStage::Completion),
        Ok(wire::PairingStage::Cancellation) => Ok(PairingStage::Cancellation),
        _ => Err(KonclaveProtocolError::UnsupportedEnum {
            field: "pairing_stage",
            value,
        }),
    }
}
