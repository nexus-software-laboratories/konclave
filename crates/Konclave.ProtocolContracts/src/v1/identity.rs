use KonclaveDomainCore::{
    DeviceCredentialBinding, Invitation, JoinProof, MAX_APPLICATION_MESSAGE_BYTES,
    MAX_MLS_KEY_PACKAGE_BYTES, PairingOffer, SignatureScheme,
};

use crate::KonclaveProtocolError;
use crate::v1::common::{
    decode_bounded, device_id_from_wire, device_id_to_wire, encode_bounded,
    invitation_id_from_wire, invitation_id_to_wire, nonce_from_bytes, nonce_to_bytes,
    pairing_context_hash_from_wire, pairing_context_hash_to_wire, pairing_id_from_wire,
    pairing_id_to_wire, public_key_from_bytes, public_key_to_bytes, role_from_wire, role_to_wire,
    routing_id_from_wire, routing_id_to_wire, signature_from_bytes, signature_to_bytes,
    version_from_wire, version_to_wire,
};
use crate::wire::v1 as wire;

const CREDENTIAL_CONTRACT: &str = "DeviceCredentialBinding";
const INVITATION_CONTRACT: &str = "Invitation";
const JOIN_PROOF_CONTRACT: &str = "JoinProof";
const PAIRING_OFFER_CONTRACT: &str = "PairingOffer";

/// Encodes a public device credential binding.
///
/// # Errors
///
/// Returns a size error when the encoded binding exceeds the v1 application limit.
pub fn encode_device_credential_binding(
    value: &DeviceCredentialBinding,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &credential_to_wire(value),
        MAX_APPLICATION_MESSAGE_BYTES,
        CREDENTIAL_CONTRACT,
    )
}

/// Decodes and shape-validates a public device credential binding.
///
/// This function does not verify the signature or derive the `DeviceId`.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_device_credential_binding(
    bytes: &[u8],
) -> Result<DeviceCredentialBinding, KonclaveProtocolError> {
    let wire = decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, CREDENTIAL_CONTRACT)?;
    credential_from_wire(wire)
}

/// Encodes an invitation.
///
/// # Errors
///
/// Returns a size error when the encoded invitation exceeds the v1 application limit.
pub fn encode_invitation(value: &Invitation) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &invitation_to_wire(value),
        MAX_APPLICATION_MESSAGE_BYTES,
        INVITATION_CONTRACT,
    )
}

/// Decodes and shape-validates an invitation.
///
/// This function does not verify the issuer signature or current expiration.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_invitation(bytes: &[u8]) -> Result<Invitation, KonclaveProtocolError> {
    let wire = decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, INVITATION_CONTRACT)?;
    invitation_from_wire(wire)
}

/// Encodes a pairing offer.
///
/// # Errors
///
/// Returns a size error when the encoded offer exceeds the v1 application limit.
pub fn encode_pairing_offer(value: &PairingOffer) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &pairing_offer_to_wire(value),
        MAX_APPLICATION_MESSAGE_BYTES,
        PAIRING_OFFER_CONTRACT,
    )
}

/// Decodes and shape-validates a pairing offer.
///
/// This function does not verify the device signature or current expiration. An offer
/// that decodes is still an unauthenticated claim until the cryptographic core has
/// re-derived its device identity from its own key.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_pairing_offer(bytes: &[u8]) -> Result<PairingOffer, KonclaveProtocolError> {
    let wire = decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, PAIRING_OFFER_CONTRACT)?;
    pairing_offer_from_wire(wire)
}

fn pairing_offer_to_wire(value: &PairingOffer) -> wire::PairingOffer {
    wire::PairingOffer {
        version: Some(version_to_wire(value.version())),
        pairing_id: Some(pairing_id_to_wire(value.pairing_id())),
        device_id: Some(device_id_to_wire(value.device_id())),
        device_root_public_key: public_key_to_bytes(value.device_root_public_key()),
        requested_role: role_to_wire(value.requested_role()),
        expires_at_unix_seconds: value.expires_at_unix_seconds(),
        device_signature: signature_to_bytes(value.device_signature()),
        context_hash: Some(pairing_context_hash_to_wire(value.context_hash())),
    }
}

fn pairing_offer_from_wire(
    value: wire::PairingOffer,
) -> Result<PairingOffer, KonclaveProtocolError> {
    Ok(PairingOffer::new(
        version_from_wire(value.version, PAIRING_OFFER_CONTRACT)?,
        pairing_id_from_wire(value.pairing_id)?,
        device_id_from_wire(value.device_id)?,
        public_key_from_bytes(&value.device_root_public_key)?,
        role_from_wire(value.requested_role)?,
        value.expires_at_unix_seconds,
        pairing_context_hash_from_wire(value.context_hash)?,
        signature_from_bytes(&value.device_signature)?,
    )?)
}

/// Encodes a join proof.
///
/// # Errors
///
/// Returns a size error when the encoded proof exceeds the v1 application limit.
pub fn encode_join_proof(value: &JoinProof) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = wire::JoinProof {
        invitation: Some(invitation_to_wire(value.invitation())),
        credential: Some(credential_to_wire(value.credential())),
        mls_key_package: prost::bytes::Bytes::copy_from_slice(value.mls_key_package()),
    };
    encode_bounded(&wire, MAX_APPLICATION_MESSAGE_BYTES, JOIN_PROOF_CONTRACT)
}

/// Decodes and shape-validates a join proof.
///
/// Cryptographic and authorization verification remains the caller's responsibility.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_join_proof(bytes: &[u8]) -> Result<JoinProof, KonclaveProtocolError> {
    let wire: wire::JoinProof =
        decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, JOIN_PROOF_CONTRACT)?;
    if wire.mls_key_package.is_empty() || wire.mls_key_package.len() > MAX_MLS_KEY_PACKAGE_BYTES {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "mls_key_package",
            minimum: 1,
            maximum: MAX_MLS_KEY_PACKAGE_BYTES,
            actual: wire.mls_key_package.len(),
        }
        .into());
    }
    Ok(JoinProof::new(
        invitation_from_wire(required(wire.invitation, "join_proof.invitation")?)?,
        credential_from_wire(required(wire.credential, "join_proof.credential")?)?,
        wire.mls_key_package.to_vec(),
    )?)
}

pub(super) fn credential_to_wire(value: &DeviceCredentialBinding) -> wire::DeviceCredentialBinding {
    wire::DeviceCredentialBinding {
        version: Some(version_to_wire(value.version())),
        device_id: Some(device_id_to_wire(value.device_id())),
        conversation_id: Some(super::common::conversation_id_to_wire(
            value.conversation_id(),
        )),
        signature_scheme: match value.signature_scheme() {
            SignatureScheme::Ed25519 => wire::SignatureScheme::Ed25519 as i32,
        },
        device_root_public_key: public_key_to_bytes(value.device_root_public_key()),
        conversation_signature_public_key: public_key_to_bytes(
            value.conversation_signature_public_key(),
        ),
        device_binding_signature: signature_to_bytes(value.device_binding_signature()),
    }
}

pub(super) fn credential_from_wire(
    wire: wire::DeviceCredentialBinding,
) -> Result<DeviceCredentialBinding, KonclaveProtocolError> {
    let signature_scheme = match wire::SignatureScheme::try_from(wire.signature_scheme) {
        Ok(wire::SignatureScheme::Ed25519) => SignatureScheme::Ed25519,
        _ => {
            return Err(KonclaveProtocolError::UnsupportedEnum {
                field: "signature_scheme",
                value: wire.signature_scheme,
            });
        }
    };
    Ok(DeviceCredentialBinding::new(
        version_from_wire(wire.version, CREDENTIAL_CONTRACT)?,
        device_id_from_wire(wire.device_id)?,
        super::common::conversation_id_from_wire(wire.conversation_id)?,
        signature_scheme,
        public_key_from_bytes(&wire.device_root_public_key)?,
        public_key_from_bytes(&wire.conversation_signature_public_key)?,
        signature_from_bytes(&wire.device_binding_signature)?,
    ))
}

pub(super) fn invitation_to_wire(value: &Invitation) -> wire::Invitation {
    wire::Invitation {
        version: Some(version_to_wire(value.version())),
        invitation_id: Some(invitation_id_to_wire(value.invitation_id())),
        conversation_id: Some(super::common::conversation_id_to_wire(
            value.conversation_id(),
        )),
        expected_device_id: Some(device_id_to_wire(value.expected_device_id())),
        role: super::common::role_to_wire(value.role()),
        expires_at_unix_seconds: value.expires_at_unix_seconds(),
        nonce: nonce_to_bytes(value.nonce()),
        issuer_device_id: Some(device_id_to_wire(value.issuer_device_id())),
        issuer_signature: signature_to_bytes(value.issuer_signature()),
        routing_id: value.routing_id().map(routing_id_to_wire),
    }
}

pub(super) fn invitation_from_wire(
    wire: wire::Invitation,
) -> Result<Invitation, KonclaveProtocolError> {
    Ok(Invitation::new(
        version_from_wire(wire.version, INVITATION_CONTRACT)?,
        invitation_id_from_wire(wire.invitation_id)?,
        super::common::conversation_id_from_wire(wire.conversation_id)?,
        wire.routing_id
            .map(|value| routing_id_from_wire(Some(value)))
            .transpose()?,
        device_id_from_wire(wire.expected_device_id)?,
        super::common::role_from_wire(wire.role)?,
        wire.expires_at_unix_seconds,
        nonce_from_bytes(&wire.nonce)?,
        device_id_from_wire(wire.issuer_device_id)?,
        signature_from_bytes(&wire.issuer_signature)?,
    )?)
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, KonclaveProtocolError> {
    super::common::required(value, field)
}
