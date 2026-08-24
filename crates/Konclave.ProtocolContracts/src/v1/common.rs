use KonclaveDomainCore::{
    ConversationId, ConversationRole, CredentialBindingHash, DeviceId, Ed25519PublicKey,
    Ed25519Signature, EnvelopeId, InvitationId, InvitationNonce, KonclaveDomainError,
    MAX_PROTOBUF_TOP_LEVEL_FIELDS, MembershipOperationId, MessageId, PairingId, PairingMessageId,
    ProtocolVersion, RoutingId,
};
use prost::Message;
use prost::bytes::Buf;
use prost::encoding::{DecodeContext, WireType, decode_key, skip_field};

use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

pub(super) fn decode_bounded<M>(
    bytes: &[u8],
    maximum: usize,
    contract: &'static str,
) -> Result<M, KonclaveProtocolError>
where
    M: Message + Default,
{
    require_repeated_field_limits(bytes, maximum, contract, [])?;
    M::decode(bytes).map_err(|error| KonclaveProtocolError::Decode {
        contract,
        reason: error.to_string(),
    })
}

pub(super) fn require_repeated_field_limits<const N: usize>(
    bytes: &[u8],
    maximum_bytes: usize,
    contract: &'static str,
    limits: [(u32, usize, &'static str); N],
) -> Result<(), KonclaveProtocolError> {
    require_input_size(bytes, maximum_bytes, contract)?;
    let mut counts = [0_usize; N];
    let mut field_count = 0_usize;
    let mut remaining = bytes;
    while remaining.has_remaining() {
        field_count += 1;
        if field_count > MAX_PROTOBUF_TOP_LEVEL_FIELDS {
            return Err(KonclaveDomainError::OutOfRange {
                field: "protobuf_top_level_fields",
                minimum: 0,
                maximum: MAX_PROTOBUF_TOP_LEVEL_FIELDS,
                actual: field_count,
            }
            .into());
        }
        let (tag, wire_type) = decode_key(&mut remaining).map_err(|_| malformed_wire(contract))?;
        if matches!(wire_type, WireType::StartGroup | WireType::EndGroup) {
            return Err(malformed_wire(contract));
        }
        if wire_type == WireType::LengthDelimited {
            for (index, (field_number, maximum, field)) in limits.iter().enumerate() {
                if tag == *field_number {
                    counts[index] += 1;
                    if counts[index] > *maximum {
                        return Err(KonclaveDomainError::OutOfRange {
                            field,
                            minimum: 0,
                            maximum: *maximum,
                            actual: counts[index],
                        }
                        .into());
                    }
                }
            }
        }
        skip_field(wire_type, tag, &mut remaining, DecodeContext::default())
            .map_err(|_| malformed_wire(contract))?;
    }
    Ok(())
}

pub(super) fn encode_bounded<M>(
    message: &M,
    maximum: usize,
    contract: &'static str,
) -> Result<Vec<u8>, KonclaveProtocolError>
where
    M: Message,
{
    let actual = message.encoded_len();
    if actual > maximum {
        return Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract,
            maximum,
            actual,
        });
    }
    Ok(message.encode_to_vec())
}

pub(super) fn required<T>(
    value: Option<T>,
    field: &'static str,
) -> Result<T, KonclaveProtocolError> {
    value.ok_or(KonclaveProtocolError::MissingField { field })
}

pub(super) fn version_to_wire(value: ProtocolVersion) -> wire::ProtocolVersion {
    wire::ProtocolVersion {
        major: value.major(),
        minor: value.minor(),
    }
}

pub(super) fn version_from_wire(
    value: Option<wire::ProtocolVersion>,
    contract: &'static str,
) -> Result<ProtocolVersion, KonclaveProtocolError> {
    let value = required(value, "version")?;
    if value.major != 1 {
        return Err(KonclaveProtocolError::UnsupportedMajor {
            contract,
            actual: value.major,
        });
    }
    Ok(ProtocolVersion::new(value.major, value.minor)?)
}

macro_rules! id_conversion {
    ($to_wire:ident, $from_wire:ident, $wire:ident, $domain:ident, $field:literal) => {
        pub(super) fn $to_wire(value: $domain) -> wire::$wire {
            wire::$wire {
                value: prost::bytes::Bytes::copy_from_slice(value.as_bytes()),
            }
        }

        pub(super) fn $from_wire(
            value: Option<wire::$wire>,
        ) -> Result<$domain, KonclaveProtocolError> {
            let value = required(value, $field)?;
            Ok($domain::from_slice(&value.value)?)
        }
    };
}

id_conversion!(
    device_id_to_wire,
    device_id_from_wire,
    DeviceId,
    DeviceId,
    "device_id"
);
id_conversion!(
    conversation_id_to_wire,
    conversation_id_from_wire,
    ConversationId,
    ConversationId,
    "conversation_id"
);
id_conversion!(
    message_id_to_wire,
    message_id_from_wire,
    MessageId,
    MessageId,
    "message_id"
);
id_conversion!(
    envelope_id_to_wire,
    envelope_id_from_wire,
    EnvelopeId,
    EnvelopeId,
    "envelope_id"
);
id_conversion!(
    invitation_id_to_wire,
    invitation_id_from_wire,
    InvitationId,
    InvitationId,
    "invitation_id"
);
id_conversion!(
    pairing_id_to_wire,
    pairing_id_from_wire,
    PairingId,
    PairingId,
    "pairing_id"
);
id_conversion!(
    pairing_message_id_to_wire,
    pairing_message_id_from_wire,
    PairingMessageId,
    PairingMessageId,
    "pairing_message_id"
);
id_conversion!(
    routing_id_to_wire,
    routing_id_from_wire,
    RoutingId,
    RoutingId,
    "routing_id"
);
id_conversion!(
    operation_id_to_wire,
    operation_id_from_wire,
    MembershipOperationId,
    MembershipOperationId,
    "operation_id"
);

pub(super) fn credential_hash_to_bytes(value: CredentialBindingHash) -> prost::bytes::Bytes {
    prost::bytes::Bytes::copy_from_slice(value.as_bytes())
}

pub(super) fn credential_hash_from_bytes(
    value: &[u8],
) -> Result<CredentialBindingHash, KonclaveProtocolError> {
    Ok(CredentialBindingHash::from_slice(value)?)
}

pub(super) fn public_key_to_bytes(value: Ed25519PublicKey) -> prost::bytes::Bytes {
    prost::bytes::Bytes::copy_from_slice(value.as_bytes())
}

pub(super) fn public_key_from_bytes(
    value: &[u8],
) -> Result<Ed25519PublicKey, KonclaveProtocolError> {
    Ok(Ed25519PublicKey::from_slice(value)?)
}

pub(super) fn signature_to_bytes(value: Ed25519Signature) -> prost::bytes::Bytes {
    prost::bytes::Bytes::copy_from_slice(value.as_bytes())
}

pub(super) fn signature_from_bytes(
    value: &[u8],
) -> Result<Ed25519Signature, KonclaveProtocolError> {
    Ok(Ed25519Signature::from_slice(value)?)
}

pub(super) fn nonce_to_bytes(value: &InvitationNonce) -> prost::bytes::Bytes {
    prost::bytes::Bytes::copy_from_slice(value.as_bytes())
}

pub(super) fn nonce_from_bytes(value: &[u8]) -> Result<InvitationNonce, KonclaveProtocolError> {
    Ok(InvitationNonce::from_slice(value)?)
}

pub(super) fn role_to_wire(value: ConversationRole) -> i32 {
    match value {
        ConversationRole::Administrator => wire::ConversationRole::Administrator as i32,
        ConversationRole::Member => wire::ConversationRole::Member as i32,
    }
}

pub(super) fn role_from_wire(value: i32) -> Result<ConversationRole, KonclaveProtocolError> {
    match wire::ConversationRole::try_from(value) {
        Ok(wire::ConversationRole::Administrator) => Ok(ConversationRole::Administrator),
        Ok(wire::ConversationRole::Member) => Ok(ConversationRole::Member),
        _ => Err(KonclaveProtocolError::UnsupportedEnum {
            field: "conversation_role",
            value,
        }),
    }
}

fn require_input_size(
    bytes: &[u8],
    maximum: usize,
    contract: &'static str,
) -> Result<(), KonclaveProtocolError> {
    if bytes.len() > maximum {
        return Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract,
            maximum,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn malformed_wire(contract: &'static str) -> KonclaveProtocolError {
    KonclaveProtocolError::Decode {
        contract,
        reason: "invalid Protocol Buffers framing".to_string(),
    }
}
