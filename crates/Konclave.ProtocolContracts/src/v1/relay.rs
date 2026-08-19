use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, MAX_RELAY_CONTROL_MESSAGE_BYTES, MAX_RELAY_ENVELOPE_BYTES,
    MAX_RELAY_PAYLOAD_BYTES, MAX_REPLAY_PAGE_BYTES, MAX_REPLAY_PAGE_SIZE, RelayEnvelope,
    ReplayPage, ReplayRequest, StoredRelayEnvelope,
};
use prost::Message;

use crate::KonclaveProtocolError;
use crate::v1::common::{
    decode_bounded, encode_bounded, envelope_id_from_wire, envelope_id_to_wire,
    require_repeated_field_limits, required, routing_id_from_wire, routing_id_to_wire,
    version_from_wire, version_to_wire,
};
use crate::wire::v1 as wire;

const RELAY_CONTRACT: &str = "RelayEnvelope";
const STORED_RELAY_ENVELOPE_MAX_BYTES: usize = MAX_RELAY_ENVELOPE_BYTES + 32;

/// Encodes a relay envelope.
///
/// # Errors
///
/// Returns a size error when the encoded envelope exceeds the v1 relay limit.
pub fn encode_relay_envelope(value: &RelayEnvelope) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &relay_to_wire(value),
        MAX_RELAY_ENVELOPE_BYTES,
        RELAY_CONTRACT,
    )
}

/// Decodes and validates one relay envelope.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_relay_envelope(bytes: &[u8]) -> Result<RelayEnvelope, KonclaveProtocolError> {
    let wire = decode_bounded(bytes, MAX_RELAY_ENVELOPE_BYTES, RELAY_CONTRACT)?;
    relay_from_wire(wire)
}

/// Encodes a stored relay envelope.
///
/// # Errors
///
/// Returns a size error when the encoded value exceeds the v1 relay limit.
pub fn encode_stored_relay_envelope(
    value: &StoredRelayEnvelope,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = stored_to_wire(value);
    encode_bounded(
        &wire,
        STORED_RELAY_ENVELOPE_MAX_BYTES,
        "StoredRelayEnvelope",
    )
}

/// Encodes a stored envelope while retaining the exact validated envelope bytes.
///
/// This is the forwarding-safe form for relays that must preserve additive fields
/// they do not interpret.
///
/// # Errors
///
/// Returns a typed protocol or domain error when the envelope bytes are invalid,
/// the cursor is zero, or the encoded result exceeds the defensive limit.
pub fn encode_stored_relay_envelope_preserving(
    encoded_envelope: &[u8],
    cursor: u64,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    let envelope = decode_relay_envelope(encoded_envelope)?;
    StoredRelayEnvelope::new(envelope, cursor)?;
    let encoded_length = stored_preserving_length(encoded_envelope.len(), cursor)?;
    if encoded_length > STORED_RELAY_ENVELOPE_MAX_BYTES {
        return Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: "StoredRelayEnvelope",
            maximum: STORED_RELAY_ENVELOPE_MAX_BYTES,
            actual: encoded_length,
        });
    }
    let mut output = Vec::with_capacity(encoded_length);
    append_length_delimited(1, encoded_envelope, &mut output);
    append_varint_field(2, cursor, &mut output);
    Ok(output)
}

/// Decodes and validates a stored relay envelope.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_stored_relay_envelope(
    bytes: &[u8],
) -> Result<StoredRelayEnvelope, KonclaveProtocolError> {
    let wire: wire::StoredRelayEnvelope = decode_bounded(
        bytes,
        STORED_RELAY_ENVELOPE_MAX_BYTES,
        "StoredRelayEnvelope",
    )?;
    stored_from_wire(wire)
}

/// Encodes a replay request.
///
/// # Errors
///
/// Returns a size error only if the fixed-size request exceeds its defensive limit.
pub fn encode_replay_request(value: ReplayRequest) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = wire::ReplayRequest {
        routing_id: Some(routing_id_to_wire(value.routing_id())),
        after_cursor: value.after_cursor(),
        limit: value.limit(),
    };
    encode_bounded(&wire, MAX_RELAY_CONTROL_MESSAGE_BYTES, "ReplayRequest")
}

/// Decodes and validates a replay request.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_replay_request(bytes: &[u8]) -> Result<ReplayRequest, KonclaveProtocolError> {
    let wire: wire::ReplayRequest =
        decode_bounded(bytes, MAX_RELAY_CONTROL_MESSAGE_BYTES, "ReplayRequest")?;
    Ok(ReplayRequest::new(
        routing_id_from_wire(wire.routing_id)?,
        wire.after_cursor,
        wire.limit,
    )?)
}

/// Encodes a bounded replay page.
///
/// # Errors
///
/// Returns a size error when the page exceeds the v1 replay-page byte limit.
pub fn encode_replay_page(value: &ReplayPage) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = wire::ReplayPage {
        envelopes: value.envelopes().iter().map(stored_to_wire).collect(),
        next_cursor: value.next_cursor(),
        has_more: value.has_more(),
    };
    encode_bounded(&wire, MAX_REPLAY_PAGE_BYTES, "ReplayPage")
}

/// Encodes a replay page while retaining every exact validated envelope encoding.
///
/// # Errors
///
/// Returns a typed protocol or domain error for malformed envelopes, invalid cursor
/// ordering, excessive count, arithmetic overflow, or an oversized encoded page.
pub fn encode_replay_page_preserving(
    envelopes: &[(&[u8], u64)],
    next_cursor: u64,
    has_more: bool,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    if envelopes.len() > MAX_REPLAY_PAGE_SIZE {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "replay_envelopes",
            minimum: 0,
            maximum: MAX_REPLAY_PAGE_SIZE,
            actual: envelopes.len(),
        }
        .into());
    }
    let mut previous_cursor = None;
    let mut encoded_length = 0_usize;
    let mut stored_lengths = Vec::with_capacity(envelopes.len());
    for (encoded_envelope, cursor) in envelopes {
        decode_relay_envelope(encoded_envelope)?;
        if *cursor == 0 || previous_cursor.is_some_and(|previous| previous >= *cursor) {
            return Err(KonclaveDomainCore::KonclaveDomainError::InvalidReplayOrder.into());
        }
        previous_cursor = Some(*cursor);
        let stored_length = stored_preserving_length(encoded_envelope.len(), *cursor)?;
        encoded_length = encoded_length
            .checked_add(length_delimited_length(stored_length)?)
            .ok_or(KonclaveProtocolError::EncodedMessageTooLarge {
                contract: "ReplayPage",
                maximum: MAX_REPLAY_PAGE_BYTES,
                actual: usize::MAX,
            })?;
        stored_lengths.push(stored_length);
    }
    if previous_cursor.is_some_and(|cursor| next_cursor < cursor) {
        return Err(KonclaveDomainCore::KonclaveDomainError::InvalidReplayOrder.into());
    }
    if next_cursor != 0 {
        encoded_length = encoded_length
            .checked_add(varint_field_length(next_cursor))
            .ok_or(KonclaveProtocolError::EncodedMessageTooLarge {
                contract: "ReplayPage",
                maximum: MAX_REPLAY_PAGE_BYTES,
                actual: usize::MAX,
            })?;
    }
    if has_more {
        encoded_length =
            encoded_length
                .checked_add(2)
                .ok_or(KonclaveProtocolError::EncodedMessageTooLarge {
                    contract: "ReplayPage",
                    maximum: MAX_REPLAY_PAGE_BYTES,
                    actual: usize::MAX,
                })?;
    }
    if encoded_length > MAX_REPLAY_PAGE_BYTES {
        return Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: "ReplayPage",
            maximum: MAX_REPLAY_PAGE_BYTES,
            actual: encoded_length,
        });
    }

    let mut output = Vec::with_capacity(encoded_length);
    for ((encoded_envelope, cursor), stored_length) in envelopes.iter().zip(stored_lengths) {
        append_key(1, 2, &mut output);
        append_varint(stored_length as u64, &mut output);
        append_length_delimited(1, encoded_envelope, &mut output);
        append_varint_field(2, *cursor, &mut output);
    }
    if next_cursor != 0 {
        append_varint_field(2, next_cursor, &mut output);
    }
    if has_more {
        append_varint_field(3, 1, &mut output);
    }
    Ok(output)
}

/// Decodes and validates a bounded replay page.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_replay_page(bytes: &[u8]) -> Result<ReplayPage, KonclaveProtocolError> {
    require_repeated_field_limits(
        bytes,
        MAX_REPLAY_PAGE_BYTES,
        "ReplayPage",
        [(1, MAX_REPLAY_PAGE_SIZE, "replay_envelopes")],
    )?;
    let wire: wire::ReplayPage = decode_bounded(bytes, MAX_REPLAY_PAGE_BYTES, "ReplayPage")?;
    if wire.envelopes.len() > MAX_REPLAY_PAGE_SIZE {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "replay_envelopes",
            minimum: 0,
            maximum: MAX_REPLAY_PAGE_SIZE,
            actual: wire.envelopes.len(),
        }
        .into());
    }
    let envelopes = wire
        .envelopes
        .into_iter()
        .map(stored_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReplayPage::new(envelopes, wire.next_cursor, wire.has_more)?)
}

/// Encodes a cursor acknowledgment.
///
/// # Errors
///
/// Returns a size error only if the fixed-size request exceeds its defensive limit.
pub fn encode_acknowledge_request(
    value: AcknowledgeRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = wire::AcknowledgeRequest {
        routing_id: Some(routing_id_to_wire(value.routing_id())),
        cursor: value.cursor(),
    };
    encode_bounded(&wire, MAX_RELAY_CONTROL_MESSAGE_BYTES, "AcknowledgeRequest")
}

/// Decodes and validates a cursor acknowledgment.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_acknowledge_request(
    bytes: &[u8],
) -> Result<AcknowledgeRequest, KonclaveProtocolError> {
    let wire: wire::AcknowledgeRequest =
        decode_bounded(bytes, MAX_RELAY_CONTROL_MESSAGE_BYTES, "AcknowledgeRequest")?;
    Ok(AcknowledgeRequest::new(
        routing_id_from_wire(wire.routing_id)?,
        wire.cursor,
    )?)
}

fn relay_to_wire(value: &RelayEnvelope) -> wire::RelayEnvelope {
    wire::RelayEnvelope {
        version: Some(version_to_wire(value.version())),
        routing_id: Some(routing_id_to_wire(value.routing_id())),
        envelope_id: Some(envelope_id_to_wire(value.envelope_id())),
        delivery_class: delivery_class_to_wire(value.delivery_class()),
        expected_parent_epoch: value.expected_parent_epoch(),
        expires_at_unix_seconds: value.expires_at_unix_seconds(),
        payload: prost::bytes::Bytes::copy_from_slice(value.payload()),
    }
}

fn relay_from_wire(wire: wire::RelayEnvelope) -> Result<RelayEnvelope, KonclaveProtocolError> {
    require_encoded_size(&wire, MAX_RELAY_ENVELOPE_BYTES, RELAY_CONTRACT)?;
    if wire.payload.is_empty() || wire.payload.len() > MAX_RELAY_PAYLOAD_BYTES {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "relay_payload",
            minimum: 1,
            maximum: MAX_RELAY_PAYLOAD_BYTES,
            actual: wire.payload.len(),
        }
        .into());
    }
    Ok(RelayEnvelope::new(
        version_from_wire(wire.version, RELAY_CONTRACT)?,
        routing_id_from_wire(wire.routing_id)?,
        envelope_id_from_wire(wire.envelope_id)?,
        delivery_class_from_wire(wire.delivery_class)?,
        wire.expected_parent_epoch,
        wire.expires_at_unix_seconds,
        wire.payload.to_vec(),
    )?)
}

fn stored_to_wire(value: &StoredRelayEnvelope) -> wire::StoredRelayEnvelope {
    wire::StoredRelayEnvelope {
        envelope: Some(relay_to_wire(value.envelope())),
        cursor: value.cursor(),
    }
}

fn stored_from_wire(
    wire: wire::StoredRelayEnvelope,
) -> Result<StoredRelayEnvelope, KonclaveProtocolError> {
    require_encoded_size(
        &wire,
        STORED_RELAY_ENVELOPE_MAX_BYTES,
        "StoredRelayEnvelope",
    )?;
    Ok(StoredRelayEnvelope::new(
        relay_from_wire(required(wire.envelope, "stored_relay_envelope.envelope")?)?,
        wire.cursor,
    )?)
}

fn require_encoded_size<M: Message>(
    wire: &M,
    maximum: usize,
    contract: &'static str,
) -> Result<(), KonclaveProtocolError> {
    let actual = wire.encoded_len();
    if actual > maximum {
        return Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract,
            maximum,
            actual,
        });
    }
    Ok(())
}

fn delivery_class_to_wire(value: DeliveryClass) -> i32 {
    match value {
        DeliveryClass::KeyPackage => wire::DeliveryClass::KeyPackage as i32,
        DeliveryClass::Welcome => wire::DeliveryClass::Welcome as i32,
        DeliveryClass::GroupProposal => wire::DeliveryClass::GroupProposal as i32,
        DeliveryClass::GroupCommit => wire::DeliveryClass::GroupCommit as i32,
        DeliveryClass::GroupApplication => wire::DeliveryClass::GroupApplication as i32,
    }
}

fn delivery_class_from_wire(value: i32) -> Result<DeliveryClass, KonclaveProtocolError> {
    match wire::DeliveryClass::try_from(value) {
        Ok(wire::DeliveryClass::KeyPackage) => Ok(DeliveryClass::KeyPackage),
        Ok(wire::DeliveryClass::Welcome) => Ok(DeliveryClass::Welcome),
        Ok(wire::DeliveryClass::GroupProposal) => Ok(DeliveryClass::GroupProposal),
        Ok(wire::DeliveryClass::GroupCommit) => Ok(DeliveryClass::GroupCommit),
        Ok(wire::DeliveryClass::GroupApplication) => Ok(DeliveryClass::GroupApplication),
        _ => Err(KonclaveProtocolError::UnsupportedEnum {
            field: "delivery_class",
            value,
        }),
    }
}

fn stored_preserving_length(
    encoded_envelope_length: usize,
    cursor: u64,
) -> Result<usize, KonclaveProtocolError> {
    length_delimited_length(encoded_envelope_length)?
        .checked_add(varint_field_length(cursor))
        .ok_or(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: "StoredRelayEnvelope",
            maximum: STORED_RELAY_ENVELOPE_MAX_BYTES,
            actual: usize::MAX,
        })
}

fn length_delimited_length(payload_length: usize) -> Result<usize, KonclaveProtocolError> {
    1_usize
        .checked_add(varint_length(payload_length as u64))
        .and_then(|length| length.checked_add(payload_length))
        .ok_or(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: "ProtocolBuffers",
            maximum: usize::MAX,
            actual: usize::MAX,
        })
}

fn varint_field_length(value: u64) -> usize {
    1 + varint_length(value)
}

fn varint_length(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn append_length_delimited(field_number: u32, value: &[u8], output: &mut Vec<u8>) {
    append_key(field_number, 2, output);
    append_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn append_varint_field(field_number: u32, value: u64, output: &mut Vec<u8>) {
    append_key(field_number, 0, output);
    append_varint(value, output);
}

fn append_key(field_number: u32, wire_type: u8, output: &mut Vec<u8>) {
    append_varint(
        (u64::from(field_number) << 3) | u64::from(wire_type),
        output,
    );
}

fn append_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

#[cfg(test)]
mod preserving_tests {
    use KonclaveDomainCore::{
        DeliveryClass, EnvelopeId, ProtocolVersion, RelayEnvelope, RoutingId,
    };

    use super::*;

    fn envelope() -> RelayEnvelope {
        RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            RoutingId::from_bytes([1; RoutingId::LENGTH]),
            EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            DeliveryClass::GroupApplication,
            None,
            100,
            vec![3],
        )
        .unwrap()
    }

    #[test]
    fn forwarding_encoders_retain_unknown_envelope_fields() {
        let mut encoded = encode_relay_envelope(&envelope()).unwrap();
        encoded.extend_from_slice(&[0xa0, 0x06, 0x07]);

        let stored = encode_stored_relay_envelope_preserving(&encoded, 1).unwrap();
        assert!(
            stored
                .windows(encoded.len())
                .any(|window| window == encoded)
        );
        assert_eq!(decode_stored_relay_envelope(&stored).unwrap().cursor(), 1);

        let page = encode_replay_page_preserving(&[(&encoded, 1)], 1, false).unwrap();
        assert!(page.windows(encoded.len()).any(|window| window == encoded));
        assert_eq!(decode_replay_page(&page).unwrap().next_cursor(), 1);
    }
}
