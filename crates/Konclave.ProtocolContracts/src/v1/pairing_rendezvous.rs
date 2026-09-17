use KonclaveDomainCore::{
    MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES, MAX_PAIRING_RENDEZVOUS_RECORD_BYTES,
    MAX_RELAY_CONTROL_MESSAGE_BYTES, PairingRendezvousId, PairingRendezvousNonce,
    PairingRendezvousRecord, PairingRendezvousTakeRequest,
};

use super::common::{decode_bounded, encode_bounded, required, version_from_wire, version_to_wire};
use crate::KonclaveProtocolError;
use crate::wire::v1 as wire;

const RECORD_CONTRACT: &str = "PairingRendezvousRecord";
const TAKE_REQUEST_CONTRACT: &str = "PairingRendezvousTakeRequest";

/// Encodes one bounded opaque pairing rendezvous record.
///
/// # Errors
///
/// Returns a size error when the encoded record exceeds the relay control bound.
pub fn encode_pairing_rendezvous_record(
    value: &PairingRendezvousRecord,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::PairingRendezvousRecord {
            version: Some(version_to_wire(value.version())),
            lookup_id: Some(identifier_to_wire(value.lookup_id())),
            expires_at_unix_seconds: value.expires_at_unix_seconds(),
            nonce: value.nonce().as_bytes().to_vec().into(),
            ciphertext: value.ciphertext().to_vec().into(),
        },
        MAX_PAIRING_RENDEZVOUS_RECORD_BYTES,
        RECORD_CONTRACT,
    )
}

/// Decodes and validates one untrusted opaque rendezvous record.
///
/// # Errors
///
/// Returns a protocol, version, identifier, expiry, nonce, or ciphertext-bound error.
pub fn decode_pairing_rendezvous_record(
    bytes: &[u8],
) -> Result<PairingRendezvousRecord, KonclaveProtocolError> {
    let value: wire::PairingRendezvousRecord =
        decode_bounded(bytes, MAX_PAIRING_RENDEZVOUS_RECORD_BYTES, RECORD_CONTRACT)?;
    if value.ciphertext.len() > MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES {
        return Err(KonclaveProtocolError::EncodedMessageTooLarge {
            contract: RECORD_CONTRACT,
            maximum: MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES,
            actual: value.ciphertext.len(),
        });
    }
    Ok(PairingRendezvousRecord::new(
        version_from_wire(value.version, RECORD_CONTRACT)?,
        identifier_from_wire(value.lookup_id)?,
        value.expires_at_unix_seconds,
        PairingRendezvousNonce::from_slice(&value.nonce)?,
        value.ciphertext.to_vec(),
    )?)
}

/// Encodes one bounded pairing rendezvous take request.
///
/// # Errors
///
/// Returns a size error when the encoded request exceeds the relay control bound.
pub fn encode_pairing_rendezvous_take_request(
    value: PairingRendezvousTakeRequest,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    encode_bounded(
        &wire::PairingRendezvousTakeRequest {
            version: Some(version_to_wire(value.version())),
            lookup_id: Some(identifier_to_wire(value.lookup_id())),
        },
        MAX_RELAY_CONTROL_MESSAGE_BYTES,
        TAKE_REQUEST_CONTRACT,
    )
}

/// Decodes and validates one untrusted pairing rendezvous take request.
///
/// # Errors
///
/// Returns a protocol, version, or identifier validation error.
pub fn decode_pairing_rendezvous_take_request(
    bytes: &[u8],
) -> Result<PairingRendezvousTakeRequest, KonclaveProtocolError> {
    let value: wire::PairingRendezvousTakeRequest = decode_bounded(
        bytes,
        MAX_RELAY_CONTROL_MESSAGE_BYTES,
        TAKE_REQUEST_CONTRACT,
    )?;
    Ok(PairingRendezvousTakeRequest::new(
        version_from_wire(value.version, TAKE_REQUEST_CONTRACT)?,
        identifier_from_wire(value.lookup_id)?,
    ))
}

fn identifier_to_wire(value: PairingRendezvousId) -> wire::PairingRendezvousId {
    wire::PairingRendezvousId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn identifier_from_wire(
    value: Option<wire::PairingRendezvousId>,
) -> Result<PairingRendezvousId, KonclaveProtocolError> {
    Ok(PairingRendezvousId::from_slice(
        &required(value, "pairing_rendezvous_id")?.value,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use KonclaveDomainCore::ProtocolVersion;

    fn record() -> PairingRendezvousRecord {
        PairingRendezvousRecord::new(
            ProtocolVersion::application_v1(),
            PairingRendezvousId::from_bytes([1; 32]),
            2_000,
            PairingRendezvousNonce::from_bytes([2; 12]),
            vec![3; 32],
        )
        .unwrap()
    }

    #[test]
    fn record_and_take_request_round_trip() {
        let record = record();
        let decoded =
            decode_pairing_rendezvous_record(&encode_pairing_rendezvous_record(&record).unwrap())
                .unwrap();
        assert!(decoded == record);

        let request = PairingRendezvousTakeRequest::new(
            ProtocolVersion::application_v1(),
            record.lookup_id(),
        );
        assert_eq!(
            decode_pairing_rendezvous_take_request(
                &encode_pairing_rendezvous_take_request(request).unwrap()
            )
            .unwrap(),
            request
        );
    }

    #[test]
    fn malformed_record_fields_fail_closed() {
        let maximum = PairingRendezvousRecord::new(
            ProtocolVersion::application_v1(),
            PairingRendezvousId::from_bytes([1; 32]),
            2_000,
            PairingRendezvousNonce::from_bytes([2; 12]),
            vec![3; MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES],
        )
        .unwrap();
        assert!(
            encode_pairing_rendezvous_record(&maximum).unwrap().len()
                <= MAX_PAIRING_RENDEZVOUS_RECORD_BYTES
        );

        let mut wire = wire::PairingRendezvousRecord {
            version: Some(version_to_wire(ProtocolVersion::application_v1())),
            lookup_id: Some(identifier_to_wire(PairingRendezvousId::from_bytes([1; 32]))),
            expires_at_unix_seconds: 2_000,
            nonce: vec![2; 12].into(),
            ciphertext: vec![3; 32].into(),
        };
        wire.nonce = vec![2; 11].into();
        let bytes = prost::Message::encode_to_vec(&wire);
        assert!(decode_pairing_rendezvous_record(&bytes).is_err());

        wire.nonce = vec![2; 12].into();
        wire.ciphertext = vec![3; MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES + 1].into();
        let bytes = prost::Message::encode_to_vec(&wire);
        assert!(decode_pairing_rendezvous_record(&bytes).is_err());
    }

    #[test]
    fn unsupported_versions_fail_and_unknown_fields_remain_compatible() {
        let record = record();
        let mut bytes = encode_pairing_rendezvous_record(&record).unwrap();
        bytes.extend_from_slice(&[0xa0, 0x06, 0x07]);
        assert!(decode_pairing_rendezvous_record(&bytes).unwrap() == record);

        let unsupported = wire::PairingRendezvousTakeRequest {
            version: Some(wire::ProtocolVersion { major: 2, minor: 0 }),
            lookup_id: Some(identifier_to_wire(PairingRendezvousId::from_bytes([1; 32]))),
        };
        assert!(matches!(
            decode_pairing_rendezvous_take_request(&prost::Message::encode_to_vec(&unsupported)),
            Err(KonclaveProtocolError::UnsupportedMajor { actual: 2, .. })
        ));

        let malformed = wire::PairingRendezvousTakeRequest {
            version: Some(version_to_wire(ProtocolVersion::application_v1())),
            lookup_id: Some(wire::PairingRendezvousId {
                value: vec![1; 31].into(),
            }),
        };
        assert!(
            decode_pairing_rendezvous_take_request(&prost::Message::encode_to_vec(&malformed))
                .is_err()
        );
    }
}
