use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};

use crate::error::LocalServiceTransportError;
use crate::identifiers::{
    AdapterKeyId, AdapterKeyVersion, CHALLENGE_LENGTH, ClientInstanceId, HarnessKind,
    LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceChallenge, MAX_PROFILE_ID_LENGTH, ServiceProfileId,
};

/// Hard limit for a frame accepted before the peer is authenticated.
///
/// Every handshake message is far smaller than this. Keeping the pre-authentication
/// limit well below the authenticated limit means an unauthenticated peer cannot make
/// the process reserve a request-sized buffer.
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 256;

/// Wire tag for the client's opening message.
const KIND_CLIENT_HELLO: u8 = 1;

/// Wire tag for the service's identity and challenge.
const KIND_SERVICE_CHALLENGE: u8 = 2;

/// Wire tag for the client's transcript signature.
const KIND_CLIENT_AUTH: u8 = 3;

/// Wire tag for the service's acceptance signature.
const KIND_SERVICE_ACCEPT: u8 = 4;

const MAX_CLIENT_HELLO_BYTES: usize = 1
    + 2
    + AdapterKeyId::LENGTH
    + 4
    + ClientInstanceId::LENGTH
    + 2
    + 2
    + MAX_PROFILE_ID_LENGTH
    + CHALLENGE_LENGTH;

const _: () = assert!(
    MAX_CLIENT_HELLO_BYTES <= MAX_HANDSHAKE_FRAME_BYTES,
    "the pre-authentication bound must admit a maximal hello"
);

/// The four messages exchanged before any request may flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    /// The client opens with its registration, instance, harness, requested profile,
    /// and challenge.
    ClientHello {
        version: u16,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
        client_instance: ClientInstanceId,
        harness: HarnessKind,
        profile: ServiceProfileId,
        challenge: LocalServiceChallenge,
    },
    /// The service answers with the identity a client pins and its own challenge.
    ServiceChallenge {
        service_public_key: Ed25519PublicKey,
        challenge: LocalServiceChallenge,
    },
    /// The client proves possession of its registered private key.
    ClientAuth { signature: Ed25519Signature },
    /// The service accepts the binding under a separate signature domain.
    ServiceAccept { signature: Ed25519Signature },
}

impl HandshakeMessage {
    /// Encodes the canonical payload for this message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::ClientHello {
                version,
                adapter_key_id,
                adapter_key_version,
                client_instance,
                harness,
                profile,
                challenge,
            } => {
                payload.push(KIND_CLIENT_HELLO);
                payload.extend_from_slice(&version.to_be_bytes());
                payload.extend_from_slice(adapter_key_id.as_bytes());
                payload.extend_from_slice(&adapter_key_version.get().to_be_bytes());
                payload.extend_from_slice(client_instance.as_bytes());
                payload.extend_from_slice(&harness.wire_value().to_be_bytes());
                let profile = profile.as_str().as_bytes();
                payload.extend_from_slice(
                    &u16::try_from(profile.len())
                        .unwrap_or(u16::MAX)
                        .to_be_bytes(),
                );
                payload.extend_from_slice(profile);
                payload.extend_from_slice(challenge.as_bytes());
            }
            Self::ServiceChallenge {
                service_public_key,
                challenge,
            } => {
                payload.push(KIND_SERVICE_CHALLENGE);
                payload.extend_from_slice(service_public_key.as_bytes());
                payload.extend_from_slice(challenge.as_bytes());
            }
            Self::ClientAuth { signature } => {
                payload.push(KIND_CLIENT_AUTH);
                payload.extend_from_slice(signature.as_bytes());
            }
            Self::ServiceAccept { signature } => {
                payload.push(KIND_SERVICE_ACCEPT);
                payload.extend_from_slice(signature.as_bytes());
            }
        }
        payload
    }

    /// Decodes one handshake payload.
    ///
    /// Every field is read at an exact offset and the payload must end precisely at
    /// the last field, so trailing bytes, short reads, and unknown tags fail before
    /// any value is used.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnknownMessageKind`],
    /// [`LocalServiceTransportError::MalformedFrame`],
    /// [`LocalServiceTransportError::UnsupportedVersion`],
    /// [`LocalServiceTransportError::UnknownHarnessKind`], or
    /// [`LocalServiceTransportError::InvalidIdentifier`].
    pub fn decode(payload: &[u8]) -> Result<Self, LocalServiceTransportError> {
        let (kind, mut rest) = payload
            .split_first()
            .ok_or(LocalServiceTransportError::MalformedFrame)?;
        let message = match *kind {
            KIND_CLIENT_HELLO => {
                let version = u16::from_be_bytes(take_array::<2>(&mut rest)?);
                if version != LOCAL_SERVICE_PROTOCOL_VERSION {
                    return Err(LocalServiceTransportError::UnsupportedVersion);
                }
                let adapter_key_id =
                    AdapterKeyId::from_bytes(take_array::<{ AdapterKeyId::LENGTH }>(&mut rest)?);
                let adapter_key_version =
                    AdapterKeyVersion::new(u32::from_be_bytes(take_array::<4>(&mut rest)?))?;
                let client_instance = ClientInstanceId::from_bytes(take_array::<
                    { ClientInstanceId::LENGTH },
                >(&mut rest)?);
                let harness =
                    HarnessKind::from_wire_value(u16::from_be_bytes(take_array::<2>(&mut rest)?))?;
                let profile = take_profile(&mut rest)?;
                let challenge =
                    LocalServiceChallenge::from_bytes(take_array::<CHALLENGE_LENGTH>(&mut rest)?);
                Self::ClientHello {
                    version,
                    adapter_key_id,
                    adapter_key_version,
                    client_instance,
                    harness,
                    profile,
                    challenge,
                }
            }
            KIND_SERVICE_CHALLENGE => Self::ServiceChallenge {
                service_public_key: Ed25519PublicKey::from_bytes(take_array::<
                    { Ed25519PublicKey::LENGTH },
                >(&mut rest)?),
                challenge: LocalServiceChallenge::from_bytes(take_array::<CHALLENGE_LENGTH>(
                    &mut rest,
                )?),
            },
            KIND_CLIENT_AUTH => Self::ClientAuth {
                signature: Ed25519Signature::from_bytes(
                    take_array::<{ Ed25519Signature::LENGTH }>(&mut rest)?,
                ),
            },
            KIND_SERVICE_ACCEPT => Self::ServiceAccept {
                signature: Ed25519Signature::from_bytes(
                    take_array::<{ Ed25519Signature::LENGTH }>(&mut rest)?,
                ),
            },
            _ => return Err(LocalServiceTransportError::UnknownMessageKind),
        };
        if !rest.is_empty() {
            return Err(LocalServiceTransportError::MalformedFrame);
        }
        Ok(message)
    }
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], LocalServiceTransportError> {
    if rest.len() < N {
        return Err(LocalServiceTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(N);
    let mut value = [0_u8; N];
    value.copy_from_slice(head);
    *rest = tail;
    Ok(value)
}

fn take_profile(rest: &mut &[u8]) -> Result<ServiceProfileId, LocalServiceTransportError> {
    let length = usize::from(u16::from_be_bytes(take_array::<2>(rest)?));
    if length == 0 || length > MAX_PROFILE_ID_LENGTH {
        return Err(LocalServiceTransportError::InvalidIdentifier { field: "profile" });
    }
    if rest.len() < length {
        return Err(LocalServiceTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(length);
    *rest = tail;
    let value = core::str::from_utf8(head)
        .map_err(|_| LocalServiceTransportError::InvalidIdentifier { field: "profile" })?;
    ServiceProfileId::parse(value)
}

#[cfg(test)]
mod tests {
    use super::{HandshakeMessage, MAX_HANDSHAKE_FRAME_BYTES};
    use crate::error::LocalServiceTransportError;
    use crate::identifiers::{
        AdapterKeyId, AdapterKeyVersion, CHALLENGE_LENGTH, ClientInstanceId, HarnessKind,
        LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceChallenge, MAX_PROFILE_ID_LENGTH,
        ServiceProfileId,
    };
    use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};

    fn hello_with(profile: &str) -> HandshakeMessage {
        HandshakeMessage::ClientHello {
            version: LOCAL_SERVICE_PROTOCOL_VERSION,
            adapter_key_id: AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH]),
            adapter_key_version: AdapterKeyVersion::new(7).unwrap(),
            client_instance: ClientInstanceId::from_bytes([2_u8; ClientInstanceId::LENGTH]),
            harness: HarnessKind::Copilot,
            profile: ServiceProfileId::parse(profile).unwrap(),
            challenge: LocalServiceChallenge::from_bytes([3_u8; CHALLENGE_LENGTH]),
        }
    }

    fn every_message() -> Vec<HandshakeMessage> {
        vec![
            hello_with("alice"),
            HandshakeMessage::ServiceChallenge {
                service_public_key: Ed25519PublicKey::from_bytes([4_u8; Ed25519PublicKey::LENGTH]),
                challenge: LocalServiceChallenge::from_bytes([5_u8; CHALLENGE_LENGTH]),
            },
            HandshakeMessage::ClientAuth {
                signature: Ed25519Signature::from_bytes([6_u8; Ed25519Signature::LENGTH]),
            },
            HandshakeMessage::ServiceAccept {
                signature: Ed25519Signature::from_bytes([7_u8; Ed25519Signature::LENGTH]),
            },
        ]
    }

    #[test]
    fn every_handshake_message_round_trips_within_the_preauth_bound() {
        for message in every_message() {
            let payload = message.encode();
            assert!(payload.len() <= MAX_HANDSHAKE_FRAME_BYTES);
            assert_eq!(HandshakeMessage::decode(&payload).unwrap(), message);
        }
    }

    #[test]
    fn a_maximal_hello_still_fits_the_preauth_bound() {
        let payload = hello_with(&"p".repeat(MAX_PROFILE_ID_LENGTH)).encode();
        assert!(payload.len() <= MAX_HANDSHAKE_FRAME_BYTES);
        assert!(HandshakeMessage::decode(&payload).is_ok());
    }

    #[test]
    fn an_unknown_kind_or_empty_payload_is_rejected() {
        assert_eq!(
            HandshakeMessage::decode(&[9_u8, 0, 0]).unwrap_err(),
            LocalServiceTransportError::UnknownMessageKind
        );
        assert_eq!(
            HandshakeMessage::decode(&[]).unwrap_err(),
            LocalServiceTransportError::MalformedFrame
        );
    }

    #[test]
    fn an_unimplemented_version_is_rejected_before_the_rest_of_the_message() {
        let mut payload = hello_with("alice").encode();
        payload[1..3].copy_from_slice(&(LOCAL_SERVICE_PROTOCOL_VERSION + 1).to_be_bytes());
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            LocalServiceTransportError::UnsupportedVersion
        );
    }

    #[test]
    fn a_zero_key_version_is_rejected() {
        let mut payload = hello_with("alice").encode();
        payload[19..23].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier {
                field: "adapter_key_version"
            }
        );
    }

    #[test]
    fn an_unimplemented_harness_is_rejected() {
        let mut payload = hello_with("alice").encode();
        payload[39..41].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            LocalServiceTransportError::UnknownHarnessKind
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        for message in every_message() {
            let mut payload = message.encode();
            payload.push(0);
            assert_eq!(
                HandshakeMessage::decode(&payload).unwrap_err(),
                LocalServiceTransportError::MalformedFrame
            );
        }
    }

    #[test]
    fn a_truncated_message_is_rejected_at_every_field() {
        for message in every_message() {
            let payload = message.encode();
            for length in 1..payload.len() {
                assert!(
                    HandshakeMessage::decode(&payload[..length]).is_err(),
                    "prefix of {length} bytes must not decode"
                );
            }
        }
    }

    #[test]
    fn an_empty_oversized_or_overrunning_profile_length_is_rejected() {
        let mut empty = hello_with("alice").encode();
        empty[41..43].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            HandshakeMessage::decode(&empty).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier { field: "profile" }
        );

        let mut oversized = hello_with("alice").encode();
        oversized[41..43].copy_from_slice(
            &u16::try_from(MAX_PROFILE_ID_LENGTH + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            HandshakeMessage::decode(&oversized).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier { field: "profile" }
        );

        let mut overrun = hello_with("alice").encode();
        overrun[41..43]
            .copy_from_slice(&u16::try_from(MAX_PROFILE_ID_LENGTH).unwrap().to_be_bytes());
        overrun[43..43 + MAX_PROFILE_ID_LENGTH].fill(b'a');
        assert_eq!(
            HandshakeMessage::decode(&overrun).unwrap_err(),
            LocalServiceTransportError::MalformedFrame
        );
    }

    #[test]
    fn a_profile_outside_the_accepted_character_set_is_rejected() {
        let mut payload = hello_with("alice").encode();
        payload[43] = b'/';
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier { field: "profile" }
        );
        payload[43] = 0xFF;
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier { field: "profile" }
        );
    }
}
