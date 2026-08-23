use crate::error::AdapterTransportError;
use crate::transcript::{
    ADAPTER_PROTOCOL_VERSION, AuthChallenge, CHALLENGE_LENGTH, MAX_IDENTIFIER_LENGTH,
};

/// Bytes carried by a frame length header.
pub const FRAME_HEADER_LENGTH: usize = 4;

/// Hard limit for a frame accepted before the peer is authenticated.
///
/// Every handshake message is far smaller than this. Keeping the pre-authentication
/// limit well below the authenticated limit means an unauthenticated peer cannot
/// make the process reserve an event-sized buffer.
pub const MAX_PREAUTH_FRAME_BYTES: usize = 1_024;

/// Hard limit for a frame accepted after both proofs verify.
pub const MAX_AUTHENTICATED_FRAME_BYTES: usize = 1_048_576;

const _: () = assert!(
    MAX_PREAUTH_FRAME_BYTES < MAX_AUTHENTICATED_FRAME_BYTES,
    "an unauthenticated peer must never reserve an event-sized buffer"
);

/// Wire tag for the adapter's opening message.
const KIND_ADAPTER_HELLO: u8 = 1;

/// Wire tag for the daemon's challenge and proof.
const KIND_DAEMON_AUTH: u8 = 2;

/// Wire tag for the adapter's returned proof.
const KIND_ADAPTER_AUTH: u8 = 3;

/// Reads a declared frame length and rejects it before any buffer is reserved.
///
/// Validating the declared length against the applicable limit first is what stops a
/// peer from causing a large allocation with a four-byte header it never satisfies.
///
/// # Errors
///
/// Returns [`AdapterTransportError::FrameTooLarge`] when the declared length exceeds
/// `limit` and [`AdapterTransportError::MalformedFrame`] when it is zero.
pub fn decode_frame_length(
    header: [u8; FRAME_HEADER_LENGTH],
    limit: usize,
) -> Result<usize, AdapterTransportError> {
    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(AdapterTransportError::MalformedFrame);
    }
    if declared > limit {
        return Err(AdapterTransportError::FrameTooLarge);
    }
    Ok(declared)
}

/// Prefixes a payload with its length header.
///
/// # Errors
///
/// Returns [`AdapterTransportError::FrameTooLarge`] when the payload exceeds `limit`.
pub fn encode_frame(payload: &[u8], limit: usize) -> Result<Vec<u8>, AdapterTransportError> {
    if payload.is_empty() {
        return Err(AdapterTransportError::MalformedFrame);
    }
    if payload.len() > limit {
        return Err(AdapterTransportError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| AdapterTransportError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LENGTH + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// The three messages exchanged before any event data may flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    /// The adapter opens with its version, consumer instance, and challenge.
    AdapterHello {
        version: u16,
        consumer: String,
        challenge: AuthChallenge,
    },
    /// The daemon answers with its profile, challenge, and proof.
    DaemonAuth {
        profile: String,
        challenge: AuthChallenge,
        proof: [u8; CHALLENGE_LENGTH],
    },
    /// The adapter returns its proof over the same transcript.
    AdapterAuth { proof: [u8; CHALLENGE_LENGTH] },
}

impl HandshakeMessage {
    /// Encodes the canonical payload for this message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::AdapterHello {
                version,
                consumer,
                challenge,
            } => {
                payload.push(KIND_ADAPTER_HELLO);
                payload.extend_from_slice(&version.to_be_bytes());
                push_bounded(&mut payload, consumer.as_bytes());
                payload.extend_from_slice(challenge.as_bytes());
            }
            Self::DaemonAuth {
                profile,
                challenge,
                proof,
            } => {
                payload.push(KIND_DAEMON_AUTH);
                push_bounded(&mut payload, profile.as_bytes());
                payload.extend_from_slice(challenge.as_bytes());
                payload.extend_from_slice(proof);
            }
            Self::AdapterAuth { proof } => {
                payload.push(KIND_ADAPTER_AUTH);
                payload.extend_from_slice(proof);
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
    /// Returns [`AdapterTransportError::UnknownMessageKind`],
    /// [`AdapterTransportError::MalformedFrame`],
    /// [`AdapterTransportError::UnsupportedVersion`], or
    /// [`AdapterTransportError::InvalidIdentifier`].
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterTransportError> {
        let (kind, mut rest) = payload
            .split_first()
            .ok_or(AdapterTransportError::MalformedFrame)?;
        let message = match *kind {
            KIND_ADAPTER_HELLO => {
                let version = u16::from_be_bytes(take_array::<2>(&mut rest)?);
                if version != ADAPTER_PROTOCOL_VERSION {
                    return Err(AdapterTransportError::UnsupportedVersion);
                }
                let consumer = take_identifier(&mut rest, "consumer")?;
                let challenge =
                    AuthChallenge::from_bytes(take_array::<CHALLENGE_LENGTH>(&mut rest)?);
                Self::AdapterHello {
                    version,
                    consumer,
                    challenge,
                }
            }
            KIND_DAEMON_AUTH => {
                let profile = take_identifier(&mut rest, "profile")?;
                let challenge =
                    AuthChallenge::from_bytes(take_array::<CHALLENGE_LENGTH>(&mut rest)?);
                let proof = take_array::<CHALLENGE_LENGTH>(&mut rest)?;
                Self::DaemonAuth {
                    profile,
                    challenge,
                    proof,
                }
            }
            KIND_ADAPTER_AUTH => Self::AdapterAuth {
                proof: take_array::<CHALLENGE_LENGTH>(&mut rest)?,
            },
            _ => return Err(AdapterTransportError::UnknownMessageKind),
        };
        if !rest.is_empty() {
            return Err(AdapterTransportError::MalformedFrame);
        }
        Ok(message)
    }
}

fn push_bounded(payload: &mut Vec<u8>, value: &[u8]) {
    let length = u16::try_from(value.len()).unwrap_or(u16::MAX);
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(value);
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], AdapterTransportError> {
    if rest.len() < N {
        return Err(AdapterTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(N);
    let mut value = [0_u8; N];
    value.copy_from_slice(head);
    *rest = tail;
    Ok(value)
}

fn take_identifier(rest: &mut &[u8], field: &'static str) -> Result<String, AdapterTransportError> {
    let length = usize::from(u16::from_be_bytes(take_array::<2>(rest)?));
    if length == 0 || length > MAX_IDENTIFIER_LENGTH {
        return Err(AdapterTransportError::InvalidIdentifier { field });
    }
    if rest.len() < length {
        return Err(AdapterTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(length);
    *rest = tail;
    let value = core::str::from_utf8(head)
        .map_err(|_| AdapterTransportError::InvalidIdentifier { field })?;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        FRAME_HEADER_LENGTH, HandshakeMessage, MAX_AUTHENTICATED_FRAME_BYTES,
        MAX_PREAUTH_FRAME_BYTES, decode_frame_length, encode_frame,
    };
    use crate::error::AdapterTransportError;
    use crate::transcript::{ADAPTER_PROTOCOL_VERSION, AuthChallenge, CHALLENGE_LENGTH};

    fn hello() -> HandshakeMessage {
        HandshakeMessage::AdapterHello {
            version: ADAPTER_PROTOCOL_VERSION,
            consumer: "01HQ8Z3K".to_string(),
            challenge: AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
        }
    }

    fn daemon_auth() -> HandshakeMessage {
        HandshakeMessage::DaemonAuth {
            profile: "alice".to_string(),
            challenge: AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
            proof: [3_u8; CHALLENGE_LENGTH],
        }
    }

    #[test]
    fn every_handshake_message_round_trips() {
        for message in [
            hello(),
            daemon_auth(),
            HandshakeMessage::AdapterAuth {
                proof: [4_u8; CHALLENGE_LENGTH],
            },
        ] {
            let payload = message.encode();
            assert!(payload.len() <= MAX_PREAUTH_FRAME_BYTES);
            assert_eq!(HandshakeMessage::decode(&payload).unwrap(), message);
        }
    }

    #[test]
    fn the_preauth_limit_is_far_below_the_authenticated_limit() {
        let declared = u32::try_from(MAX_PREAUTH_FRAME_BYTES + 1).unwrap();
        assert_eq!(
            decode_frame_length(declared.to_be_bytes(), MAX_PREAUTH_FRAME_BYTES).unwrap_err(),
            AdapterTransportError::FrameTooLarge
        );
        assert_eq!(
            decode_frame_length(declared.to_be_bytes(), MAX_AUTHENTICATED_FRAME_BYTES).unwrap(),
            MAX_PREAUTH_FRAME_BYTES + 1
        );
    }

    #[test]
    fn an_oversized_declaration_is_rejected_without_reserving_a_buffer() {
        assert_eq!(
            decode_frame_length(u32::MAX.to_be_bytes(), MAX_AUTHENTICATED_FRAME_BYTES).unwrap_err(),
            AdapterTransportError::FrameTooLarge
        );
        assert_eq!(
            decode_frame_length(0_u32.to_be_bytes(), MAX_PREAUTH_FRAME_BYTES).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
    }

    #[test]
    fn encoding_prefixes_the_exact_payload_length() {
        let payload = hello().encode();
        let frame = encode_frame(&payload, MAX_PREAUTH_FRAME_BYTES).unwrap();
        assert_eq!(frame.len(), FRAME_HEADER_LENGTH + payload.len());
        let mut header = [0_u8; FRAME_HEADER_LENGTH];
        header.copy_from_slice(&frame[..FRAME_HEADER_LENGTH]);
        assert_eq!(
            decode_frame_length(header, MAX_PREAUTH_FRAME_BYTES).unwrap(),
            payload.len()
        );
        assert_eq!(
            encode_frame(&[], MAX_PREAUTH_FRAME_BYTES).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
        assert_eq!(
            encode_frame(&[0_u8; 8], 4).unwrap_err(),
            AdapterTransportError::FrameTooLarge
        );
    }

    #[test]
    fn an_unknown_message_kind_is_rejected() {
        assert_eq!(
            HandshakeMessage::decode(&[9_u8, 0, 0]).unwrap_err(),
            AdapterTransportError::UnknownMessageKind
        );
        assert_eq!(
            HandshakeMessage::decode(&[]).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
    }

    #[test]
    fn an_unimplemented_version_is_rejected_before_the_rest_of_the_message() {
        let mut payload = hello().encode();
        payload[1..3].copy_from_slice(&(ADAPTER_PROTOCOL_VERSION + 1).to_be_bytes());
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            AdapterTransportError::UnsupportedVersion
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        for message in [hello(), daemon_auth()] {
            let mut payload = message.encode();
            payload.push(0);
            assert_eq!(
                HandshakeMessage::decode(&payload).unwrap_err(),
                AdapterTransportError::MalformedFrame
            );
        }
    }

    #[test]
    fn a_truncated_message_is_rejected_at_every_field() {
        let payload = daemon_auth().encode();
        for length in 1..payload.len() {
            assert!(
                HandshakeMessage::decode(&payload[..length]).is_err(),
                "prefix of {length} bytes must not decode"
            );
        }
    }

    #[test]
    fn a_declared_identifier_length_beyond_the_payload_is_rejected() {
        let mut payload = daemon_auth().encode();
        let overrun = u16::try_from(payload.len() + 64).unwrap().to_be_bytes();
        payload[1..3].copy_from_slice(&overrun);
        assert!(matches!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            AdapterTransportError::InvalidIdentifier { .. } | AdapterTransportError::MalformedFrame
        ));
    }

    #[test]
    fn an_empty_or_oversized_declared_identifier_is_rejected() {
        let mut empty = daemon_auth().encode();
        empty[1..3].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            HandshakeMessage::decode(&empty).unwrap_err(),
            AdapterTransportError::InvalidIdentifier { field: "profile" }
        );
    }

    #[test]
    fn a_non_utf8_identifier_is_rejected() {
        let mut payload = daemon_auth().encode();
        payload[3] = 0xFF;
        assert_eq!(
            HandshakeMessage::decode(&payload).unwrap_err(),
            AdapterTransportError::InvalidIdentifier { field: "profile" }
        );
    }
}
