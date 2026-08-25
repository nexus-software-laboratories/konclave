use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::AdapterTransportError;
use crate::frame::{HandshakeMessage, MAX_PREAUTH_FRAME_BYTES};
use crate::transcript::{
    ADAPTER_PROTOCOL_VERSION, AuthChallenge, AuthTranscript, CHALLENGE_LENGTH,
};
use crate::{ChallengeSource, LaunchCapability};

/// Longest a peer may take to complete the handshake.
///
/// An unauthenticated peer that opens a connection and stalls would otherwise hold a
/// task and a buffer indefinitely, so the whole exchange is bounded rather than each
/// individual read.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The values a daemon establishes with an adapter once both proofs verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedChannel {
    profile: String,
    consumer: String,
}

impl AuthenticatedChannel {
    /// Returns the profile this channel is bound to.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the adapter consumer instance this channel is bound to.
    #[must_use]
    pub fn consumer(&self) -> &str {
        &self.consumer
    }
}

/// Runs the daemon side of the handshake over an already connected stream.
///
/// The daemon connects outward to an adapter-owned endpoint, so this drives the
/// exchange rather than accepting one. The adapter opens, the daemon answers with its
/// profile, challenge, and proof, and the adapter returns its proof. Nothing beyond
/// the handshake is read here, so a caller keeps the stream for authenticated traffic.
///
/// The expected profile is supplied by the caller and compared against the value the
/// adapter agreed to authenticate, so a capability that belongs to another profile
/// cannot attach.
///
/// # Errors
///
/// Returns [`AdapterTransportError::HandshakeTimeout`] when the exchange exceeds
/// [`HANDSHAKE_TIMEOUT`], [`AdapterTransportError::UnauthenticPeer`] when the adapter
/// proof does not verify, [`AdapterTransportError::ProfileMismatch`] when the adapter
/// opened against a different profile, or a frame or identifier failure.
pub async fn complete_daemon_handshake<S>(
    stream: &mut S,
    expected_profile: &str,
    capability: &LaunchCapability,
    challenges: &mut dyn ChallengeSource,
) -> Result<AuthenticatedChannel, AdapterTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        daemon_handshake(stream, expected_profile, capability, challenges),
    )
    .await
    .map_err(|_| AdapterTransportError::HandshakeTimeout)?
}

async fn daemon_handshake<S>(
    stream: &mut S,
    expected_profile: &str,
    capability: &LaunchCapability,
    challenges: &mut dyn ChallengeSource,
) -> Result<AuthenticatedChannel, AdapterTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let HandshakeMessage::AdapterHello {
        consumer,
        challenge: adapter_challenge,
        ..
    } = read_message(stream).await?
    else {
        return Err(AdapterTransportError::UnexpectedMessage);
    };

    let daemon_challenge = AuthChallenge::from_bytes(challenges.next_challenge()?);
    let transcript = AuthTranscript::new(
        ADAPTER_PROTOCOL_VERSION,
        expected_profile,
        &consumer,
        adapter_challenge,
        daemon_challenge,
    )?;

    write_message(
        stream,
        &HandshakeMessage::DaemonAuth {
            profile: expected_profile.to_string(),
            challenge: daemon_challenge,
            proof: transcript.daemon_proof(capability)?,
        },
    )
    .await?;

    let HandshakeMessage::AdapterAuth { proof } = read_message(stream).await? else {
        return Err(AdapterTransportError::UnexpectedMessage);
    };
    transcript.verify_adapter_proof(capability, &proof)?;

    Ok(AuthenticatedChannel {
        profile: expected_profile.to_string(),
        consumer,
    })
}

/// Runs the adapter side of the handshake, for conformance testing and for adapters
/// that embed this crate rather than reimplementing the contract.
///
/// # Errors
///
/// Returns the same failures as [`complete_daemon_handshake`], plus
/// [`AdapterTransportError::ProfileMismatch`] when the daemon answers for a profile
/// this adapter did not launch.
pub async fn complete_adapter_handshake<S>(
    stream: &mut S,
    expected_profile: &str,
    consumer: &str,
    capability: &LaunchCapability,
    challenges: &mut dyn ChallengeSource,
) -> Result<AuthenticatedChannel, AdapterTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        adapter_handshake(stream, expected_profile, consumer, capability, challenges),
    )
    .await
    .map_err(|_| AdapterTransportError::HandshakeTimeout)?
}

async fn adapter_handshake<S>(
    stream: &mut S,
    expected_profile: &str,
    consumer: &str,
    capability: &LaunchCapability,
    challenges: &mut dyn ChallengeSource,
) -> Result<AuthenticatedChannel, AdapterTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let adapter_challenge = AuthChallenge::from_bytes(challenges.next_challenge()?);
    write_message(
        stream,
        &HandshakeMessage::AdapterHello {
            version: ADAPTER_PROTOCOL_VERSION,
            consumer: consumer.to_string(),
            challenge: adapter_challenge,
        },
    )
    .await?;

    let HandshakeMessage::DaemonAuth {
        profile,
        challenge: daemon_challenge,
        proof,
    } = read_message(stream).await?
    else {
        return Err(AdapterTransportError::UnexpectedMessage);
    };
    if profile != expected_profile {
        return Err(AdapterTransportError::ProfileMismatch);
    }

    let transcript = AuthTranscript::new(
        ADAPTER_PROTOCOL_VERSION,
        &profile,
        consumer,
        adapter_challenge,
        daemon_challenge,
    )?;
    transcript.verify_daemon_proof(capability, &proof)?;

    write_message(
        stream,
        &HandshakeMessage::AdapterAuth {
            proof: transcript.adapter_proof(capability)?,
        },
    )
    .await?;

    Ok(AuthenticatedChannel {
        profile,
        consumer: consumer.to_string(),
    })
}

async fn read_message<S>(stream: &mut S) -> Result<HandshakeMessage, AdapterTransportError>
where
    S: AsyncRead + Unpin,
{
    let payload = read_frame(stream, MAX_PREAUTH_FRAME_BYTES).await?;
    HandshakeMessage::decode(&payload)
}

/// Reads one length-prefixed frame, refusing a declared length above `limit`.
///
/// # Errors
///
/// Returns [`AdapterTransportError::ChannelClosed`] when the peer stops,
/// [`AdapterTransportError::FrameTooLarge`] when the declared length exceeds `limit`,
/// or [`AdapterTransportError::MalformedFrame`] for a zero length.
pub async fn read_frame<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, AdapterTransportError>
where
    S: AsyncRead + Unpin,
{
    KonclaveLocalFraming::read_frame(stream, limit)
        .await
        .map_err(AdapterTransportError::from)
}

/// Writes one length-prefixed frame, refusing a payload above `limit`.
///
/// # Errors
///
/// Returns [`AdapterTransportError::FrameTooLarge`] when the payload exceeds `limit`
/// or [`AdapterTransportError::ChannelClosed`] when the peer stops.
pub async fn write_frame<S>(
    stream: &mut S,
    payload: &[u8],
    limit: usize,
) -> Result<(), AdapterTransportError>
where
    S: AsyncWrite + Unpin,
{
    KonclaveLocalFraming::write_frame(stream, payload, limit)
        .await
        .map_err(AdapterTransportError::from)
}

async fn write_message<S>(
    stream: &mut S,
    message: &HandshakeMessage,
) -> Result<(), AdapterTransportError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &message.encode(), MAX_PREAUTH_FRAME_BYTES).await
}

/// A deterministic challenge source for tests and conformance vectors.
///
/// Production callers use [`OsChallenges`]. A fixed sequence here keeps handshake
/// tests reproducible without weakening the production path, and the source still
/// refuses to repeat a challenge within one process.
#[derive(Debug, Default)]
pub struct SequentialChallenges {
    issued: u64,
}

impl SequentialChallenges {
    /// Creates a source that starts from the first challenge.
    #[must_use]
    pub const fn new() -> Self {
        Self { issued: 0 }
    }
}

impl ChallengeSource for SequentialChallenges {
    fn next_challenge(&mut self) -> Result<[u8; CHALLENGE_LENGTH], AdapterTransportError> {
        self.issued = self
            .issued
            .checked_add(1)
            .ok_or(AdapterTransportError::ChallengeExhausted)?;
        let mut challenge = [0_u8; CHALLENGE_LENGTH];
        challenge[..8].copy_from_slice(&self.issued.to_be_bytes());
        Ok(challenge)
    }
}

/// The production challenge source.
///
/// Each challenge is operating-system random material with a monotonic counter in its
/// trailing bytes. The randomness makes a challenge unpredictable, and the counter
/// makes repetition within one process structurally impossible without retaining
/// every value ever issued.
#[derive(Debug, Default)]
pub struct OsChallenges {
    issued: u64,
}

impl OsChallenges {
    /// Creates a source that starts from the first challenge.
    #[must_use]
    pub const fn new() -> Self {
        Self { issued: 0 }
    }
}

impl ChallengeSource for OsChallenges {
    fn next_challenge(&mut self) -> Result<[u8; CHALLENGE_LENGTH], AdapterTransportError> {
        self.issued = self
            .issued
            .checked_add(1)
            .ok_or(AdapterTransportError::ChallengeExhausted)?;
        let mut challenge = [0_u8; CHALLENGE_LENGTH];
        KonclaveCryptographicCore::fill_random(&mut challenge)
            .map_err(|_| AdapterTransportError::ChallengeExhausted)?;
        let counter = self.issued.to_be_bytes();
        challenge[CHALLENGE_LENGTH - counter.len()..].copy_from_slice(&counter);
        Ok(challenge)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::OsChallenges;
    use crate::ChallengeSource;

    #[test]
    fn operating_system_challenges_never_repeat_and_are_not_sequential() {
        let mut source = OsChallenges::new();
        let mut seen = HashSet::new();
        let mut previous = None;
        for _ in 0..256 {
            let challenge = source.next_challenge().unwrap();
            assert!(
                seen.insert(challenge),
                "challenge repeated within one process"
            );
            if let Some(previous) = previous {
                assert_ne!(
                    challenge, previous,
                    "consecutive challenges must not be identical"
                );
            }
            // The leading bytes carry randomness rather than the counter, so an
            // observer cannot predict the next challenge from the previous one.
            assert_ne!(challenge[..8], [0_u8; 8]);
            previous = Some(challenge);
        }
    }
}
