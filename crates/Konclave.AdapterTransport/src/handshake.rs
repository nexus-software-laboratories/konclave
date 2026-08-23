use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::AdapterTransportError;
use crate::frame::{
    FRAME_HEADER_LENGTH, HandshakeMessage, MAX_PREAUTH_FRAME_BYTES, decode_frame_length,
    encode_frame,
};
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
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| AdapterTransportError::ChannelClosed)?;
    let length = decode_frame_length(header, MAX_PREAUTH_FRAME_BYTES)?;
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|_| AdapterTransportError::ChannelClosed)?;
    HandshakeMessage::decode(&payload)
}

async fn write_message<S>(
    stream: &mut S,
    message: &HandshakeMessage,
) -> Result<(), AdapterTransportError>
where
    S: AsyncWrite + Unpin,
{
    let frame = encode_frame(&message.encode(), MAX_PREAUTH_FRAME_BYTES)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|_| AdapterTransportError::ChannelClosed)?;
    stream
        .flush()
        .await
        .map_err(|_| AdapterTransportError::ChannelClosed)
}

/// A deterministic challenge source for tests and conformance vectors.
///
/// Production callers supply an operating-system random source. A fixed sequence here
/// keeps handshake tests reproducible without weakening the production path, and the
/// source still refuses to repeat a challenge within one process.
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
