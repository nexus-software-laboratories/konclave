#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Harness-neutral authentication for Konclave's local adapter channel.
//!
//! An adapter creates a local endpoint and an owner-protected launch capability, then
//! starts a daemon that connects outward to it. Both sides prove possession of that
//! capability over one canonical transcript before any event data flows. Nothing here
//! knows about a specific agent harness, so every adapter shares one contract.

mod capability;
mod endpoint;
mod error;
mod frame;
mod handshake;
mod transcript;

pub use capability::LaunchCapability;
pub use endpoint::{
    AdapterConnection, AdapterEndpoint, MAX_ENDPOINT_LENGTH, connect_adapter_endpoint,
};
pub use error::AdapterTransportError;
pub use frame::{
    FRAME_HEADER_LENGTH, HandshakeMessage, MAX_AUTHENTICATED_FRAME_BYTES, MAX_PREAUTH_FRAME_BYTES,
    decode_frame_length, encode_frame,
};
pub use handshake::{
    AuthenticatedChannel, HANDSHAKE_TIMEOUT, SequentialChallenges, complete_adapter_handshake,
    complete_daemon_handshake,
};
pub use transcript::{
    ADAPTER_PROTOCOL_VERSION, AuthChallenge, AuthTranscript, CHALLENGE_LENGTH,
    MAX_IDENTIFIER_LENGTH,
};

/// Supplies non-repeating handshake challenges.
///
/// Production callers back this with an operating-system random source. Making it a
/// trait keeps that source out of this crate, so the contract can be exercised
/// deterministically without a test-only branch in the production path.
pub trait ChallengeSource: Send {
    /// Returns a challenge that this source has not issued before.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::ChallengeExhausted`] when no further
    /// non-repeating value can be produced.
    fn next_challenge(&mut self) -> Result<[u8; CHALLENGE_LENGTH], AdapterTransportError>;
}
