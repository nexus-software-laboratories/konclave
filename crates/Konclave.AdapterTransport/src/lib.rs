#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Harness-neutral authentication for Konclave's local adapter channel.
//!
//! An adapter creates a local endpoint and an owner-protected launch capability, then
//! starts a daemon that connects outward to it. Both sides prove possession of that
//! capability over one canonical transcript before any event data flows. Nothing here
//! knows about a specific agent harness, so every adapter shares one contract.

mod capability;
mod error;
mod frame;
mod transcript;

pub use capability::LaunchCapability;
pub use error::AdapterTransportError;
pub use frame::{
    FRAME_HEADER_LENGTH, HandshakeMessage, MAX_AUTHENTICATED_FRAME_BYTES, MAX_PREAUTH_FRAME_BYTES,
    decode_frame_length, encode_frame,
};
pub use transcript::{
    ADAPTER_PROTOCOL_VERSION, AuthChallenge, AuthTranscript, CHALLENGE_LENGTH,
    MAX_IDENTIFIER_LENGTH,
};
