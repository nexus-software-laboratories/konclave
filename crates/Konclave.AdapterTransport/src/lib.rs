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
mod transcript;

pub use capability::LaunchCapability;
pub use error::AdapterTransportError;
pub use transcript::{
    ADAPTER_PROTOCOL_VERSION, AuthChallenge, AuthTranscript, CHALLENGE_LENGTH,
    MAX_IDENTIFIER_LENGTH,
};
