#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod access;
mod application;
mod client;
mod error;
mod http;
mod projection;

pub use access::{
    A2ABearerCredential, A2AHttpAccess, A2AHttpAction, A2AHttpAuthorizationDecision,
    A2AHttpPrincipalId, StaticBearerAccess,
};
pub use application::{
    A2AGatewayApplication, A2AGatewayClock, A2AGatewayClockError, A2AGatewayWaitConfig,
    A2ATaskSubmission, A2ATaskSubmissionError, A2ATaskSubmitter, SystemA2AGatewayClock,
};
pub use client::{
    A2AAgentCardFetchOutcome, A2AHttpClientConfig, A2AHttpJsonClient, fetch_public_agent_card,
};
pub use error::A2AGatewayError;
pub use http::{
    A2A_JSON_MEDIA_TYPE, A2A_VERSION_HEADER, A2AHttpConfig, A2AHttpState, a2a_router,
    serve_a2a_until, validate_a2a_binding,
};
