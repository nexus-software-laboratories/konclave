#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Outbound relay transport and client composition for trusted Konclave endpoints.

mod credential;
mod endpoint;
mod enrollment;
mod error;
mod http;
mod pairing;
mod websocket;

pub use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayEnrollmentResponse,
    RelayPrincipalId,
};
pub use credential::RelayAccessCredential;
pub use endpoint::RelayEndpoint;
pub use enrollment::{RelayEnrollmentClient, RelayEnrollmentTransport};
pub use error::KonclaveClientError;
pub use http::{RelayClient, RelayTransport};
pub use pairing::{MAX_PAIRING_CAPABILITY_TEXT_BYTES, PairingCapability, PairingCapabilityText};
pub use websocket::RelayWatchSession;

#[cfg(test)]
mod tests {
    #[test]
    fn dependency_trace_logging_is_compiled_out() {
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }
}
