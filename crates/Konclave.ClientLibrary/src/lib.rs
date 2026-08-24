#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Outbound relay transport and client composition for trusted Konclave endpoints.

mod credential;
mod endpoint;
mod enrollment;
mod enrollment_credential;
mod error;
mod health;
mod http;
mod installation;
mod pairing;
mod protected_http;
mod websocket;

pub use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentAuthorityId, RelayEnrollmentOutcome,
    RelayEnrollmentRequest, RelayEnrollmentResponse, RelayPrincipalId,
};
pub use credential::RelayAccessCredential;
pub use endpoint::RelayEndpoint;
pub use enrollment::{
    HttpRelayEnrollmentTransport, RelayEnrollmentClient, RelayEnrollmentTransport,
};
pub use enrollment_credential::RelayEnrollmentCredential;
pub use error::KonclaveClientError;
pub use health::check_relay_health;
pub use http::{RelayClient, RelayTransport};
pub use installation::{
    RELAY_INSTALLATION_CONFIG_FILE, RelayEnrollmentSourceConfig, RelayInstallationConfig,
    RelayInstallationConfigError, default_profile_root,
};
pub use pairing::{MAX_PAIRING_CAPABILITY_TEXT_BYTES, PairingCapability, PairingCapabilityText};
pub use websocket::RelayWatchSession;

#[cfg(test)]
mod tests {
    #[test]
    fn dependency_trace_logging_is_compiled_out() {
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }
}
