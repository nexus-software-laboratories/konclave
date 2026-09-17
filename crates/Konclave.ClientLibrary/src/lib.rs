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
mod pairing_rendezvous;
mod protected_http;
mod websocket;

pub use KonclaveDomainCore::{
    MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES, MAX_PAIRING_RENDEZVOUS_RECORD_BYTES,
    PairingRendezvousId, PairingRendezvousNonce, PairingRendezvousRecord,
    PairingRendezvousTakeRequest, ShortCodeAttemptClaimRequest, ShortCodeAttemptMessageRequest,
    ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest, ShortCodeAttemptSnapshot,
    ShortCodePairingAttemptId, ShortCodePairingLocator, ShortCodeRelayMessage, ShortCodeRelayStage,
};
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
pub use http::{
    PairingRendezvousPublishResult, PairingRendezvousTransport, RelayClient, RelayTransport,
    ShortCodeAttemptMessageResult, ShortCodeAttemptPublishResult, ShortCodePairingTransport,
};
pub use installation::{
    RELAY_INSTALLATION_CONFIG_FILE, RelayEnrollmentSourceConfig, RelayInstallationConfig,
    RelayInstallationConfigError, default_profile_root, relay_enrollment_installation_id,
};
pub use pairing::{MAX_PAIRING_CAPABILITY_TEXT_BYTES, PairingCapability, PairingCapabilityText};
pub use pairing_rendezvous::{
    PAIRING_RENDEZVOUS_TOKEN_CHARACTERS, PairingRendezvousTokenText, create_pairing_rendezvous,
    open_pairing_rendezvous, pairing_rendezvous_take_request,
};
pub use websocket::RelayWatchSession;

#[cfg(test)]
mod tests {
    #[test]
    fn dependency_trace_logging_is_compiled_out() {
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }
}
