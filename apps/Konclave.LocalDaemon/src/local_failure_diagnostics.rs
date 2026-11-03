use std::fmt;

use KonclaveLocalServiceTransport::LocalServiceTransportError;
use sha2::{Digest as _, Sha256};

use crate::application::ApplicationServiceError;
use crate::authorization_runtime::AuthorizationRuntimeError;
use crate::conversation::ConversationCoordinatorError;
use crate::local_failure_log::LOCAL_FAILURE_TARGET;
use crate::pairing_service::PairingServiceError;
use crate::persistence::ProfileStoreError;
use crate::profile_lifecycle::{ProfileComponent, ProfileFailure};
use crate::profile_supervisor::ProfileSupervisorError;

const CONNECTION_REFERENCE_DOMAIN: &[u8] = b"konclave:local-connection\0";

/// Ephemeral correlation derived only from the service's fresh public challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionReference(String);

impl ConnectionReference {
    pub(crate) fn new(service_challenge: &[u8; 32]) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONNECTION_REFERENCE_DOMAIN);
        digest.update(service_challenge);
        let mut reference = format!("{:x}", digest.finalize());
        reference.truncate(16);
        Self(reference)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn context(&self, stage: FailureStage, sequence: u64) -> FailureContext {
        FailureContext {
            stage,
            connection: Some(self.clone()),
            sequence,
        }
    }
}

/// Context labels carry no paths, credentials, operation names, or argument values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureStage {
    ServiceLifecycle,
    Handshake,
    ProfileAttach,
    ProfileServices,
    ProfileRuntime,
    ProfileRelayWatch,
    ProfilePairing,
    ProfileAttachment,
    RequestRead,
    RequestExecution,
    ResponseWrite,
    DeliveryRelease,
}

impl FailureStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceLifecycle => "service_lifecycle",
            Self::Handshake => "handshake",
            Self::ProfileAttach => "profile_attach",
            Self::ProfileServices => "profile_services",
            Self::ProfileRuntime => "profile_runtime",
            Self::ProfileRelayWatch => "profile_relay_watch",
            Self::ProfilePairing => "profile_pairing",
            Self::ProfileAttachment => "profile_attachment",
            Self::RequestRead => "request_read",
            Self::RequestExecution => "request_execution",
            Self::ResponseWrite => "response_write",
            Self::DeliveryRelease => "delivery_release",
        }
    }
}

impl fmt::Display for FailureStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error context preserves connection-local ordering without logging request IDs.
#[derive(Clone, Debug)]
pub(crate) struct FailureContext {
    pub(crate) stage: FailureStage,
    pub(crate) connection: Option<ConnectionReference>,
    pub(crate) sequence: u64,
}

impl fmt::Display for FailureContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stage.as_str())
    }
}

/// Classifies typed causes only; arbitrary messages and Debug implementations are ignored.
pub(crate) fn failure_code(error: &anyhow::Error) -> &'static str {
    error
        .chain()
        .find_map(typed_failure_code)
        .unwrap_or("unclassified_failure")
}

fn typed_failure_code(error: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    if let Some(error) = error.downcast_ref::<ProfileFailure>() {
        return Some(failure_code(error.cause()));
    }
    if let Some(error) = error.downcast_ref::<LocalServiceTransportError>() {
        return Some(error.code());
    }
    if let Some(error) = error.downcast_ref::<ProfileSupervisorError>() {
        if let Some(source) = error.failure_source() {
            let code = failure_code(source);
            if code != "unclassified_failure" {
                return Some(code);
            }
        }
        return Some(error.code());
    }
    if let Some(error) = error.downcast_ref::<PairingServiceError>() {
        return Some(pairing_failure_code(error));
    }
    if let Some(error) = error.downcast_ref::<ApplicationServiceError>() {
        return Some(application_failure_code(error));
    }
    if let Some(error) = error.downcast_ref::<ConversationCoordinatorError>() {
        return Some(conversation_failure_code(error));
    }
    if let Some(error) = error.downcast_ref::<KonclaveClientLibrary::KonclaveClientError>() {
        return Some(client_failure_code(error));
    }
    if let Some(error) = error.downcast_ref::<AuthorizationRuntimeError>() {
        return Some(match error {
            AuthorizationRuntimeError::Store(_) => "authorization_store_failure",
            AuthorizationRuntimeError::InvalidProjection => "authorization_invalid_projection",
            AuthorizationRuntimeError::ObservationDeadlineExceeded => {
                "authorization_observation_deadline"
            }
            AuthorizationRuntimeError::BlockingOperationFailed => "authorization_worker_failure",
            AuthorizationRuntimeError::UnexpectedStop => "authorization_stopped",
        });
    }
    if let Some(error) = error.downcast_ref::<ProfileStoreError>() {
        return Some(profile_store_failure_code(error));
    }
    if let Some(error) = error.downcast_ref::<KonclaveSecretStorage::SecretStorageError>() {
        return Some(error.code());
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return Some(match error.kind() {
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::TimedOut => "io_timed_out",
            std::io::ErrorKind::WouldBlock => "io_would_block",
            std::io::ErrorKind::NotFound => "io_not_found",
            _ => "io_failure",
        });
    }
    if let Some(error) = error.downcast_ref::<tokio::task::JoinError>() {
        return Some(if error.is_panic() {
            "worker_panicked"
        } else {
            "worker_cancelled"
        });
    }
    None
}

fn profile_store_failure_code(error: &ProfileStoreError) -> &'static str {
    match error {
        ProfileStoreError::ProfileLocked => "profile_locked",
        ProfileStoreError::Io => "profile_io_failure",
        ProfileStoreError::Storage => "profile_storage_failure",
        ProfileStoreError::UnsupportedSchema => "profile_schema_unsupported",
        ProfileStoreError::ProfileMismatch => "profile_mismatch",
        ProfileStoreError::CorruptData => "profile_integrity_failure",
        ProfileStoreError::Credential => "profile_credential_unavailable",
        ProfileStoreError::AdapterConsumerActive => "adapter_consumer_active",
        ProfileStoreError::InvalidAdapterLease => "adapter_lease_invalid",
        _ => "profile_store_failure",
    }
}

fn client_failure_code(error: &KonclaveClientLibrary::KonclaveClientError) -> &'static str {
    use KonclaveClientLibrary::KonclaveClientError;
    match error {
        KonclaveClientError::RelayRejected { status, .. } => match status {
            401 => "relay_http_unauthorized",
            403 => "relay_http_forbidden",
            404 => "relay_http_not_found",
            409 => "relay_http_conflict",
            410 => "relay_http_expired",
            429 => "relay_http_rate_limited",
            500..=599 => "relay_http_unavailable",
            _ => "relay_http_rejected",
        },
        KonclaveClientError::WatchRejected { .. } => "relay_watch_rejected",
        KonclaveClientError::Timeout => "relay_timeout",
        KonclaveClientError::TransportUnavailable => "relay_transport_unavailable",
        KonclaveClientError::WatchClosed => "relay_watch_closed",
        KonclaveClientError::InvalidResponse => "relay_response_invalid",
        KonclaveClientError::ResponseTooLarge { .. } => "relay_response_too_large",
        KonclaveClientError::Protocol(error) => error.code(),
        KonclaveClientError::Cryptographic(error) => error.code(),
        _ => "relay_client_configuration_failure",
    }
}

fn application_failure_code(error: &ApplicationServiceError) -> &'static str {
    match error {
        ApplicationServiceError::Relay(error) => client_failure_code(error),
        ApplicationServiceError::Conversation(error) => conversation_failure_code(error),
        ApplicationServiceError::PolicyStorage(error) => profile_store_failure_code(error),
        ApplicationServiceError::Task | ApplicationServiceError::Worker(_) => {
            "application_worker_failed"
        }
        ApplicationServiceError::Protocol => "application_protocol_failure",
        ApplicationServiceError::LocalPolicyProposal => "application_local_policy_proposal",
        ApplicationServiceError::PolicyProposalMismatch => "application_policy_proposal_mismatch",
        ApplicationServiceError::IdempotencyConflict => "application_idempotency_conflict",
        ApplicationServiceError::OutboundExpired => "application_outbound_expired",
        ApplicationServiceError::OutboundRemoved => "application_outbound_removed",
        ApplicationServiceError::InvalidRelayResponse => "application_relay_response_invalid",
        ApplicationServiceError::SystemTimeUnavailable => "application_clock_unavailable",
        ApplicationServiceError::WatchCapacityExceeded => "application_watch_capacity_exceeded",
        ApplicationServiceError::ProfileClosing => "profile_closing",
    }
}

fn pairing_failure_code(error: &PairingServiceError) -> &'static str {
    match error {
        PairingServiceError::Application(error) => application_failure_code(error),
        PairingServiceError::Client(error) => client_failure_code(error),
        PairingServiceError::Conversation(error) => conversation_failure_code(error),
        PairingServiceError::Persistence(error) => profile_store_failure_code(error),
        PairingServiceError::Cryptographic(error) => error.code(),
        PairingServiceError::Protocol(error) => error.code(),
        PairingServiceError::Expired => "pairing_expired",
        PairingServiceError::InvalidAuthorizationWindow => "pairing_authorization_window_invalid",
        PairingServiceError::InvalidTransition => "pairing_transition_invalid",
        PairingServiceError::AuthorizationMismatch => "pairing_authorization_mismatch",
        PairingServiceError::RelayMismatch => "pairing_relay_mismatch",
        PairingServiceError::InvalidRelayResponse => "pairing_relay_response_invalid",
        PairingServiceError::Task => "pairing_worker_failed",
        PairingServiceError::ProfileClosing => "profile_closing",
        PairingServiceError::RendezvousCleanup => "pairing_rendezvous_cleanup_failed",
        PairingServiceError::InvalidRendezvousRole => "pairing_rendezvous_role_invalid",
        PairingServiceError::ShortCodeRejected => "short_code_rejected",
        PairingServiceError::State(_) => "pairing_state_failure",
        PairingServiceError::ShortCodeState(_) => "short_code_state_failure",
        PairingServiceError::RepeatPairingState(_) => "repeat_pairing_state_failure",
    }
}

fn conversation_failure_code(error: &ConversationCoordinatorError) -> &'static str {
    match error {
        ConversationCoordinatorError::Profile(error) => profile_store_failure_code(error),
        ConversationCoordinatorError::Cryptographic => "conversation_cryptographic_failure",
        ConversationCoordinatorError::SecretStorage => "conversation_secret_storage_failure",
        ConversationCoordinatorError::StateUnavailable => "conversation_state_unavailable",
        ConversationCoordinatorError::MissingMlsState => "conversation_mls_state_missing",
        ConversationCoordinatorError::MissingMembershipJournal => {
            "conversation_membership_journal_missing"
        }
        ConversationCoordinatorError::StateMismatch => "conversation_state_mismatch",
        ConversationCoordinatorError::Protocol => "conversation_protocol_failure",
        ConversationCoordinatorError::Unauthorized => "conversation_not_authorized",
        _ => "conversation_operation_failure",
    }
}

pub(crate) fn record_profile_failure(error: &anyhow::Error) {
    let stage = match error.downcast_ref::<ProfileComponent>() {
        Some(ProfileComponent::RelayWatch) => FailureStage::ProfileRelayWatch,
        Some(ProfileComponent::Pairing) => FailureStage::ProfilePairing,
        Some(ProfileComponent::Attachment) => FailureStage::ProfileAttachment,
        None => FailureStage::ProfileRuntime,
    };
    record_failure_at(
        error,
        Some(&FailureContext {
            stage,
            connection: None,
            sequence: 0,
        }),
    );
}

pub(crate) fn record_failure(error: &anyhow::Error) {
    record_failure_at(error, error.downcast_ref::<FailureContext>());
}

pub(crate) fn record_failure_at(error: &anyhow::Error, context: Option<&FailureContext>) {
    record_code(context, failure_code(error));
}

pub(crate) fn record_code(context: Option<&FailureContext>, code: &'static str) {
    tracing::warn!(
        target: LOCAL_FAILURE_TARGET,
        stage = context.map_or("client_task", |context| context.stage.as_str()),
        code,
        connection = context.and_then(|context| context.connection.as_ref().map(ConnectionReference::as_str)),
        request_sequence = context.map(|context| context.sequence),
        "local service failure"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_retained_code(error: anyhow::Error, expected: &'static str) {
        assert_eq!(failure_code(&error), expected);
        let failure = ProfileFailure::new(error);
        assert_eq!(format!("{failure:?}"), "ProfileFailure");
        assert_eq!(failure.to_string(), "the profile task set failed");
        let refusal = ProfileSupervisorError::FailedRuntime(failure);
        assert_eq!(failure_code(&anyhow::Error::new(refusal.clone())), expected);
        assert!(!format!("{refusal:?}").contains("PRIVATE"));
        assert!(!refusal.to_string().contains("PRIVATE"));
    }

    #[test]
    fn retained_relay_failures_never_export_remote_code_strings() {
        use KonclaveClientLibrary::KonclaveClientError;
        for (status, expected) in [
            (401, "relay_http_unauthorized"),
            (403, "relay_http_forbidden"),
            (404, "relay_http_not_found"),
            (409, "relay_http_conflict"),
            (410, "relay_http_expired"),
            (429, "relay_http_rate_limited"),
            (500, "relay_http_unavailable"),
            (599, "relay_http_unavailable"),
            (400, "relay_http_rejected"),
            (600, "relay_http_rejected"),
        ] {
            assert_retained_code(
                PairingServiceError::Application(ApplicationServiceError::Relay(
                    KonclaveClientError::RelayRejected {
                        status,
                        relay_code: "PRIVATE-CREDENTIAL-AND-PAYLOAD".to_owned(),
                    },
                ))
                .into(),
                expected,
            );
        }
        for (error, expected) in [
            (KonclaveClientError::WatchRejected {
                close_code: 4401,
                relay_code: "PRIVATE-CREDENTIAL-AND-PAYLOAD".to_owned(),
            }, "relay_watch_rejected"),
            (KonclaveClientError::Timeout, "relay_timeout"),
            (KonclaveClientError::TransportUnavailable, "relay_transport_unavailable"),
            (KonclaveClientError::WatchClosed, "relay_watch_closed"),
            (KonclaveClientError::InvalidResponse, "relay_response_invalid"),
            (KonclaveClientError::ResponseTooLarge { maximum: 1 }, "relay_response_too_large"),
            (KonclaveClientError::InvalidEndpoint, "relay_client_configuration_failure"),
            (KonclaveClientError::Protocol(
                KonclaveProtocolContracts::KonclaveProtocolError::Decode {
                    contract: "test",
                    reason: "PRIVATE-CREDENTIAL-AND-PAYLOAD".to_owned(),
                },
            ), "malformed"),
            (KonclaveClientError::Cryptographic(
                KonclaveCryptographicCore::KonclaveCryptographicError::InvalidLocalServiceSignature,
            ), "invalid_local_service_signature"),
        ] {
            assert_retained_code(PairingServiceError::Client(error).into(), expected);
        }
    }

    #[test]
    fn application_and_pairing_failures_have_finite_retained_codes() {
        for (error, expected) in [
            (ApplicationServiceError::Task, "application_worker_failed"),
            (
                ApplicationServiceError::Worker(crate::native_workers::NativeWorkerError::Task),
                "application_worker_failed",
            ),
            (
                ApplicationServiceError::Worker(
                    crate::native_workers::NativeWorkerError::UnobservedOperation(Box::new(
                        ConversationCoordinatorError::StateUnavailable,
                    )),
                ),
                "application_worker_failed",
            ),
            (
                ApplicationServiceError::Protocol,
                "application_protocol_failure",
            ),
            (
                ApplicationServiceError::LocalPolicyProposal,
                "application_local_policy_proposal",
            ),
            (
                ApplicationServiceError::PolicyProposalMismatch,
                "application_policy_proposal_mismatch",
            ),
            (
                ApplicationServiceError::IdempotencyConflict,
                "application_idempotency_conflict",
            ),
            (
                ApplicationServiceError::OutboundExpired,
                "application_outbound_expired",
            ),
            (
                ApplicationServiceError::OutboundRemoved,
                "application_outbound_removed",
            ),
            (
                ApplicationServiceError::InvalidRelayResponse,
                "application_relay_response_invalid",
            ),
            (
                ApplicationServiceError::SystemTimeUnavailable,
                "application_clock_unavailable",
            ),
            (
                ApplicationServiceError::WatchCapacityExceeded,
                "application_watch_capacity_exceeded",
            ),
            (ApplicationServiceError::ProfileClosing, "profile_closing"),
            (
                ApplicationServiceError::PolicyStorage(ProfileStoreError::Storage),
                "profile_storage_failure",
            ),
            (
                ApplicationServiceError::Conversation(
                    ConversationCoordinatorError::StateUnavailable,
                ),
                "conversation_state_unavailable",
            ),
        ] {
            assert_retained_code(PairingServiceError::Application(error).into(), expected);
        }
        for (error, expected) in [
            (PairingServiceError::Expired, "pairing_expired"),
            (PairingServiceError::InvalidAuthorizationWindow, "pairing_authorization_window_invalid"),
            (PairingServiceError::InvalidTransition, "pairing_transition_invalid"),
            (PairingServiceError::AuthorizationMismatch, "pairing_authorization_mismatch"),
            (PairingServiceError::RelayMismatch, "pairing_relay_mismatch"),
            (PairingServiceError::InvalidRelayResponse, "pairing_relay_response_invalid"),
            (PairingServiceError::Task, "pairing_worker_failed"),
            (PairingServiceError::ProfileClosing, "profile_closing"),
            (PairingServiceError::RendezvousCleanup, "pairing_rendezvous_cleanup_failed"),
            (PairingServiceError::InvalidRendezvousRole, "pairing_rendezvous_role_invalid"),
            (PairingServiceError::ShortCodeRejected, "short_code_rejected"),
            (PairingServiceError::State(crate::pairing::PairingStateError::InvalidEncoding), "pairing_state_failure"),
            (PairingServiceError::ShortCodeState(crate::short_code_pairing::ShortCodeStateError::InvalidEncoding), "short_code_state_failure"),
            (PairingServiceError::RepeatPairingState(crate::repeat_pairing::RepeatPairingStateError::InvalidState), "repeat_pairing_state_failure"),
            (PairingServiceError::Persistence(ProfileStoreError::Storage), "profile_storage_failure"),
            (PairingServiceError::Conversation(ConversationCoordinatorError::MissingMlsState), "conversation_mls_state_missing"),
            (PairingServiceError::Protocol(KonclaveProtocolContracts::KonclaveProtocolError::MissingField { field: "test" }), "missing_field"),
            (PairingServiceError::Cryptographic(KonclaveCryptographicCore::KonclaveCryptographicError::InvalidLocalServiceSignature), "invalid_local_service_signature"),
        ] {
            assert_retained_code(error.into(), expected);
        }
    }

    #[test]
    fn conversation_failures_remain_typed_through_transparent_wrappers() {
        for (error, expected) in [
            (
                ConversationCoordinatorError::Profile(ProfileStoreError::Storage),
                "profile_storage_failure",
            ),
            (
                ConversationCoordinatorError::Cryptographic,
                "conversation_cryptographic_failure",
            ),
            (
                ConversationCoordinatorError::SecretStorage,
                "conversation_secret_storage_failure",
            ),
            (
                ConversationCoordinatorError::StateUnavailable,
                "conversation_state_unavailable",
            ),
            (
                ConversationCoordinatorError::MissingMlsState,
                "conversation_mls_state_missing",
            ),
            (
                ConversationCoordinatorError::MissingMembershipJournal,
                "conversation_membership_journal_missing",
            ),
            (
                ConversationCoordinatorError::StateMismatch,
                "conversation_state_mismatch",
            ),
            (
                ConversationCoordinatorError::Protocol,
                "conversation_protocol_failure",
            ),
            (
                ConversationCoordinatorError::Unauthorized,
                "conversation_not_authorized",
            ),
            (
                ConversationCoordinatorError::TrustedDeviceRemoved,
                "conversation_operation_failure",
            ),
        ] {
            assert_retained_code(PairingServiceError::Conversation(error).into(), expected);
        }
    }

    #[test]
    fn references_are_bounded_ephemeral_and_domain_separated() {
        let first = ConnectionReference::new(&[0x42; 32]);
        assert_eq!(first.as_str(), "5c80549fc794cd0e");
        assert_eq!(first.as_str().len(), 16);
        assert!(first.as_str().bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, ConnectionReference::new(&[0x43; 32]));
        assert_eq!(first, ConnectionReference::new(&[0x42; 32]));
        assert_ne!(first.as_str(), "4242424242424242");
    }

    #[test]
    fn typed_errors_and_context_keep_messages_out_of_codes() {
        let cases = [
            (
                anyhow::Error::new(LocalServiceTransportError::ChannelClosed),
                "local_service_channel_closed",
            ),
            (
                anyhow::Error::new(ProfileSupervisorError::ClientLimit),
                "client_limit",
            ),
            (
                anyhow::Error::new(ProfileSupervisorError::ProfileLocked),
                "profile_locked",
            ),
            (
                anyhow::Error::new(ProfileSupervisorError::Open(std::sync::Arc::new(
                    anyhow::Error::new(ProfileStoreError::Storage),
                ))),
                "profile_storage_failure",
            ),
            (
                anyhow::Error::new(AuthorizationRuntimeError::ObservationDeadlineExceeded),
                "authorization_observation_deadline",
            ),
            (
                anyhow::Error::new(
                    KonclaveSecretStorage::SecretStorageError::OwnerProtectedStorageUnsafe,
                ),
                "owner_protected_storage_unsafe",
            ),
            (
                anyhow::Error::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "PRIVATE-CREDENTIAL-AND-PAYLOAD",
                )),
                "permission_denied",
            ),
            (
                anyhow::anyhow!("PRIVATE-CREDENTIAL-AND-PAYLOAD"),
                "unclassified_failure",
            ),
        ];
        for (error, expected) in cases {
            let error = error.context(FailureContext {
                stage: FailureStage::ProfileAttach,
                connection: Some(ConnectionReference::new(&[0x42; 32])),
                sequence: 1,
            });
            assert_eq!(failure_code(&error), expected);
            assert_eq!(
                error.downcast_ref::<FailureContext>().unwrap().stage,
                FailureStage::ProfileAttach
            );
        }
    }

    #[test]
    fn all_failure_stages_have_distinct_finite_labels() {
        let stages = [
            FailureStage::ServiceLifecycle,
            FailureStage::Handshake,
            FailureStage::ProfileAttach,
            FailureStage::ProfileServices,
            FailureStage::ProfileRuntime,
            FailureStage::ProfileRelayWatch,
            FailureStage::ProfilePairing,
            FailureStage::ProfileAttachment,
            FailureStage::RequestRead,
            FailureStage::RequestExecution,
            FailureStage::ResponseWrite,
            FailureStage::DeliveryRelease,
        ];
        let labels: std::collections::BTreeSet<_> =
            stages.iter().map(|stage| stage.as_str()).collect();
        assert_eq!(labels.len(), stages.len());
    }
}
