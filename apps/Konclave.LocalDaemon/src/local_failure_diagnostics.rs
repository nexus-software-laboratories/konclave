use std::fmt;

use KonclaveLocalServiceTransport::LocalServiceTransportError;
use sha2::{Digest as _, Sha256};

use crate::authorization_runtime::AuthorizationRuntimeError;
use crate::persistence::ProfileStoreError;
use crate::profile_supervisor::ProfileSupervisorError;

const CONNECTION_REFERENCE_DOMAIN: &[u8] = b"konclave:local-connection\0";

/// Ephemeral correlation derived only from the connection's random client nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionReference(String);

impl ConnectionReference {
    pub(crate) fn new(client_instance: &[u8; 16]) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONNECTION_REFERENCE_DOMAIN);
        digest.update(client_instance);
        let mut reference = format!("{:x}", digest.finalize());
        reference.truncate(16);
        Self(reference)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Context labels carry no paths, credentials, operation names, or argument values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureStage {
    Handshake,
    ProfileAttach,
    ProfileServices,
    RequestRead,
    RequestExecution,
    ResponseWrite,
    DeliveryRelease,
}

impl FailureStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::ProfileAttach => "profile_attach",
            Self::ProfileServices => "profile_services",
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
    if let Some(error) = error.downcast_ref::<LocalServiceTransportError>() {
        return error.code();
    }
    if let Some(error) = error.downcast_ref::<ProfileSupervisorError>() {
        if let Some(source) = error.open_source() {
            let code = failure_code(source);
            if code != "unclassified_failure" {
                return code;
            }
        }
        return error.code();
    }
    if let Some(error) = error.downcast_ref::<AuthorizationRuntimeError>() {
        return match error {
            AuthorizationRuntimeError::Store(_) => "authorization_store_failure",
            AuthorizationRuntimeError::InvalidProjection => "authorization_invalid_projection",
            AuthorizationRuntimeError::ObservationDeadlineExceeded => {
                "authorization_observation_deadline"
            }
            AuthorizationRuntimeError::BlockingOperationFailed => "authorization_worker_failure",
            AuthorizationRuntimeError::UnexpectedStop => "authorization_stopped",
        };
    }
    if let Some(error) = error.downcast_ref::<ProfileStoreError>() {
        return match error {
            ProfileStoreError::ProfileLocked => "profile_locked",
            ProfileStoreError::Io => "profile_io_failure",
            ProfileStoreError::Storage => "profile_storage_failure",
            ProfileStoreError::UnsupportedSchema => "profile_schema_unsupported",
            ProfileStoreError::ProfileMismatch => "profile_mismatch",
            ProfileStoreError::CorruptData => "profile_integrity_failure",
            ProfileStoreError::Credential => "profile_credential_unavailable",
            _ => "profile_store_failure",
        };
    }
    if let Some(error) = error.downcast_ref::<KonclaveSecretStorage::SecretStorageError>() {
        return error.code();
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return match error.kind() {
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::TimedOut => "io_timed_out",
            std::io::ErrorKind::WouldBlock => "io_would_block",
            std::io::ErrorKind::NotFound => "io_not_found",
            _ => "io_failure",
        };
    }
    if let Some(error) = error.downcast_ref::<tokio::task::JoinError>() {
        return if error.is_panic() {
            "worker_panicked"
        } else {
            "worker_cancelled"
        };
    }
    "unclassified_failure"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_bounded_ephemeral_and_domain_separated() {
        let first = ConnectionReference::new(&[0x42; 16]);
        assert_eq!(first.as_str(), "5deed3fe8eee37ab");
        assert_eq!(first.as_str().len(), 16);
        assert!(first.as_str().bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, ConnectionReference::new(&[0x43; 16]));
        assert_eq!(first, ConnectionReference::new(&[0x42; 16]));
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
                connection: Some(ConnectionReference::new(&[0x42; 16])),
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
            FailureStage::Handshake,
            FailureStage::ProfileAttach,
            FailureStage::ProfileServices,
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
