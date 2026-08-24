use std::sync::Arc;

use KonclaveDomainCore::MAX_RELAY_CONTROL_MESSAGE_BYTES;
use KonclaveProtocolContracts::v1::{
    decode_relay_enrollment_response, encode_relay_enrollment_request,
};
use KonclaveRelayAuthentication::{RelayEnrollmentRequest, RelayEnrollmentResponse};
use async_trait::async_trait;

use crate::protected_http::ProtectedHttpClient;
use crate::{KonclaveClientError, RelayEndpoint, RelayEnrollmentCredential};

/// Deployment-specific transport for authenticated relay principal registration.
#[async_trait]
pub trait RelayEnrollmentTransport: Send + Sync {
    /// Registers one client-generated principal digest.
    ///
    /// # Errors
    ///
    /// Returns a typed transport, authentication, policy, protocol, or bounds error.
    async fn register(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentResponse, KonclaveClientError>;
}

/// Authenticated self-hosted relay enrollment over bounded HTTP.
#[derive(Clone)]
pub struct HttpRelayEnrollmentTransport {
    http: ProtectedHttpClient,
    credential: Arc<RelayEnrollmentCredential>,
}

impl HttpRelayEnrollmentTransport {
    /// Creates a transport with redirects and automatic proxy discovery disabled.
    ///
    /// The endpoint must already satisfy the shared TLS-or-loopback policy.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the underlying HTTP client cannot initialize.
    pub fn new(
        endpoint: RelayEndpoint,
        credential: RelayEnrollmentCredential,
    ) -> Result<Self, KonclaveClientError> {
        Ok(Self {
            http: ProtectedHttpClient::new(endpoint)?,
            credential: Arc::new(credential),
        })
    }
}

#[async_trait]
impl RelayEnrollmentTransport for HttpRelayEnrollmentTransport {
    async fn register(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentResponse, KonclaveClientError> {
        let body = encode_relay_enrollment_request(&request)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post(
                "v1/enrollment/principals",
                authorization,
                body,
                MAX_RELAY_CONTROL_MESSAGE_BYTES,
            )
            .await?;
        let enrollment = decode_relay_enrollment_response(&response.body)?;
        let expected_status = match enrollment.outcome() {
            KonclaveRelayAuthentication::RelayEnrollmentOutcome::Registered => 201,
            KonclaveRelayAuthentication::RelayEnrollmentOutcome::AlreadyRegistered => 200,
            _ => return Err(KonclaveClientError::InvalidEnrollmentResponse),
        };
        if response.status != expected_status {
            return Err(KonclaveClientError::InvalidEnrollmentResponse);
        }
        Ok(enrollment)
    }
}

/// Validates deployment enrollment responses against their exact request identity.
pub struct RelayEnrollmentClient<T> {
    transport: Arc<T>,
}

impl<T> Clone for RelayEnrollmentClient<T> {
    fn clone(&self) -> Self {
        Self {
            transport: Arc::clone(&self.transport),
        }
    }
}

impl<T> RelayEnrollmentClient<T>
where
    T: RelayEnrollmentTransport,
{
    /// Creates a validating enrollment client over one deployment adapter.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport: Arc::new(transport),
        }
    }

    /// Registers one principal and rejects a response for any other logical request.
    ///
    /// # Errors
    ///
    /// Returns the transport error or
    /// [`KonclaveClientError::InvalidEnrollmentResponse`] when the authenticated
    /// response does not echo the exact version, request, and principal.
    pub async fn register(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentResponse, KonclaveClientError> {
        let response = self.transport.register(request).await?;
        if response.version() != request.version()
            || response.request_id() != request.request_id()
            || response.principal_id() != request.principal_id()
        {
            return Err(KonclaveClientError::InvalidEnrollmentResponse);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::ProtocolVersion;
    use KonclaveRelayAuthentication::{
        EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest,
        RelayEnrollmentResponse, RelayPrincipalId,
    };

    use super::*;

    struct EchoTransport {
        rewrite_principal: bool,
    }

    #[async_trait]
    impl RelayEnrollmentTransport for EchoTransport {
        async fn register(
            &self,
            request: RelayEnrollmentRequest,
        ) -> Result<RelayEnrollmentResponse, KonclaveClientError> {
            Ok(RelayEnrollmentResponse::new(
                request.version(),
                request.request_id(),
                if self.rewrite_principal {
                    RelayPrincipalId::from_bytes([9; RelayPrincipalId::LENGTH])
                } else {
                    request.principal_id()
                },
                RelayEnrollmentOutcome::Registered,
            ))
        }
    }

    fn request() -> RelayEnrollmentRequest {
        RelayEnrollmentRequest::new(
            ProtocolVersion::application_v1(),
            EnrollmentRequestId::from_bytes([1; EnrollmentRequestId::LENGTH]),
            RelayPrincipalId::from_bytes([2; RelayPrincipalId::LENGTH]),
        )
    }

    #[tokio::test]
    async fn exact_response_is_accepted() {
        let response = RelayEnrollmentClient::new(EchoTransport {
            rewrite_principal: false,
        })
        .register(request())
        .await
        .unwrap();
        assert_eq!(response.outcome(), RelayEnrollmentOutcome::Registered);
    }

    #[tokio::test]
    async fn rewritten_response_identity_is_rejected() {
        let error = RelayEnrollmentClient::new(EchoTransport {
            rewrite_principal: true,
        })
        .register(request())
        .await
        .unwrap_err();
        assert_eq!(error.code(), "client_invalid_enrollment_response");
    }
}
