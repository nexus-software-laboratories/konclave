#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Reconnecting AccountTrusted JSON operations over Konclave's authenticated local
//! service transport.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveBoundedDocuments::deserialize_strict;
use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveDomainCore::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::time::timeout;

use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceSet, AuthorizationPolicyVersion, ClientInstanceId, HarnessKind,
    IssuerHandshakeRequest, IssuerKeyId, IssuerKeyVersion, LocalServiceEndpoint,
    LocalServiceErrorCode, LocalServiceRequest, LocalServiceResponse, LocalServiceTransportError,
    MAX_RPC_PAYLOAD_BYTES, OperationName, RequestId, ServiceProfileId, SessionCapabilities,
    SessionGrant, SessionGrantClaims, SessionGrantId, SessionHandshakeRequest,
    complete_issuer_client_handshake, complete_session_client_handshake, connect_local_service,
    decode_lowercase_hex, encode_lowercase_hex, read_response, write_request,
};

const GRANT_ISSUE_OPERATION: &str = "authorization.grant.issue";
const GRANT_REQUEST_DOMAIN: &[u8] = b"konclave-local-json-client-grant-request-v1\0";
const CLIENT_INSTANCE_DOMAIN: &[u8] = b"konclave-local-json-client-instance-v1\0";
const MAX_CLIENT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_GRANT_REFRESH_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Installed issuer identity used to obtain exact-profile session grants.
///
/// This value intentionally does not implement `Clone` or `Debug` because it owns a
/// signing identity.
pub struct LocalServiceIssuerCredential {
    key_id: IssuerKeyId,
    key_version: IssuerKeyVersion,
    identity: LocalServiceIdentity,
}

impl LocalServiceIssuerCredential {
    /// Creates one installed issuer credential.
    #[must_use]
    pub const fn new(
        key_id: IssuerKeyId,
        key_version: IssuerKeyVersion,
        identity: LocalServiceIdentity,
    ) -> Self {
        Self {
            key_id,
            key_version,
            identity,
        }
    }
}

/// Validated configuration for a reconnecting authenticated JSON operation client.
///
/// This value does not implement `Clone` or `Debug` because it owns the issuer
/// signing identity.
pub struct LocalServiceJsonClientConfig {
    endpoint: LocalServiceEndpoint,
    issuer: LocalServiceIssuerCredential,
    service_public_key: Ed25519PublicKey,
    profile: ServiceProfileId,
    harness: HarnessKind,
    request_timeout: Duration,
    grant_refresh_window: Duration,
}

impl LocalServiceJsonClientConfig {
    /// Creates one exact-profile local-service client configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when a timeout is zero or exceeds its hard
    /// bound, or when the refresh window exceeds five minutes.
    pub fn new(
        endpoint: LocalServiceEndpoint,
        issuer: LocalServiceIssuerCredential,
        service_public_key: Ed25519PublicKey,
        profile: ServiceProfileId,
        harness: HarnessKind,
        request_timeout: Duration,
        grant_refresh_window: Duration,
    ) -> Result<Self, LocalServiceJsonClientError> {
        if request_timeout.is_zero()
            || request_timeout > MAX_CLIENT_TIMEOUT
            || grant_refresh_window > MAX_GRANT_REFRESH_WINDOW
        {
            return Err(LocalServiceJsonClientError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint,
            issuer,
            service_public_key,
            profile,
            harness,
            request_timeout,
            grant_refresh_window,
        })
    }
}

/// Stable high-level failures from authenticated local-service JSON operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalServiceJsonClientError {
    /// Client configuration is invalid.
    #[error("local service JSON client configuration is invalid")]
    InvalidConfiguration,
    /// The owner-restricted endpoint or framed channel is unavailable.
    #[error("local service JSON client transport is unavailable")]
    Transport,
    /// The client could not authenticate the expected service or session grant.
    #[error("local service JSON client authentication failed")]
    Authentication,
    /// The operation exceeded its finite deadline.
    #[error("local service JSON client deadline exceeded")]
    DeadlineExceeded,
    /// The authenticated service returned a stable operation failure.
    #[error("local service JSON operation failed: {0:?}")]
    Service(LocalServiceErrorCode),
    /// An authenticated response did not match its request or declared shape.
    #[error("local service JSON response is invalid")]
    InvalidResponse,
}

/// Account-issued exact-profile JSON client using one ephemeral session identity.
pub struct LocalServiceJsonClient {
    config: LocalServiceJsonClientConfig,
    session_identity: LocalServiceIdentity,
    grant: tokio::sync::Mutex<Option<SessionGrant>>,
    sequence: AtomicU64,
}

impl LocalServiceJsonClient {
    /// Generates one ephemeral session identity and obtains its first exact-profile
    /// grant.
    ///
    /// # Errors
    ///
    /// Returns a cryptographic, endpoint, authentication, service, timeout, or
    /// response-validation failure.
    pub async fn connect(
        config: LocalServiceJsonClientConfig,
    ) -> Result<Self, LocalServiceJsonClientError> {
        let session_identity = LocalServiceIdentity::generate()
            .map_err(|_| LocalServiceJsonClientError::Authentication)?;
        let provisional = Self {
            config,
            session_identity,
            grant: tokio::sync::Mutex::new(None),
            sequence: AtomicU64::new(1),
        };
        let grant = provisional.issue_grant().await?;
        *provisional.grant.lock().await = Some(grant);
        Ok(provisional)
    }

    /// Invokes one bounded operation with a caller-stable request identifier.
    ///
    /// A transport retry opens a fresh authenticated session using the same ephemeral
    /// key and request identifier, preserving the daemon request-ledger identity.
    ///
    /// # Errors
    ///
    /// Returns a typed transport, authentication, deadline, service, bound, or
    /// response-validation failure.
    pub async fn request(
        &self,
        request_id: RequestId,
        operation: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, LocalServiceJsonClientError> {
        timeout(
            self.config.request_timeout,
            self.request_with_reconciliation(request_id, operation, payload),
        )
        .await
        .map_err(|_| LocalServiceJsonClientError::DeadlineExceeded)?
    }

    async fn request_with_reconciliation(
        &self,
        request_id: RequestId,
        operation: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, LocalServiceJsonClientError> {
        let operation = OperationName::parse(operation)
            .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?;
        let request = LocalServiceRequest::new(request_id, operation, payload)
            .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?;
        let grant = self.current_grant().await?;
        match self.invoke_once(&grant, &request).await {
            Ok(payload) => Ok(payload),
            Err(LocalServiceJsonClientError::Transport) => self.invoke_once(&grant, &request).await,
            Err(LocalServiceJsonClientError::Authentication) => {
                let grant = self.refresh_grant().await?;
                self.invoke_once(&grant, &request).await
            }
            Err(error) => Err(error),
        }
    }

    async fn current_grant(&self) -> Result<SessionGrant, LocalServiceJsonClientError> {
        let now = current_unix_milliseconds()?;
        let mut grant = self.grant.lock().await;
        let refresh_at = now
            .checked_add(
                u64::try_from(self.config.grant_refresh_window.as_millis())
                    .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?,
            )
            .ok_or(LocalServiceJsonClientError::InvalidConfiguration)?;
        if grant
            .as_ref()
            .is_none_or(|grant| grant.expires_at_unix_milliseconds() <= refresh_at)
        {
            *grant = Some(self.issue_grant().await?);
        }
        grant
            .clone()
            .ok_or(LocalServiceJsonClientError::InvalidResponse)
    }

    async fn refresh_grant(&self) -> Result<SessionGrant, LocalServiceJsonClientError> {
        let mut grant = self.grant.lock().await;
        *grant = Some(self.issue_grant().await?);
        grant
            .clone()
            .ok_or(LocalServiceJsonClientError::InvalidResponse)
    }

    async fn issue_grant(&self) -> Result<SessionGrant, LocalServiceJsonClientError> {
        let request_id = RequestId::from_bytes(self.derived_id(GRANT_REQUEST_DOMAIN)?);
        let request = LocalServiceRequest::new(
            request_id,
            OperationName::parse(GRANT_ISSUE_OPERATION)
                .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?,
            serde_json::to_vec(&GrantIssueRequest {
                profile: self.config.profile.as_str(),
                session_public_key: encode_lowercase_hex(
                    self.session_identity.public_key().as_bytes(),
                ),
                harness: self.config.harness.as_str(),
            })
            .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?,
        )
        .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?;
        let payload = match self.invoke_issuer_once(&request).await {
            Ok(payload) => payload,
            Err(LocalServiceJsonClientError::Transport) => {
                self.invoke_issuer_once(&request).await?
            }
            Err(error) => return Err(error),
        };
        self.parse_grant(&payload)
    }

    async fn invoke_issuer_once(
        &self,
        request: &LocalServiceRequest,
    ) -> Result<Vec<u8>, LocalServiceJsonClientError> {
        let client_instance =
            ClientInstanceId::from_bytes(self.derived_id(CLIENT_INSTANCE_DOMAIN)?);
        timeout(self.config.request_timeout, async {
            let mut stream = connect_local_service(self.config.endpoint())
                .await
                .map_err(map_transport_error)?;
            complete_issuer_client_handshake(
                &mut stream,
                &IssuerHandshakeRequest {
                    issuer_key_id: self.config.issuer.key_id,
                    issuer_key_version: self.config.issuer.key_version,
                    client_instance,
                    harness: self.config.harness,
                },
                &self.config.issuer.identity,
                self.config.service_public_key,
            )
            .await
            .map_err(map_transport_error)?;
            write_request(&mut stream, request)
                .await
                .map_err(map_transport_error)?;
            read_response(&mut stream)
                .await
                .map_err(map_transport_error)
        })
        .await
        .map_err(|_| LocalServiceJsonClientError::DeadlineExceeded)?
        .and_then(|response| response_payload(response, request.request_id()))
    }

    async fn invoke_once(
        &self,
        grant: &SessionGrant,
        request: &LocalServiceRequest,
    ) -> Result<Vec<u8>, LocalServiceJsonClientError> {
        let client_instance =
            ClientInstanceId::from_bytes(self.derived_id(CLIENT_INSTANCE_DOMAIN)?);
        timeout(self.config.request_timeout, async {
            let mut stream = connect_local_service(self.config.endpoint())
                .await
                .map_err(map_transport_error)?;
            complete_session_client_handshake(
                &mut stream,
                &SessionHandshakeRequest {
                    grant: grant.clone(),
                    client_instance,
                },
                &self.session_identity,
                self.config.service_public_key,
            )
            .await
            .map_err(map_transport_error)?;
            write_request(&mut stream, request)
                .await
                .map_err(map_transport_error)?;
            read_response(&mut stream)
                .await
                .map_err(map_transport_error)
        })
        .await
        .map_err(|_| LocalServiceJsonClientError::DeadlineExceeded)?
        .and_then(|response| response_payload(response, request.request_id()))
    }

    fn parse_grant(&self, payload: &[u8]) -> Result<SessionGrant, LocalServiceJsonClientError> {
        let result: GrantIssueResult = deserialize_strict(payload, MAX_RPC_PAYLOAD_BYTES)
            .map_err(|_| LocalServiceJsonClientError::InvalidResponse)?;
        if result.issuer_key_id != encode_lowercase_hex(self.config.issuer.key_id.as_bytes())
            || result.issuer_key_version != self.config.issuer.key_version.get()
            || result.profile != self.config.profile.as_str()
            || result.session_public_key
                != encode_lowercase_hex(self.session_identity.public_key().as_bytes())
            || result.harness != self.config.harness.as_str()
        {
            return Err(LocalServiceJsonClientError::InvalidResponse);
        }
        SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes(
                decode_lowercase_hex::<16>(&result.grant_id)
                    .ok_or(LocalServiceJsonClientError::InvalidResponse)?,
            ),
            issuer_key_id: self.config.issuer.key_id,
            issuer_key_version: self.config.issuer.key_version,
            profile: self.config.profile.clone(),
            session_public_key: self.session_identity.public_key(),
            harness: self.config.harness,
            evidence: AuthorizationEvidenceSet::from_bits(result.evidence)
                .map_err(|_| LocalServiceJsonClientError::InvalidResponse)?,
            policy_version: AuthorizationPolicyVersion::new(result.policy_version)
                .map_err(|_| LocalServiceJsonClientError::InvalidResponse)?,
            issued_at_unix_milliseconds: result.issued_at_unix_milliseconds,
            expires_at_unix_milliseconds: result.expires_at_unix_milliseconds,
            capabilities: SessionCapabilities::from_bits(result.capabilities)
                .map_err(|_| LocalServiceJsonClientError::InvalidResponse)?,
        })
        .map_err(|_| LocalServiceJsonClientError::InvalidResponse)
    }

    fn derived_id(&self, domain: &[u8]) -> Result<[u8; 16], LocalServiceJsonClientError> {
        let sequence = self
            .sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?;
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(self.session_identity.public_key().as_bytes());
        digest.update(sequence.to_be_bytes());
        digest.finalize()[..16]
            .try_into()
            .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)
    }
}

impl LocalServiceJsonClientConfig {
    fn endpoint(&self) -> &LocalServiceEndpoint {
        &self.endpoint
    }
}

fn response_payload(
    response: LocalServiceResponse,
    request_id: RequestId,
) -> Result<Vec<u8>, LocalServiceJsonClientError> {
    if response.request_id() != request_id {
        return Err(LocalServiceJsonClientError::InvalidResponse);
    }
    match response {
        LocalServiceResponse::Success { payload, .. } => Ok(payload),
        LocalServiceResponse::Failure { code, .. } => {
            Err(LocalServiceJsonClientError::Service(code))
        }
    }
}

fn map_transport_error(error: LocalServiceTransportError) -> LocalServiceJsonClientError {
    match error {
        LocalServiceTransportError::UnauthenticClient
        | LocalServiceTransportError::UnauthenticService
        | LocalServiceTransportError::ServiceKeyMismatch => {
            LocalServiceJsonClientError::Authentication
        }
        _ => LocalServiceJsonClientError::Transport,
    }
}

fn current_unix_milliseconds() -> Result<u64, LocalServiceJsonClientError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)?
            .as_millis(),
    )
    .map_err(|_| LocalServiceJsonClientError::InvalidConfiguration)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantIssueRequest<'a> {
    profile: &'a str,
    session_public_key: String,
    harness: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantIssueResult {
    grant_id: String,
    issuer_key_id: String,
    issuer_key_version: u32,
    profile: String,
    session_public_key: String,
    harness: String,
    evidence: u8,
    policy_version: u64,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    capabilities: u64,
}
