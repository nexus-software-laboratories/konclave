use std::sync::Arc;
use std::time::Duration;

use KonclaveDomainCore::{
    AcknowledgeRequest, MAX_RELAY_CONTROL_MESSAGE_BYTES, MAX_RELAY_ENVELOPE_BYTES,
    MAX_REPLAY_PAGE_BYTES, RelayEnvelope, ReplayPage, ReplayRequest, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_replay_page, decode_stored_relay_envelope,
    encode_acknowledge_request, encode_relay_envelope, encode_replay_request,
};
use async_trait::async_trait;

use crate::protected_http::{DEFAULT_OPERATION_TIMEOUT, ProtectedHttpClient};
use crate::websocket::connect_watch;
use crate::{KonclaveClientError, RelayAccessCredential, RelayEndpoint, RelayWatchSession};

const DEFAULT_WATCH_READ_TIMEOUT: Duration = Duration::from_secs(75);
const STORED_ENVELOPE_MAX_BYTES: usize = MAX_RELAY_ENVELOPE_BYTES + 32;

/// Outbound relay operations shared by daemon and command adapters.
#[async_trait]
pub trait RelayTransport: Send + Sync {
    /// Submits one opaque envelope.
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<StoredRelayEnvelope, KonclaveClientError>;

    /// Reads one bounded replay page.
    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError>;

    /// Advances and returns one principal's effective acknowledgment.
    async fn acknowledge(
        &self,
        request: AcknowledgeRequest,
    ) -> Result<AcknowledgeRequest, KonclaveClientError>;

    /// Opens one authenticated WebSocket watch after the supplied durable cursor.
    async fn connect_watch(
        &self,
        request: ReplayRequest,
    ) -> Result<RelayWatchSession, KonclaveClientError>;
}

/// Cloneable outbound HTTP/WebSocket relay client sharing one protected credential.
#[derive(Clone)]
pub struct RelayClient {
    http: ProtectedHttpClient,
    endpoint: RelayEndpoint,
    credential: Arc<RelayAccessCredential>,
    operation_timeout: Duration,
}

impl RelayClient {
    /// Creates a relay client with redirects disabled and bounded request deadlines.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the underlying HTTP client cannot initialize.
    pub fn new(
        endpoint: RelayEndpoint,
        credential: RelayAccessCredential,
    ) -> Result<Self, KonclaveClientError> {
        let http = ProtectedHttpClient::new(endpoint.clone())?;
        Ok(Self {
            http,
            endpoint,
            credential: Arc::new(credential),
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        })
    }

    async fn post(
        &self,
        relative: &str,
        body: Vec<u8>,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, KonclaveClientError> {
        let authorization = self.credential.authorization_header()?;
        Ok(self
            .http
            .post(relative, authorization, body, maximum_response_bytes)
            .await?
            .body)
    }
}

#[async_trait]
impl RelayTransport for RelayClient {
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
        let request = encode_relay_envelope(envelope)?;
        let response = self
            .post("v1/envelopes", request, STORED_ENVELOPE_MAX_BYTES)
            .await?;
        decode_stored_relay_envelope(&response).map_err(Into::into)
    }

    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
        let request = encode_replay_request(request)?;
        let response = self
            .post("v1/replay", request, MAX_REPLAY_PAGE_BYTES)
            .await?;
        decode_replay_page(&response).map_err(Into::into)
    }

    async fn acknowledge(
        &self,
        request: AcknowledgeRequest,
    ) -> Result<AcknowledgeRequest, KonclaveClientError> {
        let request = encode_acknowledge_request(request)?;
        let response = self
            .post(
                "v1/acknowledgments",
                request,
                MAX_RELAY_CONTROL_MESSAGE_BYTES,
            )
            .await?;
        decode_acknowledge_request(&response).map_err(Into::into)
    }

    async fn connect_watch(
        &self,
        request: ReplayRequest,
    ) -> Result<RelayWatchSession, KonclaveClientError> {
        connect_watch(
            &self.endpoint,
            Arc::clone(&self.credential),
            request,
            self.operation_timeout,
            DEFAULT_WATCH_READ_TIMEOUT,
        )
        .await
    }
}
