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
use futures_util::StreamExt;
use reqwest::Response;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

use crate::error::stable_relay_code;
use crate::websocket::connect_watch;
use crate::{KonclaveClientError, RelayAccessCredential, RelayEndpoint, RelayWatchSession};

const PROTOBUF_MEDIA_TYPE: &str = "application/protobuf";
const ERROR_CODE_HEADER: &str = "x-konclave-error-code";
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
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
    http: reqwest::Client,
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
        Self::ensure_tls_provider()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(DEFAULT_OPERATION_TIMEOUT)
            .timeout(DEFAULT_OPERATION_TIMEOUT)
            .user_agent(concat!("KonclaveClientLibrary/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| KonclaveClientError::TransportUnavailable)?;
        Ok(Self {
            http,
            endpoint,
            credential: Arc::new(credential),
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        })
    }

    fn ensure_tls_provider() -> Result<(), KonclaveClientError> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        if rustls::crypto::CryptoProvider::get_default().is_some() {
            Ok(())
        } else {
            Err(KonclaveClientError::TransportUnavailable)
        }
    }

    async fn post(
        &self,
        relative: &str,
        body: Vec<u8>,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, KonclaveClientError> {
        let url = self.endpoint.http_url(relative)?;
        let authorization = self.credential.authorization_header()?;
        let response = self
            .http
            .post(url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, PROTOBUF_MEDIA_TYPE)
            .body(body)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        if !response.status().is_success() {
            return Err(relay_rejection(&response));
        }
        if response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(PROTOBUF_MEDIA_TYPE)
        {
            return Err(KonclaveClientError::InvalidResponse);
        }
        read_bounded(response, maximum_response_bytes).await
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

async fn read_bounded(response: Response, maximum: usize) -> Result<Vec<u8>, KonclaveClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(KonclaveClientError::ResponseTooLarge { maximum });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(maximum),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| KonclaveClientError::TransportUnavailable)?;
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(KonclaveClientError::ResponseTooLarge { maximum })?;
        if next_length > maximum {
            return Err(KonclaveClientError::ResponseTooLarge { maximum });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn relay_rejection(response: &Response) -> KonclaveClientError {
    let relay_code = response
        .headers()
        .get(ERROR_CODE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(stable_relay_code)
        .unwrap_or_else(|| "relay_rejected".to_string());
    KonclaveClientError::RelayRejected {
        status: response.status().as_u16(),
        relay_code,
    }
}

fn map_reqwest_error(error: reqwest::Error) -> KonclaveClientError {
    if error.is_timeout() {
        KonclaveClientError::Timeout
    } else {
        KonclaveClientError::TransportUnavailable
    }
}
