use std::time::Duration;

use KonclaveA2AContracts::wire::AgentInterface;
use KonclaveA2AContracts::{
    A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_WELL_KNOWN_AGENT_CARD_PATH,
    InitialA2AAgentCard, InitialA2AAgentSecurityKind, InitialA2AInterfaceEnvironment,
    InitialA2ATaskResponse, InitialSendMessageRequest, MAX_A2A_ENCODED_AGENT_CARD_BYTES,
    MAX_A2A_ENCODED_RESPONSE_BYTES, decode_initial_agent_card_json,
    decode_initial_send_message_response_json, decode_initial_task_json,
    validate_initial_agent_interface,
};
use KonclaveA2ADomain::A2ATaskId;
use KonclaveBoundedDocuments::deserialize_strict;
use KonclaveProtectedHttp::protected_http_client_builder;
use futures_util::StreamExt as _;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderMap,
    HeaderValue, IF_NONE_MATCH,
};
use reqwest::{Response, StatusCode};
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::{A2A_JSON_MEDIA_TYPE, A2A_VERSION_HEADER, A2ABearerCredential, A2AGatewayError};

const MAX_REMOTE_ERROR_BYTES: usize = 64 * 1024;
const MAX_ETAG_BYTES: usize = 256;
const MAX_CACHE_CONTROL_BYTES: usize = 256;

/// Bounded outbound HTTP behavior for the initial A2A client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2AHttpClientConfig {
    timeout: Duration,
    maximum_response_bytes: usize,
}

impl A2AHttpClientConfig {
    /// Creates finite outbound request and response bounds.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for zero or oversized values.
    pub fn new(timeout: Duration, maximum_response_bytes: usize) -> Result<Self, A2AGatewayError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(60)
            || maximum_response_bytes == 0
            || maximum_response_bytes > MAX_A2A_ENCODED_RESPONSE_BYTES
        {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        Ok(Self {
            timeout,
            maximum_response_bytes,
        })
    }
}

impl Default for A2AHttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            maximum_response_bytes: MAX_A2A_ENCODED_RESPONSE_BYTES,
        }
    }
}

/// Result of one conditional public Agent Card fetch.
pub enum A2AAgentCardFetchOutcome {
    /// The remote card changed or no validator was supplied.
    Modified {
        /// Validated public Agent Card.
        card: Box<InitialA2AAgentCard>,
        /// Bounded response entity tag, when supplied.
        etag: Option<String>,
        /// Bounded cache policy supplied by the server, when present.
        cache_control: Option<String>,
    },
    /// The supplied entity tag still identifies the current remote card.
    NotModified,
}

/// Outbound-only client for the strict A2A HTTP+JSON profile.
pub struct A2AHttpJsonClient {
    client: reqwest::Client,
    base_url: Url,
    tenant: Option<String>,
    bearer_token: Option<Zeroizing<String>>,
    maximum_response_bytes: usize,
    agent_name: String,
    agent_version: String,
    extended_agent_card: bool,
    interface_identity: Vec<(String, Option<String>)>,
    security_identity: Option<(InitialA2AAgentSecurityKind, String)>,
}

impl A2AHttpJsonClient {
    /// Creates a client from one validated Agent Card and optional Bearer credential.
    ///
    /// Redirects and automatic proxy discovery are disabled. The built-in client
    /// supports unauthenticated loopback cards and Bearer cards; mutual TLS requires a
    /// deployment-specific client implementation.
    ///
    /// # Errors
    ///
    /// Returns a configuration, authentication-profile, URL, or HTTP client error.
    pub fn new(
        card: &InitialA2AAgentCard,
        credential: Option<A2ABearerCredential>,
        config: A2AHttpClientConfig,
    ) -> Result<Self, A2AGatewayError> {
        let interface = card
            .interfaces()
            .first()
            .ok_or(A2AGatewayError::InvalidConfiguration)?;
        let bearer_token = match (card.security().map(|security| security.kind()), credential) {
            (None, None) => None,
            (Some(InitialA2AAgentSecurityKind::Bearer), Some(credential)) => {
                Some(credential.into_secret())
            }
            (Some(InitialA2AAgentSecurityKind::MutualTls), _) => {
                return Err(A2AGatewayError::UnsupportedAuthentication);
            }
            _ => return Err(A2AGatewayError::InvalidConfiguration),
        };
        let client = protected_http_client_builder()
            .map_err(|_| A2AGatewayError::InvalidConfiguration)?
            .timeout(config.timeout)
            .build()
            .map_err(|_| A2AGatewayError::InvalidConfiguration)?;
        Ok(Self {
            client,
            base_url: Url::parse(interface.url())
                .map_err(|_| A2AGatewayError::InvalidConfiguration)?,
            tenant: interface.tenant().map(str::to_owned),
            bearer_token,
            maximum_response_bytes: config.maximum_response_bytes,
            agent_name: card.name().to_owned(),
            agent_version: card.version().to_owned(),
            extended_agent_card: card.extended_agent_card(),
            interface_identity: card
                .interfaces()
                .iter()
                .map(|interface| {
                    (
                        interface.url().to_owned(),
                        interface.tenant().map(str::to_owned),
                    )
                })
                .collect(),
            security_identity: card
                .security()
                .map(|security| (security.kind(), security.name().to_owned())),
        })
    }

    /// Sends one validated task-creating request.
    ///
    /// # Errors
    ///
    /// Returns transport, remote, response-bound, or response-contract failures.
    pub async fn send_message(
        &self,
        request: InitialSendMessageRequest,
    ) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
        if request.tenant() != self.tenant.as_deref() {
            return Err(A2AGatewayError::RouteMismatch);
        }
        let requested_context = request.context_id().map(str::to_owned);
        let body =
            serde_json::to_vec(&request.into_wire()).map_err(|_| A2AGatewayError::Contract)?;
        if body.len() > KonclaveA2AContracts::MAX_A2A_ENCODED_REQUEST_BYTES {
            return Err(A2AGatewayError::Contract);
        }
        let response = self
            .apply_headers(
                self.client
                    .post(self.endpoint("message:send")?)
                    .header(CONTENT_TYPE, A2A_JSON_MEDIA_TYPE)
                    .body(body),
            )?
            .send()
            .await
            .map_err(|_| A2AGatewayError::Transport)?;
        let bytes = self.success_bytes(response).await?;
        let task = decode_initial_send_message_response_json(&bytes)
            .map_err(|_| A2AGatewayError::Contract)?;
        A2ATaskId::parse(task.task_id().to_owned()).map_err(|_| A2AGatewayError::Contract)?;
        if requested_context
            .as_deref()
            .is_some_and(|context| context != task.context_id())
        {
            return Err(A2AGatewayError::Contract);
        }
        Ok(task)
    }

    /// Loads one exact task through `GET /tasks/{id}`.
    ///
    /// # Errors
    ///
    /// Returns configuration, transport, remote, response-bound, or response-contract
    /// failures.
    pub async fn get_task(
        &self,
        task_id: &A2ATaskId,
        history_length: Option<u32>,
    ) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
        if history_length.is_some_and(|value| value > 1) {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        let mut url = self.endpoint(&format!("tasks/{}", task_id.as_str()))?;
        if let Some(history_length) = history_length {
            url.query_pairs_mut()
                .append_pair("historyLength", &history_length.to_string());
        }
        let response = self
            .apply_headers(self.client.get(url))?
            .send()
            .await
            .map_err(|_| A2AGatewayError::Transport)?;
        let bytes = self.success_bytes(response).await?;
        let task = decode_initial_task_json(&bytes).map_err(|_| A2AGatewayError::Contract)?;
        if task.task_id() != task_id.as_str() {
            return Err(A2AGatewayError::Contract);
        }
        Ok(task)
    }

    /// Retrieves the authenticated extended Agent Card.
    ///
    /// # Errors
    ///
    /// Returns transport, remote, response-bound, or card-contract failures.
    pub async fn get_extended_agent_card(
        &self,
        environment: InitialA2AInterfaceEnvironment,
    ) -> Result<InitialA2AAgentCard, A2AGatewayError> {
        if !self.extended_agent_card {
            return Err(A2AGatewayError::ExtendedCardNotConfigured);
        }
        let response = self
            .apply_headers(self.client.get(self.endpoint("extendedAgentCard")?))?
            .send()
            .await
            .map_err(|_| A2AGatewayError::Transport)?;
        let bytes = self.success_bytes(response).await?;
        let card = decode_initial_agent_card_json(&bytes, environment, self.tenant.as_deref())
            .map_err(|_| A2AGatewayError::Contract)?;
        let interface_identity = card
            .interfaces()
            .iter()
            .map(|interface| {
                (
                    interface.url().to_owned(),
                    interface.tenant().map(str::to_owned),
                )
            })
            .collect::<Vec<_>>();
        let security_identity = card
            .security()
            .map(|security| (security.kind(), security.name().to_owned()));
        if card.name() != self.agent_name
            || card.version() != self.agent_version
            || interface_identity != self.interface_identity
            || security_identity != self.security_identity
        {
            return Err(A2AGatewayError::Contract);
        }
        Ok(card)
    }

    fn endpoint(&self, operation: &str) -> Result<Url, A2AGatewayError> {
        let mut url = self.base_url.clone();
        let mut path = url.path().trim_end_matches('/').to_owned();
        if let Some(tenant) = &self.tenant {
            path.push('/');
            path.push_str(tenant);
        }
        path.push('/');
        path.push_str(operation);
        url.set_path(&path);
        Ok(url)
    }

    fn apply_headers(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, A2AGatewayError> {
        let request = request
            .header(ACCEPT, A2A_JSON_MEDIA_TYPE)
            .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION);
        let Some(token) = &self.bearer_token else {
            return Ok(request);
        };
        let header = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let mut header =
            HeaderValue::from_str(&header).map_err(|_| A2AGatewayError::InvalidConfiguration)?;
        header.set_sensitive(true);
        Ok(request.header(AUTHORIZATION, header))
    }

    async fn success_bytes(&self, response: Response) -> Result<Vec<u8>, A2AGatewayError> {
        let status = response.status();
        if !status.is_success() {
            return Err(remote_error(response).await);
        }
        require_json_content_type(response.headers())?;
        read_response_bytes(response, self.maximum_response_bytes).await
    }
}

/// Fetches the standard public well-known Agent Card without redirects or ambient
/// proxy discovery.
///
/// # Errors
///
/// Returns URL, transport, remote, response-bound, or Agent Card contract failures.
pub async fn fetch_public_agent_card(
    discovery_url: &str,
    environment: InitialA2AInterfaceEnvironment,
    expected_tenant: Option<&str>,
    etag: Option<&str>,
    config: A2AHttpClientConfig,
) -> Result<A2AAgentCardFetchOutcome, A2AGatewayError> {
    let interface = validate_initial_agent_interface(
        AgentInterface {
            url: discovery_url.to_owned(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_owned(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_owned(),
        },
        environment,
    )
    .map_err(|_| A2AGatewayError::InvalidConfiguration)?;
    let url = Url::parse(interface.url()).map_err(|_| A2AGatewayError::InvalidConfiguration)?;
    if url.path() != A2A_WELL_KNOWN_AGENT_CARD_PATH {
        return Err(A2AGatewayError::InvalidConfiguration);
    }
    let client = protected_http_client_builder()
        .map_err(|_| A2AGatewayError::InvalidConfiguration)?
        .timeout(config.timeout)
        .build()
        .map_err(|_| A2AGatewayError::InvalidConfiguration)?;
    let mut request = client
        .get(url.clone())
        .header(ACCEPT, A2A_JSON_MEDIA_TYPE)
        .header(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION);
    if let Some(etag) = etag {
        if etag.is_empty() || etag.len() > MAX_ETAG_BYTES || !etag.is_ascii() {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        request = request.header(IF_NONE_MATCH, etag);
    }
    let response = request
        .send()
        .await
        .map_err(|_| A2AGatewayError::Transport)?;
    if response.status() == StatusCode::NOT_MODIFIED && etag.is_some() {
        return Ok(A2AAgentCardFetchOutcome::NotModified);
    }
    if response.status() == StatusCode::NOT_MODIFIED {
        return Err(A2AGatewayError::Contract);
    }
    if !response.status().is_success() {
        return Err(remote_error(response).await);
    }
    require_json_content_type(response.headers())?;
    let response_etag = response
        .headers()
        .get(ETAG)
        .map(|value| {
            let value = value.to_str().map_err(|_| A2AGatewayError::Contract)?;
            if value.is_empty() || value.len() > MAX_ETAG_BYTES {
                return Err(A2AGatewayError::Contract);
            }
            Ok(value.to_owned())
        })
        .transpose()?;
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .map(|value| {
            let value = value.to_str().map_err(|_| A2AGatewayError::Contract)?;
            if value.is_empty() || value.len() > MAX_CACHE_CONTROL_BYTES {
                return Err(A2AGatewayError::Contract);
            }
            Ok(value.to_owned())
        })
        .transpose()?;
    let bytes = read_response_bytes(response, MAX_A2A_ENCODED_AGENT_CARD_BYTES).await?;
    let card = decode_initial_agent_card_json(&bytes, environment, expected_tenant)
        .map_err(|_| A2AGatewayError::Contract)?;
    let preferred_url = Url::parse(
        card.interfaces()
            .first()
            .ok_or(A2AGatewayError::Contract)?
            .url(),
    )
    .map_err(|_| A2AGatewayError::Contract)?;
    if !same_origin(&url, &preferred_url) {
        return Err(A2AGatewayError::Contract);
    }
    Ok(A2AAgentCardFetchOutcome::Modified {
        card: Box::new(card),
        etag: response_etag,
        cache_control,
    })
}

async fn read_response_bytes(
    response: Response,
    maximum: usize,
) -> Result<Vec<u8>, A2AGatewayError> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > maximum)
    {
        return Err(A2AGatewayError::Contract);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| A2AGatewayError::Transport)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(A2AGatewayError::Contract);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn remote_error(response: Response) -> A2AGatewayError {
    let status = response.status().as_u16();
    let reason = read_response_bytes(response, MAX_REMOTE_ERROR_BYTES)
        .await
        .ok()
        .and_then(|bytes| deserialize_strict::<Value>(&bytes, MAX_REMOTE_ERROR_BYTES).ok())
        .and_then(|value| {
            value["error"]["details"]
                .as_array()
                .and_then(|details| details.iter().find_map(|detail| detail["reason"].as_str()))
                .filter(|reason| {
                    !reason.is_empty()
                        && reason.len() <= 128
                        && reason.bytes().all(|byte| {
                            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
                .map(str::to_owned)
        });
    A2AGatewayError::Remote { status, reason }
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), A2AGatewayError> {
    let value = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(A2AGatewayError::Contract)?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case(A2A_JSON_MEDIA_TYPE)
        || media_type.eq_ignore_ascii_case("application/json")
    {
        Ok(())
    } else {
        Err(A2AGatewayError::Contract)
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left
            .host_str()
            .zip(right.host_str())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && left.port_or_known_default() == right.port_or_known_default()
}
