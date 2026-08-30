use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use KonclaveA2AContracts::wire::{GetExtendedAgentCardRequest, GetTaskRequest};
use KonclaveA2AContracts::{
    A2A_PROTOCOL_VERSION, A2A_WELL_KNOWN_AGENT_CARD_PATH, A2AContractError,
    InitialA2AAgentSecurityKind, MAX_A2A_ENCODED_REQUEST_BYTES, decode_initial_send_message_json,
    validate_initial_get_extended_agent_card_request, validate_initial_get_task_request,
};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::time::timeout;
use tower::limit::ConcurrencyLimitLayer;

use crate::projection::send_message_response;
use crate::{
    A2AGatewayApplication, A2AGatewayError, A2AHttpAccess, A2AHttpAction,
    A2AHttpAuthorizationDecision,
};

/// Preferred A2A v1.0.1 HTTP+JSON media type.
pub const A2A_JSON_MEDIA_TYPE: &str = "application/a2a+json";
/// Optional protocol-version request header.
pub const A2A_VERSION_HEADER: &str = "a2a-version";
const MAX_HTTP_CONCURRENT_REQUESTS: usize = 256;
const MAX_AGENT_CARD_CACHE_SECONDS: u64 = 86_400;
const MAX_QUERY_BYTES: usize = 256;

/// Bounded HTTP behavior for the reference gateway router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2AHttpConfig {
    request_body_timeout: Duration,
    agent_card_cache_seconds: u64,
    max_concurrent_requests: usize,
}

impl A2AHttpConfig {
    /// Creates one finite HTTP configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for zero/oversized timeouts, cache lifetimes, or
    /// concurrency.
    pub fn new(
        request_body_timeout: Duration,
        agent_card_cache_seconds: u64,
        max_concurrent_requests: usize,
    ) -> Result<Self, A2AGatewayError> {
        if request_body_timeout.is_zero()
            || request_body_timeout > Duration::from_secs(60)
            || agent_card_cache_seconds > MAX_AGENT_CARD_CACHE_SECONDS
            || max_concurrent_requests == 0
            || max_concurrent_requests > MAX_HTTP_CONCURRENT_REQUESTS
        {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        Ok(Self {
            request_body_timeout,
            agent_card_cache_seconds,
            max_concurrent_requests,
        })
    }
}

impl Default for A2AHttpConfig {
    fn default() -> Self {
        Self {
            request_body_timeout: Duration::from_secs(10),
            agent_card_cache_seconds: 3_600,
            max_concurrent_requests: MAX_HTTP_CONCURRENT_REQUESTS,
        }
    }
}

/// Immutable state used by the reference HTTP+JSON router.
#[derive(Clone)]
pub struct A2AHttpState {
    application: A2AGatewayApplication,
    access: Arc<dyn A2AHttpAccess>,
    config: A2AHttpConfig,
    public_card: CachedCard,
    extended_card: Option<CachedCard>,
}

impl A2AHttpState {
    /// Creates HTTP state after verifying card and access authentication agree.
    ///
    /// # Errors
    ///
    /// Returns a configuration or Agent Card serialization error.
    pub fn new(
        application: A2AGatewayApplication,
        access: Arc<dyn A2AHttpAccess>,
        config: A2AHttpConfig,
    ) -> Result<Self, A2AGatewayError> {
        let advertised = application
            .card()
            .security()
            .map(|security| security.kind());
        if advertised != access.authentication_kind() {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        let public_card = CachedCard::new(
            application
                .card()
                .deterministic_json()
                .map_err(|_| A2AGatewayError::Contract)?,
            config.agent_card_cache_seconds,
            false,
        )?;
        let extended_card = application
            .extended_card()
            .map(|card| {
                card.deterministic_json()
                    .map_err(|_| A2AGatewayError::Contract)
                    .and_then(|bytes| CachedCard::new(bytes, config.agent_card_cache_seconds, true))
            })
            .transpose()?;
        Ok(Self {
            application,
            access,
            config,
            public_card,
            extended_card,
        })
    }
}

/// Builds the strict non-streaming A2A HTTP+JSON routes.
pub fn a2a_router(state: A2AHttpState) -> Router {
    let concurrency = state.config.max_concurrent_requests;
    Router::new()
        .route(A2A_WELL_KNOWN_AGENT_CARD_PATH, get(public_agent_card))
        .route("/message:send", post(send_message_unscoped))
        .route("/{tenant}/message:send", post(send_message_tenant))
        .route("/tasks/{id}", get(get_task_unscoped))
        .route("/{tenant}/tasks/{id}", get(get_task_tenant))
        .route("/extendedAgentCard", get(extended_agent_card_unscoped))
        .route(
            "/{tenant}/extendedAgentCard",
            get(extended_agent_card_tenant),
        )
        .route("/message:stream", post(unsupported_operation))
        .route("/{tenant}/message:stream", post(unsupported_operation))
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(concurrency))
}

/// Serves the reference router until the supplied shutdown future completes.
///
/// Non-loopback binding requires an explicit assertion that trusted TLS termination
/// protects the listener. This process is the network-edge gateway; it does not open
/// any listener in a local agent or daemon process.
///
/// # Errors
///
/// Returns a configuration or server error when the address is unsafe, cannot bind,
/// or cannot serve.
pub async fn serve_a2a_until<F>(
    address: SocketAddr,
    tls_terminated: bool,
    state: A2AHttpState,
    shutdown: F,
) -> Result<(), A2AGatewayError>
where
    F: Future<Output = ()> + Send + 'static,
{
    validate_a2a_binding(address.ip(), tls_terminated)?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|_| A2AGatewayError::ServerUnavailable)?;
    axum::serve(listener, a2a_router(state))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|_| A2AGatewayError::ServerUnavailable)
}

/// Validates that a gateway listener is loopback-only or protected by trusted TLS
/// termination.
///
/// # Errors
///
/// Returns a configuration error for a non-loopback plaintext binding.
pub fn validate_a2a_binding(address: IpAddr, tls_terminated: bool) -> Result<(), A2AGatewayError> {
    if address.is_loopback() || tls_terminated {
        Ok(())
    } else {
        Err(A2AGatewayError::InvalidConfiguration)
    }
}

async fn public_agent_card(State(state): State<A2AHttpState>, request: Request<Body>) -> Response {
    if state.application.public_card().is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    cached_card_response(&state.public_card, request.headers())
}

async fn send_message_unscoped(
    State(state): State<A2AHttpState>,
    request: Request<Body>,
) -> Response {
    send_message(state, None, request).await
}

async fn send_message_tenant(
    State(state): State<A2AHttpState>,
    Path(tenant): Path<String>,
    request: Request<Body>,
) -> Response {
    send_message(state, Some(tenant), request).await
}

async fn send_message(
    state: A2AHttpState,
    path_tenant: Option<String>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(response) = authorize(&state, &parts, A2AHttpAction::SendMessage) {
        return *response;
    }
    if let Err(response) = validate_common_headers(&parts.headers) {
        return *response;
    }
    if let Err(response) = validate_path_tenant(&state.application, path_tenant.as_deref()) {
        return *response;
    }
    if let Err(response) = validate_json_content_type(&parts.headers) {
        return *response;
    }
    let bytes = match read_body(
        body,
        &parts.headers,
        state.config.request_body_timeout,
        MAX_A2A_ENCODED_REQUEST_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let request = match decode_initial_send_message_json(&bytes, state.application.tenant()) {
        Ok(request) => request,
        Err(error) => return contract_error_response(error),
    };
    match state.application.send_message(request).await {
        Ok(task) => {
            let response = send_message_response(task);
            match serde_json::to_vec(&response) {
                Ok(bytes) => json_response(StatusCode::OK, bytes),
                Err(_) => gateway_error_response(A2AGatewayError::InvalidTaskProjection),
            }
        }
        Err(error) => gateway_error_response(error),
    }
}

async fn get_task_unscoped(
    State(state): State<A2AHttpState>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> Response {
    get_task(state, None, id, request).await
}

async fn get_task_tenant(
    State(state): State<A2AHttpState>,
    Path((tenant, id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    get_task(state, Some(tenant), id, request).await
}

async fn get_task(
    state: A2AHttpState,
    path_tenant: Option<String>,
    id: String,
    request: Request<Body>,
) -> Response {
    let (parts, _) = request.into_parts();
    if let Err(response) = authorize(&state, &parts, A2AHttpAction::GetTask) {
        return *response;
    }
    if let Err(response) = validate_common_headers(&parts.headers) {
        return *response;
    }
    if let Err(response) = validate_path_tenant(&state.application, path_tenant.as_deref()) {
        return *response;
    }
    if id.ends_with(":subscribe") {
        return unsupported_operation_response();
    }
    let history_length = match parse_history_length(parts.uri.query()) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let request = match validate_initial_get_task_request(
        GetTaskRequest {
            tenant: state.application.tenant().unwrap_or_default().to_owned(),
            id,
            history_length,
        },
        state.application.tenant(),
    ) {
        Ok(request) => request,
        Err(error) => return contract_error_response(error),
    };
    match state.application.get_task(request).await {
        Ok(task) => match task.deterministic_json() {
            Ok(bytes) => json_response(StatusCode::OK, bytes),
            Err(_) => gateway_error_response(A2AGatewayError::InvalidTaskProjection),
        },
        Err(error) => gateway_error_response(error),
    }
}

async fn extended_agent_card_unscoped(
    State(state): State<A2AHttpState>,
    request: Request<Body>,
) -> Response {
    extended_agent_card(state, None, request).await
}

async fn extended_agent_card_tenant(
    State(state): State<A2AHttpState>,
    Path(tenant): Path<String>,
    request: Request<Body>,
) -> Response {
    extended_agent_card(state, Some(tenant), request).await
}

async fn extended_agent_card(
    state: A2AHttpState,
    path_tenant: Option<String>,
    request: Request<Body>,
) -> Response {
    let (parts, _) = request.into_parts();
    if let Err(response) = authorize(&state, &parts, A2AHttpAction::GetExtendedAgentCard) {
        return *response;
    }
    if let Err(response) = validate_common_headers(&parts.headers) {
        return *response;
    }
    if let Err(response) = validate_path_tenant(&state.application, path_tenant.as_deref()) {
        return *response;
    }
    if parts.uri.query().is_some() {
        return contract_error_response(A2AContractError::UnsupportedField {
            field: "get_extended_agent_card.query",
        });
    }
    if let Err(error) = validate_initial_get_extended_agent_card_request(
        GetExtendedAgentCardRequest {
            tenant: state.application.tenant().unwrap_or_default().to_owned(),
        },
        state.application.tenant(),
    ) {
        return contract_error_response(error);
    }
    match &state.extended_card {
        Some(card) => cached_card_response(card, &parts.headers),
        None => gateway_error_response(A2AGatewayError::ExtendedCardNotConfigured),
    }
}

async fn unsupported_operation(
    State(state): State<A2AHttpState>,
    request: Request<Body>,
) -> Response {
    let (parts, _) = request.into_parts();
    if let Err(response) = authorize(&state, &parts, A2AHttpAction::UnsupportedOperation) {
        return *response;
    }
    if let Err(response) = validate_common_headers(&parts.headers) {
        return *response;
    }
    unsupported_operation_response()
}

fn unsupported_operation_response() -> Response {
    a2a_error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_ARGUMENT",
        "A2A operation is not supported",
        "UNSUPPORTED_OPERATION",
        None,
    )
}

fn authorize(
    state: &A2AHttpState,
    parts: &Parts,
    action: A2AHttpAction,
) -> Result<(), Box<Response>> {
    let principal = match state.access.authenticate(parts) {
        Ok(principal) => principal,
        Err(A2AGatewayError::Unauthenticated) => {
            return Err(Box::new(authentication_error_response(
                state.access.authentication_kind(),
            )));
        }
        Err(error) => return Err(Box::new(gateway_error_response(error))),
    };
    match state.access.authorize(principal, action) {
        A2AHttpAuthorizationDecision::Allow => Ok(()),
        A2AHttpAuthorizationDecision::Deny => {
            Err(Box::new(gateway_error_response(A2AGatewayError::Forbidden)))
        }
        A2AHttpAuthorizationDecision::Unavailable => Err(Box::new(gateway_error_response(
            A2AGatewayError::AuthorizationUnavailable,
        ))),
    }
}

fn validate_common_headers(headers: &HeaderMap) -> Result<(), Box<Response>> {
    let mut versions = headers.get_all(A2A_VERSION_HEADER).iter();
    if let Some(version) = versions.next() {
        if versions.next().is_some()
            || version
                .to_str()
                .ok()
                .is_none_or(|version| version != A2A_PROTOCOL_VERSION)
        {
            return Err(Box::new(a2a_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "A2A protocol version is not supported",
                "VERSION_NOT_SUPPORTED",
                None,
            )));
        }
    }
    Ok(())
}

fn validate_path_tenant(
    application: &A2AGatewayApplication,
    path_tenant: Option<&str>,
) -> Result<(), Box<Response>> {
    if application.tenant() == path_tenant {
        Ok(())
    } else {
        Err(Box::new(a2a_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "A2A task or route was not found",
            "TASK_NOT_FOUND",
            None,
        )))
    }
}

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), Box<Response>> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(Box::new(content_type_error()));
    };
    if values.next().is_some() {
        return Err(Box::new(content_type_error()));
    }
    let Ok(value) = value.to_str() else {
        return Err(Box::new(content_type_error()));
    };
    let mut segments = value.split(';');
    let media_type = segments.next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case(A2A_JSON_MEDIA_TYPE)
        && !media_type.eq_ignore_ascii_case("application/json")
    {
        return Err(Box::new(content_type_error()));
    }
    if segments.any(|parameter| !parameter.trim().eq_ignore_ascii_case("charset=utf-8")) {
        return Err(Box::new(content_type_error()));
    }
    Ok(())
}

fn content_type_error() -> Response {
    a2a_error_response(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "INVALID_ARGUMENT",
        "A2A content type is not supported",
        "CONTENT_TYPE_NOT_SUPPORTED",
        None,
    )
}

async fn read_body(
    body: Body,
    headers: &HeaderMap,
    body_timeout: Duration,
    maximum: usize,
) -> Result<Vec<u8>, Box<Response>> {
    if headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > maximum)
    {
        return Err(Box::new(request_too_large_response()));
    }
    match timeout(body_timeout, to_bytes(body, maximum.saturating_add(1))).await {
        Err(_) => Err(Box::new(a2a_error_response(
            StatusCode::REQUEST_TIMEOUT,
            "DEADLINE_EXCEEDED",
            "A2A request body timed out",
            "REQUEST_TIMEOUT",
            None,
        ))),
        Ok(Err(_)) => Err(Box::new(contract_error_response(
            A2AContractError::MalformedEncoding,
        ))),
        Ok(Ok(bytes)) if bytes.len() > maximum => Err(Box::new(request_too_large_response())),
        Ok(Ok(bytes)) => Ok(bytes.to_vec()),
    }
}

fn request_too_large_response() -> Response {
    a2a_error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "RESOURCE_EXHAUSTED",
        "A2A request body exceeds its bound",
        "REQUEST_TOO_LARGE",
        None,
    )
}

fn parse_history_length(query: Option<&str>) -> Result<Option<i32>, Box<Response>> {
    let Some(query) = query else {
        return Ok(None);
    };
    if query.len() > MAX_QUERY_BYTES {
        return Err(Box::new(contract_error_response(
            A2AContractError::OutOfRange {
                field: "get_task.query",
            },
        )));
    }
    let mut history_length = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key != "historyLength" || history_length.is_some() {
            return Err(Box::new(contract_error_response(
                A2AContractError::UnsupportedField {
                    field: "get_task.query",
                },
            )));
        }
        history_length = Some(value.parse::<i32>().map_err(|_| {
            Box::new(contract_error_response(A2AContractError::OutOfRange {
                field: "history_length",
            }))
        })?);
    }
    Ok(history_length)
}

fn contract_error_response(error: A2AContractError) -> Response {
    let field = match &error {
        A2AContractError::MissingField { field }
        | A2AContractError::UnsupportedField { field }
        | A2AContractError::InvalidIdentifier { field }
        | A2AContractError::InvalidText { field }
        | A2AContractError::DuplicateValue { field }
        | A2AContractError::OutOfRange { field } => Some(*field),
        A2AContractError::EncodedMessageTooLarge { .. }
        | A2AContractError::MalformedEncoding
        | A2AContractError::TenantMismatch
        | A2AContractError::InvalidInterfaceUrl => None,
    };
    a2a_error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_ARGUMENT",
        "A2A request is invalid",
        "INVALID_REQUEST",
        field,
    )
}

fn gateway_error_response(error: A2AGatewayError) -> Response {
    match error {
        A2AGatewayError::Unauthenticated => authentication_error_response(None),
        A2AGatewayError::Forbidden => a2a_error_response(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "A2A operation is forbidden",
            "PERMISSION_DENIED",
            None,
        ),
        A2AGatewayError::RouteMismatch | A2AGatewayError::TaskNotFound => a2a_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "A2A task or route was not found",
            "TASK_NOT_FOUND",
            None,
        ),
        A2AGatewayError::Conflict => a2a_error_response(
            StatusCode::CONFLICT,
            "ALREADY_EXISTS",
            "A2A task identity conflicts with existing state",
            "IDEMPOTENCY_CONFLICT",
            None,
        ),
        A2AGatewayError::CapacityExceeded => {
            unavailable_response("A2A task capacity is exhausted", "RESOURCE_EXHAUSTED")
        }
        A2AGatewayError::StorageUnavailable
        | A2AGatewayError::SubmissionUnavailable
        | A2AGatewayError::AuthorizationUnavailable => {
            unavailable_response("A2A gateway is temporarily unavailable", "UNAVAILABLE")
        }
        A2AGatewayError::ResponseWaitExpired => a2a_error_response(
            StatusCode::GATEWAY_TIMEOUT,
            "DEADLINE_EXCEEDED",
            "A2A response wait expired",
            "DEADLINE_EXCEEDED",
            None,
        ),
        A2AGatewayError::ExtendedCardNotConfigured => a2a_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "A2A extended Agent Card is not configured",
            "EXTENDED_AGENT_CARD_NOT_CONFIGURED",
            None,
        ),
        A2AGatewayError::Contract
        | A2AGatewayError::InvalidConfiguration
        | A2AGatewayError::InvalidTaskProjection
        | A2AGatewayError::ClockUnavailable
        | A2AGatewayError::UnsupportedAuthentication
        | A2AGatewayError::Transport
        | A2AGatewayError::ServerUnavailable
        | A2AGatewayError::Remote { .. } => a2a_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "A2A gateway failed",
            "INVALID_AGENT_RESPONSE",
            None,
        ),
    }
}

fn authentication_error_response(kind: Option<InitialA2AAgentSecurityKind>) -> Response {
    let mut response = a2a_error_response(
        StatusCode::UNAUTHORIZED,
        "UNAUTHENTICATED",
        "A2A authentication failed",
        "UNAUTHENTICATED",
        None,
    );
    if kind == Some(InitialA2AAgentSecurityKind::Bearer) {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

fn unavailable_response(message: &'static str, reason: &'static str) -> Response {
    let mut response = a2a_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "UNAVAILABLE",
        message,
        reason,
        None,
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn a2a_error_response(
    status: StatusCode,
    rpc_status: &'static str,
    message: &'static str,
    reason: &'static str,
    field: Option<&'static str>,
) -> Response {
    let mut details = vec![ErrorDetail::Info(ErrorInfo {
        type_name: "type.googleapis.com/google.rpc.ErrorInfo",
        reason,
        domain: "a2a-protocol.org",
    })];
    if let Some(field) = field {
        details.push(ErrorDetail::BadRequest(BadRequest {
            type_name: "type.googleapis.com/google.rpc.BadRequest",
            field_violations: [FieldViolation {
                field,
                description: "value is invalid",
            }],
        }));
    }
    let envelope = ErrorEnvelope {
        error: ErrorStatus {
            code: status.as_u16(),
            status: rpc_status,
            message,
            details,
        },
    };
    match serde_json::to_vec(&envelope) {
        Ok(bytes) => json_response(status, bytes),
        Err(_) => status.into_response(),
    }
}

fn json_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(A2A_JSON_MEDIA_TYPE));
    response
}

fn cached_card_response(card: &CachedCard, headers: &HeaderMap) -> Response {
    if headers
        .get(IF_NONE_MATCH)
        .is_some_and(|etag| etag == card.etag)
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        card.apply_headers(response.headers_mut());
        return response;
    }
    let mut response = json_response(StatusCode::OK, card.bytes.as_ref().to_vec());
    card.apply_headers(response.headers_mut());
    response
}

#[derive(Clone)]
struct CachedCard {
    bytes: Arc<[u8]>,
    etag: HeaderValue,
    cache_control: HeaderValue,
}

impl CachedCard {
    fn new(bytes: Vec<u8>, max_age_seconds: u64, private: bool) -> Result<Self, A2AGatewayError> {
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let etag = HeaderValue::from_str(&format!("\"{}\"", lowercase_hex(digest)))
            .map_err(|_| A2AGatewayError::InvalidConfiguration)?;
        let visibility = if private { "private" } else { "public" };
        let cache_control =
            HeaderValue::from_str(&format!("{visibility}, max-age={max_age_seconds}"))
                .map_err(|_| A2AGatewayError::InvalidConfiguration)?;
        Ok(Self {
            bytes: bytes.into(),
            etag,
            cache_control,
        })
    }

    fn apply_headers(&self, headers: &mut HeaderMap) {
        headers.insert(ETAG, self.etag.clone());
        headers.insert(CACHE_CONTROL, self.cache_control.clone());
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorStatus,
}

#[derive(Serialize)]
struct ErrorStatus {
    code: u16,
    status: &'static str,
    message: &'static str,
    details: Vec<ErrorDetail>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ErrorDetail {
    Info(ErrorInfo),
    BadRequest(BadRequest),
}

#[derive(Serialize)]
struct ErrorInfo {
    #[serde(rename = "@type")]
    type_name: &'static str,
    reason: &'static str,
    domain: &'static str,
}

#[derive(Serialize)]
struct BadRequest {
    #[serde(rename = "@type")]
    type_name: &'static str,
    #[serde(rename = "fieldViolations")]
    field_violations: [FieldViolation; 1],
}

#[derive(Serialize)]
struct FieldViolation {
    field: &'static str,
    description: &'static str,
}

fn lowercase_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
