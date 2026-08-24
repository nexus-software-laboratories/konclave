use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use KonclaveDomainCore::{
    AcknowledgeRequest, MAX_RELAY_CONTROL_MESSAGE_BYTES, MAX_RELAY_ENVELOPE_BYTES,
};
use KonclaveProtocolContracts::KonclaveProtocolError;
use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_relay_enrollment_request, decode_replay_request,
    encode_acknowledge_request, encode_relay_enrollment_response,
    encode_stored_relay_envelope_preserving,
};
use KonclaveRelayCore::{RelayError, RelayPrincipalId};
use anyhow::{Context, bail};
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Extension, State, WebSocketUpgrade};
use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::Handle;
use serde::Serialize;
use tokio::sync::watch;
use tokio::time::timeout;
use tower::limit::ConcurrencyLimitLayer;

use crate::access::{RelayAccess, StaticRelayAccess};
use crate::application::RelayApplication;

const PROTOBUF_MEDIA_TYPE: &str = "application/protobuf";
const ERROR_CODE_HEADER: &str = "x-konclave-error-code";
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_REQUESTS: usize = 256;
const MAX_WEBSOCKET_SESSIONS: usize = 256;
const MAX_CONCURRENT_ENROLLMENTS: usize = 8;
const MAX_ENROLLMENTS_PER_WINDOW: u32 = 16;
const ENROLLMENT_RATE_WINDOW: Duration = Duration::from_secs(1);
const ACCESS_FILE_ENV: &str = "KONCLAVE_RELAY_ACCESS_FILE";
const DATABASE_PATH_ENV: &str = "KONCLAVE_RELAY_DATABASE_PATH";
const TLS_TERMINATED_ENV: &str = "KONCLAVE_RELAY_TLS_TERMINATED";

/// Immutable dependencies shared by relay HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    service_name: String,
    application: RelayApplication,
    websocket_slots: Arc<tokio::sync::Semaphore>,
    enrollment_slots: Arc<tokio::sync::Semaphore>,
    enrollment_rate: EnrollmentRateLimiter,
    watch_config: crate::websocket::SessionConfig,
}

#[derive(Clone)]
struct EnrollmentRateLimiter {
    window: Arc<Mutex<EnrollmentRateWindow>>,
}

struct EnrollmentRateWindow {
    started: Instant,
    requests: u32,
}

impl EnrollmentRateLimiter {
    fn new() -> Self {
        Self {
            window: Arc::new(Mutex::new(EnrollmentRateWindow {
                started: Instant::now(),
                requests: 0,
            })),
        }
    }

    fn try_acquire(&self) -> bool {
        let Ok(mut window) = self.window.lock() else {
            return false;
        };
        if window.started.elapsed() >= ENROLLMENT_RATE_WINDOW {
            window.started = Instant::now();
            window.requests = 0;
        }
        if window.requests >= MAX_ENROLLMENTS_PER_WINDOW {
            return false;
        }
        window.requests += 1;
        true
    }
}

impl HttpState {
    /// Creates handler state from a service label and initialized application.
    #[must_use]
    pub fn new(service_name: impl Into<String>, application: RelayApplication) -> Self {
        Self {
            service_name: service_name.into(),
            application,
            websocket_slots: Arc::new(tokio::sync::Semaphore::new(MAX_WEBSOCKET_SESSIONS)),
            enrollment_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ENROLLMENTS)),
            enrollment_rate: EnrollmentRateLimiter::new(),
            watch_config: crate::websocket::SessionConfig::default(),
        }
    }

    /// Overrides watch timing while retaining the production protocol bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when any timeout or interval is zero.
    pub fn with_watch_timing(
        mut self,
        handshake_timeout: Duration,
        write_timeout: Duration,
        ping_interval: Duration,
        replay_safety_interval: Duration,
    ) -> anyhow::Result<Self> {
        self.watch_config = crate::websocket::SessionConfig::new(
            handshake_timeout,
            write_timeout,
            ping_interval,
            replay_safety_interval,
        )?;
        Ok(self)
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: String,
}

/// Builds the health, authenticated protobuf, and authenticated WebSocket routes.
pub fn router(
    state: HttpState,
    access: StaticRelayAccess,
    shutdown: watch::Receiver<bool>,
) -> Router {
    let websocket_shutdown = shutdown.clone();
    let data_access = RelayAccess::new(access.clone(), state.application.registry());
    let protected = Router::new()
        .route("/v1/envelopes", post(submit))
        .route("/v1/replay", post(replay))
        .route("/v1/acknowledgments", post(acknowledge))
        .route(
            "/ws",
            get(
                move |upgrade: WebSocketUpgrade,
                      State(state): State<HttpState>,
                      Extension(principal): Extension<RelayPrincipalId>| {
                    let shutdown = websocket_shutdown.clone();
                    async move {
                        let permit = match state.websocket_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                return error_response(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "relay_websocket_capacity",
                                );
                            }
                        };
                        crate::websocket::upgrade(
                            upgrade,
                            principal,
                            state.application,
                            permit,
                            shutdown,
                            state.watch_config,
                        )
                        .await
                    }
                },
            ),
        )
        .route_layer(middleware::from_fn_with_state(
            data_access,
            authenticate_request,
        ));
    let enrollment = Router::new()
        .route("/v1/enrollment/principals", post(enroll_principal))
        .route_layer(middleware::from_fn_with_state(
            access,
            authenticate_enrollment_request,
        ));

    Router::new()
        .route("/healthz", get(health))
        .merge(enrollment)
        .merge(protected)
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
}

#[allow(dead_code)]
pub(crate) fn check_health() -> anyhow::Result<()> {
    let address = std::env::var("SERVICE_HEALTH_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()
        .context("parsing SERVICE_HEALTH_ADDRESS")?;
    check_health_at(address)
}

fn check_health_at(address: SocketAddr) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("connecting to health endpoint at {address}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting healthcheck read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting healthcheck write timeout")?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .context("writing healthcheck request")?;

    let mut response = [0_u8; 128];
    let mut response_length = 0;
    while response_length < response.len() {
        let read_length = stream
            .read(&mut response[response_length..])
            .context("reading healthcheck response")?;
        if read_length == 0 {
            break;
        }
        response_length += read_length;
        if response[..response_length].contains(&b'\n') {
            break;
        }
    }
    let status_line = std::str::from_utf8(&response[..response_length])
        .context("decoding healthcheck response")?
        .lines()
        .next()
        .unwrap_or_default();
    if status_line.split_whitespace().nth(1) != Some("200") {
        bail!("health endpoint returned a non-success status");
    }

    Ok(())
}

/// Loads fail-closed relay state and serves until shutdown.
///
/// # Errors
///
/// Returns an error when configuration, access policy, storage, binding security, or
/// the HTTP server fails.
#[allow(dead_code)]
pub async fn serve_until(
    mut shutdown: watch::Receiver<bool>,
    shutdown_grace_period: Duration,
) -> anyhow::Result<()> {
    let address = std::env::var("SERVICE_HTTP_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()
        .context("parsing SERVICE_HTTP_ADDRESS")?;
    let tls_terminated = parse_tls_termination()?;
    validate_binding(address.ip(), tls_terminated)?;

    let access_path = required_path(ACCESS_FILE_ENV)?;
    let database_path = required_path(DATABASE_PATH_ENV)?;
    let access = tokio::task::spawn_blocking(move || StaticRelayAccess::load(&access_path))
        .await
        .context("joining relay access-file load")??;
    let application = RelayApplication::connect(&database_path, access.clone())
        .await
        .context("opening relay application")?;
    let state = HttpState::new(env!("CARGO_PKG_NAME"), application);

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    let router_shutdown = shutdown.clone();
    let server = async move {
        axum_server::bind(address)
            .handle(handle)
            .serve(router(state, access, router_shutdown).into_make_service())
            .await
            .context("serving HTTP requests")
    };
    let shutdown_signal = async move {
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        shutdown_handle.graceful_shutdown(Some(shutdown_grace_period));
        anyhow::Result::<()>::Ok(())
    };

    tokio::try_join!(server, shutdown_signal)?;
    Ok(())
}

async fn authenticate_request(
    State(access): State<RelayAccess>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match access.authenticate_data_plane(request.headers()).await {
        Ok(principal) => {
            request
                .headers_mut()
                .remove(axum::http::header::AUTHORIZATION);
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(RelayError::Unauthorized) => authentication_error_response(),
        Err(error) => relay_error_response(&error),
    }
}

async fn authenticate_enrollment_request(
    State(access): State<StaticRelayAccess>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match access.authenticate_enrollment(request.headers()) {
        Ok(()) => {
            request
                .headers_mut()
                .remove(axum::http::header::AUTHORIZATION);
            next.run(request).await
        }
        Err(_) => authentication_error_response(),
    }
}

async fn enroll_principal(State(state): State<HttpState>, request: Request<Body>) -> Response {
    let _permit = match state.enrollment_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "relay_enrollment_capacity");
        }
    };
    if !state.enrollment_rate.try_acquire() {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "relay_enrollment_rate_limited",
        );
    }
    let bytes = match read_protobuf(request, MAX_RELAY_CONTROL_MESSAGE_BYTES).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let request = match decode_relay_enrollment_request(&bytes) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(&error),
    };
    let response = match state.application.register_principal(request).await {
        Ok(response) => response,
        Err(error) => return relay_error_response(&error),
    };
    let status = match response.outcome() {
        KonclaveRelayAuthentication::RelayEnrollmentOutcome::Registered => StatusCode::CREATED,
        KonclaveRelayAuthentication::RelayEnrollmentOutcome::AlreadyRegistered => StatusCode::OK,
        _ => return internal_error_response(),
    };
    match encode_relay_enrollment_response(&response) {
        Ok(bytes) => protobuf_response(status, bytes),
        Err(_) => internal_error_response(),
    }
}

async fn submit(
    State(state): State<HttpState>,
    Extension(principal): Extension<RelayPrincipalId>,
    request: Request<Body>,
) -> Response {
    let bytes = match read_protobuf(request, MAX_RELAY_ENVELOPE_BYTES).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let outcome = match state.application.submit_encoded(principal, &bytes).await {
        Ok(outcome) => outcome,
        Err(error) => return relay_error_response(&error),
    };
    let bytes = match encode_stored_relay_envelope_preserving(&bytes, outcome.cursor()) {
        Ok(bytes) => bytes,
        Err(_) => return internal_error_response(),
    };
    protobuf_response(
        if outcome.duplicate() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        bytes,
    )
}

async fn replay(
    State(state): State<HttpState>,
    Extension(principal): Extension<RelayPrincipalId>,
    request: Request<Body>,
) -> Response {
    let bytes = match read_protobuf(request, MAX_RELAY_CONTROL_MESSAGE_BYTES).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let request = match decode_replay_request(&bytes) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(&error),
    };
    let page = match state.application.replay_encoded(principal, request).await {
        Ok(page) => page,
        Err(error) => return relay_error_response(&error),
    };
    protobuf_response(StatusCode::OK, page.into_bytes())
}

async fn acknowledge(
    State(state): State<HttpState>,
    Extension(principal): Extension<RelayPrincipalId>,
    request: Request<Body>,
) -> Response {
    let bytes = match read_protobuf(request, MAX_RELAY_CONTROL_MESSAGE_BYTES).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let request = match decode_acknowledge_request(&bytes) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(&error),
    };
    let route = request.routing_id();
    let cursor = match state.application.acknowledge(principal, request).await {
        Ok(cursor) => cursor,
        Err(error) => return relay_error_response(&error),
    };
    let response = match AcknowledgeRequest::new(route, cursor) {
        Ok(response) => response,
        Err(_) => return internal_error_response(),
    };
    match encode_acknowledge_request(response) {
        Ok(bytes) => protobuf_response(StatusCode::OK, bytes),
        Err(_) => internal_error_response(),
    }
}

async fn read_protobuf(request: Request<Body>, maximum: usize) -> Result<Bytes, Box<Response>> {
    read_protobuf_with_timeout(request, maximum, REQUEST_BODY_TIMEOUT).await
}

async fn read_protobuf_with_timeout(
    request: Request<Body>,
    maximum: usize,
    body_timeout: Duration,
) -> Result<Bytes, Box<Response>> {
    if request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(PROTOBUF_MEDIA_TYPE)
    {
        return Err(Box::new(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        )));
    }
    let body = timeout(
        body_timeout,
        to_bytes(request.into_body(), maximum.saturating_add(1)),
    )
    .await;
    match body {
        Err(_) => Err(Box::new(error_response(
            StatusCode::REQUEST_TIMEOUT,
            "relay_request_timeout",
        ))),
        Ok(Err(_)) => Err(Box::new(error_response(
            StatusCode::BAD_REQUEST,
            "relay_request_body_invalid",
        ))),
        Ok(Ok(bytes)) if bytes.len() > maximum => Err(Box::new(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "encoded_message_too_large",
        ))),
        Ok(Ok(bytes)) => Ok(bytes),
    }
}

async fn health(State(state): State<HttpState>) -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            service: state.service_name,
        }),
    )
}

fn protobuf_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(PROTOBUF_MEDIA_TYPE));
    response
}

fn authentication_error_response() -> Response {
    let mut response = error_response(StatusCode::UNAUTHORIZED, "relay_authentication_failed");
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"konclave-relay\""),
    );
    response
}

fn protocol_error_response(error: &KonclaveProtocolError) -> Response {
    let status = match error {
        KonclaveProtocolError::EncodedMessageTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        KonclaveProtocolError::UnsupportedMajor { .. } => StatusCode::UPGRADE_REQUIRED,
        _ => StatusCode::BAD_REQUEST,
    };
    error_response(status, error.code())
}

fn relay_error_response(error: &RelayError) -> Response {
    let status = match error {
        RelayError::Unauthorized => StatusCode::FORBIDDEN,
        RelayError::ExpiredEnvelope => StatusCode::GONE,
        RelayError::IdempotencyConflict
        | RelayError::StaleEpoch
        | RelayError::EnrollmentConflict => StatusCode::CONFLICT,
        RelayError::PrincipalCapacityExceeded => StatusCode::TOO_MANY_REQUESTS,
        RelayError::PrincipalRevoked => StatusCode::FORBIDDEN,
        RelayError::UnsupportedEnrollmentVersion => StatusCode::BAD_REQUEST,
        RelayError::InvalidAcknowledgment => StatusCode::UNPROCESSABLE_ENTITY,
        RelayError::SequenceExhausted
        | RelayError::ClockUnavailable
        | RelayError::StorageFailure { .. } => StatusCode::SERVICE_UNAVAILABLE,
        RelayError::UnsupportedSchemaVersion { .. } | RelayError::InvalidStoredData => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        RelayError::Protocol(error) => {
            return protocol_error_response(error);
        }
        RelayError::EnvelopeEncodingMismatch => StatusCode::BAD_REQUEST,
        RelayError::Domain(_) => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, error.code())
}

fn internal_error_response() -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "relay_internal_error")
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(ERROR_CODE_HEADER, HeaderValue::from_static(code));
    response
}

fn required_path(name: &'static str) -> anyhow::Result<PathBuf> {
    let value = std::env::var_os(name).context(format!("{name} is required"))?;
    if value.is_empty() {
        bail!("{name} cannot be empty");
    }
    Ok(PathBuf::from(value))
}

fn parse_tls_termination() -> anyhow::Result<bool> {
    match std::env::var(TLS_TERMINATED_ENV) {
        Ok(value) if value == "true" => Ok(true),
        Ok(_) => bail!("{TLS_TERMINATED_ENV} must be exactly 'true' when set"),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{TLS_TERMINATED_ENV} is not valid Unicode")
        }
    }
}

fn validate_binding(address: IpAddr, tls_terminated: bool) -> anyhow::Result<()> {
    if address.is_loopback() || tls_terminated {
        Ok(())
    } else {
        bail!(
            "non-loopback relay binding requires explicit TLS termination through \
             {TLS_TERMINATED_ENV}=true"
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::TcpListener;
    use std::thread;

    use axum::http::header::AUTHORIZATION;
    use futures_util::stream;

    use super::*;

    fn start_server(status: &'static str) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        (address, handle)
    }

    #[test]
    fn healthcheck_accepts_success_status() {
        let (address, server) = start_server("200 OK");
        check_health_at(address).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn healthcheck_rejects_failure_status() {
        let (address, server) = start_server("503 Service Unavailable");
        let error = check_health_at(address).unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("non-success"));
    }

    #[test]
    fn remote_bindings_require_explicit_tls_termination() {
        assert!(validate_binding(IpAddr::from([127, 0, 0, 1]), false).is_ok());
        assert!(validate_binding(IpAddr::from([0, 0, 0, 0]), true).is_ok());
        assert!(validate_binding(IpAddr::from([0, 0, 0, 0]), false).is_err());
    }

    #[test]
    fn authorization_headers_are_never_response_metadata() {
        let response = error_response(StatusCode::BAD_REQUEST, "malformed");
        assert!(!response.headers().contains_key(AUTHORIZATION));
    }

    #[tokio::test]
    async fn request_body_read_timeout_returns_a_stable_error() {
        let request = Request::builder()
            .header(CONTENT_TYPE, PROTOBUF_MEDIA_TYPE)
            .body(Body::from_stream(stream::pending::<
                Result<Bytes, Infallible>,
            >()))
            .unwrap();
        let response = read_protobuf_with_timeout(request, 1, Duration::from_millis(1))
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            response.headers().get(ERROR_CODE_HEADER).unwrap(),
            "relay_request_timeout"
        );
    }
}
