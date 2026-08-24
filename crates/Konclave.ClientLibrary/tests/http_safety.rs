use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use KonclaveClientLibrary::{
    EnrollmentRequestId, HttpRelayEnrollmentTransport, KonclaveClientError, RelayAccessCredential,
    RelayClient, RelayEndpoint, RelayEnrollmentClient, RelayEnrollmentCredential,
    RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayPrincipalId, RelayTransport,
};
use KonclaveDomainCore::{
    DeliveryClass, EnvelopeId, MAX_RELAY_CONTROL_MESSAGE_BYTES, MAX_RELAY_ENVELOPE_BYTES,
    ProtocolVersion, RelayEnvelope, RoutingId,
};
use KonclaveProtocolContracts::v1::{
    decode_relay_enrollment_request, encode_relay_enrollment_response,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::Redirect;
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::stream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

async fn serve(router: Router) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    (address, shutdown, server)
}

fn client(address: SocketAddr) -> RelayClient {
    RelayClient::new(
        RelayEndpoint::parse(&format!("http://{address}")).unwrap(),
        RelayAccessCredential::from_bytes([7; RelayAccessCredential::LENGTH]),
    )
    .unwrap()
}

fn enrollment_client(address: SocketAddr) -> RelayEnrollmentClient<HttpRelayEnrollmentTransport> {
    RelayEnrollmentClient::new(
        HttpRelayEnrollmentTransport::new(
            RelayEndpoint::parse(&format!("http://{address}")).unwrap(),
            RelayEnrollmentCredential::from_bytes([6; RelayEnrollmentCredential::LENGTH]),
        )
        .unwrap(),
    )
}

fn enrollment_request() -> RelayEnrollmentRequest {
    RelayEnrollmentRequest::new(
        ProtocolVersion::application_v1(),
        EnrollmentRequestId::from_bytes([1; EnrollmentRequestId::LENGTH]),
        RelayPrincipalId::from_bytes([2; RelayPrincipalId::LENGTH]),
    )
}

fn envelope() -> RelayEnvelope {
    RelayEnvelope::new(
        ProtocolVersion::application_v1(),
        RoutingId::from_bytes([8; RoutingId::LENGTH]),
        EnvelopeId::from_bytes([9; EnvelopeId::LENGTH]),
        DeliveryClass::GroupApplication,
        None,
        u64::MAX / 2,
        vec![1],
    )
    .unwrap()
}

#[tokio::test]
async fn clients_never_forward_bearer_credentials_across_redirects() {
    let target_hit = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&target_hit);
    let target_handler = move || {
        let observed = Arc::clone(&observed);
        async move {
            observed.store(true, Ordering::SeqCst);
            StatusCode::OK
        }
    };
    let target = Router::new()
        .route("/v1/envelopes", post(target_handler.clone()))
        .route("/v1/enrollment/principals", post(target_handler));
    let (target_address, target_shutdown, target_server) = serve(target).await;
    let location = format!("http://{target_address}/v1/envelopes");
    let redirect_handler = move || {
        let location = location.clone();
        async move { Redirect::temporary(&location) }
    };
    let enrollment_location = format!("http://{target_address}/v1/enrollment/principals");
    let enrollment_redirect = move || {
        let location = enrollment_location.clone();
        async move { Redirect::temporary(&location) }
    };
    let redirect = Router::new()
        .route("/v1/envelopes", post(redirect_handler))
        .route("/v1/enrollment/principals", post(enrollment_redirect));
    let (address, shutdown, server) = serve(redirect).await;

    let error = client(address).submit(&envelope()).await.err().unwrap();
    assert!(matches!(
        error,
        KonclaveClientError::RelayRejected { status: 307, .. }
    ));
    let enrollment_error = enrollment_client(address)
        .register(enrollment_request())
        .await
        .unwrap_err();
    assert!(matches!(
        enrollment_error,
        KonclaveClientError::RelayRejected { status: 307, .. }
    ));
    assert!(!target_hit.load(Ordering::SeqCst));

    shutdown.send(()).unwrap();
    target_shutdown.send(()).unwrap();
    server.await.unwrap();
    target_server.await.unwrap();
}

#[tokio::test]
async fn client_rejects_oversized_chunked_success_responses() {
    let body = vec![0_u8; MAX_RELAY_ENVELOPE_BYTES + 33];
    let oversized = Router::new().route(
        "/v1/envelopes",
        post(move || {
            let mut first = body.clone();
            let second = first.split_off(first.len() / 2);
            async move {
                Response::builder()
                    .header(CONTENT_TYPE, "application/protobuf")
                    .body(Body::from_stream(stream::iter([
                        Ok::<_, Infallible>(Bytes::from(first)),
                        Ok::<_, Infallible>(Bytes::from(second)),
                    ])))
                    .unwrap()
            }
        }),
    );
    let (address, shutdown, server) = serve(oversized).await;

    let error = client(address).submit(&envelope()).await.err().unwrap();
    assert!(matches!(
        error,
        KonclaveClientError::ResponseTooLarge { .. }
    ));

    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn enrollment_client_sends_canonical_request_and_credential() {
    let credential_seen = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&credential_seen);
    let router = Router::new().route(
        "/v1/enrollment/principals",
        post(move |headers: HeaderMap, body: Bytes| {
            let observed = Arc::clone(&observed);
            async move {
                let expected = Zeroizing::new(format!(
                    "Bearer {}",
                    URL_SAFE_NO_PAD.encode([6; RelayEnrollmentCredential::LENGTH])
                ));
                observed.store(
                    headers
                        .get(AUTHORIZATION)
                        .is_some_and(|value| value.as_bytes() == expected.as_bytes()),
                    Ordering::SeqCst,
                );
                let request = decode_relay_enrollment_request(&body).unwrap();
                let response = KonclaveClientLibrary::RelayEnrollmentResponse::new(
                    request.version(),
                    request.request_id(),
                    request.principal_id(),
                    RelayEnrollmentOutcome::Registered,
                );
                (
                    StatusCode::CREATED,
                    [(CONTENT_TYPE, "application/protobuf")],
                    encode_relay_enrollment_response(&response).unwrap(),
                )
            }
        }),
    );
    let (address, shutdown, server) = serve(router).await;

    let response = enrollment_client(address)
        .register(enrollment_request())
        .await
        .unwrap();
    assert_eq!(response.outcome(), RelayEnrollmentOutcome::Registered);
    assert!(credential_seen.load(Ordering::SeqCst));

    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn enrollment_client_rejects_wrong_media_type_and_chunked_oversize() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&request_count);
    let router = Router::new().route(
        "/v1/enrollment/principals",
        post(move || {
            let request_index = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                if request_index == 0 {
                    return Response::builder()
                        .status(StatusCode::CREATED)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap();
                }
                let body = vec![0_u8; MAX_RELAY_CONTROL_MESSAGE_BYTES + 1];
                let (first, second) = body.split_at(body.len() / 2);
                Response::builder()
                    .status(StatusCode::CREATED)
                    .header(CONTENT_TYPE, "application/protobuf")
                    .body(Body::from_stream(stream::iter([
                        Ok::<_, Infallible>(Bytes::copy_from_slice(first)),
                        Ok::<_, Infallible>(Bytes::copy_from_slice(second)),
                    ])))
                    .unwrap()
            }
        }),
    );
    let (address, shutdown, server) = serve(router).await;
    let client = enrollment_client(address);

    assert!(matches!(
        client.register(enrollment_request()).await.unwrap_err(),
        KonclaveClientError::InvalidResponse
    ));
    assert!(matches!(
        client.register(enrollment_request()).await.unwrap_err(),
        KonclaveClientError::ResponseTooLarge {
            maximum: MAX_RELAY_CONTROL_MESSAGE_BYTES
        }
    ));

    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn enrollment_client_enforces_status_outcome_and_response_identity() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&request_count);
    let router = Router::new().route(
        "/v1/enrollment/principals",
        post(move |body: Bytes| {
            let request_index = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                let request = decode_relay_enrollment_request(&body).unwrap();
                let (status, outcome, principal) = match request_index {
                    0 => (
                        StatusCode::CREATED,
                        RelayEnrollmentOutcome::Registered,
                        request.principal_id(),
                    ),
                    1 => (
                        StatusCode::OK,
                        RelayEnrollmentOutcome::AlreadyRegistered,
                        request.principal_id(),
                    ),
                    2 => (
                        StatusCode::OK,
                        RelayEnrollmentOutcome::Registered,
                        request.principal_id(),
                    ),
                    _ => (
                        StatusCode::CREATED,
                        RelayEnrollmentOutcome::Registered,
                        RelayPrincipalId::from_bytes([9; RelayPrincipalId::LENGTH]),
                    ),
                };
                let response = KonclaveClientLibrary::RelayEnrollmentResponse::new(
                    request.version(),
                    request.request_id(),
                    principal,
                    outcome,
                );
                (
                    status,
                    [(CONTENT_TYPE, "application/protobuf")],
                    encode_relay_enrollment_response(&response).unwrap(),
                )
            }
        }),
    );
    let (address, shutdown, server) = serve(router).await;
    let client = enrollment_client(address);

    assert_eq!(
        client
            .register(enrollment_request())
            .await
            .unwrap()
            .outcome(),
        RelayEnrollmentOutcome::Registered
    );
    assert_eq!(
        client
            .register(enrollment_request())
            .await
            .unwrap()
            .outcome(),
        RelayEnrollmentOutcome::AlreadyRegistered
    );
    assert!(matches!(
        client.register(enrollment_request()).await.unwrap_err(),
        KonclaveClientError::InvalidEnrollmentResponse
    ));
    assert!(matches!(
        client.register(enrollment_request()).await.unwrap_err(),
        KonclaveClientError::InvalidEnrollmentResponse
    ));

    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn enrollment_client_preserves_bounded_relay_rejections() {
    let responses = Arc::new(Mutex::new(std::collections::VecDeque::from([
        (StatusCode::BAD_REQUEST, "invalid_length"),
        (StatusCode::UNAUTHORIZED, "relay_authentication_failed"),
        (StatusCode::FORBIDDEN, "relay_principal_revoked"),
        (StatusCode::CONFLICT, "relay_enrollment_conflict"),
        (StatusCode::PAYLOAD_TOO_LARGE, "encoded_message_too_large"),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"),
        (StatusCode::TOO_MANY_REQUESTS, "relay_principal_capacity"),
        (StatusCode::INTERNAL_SERVER_ERROR, "relay_internal_error"),
        (StatusCode::SERVICE_UNAVAILABLE, "relay_storage_failure"),
    ])));
    let pending = Arc::clone(&responses);
    let router = Router::new().route(
        "/v1/enrollment/principals",
        post(move || {
            let (status, code) = pending.lock().unwrap().pop_front().unwrap();
            async move { (status, [("x-konclave-error-code", code)]) }
        }),
    );
    let (address, shutdown, server) = serve(router).await;
    let client = enrollment_client(address);
    let expected = [
        (400, "invalid_length"),
        (401, "relay_authentication_failed"),
        (403, "relay_principal_revoked"),
        (409, "relay_enrollment_conflict"),
        (413, "encoded_message_too_large"),
        (415, "unsupported_media_type"),
        (429, "relay_principal_capacity"),
        (500, "relay_internal_error"),
        (503, "relay_storage_failure"),
    ];

    for (expected_status, expected_code) in expected {
        let error = client.register(enrollment_request()).await.unwrap_err();
        assert!(matches!(
            error,
            KonclaveClientError::RelayRejected {
                status,
                ref relay_code
            } if status == expected_status && relay_code == expected_code
        ));
    }
    assert!(responses.lock().unwrap().is_empty());

    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn client_ignores_automatic_proxy_configuration() {
    if let Ok(target) = std::env::var("KONCLAVE_PROXY_TEST_TARGET") {
        let error = client(target.parse().unwrap())
            .submit(&envelope())
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error,
            KonclaveClientError::RelayRejected {
                status: 403,
                ref relay_code
            } if relay_code == "direct_target"
        ));
        let enrollment_error = enrollment_client(target.parse().unwrap())
            .register(enrollment_request())
            .await
            .unwrap_err();
        assert!(matches!(
            enrollment_error,
            KonclaveClientError::RelayRejected {
                status: 403,
                ref relay_code
            } if relay_code == "direct_target"
        ));
        return;
    }

    let target = Router::new()
        .route(
            "/v1/envelopes",
            post(|| async {
                (
                    StatusCode::FORBIDDEN,
                    [("x-konclave-error-code", "direct_target")],
                )
            }),
        )
        .route(
            "/v1/enrollment/principals",
            post(|| async {
                (
                    StatusCode::FORBIDDEN,
                    [("x-konclave-error-code", "direct_target")],
                )
            }),
        );
    let (target_address, target_shutdown, target_server) = serve(target).await;
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let (proxy_shutdown, mut proxy_shutdown_rx) = oneshot::channel();
    let proxy_server = tokio::spawn(async move {
        tokio::select! {
            accepted = proxy_listener.accept() => accepted.is_ok(),
            _ = &mut proxy_shutdown_rx => false,
        }
    });
    let executable = std::env::current_exe().unwrap();
    let child = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .args([
                "--exact",
                "client_ignores_automatic_proxy_configuration",
                "--nocapture",
            ])
            .env("KONCLAVE_PROXY_TEST_TARGET", target_address.to_string())
            .env("HTTP_PROXY", format!("http://{proxy_address}"))
            .env("http_proxy", format!("http://{proxy_address}"))
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .status()
            .unwrap()
    })
    .await
    .unwrap();

    target_shutdown.send(()).unwrap();
    let _ = proxy_shutdown.send(());
    target_server.await.unwrap();
    let proxy_was_used = proxy_server.await.unwrap();
    assert!(child.success());
    assert!(!proxy_was_used);
}
