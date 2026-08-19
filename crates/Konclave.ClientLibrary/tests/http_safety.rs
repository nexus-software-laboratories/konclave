use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use KonclaveClientLibrary::{
    KonclaveClientError, RelayAccessCredential, RelayClient, RelayEndpoint, RelayTransport,
};
use KonclaveDomainCore::{
    DeliveryClass, EnvelopeId, MAX_RELAY_ENVELOPE_BYTES, ProtocolVersion, RelayEnvelope, RoutingId,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::Response;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::Redirect;
use axum::routing::post;
use futures_util::stream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

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
async fn client_never_forwards_bearer_credentials_across_redirects() {
    let target_hit = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&target_hit);
    let target = Router::new().route(
        "/v1/envelopes",
        post(move || {
            let observed = Arc::clone(&observed);
            async move {
                observed.store(true, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );
    let (target_address, target_shutdown, target_server) = serve(target).await;
    let location = format!("http://{target_address}/v1/envelopes");
    let redirect = Router::new().route(
        "/v1/envelopes",
        post(move || {
            let location = location.clone();
            async move { Redirect::temporary(&location) }
        }),
    );
    let (address, shutdown, server) = serve(redirect).await;

    let error = client(address).submit(&envelope()).await.err().unwrap();
    assert!(matches!(
        error,
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
        return;
    }

    let target = Router::new().route(
        "/v1/envelopes",
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
