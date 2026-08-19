mod support;

use std::time::Duration;

use KonclaveCommunityRelay::http::{HttpState, router};
use axum::http::HeaderValue;
use axum::http::header::AUTHORIZATION;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use support::TestRelay;

#[tokio::test]
async fn authenticated_websocket_replies_to_ping_and_shuts_down() {
    let relay = TestRelay::new(true).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let token = relay.token;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router(
                HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
                relay.access,
                shutdown_rx.clone(),
            ),
        )
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .unwrap();
    });

    let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", URL_SAFE_NO_PAD.encode(token))).unwrap(),
    );
    let (mut client, _) = connect_async(request).await.unwrap();
    client.send(Message::Ping(Vec::new().into())).await.unwrap();
    let response = timeout(Duration::from_secs(1), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(response, Message::Pong(_)));

    client.close(None).await.unwrap();
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}
