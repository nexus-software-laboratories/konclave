use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[path = "../src/http.rs"]
mod http;
#[path = "../src/websocket.rs"]
mod websocket;

#[tokio::test]
async fn websocket_replies_to_ping_and_shuts_down() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            http::router(env!("CARGO_PKG_NAME"), shutdown_rx.clone()),
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

    let (mut client, _) = connect_async(format!("ws://{address}/ws")).await.unwrap();
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
