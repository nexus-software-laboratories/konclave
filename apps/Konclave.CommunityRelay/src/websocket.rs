use std::time::Duration;

use anyhow::{Context, anyhow};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, timeout};

pub async fn upgrade(upgrade: WebSocketUpgrade, shutdown: watch::Receiver<bool>) -> Response {
    upgrade.on_upgrade(|socket| async move {
        if let Err(error) = run_session(socket, 16, Duration::from_secs(30), shutdown).await {
            eprintln!("WebSocket session failed: {error:#}");
        }
    })
}

pub async fn run_session(
    socket: WebSocket,
    outbound_capacity: usize,
    ping_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if outbound_capacity == 0 {
        return Err(anyhow!("WebSocket outbound capacity must be positive"));
    }

    let (mut sender, mut receiver) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Message>(outbound_capacity);
    let mut writer = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            sender
                .send(message)
                .await
                .context("writing WebSocket message")?;
        }
        anyhow::Result::<()>::Ok(())
    });
    let mut ping = tokio::time::interval_at(Instant::now() + ping_interval, ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let session_result = loop {
        tokio::select! {
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Ping(payload))) => {
                        if outbound_tx.try_send(Message::Pong(payload)).is_err() {
                            break Err(anyhow!("WebSocket outbound queue is full"));
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => break Err(error.into()),
                }
            }
            _ = ping.tick() => {
                if outbound_tx
                    .try_send(Message::Ping(Vec::new().into()))
                    .is_err()
                {
                    break Err(anyhow!("WebSocket outbound queue is full"));
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
        }
    };

    drop(outbound_tx);
    match timeout(Duration::from_secs(1), &mut writer).await {
        Ok(result) => {
            result.context("joining WebSocket writer")??;
        }
        Err(_) => {
            writer.abort();
            let _ = writer.await;
            return Err(anyhow!("WebSocket writer did not stop within one second"));
        }
    }
    session_result
}
