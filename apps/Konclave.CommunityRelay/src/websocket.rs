use std::time::Duration;

use KonclaveDomainCore::{MAX_RELAY_CONTROL_MESSAGE_BYTES, ReplayRequest, RoutingId};
use KonclaveProtocolContracts::v1::decode_replay_request;
use KonclaveRelayCore::{RelayError, RelayPrincipalId};
use anyhow::{Context, anyhow, bail};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, broadcast, watch};
use tokio::time::{Instant, MissedTickBehavior, timeout};

use crate::application::RelayApplication;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const REPLAY_SAFETY_INTERVAL: Duration = Duration::from_secs(30);
const CLOSE_GOING_AWAY: u16 = 1001;
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_POLICY_VIOLATION: u16 = 1008;
const CLOSE_INTERNAL_ERROR: u16 = 1011;

pub(crate) async fn upgrade(
    upgrade: WebSocketUpgrade,
    principal: RelayPrincipalId,
    application: RelayApplication,
    permit: OwnedSemaphorePermit,
    shutdown: watch::Receiver<bool>,
    config: SessionConfig,
) -> Response {
    upgrade
        .max_message_size(MAX_RELAY_CONTROL_MESSAGE_BYTES)
        .max_frame_size(MAX_RELAY_CONTROL_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            if let Err(error) =
                run_watch_session(socket, principal, application, shutdown, config).await
            {
                report_session_error(&error);
            }
        })
}

fn report_session_error(error: &anyhow::Error) {
    #[cfg(feature = "rust-service-observability")]
    tracing::warn!(error = %error, "WebSocket session failed");
    #[cfg(not(feature = "rust-service-observability"))]
    eprintln!("WebSocket session failed: {error:#}");
}

async fn run_watch_session(
    socket: WebSocket,
    principal: RelayPrincipalId,
    application: RelayApplication,
    mut shutdown: watch::Receiver<bool>,
    config: SessionConfig,
) -> anyhow::Result<()> {
    if config.handshake_timeout.is_zero()
        || config.write_timeout.is_zero()
        || config.ping_interval.is_zero()
        || config.replay_safety_interval.is_zero()
    {
        bail!("WebSocket session timeouts must be positive");
    }

    let mut notifications = application.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let Some(request) =
        receive_replay_request(&mut sender, &mut receiver, &mut shutdown, config).await?
    else {
        return Ok(());
    };

    let route = request.routing_id();
    let limit = request.limit();
    let mut cursor = request.after_cursor();
    let mut replay_pending = drain_replay(
        &mut sender,
        &application,
        principal,
        route,
        limit,
        &mut cursor,
        true,
        config.write_timeout,
    )
    .await?;

    let mut heartbeat =
        tokio::time::interval_at(Instant::now() + config.ping_interval, config.ping_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut replay_safety = tokio::time::interval_at(
        Instant::now() + config.replay_safety_interval,
        config.replay_safety_interval,
    );
    replay_safety.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut heartbeat_state = HeartbeatState::default();

    loop {
        tokio::select! {
            _ = std::future::ready(()), if replay_pending => {
                replay_pending = drain_replay(
                    &mut sender,
                    &application,
                    principal,
                    route,
                    limit,
                    &mut cursor,
                    false,
                    config.write_timeout,
                )
                .await?;
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Ping(payload))) => {
                        send_message(
                            &mut sender,
                            Message::Pong(payload),
                            config.write_timeout,
                        )
                        .await?;
                    }
                    Some(Ok(Message::Pong(_))) => heartbeat_state.observe_pong(),
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(Message::Binary(_) | Message::Text(_))) => {
                        close_with(
                            &mut sender,
                            CLOSE_PROTOCOL_ERROR,
                            "relay_watch_unexpected_message",
                            config.write_timeout,
                        )
                        .await;
                        bail!("unexpected WebSocket message after watch initialization");
                    }
                    Some(Err(error)) => return Err(error.into()),
                }
            }
            event = notifications.recv() => {
                match event {
                    Ok(event) if event.routing_id == route && event.cursor > cursor => {
                        replay_pending = drain_replay(
                            &mut sender,
                            &application,
                            principal,
                            route,
                            limit,
                            &mut cursor,
                            false,
                            config.write_timeout,
                        )
                        .await?;
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        replay_pending = drain_replay(
                            &mut sender,
                            &application,
                            principal,
                            route,
                            limit,
                            &mut cursor,
                            false,
                            config.write_timeout,
                        )
                        .await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(anyhow!("relay event channel closed"));
                    }
                }
            }
            _ = heartbeat.tick() => {
                if heartbeat_state.begin_ping().is_err() {
                    close_with(
                        &mut sender,
                        CLOSE_POLICY_VIOLATION,
                        "relay_watch_heartbeat_timeout",
                        config.write_timeout,
                    )
                    .await;
                    bail!("WebSocket heartbeat timed out");
                }
                send_message(
                    &mut sender,
                    Message::Ping(Vec::new().into()),
                    config.write_timeout,
                )
                .await?;
            }
            _ = replay_safety.tick() => {
                replay_pending = drain_replay(
                    &mut sender,
                    &application,
                    principal,
                    route,
                    limit,
                    &mut cursor,
                    false,
                    config.write_timeout,
                )
                .await?;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    close_with(
                        &mut sender,
                        CLOSE_GOING_AWAY,
                        "relay_shutdown",
                        config.write_timeout,
                    )
                    .await;
                    return Ok(());
                }
            }
        }
    }
}

async fn receive_replay_request(
    sender: &mut SplitSink<WebSocket, Message>,
    receiver: &mut SplitStream<WebSocket>,
    shutdown: &mut watch::Receiver<bool>,
    config: SessionConfig,
) -> anyhow::Result<Option<ReplayRequest>> {
    let handshake = async {
        loop {
            tokio::select! {
                message = receiver.next() => {
                    match message {
                        Some(Ok(Message::Binary(bytes))) => {
                            return match decode_replay_request(&bytes) {
                                Ok(request) => Ok(Some(request)),
                                Err(error) => {
                                    close_with(
                                        sender,
                                        CLOSE_PROTOCOL_ERROR,
                                        error.code(),
                                        config.write_timeout,
                                    )
                                    .await;
                                    Err(error).context("decoding WebSocket replay request")
                                }
                            };
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            send_message(
                                sender,
                                Message::Pong(payload),
                                config.write_timeout,
                            )
                            .await?;
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close(_))) | None => return Ok(None),
                        Some(Ok(Message::Text(_))) => {
                            close_with(
                                sender,
                                CLOSE_PROTOCOL_ERROR,
                                "relay_watch_binary_required",
                                config.write_timeout,
                            )
                            .await;
                            bail!("WebSocket watch initialization requires binary protobuf");
                        }
                        Some(Err(error)) => return Err(error.into()),
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(None);
                    }
                }
            }
        }
    };

    match timeout(config.handshake_timeout, handshake).await {
        Ok(result) => result,
        Err(_) => {
            close_with(
                sender,
                CLOSE_POLICY_VIOLATION,
                "relay_watch_handshake_timeout",
                config.write_timeout,
            )
            .await;
            bail!("WebSocket watch initialization timed out");
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the replay loop keeps authorization, route, cursor, and I/O bounds explicit"
)]
async fn drain_replay(
    sender: &mut SplitSink<WebSocket, Message>,
    application: &RelayApplication,
    principal: RelayPrincipalId,
    route: RoutingId,
    limit: u32,
    cursor: &mut u64,
    send_empty: bool,
    write_timeout: Duration,
) -> anyhow::Result<bool> {
    let request = ReplayRequest::new(route, *cursor, limit)?;
    let page = match application.replay_encoded(principal, request).await {
        Ok(page) => page,
        Err(error) => {
            close_with(
                sender,
                close_code_for_relay_error(&error),
                error.code(),
                write_timeout,
            )
            .await;
            return Err(error).context("loading WebSocket replay page");
        }
    };
    let next_cursor = page.next_cursor();
    let has_more = page.has_more();
    let envelope_count = page.envelope_count();
    if envelope_count > 0 || send_empty {
        send_message(
            sender,
            Message::Binary(page.into_bytes().into()),
            write_timeout,
        )
        .await?;
    }
    if (envelope_count == 0 && next_cursor != *cursor)
        || (envelope_count > 0 && next_cursor <= *cursor)
    {
        bail!("WebSocket replay returned an invalid cursor transition");
    }
    *cursor = next_cursor;
    Ok(has_more)
}

const fn close_code_for_relay_error(error: &RelayError) -> u16 {
    match error {
        RelayError::Unauthorized => CLOSE_POLICY_VIOLATION,
        _ => CLOSE_INTERNAL_ERROR,
    }
}

async fn send_message(
    sender: &mut SplitSink<WebSocket, Message>,
    message: Message,
    write_timeout: Duration,
) -> anyhow::Result<()> {
    timeout(write_timeout, sender.send(message))
        .await
        .context("WebSocket write timed out")?
        .context("writing WebSocket message")
}

async fn close_with(
    sender: &mut SplitSink<WebSocket, Message>,
    code: u16,
    reason: &'static str,
    write_timeout: Duration,
) {
    let _ = timeout(
        write_timeout,
        sender.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))),
    )
    .await;
}

#[derive(Clone, Copy)]
pub(crate) struct SessionConfig {
    handshake_timeout: Duration,
    write_timeout: Duration,
    ping_interval: Duration,
    replay_safety_interval: Duration,
}

impl SessionConfig {
    pub(crate) fn new(
        handshake_timeout: Duration,
        write_timeout: Duration,
        ping_interval: Duration,
        replay_safety_interval: Duration,
    ) -> anyhow::Result<Self> {
        if handshake_timeout.is_zero()
            || write_timeout.is_zero()
            || ping_interval.is_zero()
            || replay_safety_interval.is_zero()
        {
            bail!("WebSocket session timeouts must be positive");
        }
        Ok(Self {
            handshake_timeout,
            write_timeout,
            ping_interval,
            replay_safety_interval,
        })
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: HANDSHAKE_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
            ping_interval: PING_INTERVAL,
            replay_safety_interval: REPLAY_SAFETY_INTERVAL,
        }
    }
}

#[derive(Default)]
struct HeartbeatState {
    awaiting_pong: bool,
}

impl HeartbeatState {
    fn begin_ping(&mut self) -> Result<(), ()> {
        if self.awaiting_pong {
            Err(())
        } else {
            self.awaiting_pong = true;
            Ok(())
        }
    }

    const fn observe_pong(&mut self) {
        self.awaiting_pong = false;
    }
}

#[cfg(test)]
mod tests {
    use super::HeartbeatState;

    #[test]
    fn heartbeat_requires_a_pong_before_the_next_ping() {
        let mut heartbeat = HeartbeatState::default();
        assert!(heartbeat.begin_ping().is_ok());
        assert!(heartbeat.begin_ping().is_err());
        heartbeat.observe_pong();
        assert!(heartbeat.begin_ping().is_ok());
    }
}
