mod support;

use std::net::SocketAddr;
use std::time::Duration;

use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveDomainCore::{
    DeliveryClass, EnvelopeId, ProtocolVersion, RelayEnvelope, ReplayRequest, RoutingId,
};
use KonclaveProtocolContracts::v1::{
    decode_replay_page, encode_relay_envelope, encode_replay_request,
};
use KonclaveRelayCore::{RelayPrincipalId, SubmitResult};
use axum::http::HeaderValue;
use axum::http::header::AUTHORIZATION;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

use support::TestRelay;

async fn start_server(relay: &TestRelay) -> (SocketAddr, watch::Sender<bool>, JoinHandle<()>) {
    start_server_with_timing(relay, None).await
}

async fn start_server_with_timing(
    relay: &TestRelay,
    timing: Option<(Duration, Duration, Duration, Duration)>,
) -> (SocketAddr, watch::Sender<bool>, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let application = relay.application.clone();
    let access = relay.access.clone();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        let mut state = HttpState::new(env!("CARGO_PKG_NAME"), application);
        if let Some((handshake, write, ping, replay_safety)) = timing {
            state = state
                .with_watch_timing(handshake, write, ping, replay_safety)
                .unwrap();
        }
        axum::serve(listener, router(state, access, shutdown_rx.clone()))
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
    (address, shutdown_tx, server)
}

async fn connect(
    address: SocketAddr,
    token: &[u8; RelayPrincipalId::LENGTH],
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", URL_SAFE_NO_PAD.encode(token))).unwrap(),
    );
    connect_async(request).await.unwrap().0
}

async fn next_binary(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Vec<u8> {
    loop {
        let message = timeout(Duration::from_secs(1), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match message {
            Message::Binary(bytes) => return bytes.to_vec(),
            Message::Ping(payload) => client.send(Message::Pong(payload)).await.unwrap(),
            Message::Close(frame) => panic!("unexpected close frame: {frame:?}"),
            Message::Text(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
}

fn envelope(route: RoutingId, id: u8, payload: u8) -> RelayEnvelope {
    RelayEnvelope::new(
        ProtocolVersion::application_v1(),
        route,
        EnvelopeId::from_bytes([id; EnvelopeId::LENGTH]),
        DeliveryClass::GroupApplication,
        None,
        u64::MAX / 2,
        vec![payload],
    )
    .unwrap()
}

async fn submit(
    application: &RelayApplication,
    token: &[u8; RelayPrincipalId::LENGTH],
    envelope: &RelayEnvelope,
) -> SubmitResult {
    application
        .submit_encoded(
            RelayPrincipalId::from_access_token(token),
            &encode_relay_envelope(envelope).unwrap(),
        )
        .await
        .unwrap()
}

async fn stop_server(shutdown: watch::Sender<bool>, server: JoinHandle<()>) {
    shutdown.send(true).unwrap();
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn authenticated_websocket_replies_to_ping_and_shuts_down() {
    let relay = TestRelay::new(true).await;
    let (address, shutdown, server) = start_server(&relay).await;
    let mut client = connect(address, &relay.token).await;

    client.send(Message::Ping(Vec::new().into())).await.unwrap();
    let response = timeout(Duration::from_secs(1), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(response, Message::Pong(_)));

    client.close(None).await.unwrap();
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_replays_then_pushes_and_recovers_missed_envelopes() {
    let relay = TestRelay::new(true).await;
    let (address, shutdown, server) = start_server(&relay).await;
    let mut client = connect(address, &relay.token).await;
    client
        .send(Message::Binary(
            encode_replay_request(ReplayRequest::new(relay.route, 0, 100).unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    let initial = decode_replay_page(&next_binary(&mut client).await).unwrap();
    assert!(initial.envelopes().is_empty());
    assert_eq!(initial.next_cursor(), 0);

    let first = envelope(relay.route, 21, 1);
    assert_eq!(
        submit(&relay.application, &relay.token, &first).await,
        SubmitResult::new(1, false)
    );
    let pushed = decode_replay_page(&next_binary(&mut client).await).unwrap();
    assert_eq!(pushed.envelopes().len(), 1);
    assert_eq!(pushed.next_cursor(), 1);

    client.close(None).await.unwrap();
    let second = envelope(relay.route, 22, 2);
    assert_eq!(
        submit(&relay.application, &relay.token, &second).await,
        SubmitResult::new(2, false)
    );

    let mut reconnected = connect(address, &relay.token).await;
    reconnected
        .send(Message::Binary(
            encode_replay_request(ReplayRequest::new(relay.route, 1, 100).unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    let missed = decode_replay_page(&next_binary(&mut reconnected).await).unwrap();
    assert_eq!(missed.envelopes().len(), 1);
    assert_eq!(missed.next_cursor(), 2);
    assert_eq!(missed.envelopes()[0].envelope().payload(), &[2]);

    reconnected.close(None).await.unwrap();
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_catch_up_sends_bounded_pages_until_current() {
    let relay = TestRelay::new(true).await;
    assert_eq!(
        submit(
            &relay.application,
            &relay.token,
            &envelope(relay.route, 24, 4)
        )
        .await,
        SubmitResult::new(1, false)
    );
    assert_eq!(
        submit(
            &relay.application,
            &relay.token,
            &envelope(relay.route, 25, 5)
        )
        .await,
        SubmitResult::new(2, false)
    );
    let (address, shutdown, server) = start_server(&relay).await;
    let mut client = connect(address, &relay.token).await;
    client
        .send(Message::Binary(
            encode_replay_request(ReplayRequest::new(relay.route, 0, 1).unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();

    let first = decode_replay_page(&next_binary(&mut client).await).unwrap();
    assert_eq!(first.envelopes().len(), 1);
    assert_eq!(first.next_cursor(), 1);
    assert!(first.has_more());
    let second = decode_replay_page(&next_binary(&mut client).await).unwrap();
    assert_eq!(second.envelopes().len(), 1);
    assert_eq!(second.next_cursor(), 2);
    assert!(!second.has_more());

    client.close(None).await.unwrap();
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_upgrade_rejects_missing_authentication() {
    let relay = TestRelay::new(true).await;
    let (address, shutdown, server) = start_server(&relay).await;
    let error = connect_async(format!("ws://{address}/ws"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        WebSocketError::Http(response) if response.status() == 401
    ));
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_watch_rejects_unauthorized_routes() {
    let relay = TestRelay::new(false).await;
    let (address, shutdown, server) = start_server(&relay).await;
    let mut client = connect(address, &relay.token).await;
    client
        .send(Message::Binary(
            encode_replay_request(
                ReplayRequest::new(RoutingId::from_bytes([4; RoutingId::LENGTH]), 0, 100).unwrap(),
            )
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let message = timeout(Duration::from_secs(1), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        message,
        Message::Close(Some(frame))
            if frame.code == CloseCode::Policy && frame.reason == "relay_unauthorized"
    ));
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_watch_rejects_malformed_initial_frames() {
    let relay = TestRelay::new(true).await;
    let (address, shutdown, server) = start_server(&relay).await;
    let mut client = connect(address, &relay.token).await;
    client
        .send(Message::Binary(vec![0xff].into()))
        .await
        .unwrap();
    let message = timeout(Duration::from_secs(1), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        message,
        Message::Close(Some(frame))
            if frame.code == CloseCode::Protocol && frame.reason == "malformed"
    ));
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_safety_replay_recovers_a_notification_from_another_instance() {
    let relay = TestRelay::new(true).await;
    let external_application =
        RelayApplication::connect(&relay.database_path, relay.access.clone())
            .await
            .unwrap();
    let (address, shutdown, server) = start_server_with_timing(
        &relay,
        Some((
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(25),
        )),
    )
    .await;
    let mut client = connect(address, &relay.token).await;
    client
        .send(Message::Binary(
            encode_replay_request(ReplayRequest::new(relay.route, 0, 100).unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    assert!(
        decode_replay_page(&next_binary(&mut client).await)
            .unwrap()
            .envelopes()
            .is_empty()
    );

    let missed_notification = envelope(relay.route, 23, 3);
    assert_eq!(
        submit(&external_application, &relay.token, &missed_notification).await,
        SubmitResult::new(1, false)
    );
    let recovered = decode_replay_page(&next_binary(&mut client).await).unwrap();
    assert_eq!(recovered.next_cursor(), 1);
    assert_eq!(recovered.envelopes()[0].envelope().payload(), &[3]);

    client.close(None).await.unwrap();
    stop_server(shutdown, server).await;
}

#[tokio::test]
async fn websocket_heartbeat_closes_a_session_that_does_not_pong() {
    let relay = TestRelay::new(true).await;
    let (address, shutdown, server) = start_server_with_timing(
        &relay,
        Some((
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(25),
            Duration::from_secs(1),
        )),
    )
    .await;
    let mut client = connect(address, &relay.token).await;
    client
        .send(Message::Binary(
            encode_replay_request(ReplayRequest::new(relay.route, 0, 100).unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    assert!(
        decode_replay_page(&next_binary(&mut client).await)
            .unwrap()
            .envelopes()
            .is_empty()
    );

    tokio::time::sleep(Duration::from_millis(80)).await;
    loop {
        let message = timeout(Duration::from_secs(1), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Close(Some(frame)) = message {
            assert_eq!(frame.code, CloseCode::Policy);
            assert_eq!(frame.reason, "relay_watch_heartbeat_timeout");
            break;
        }
    }
    stop_server(shutdown, server).await;
}
