mod support;

use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, EnvelopeId, MAX_RELAY_ENVELOPE_BYTES, ProtocolVersion,
    RelayEnvelope, ReplayRequest, RoutingId,
};
use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_replay_page, decode_stored_relay_envelope,
    encode_acknowledge_request, encode_relay_envelope, encode_replay_request,
};
use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tower::util::ServiceExt;

use support::TestRelay;

const PROTOBUF_MEDIA_TYPE: &str = "application/protobuf";

fn envelope(route: RoutingId) -> RelayEnvelope {
    RelayEnvelope::new(
        ProtocolVersion::application_v1(),
        route,
        EnvelopeId::from_bytes([9; EnvelopeId::LENGTH]),
        DeliveryClass::GroupApplication,
        None,
        u64::MAX / 2,
        vec![1, 2, 3],
    )
    .unwrap()
}

fn protobuf_request(uri: &str, body: Vec<u8>, token: Option<&[u8]>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, PROTOBUF_MEDIA_TYPE);
    if let Some(token) = token {
        builder = builder.header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", URL_SAFE_NO_PAD.encode(token))).unwrap(),
        );
    }
    builder.body(Body::from(body)).unwrap()
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), MAX_RELAY_ENVELOPE_BYTES * 16)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn health_endpoint_is_public_but_relay_operations_require_authentication() {
    let relay = TestRelay::new(true).await;
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let unauthorized = app
        .oneshot(protobuf_request(
            "/v1/envelopes",
            vec![0; MAX_RELAY_ENVELOPE_BYTES + 1],
            None,
        ))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized.headers().get("x-konclave-error-code").unwrap(),
        "relay_authentication_failed"
    );
}

#[tokio::test]
async fn submit_retry_replay_and_acknowledge_use_bounded_protobuf_contracts() {
    let relay = TestRelay::new(true).await;
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    let envelope = envelope(relay.route);
    let mut encoded_envelope = encode_relay_envelope(&envelope).unwrap();
    encoded_envelope.extend_from_slice(&[0xa0, 0x06, 0x07]);

    let accepted = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/envelopes",
            encoded_envelope.clone(),
            Some(&relay.token),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::CREATED);
    assert_eq!(
        accepted.headers().get(CONTENT_TYPE).unwrap(),
        PROTOBUF_MEDIA_TYPE
    );
    let accepted_bytes = response_bytes(accepted).await;
    assert!(
        accepted_bytes
            .windows(encoded_envelope.len())
            .any(|window| window == encoded_envelope)
    );
    assert_eq!(
        decode_stored_relay_envelope(&accepted_bytes)
            .unwrap()
            .cursor(),
        1
    );

    let duplicate = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/envelopes",
            encoded_envelope.clone(),
            Some(&relay.token),
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    assert_eq!(
        decode_stored_relay_envelope(&response_bytes(duplicate).await)
            .unwrap()
            .cursor(),
        1
    );

    let replay_request = ReplayRequest::new(relay.route, 0, 100).unwrap();
    let replay = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/replay",
            encode_replay_request(replay_request).unwrap(),
            Some(&relay.token),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_bytes = response_bytes(replay).await;
    assert!(
        replay_bytes
            .windows(encoded_envelope.len())
            .any(|window| window == encoded_envelope)
    );
    let page = decode_replay_page(&replay_bytes).unwrap();
    assert_eq!(page.envelopes().len(), 1);
    assert_eq!(page.next_cursor(), 1);

    let acknowledgment = app
        .oneshot(protobuf_request(
            "/v1/acknowledgments",
            encode_acknowledge_request(AcknowledgeRequest::new(relay.route, 1).unwrap()).unwrap(),
            Some(&relay.token),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledgment.status(), StatusCode::OK);
    assert_eq!(
        decode_acknowledge_request(&response_bytes(acknowledgment).await)
            .unwrap()
            .cursor(),
        1
    );
}

#[tokio::test]
async fn route_grants_content_type_and_body_bounds_fail_closed() {
    let relay = TestRelay::new(false).await;
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );

    let forbidden = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/envelopes",
            encode_relay_envelope(&envelope(RoutingId::from_bytes([4; RoutingId::LENGTH])))
                .unwrap(),
            Some(&relay.token),
        ))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        forbidden.headers().get("x-konclave-error-code").unwrap(),
        "relay_unauthorized"
    );

    let unsupported = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/replay")
                .header(
                    AUTHORIZATION,
                    format!("Bearer {}", URL_SAFE_NO_PAD.encode(relay.token)),
                )
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        unsupported.headers().get("x-konclave-error-code").unwrap(),
        "unsupported_media_type"
    );

    let oversized = app
        .oneshot(protobuf_request(
            "/v1/envelopes",
            vec![0; MAX_RELAY_ENVELOPE_BYTES + 1],
            Some(&relay.token),
        ))
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        oversized.headers().get("x-konclave-error-code").unwrap(),
        "encoded_message_too_large"
    );
}
