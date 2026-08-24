mod support;

use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, EnvelopeId, MAX_RELAY_ENVELOPE_BYTES, ProtocolVersion,
    RelayEnvelope, ReplayRequest, RoutingId,
};
use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_relay_enrollment_response, decode_replay_page,
    decode_stored_relay_envelope, encode_acknowledge_request, encode_relay_enrollment_request,
    encode_relay_envelope, encode_replay_request,
};
use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayPrincipalId,
};
use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tower::util::ServiceExt;

use support::TestRelay;

const PROTOBUF_MEDIA_TYPE: &str = "application/protobuf";
const ENROLLMENT_RATE_REQUESTS: u32 = 16;

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

#[tokio::test]
async fn enrollment_authenticates_before_bounded_body_processing() {
    let relay = TestRelay::with_enrollment(true).await;
    let enrollment_token = relay.enrollment_token.unwrap();
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    let oversized = vec![0; KonclaveDomainCore::MAX_RELAY_CONTROL_MESSAGE_BYTES + 1];
    let missing = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            oversized.clone(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let wrong = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            oversized.clone(),
            Some(&[5; RelayPrincipalId::LENGTH]),
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let authorized = app
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            oversized,
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn enrollment_registers_one_digest_and_enables_its_data_token() {
    let relay = TestRelay::with_enrollment(true).await;
    let database_path = relay.database_path.clone();
    let enrollment_token = relay.enrollment_token.unwrap();
    let application = relay.application.clone();
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    let data_token = [21_u8; RelayPrincipalId::LENGTH];
    let request = RelayEnrollmentRequest::new(
        ProtocolVersion::application_v1(),
        EnrollmentRequestId::from_bytes([22; EnrollmentRequestId::LENGTH]),
        RelayPrincipalId::from_access_token(&data_token),
    );
    let encoded = encode_relay_enrollment_request(&request).unwrap();
    let registered = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            encoded.clone(),
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered = decode_relay_enrollment_response(&response_bytes(registered).await).unwrap();
    assert_eq!(registered.request_id(), request.request_id());
    assert_eq!(registered.principal_id(), request.principal_id());
    assert_eq!(registered.outcome(), RelayEnrollmentOutcome::Registered);

    let duplicate = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            encoded,
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    assert_eq!(
        decode_relay_enrollment_response(&response_bytes(duplicate).await)
            .unwrap()
            .outcome(),
        RelayEnrollmentOutcome::AlreadyRegistered
    );
    let conflict = RelayEnrollmentRequest::new(
        request.version(),
        request.request_id(),
        RelayPrincipalId::from_bytes([27; RelayPrincipalId::LENGTH]),
    );
    let conflict = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            encode_relay_enrollment_request(&conflict).unwrap(),
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        conflict.headers().get("x-konclave-error-code").unwrap(),
        "relay_enrollment_conflict"
    );

    let accepted = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/envelopes",
            encode_relay_envelope(&envelope(RoutingId::from_bytes([23; RoutingId::LENGTH])))
                .unwrap(),
            Some(&data_token),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let authority_as_data_token = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/envelopes",
            encode_relay_envelope(&envelope(RoutingId::from_bytes([24; RoutingId::LENGTH])))
                .unwrap(),
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(authority_as_data_token.status(), StatusCode::UNAUTHORIZED);
    assert!(
        application
            .revoke_principal(request.principal_id())
            .await
            .unwrap()
    );
    let revoked_enrollment = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            encode_relay_enrollment_request(&request).unwrap(),
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(revoked_enrollment.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        revoked_enrollment
            .headers()
            .get("x-konclave-error-code")
            .unwrap(),
        "relay_principal_revoked"
    );
    let revoked = app
        .oneshot(protobuf_request(
            "/v1/envelopes",
            encode_relay_envelope(&envelope(RoutingId::from_bytes([28; RoutingId::LENGTH])))
                .unwrap(),
            Some(&data_token),
        ))
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);

    for entry in std::fs::read_dir(database_path.parent().unwrap()).unwrap() {
        let path = entry.unwrap().path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("relay.sqlite"))
        {
            continue;
        }
        let bytes = std::fs::read(path).unwrap();
        for secret in [&data_token[..], &enrollment_token[..]] {
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
    }
}

#[tokio::test]
async fn enrollment_rate_limit_is_bounded_and_stable() {
    let relay = TestRelay::with_enrollment(true).await;
    let enrollment_token = relay.enrollment_token.unwrap();
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    let request = RelayEnrollmentRequest::new(
        ProtocolVersion::application_v1(),
        EnrollmentRequestId::from_bytes([25; EnrollmentRequestId::LENGTH]),
        RelayPrincipalId::from_bytes([26; RelayPrincipalId::LENGTH]),
    );
    let encoded = encode_relay_enrollment_request(&request).unwrap();
    for index in 0..ENROLLMENT_RATE_REQUESTS {
        let response = app
            .clone()
            .oneshot(protobuf_request(
                "/v1/enrollment/principals",
                encoded.clone(),
                Some(&enrollment_token),
            ))
            .await
            .unwrap();
        assert!(
            matches!(response.status(), StatusCode::CREATED | StatusCode::OK),
            "request {index} was unexpectedly rejected"
        );
    }
    let limited = app
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            encoded,
            Some(&enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.headers().get("x-konclave-error-code").unwrap(),
        "relay_enrollment_rate_limited"
    );
}
