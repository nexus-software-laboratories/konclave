mod support;

use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, EnvelopeId, MAX_RELAY_ENVELOPE_BYTES, PairingRendezvousId,
    PairingRendezvousNonce, PairingRendezvousRecord, PairingRendezvousTakeRequest, ProtocolVersion,
    RelayEnvelope, ReplayRequest, RoutingId, ShortCodeAttemptClaimRequest,
    ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest,
    ShortCodePairingAttemptId, ShortCodePairingLocator, ShortCodeRelayStage,
};
use KonclaveProtocolContracts::v1::{
    decode_acknowledge_request, decode_pairing_rendezvous_record, decode_relay_enrollment_response,
    decode_replay_page, decode_short_code_attempt_snapshot, decode_short_code_capability_response,
    decode_stored_relay_envelope, encode_acknowledge_request, encode_pairing_rendezvous_record,
    encode_pairing_rendezvous_take_request, encode_relay_enrollment_request, encode_relay_envelope,
    encode_replay_request, encode_short_code_attempt_claim_request,
    encode_short_code_attempt_message_request, encode_short_code_attempt_publish_request,
    encode_short_code_attempt_read_request,
};
use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayPrincipalId,
};
use KonclaveRelayCore::{PairingRendezvousRepository, SqliteRelayRepository};
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

fn pairing_rendezvous(id: u8, ciphertext: u8, expires_at: u64) -> PairingRendezvousRecord {
    PairingRendezvousRecord::new(
        ProtocolVersion::application_v1(),
        PairingRendezvousId::from_bytes([id; 32]),
        expires_at,
        PairingRendezvousNonce::from_bytes([id.wrapping_add(1); 12]),
        vec![ciphertext; 32],
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

fn short_code_attempt(
    locator: u8,
    attempt: u8,
    deadline_unix_seconds: u64,
) -> ShortCodeAttemptPublishRequest {
    ShortCodeAttemptPublishRequest::new(
        ProtocolVersion::application_v1(),
        ShortCodePairingLocator::from_bytes([locator; ShortCodePairingLocator::LENGTH]),
        ShortCodePairingAttemptId::from_bytes([attempt; ShortCodePairingAttemptId::LENGTH]),
        deadline_unix_seconds,
    )
    .unwrap()
}

fn short_code_message(
    attempt_id: ShortCodePairingAttemptId,
    stage: ShortCodeRelayStage,
) -> ShortCodeAttemptMessageRequest {
    ShortCodeAttemptMessageRequest::new(
        ProtocolVersion::application_v1(),
        attempt_id,
        stage,
        vec![stage as u8],
    )
    .unwrap()
}

async fn enroll_data_token(
    app: &axum::Router,
    enrollment_token: &[u8],
    data_token: &[u8; RelayPrincipalId::LENGTH],
    request_id: u8,
) {
    let request = RelayEnrollmentRequest::new(
        ProtocolVersion::application_v1(),
        EnrollmentRequestId::from_bytes([request_id; EnrollmentRequestId::LENGTH]),
        RelayPrincipalId::from_access_token(data_token),
    );
    let response = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/enrollment/principals",
            encode_relay_enrollment_request(&request).unwrap(),
            Some(enrollment_token),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
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
async fn pairing_rendezvous_publish_and_take_are_authenticated_one_time_operations() {
    let relay = TestRelay::new(true).await;
    let database_path = relay.database_path.clone();
    let token = relay.token;
    let principal = RelayPrincipalId::from_access_token(&token);
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    let record = pairing_rendezvous(31, 32, u64::MAX / 2);
    let encoded = encode_pairing_rendezvous_record(&record).unwrap();

    let unauthenticated = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous",
            vec![0; KonclaveDomainCore::MAX_RELAY_CONTROL_MESSAGE_BYTES + 1],
            None,
        ))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let published = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous",
            encoded.clone(),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(published.status(), StatusCode::CREATED);
    let duplicate = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous",
            encoded,
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    let conflict = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous",
            encode_pairing_rendezvous_record(&pairing_rendezvous(31, 33, u64::MAX / 2)).unwrap(),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        conflict.headers().get("x-konclave-error-code").unwrap(),
        "relay_pairing_rendezvous_conflict"
    );

    let take =
        PairingRendezvousTakeRequest::new(ProtocolVersion::application_v1(), record.lookup_id());
    let taken = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous/take",
            encode_pairing_rendezvous_take_request(take).unwrap(),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(taken.status(), StatusCode::OK);
    assert_eq!(
        taken.headers().get(CONTENT_TYPE).unwrap(),
        PROTOBUF_MEDIA_TYPE
    );
    let taken = decode_pairing_rendezvous_record(&response_bytes(taken).await).unwrap();
    assert_eq!(taken.lookup_id(), record.lookup_id());
    assert_eq!(taken.ciphertext(), record.ciphertext());

    let consumed = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous/take",
            encode_pairing_rendezvous_take_request(take).unwrap(),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(consumed.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        consumed.headers().get("x-konclave-error-code").unwrap(),
        "relay_pairing_rendezvous_unavailable"
    );

    let repository = SqliteRelayRepository::connect(&database_path)
        .await
        .unwrap();
    repository
        .publish_pairing_rendezvous(principal, pairing_rendezvous(34, 35, 2), 1)
        .await
        .unwrap();
    let expired_take = PairingRendezvousTakeRequest::new(
        ProtocolVersion::application_v1(),
        PairingRendezvousId::from_bytes([34; 32]),
    );
    let expired = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous/take",
            encode_pairing_rendezvous_take_request(expired_take).unwrap(),
            Some(&token),
        ))
        .await
        .unwrap();
    let unknown_take = PairingRendezvousTakeRequest::new(
        ProtocolVersion::application_v1(),
        PairingRendezvousId::from_bytes([36; 32]),
    );
    let unknown = app
        .oneshot(protobuf_request(
            "/v1/pairing-rendezvous/take",
            encode_pairing_rendezvous_take_request(unknown_take).unwrap(),
            Some(&token),
        ))
        .await
        .unwrap();
    for response in [expired, unknown] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("x-konclave-error-code").unwrap(),
            "relay_pairing_rendezvous_unavailable"
        );
    }
}

#[tokio::test]
async fn short_code_pairing_enforces_roles_order_isolation_rates_and_one_time_capability() {
    let relay = TestRelay::with_enrollment(true).await;
    let creator_token = relay.token;
    let enrollment_token = relay.enrollment_token.unwrap();
    let claimant_token = [31_u8; RelayPrincipalId::LENGTH];
    let observer_token = [32_u8; RelayPrincipalId::LENGTH];
    let rate_limited_token = [33_u8; RelayPrincipalId::LENGTH];
    let app = router(
        HttpState::new(env!("CARGO_PKG_NAME"), relay.application),
        relay.access,
        tokio::sync::watch::channel(false).1,
    );
    enroll_data_token(&app, &enrollment_token, &claimant_token, 41).await;
    enroll_data_token(&app, &enrollment_token, &observer_token, 42).await;
    enroll_data_token(&app, &enrollment_token, &rate_limited_token, 43).await;

    let unauthenticated = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            vec![0; KonclaveDomainCore::MAX_SHORT_CODE_RELAY_MESSAGE_BYTES + 1],
            None,
        ))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let expired = short_code_attempt(51, 61, 1);
    let expired = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            encode_short_code_attempt_publish_request(expired).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::GONE);

    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let excessive = short_code_attempt(54, 64, deadline + 600);
    let excessive = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            encode_short_code_attempt_publish_request(excessive).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(excessive.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let publish = short_code_attempt(52, 62, deadline);
    let encoded_publish = encode_short_code_attempt_publish_request(publish).unwrap();
    let published = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            encoded_publish.clone(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(published.status(), StatusCode::CREATED);
    let duplicate = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            encoded_publish.clone(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    let conflicting_owner = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            encoded_publish,
            Some(&claimant_token),
        ))
        .await
        .unwrap();
    assert_eq!(conflicting_owner.status(), StatusCode::CONFLICT);

    let claim = ShortCodeAttemptClaimRequest::new(
        ProtocolVersion::application_v1(),
        publish.locator(),
        vec![71],
    )
    .unwrap();
    let creator_cannot_claim = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/claim",
            encode_short_code_attempt_claim_request(&claim).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(creator_cannot_claim.status(), StatusCode::NOT_FOUND);
    let claimed = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/claim",
            encode_short_code_attempt_claim_request(&claim).unwrap(),
            Some(&claimant_token),
        ))
        .await
        .unwrap();
    assert_eq!(claimed.status(), StatusCode::OK);
    let claimed = decode_short_code_attempt_snapshot(&response_bytes(claimed).await).unwrap();
    assert_eq!(
        claimed.message(ShortCodeRelayStage::CredentialRequest),
        Some(&[71][..])
    );
    let claim_race_loser = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/claim",
            encode_short_code_attempt_claim_request(&claim).unwrap(),
            Some(&observer_token),
        ))
        .await
        .unwrap();
    assert_eq!(claim_race_loser.status(), StatusCode::NOT_FOUND);
    let isolated = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/read",
            encode_short_code_attempt_read_request(ShortCodeAttemptReadRequest::new(
                ProtocolVersion::application_v1(),
                publish.attempt_id(),
            ))
            .unwrap(),
            Some(&observer_token),
        ))
        .await
        .unwrap();
    assert_eq!(isolated.status(), StatusCode::NOT_FOUND);

    let out_of_order = short_code_message(publish.attempt_id(), ShortCodeRelayStage::Capability);
    let out_of_order = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/messages",
            encode_short_code_attempt_message_request(&out_of_order).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(out_of_order.status(), StatusCode::CONFLICT);
    let wrong_role = short_code_message(
        publish.attempt_id(),
        ShortCodeRelayStage::CredentialResponse,
    );
    let wrong_role = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/messages",
            encode_short_code_attempt_message_request(&wrong_role).unwrap(),
            Some(&claimant_token),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_role.status(), StatusCode::CONFLICT);

    for (stage, token) in [
        (ShortCodeRelayStage::CredentialResponse, &creator_token[..]),
        (
            ShortCodeRelayStage::ClaimantFinalization,
            &claimant_token[..],
        ),
        (ShortCodeRelayStage::CreatorIdentity, &creator_token[..]),
        (
            ShortCodeRelayStage::ClaimantConfirmation,
            &claimant_token[..],
        ),
        (ShortCodeRelayStage::CreatorConfirmation, &creator_token[..]),
    ] {
        let message = short_code_message(publish.attempt_id(), stage);
        let encoded = encode_short_code_attempt_message_request(&message).unwrap();
        let response = app
            .clone()
            .oneshot(protobuf_request(
                "/v1/short-code-attempts/messages",
                encoded.clone(),
                Some(token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        if stage == ShortCodeRelayStage::CredentialResponse {
            let duplicate = app
                .clone()
                .oneshot(protobuf_request(
                    "/v1/short-code-attempts/messages",
                    encoded,
                    Some(token),
                ))
                .await
                .unwrap();
            assert_eq!(duplicate.status(), StatusCode::OK);
        }
    }

    let capability = short_code_message(publish.attempt_id(), ShortCodeRelayStage::Capability);
    let capability_payload = capability.payload().to_vec();
    let capability = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/messages",
            encode_short_code_attempt_message_request(&capability).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(capability.status(), StatusCode::CREATED);

    for token in [&creator_token[..], &claimant_token[..]] {
        let snapshot = app
            .clone()
            .oneshot(protobuf_request(
                "/v1/short-code-attempts/read",
                encode_short_code_attempt_read_request(ShortCodeAttemptReadRequest::new(
                    ProtocolVersion::application_v1(),
                    publish.attempt_id(),
                ))
                .unwrap(),
                Some(token),
            ))
            .await
            .unwrap();
        assert_eq!(snapshot.status(), StatusCode::OK);
        let snapshot = decode_short_code_attempt_snapshot(&response_bytes(snapshot).await).unwrap();
        assert_eq!(snapshot.messages().len(), 6);
        assert!(snapshot.message(ShortCodeRelayStage::Capability).is_none());
    }

    let take_request =
        ShortCodeAttemptReadRequest::new(ProtocolVersion::application_v1(), publish.attempt_id());
    let creator_take = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/capability/take",
            encode_short_code_attempt_read_request(take_request).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(creator_take.status(), StatusCode::NOT_FOUND);
    let claimant_take = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/capability/take",
            encode_short_code_attempt_read_request(take_request).unwrap(),
            Some(&claimant_token),
        ))
        .await
        .unwrap();
    assert_eq!(claimant_take.status(), StatusCode::OK);
    let (version, attempt_id, payload) =
        decode_short_code_capability_response(&response_bytes(claimant_take).await).unwrap();
    assert_eq!(version, ProtocolVersion::application_v1());
    assert_eq!(attempt_id, publish.attempt_id());
    assert_eq!(payload, capability_payload);
    let consumed = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/capability/take",
            encode_short_code_attempt_read_request(take_request).unwrap(),
            Some(&claimant_token),
        ))
        .await
        .unwrap();
    assert_eq!(consumed.status(), StatusCode::NOT_FOUND);

    let cancellable = short_code_attempt(53, 63, deadline);
    let publish_cancellable = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts",
            encode_short_code_attempt_publish_request(cancellable).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(publish_cancellable.status(), StatusCode::CREATED);
    let cancellation_claim = ShortCodeAttemptClaimRequest::new(
        ProtocolVersion::application_v1(),
        cancellable.locator(),
        vec![72],
    )
    .unwrap();
    let cancellation_claim = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/claim",
            encode_short_code_attempt_claim_request(&cancellation_claim).unwrap(),
            Some(&observer_token),
        ))
        .await
        .unwrap();
    assert_eq!(cancellation_claim.status(), StatusCode::OK);
    let cancel_request = ShortCodeAttemptReadRequest::new(
        ProtocolVersion::application_v1(),
        cancellable.attempt_id(),
    );
    for _ in 0..2 {
        let cancelled = app
            .clone()
            .oneshot(protobuf_request(
                "/v1/short-code-attempts/cancel",
                encode_short_code_attempt_read_request(cancel_request).unwrap(),
                Some(&observer_token),
            ))
            .await
            .unwrap();
        assert_eq!(cancelled.status(), StatusCode::OK);
    }
    let cancelled_read = app
        .clone()
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/read",
            encode_short_code_attempt_read_request(cancel_request).unwrap(),
            Some(&creator_token),
        ))
        .await
        .unwrap();
    assert_eq!(cancelled_read.status(), StatusCode::NOT_FOUND);

    for locator in 100..110 {
        let unknown = ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingLocator::from_bytes([locator; ShortCodePairingLocator::LENGTH]),
            vec![73],
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(protobuf_request(
                "/v1/short-code-attempts/claim",
                encode_short_code_attempt_claim_request(&unknown).unwrap(),
                Some(&rate_limited_token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let limited = ShortCodeAttemptClaimRequest::new(
        ProtocolVersion::application_v1(),
        ShortCodePairingLocator::from_bytes([110; ShortCodePairingLocator::LENGTH]),
        vec![73],
    )
    .unwrap();
    let limited = app
        .oneshot(protobuf_request(
            "/v1/short-code-attempts/claim",
            encode_short_code_attempt_claim_request(&limited).unwrap(),
            Some(&rate_limited_token),
        ))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.headers().get("x-konclave-error-code").unwrap(),
        "relay_short_code_pairing_rate_limited"
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
