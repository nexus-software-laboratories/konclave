mod common;

use std::sync::Arc;

use KonclaveA2AContracts::{
    InitialA2AInterfaceEnvironment, decode_initial_agent_card_json,
    decode_initial_send_message_response_json, decode_initial_task_json,
};
use KonclaveA2AGateway::{
    A2A_JSON_MEDIA_TYPE, A2A_VERSION_HEADER, A2ABearerCredential, A2AGatewayApplication,
    A2AGatewayWaitConfig, A2AHttpAccess, A2AHttpAction, A2AHttpAuthorizationDecision,
    A2AHttpConfig, A2AHttpPrincipalId, A2AHttpState, StaticBearerAccess, a2a_router,
    validate_a2a_binding,
};
use axum::body::{Body, to_bytes};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, WWW_AUTHENTICATE,
};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{
    CompletingSubmitter, PUBLICATION, RecordingSubmitter, TestClock, application,
    application_with_publication, request_wire, store,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn remote_bindings_require_explicit_tls_termination() {
    assert!(validate_a2a_binding("127.0.0.1".parse().unwrap(), false).is_ok());
    assert!(validate_a2a_binding("0.0.0.0".parse().unwrap(), true).is_ok());
    assert_eq!(
        validate_a2a_binding("0.0.0.0".parse().unwrap(), false).err(),
        Some(KonclaveA2AGateway::A2AGatewayError::InvalidConfiguration)
    );
}

#[test]
fn static_bearer_access_is_bounded_case_insensitive_and_duplicate_safe() {
    assert!(A2ABearerCredential::parse("short").is_err());
    assert!(
        StaticBearerAccess::new([
            A2ABearerCredential::parse(TOKEN).unwrap(),
            A2ABearerCredential::parse(TOKEN).unwrap()
        ])
        .is_err()
    );
    let access = StaticBearerAccess::new([A2ABearerCredential::parse(TOKEN).unwrap()]).unwrap();
    let request = Request::builder()
        .header(AUTHORIZATION, format!("bEaReR {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let (parts, _) = request.into_parts();
    assert!(access.authenticate(&parts).is_ok());

    let mut request = Request::builder().body(Body::empty()).unwrap();
    request
        .headers_mut()
        .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
    request
        .headers_mut()
        .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
    let (parts, _) = request.into_parts();
    assert_eq!(
        access.authenticate(&parts).err(),
        Some(KonclaveA2AGateway::A2AGatewayError::Unauthenticated)
    );
}

fn state(application: A2AGatewayApplication) -> A2AHttpState {
    let access = StaticBearerAccess::new([A2ABearerCredential::parse(TOKEN).unwrap()]).unwrap();
    A2AHttpState::new(application, Arc::new(access), A2AHttpConfig::default()).unwrap()
}

fn authenticated(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .uri(path)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(A2A_VERSION_HEADER, "1.0")
}

async fn body(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 512 * 1024)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn protected_send_get_and_extended_routes_follow_the_http_json_binding() {
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let application = application(
        store.clone(),
        Arc::new(CompletingSubmitter { store }),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    );
    let router = a2a_router(state(application));
    let response = router
        .clone()
        .oneshot(
            authenticated("/tenant-a/message:send")
                .method("POST")
                .header(CONTENT_TYPE, A2A_JSON_MEDIA_TYPE)
                .body(Body::from(
                    serde_json::to_vec(&request_wire("request", false, 1)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        A2A_JSON_MEDIA_TYPE
    );
    let task = decode_initial_send_message_response_json(&body(response).await).unwrap();
    assert_eq!(task.as_wire().history.len(), 1);

    let response = router
        .clone()
        .oneshot(
            authenticated(&format!(
                "/tenant-a/tasks/{}?historyLength=0",
                task.task_id()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        decode_initial_task_json(&body(response).await)
            .unwrap()
            .as_wire()
            .history
            .is_empty()
    );

    let response = router
        .oneshot(
            authenticated("/tenant-a/extendedAgentCard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CACHE_CONTROL).unwrap(),
        "private, max-age=3600"
    );
    let card = decode_initial_agent_card_json(
        &body(response).await,
        InitialA2AInterfaceEnvironment::Production,
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(card.skills().len(), 2);
}

#[tokio::test]
async fn public_card_is_opt_in_and_supports_etag_revalidation() {
    let root = tempfile::tempdir().unwrap();
    let private = a2a_router(state(application(
        store(&root),
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    )));
    assert_eq!(
        private
            .oneshot(
                Request::builder()
                    .uri("/.well-known/agent-card.json")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    let mut publication: Value = serde_json::from_slice(PUBLICATION).unwrap();
    publication["spec"]["publicWellKnown"] = json!(true);
    let root = tempfile::tempdir().unwrap();
    let public = a2a_router(state(application_with_publication(
        &serde_json::to_vec(&publication).unwrap(),
        InitialA2AInterfaceEnvironment::Production,
        store(&root),
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    )));
    let response = public
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CACHE_CONTROL).unwrap(),
        "public, max-age=3600"
    );
    let etag = response.headers().get(ETAG).unwrap().clone();
    assert!(etag.to_str().unwrap().starts_with('"'));
    assert!(
        decode_initial_agent_card_json(
            &body(response).await,
            InitialA2AInterfaceEnvironment::Production,
            Some("tenant-a")
        )
        .is_ok()
    );

    let response = public
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .header(IF_NONE_MATCH, etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert!(body(response).await.is_empty());
}

#[tokio::test]
async fn authentication_precedes_body_parsing_and_route_disclosure() {
    let root = tempfile::tempdir().unwrap();
    let router = a2a_router(state(application(
        store(&root),
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    )));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tenant-a/message:send")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(vec![0_u8; 256 * 1024]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");

    let response = router
        .clone()
        .oneshot(
            authenticated("/other/tasks/00112233445566778899aabbccddeeff")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = router
        .oneshot(
            authenticated("/tenant-a/message:send")
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        serde_json::from_slice::<Value>(&body(response).await).unwrap()["error"]["details"][0]["reason"],
        "CONTENT_TYPE_NOT_SUPPORTED"
    );
}

#[tokio::test]
async fn unsupported_streaming_and_denied_authorization_return_bounded_errors() {
    let root = tempfile::tempdir().unwrap();
    let application = application(
        store(&root),
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    );
    let router = a2a_router(state(application.clone()));
    let response = router
        .oneshot(
            authenticated("/tenant-a/message:stream")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&body(response).await).unwrap()["error"]["details"][0]["reason"],
        "UNSUPPORTED_OPERATION"
    );

    let denied = A2AHttpState::new(
        application,
        Arc::new(DecisionAccess(A2AHttpAuthorizationDecision::Deny)),
        A2AHttpConfig::default(),
    )
    .unwrap();
    let response = a2a_router(denied)
        .oneshot(
            Request::builder()
                .uri("/tenant-a/tasks/00112233445566778899aabbccddeeff")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

struct DecisionAccess(A2AHttpAuthorizationDecision);

impl A2AHttpAccess for DecisionAccess {
    fn authentication_kind(&self) -> Option<KonclaveA2AContracts::InitialA2AAgentSecurityKind> {
        Some(KonclaveA2AContracts::InitialA2AAgentSecurityKind::Bearer)
    }

    fn authenticate(
        &self,
        _request: &Parts,
    ) -> Result<A2AHttpPrincipalId, KonclaveA2AGateway::A2AGatewayError> {
        Ok(A2AHttpPrincipalId::from_bytes([7; 32]))
    }

    fn authorize(
        &self,
        _principal: A2AHttpPrincipalId,
        _action: A2AHttpAction,
    ) -> A2AHttpAuthorizationDecision {
        self.0
    }
}
