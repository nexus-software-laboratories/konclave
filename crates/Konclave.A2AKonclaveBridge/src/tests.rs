use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use KonclaveA2AContracts::wire::{
    Message, Part, Role, SendMessageConfiguration, SendMessageRequest, TaskState, part,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, InitialA2AInterfaceEnvironment, InitialSendMessageRequest,
    MAX_A2A_TEXT_BYTES, decode_initial_send_message_response_json,
    validate_initial_send_message_request,
};
use KonclaveA2ADiscovery::compile_a2a_agent_publication_source;
use KonclaveA2ADomain::{A2AAgentId, A2AAgentRoute, A2AContextId, A2ATaskId, A2ATenantId};
use KonclaveA2AGateway::{
    A2A_JSON_MEDIA_TYPE, A2A_VERSION_HEADER, A2ABearerCredential, A2AGatewayApplication,
    A2AGatewayClock, A2AGatewayClockError, A2AGatewayError, A2AGatewayWaitConfig, A2AHttpConfig,
    A2AHttpState, StaticBearerAccess, a2a_router,
};
use KonclaveA2ATaskStore::{A2ATaskKey, A2ATaskStore};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveDomainCore::{ConversationId, DeviceId};
use KonclaveLocalServiceClient::LocalServiceJsonClientError;
use KonclaveLocalServiceTransport::{LocalServiceErrorCode, RequestId, encode_lowercase_hex};
use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt;

use super::{
    A2AKonclaveBridge, A2AKonclaveBridgeConfig, A2AKonclaveLocalService,
    A2AKonclaveLocalServiceError, MessagePage, map_client_error,
};

const PUBLICATION: &[u8] = include_bytes!("../../../a2a/examples/agent-publication.json");
const EMPTY_MODE: u8 = 0;
const EXACT_MODE: u8 = 1;
const WRONG_THEN_EXACT_MODE: u8 = 2;
const HANGING_WATCH_MODE: u8 = 3;
const ENDLESS_HISTORY_MODE: u8 = 4;
const BEARER_TOKEN: &str = "bridge-test-bearer-credential-0001";

#[test]
fn concrete_client_failures_narrow_to_the_bridge_error_contract() {
    assert_eq!(
        map_client_error(LocalServiceJsonClientError::Service(
            LocalServiceErrorCode::NotAuthorized,
        )),
        A2AKonclaveLocalServiceError::RequestRejected
    );
    assert_eq!(
        map_client_error(LocalServiceJsonClientError::Service(
            LocalServiceErrorCode::Busy,
        )),
        A2AKonclaveLocalServiceError::Unavailable
    );
    assert_eq!(
        map_client_error(LocalServiceJsonClientError::InvalidResponse),
        A2AKonclaveLocalServiceError::InvalidResponse
    );
}

#[tokio::test]
async fn exact_response_completes_once_after_adversarial_messages() {
    let fixture = Fixture::new(WRONG_THEN_EXACT_MODE, &[]);
    let response = fixture
        .application(false)
        .send_message(request("request", false))
        .await
        .unwrap();

    assert!(response.state() == TaskState::Completed);
    let messages = fixture
        .store
        .messages(&fixture.task_key(response.task_id()), 2)
        .unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].text(), "response");
    assert_eq!(messages[1].message_id().as_str(), "06".repeat(16));
    assert!(fixture.local.read_calls.load(Ordering::SeqCst) >= 2);

    {
        let calls = fixture.local.calls.lock().unwrap();
        let send = calls
            .iter()
            .find(|call| call.operation == "send_directed_request")
            .unwrap();
        let payload: Value = serde_json::from_slice(&send.payload).unwrap();
        assert_eq!(payload["conversation_id"], "04".repeat(32));
        assert_eq!(payload["target_device_id"], "05".repeat(32));
        assert_eq!(payload["text"], "request");
        assert_eq!(
            payload["message_id"],
            encode_lowercase_hex(&send.request_id)
        );
        assert!(payload.get("reply_to_message_id").is_none());
    }

    let retried = fixture
        .application(false)
        .send_message(request("request", false))
        .await
        .unwrap();
    assert!(retried.state() == TaskState::Completed);
    assert_eq!(
        fixture
            .store
            .messages(&fixture.task_key(retried.task_id()), 2)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fixture
            .local
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.operation == "send_directed_request")
            .count(),
        1
    );
}

#[test]
fn local_message_page_shape_is_accepted() {
    let local = FakeLocalService::new(EXACT_MODE, &[]);
    *local.sent.lock().unwrap() = Some(SentRequest {
        conversation_id: "04".repeat(32),
        message_id: "03".repeat(16),
        target_device_id: "05".repeat(32),
    });
    let page: MessagePage = serde_json::from_slice(&local.response_page(false)).unwrap();
    assert!(page.messages.as_slice()[0].valid_shape());
}

#[tokio::test]
async fn exact_retry_after_temporary_failure_reuses_the_send_identity() {
    let fixture = Fixture::new(EXACT_MODE, &[A2AKonclaveLocalServiceError::Unavailable]);
    let first_error = fixture
        .application(true)
        .send_message(request("request", false))
        .await
        .err()
        .unwrap();
    assert_eq!(first_error, A2AGatewayError::SubmissionUnavailable);
    let task_id = fixture.local.expected_message_id();
    assert!(
        fixture
            .store
            .get_task(&fixture.task_key(&task_id))
            .unwrap()
            .state()
            == KonclaveA2ADomain::A2ATaskState::Submitted
    );
    let response = fixture
        .application(false)
        .send_message(request("request", false))
        .await
        .unwrap();

    assert!(response.state() == TaskState::Completed);
    let calls = fixture.local.calls.lock().unwrap();
    let sends = calls
        .iter()
        .filter(|call| call.operation == "send_directed_request")
        .collect::<Vec<_>>();
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[0].request_id, sends[1].request_id);
    assert_eq!(sends[0].payload, sends[1].payload);
}

#[tokio::test]
async fn a_hanging_watch_is_cancelled_by_the_observation_deadline() {
    let fixture = Fixture::new(HANGING_WATCH_MODE, &[]);
    let started = tokio::time::Instant::now();
    let error = fixture
        .application(true)
        .send_message(request("request", false))
        .await
        .err()
        .unwrap();

    assert_eq!(error, A2AGatewayError::ResponseWaitExpired);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn an_endless_ready_history_page_still_yields_to_the_observation_deadline() {
    let fixture = Fixture::new(ENDLESS_HISTORY_MODE, &[]);
    let started = tokio::time::Instant::now();
    let error = fixture
        .application(true)
        .send_message(request("request", false))
        .await
        .err()
        .unwrap();

    assert_eq!(error, A2AGatewayError::ResponseWaitExpired);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn an_oversized_exact_response_fails_instead_of_remaining_working() {
    let fixture = Fixture::new(EXACT_MODE, &[]);
    *fixture.local.response_text.lock().unwrap() = "x".repeat(MAX_A2A_TEXT_BYTES + 1);
    let response = fixture
        .application(false)
        .send_message(request("request", false))
        .await
        .unwrap();

    assert!(response.state() == TaskState::Failed);
    let record = fixture
        .store
        .get_task(&fixture.task_key(response.task_id()))
        .unwrap();
    assert_eq!(
        record.terminal_reason().unwrap().as_str(),
        "konclave_response_out_of_bounds"
    );
}

#[tokio::test]
async fn authenticated_http_send_uses_the_real_bridge_submitter() {
    let fixture = Fixture::new(EXACT_MODE, &[]);
    let access =
        StaticBearerAccess::new([A2ABearerCredential::parse(BEARER_TOKEN).unwrap()]).unwrap();
    let state = A2AHttpState::new(
        fixture.application(false),
        Arc::new(access),
        A2AHttpConfig::default(),
    )
    .unwrap();
    let response = a2a_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tenant-a/message:send")
                .header(AUTHORIZATION, format!("Bearer {BEARER_TOKEN}"))
                .header(A2A_VERSION_HEADER, "1.0")
                .header(CONTENT_TYPE, A2A_JSON_MEDIA_TYPE)
                .body(Body::from(
                    serde_json::to_vec(&request("request", false).into_wire()).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
    let task = decode_initial_send_message_response_json(&bytes).unwrap();
    assert!(task.state() == TaskState::Completed);
}

#[tokio::test]
async fn concurrent_exact_submissions_share_one_send_and_observer() {
    let fixture = Fixture::new(EXACT_MODE, &[]);
    let application = fixture.application(false);
    let (first, second) = tokio::join!(
        application.send_message(request("request", true)),
        application.send_message(request("request", true))
    );

    assert!(first.unwrap().state() != TaskState::Rejected);
    assert!(second.unwrap().state() != TaskState::Rejected);
    assert_eq!(
        fixture
            .local
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.operation == "send_directed_request")
            .count(),
        1
    );
}

#[tokio::test]
async fn local_policy_rejection_becomes_a_terminal_rejected_task() {
    let fixture = Fixture::new(EMPTY_MODE, &[A2AKonclaveLocalServiceError::RequestRejected]);
    let response = fixture
        .application(true)
        .send_message(request("request", true))
        .await
        .unwrap();

    assert!(response.state() == TaskState::Rejected);
    let record = fixture
        .store
        .get_task(&fixture.task_key(response.task_id()))
        .unwrap();
    assert_eq!(
        record.terminal_reason().unwrap().as_str(),
        "konclave_request_rejected"
    );
}

#[tokio::test]
async fn a_working_task_resumes_observation_after_bridge_restart() {
    let fixture = Fixture::new(EMPTY_MODE, &[]);
    let first_bridge = fixture.bridge(true);
    let first_application = fixture.application_with_bridge(first_bridge.clone(), true);
    let first = first_application
        .send_message(request("request", false))
        .await;
    assert_eq!(first.err().unwrap(), A2AGatewayError::ResponseWaitExpired);
    first_bridge
        .shutdown(Duration::from_millis(100))
        .await
        .unwrap();
    drop(first_application);
    drop(first_bridge);

    fixture.local.mode.store(EXACT_MODE, Ordering::SeqCst);
    let response = fixture
        .application(false)
        .send_message(request("request", false))
        .await
        .unwrap();

    assert!(response.state() == TaskState::Completed);
    let calls = fixture.local.calls.lock().unwrap();
    let sends = calls
        .iter()
        .filter(|call| call.operation == "send_directed_request")
        .collect::<Vec<_>>();
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[0].request_id, sends[1].request_id);
}

#[tokio::test]
async fn a_rejected_resubmission_does_not_overwrite_an_accepted_working_task() {
    let fixture = Fixture::new(EMPTY_MODE, &[]);
    let first_bridge = fixture.bridge(true);
    let first_application = fixture.application_with_bridge(first_bridge.clone(), true);
    let first = first_application
        .send_message(request("request", false))
        .await;
    assert_eq!(first.err().unwrap(), A2AGatewayError::ResponseWaitExpired);
    first_bridge
        .shutdown(Duration::from_millis(100))
        .await
        .unwrap();
    drop(first_application);
    drop(first_bridge);

    fixture
        .local
        .send_errors
        .lock()
        .unwrap()
        .push_back(A2AKonclaveLocalServiceError::RequestRejected);
    let retry = fixture
        .application(true)
        .send_message(request("request", false))
        .await;
    assert_eq!(retry.err().unwrap(), A2AGatewayError::SubmissionUnavailable);
    let task_id = fixture.local.expected_message_id();
    assert!(
        fixture
            .store
            .get_task(&fixture.task_key(&task_id))
            .unwrap()
            .state()
            == KonclaveA2ADomain::A2ATaskState::Working
    );
}

#[tokio::test]
async fn shutdown_cancels_and_joins_a_blocked_observer() {
    let fixture = Fixture::new(HANGING_WATCH_MODE, &[]);
    let bridge = fixture.bridge(false);
    let application = fixture.application_with_bridge(bridge.clone(), false);
    let response = application
        .send_message(request("request", true))
        .await
        .unwrap();
    assert!(response.state() == TaskState::Working);
    tokio::time::timeout(
        Duration::from_millis(100),
        fixture.local.watch_started.notified(),
    )
    .await
    .unwrap();

    bridge.shutdown(Duration::from_millis(100)).await.unwrap();
    let retry = application
        .send_message(request("request", true))
        .await
        .err()
        .unwrap();
    assert_eq!(retry, A2AGatewayError::SubmissionUnavailable);
}

#[tokio::test]
async fn observer_capacity_is_reserved_before_the_directed_send() {
    let fixture = Fixture::new(HANGING_WATCH_MODE, &[]);
    let bridge = fixture.bridge_with_limit(false, 1);
    let application = fixture.application_with_bridge(bridge.clone(), false);
    let first = application
        .send_message(request_with_id("message-1", "request", true))
        .await
        .unwrap();
    assert!(first.state() == TaskState::Working);
    tokio::time::timeout(
        Duration::from_millis(100),
        fixture.local.watch_started.notified(),
    )
    .await
    .unwrap();

    let second = application
        .send_message(request_with_id("message-2", "other request", false))
        .await
        .err()
        .unwrap();
    assert_eq!(second, A2AGatewayError::SubmissionUnavailable);
    assert_eq!(
        fixture
            .local
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.operation == "send_directed_request")
            .count(),
        1
    );

    bridge.shutdown(Duration::from_millis(100)).await.unwrap();
    fixture.local.mode.store(EXACT_MODE, Ordering::SeqCst);
    let retried = fixture
        .application(false)
        .send_message(request_with_id("message-2", "other request", false))
        .await
        .unwrap();
    assert!(retried.state() == TaskState::Completed);
}

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<A2ASqliteTaskStore>,
    local: Arc<FakeLocalService>,
    clock: Arc<TestClock>,
}

impl Fixture {
    fn new(mode: u8, send_errors: &[A2AKonclaveLocalServiceError]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(
            A2ASqliteTaskStore::open(
                root.path().join("tasks.sqlite"),
                A2ASqliteTaskStoreConfig::default(),
            )
            .unwrap(),
        );
        Self {
            _root: root,
            store,
            local: Arc::new(FakeLocalService::new(mode, send_errors)),
            clock: Arc::new(TestClock::new(1_700_000_000_000)),
        }
    }

    fn application(&self, return_quickly: bool) -> A2AGatewayApplication {
        self.application_with_bridge(self.bridge(return_quickly), return_quickly)
    }

    fn bridge(&self, return_quickly: bool) -> Arc<A2AKonclaveBridge> {
        self.bridge_with_limit(return_quickly, 256)
    }

    fn bridge_with_limit(
        &self,
        return_quickly: bool,
        max_concurrent_observers: usize,
    ) -> Arc<A2AKonclaveBridge> {
        let config = A2AKonclaveBridgeConfig::new(
            Duration::from_millis(if return_quickly { 40 } else { 500 }),
            Duration::from_millis(5),
            100,
            max_concurrent_observers,
        )
        .unwrap();
        Arc::new(A2AKonclaveBridge::with_nonce(
            self.store.clone(),
            self.local.clone(),
            self.clock.clone(),
            config,
            [9; 16],
        ))
    }

    fn application_with_bridge(
        &self,
        bridge: Arc<A2AKonclaveBridge>,
        return_quickly: bool,
    ) -> A2AGatewayApplication {
        A2AGatewayApplication::new(
            route(),
            compile_a2a_agent_publication_source(
                PUBLICATION,
                InitialA2AInterfaceEnvironment::Production,
            )
            .unwrap(),
            self.store.clone(),
            bridge,
            self.clock.clone(),
            A2AGatewayWaitConfig::new(
                Duration::from_millis(if return_quickly { 100 } else { 750 }),
                Duration::from_millis(5),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn task_key(&self, task_id: &str) -> A2ATaskKey {
        A2ATaskKey::new(
            A2AAgentId::parse("contract-agent").unwrap(),
            Some(A2ATenantId::parse("tenant-a").unwrap()),
            A2ATaskId::parse(task_id).unwrap(),
        )
    }
}

struct TestClock(AtomicU64);

impl TestClock {
    fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }
}

impl A2AGatewayClock for TestClock {
    fn now_unix_milliseconds(&self) -> Result<u64, A2AGatewayClockError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

struct CapturedCall {
    request_id: [u8; 16],
    operation: String,
    payload: Vec<u8>,
}

struct SentRequest {
    conversation_id: String,
    message_id: String,
    target_device_id: String,
}

struct FakeLocalService {
    mode: AtomicU8,
    send_errors: Mutex<VecDeque<A2AKonclaveLocalServiceError>>,
    sent: Mutex<Option<SentRequest>>,
    calls: Mutex<Vec<CapturedCall>>,
    read_calls: AtomicUsize,
    response_text: Mutex<String>,
    watch_started: Notify,
}

impl FakeLocalService {
    fn new(mode: u8, send_errors: &[A2AKonclaveLocalServiceError]) -> Self {
        Self {
            mode: AtomicU8::new(mode),
            send_errors: Mutex::new(send_errors.iter().copied().collect()),
            sent: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
            read_calls: AtomicUsize::new(0),
            response_text: Mutex::new("response".to_string()),
            watch_started: Notify::new(),
        }
    }

    fn empty_page() -> Vec<u8> {
        serde_json::to_vec(&json!({"messages": [], "has_more": false})).unwrap()
    }

    fn expected_message_id(&self) -> String {
        self.sent
            .lock()
            .unwrap()
            .as_ref()
            .map(|sent| sent.message_id.clone())
            .unwrap_or_else(|| {
                self.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|call| call.operation == "send_directed_request")
                    .map(|call| encode_lowercase_hex(&call.request_id))
                    .unwrap()
            })
    }

    fn response_page(&self, wrong_only: bool) -> Vec<u8> {
        let sent = self.sent.lock().unwrap();
        let sent = sent.as_ref().unwrap();
        let response_text = self.response_text.lock().unwrap().clone();
        let exact = message(
            &sent.conversation_id,
            &sent.target_device_id,
            &sent.message_id,
            "text",
            &response_text,
            14,
        );
        let messages = if wrong_only {
            vec![
                message(
                    &sent.conversation_id,
                    &"08".repeat(32),
                    &sent.message_id,
                    "text",
                    "wrong sender",
                    11,
                ),
                message(
                    &sent.conversation_id,
                    &sent.target_device_id,
                    &"09".repeat(16),
                    "text",
                    "wrong reply",
                    12,
                ),
                message(
                    &sent.conversation_id,
                    &sent.target_device_id,
                    &sent.message_id,
                    "directed_request",
                    "unrelated request",
                    13,
                ),
            ]
        } else {
            vec![exact]
        };
        serde_json::to_vec(&json!({"messages": messages, "has_more": false})).unwrap()
    }
}

#[async_trait]
impl A2AKonclaveLocalService for FakeLocalService {
    async fn request(
        &self,
        request_id: RequestId,
        operation: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, A2AKonclaveLocalServiceError> {
        self.calls.lock().unwrap().push(CapturedCall {
            request_id: *request_id.as_bytes(),
            operation: operation.to_string(),
            payload: payload.clone(),
        });
        match operation {
            "send_directed_request" => {
                if let Some(code) = self.send_errors.lock().unwrap().pop_front() {
                    return Err(code);
                }
                let value: Value = serde_json::from_slice(&payload).unwrap();
                let sent = SentRequest {
                    conversation_id: value["conversation_id"].as_str().unwrap().to_string(),
                    message_id: value["message_id"].as_str().unwrap().to_string(),
                    target_device_id: value["target_device_id"].as_str().unwrap().to_string(),
                };
                let response = json!({
                    "conversation_id": sent.conversation_id,
                    "message_id": sent.message_id,
                    "sender_counter": 1,
                    "cursor": 10
                });
                *self.sent.lock().unwrap() = Some(sent);
                Ok(serde_json::to_vec(&response).unwrap())
            }
            "read_messages" => {
                let read = self.read_calls.fetch_add(1, Ordering::SeqCst);
                match self.mode.load(Ordering::SeqCst) {
                    EXACT_MODE => Ok(self.response_page(false)),
                    WRONG_THEN_EXACT_MODE if read == 0 => Ok(self.response_page(true)),
                    WRONG_THEN_EXACT_MODE => Ok(self.response_page(false)),
                    ENDLESS_HISTORY_MODE => {
                        Ok(serde_json::to_vec(&json!({"messages": [], "has_more": true})).unwrap())
                    }
                    _ => Ok(Self::empty_page()),
                }
            }
            "watch_messages" => {
                self.watch_started.notify_one();
                if self.mode.load(Ordering::SeqCst) == HANGING_WATCH_MODE {
                    std::future::pending::<Result<Vec<u8>, A2AKonclaveLocalServiceError>>().await
                } else {
                    Ok(Self::empty_page())
                }
            }
            "sync_messages" => Ok(Self::empty_page()),
            _ => Err(A2AKonclaveLocalServiceError::Unavailable),
        }
    }
}

fn message(
    conversation_id: &str,
    sender_device_id: &str,
    reply_to_message_id: &str,
    content_type: &str,
    text: &str,
    cursor: u64,
) -> Value {
    let mut value = json!({
        "conversation_id": conversation_id,
        "message_id": "06".repeat(16),
        "envelope_id": "07".repeat(16),
        "sender_device_id": sender_device_id,
        "epoch": 1,
        "sender_counter": cursor,
        "sent_at_unix_milliseconds": 1_700_000_000_010_u64,
        "reply_to_message_id": reply_to_message_id,
        "cursor": cursor,
        "direction": "inbound",
        "content_type": content_type,
        "duplicate": false
    });
    if content_type == "text" {
        value["text"] = json!(text);
    } else {
        value["target_device_id"] = json!("05".repeat(32));
        value["text"] = json!(text);
    }
    value
}

fn route() -> A2AAgentRoute {
    A2AAgentRoute::new(
        A2AAgentId::parse("contract-agent").unwrap(),
        A2AContextId::parse("context-1").unwrap(),
        Some(A2ATenantId::parse("tenant-a").unwrap()),
        ConversationId::from_bytes([4; ConversationId::LENGTH]),
        DeviceId::from_bytes([5; DeviceId::LENGTH]),
    )
}

fn request(text: &str, return_immediately: bool) -> InitialSendMessageRequest {
    request_with_id("message-1", text, return_immediately)
}

fn request_with_id(
    message_id: &str,
    text: &str,
    return_immediately: bool,
) -> InitialSendMessageRequest {
    validate_initial_send_message_request(
        SendMessageRequest {
            tenant: "tenant-a".to_string(),
            message: Some(Message {
                message_id: message_id.to_string(),
                context_id: "context-1".to_string(),
                task_id: String::new(),
                role: Role::User as i32,
                parts: vec![Part {
                    content: Some(part::Content::Text(text.to_string())),
                    metadata: None,
                    filename: String::new(),
                    media_type: A2A_TEXT_MEDIA_TYPE.to_string(),
                }],
                metadata: None,
                extensions: vec![],
                reference_task_ids: vec![],
            }),
            configuration: Some(SendMessageConfiguration {
                accepted_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_string()],
                task_push_notification_config: None,
                history_length: Some(1),
                return_immediately,
            }),
            metadata: None,
        },
        Some("tenant-a"),
    )
    .unwrap()
}
