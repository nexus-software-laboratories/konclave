#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use KonclaveA2AContracts::wire::{
    Message, Part, Role, SendMessageConfiguration, SendMessageRequest, part,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, InitialA2AInterfaceEnvironment, InitialSendMessageRequest,
    validate_initial_send_message_request,
};
use KonclaveA2ADiscovery::compile_a2a_agent_publication_source;
use KonclaveA2ADomain::{
    A2AAgentId, A2AAgentRoute, A2AContextId, A2AMessageId, A2ATaskState, A2ATenantId,
};
use KonclaveA2AGateway::{
    A2AGatewayApplication, A2AGatewayClock, A2AGatewayClockError, A2AGatewayWaitConfig,
    A2ATaskSubmission, A2ATaskSubmissionError, A2ATaskSubmitter,
};
use KonclaveA2ATaskStore::{A2ATaskMessage, A2ATaskMessageRole, A2ATaskStore, A2ATaskTransition};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveDomainCore::{ConversationId, DeviceId};
use async_trait::async_trait;

pub const PUBLICATION: &[u8] = include_bytes!("../../../../a2a/examples/agent-publication.json");

pub fn request(
    text: &str,
    return_immediately: bool,
    history_length: i32,
) -> InitialSendMessageRequest {
    validate_initial_send_message_request(
        request_wire(text, return_immediately, history_length),
        Some("tenant-a"),
    )
    .unwrap()
}

pub fn request_wire(
    text: &str,
    return_immediately: bool,
    history_length: i32,
) -> SendMessageRequest {
    SendMessageRequest {
        tenant: "tenant-a".to_owned(),
        message: Some(Message {
            message_id: "message-1".to_owned(),
            context_id: "context-1".to_owned(),
            task_id: String::new(),
            role: Role::User as i32,
            parts: vec![Part {
                content: Some(part::Content::Text(text.to_owned())),
                metadata: None,
                filename: String::new(),
                media_type: A2A_TEXT_MEDIA_TYPE.to_owned(),
            }],
            metadata: None,
            extensions: vec![],
            reference_task_ids: vec![],
        }),
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_owned()],
            task_push_notification_config: None,
            history_length: Some(history_length),
            return_immediately,
        }),
        metadata: None,
    }
}

pub fn route() -> A2AAgentRoute {
    A2AAgentRoute::new(
        A2AAgentId::parse("contract-agent").unwrap(),
        A2AContextId::parse("context-1").unwrap(),
        Some(A2ATenantId::parse("tenant-a").unwrap()),
        ConversationId::from_bytes([4; ConversationId::LENGTH]),
        DeviceId::from_bytes([5; DeviceId::LENGTH]),
    )
}

pub fn store(root: &tempfile::TempDir) -> Arc<A2ASqliteTaskStore> {
    Arc::new(
        A2ASqliteTaskStore::open(
            root.path().join("tasks.sqlite"),
            A2ASqliteTaskStoreConfig::default(),
        )
        .unwrap(),
    )
}

pub fn application(
    store: Arc<A2ASqliteTaskStore>,
    submitter: Arc<dyn A2ATaskSubmitter>,
    clock: Arc<TestClock>,
    wait: A2AGatewayWaitConfig,
) -> A2AGatewayApplication {
    application_with_publication(
        PUBLICATION,
        InitialA2AInterfaceEnvironment::Production,
        store,
        submitter,
        clock,
        wait,
    )
}

pub fn application_with_publication(
    publication: &[u8],
    environment: InitialA2AInterfaceEnvironment,
    store: Arc<A2ASqliteTaskStore>,
    submitter: Arc<dyn A2ATaskSubmitter>,
    clock: Arc<TestClock>,
    wait: A2AGatewayWaitConfig,
) -> A2AGatewayApplication {
    A2AGatewayApplication::new(
        route(),
        compile_a2a_agent_publication_source(publication, environment).unwrap(),
        store,
        submitter,
        clock,
        wait,
    )
    .unwrap()
}

pub struct TestClock {
    pub value: AtomicU64,
}

impl TestClock {
    pub fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
        }
    }
}

impl A2AGatewayClock for TestClock {
    fn now_unix_milliseconds(&self) -> Result<u64, A2AGatewayClockError> {
        Ok(self.value.load(Ordering::SeqCst))
    }
}

#[derive(Default)]
pub struct RecordingSubmitter {
    pub calls: AtomicUsize,
}

#[async_trait]
impl A2ATaskSubmitter for RecordingSubmitter {
    async fn submit(&self, submission: A2ATaskSubmission) -> Result<(), A2ATaskSubmissionError> {
        assert_eq!(submission.text(), "request");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

pub struct CompletingSubmitter {
    pub store: Arc<A2ASqliteTaskStore>,
}

#[async_trait]
impl A2ATaskSubmitter for CompletingSubmitter {
    async fn submit(&self, submission: A2ATaskSubmission) -> Result<(), A2ATaskSubmissionError> {
        let key = submission.key().clone();
        self.store
            .append_message(
                A2ATaskMessage::new(
                    key.clone(),
                    A2AMessageId::parse("response-1").unwrap(),
                    A2ATaskMessageRole::Agent,
                    "response",
                    110,
                )
                .unwrap(),
                110,
            )
            .unwrap();
        self.store
            .transition_task(A2ATaskTransition::new(
                key,
                0,
                A2ATaskState::Completed,
                None,
                120,
            ))
            .unwrap();
        Ok(())
    }
}
