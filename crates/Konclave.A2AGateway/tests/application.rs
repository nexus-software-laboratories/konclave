mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use KonclaveA2AContracts::wire::{GetTaskRequest, ListTasksRequest, TaskState, part};
use KonclaveA2AContracts::{
    INITIAL_TASK_TERMINAL_REASON_FIELD, InitialA2AInterfaceEnvironment,
    validate_initial_get_task_request, validate_initial_list_tasks_request,
};
use KonclaveA2ADiscovery::compile_a2a_agent_publication_source;
use KonclaveA2ADomain::{A2AAgentId, A2AArtifactId, A2ATaskId, A2ATaskState, A2ATenantId};
use KonclaveA2AGateway::{
    A2AGatewayApplication, A2AGatewayError, A2AGatewayWaitConfig, A2ATaskSubmission,
    A2ATaskSubmissionError, A2ATaskSubmitter,
};
use KonclaveA2ATaskStore::{
    A2ATaskArtifact, A2ATaskKey, A2ATaskStore, A2ATaskTransition, A2ATerminalReason,
};
use KonclaveA2ATaskStoreSqlite::A2ASqliteTaskStoreConfig;
use async_trait::async_trait;

use common::{
    CompletingSubmitter, PUBLICATION, RecordingSubmitter, TestClock, application, request,
    request_with_message_id, route, store,
};

#[test]
fn sqlite_reference_constructor_opens_the_public_store() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        A2AGatewayApplication::open_sqlite(
            route(),
            compile_a2a_agent_publication_source(
                PUBLICATION,
                InitialA2AInterfaceEnvironment::Production
            )
            .unwrap(),
            root.path().join("tasks.sqlite"),
            A2ASqliteTaskStoreConfig::default(),
            Arc::new(RecordingSubmitter::default()),
            Arc::new(TestClock::new(100)),
            A2AGatewayWaitConfig::default(),
        )
        .is_ok()
    );
}

#[tokio::test]
async fn immediate_send_is_durable_idempotent_and_resubmittable() {
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let submitter = Arc::new(RecordingSubmitter::default());
    let clock = Arc::new(TestClock::new(100));
    let application = application(
        store,
        submitter.clone(),
        clock.clone(),
        A2AGatewayWaitConfig::default(),
    );

    let first = application
        .send_message(request("request", true, 1))
        .await
        .unwrap();
    assert!(first.state() == TaskState::Submitted);
    assert_eq!(first.as_wire().history.len(), 1);
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 1);

    clock.value.store(200, Ordering::SeqCst);
    let retry = application
        .send_message(request("request", true, 1))
        .await
        .unwrap();
    assert_eq!(retry.task_id(), first.task_id());
    assert_eq!(submitter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        application
            .send_message(request("changed", true, 1))
            .await
            .err(),
        Some(A2AGatewayError::Conflict)
    );
}

#[tokio::test]
async fn restart_resubmits_an_existing_submitted_task() {
    let root = tempfile::tempdir().unwrap();
    let first_submitter = Arc::new(RecordingSubmitter::default());
    let first = application(
        store(&root),
        first_submitter,
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    );
    let task = first
        .send_message(request("request", true, 0))
        .await
        .unwrap();
    let task_id = task.task_id().to_owned();
    drop(first);

    let restarted_submitter = Arc::new(RecordingSubmitter::default());
    let restarted = application(
        store(&root),
        restarted_submitter.clone(),
        Arc::new(TestClock::new(200)),
        A2AGatewayWaitConfig::default(),
    );
    let recovered = restarted
        .send_message(request("request", true, 0))
        .await
        .unwrap();
    assert_eq!(recovered.task_id(), task_id);
    assert_eq!(restarted_submitter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_immediate_send_waits_for_terminal_state_and_projects_history() {
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let submitter = Arc::new(CompletingSubmitter {
        store: store.clone(),
    });
    let application = application(
        store,
        submitter,
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::new(Duration::from_secs(1), Duration::from_millis(1)).unwrap(),
    );
    let completed = application
        .send_message(request("request", false, 1))
        .await
        .unwrap();
    assert!(completed.state() == TaskState::Completed);
    assert!(matches!(
        &completed
            .as_wire()
            .status
            .as_ref()
            .unwrap()
            .message
            .as_ref()
            .unwrap()
            .parts[0]
            .content,
        Some(part::Content::Text(text)) if text == "response"
    ));
    assert_eq!(completed.as_wire().history.len(), 1);

    let get = validate_initial_get_task_request(
        GetTaskRequest {
            tenant: "tenant-a".to_owned(),
            id: completed.task_id().to_owned(),
            history_length: Some(0),
        },
        Some("tenant-a"),
    )
    .unwrap();
    assert!(
        application
            .get_task(get)
            .await
            .unwrap()
            .as_wire()
            .history
            .is_empty()
    );
}

#[tokio::test]
async fn non_immediate_send_expires_without_fabricating_completion() {
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let application = application(
        store,
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::new(Duration::from_millis(10), Duration::from_millis(1)).unwrap(),
    );
    assert_eq!(
        application
            .send_message(request("request", false, 0))
            .await
            .err(),
        Some(A2AGatewayError::ResponseWaitExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn submission_is_inside_the_configured_response_deadline() {
    let root = tempfile::tempdir().unwrap();
    let application = application(
        store(&root),
        Arc::new(PendingSubmitter),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::new(Duration::from_secs(5), Duration::from_millis(1)).unwrap(),
    );
    assert_eq!(
        application
            .send_message(request("request", true, 0))
            .await
            .err(),
        Some(A2AGatewayError::ResponseWaitExpired)
    );
}

#[tokio::test]
async fn artifact_only_completion_is_not_projected_as_text_success() {
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let application = application(
        store.clone(),
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    );
    let task = application
        .send_message(request("request", true, 0))
        .await
        .unwrap();
    let key = A2ATaskKey::new(
        A2AAgentId::parse("contract-agent").unwrap(),
        Some(A2ATenantId::parse("tenant-a").unwrap()),
        A2ATaskId::parse(task.task_id().to_owned()).unwrap(),
    );
    store
        .append_artifact(
            A2ATaskArtifact::new(
                key.clone(),
                A2AArtifactId::parse("artifact-1").unwrap(),
                vec![1],
                true,
                110,
            )
            .unwrap(),
            110,
        )
        .unwrap();
    store
        .transition_task(A2ATaskTransition::new(
            key,
            0,
            A2ATaskState::Completed,
            None,
            120,
        ))
        .unwrap();
    let get = validate_initial_get_task_request(
        GetTaskRequest {
            tenant: "tenant-a".to_owned(),
            id: task.task_id().to_owned(),
            history_length: Some(0),
        },
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(
        application.get_task(get).await.err(),
        Some(A2AGatewayError::InvalidTaskProjection)
    );
}

#[tokio::test]
async fn get_task_hides_pruned_entries_and_list_tasks_projects_terminal_reasons() {
    let root = tempfile::tempdir().unwrap();
    let store = store(&root);
    let application = application(
        store.clone(),
        Arc::new(RecordingSubmitter::default()),
        Arc::new(TestClock::new(100)),
        A2AGatewayWaitConfig::default(),
    );
    let _first = application
        .send_message(request_with_message_id("message-1", "request", true, 0))
        .await
        .unwrap();
    let second = application
        .send_message(request_with_message_id("message-2", "request", true, 0))
        .await
        .unwrap();
    let second_key = A2ATaskKey::new(
        A2AAgentId::parse("contract-agent").unwrap(),
        Some(A2ATenantId::parse("tenant-a").unwrap()),
        A2ATaskId::parse(second.task_id().to_owned()).unwrap(),
    );
    store
        .transition_task(A2ATaskTransition::new(
            second_key.clone(),
            0,
            A2ATaskState::Rejected,
            Some(A2ATerminalReason::parse("konclave_request_rejected").unwrap()),
            110,
        ))
        .unwrap();

    let list = validate_initial_list_tasks_request(
        ListTasksRequest {
            tenant: "tenant-a".to_owned(),
            context_id: String::new(),
            status: 0,
            page_size: Some(50),
            page_token: String::new(),
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: None,
        },
        Some("tenant-a"),
    )
    .unwrap();
    let list = application.list_tasks(list).await.unwrap();
    assert_eq!(list.as_wire().tasks.len(), 2);
    assert!(
        list.as_wire()
            .tasks
            .iter()
            .all(|task| task.history.is_empty())
    );
    let rejected = list
        .as_wire()
        .tasks
        .iter()
        .find(|task| task.id == second.task_id())
        .unwrap();
    assert_eq!(
        rejected.metadata.as_ref().unwrap().fields[INITIAL_TASK_TERMINAL_REASON_FIELD]
            .kind
            .as_ref()
            .and_then(|kind| match kind {
                pbjson_types::value::Kind::StringValue(value) => Some(value.as_str()),
                _ => None,
            }),
        Some("konclave_request_rejected")
    );

    store.prune(110 + 7 * 24 * 60 * 60 * 1_000).unwrap();
    let get = validate_initial_get_task_request(
        GetTaskRequest {
            tenant: "tenant-a".to_owned(),
            id: second.task_id().to_owned(),
            history_length: Some(0),
        },
        Some("tenant-a"),
    )
    .unwrap();
    assert_eq!(
        application.get_task(get).await.err(),
        Some(A2AGatewayError::TaskNotFound)
    );
}

struct PendingSubmitter;

#[async_trait]
impl A2ATaskSubmitter for PendingSubmitter {
    async fn submit(&self, _submission: A2ATaskSubmission) -> Result<(), A2ATaskSubmissionError> {
        std::future::pending().await
    }
}
