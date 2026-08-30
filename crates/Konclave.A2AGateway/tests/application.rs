mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use KonclaveA2AContracts::wire::{GetTaskRequest, TaskState, part};
use KonclaveA2AContracts::{InitialA2AInterfaceEnvironment, validate_initial_get_task_request};
use KonclaveA2ADiscovery::compile_a2a_agent_publication_source;
use KonclaveA2AGateway::{A2AGatewayApplication, A2AGatewayError, A2AGatewayWaitConfig};
use KonclaveA2ATaskStoreSqlite::A2ASqliteTaskStoreConfig;

use common::{
    CompletingSubmitter, PUBLICATION, RecordingSubmitter, TestClock, application, request, route,
    store,
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
