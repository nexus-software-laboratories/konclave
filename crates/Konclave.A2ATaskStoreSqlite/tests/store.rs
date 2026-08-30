use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use KonclaveA2AContracts::wire::{Message, Part, Role, SendMessageRequest, part};
use KonclaveA2AContracts::{A2A_TEXT_MEDIA_TYPE, validate_initial_send_message_request};
use KonclaveA2ADomain::{
    A2AAgentId, A2AAgentRoute, A2AArtifactId, A2AContextId, A2AMessageId, A2ATaskState,
    A2ATenantId, map_initial_send_message,
};
use KonclaveA2ATaskStore::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskMessage, A2ATaskMessageRole, A2ATaskStore,
    A2ATaskStoreError, A2ATaskTransition, A2ATerminalReason, AppendA2ATaskRecordOutcome,
    CreateA2ATaskOutcome, TransitionA2ATaskOutcome,
};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveDomainCore::{ConversationId, DeviceId};
use rusqlite::{Connection, params};

fn config() -> A2ASqliteTaskStoreConfig {
    A2ASqliteTaskStoreConfig {
        max_tasks: 16,
        max_messages_per_task: 8,
        max_artifacts_per_task: 4,
        max_payload_bytes: 1024 * 1024,
        max_prune_batch: 8,
        content_retention_milliseconds: 10,
        idempotency_retention_milliseconds: 20,
        busy_timeout_milliseconds: 1_000,
    }
}

fn route(agent: &str, tenant: &str, conversation: u8, target: u8) -> A2AAgentRoute {
    A2AAgentRoute::new(
        A2AAgentId::parse(agent).unwrap(),
        A2AContextId::parse("context-a").unwrap(),
        Some(A2ATenantId::parse(tenant).unwrap()),
        ConversationId::from_bytes([conversation; ConversationId::LENGTH]),
        DeviceId::from_bytes([target; DeviceId::LENGTH]),
    )
}

fn creation(
    agent: &str,
    tenant: &str,
    conversation: u8,
    target: u8,
    source_message: &str,
    text: &str,
    created_at: u64,
) -> A2ATaskCreation {
    let request = validate_initial_send_message_request(
        SendMessageRequest {
            tenant: tenant.to_string(),
            message: Some(Message {
                message_id: source_message.to_string(),
                context_id: "context-a".to_string(),
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
            configuration: None,
            metadata: None,
        },
        Some(tenant),
    )
    .unwrap();
    A2ATaskCreation::from_mapping(
        map_initial_send_message(&route(agent, tenant, conversation, target), request).unwrap(),
        created_at,
    )
}

fn open(path: &Path) -> A2ASqliteTaskStore {
    A2ASqliteTaskStore::open(path, config()).unwrap()
}

fn created(outcome: CreateA2ATaskOutcome) -> KonclaveA2ATaskStore::A2ATaskRecord {
    match outcome {
        CreateA2ATaskOutcome::Created(task) => task,
        CreateA2ATaskOutcome::Existing(_) => panic!("task should have been created"),
    }
}

#[test]
fn create_is_exact_idempotent_and_survives_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = open(&path);
    let first = creation("agent-a", "tenant-a", 4, 5, "message-a", "request", 100);
    let key = first.key().clone();
    let task = created(store.create_task(first).unwrap());
    assert_eq!(task.state(), A2ATaskState::Submitted);
    assert_eq!(task.generation(), 0);
    assert_eq!(task.request_text(), Some("request"));
    let messages = store.messages(&key, 8).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].role(), A2ATaskMessageRole::User);
    assert_eq!(messages[0].text(), "request");

    assert!(matches!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                200
            ))
            .unwrap(),
        CreateA2ATaskOutcome::Existing(_)
    ));
    assert_eq!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "changed",
                125,
            ))
            .err(),
        Some(A2ATaskStoreError::Conflict)
    );
    assert_eq!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "changed",
                200
            ))
            .err(),
        Some(A2ATaskStoreError::Conflict)
    );
    drop(store);

    let reopened = open(&path);
    let task = reopened.get_task(&key).unwrap();
    assert_eq!(task.created_at_unix_milliseconds(), 100);
    assert_eq!(task.request_text(), Some("request"));
}

#[test]
fn restart_recovers_a_response_appended_before_terminal_transition() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = open(&path);
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    store
        .append_message(
            A2ATaskMessage::new(
                key.clone(),
                A2AMessageId::parse("response-a").unwrap(),
                A2ATaskMessageRole::Agent,
                "response",
                110,
            )
            .unwrap(),
            110,
        )
        .unwrap();
    drop(store);

    let reopened = open(&path);
    assert_eq!(
        reopened.get_task(&key).unwrap().state(),
        A2ATaskState::Submitted
    );
    assert_eq!(reopened.messages(&key, 8).unwrap().len(), 2);
    let completed = reopened
        .transition_task(A2ATaskTransition::new(
            key,
            0,
            A2ATaskState::Completed,
            None,
            120,
        ))
        .unwrap();
    assert!(matches!(completed, TransitionA2ATaskOutcome::Applied(_)));
}

#[test]
fn create_failure_rolls_back_context_task_status_and_message() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = open(&path);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_initial_status
             BEFORE INSERT ON a2a_task_status
             BEGIN
                 SELECT RAISE(FAIL, 'injected status failure');
             END;",
        )
        .unwrap();
    let task = creation("agent-a", "tenant-a", 4, 5, "message-a", "request", 100);
    let key = task.key().clone();
    assert_eq!(
        store.create_task(task).err(),
        Some(A2ATaskStoreError::Storage)
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM a2a_context", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM a2a_task", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    connection
        .execute("DROP TRIGGER fail_initial_status", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                101,
            ))
            .unwrap(),
        CreateA2ATaskOutcome::Created(_)
    ));
    assert!(store.get_task(&key).is_ok());
}

#[test]
fn route_and_tenant_scopes_produce_distinct_tasks() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("tasks.sqlite"));
    let keys = [
        created(
            store
                .create_task(creation(
                    "agent-a",
                    "tenant-a",
                    4,
                    5,
                    "message-a",
                    "request",
                    100,
                ))
                .unwrap(),
        )
        .key()
        .clone(),
        created(
            store
                .create_task(creation(
                    "agent-b",
                    "tenant-a",
                    4,
                    5,
                    "message-a",
                    "request",
                    100,
                ))
                .unwrap(),
        )
        .key()
        .clone(),
        created(
            store
                .create_task(creation(
                    "agent-a",
                    "tenant-b",
                    4,
                    5,
                    "message-a",
                    "request",
                    100,
                ))
                .unwrap(),
        )
        .key()
        .clone(),
    ];
    assert_ne!(keys[0].task_id().as_str(), keys[1].task_id().as_str());
    assert_ne!(keys[0].task_id().as_str(), keys[2].task_id().as_str());
    for key in keys {
        assert!(store.get_task(&key).is_ok());
    }
    assert_eq!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                6,
                5,
                "message-b",
                "request",
                101,
            ))
            .err(),
        Some(A2ATaskStoreError::Conflict)
    );
}

#[test]
fn transitions_require_generation_terminal_reason_and_completion_evidence() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("tasks.sqlite"));
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    assert!(matches!(
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                0,
                A2ATaskState::Working,
                None,
                110,
            ))
            .unwrap(),
        TransitionA2ATaskOutcome::Applied(_)
    ));
    assert!(matches!(
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                0,
                A2ATaskState::Working,
                None,
                999,
            ))
            .unwrap(),
        TransitionA2ATaskOutcome::Existing(_)
    ));
    assert_eq!(
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                99,
                A2ATaskState::Working,
                None,
                999,
            ))
            .err(),
        Some(A2ATaskStoreError::Conflict)
    );
    assert_eq!(
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                1,
                A2ATaskState::Completed,
                None,
                120,
            ))
            .err(),
        Some(A2ATaskStoreError::InvalidTransition)
    );

    let response = A2ATaskMessage::new(
        key.clone(),
        A2AMessageId::parse("response-a").unwrap(),
        A2ATaskMessageRole::Agent,
        "response",
        115,
    )
    .unwrap();
    assert_eq!(
        store.append_message(response, 115).unwrap(),
        AppendA2ATaskRecordOutcome::Appended { sequence: 2 }
    );
    let completed = store
        .transition_task(A2ATaskTransition::new(
            key.clone(),
            1,
            A2ATaskState::Completed,
            None,
            120,
        ))
        .unwrap();
    let TransitionA2ATaskOutcome::Applied(completed) = completed else {
        panic!("completion should be applied");
    };
    assert_eq!(completed.generation(), 2);
    assert_eq!(completed.terminal_at_unix_milliseconds(), Some(120));
    let repeated = store
        .transition_task(A2ATaskTransition::new(
            key.clone(),
            1,
            A2ATaskState::Completed,
            None,
            999,
        ))
        .unwrap();
    let TransitionA2ATaskOutcome::Existing(repeated) = repeated else {
        panic!("exact terminal retry should return the existing task");
    };
    assert_eq!(repeated.generation(), 2);
    assert_eq!(
        store
            .transition_task(A2ATaskTransition::new(
                key,
                2,
                A2ATaskState::Failed,
                Some(A2ATerminalReason::parse("late_failure").unwrap()),
                130,
            ))
            .err(),
        Some(A2ATaskStoreError::InvalidTransition)
    );
}

#[test]
fn message_and_artifact_appends_are_ordered_idempotent_and_conflict_checked() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("tasks.sqlite"));
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    let response_id = A2AMessageId::parse("response-a").unwrap();
    assert_eq!(
        store
            .append_message(
                A2ATaskMessage::new(
                    key.clone(),
                    response_id.clone(),
                    A2ATaskMessageRole::Agent,
                    "response",
                    110,
                )
                .unwrap(),
                110,
            )
            .unwrap(),
        AppendA2ATaskRecordOutcome::Appended { sequence: 2 }
    );
    assert_eq!(
        store
            .append_message(
                A2ATaskMessage::new(
                    key.clone(),
                    response_id.clone(),
                    A2ATaskMessageRole::Agent,
                    "response",
                    999,
                )
                .unwrap(),
                999,
            )
            .unwrap(),
        AppendA2ATaskRecordOutcome::Existing { sequence: 2 }
    );
    assert_eq!(
        store
            .append_message(
                A2ATaskMessage::new(
                    key.clone(),
                    response_id,
                    A2ATaskMessageRole::Agent,
                    "changed",
                    110,
                )
                .unwrap(),
                110,
            )
            .err(),
        Some(A2ATaskStoreError::Conflict)
    );

    let artifact_id = A2AArtifactId::parse("artifact-a").unwrap();
    assert_eq!(
        store
            .append_artifact(
                A2ATaskArtifact::new(key.clone(), artifact_id.clone(), vec![1, 2, 3], true, 120,)
                    .unwrap(),
                120,
            )
            .unwrap(),
        AppendA2ATaskRecordOutcome::Appended { sequence: 1 }
    );
    assert_eq!(
        store
            .append_artifact(
                A2ATaskArtifact::new(key.clone(), artifact_id.clone(), vec![1, 2, 3], true, 999,)
                    .unwrap(),
                999,
            )
            .unwrap(),
        AppendA2ATaskRecordOutcome::Existing { sequence: 1 }
    );
    assert_eq!(
        store
            .append_artifact(
                A2ATaskArtifact::new(key.clone(), artifact_id, vec![4], true, 120).unwrap(),
                120,
            )
            .err(),
        Some(A2ATaskStoreError::Conflict)
    );

    let messages = store.messages(&key, 8).unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].sequence(), 2);
    assert_eq!(messages[1].recorded_at_unix_milliseconds(), 110);
    let latest = store.messages(&key, 1).unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].sequence(), 2);
    assert_eq!(latest[0].text(), "response");
    let artifacts = store.artifacts(&key, 4).unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].canonical_bytes(), &[1, 2, 3]);
    assert_eq!(artifacts[0].recorded_at_unix_milliseconds(), 120);
}

#[test]
fn cancellation_and_failure_reasons_are_terminal() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("tasks.sqlite"));
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    assert_eq!(
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                0,
                A2ATaskState::Canceled,
                None,
                110,
            ))
            .err(),
        Some(A2ATaskStoreError::InvalidTransition)
    );
    let reason = A2ATerminalReason::parse("caller_canceled").unwrap();
    let canceled = store
        .transition_task(A2ATaskTransition::new(
            key.clone(),
            0,
            A2ATaskState::Canceled,
            Some(reason),
            110,
        ))
        .unwrap();
    let TransitionA2ATaskOutcome::Applied(canceled) = canceled else {
        panic!("cancellation should be applied");
    };
    assert_eq!(canceled.state(), A2ATaskState::Canceled);
    assert_eq!(
        canceled.terminal_reason().unwrap().as_str(),
        "caller_canceled"
    );
    assert_eq!(
        store
            .transition_task(A2ATaskTransition::new(
                key,
                1,
                A2ATaskState::Working,
                None,
                120,
            ))
            .err(),
        Some(A2ATaskStoreError::InvalidTransition)
    );
}

#[test]
fn retention_prunes_payload_then_tombstone_without_evicting_active_tasks() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("tasks.sqlite"));
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    store
        .transition_task(A2ATaskTransition::new(
            key.clone(),
            0,
            A2ATaskState::Failed,
            Some(A2ATerminalReason::parse("transport_failed").unwrap()),
            110,
        ))
        .unwrap();
    assert_eq!(store.prune(119).unwrap().pruned_task_payloads, 0);
    let pruned = store.prune(120).unwrap();
    assert_eq!(pruned.pruned_task_payloads, 1);
    let tombstone = store.get_task(&key).unwrap();
    assert!(tombstone.content_pruned());
    assert_eq!(tombstone.request_text(), None);
    assert!(store.messages(&key, 8).unwrap().is_empty());
    assert!(matches!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                125,
            ))
            .unwrap(),
        CreateA2ATaskOutcome::Existing(_)
    ));
    assert_eq!(store.prune(130).unwrap().removed_tombstones, 1);
    assert_eq!(
        store.get_task(&key).err(),
        Some(A2ATaskStoreError::NotFound)
    );

    let active = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                6,
                7,
                "message-b",
                "active",
                130,
            ))
            .unwrap(),
    );
    assert_eq!(store.prune(1_000).unwrap().pruned_task_payloads, 0);
    assert!(store.get_task(active.key()).is_ok());
}

#[test]
fn retention_work_is_bounded_per_transaction() {
    let root = tempfile::tempdir().unwrap();
    let store = A2ASqliteTaskStore::open(
        root.path().join("tasks.sqlite"),
        A2ASqliteTaskStoreConfig {
            max_prune_batch: 1,
            ..config()
        },
    )
    .unwrap();
    let mut keys = Vec::new();
    for source in ["message-a", "message-b"] {
        let task = created(
            store
                .create_task(creation(
                    "agent-a", "tenant-a", 4, 5, source, "request", 100,
                ))
                .unwrap(),
        );
        let key = task.key().clone();
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                0,
                A2ATaskState::Rejected,
                Some(A2ATerminalReason::parse("not_supported").unwrap()),
                110,
            ))
            .unwrap();
        keys.push(key);
    }
    assert_eq!(store.prune(120).unwrap().pruned_task_payloads, 1);
    assert_eq!(store.prune(120).unwrap().pruned_task_payloads, 1);
    assert_eq!(store.prune(130).unwrap().removed_tombstones, 1);
    assert_eq!(store.prune(130).unwrap().removed_tombstones, 1);
    assert!(
        keys.iter()
            .all(|key| store.get_task(key).err() == Some(A2ATaskStoreError::NotFound))
    );
}

#[test]
fn hard_capacity_fails_closed_until_an_eligible_tombstone_expires() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = A2ASqliteTaskStore::open(
        &path,
        A2ASqliteTaskStoreConfig {
            max_tasks: 1,
            ..config()
        },
    )
    .unwrap();
    let first = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    assert_eq!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-b",
                "request",
                101,
            ))
            .err(),
        Some(A2ATaskStoreError::CapacityExceeded)
    );
    store
        .transition_task(A2ATaskTransition::new(
            first.key().clone(),
            0,
            A2ATaskState::Rejected,
            Some(A2ATerminalReason::parse("not_supported").unwrap()),
            110,
        ))
        .unwrap();
    assert!(matches!(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-b",
                "request",
                130,
            ))
            .unwrap(),
        CreateA2ATaskOutcome::Created(_)
    ));
}

#[test]
fn invalid_capacity_and_retention_configuration_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    for invalid in [
        A2ASqliteTaskStoreConfig {
            max_tasks: 0,
            ..config()
        },
        A2ASqliteTaskStoreConfig {
            max_messages_per_task: 1,
            ..config()
        },
        A2ASqliteTaskStoreConfig {
            idempotency_retention_milliseconds: 10,
            ..config()
        },
        A2ASqliteTaskStoreConfig {
            busy_timeout_milliseconds: 0,
            ..config()
        },
        A2ASqliteTaskStoreConfig {
            max_prune_batch: 0,
            ..config()
        },
    ] {
        assert_eq!(
            A2ASqliteTaskStore::open(root.path().join("invalid.sqlite"), invalid).err(),
            Some(A2ATaskStoreError::InvalidConfiguration)
        );
    }
}

#[test]
fn message_artifact_and_utf8_byte_capacities_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let message_store = A2ASqliteTaskStore::open(
        root.path().join("messages.sqlite"),
        A2ASqliteTaskStoreConfig {
            max_messages_per_task: 2,
            ..config()
        },
    )
    .unwrap();
    let task = created(
        message_store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    message_store
        .append_message(
            A2ATaskMessage::new(
                key.clone(),
                A2AMessageId::parse("response-a").unwrap(),
                A2ATaskMessageRole::Agent,
                "response",
                110,
            )
            .unwrap(),
            110,
        )
        .unwrap();
    assert_eq!(
        message_store
            .append_message(
                A2ATaskMessage::new(
                    key,
                    A2AMessageId::parse("response-b").unwrap(),
                    A2ATaskMessageRole::Agent,
                    "another",
                    111,
                )
                .unwrap(),
                111,
            )
            .err(),
        Some(A2ATaskStoreError::CapacityExceeded)
    );

    let artifact_store = A2ASqliteTaskStore::open(
        root.path().join("artifacts.sqlite"),
        A2ASqliteTaskStoreConfig {
            max_artifacts_per_task: 1,
            ..config()
        },
    )
    .unwrap();
    let task = created(
        artifact_store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-b",
                "request",
                100,
            ))
            .unwrap(),
    );
    artifact_store
        .append_artifact(
            A2ATaskArtifact::new(
                task.key().clone(),
                A2AArtifactId::parse("artifact-a").unwrap(),
                vec![1],
                false,
                110,
            )
            .unwrap(),
            110,
        )
        .unwrap();
    assert_eq!(
        artifact_store
            .append_artifact(
                A2ATaskArtifact::new(
                    task.key().clone(),
                    A2AArtifactId::parse("artifact-b").unwrap(),
                    vec![2],
                    false,
                    111,
                )
                .unwrap(),
                111,
            )
            .err(),
        Some(A2ATaskStoreError::CapacityExceeded)
    );

    let utf8_store = A2ASqliteTaskStore::open(
        root.path().join("utf8.sqlite"),
        A2ASqliteTaskStoreConfig {
            max_payload_bytes: 2,
            ..config()
        },
    )
    .unwrap();
    let task = created(
        utf8_store
            .create_task(creation("agent-a", "tenant-a", 4, 5, "message-c", "é", 100))
            .unwrap(),
    );
    assert_eq!(
        utf8_store
            .append_message(
                A2ATaskMessage::new(
                    task.key().clone(),
                    A2AMessageId::parse("response-c").unwrap(),
                    A2ATaskMessageRole::Agent,
                    "a",
                    110,
                )
                .unwrap(),
                110,
            )
            .err(),
        Some(A2ATaskStoreError::CapacityExceeded)
    );
}

#[test]
fn complete_artifact_is_valid_evidence_but_interrupted_states_are_not() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("tasks.sqlite"));
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    for state in [A2ATaskState::InputRequired, A2ATaskState::AuthRequired] {
        assert_eq!(
            store
                .transition_task(A2ATaskTransition::new(key.clone(), 0, state, None, 110,))
                .err(),
            Some(A2ATaskStoreError::InvalidTransition)
        );
    }
    store
        .append_artifact(
            A2ATaskArtifact::new(
                key.clone(),
                A2AArtifactId::parse("artifact-a").unwrap(),
                vec![1, 2, 3],
                true,
                110,
            )
            .unwrap(),
            110,
        )
        .unwrap();
    let completed = store
        .transition_task(A2ATaskTransition::new(
            key,
            0,
            A2ATaskState::Completed,
            None,
            120,
        ))
        .unwrap();
    assert!(matches!(completed, TransitionA2ATaskOutcome::Applied(_)));
}

#[test]
fn concurrent_transitions_commit_only_one_generation() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(open(&root.path().join("tasks.sqlite")));
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for (state, reason) in [
        (A2ATaskState::Working, None),
        (
            A2ATaskState::Failed,
            Some(A2ATerminalReason::parse("failed").unwrap()),
        ),
    ] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let key = key.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            store.transition_task(A2ATaskTransition::new(key, 0, state, reason, 110))
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(A2ATaskStoreError::Conflict)))
            .count(),
        1
    );
    assert_eq!(store.get_task(&key).unwrap().generation(), 1);
}

#[test]
fn schema_pragmas_and_corruption_checks_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = open(&path);
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap()
            .to_ascii_lowercase(),
        "wal"
    );
    assert_eq!(
        connection
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    connection
        .execute(
            "UPDATE a2a_task SET request_message_id = ?1
             WHERE agent_id = ?2 AND tenant_id = ?3 AND task_id = ?4",
            params![
                [9_u8; 16].as_slice(),
                key.agent_id().as_str(),
                key.tenant().unwrap().as_str(),
                key.task_id().as_str()
            ],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        open(&path).get_task(&key).err(),
        Some(A2ATaskStoreError::CorruptData)
    );
}

#[test]
fn unsupported_schema_and_status_history_tampering_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let partial_path = root.path().join("partial.sqlite");
    let connection = Connection::open(&partial_path).unwrap();
    connection
        .execute("CREATE TABLE a2a_task (unexpected INTEGER)", [])
        .unwrap();
    drop(connection);
    assert_eq!(
        A2ASqliteTaskStore::open(&partial_path, config()).err(),
        Some(A2ATaskStoreError::CorruptData)
    );

    let version_path = root.path().join("version.sqlite");
    drop(open(&version_path));
    let connection = Connection::open(&version_path).unwrap();
    connection
        .execute(
            "UPDATE a2a_store_meta SET schema_version = 2 WHERE singleton_id = 1",
            [],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        A2ASqliteTaskStore::open(&version_path, config()).err(),
        Some(A2ATaskStoreError::CorruptData)
    );

    let status_path = root.path().join("status.sqlite");
    let store = open(&status_path);
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    drop(store);
    let connection = Connection::open(&status_path).unwrap();
    connection
        .execute(
            "UPDATE a2a_task_status SET state = 2
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3 AND generation = 0",
            params![
                key.agent_id().as_str(),
                key.tenant().unwrap().as_str(),
                key.task_id().as_str()
            ],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        open(&status_path).get_task(&key).err(),
        Some(A2ATaskStoreError::CorruptData)
    );

    let context_path = root.path().join("context.sqlite");
    let store = open(&context_path);
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-b",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    drop(store);
    let connection = Connection::open(&context_path).unwrap();
    connection
        .execute(
            "DELETE FROM a2a_task
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3",
            params![
                key.agent_id().as_str(),
                key.tenant().unwrap().as_str(),
                key.task_id().as_str()
            ],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        A2ASqliteTaskStore::open(&context_path, config()).err(),
        Some(A2ATaskStoreError::CorruptData)
    );
}

#[test]
fn pruned_tombstone_identity_remains_self_verifying() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = open(&path);
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    store
        .transition_task(A2ATaskTransition::new(
            key.clone(),
            0,
            A2ATaskState::Rejected,
            Some(A2ATerminalReason::parse("not_supported").unwrap()),
            110,
        ))
        .unwrap();
    store.prune(120).unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE a2a_context SET conversation_id = ?1
             WHERE agent_id = ?2 AND tenant_id = ?3 AND context_id = ?4",
            params![
                [9_u8; 32].as_slice(),
                key.agent_id().as_str(),
                key.tenant().unwrap().as_str(),
                "context-a"
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE a2a_task SET conversation_id = ?1
             WHERE agent_id = ?2 AND tenant_id = ?3 AND task_id = ?4",
            params![
                [9_u8; 32].as_slice(),
                key.agent_id().as_str(),
                key.tenant().unwrap().as_str(),
                key.task_id().as_str()
            ],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        open(&path).get_task(&key).err(),
        Some(A2ATaskStoreError::CorruptData)
    );
}

#[test]
fn duplicate_append_revalidates_the_existing_record() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("tasks.sqlite");
    let store = open(&path);
    let task = created(
        store
            .create_task(creation(
                "agent-a",
                "tenant-a",
                4,
                5,
                "message-a",
                "request",
                100,
            ))
            .unwrap(),
    );
    let key = task.key().clone();
    let response_id = A2AMessageId::parse("response-a").unwrap();
    store
        .append_message(
            A2ATaskMessage::new(
                key.clone(),
                response_id.clone(),
                A2ATaskMessageRole::Agent,
                "response",
                110,
            )
            .unwrap(),
            110,
        )
        .unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE a2a_task_message SET identity_digest = ?1
             WHERE agent_id = ?2 AND tenant_id = ?3 AND task_id = ?4
               AND message_id = ?5",
            params![
                [9_u8; 32].as_slice(),
                key.agent_id().as_str(),
                key.tenant().unwrap().as_str(),
                key.task_id().as_str(),
                response_id.as_str()
            ],
        )
        .unwrap();
    drop(connection);

    let reopened = open(&path);
    assert_eq!(
        reopened
            .append_message(
                A2ATaskMessage::new(key, response_id, A2ATaskMessageRole::Agent, "response", 999,)
                    .unwrap(),
                999,
            )
            .err(),
        Some(A2ATaskStoreError::CorruptData)
    );
}
