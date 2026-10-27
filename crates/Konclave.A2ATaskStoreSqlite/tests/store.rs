use std::path::Path;

use KonclaveA2ADomain::{A2AMessageId, A2ATaskState};
use KonclaveA2ATaskStore::test_support::{
    A2ATaskStoreContractConfig, A2ATaskStoreContractFixture, assert_a2a_task_store_contract,
    created, creation,
};
use KonclaveA2ATaskStore::{
    A2ATaskMessage, A2ATaskMessageRole, A2ATaskStore, A2ATaskStoreError, A2ATaskTransition,
    A2ATerminalReason,
};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use rusqlite::{Connection, params};

fn sqlite_config(config: A2ATaskStoreContractConfig) -> A2ASqliteTaskStoreConfig {
    A2ASqliteTaskStoreConfig {
        max_tasks: config.max_tasks,
        max_messages_per_task: config.max_messages_per_task,
        max_artifacts_per_task: config.max_artifacts_per_task,
        max_payload_bytes: config.max_payload_bytes,
        max_prune_batch: config.max_prune_batch,
        content_retention_milliseconds: config.content_retention_milliseconds,
        idempotency_retention_milliseconds: config.idempotency_retention_milliseconds,
        busy_timeout_milliseconds: 1_000,
    }
}

fn config() -> A2ASqliteTaskStoreConfig {
    sqlite_config(A2ATaskStoreContractConfig::default())
}

fn open(path: &Path) -> A2ASqliteTaskStore {
    A2ASqliteTaskStore::open(path, config()).unwrap()
}

struct SqliteContractFixture {
    root: tempfile::TempDir,
}

impl A2ATaskStoreContractFixture for SqliteContractFixture {
    type Store = A2ASqliteTaskStore;

    fn open(&self, config: A2ATaskStoreContractConfig) -> Result<Self::Store, A2ATaskStoreError> {
        A2ASqliteTaskStore::open(self.root.path().join("tasks.sqlite"), sqlite_config(config))
    }
}

#[test]
fn portable_task_store_contract() {
    assert_a2a_task_store_contract(|| SqliteContractFixture {
        root: tempfile::tempdir().unwrap(),
    });
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
        "delete"
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

    let trigger_path = root.path().join("trigger.sqlite");
    drop(open(&trigger_path));
    let connection = Connection::open(&trigger_path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER a2a_delete_tasks
             AFTER INSERT ON a2a_task_message
             BEGIN
                 DELETE FROM a2a_task;
             END;",
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        A2ASqliteTaskStore::open(&trigger_path, config()).err(),
        Some(A2ATaskStoreError::CorruptData)
    );

    let hidden_index_path = root.path().join("hidden-index.sqlite");
    drop(open(&hidden_index_path));
    let connection = Connection::open(&hidden_index_path).unwrap();
    connection
        .execute(
            "CREATE INDEX attacker_index ON a2a_task_message(message_id)",
            [],
        )
        .unwrap();
    connection
        .pragma_update(None, "writable_schema", "ON")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema
             SET name = 'sqlite_hidden',
                 sql = 'CREATE INDEX sqlite_hidden ON a2a_task_message(message_id)'
             WHERE name = 'attacker_index'",
            [],
        )
        .unwrap();
    connection
        .pragma_update(None, "writable_schema", "OFF")
        .unwrap();
    drop(connection);
    assert_eq!(
        A2ASqliteTaskStore::open(&hidden_index_path, config()).err(),
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
