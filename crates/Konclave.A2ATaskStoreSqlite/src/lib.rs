#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::{Arc, Barrier};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use KonclaveA2ADomain::{
    A2AAgentId, A2AArtifactId, A2AContextId, A2AMessageId, A2ATaskId, A2ATaskState, A2ATenantId,
};
use KonclaveA2ATaskStore::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskKey, A2ATaskMessage, A2ATaskMessageRole,
    A2ATaskPruneOutcome, A2ATaskRecord, A2ATaskStore, A2ATaskStoreError, A2ATaskTransition,
    A2ATerminalReason, AppendA2ATaskRecordOutcome, CreateA2ATaskOutcome, StoredA2ATaskArtifact,
    StoredA2ATaskMessage, TransitionA2ATaskOutcome,
};
use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

const SCHEMA_VERSION: u32 = 1;
const HARD_MAX_SCHEMA_OBJECT_COUNT: i64 = 16;
const MAX_SCHEMA_IDENTIFIER_BYTES: i64 = 128;
const MAX_SCHEMA_SQL_BYTES: i64 = 4_096;
const MAX_PAGE_SIZE: usize = 256;
const HARD_MAX_TASKS: usize = 100_000;
const HARD_MAX_PAYLOAD_BYTES: usize = 1024 * 1024 * 1024;
const HARD_MAX_RETENTION_MILLISECONDS: u64 = 10 * 365 * 24 * 60 * 60 * 1_000;
const HARD_MAX_BUSY_TIMEOUT_MILLISECONDS: u64 = 60_000;
const HARD_MAX_PRUNE_BATCH: usize = 1_024;
const CREATE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS a2a_store_meta (
        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
        schema_version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS a2a_context (
        agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        context_id TEXT NOT NULL,
        conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 32),
        target_device_id BLOB NOT NULL CHECK (length(target_device_id) = 32),
        created_at_unix_milliseconds INTEGER NOT NULL,
        PRIMARY KEY (agent_id, tenant_id, context_id)
    );
    CREATE TABLE IF NOT EXISTS a2a_task (
        agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        context_id TEXT NOT NULL,
        source_message_id TEXT NOT NULL,
        conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 32),
        target_device_id BLOB NOT NULL CHECK (length(target_device_id) = 32),
        request_message_id BLOB NOT NULL CHECK (length(request_message_id) = 16),
        identity_digest BLOB NOT NULL CHECK (length(identity_digest) = 32),
        return_immediately INTEGER NOT NULL CHECK (return_immediately IN (0, 1)),
        history_length INTEGER,
        state INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        created_at_unix_milliseconds INTEGER NOT NULL,
        updated_at_unix_milliseconds INTEGER NOT NULL,
        terminal_at_unix_milliseconds INTEGER,
        terminal_reason TEXT,
        content_pruned INTEGER NOT NULL CHECK (content_pruned IN (0, 1)),
        content_expires_at_unix_milliseconds INTEGER,
        tombstone_expires_at_unix_milliseconds INTEGER,
        request_text_digest BLOB NOT NULL CHECK (length(request_text_digest) = 32),
        PRIMARY KEY (agent_id, tenant_id, task_id),
        FOREIGN KEY (agent_id, tenant_id, context_id)
            REFERENCES a2a_context(agent_id, tenant_id, context_id)
    );
    CREATE TABLE IF NOT EXISTS a2a_task_status (
        agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        state INTEGER NOT NULL,
        terminal_reason TEXT,
        occurred_at_unix_milliseconds INTEGER NOT NULL,
        PRIMARY KEY (agent_id, tenant_id, task_id, generation),
        FOREIGN KEY (agent_id, tenant_id, task_id)
            REFERENCES a2a_task(agent_id, tenant_id, task_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS a2a_task_message (
        agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        message_id TEXT NOT NULL,
        role INTEGER NOT NULL,
        text TEXT NOT NULL,
        identity_digest BLOB NOT NULL CHECK (length(identity_digest) = 32),
        recorded_at_unix_milliseconds INTEGER NOT NULL,
        PRIMARY KEY (agent_id, tenant_id, task_id, sequence),
        UNIQUE (agent_id, tenant_id, task_id, message_id),
        FOREIGN KEY (agent_id, tenant_id, task_id)
            REFERENCES a2a_task(agent_id, tenant_id, task_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS a2a_task_artifact (
        agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        artifact_id TEXT NOT NULL,
        content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
        canonical_bytes BLOB NOT NULL,
        complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
        identity_digest BLOB NOT NULL CHECK (length(identity_digest) = 32),
        recorded_at_unix_milliseconds INTEGER NOT NULL,
        PRIMARY KEY (agent_id, tenant_id, task_id, sequence),
        UNIQUE (agent_id, tenant_id, task_id, artifact_id),
        FOREIGN KEY (agent_id, tenant_id, task_id)
            REFERENCES a2a_task(agent_id, tenant_id, task_id) ON DELETE CASCADE
    );";
type ExistingArtifactRow = (i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64);

/// Validated capacities and retention windows for one SQLite task store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2ASqliteTaskStoreConfig {
    /// Maximum retained task rows, including tombstones.
    pub max_tasks: usize,
    /// Maximum retained messages for one task.
    pub max_messages_per_task: usize,
    /// Maximum retained artifacts for one task.
    pub max_artifacts_per_task: usize,
    /// Maximum aggregate retained message and artifact payload bytes.
    pub max_payload_bytes: usize,
    /// Maximum terminal tasks processed by one retention transaction.
    pub max_prune_batch: usize,
    /// Time terminal payload remains readable.
    pub content_retention_milliseconds: u64,
    /// Time terminal identity remains idempotent.
    pub idempotency_retention_milliseconds: u64,
    /// SQLite busy timeout.
    pub busy_timeout_milliseconds: u64,
}

impl Default for A2ASqliteTaskStoreConfig {
    fn default() -> Self {
        Self {
            max_tasks: 1_024,
            max_messages_per_task: 256,
            max_artifacts_per_task: 64,
            max_payload_bytes: 64 * 1024 * 1024,
            max_prune_batch: 256,
            content_retention_milliseconds: 7 * 24 * 60 * 60 * 1_000,
            idempotency_retention_milliseconds: 30 * 24 * 60 * 60 * 1_000,
            busy_timeout_milliseconds: 5_000,
        }
    }
}

impl A2ASqliteTaskStoreConfig {
    fn validate(self) -> Result<Self, A2ATaskStoreError> {
        if self.max_tasks == 0
            || self.max_tasks > HARD_MAX_TASKS
            || self.max_messages_per_task < 2
            || self.max_messages_per_task > MAX_PAGE_SIZE
            || self.max_artifacts_per_task == 0
            || self.max_artifacts_per_task > MAX_PAGE_SIZE
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > HARD_MAX_PAYLOAD_BYTES
            || self.max_prune_batch == 0
            || self.max_prune_batch > HARD_MAX_PRUNE_BATCH
            || self.content_retention_milliseconds == 0
            || self.content_retention_milliseconds > HARD_MAX_RETENTION_MILLISECONDS
            || self.idempotency_retention_milliseconds <= self.content_retention_milliseconds
            || self.idempotency_retention_milliseconds > HARD_MAX_RETENTION_MILLISECONDS
            || self.busy_timeout_milliseconds == 0
            || self.busy_timeout_milliseconds > HARD_MAX_BUSY_TIMEOUT_MILLISECONDS
        {
            return Err(A2ATaskStoreError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Complete public SQLite implementation of the A2A task-store contract.
pub struct A2ASqliteTaskStore {
    connection: Mutex<Connection>,
    config: A2ASqliteTaskStoreConfig,
    #[cfg(test)]
    test_hooks: TestHooks,
}

#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    fail_after_task_insert: AtomicBool,
    snapshot_after_task_load: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    prune_before_commit: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
}

impl A2ASqliteTaskStore {
    /// Opens or initializes one SQLite task store.
    ///
    /// # Errors
    ///
    /// Returns configuration, schema, storage, or corruption errors.
    pub fn open(
        path: impl AsRef<Path>,
        config: A2ASqliteTaskStoreConfig,
    ) -> Result<Self, A2ATaskStoreError> {
        let config = config.validate()?;
        let mut connection = Connection::open(path).map_err(|_| A2ATaskStoreError::Storage)?;
        configure_connection_security(&connection)?;
        connection
            .busy_timeout(Duration::from_millis(config.busy_timeout_milliseconds))
            .map_err(|_| A2ATaskStoreError::Storage)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| A2ATaskStoreError::Storage)?;
        initialize_schema(&mut connection)?;
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .map_err(|_| A2ATaskStoreError::Storage)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| A2ATaskStoreError::Storage)?;
        verify_pragmas(&connection, config.busy_timeout_milliseconds)?;
        verify_store_bounds(&connection, config)?;
        Ok(Self {
            connection: Mutex::new(connection),
            config,
            #[cfg(test)]
            test_hooks: TestHooks::default(),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, A2ATaskStoreError> {
        self.connection
            .lock()
            .map_err(|_| A2ATaskStoreError::Storage)
    }
}

impl A2ATaskStore for A2ASqliteTaskStore {
    fn create_task(
        &self,
        creation: A2ATaskCreation,
    ) -> Result<CreateA2ATaskOutcome, A2ATaskStoreError> {
        let identity_digest = creation.identity_digest();
        let initial_message = A2ATaskMessage::new(
            creation.key().clone(),
            creation.source_message_id().clone(),
            A2ATaskMessageRole::User,
            creation.request_text().to_owned(),
            creation.created_at_unix_milliseconds(),
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        prune_in(
            &transaction,
            self.config,
            creation.created_at_unix_milliseconds(),
        )?;
        ensure_context_binding(&transaction, &creation, self.config)?;
        if let Some(existing) = load_task_optional(&transaction, creation.key())? {
            if existing.identity_digest() == &identity_digest {
                transaction
                    .commit()
                    .map_err(|_| A2ATaskStoreError::Storage)?;
                return Ok(CreateA2ATaskOutcome::Existing(existing));
            }
            return Err(A2ATaskStoreError::Conflict);
        }
        require_task_capacity(&transaction, self.config)?;
        require_payload_capacity(&transaction, self.config, initial_message.text().len())?;
        let changed = transaction
            .execute(
                "INSERT INTO a2a_task (
                    agent_id, tenant_id, task_id, context_id, source_message_id,
                    conversation_id, target_device_id, request_message_id,
                    identity_digest, return_immediately, history_length, state,
                    generation, created_at_unix_milliseconds,
                    updated_at_unix_milliseconds, terminal_at_unix_milliseconds,
                    terminal_reason, content_pruned,
                    content_expires_at_unix_milliseconds,
                    tombstone_expires_at_unix_milliseconds,
                    request_text_digest
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, 0,
                    ?12, ?12, NULL, NULL, 0, NULL, NULL, ?13
                 )",
                params![
                    creation.key().agent_id().as_str(),
                    tenant_value(creation.key()),
                    creation.key().task_id().as_str(),
                    creation.context_id().as_str(),
                    creation.source_message_id().as_str(),
                    creation.conversation_id().as_bytes().as_slice(),
                    creation.target_device_id().as_bytes().as_slice(),
                    creation.request_message_id().as_bytes().as_slice(),
                    identity_digest.as_slice(),
                    i64::from(creation.return_immediately()),
                    creation.history_length().map(i64::from),
                    to_sql(creation.created_at_unix_milliseconds())?,
                    creation.request_text_digest().as_slice(),
                ],
            )
            .map_err(map_insert_error)?;
        if changed != 1 {
            return Err(A2ATaskStoreError::CorruptData);
        }
        #[cfg(test)]
        if self
            .test_hooks
            .fail_after_task_insert
            .swap(false, Ordering::SeqCst)
        {
            return Err(A2ATaskStoreError::Storage);
        }
        insert_status(
            &transaction,
            creation.key(),
            0,
            A2ATaskState::Submitted,
            None,
            creation.created_at_unix_milliseconds(),
        )?;
        insert_message(&transaction, &initial_message, 1)?;
        let task = load_task(&transaction, creation.key())?;
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
        Ok(CreateA2ATaskOutcome::Created(task))
    }

    fn get_task(&self, key: &A2ATaskKey) -> Result<A2ATaskRecord, A2ATaskStoreError> {
        let connection = self.lock()?;
        load_task(&connection, key)
    }

    fn transition_task(
        &self,
        transition: A2ATaskTransition,
    ) -> Result<TransitionA2ATaskOutcome, A2ATaskStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        let current = load_task(&transaction, transition.key())?;
        if current.generation() != transition.expected_generation() {
            if transition
                .expected_generation()
                .checked_add(1)
                .is_some_and(|generation| generation == current.generation())
                && current.state() == transition.state()
                && terminal_reasons_equal(current.terminal_reason(), transition.terminal_reason())
            {
                transaction
                    .commit()
                    .map_err(|_| A2ATaskStoreError::Storage)?;
                return Ok(TransitionA2ATaskOutcome::Existing(current));
            }
            return Err(A2ATaskStoreError::Conflict);
        }
        validate_transition(&transaction, &current, &transition)?;
        let generation = current
            .generation()
            .checked_add(1)
            .ok_or(A2ATaskStoreError::CorruptData)?;
        let terminal = is_terminal(transition.state());
        let (terminal_at, content_expires_at, tombstone_expires_at) = if terminal {
            let terminal_at = transition.occurred_at_unix_milliseconds();
            (
                Some(terminal_at),
                Some(
                    terminal_at
                        .checked_add(self.config.content_retention_milliseconds)
                        .ok_or(A2ATaskStoreError::InvalidConfiguration)?,
                ),
                Some(
                    terminal_at
                        .checked_add(self.config.idempotency_retention_milliseconds)
                        .ok_or(A2ATaskStoreError::InvalidConfiguration)?,
                ),
            )
        } else {
            (None, None, None)
        };
        let changed = transaction
            .execute(
                "UPDATE a2a_task
                 SET state = ?1,
                     generation = ?2,
                     updated_at_unix_milliseconds = ?3,
                     terminal_at_unix_milliseconds = ?4,
                     terminal_reason = ?5,
                     content_expires_at_unix_milliseconds = ?6,
                     tombstone_expires_at_unix_milliseconds = ?7
                 WHERE agent_id = ?8 AND tenant_id = ?9 AND task_id = ?10
                   AND generation = ?11",
                params![
                    state_code(transition.state()),
                    to_sql(generation)?,
                    to_sql(transition.occurred_at_unix_milliseconds())?,
                    terminal_at.map(to_sql).transpose()?,
                    transition.terminal_reason().map(A2ATerminalReason::as_str),
                    content_expires_at.map(to_sql).transpose()?,
                    tombstone_expires_at.map(to_sql).transpose()?,
                    transition.key().agent_id().as_str(),
                    tenant_value(transition.key()),
                    transition.key().task_id().as_str(),
                    to_sql(current.generation())?,
                ],
            )
            .map_err(|_| A2ATaskStoreError::Storage)?;
        if changed != 1 {
            return Err(A2ATaskStoreError::Conflict);
        }
        insert_status(
            &transaction,
            transition.key(),
            generation,
            transition.state(),
            transition.terminal_reason(),
            transition.occurred_at_unix_milliseconds(),
        )?;
        let task = load_task(&transaction, transition.key())?;
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
        Ok(TransitionA2ATaskOutcome::Applied(task))
    }

    fn append_message(
        &self,
        message: A2ATaskMessage,
        now_unix_milliseconds: u64,
    ) -> Result<AppendA2ATaskRecordOutcome, A2ATaskStoreError> {
        let digest = message.identity_digest();
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        prune_in(&transaction, self.config, now_unix_milliseconds)?;
        let task = load_task(&transaction, message.key())?;
        if let Some((sequence, existing_digest)) =
            existing_message(&transaction, message.key(), message.message_id())?
        {
            if existing_digest == digest {
                transaction
                    .commit()
                    .map_err(|_| A2ATaskStoreError::Storage)?;
                return Ok(AppendA2ATaskRecordOutcome::Existing { sequence });
            }
            return Err(A2ATaskStoreError::Conflict);
        }
        if is_terminal(task.state()) || task.content_pruned() {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
        let count = record_count(&transaction, "a2a_task_message", message.key())?;
        if count >= self.config.max_messages_per_task {
            return Err(A2ATaskStoreError::CapacityExceeded);
        }
        require_payload_capacity(&transaction, self.config, message.text().len())?;
        let sequence = u64::try_from(count)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(A2ATaskStoreError::CorruptData)?;
        insert_message(&transaction, &message, sequence)?;
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
        Ok(AppendA2ATaskRecordOutcome::Appended { sequence })
    }

    fn append_artifact(
        &self,
        artifact: A2ATaskArtifact,
        now_unix_milliseconds: u64,
    ) -> Result<AppendA2ATaskRecordOutcome, A2ATaskStoreError> {
        let digest = artifact.identity_digest();
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        prune_in(&transaction, self.config, now_unix_milliseconds)?;
        let task = load_task(&transaction, artifact.key())?;
        if let Some((sequence, existing_digest)) =
            existing_artifact(&transaction, artifact.key(), artifact.artifact_id())?
        {
            if existing_digest == digest {
                transaction
                    .commit()
                    .map_err(|_| A2ATaskStoreError::Storage)?;
                return Ok(AppendA2ATaskRecordOutcome::Existing { sequence });
            }
            return Err(A2ATaskStoreError::Conflict);
        }
        if is_terminal(task.state()) || task.content_pruned() {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
        let count = record_count(&transaction, "a2a_task_artifact", artifact.key())?;
        if count >= self.config.max_artifacts_per_task {
            return Err(A2ATaskStoreError::CapacityExceeded);
        }
        require_payload_capacity(&transaction, self.config, artifact.canonical_bytes().len())?;
        let sequence = u64::try_from(count)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(A2ATaskStoreError::CorruptData)?;
        insert_artifact(&transaction, &artifact, sequence)?;
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
        Ok(AppendA2ATaskRecordOutcome::Appended { sequence })
    }

    fn messages(
        &self,
        key: &A2ATaskKey,
        limit: usize,
    ) -> Result<Vec<StoredA2ATaskMessage>, A2ATaskStoreError> {
        validate_page_limit(limit, self.config.max_messages_per_task)?;
        let connection = self.lock()?;
        let task = load_task(&connection, key)?;
        if task.content_pruned() {
            return Ok(Vec::new());
        }
        load_messages(&connection, key, limit)
    }

    fn task_with_messages(
        &self,
        key: &A2ATaskKey,
        limit: usize,
    ) -> Result<(A2ATaskRecord, Vec<StoredA2ATaskMessage>), A2ATaskStoreError> {
        validate_page_limit(limit, self.config.max_messages_per_task)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        let task = load_task(&transaction, key)?;
        #[cfg(test)]
        run_test_barrier(&self.test_hooks.snapshot_after_task_load);
        let messages = if task.content_pruned() {
            Vec::new()
        } else {
            load_messages(&transaction, key, limit)?
        };
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
        Ok((task, messages))
    }

    fn artifacts(
        &self,
        key: &A2ATaskKey,
        limit: usize,
    ) -> Result<Vec<StoredA2ATaskArtifact>, A2ATaskStoreError> {
        validate_page_limit(limit, self.config.max_artifacts_per_task)?;
        let connection = self.lock()?;
        let task = load_task(&connection, key)?;
        if task.content_pruned() {
            return Ok(Vec::new());
        }
        load_artifacts(&connection, key, limit)
    }

    fn prune(&self, now_unix_milliseconds: u64) -> Result<A2ATaskPruneOutcome, A2ATaskStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        let outcome = prune_in(&transaction, self.config, now_unix_milliseconds)?;
        #[cfg(test)]
        run_test_barrier(&self.test_hooks.prune_before_commit);
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
        Ok(outcome)
    }
}

#[derive(PartialEq, Eq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

fn configure_connection_security(connection: &Connection) -> Result<(), A2ATaskStoreError> {
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_WRITABLE_SCHEMA, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
}

fn set_db_config(
    connection: &Connection,
    config: DbConfig,
    enabled: bool,
) -> Result<(), A2ATaskStoreError> {
    let configured = connection
        .set_db_config(config, enabled)
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if configured != enabled {
        return Err(A2ATaskStoreError::Storage);
    }
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<(), A2ATaskStoreError> {
    let expected_objects = expected_schema_objects()?;
    let existing_objects = schema_objects(connection)?;
    if !existing_objects.is_empty() && existing_objects != expected_objects {
        return Err(A2ATaskStoreError::CorruptData);
    }
    if existing_objects.is_empty() {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        transaction
            .execute_batch(CREATE_SCHEMA_SQL)
            .map_err(|_| A2ATaskStoreError::Storage)?;
        transaction
            .execute(
                "INSERT INTO a2a_store_meta (singleton_id, schema_version) VALUES (1, ?1)",
                params![i64::from(SCHEMA_VERSION)],
            )
            .map_err(|_| A2ATaskStoreError::Storage)?;
        transaction
            .commit()
            .map_err(|_| A2ATaskStoreError::Storage)?;
    }
    if schema_objects(connection)? != expected_objects {
        return Err(A2ATaskStoreError::CorruptData);
    }
    let version: Option<i64> = connection
        .query_row(
            "SELECT schema_version FROM a2a_store_meta WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if version != Some(i64::from(SCHEMA_VERSION)) {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

fn expected_schema_objects() -> Result<Vec<SchemaObject>, A2ATaskStoreError> {
    let connection = Connection::open_in_memory().map_err(|_| A2ATaskStoreError::Storage)?;
    connection
        .execute_batch(CREATE_SCHEMA_SQL)
        .map_err(|_| A2ATaskStoreError::Storage)?;
    schema_objects(&connection)
}

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, A2ATaskStoreError> {
    let metrics: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(MAX(length(CAST(type AS BLOB))), 0),
                    COALESCE(MAX(length(CAST(name AS BLOB))), 0),
                    COALESCE(MAX(length(CAST(tbl_name AS BLOB))), 0),
                    COALESCE(MAX(length(CAST(sql AS BLOB))), 0)
             FROM sqlite_schema
             ",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if metrics.0 > HARD_MAX_SCHEMA_OBJECT_COUNT
        || metrics.1 > MAX_SCHEMA_IDENTIFIER_BYTES
        || metrics.2 > MAX_SCHEMA_IDENTIFIER_BYTES
        || metrics.3 > MAX_SCHEMA_IDENTIFIER_BYTES
        || metrics.4 > MAX_SCHEMA_SQL_BYTES
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_schema
             ORDER BY type, name
             LIMIT 17",
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| A2ATaskStoreError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    rows.into_iter()
        .map(|row| {
            Ok(SchemaObject {
                object_type: row.0,
                name: row.1,
                table_name: row.2,
                sql: row.3,
            })
        })
        .collect()
}

fn verify_pragmas(
    connection: &Connection,
    expected_busy_timeout_milliseconds: u64,
) -> Result<(), A2ATaskStoreError> {
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if foreign_keys != 1
        || !journal_mode.eq_ignore_ascii_case("delete")
        || synchronous != 2
        || from_sql(busy_timeout)? != expected_busy_timeout_milliseconds
    {
        return Err(A2ATaskStoreError::Storage);
    }
    Ok(())
}

fn verify_store_bounds(
    connection: &Connection,
    config: A2ASqliteTaskStoreConfig,
) -> Result<(), A2ATaskStoreError> {
    let tasks: i64 = connection
        .query_row("SELECT count(*) FROM a2a_task", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let contexts: i64 = connection
        .query_row("SELECT count(*) FROM a2a_context", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let max_messages: i64 = connection
        .query_row(
            "SELECT COALESCE(max(record_count), 0)
             FROM (
                SELECT count(*) AS record_count
                FROM a2a_task_message
                GROUP BY agent_id, tenant_id, task_id
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let max_artifacts: i64 = connection
        .query_row(
            "SELECT COALESCE(max(record_count), 0)
             FROM (
                SELECT count(*) AS record_count
                FROM a2a_task_artifact
                GROUP BY agent_id, tenant_id, task_id
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let invalid_context_relationship: bool = connection
        .query_row(
            "SELECT EXISTS (
                SELECT 1
                FROM a2a_context c
                LEFT JOIN a2a_task t
                  ON t.agent_id = c.agent_id
                 AND t.tenant_id = c.tenant_id
                 AND t.context_id = c.context_id
                WHERE t.task_id IS NULL
                UNION ALL
                SELECT 1
                FROM a2a_task t
                LEFT JOIN a2a_context c
                  ON c.agent_id = t.agent_id
                 AND c.tenant_id = t.tenant_id
                 AND c.context_id = t.context_id
                WHERE c.context_id IS NULL
                   OR c.conversation_id != t.conversation_id
                   OR c.target_device_id != t.target_device_id
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let payload_bytes = retained_payload_bytes(connection)?;
    if usize::try_from(tasks)
        .ok()
        .is_none_or(|value| value > config.max_tasks)
        || usize::try_from(contexts)
            .ok()
            .is_none_or(|value| value > config.max_tasks)
        || usize::try_from(max_messages)
            .ok()
            .is_none_or(|value| value > config.max_messages_per_task)
        || usize::try_from(max_artifacts)
            .ok()
            .is_none_or(|value| value > config.max_artifacts_per_task)
        || payload_bytes > config.max_payload_bytes
    {
        return Err(A2ATaskStoreError::CapacityExceeded);
    }
    if invalid_context_relationship {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

fn ensure_context_binding(
    transaction: &Transaction<'_>,
    creation: &A2ATaskCreation,
    config: A2ASqliteTaskStoreConfig,
) -> Result<(), A2ATaskStoreError> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT conversation_id, target_device_id
             FROM a2a_context
             WHERE agent_id = ?1 AND tenant_id = ?2 AND context_id = ?3",
            params![
                creation.key().agent_id().as_str(),
                tenant_value(creation.key()),
                creation.context_id().as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if let Some((conversation, target)) = existing {
        if ConversationId::from_slice(&conversation).map_err(|_| A2ATaskStoreError::CorruptData)?
            != creation.conversation_id()
            || DeviceId::from_slice(&target).map_err(|_| A2ATaskStoreError::CorruptData)?
                != creation.target_device_id()
        {
            return Err(A2ATaskStoreError::Conflict);
        }
        return Ok(());
    }
    let orphaned_task: bool = transaction
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM a2a_task
                WHERE agent_id = ?1 AND tenant_id = ?2 AND context_id = ?3
             )",
            params![
                creation.key().agent_id().as_str(),
                tenant_value(creation.key()),
                creation.context_id().as_str()
            ],
            |row| row.get(0),
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if orphaned_task {
        return Err(A2ATaskStoreError::CorruptData);
    }
    let contexts: i64 = transaction
        .query_row("SELECT count(*) FROM a2a_context", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if usize::try_from(contexts)
        .ok()
        .is_none_or(|count| count >= config.max_tasks)
    {
        return Err(A2ATaskStoreError::CapacityExceeded);
    }
    transaction
        .execute(
            "INSERT INTO a2a_context (
                agent_id, tenant_id, context_id, conversation_id,
                target_device_id, created_at_unix_milliseconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                creation.key().agent_id().as_str(),
                tenant_value(creation.key()),
                creation.context_id().as_str(),
                creation.conversation_id().as_bytes().as_slice(),
                creation.target_device_id().as_bytes().as_slice(),
                to_sql(creation.created_at_unix_milliseconds())?
            ],
        )
        .map_err(map_insert_error)?;
    Ok(())
}

fn load_task(
    connection: &Connection,
    key: &A2ATaskKey,
) -> Result<A2ATaskRecord, A2ATaskStoreError> {
    load_task_optional(connection, key)?.ok_or(A2ATaskStoreError::NotFound)
}

fn load_task_optional(
    connection: &Connection,
    key: &A2ATaskKey,
) -> Result<Option<A2ATaskRecord>, A2ATaskStoreError> {
    let row = connection
        .query_row(
            "SELECT context_id, source_message_id, conversation_id, target_device_id,
                    request_message_id, identity_digest, return_immediately,
                    history_length, state, generation, created_at_unix_milliseconds,
                    updated_at_unix_milliseconds, terminal_at_unix_milliseconds,
                    terminal_reason, content_pruned,
                    content_expires_at_unix_milliseconds,
                    tombstone_expires_at_unix_milliseconds,
                    request_text_digest
             FROM a2a_task
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3",
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Option<i64>>(15)?,
                    row.get::<_, Option<i64>>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                ))
            },
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let request_text = if row.14 == 0 {
        connection
            .query_row(
                "SELECT text FROM a2a_task_message
                 WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
                   AND sequence = 1",
                params![
                    key.agent_id().as_str(),
                    tenant_value(key),
                    key.task_id().as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| A2ATaskStoreError::Storage)?
    } else {
        None
    };
    let terminal_reason = row
        .13
        .map(A2ATerminalReason::parse)
        .transpose()
        .map_err(|_| A2ATaskStoreError::CorruptData)?;
    let content_pruned = parse_bool(row.14)?;
    let content_expires_at = row.15.map(from_sql).transpose()?;
    let tombstone_expires_at = row.16.map(from_sql).transpose()?;
    if (!content_pruned && request_text.is_none())
        || request_text
            .as_ref()
            .is_some_and(|text| text.is_empty() || text.len() > 64 * 1024)
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    let state = state_from_code(row.8)?;
    let terminal_at = row.12.map(from_sql).transpose()?;
    validate_task_shape(
        state,
        from_sql(row.9)?,
        from_sql(row.11)?,
        terminal_at,
        terminal_reason.as_ref(),
        content_pruned,
        content_expires_at,
        tombstone_expires_at,
    )?;
    let record = A2ATaskRecord::new(
        key.clone(),
        A2AContextId::parse(row.0).map_err(|_| A2ATaskStoreError::CorruptData)?,
        A2AMessageId::parse(row.1).map_err(|_| A2ATaskStoreError::CorruptData)?,
        ConversationId::from_slice(&row.2).map_err(|_| A2ATaskStoreError::CorruptData)?,
        DeviceId::from_slice(&row.3).map_err(|_| A2ATaskStoreError::CorruptData)?,
        MessageId::from_slice(&row.4).map_err(|_| A2ATaskStoreError::CorruptData)?,
        row.5
            .try_into()
            .map_err(|_| A2ATaskStoreError::CorruptData)?,
        row.17
            .try_into()
            .map_err(|_| A2ATaskStoreError::CorruptData)?,
        request_text,
        parse_bool(row.6)?,
        row.7
            .map(from_sql)
            .transpose()?
            .map(|value| u32::try_from(value).map_err(|_| A2ATaskStoreError::CorruptData))
            .transpose()?,
        state,
        from_sql(row.9)?,
        from_sql(row.10)?,
        from_sql(row.11)?,
        terminal_at,
        terminal_reason,
        content_pruned,
    );
    if record.key().task_id().request_message_id() != record.request_message_id()
        || !record.retained_identity_is_valid()
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    verify_context_binding(connection, &record)?;
    if !record.content_pruned() {
        let initial = load_message_at_sequence(connection, record.key(), 1)?
            .ok_or(A2ATaskStoreError::CorruptData)?;
        if initial.sequence() != 1
            || initial.role() != A2ATaskMessageRole::User
            || initial.message_id() != record.source_message_id()
            || initial.text() != record.request_text().unwrap_or_default()
        {
            return Err(A2ATaskStoreError::CorruptData);
        }
    }
    verify_status_history(connection, &record)?;
    Ok(Some(record))
}

fn verify_context_binding(
    connection: &Connection,
    task: &A2ATaskRecord,
) -> Result<(), A2ATaskStoreError> {
    let context: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT conversation_id, target_device_id
             FROM a2a_context
             WHERE agent_id = ?1 AND tenant_id = ?2 AND context_id = ?3",
            params![
                task.key().agent_id().as_str(),
                tenant_value(task.key()),
                task.context_id().as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let Some((conversation, target)) = context else {
        return Err(A2ATaskStoreError::CorruptData);
    };
    if ConversationId::from_slice(&conversation).ok() != Some(task.conversation_id())
        || DeviceId::from_slice(&target).ok() != Some(task.target_device_id())
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the complete durable task-state shape remains explicit"
)]
fn validate_task_shape(
    state: A2ATaskState,
    generation: u64,
    updated_at: u64,
    terminal_at: Option<u64>,
    terminal_reason: Option<&A2ATerminalReason>,
    content_pruned: bool,
    content_expires_at: Option<u64>,
    tombstone_expires_at: Option<u64>,
) -> Result<(), A2ATaskStoreError> {
    let terminal = is_terminal(state);
    if generation > 2
        || (terminal
            && (terminal_at != Some(updated_at)
                || content_expires_at.is_none()
                || tombstone_expires_at.is_none()
                || terminal_at > content_expires_at
                || content_expires_at > tombstone_expires_at))
        || (!terminal
            && (terminal_at.is_some()
                || terminal_reason.is_some()
                || content_pruned
                || content_expires_at.is_some()
                || tombstone_expires_at.is_some()))
        || (state == A2ATaskState::Completed && terminal_reason.is_some())
        || (matches!(
            state,
            A2ATaskState::Failed | A2ATaskState::Rejected | A2ATaskState::Canceled
        ) && terminal_reason.is_none())
        || matches!(
            state,
            A2ATaskState::InputRequired | A2ATaskState::AuthRequired
        )
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

fn verify_status_history(
    connection: &Connection,
    task: &A2ATaskRecord,
) -> Result<(), A2ATaskStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT generation, state, terminal_reason, occurred_at_unix_milliseconds
             FROM a2a_task_status
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
             ORDER BY generation
             LIMIT 4",
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let rows = statement
        .query_map(
            params![
                task.key().agent_id().as_str(),
                tenant_value(task.key()),
                task.key().task_id().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(|_| A2ATaskStoreError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let expected_length = task
        .generation()
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(A2ATaskStoreError::CorruptData)?;
    if rows.len() != expected_length || rows.is_empty() || rows.len() > 3 {
        return Err(A2ATaskStoreError::CorruptData);
    }
    let mut previous_state = None;
    let mut previous_time = 0;
    for (index, row) in rows.iter().enumerate() {
        let generation = from_sql(row.0)?;
        let state = state_from_code(row.1)?;
        let reason = row
            .2
            .as_ref()
            .map(|value| A2ATerminalReason::parse(value.clone()))
            .transpose()
            .map_err(|_| A2ATaskStoreError::CorruptData)?;
        let occurred_at = from_sql(row.3)?;
        if generation != u64::try_from(index).map_err(|_| A2ATaskStoreError::CorruptData)?
            || occurred_at < previous_time
            || (index == 0
                && (state != A2ATaskState::Submitted
                    || reason.is_some()
                    || occurred_at != task.created_at_unix_milliseconds()))
            || !valid_status_reason(state, reason.as_ref())
            || previous_state.is_some_and(|previous| !allowed_state_transition(previous, state))
        {
            return Err(A2ATaskStoreError::CorruptData);
        }
        previous_state = Some(state);
        previous_time = occurred_at;
    }
    let last = rows.last().ok_or(A2ATaskStoreError::CorruptData)?;
    if state_from_code(last.1)? != task.state()
        || from_sql(last.0)? != task.generation()
        || from_sql(last.3)? != task.updated_at_unix_milliseconds()
        || last.2.as_deref() != task.terminal_reason().map(A2ATerminalReason::as_str)
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(())
}

const fn allowed_state_transition(previous: A2ATaskState, next: A2ATaskState) -> bool {
    match previous {
        A2ATaskState::Submitted => matches!(
            next,
            A2ATaskState::Working
                | A2ATaskState::Completed
                | A2ATaskState::Failed
                | A2ATaskState::Rejected
                | A2ATaskState::Canceled
        ),
        A2ATaskState::Working => matches!(
            next,
            A2ATaskState::Completed
                | A2ATaskState::Failed
                | A2ATaskState::Rejected
                | A2ATaskState::Canceled
        ),
        _ => false,
    }
}

fn valid_status_reason(state: A2ATaskState, reason: Option<&A2ATerminalReason>) -> bool {
    match state {
        A2ATaskState::Submitted | A2ATaskState::Working | A2ATaskState::Completed => {
            reason.is_none()
        }
        A2ATaskState::Failed | A2ATaskState::Canceled | A2ATaskState::Rejected => reason.is_some(),
        A2ATaskState::InputRequired | A2ATaskState::AuthRequired => false,
    }
}

fn validate_transition(
    connection: &Connection,
    current: &A2ATaskRecord,
    transition: &A2ATaskTransition,
) -> Result<(), A2ATaskStoreError> {
    if is_terminal(current.state()) {
        return Err(A2ATaskStoreError::InvalidTransition);
    }
    let allowed = match current.state() {
        A2ATaskState::Submitted => matches!(
            transition.state(),
            A2ATaskState::Working
                | A2ATaskState::Completed
                | A2ATaskState::Failed
                | A2ATaskState::Rejected
                | A2ATaskState::Canceled
        ),
        A2ATaskState::Working => matches!(
            transition.state(),
            A2ATaskState::Completed
                | A2ATaskState::Failed
                | A2ATaskState::Rejected
                | A2ATaskState::Canceled
        ),
        _ => false,
    };
    if !allowed
        || transition.occurred_at_unix_milliseconds() < current.updated_at_unix_milliseconds()
    {
        return Err(A2ATaskStoreError::InvalidTransition);
    }
    match transition.state() {
        A2ATaskState::Completed if transition.terminal_reason().is_some() => {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
        A2ATaskState::Failed | A2ATaskState::Rejected | A2ATaskState::Canceled
            if transition.terminal_reason().is_none() =>
        {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
        A2ATaskState::Working if transition.terminal_reason().is_some() => {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
        _ => {}
    }
    if transition.state() == A2ATaskState::Completed {
        let evidence: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM a2a_task_message
                    WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3 AND role = 2
                    UNION ALL
                    SELECT 1 FROM a2a_task_artifact
                    WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3 AND complete = 1
                 )",
                params![
                    current.key().agent_id().as_str(),
                    tenant_value(current.key()),
                    current.key().task_id().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|_| A2ATaskStoreError::Storage)?;
        if !evidence {
            return Err(A2ATaskStoreError::InvalidTransition);
        }
    }
    Ok(())
}

fn insert_status(
    transaction: &Transaction<'_>,
    key: &A2ATaskKey,
    generation: u64,
    state: A2ATaskState,
    reason: Option<&A2ATerminalReason>,
    occurred_at: u64,
) -> Result<(), A2ATaskStoreError> {
    transaction
        .execute(
            "INSERT INTO a2a_task_status (
                agent_id, tenant_id, task_id, generation, state,
                terminal_reason, occurred_at_unix_milliseconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str(),
                to_sql(generation)?,
                state_code(state),
                reason.map(A2ATerminalReason::as_str),
                to_sql(occurred_at)?,
            ],
        )
        .map_err(map_insert_error)?;
    Ok(())
}

fn insert_message(
    transaction: &Transaction<'_>,
    message: &A2ATaskMessage,
    sequence: u64,
) -> Result<(), A2ATaskStoreError> {
    transaction
        .execute(
            "INSERT INTO a2a_task_message (
                agent_id, tenant_id, task_id, sequence, message_id,
                role, text, identity_digest, recorded_at_unix_milliseconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                message.key().agent_id().as_str(),
                tenant_value(message.key()),
                message.key().task_id().as_str(),
                to_sql(sequence)?,
                message.message_id().as_str(),
                role_code(message.role()),
                message.text(),
                message.identity_digest().as_slice(),
                to_sql(message.recorded_at_unix_milliseconds())?,
            ],
        )
        .map_err(map_insert_error)?;
    Ok(())
}

fn insert_artifact(
    transaction: &Transaction<'_>,
    artifact: &A2ATaskArtifact,
    sequence: u64,
) -> Result<(), A2ATaskStoreError> {
    transaction
        .execute(
            "INSERT INTO a2a_task_artifact (
                agent_id, tenant_id, task_id, sequence, artifact_id,
                content_digest, canonical_bytes, complete, identity_digest,
                recorded_at_unix_milliseconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.key().agent_id().as_str(),
                tenant_value(artifact.key()),
                artifact.key().task_id().as_str(),
                to_sql(sequence)?,
                artifact.artifact_id().as_str(),
                artifact.content_digest().as_slice(),
                artifact.canonical_bytes(),
                i64::from(artifact.complete()),
                artifact.identity_digest().as_slice(),
                to_sql(artifact.recorded_at_unix_milliseconds())?,
            ],
        )
        .map_err(map_insert_error)?;
    Ok(())
}

fn existing_message(
    connection: &Connection,
    key: &A2ATaskKey,
    message_id: &A2AMessageId,
) -> Result<Option<(u64, [u8; 32])>, A2ATaskStoreError> {
    let row: Option<(i64, i64, String, Vec<u8>, i64)> = connection
        .query_row(
            "SELECT sequence, role, text, identity_digest,
                    recorded_at_unix_milliseconds
             FROM a2a_task_message
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
               AND message_id = ?4",
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str(),
                message_id.as_str()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let message = A2ATaskMessage::new(
        key.clone(),
        message_id.clone(),
        role_from_code(row.1)?,
        row.2,
        from_sql(row.4)?,
    )
    .map_err(|_| A2ATaskStoreError::CorruptData)?;
    let digest = message.identity_digest();
    if digest.as_slice() != row.3.as_slice() {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(Some((from_sql(row.0)?, digest)))
}

fn existing_artifact(
    connection: &Connection,
    key: &A2ATaskKey,
    artifact_id: &A2AArtifactId,
) -> Result<Option<(u64, [u8; 32])>, A2ATaskStoreError> {
    let row: Option<ExistingArtifactRow> = connection
        .query_row(
            "SELECT sequence, content_digest, canonical_bytes, complete,
                    identity_digest, recorded_at_unix_milliseconds
             FROM a2a_task_artifact
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
               AND artifact_id = ?4",
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str(),
                artifact_id.as_str()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let artifact = A2ATaskArtifact::new(
        key.clone(),
        artifact_id.clone(),
        row.2,
        parse_bool(row.3)?,
        from_sql(row.5)?,
    )
    .map_err(|_| A2ATaskStoreError::CorruptData)?;
    let digest = artifact.identity_digest();
    if artifact.content_digest().as_slice() != row.1.as_slice()
        || digest.as_slice() != row.4.as_slice()
    {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(Some((from_sql(row.0)?, digest)))
}

fn record_count(
    connection: &Connection,
    table: &str,
    key: &A2ATaskKey,
) -> Result<usize, A2ATaskStoreError> {
    let sql = format!(
        "SELECT count(*) FROM {table}
         WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3"
    );
    let count: i64 = connection
        .query_row(
            &sql,
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str()
            ],
            |row| row.get(0),
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    usize::try_from(count).map_err(|_| A2ATaskStoreError::CorruptData)
}

fn load_messages(
    connection: &Connection,
    key: &A2ATaskKey,
    limit: usize,
) -> Result<Vec<StoredA2ATaskMessage>, A2ATaskStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, message_id, role, text, identity_digest,
                    recorded_at_unix_milliseconds
             FROM (
                SELECT sequence, message_id, role, text, identity_digest,
                       recorded_at_unix_milliseconds
                FROM a2a_task_message
                WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
                ORDER BY sequence DESC
                LIMIT ?4
             )
             ORDER BY sequence",
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let rows = statement
        .query_map(
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str(),
                i64::try_from(limit).map_err(|_| A2ATaskStoreError::InvalidConfiguration)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|_| A2ATaskStoreError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let mut messages = Vec::with_capacity(rows.len());
    let mut previous_sequence: Option<u64> = None;
    for row in rows {
        let sequence = from_sql(row.0)?;
        if previous_sequence.is_some_and(|previous| previous.checked_add(1) != Some(sequence)) {
            return Err(A2ATaskStoreError::CorruptData);
        }
        previous_sequence = Some(sequence);
        let message = A2ATaskMessage::new(
            key.clone(),
            A2AMessageId::parse(row.1).map_err(|_| A2ATaskStoreError::CorruptData)?,
            role_from_code(row.2)?,
            row.3.clone(),
            from_sql(row.5)?,
        )
        .map_err(|_| A2ATaskStoreError::CorruptData)?;
        if message.identity_digest().as_slice() != row.4.as_slice() {
            return Err(A2ATaskStoreError::CorruptData);
        }
        messages.push(StoredA2ATaskMessage::new(
            sequence,
            message.message_id().clone(),
            message.role(),
            row.3,
            message.recorded_at_unix_milliseconds(),
        ));
    }
    Ok(messages)
}

fn load_message_at_sequence(
    connection: &Connection,
    key: &A2ATaskKey,
    sequence: u64,
) -> Result<Option<StoredA2ATaskMessage>, A2ATaskStoreError> {
    let row: Option<(String, i64, String, Vec<u8>, i64)> = connection
        .query_row(
            "SELECT message_id, role, text, identity_digest,
                    recorded_at_unix_milliseconds
             FROM a2a_task_message
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
               AND sequence = ?4",
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str(),
                to_sql(sequence)?
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let message = A2ATaskMessage::new(
        key.clone(),
        A2AMessageId::parse(row.0).map_err(|_| A2ATaskStoreError::CorruptData)?,
        role_from_code(row.1)?,
        row.2.clone(),
        from_sql(row.4)?,
    )
    .map_err(|_| A2ATaskStoreError::CorruptData)?;
    if message.identity_digest().as_slice() != row.3.as_slice() {
        return Err(A2ATaskStoreError::CorruptData);
    }
    Ok(Some(StoredA2ATaskMessage::new(
        sequence,
        message.message_id().clone(),
        message.role(),
        row.2,
        message.recorded_at_unix_milliseconds(),
    )))
}

fn load_artifacts(
    connection: &Connection,
    key: &A2ATaskKey,
    limit: usize,
) -> Result<Vec<StoredA2ATaskArtifact>, A2ATaskStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, artifact_id, content_digest, canonical_bytes,
                    complete, identity_digest, recorded_at_unix_milliseconds
             FROM a2a_task_artifact
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3
             ORDER BY sequence
             LIMIT ?4",
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let rows = statement
        .query_map(
            params![
                key.agent_id().as_str(),
                tenant_value(key),
                key.task_id().as_str(),
                i64::try_from(limit).map_err(|_| A2ATaskStoreError::InvalidConfiguration)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .map_err(|_| A2ATaskStoreError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    let mut artifacts = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        let sequence = from_sql(row.0)?;
        if sequence != u64::try_from(index + 1).map_err(|_| A2ATaskStoreError::CorruptData)? {
            return Err(A2ATaskStoreError::CorruptData);
        }
        let artifact = A2ATaskArtifact::new(
            key.clone(),
            A2AArtifactId::parse(row.1).map_err(|_| A2ATaskStoreError::CorruptData)?,
            row.3.clone(),
            parse_bool(row.4)?,
            from_sql(row.6)?,
        )
        .map_err(|_| A2ATaskStoreError::CorruptData)?;
        if artifact.content_digest().as_slice() != row.2.as_slice()
            || artifact.identity_digest().as_slice() != row.5.as_slice()
        {
            return Err(A2ATaskStoreError::CorruptData);
        }
        artifacts.push(StoredA2ATaskArtifact::new(
            sequence,
            artifact.artifact_id().clone(),
            *artifact.content_digest(),
            row.3,
            artifact.complete(),
            artifact.recorded_at_unix_milliseconds(),
        ));
    }
    Ok(artifacts)
}

fn prune_in(
    transaction: &Transaction<'_>,
    config: A2ASqliteTaskStoreConfig,
    now: u64,
) -> Result<A2ATaskPruneOutcome, A2ATaskStoreError> {
    let mut outcome = A2ATaskPruneOutcome::default();
    for _ in 0..config.max_prune_batch {
        let Some(candidate) = next_retention_candidate(transaction, now)? else {
            break;
        };
        match candidate.kind {
            RetentionKind::Payload => {
                delete_payloads(transaction, &candidate.key)?;
                let changed = transaction
                    .execute(
                        "UPDATE a2a_task SET content_pruned = 1
                         WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3",
                        params![
                            candidate.key.agent_id().as_str(),
                            tenant_value(&candidate.key),
                            candidate.key.task_id().as_str()
                        ],
                    )
                    .map_err(|_| A2ATaskStoreError::Storage)?;
                if changed != 1 {
                    return Err(A2ATaskStoreError::CorruptData);
                }
                outcome.pruned_task_payloads += 1;
            }
            RetentionKind::Tombstone => {
                let changed = transaction
                    .execute(
                        "DELETE FROM a2a_task
                         WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3",
                        params![
                            candidate.key.agent_id().as_str(),
                            tenant_value(&candidate.key),
                            candidate.key.task_id().as_str()
                        ],
                    )
                    .map_err(|_| A2ATaskStoreError::Storage)?;
                if changed != 1 {
                    return Err(A2ATaskStoreError::CorruptData);
                }
                outcome.removed_tombstones += 1;
            }
        }
    }
    transaction
        .execute(
            "DELETE FROM a2a_context
             WHERE NOT EXISTS (
                SELECT 1 FROM a2a_task
                WHERE a2a_task.agent_id = a2a_context.agent_id
                  AND a2a_task.tenant_id = a2a_context.tenant_id
                  AND a2a_task.context_id = a2a_context.context_id
             )",
            [],
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    Ok(outcome)
}

enum RetentionKind {
    Payload,
    Tombstone,
}

struct RetentionCandidate {
    key: A2ATaskKey,
    kind: RetentionKind,
}

fn next_retention_candidate(
    connection: &Connection,
    now: u64,
) -> Result<Option<RetentionCandidate>, A2ATaskStoreError> {
    let row: Option<(i64, String, String, String)> = connection
        .query_row(
            "SELECT kind, agent_id, tenant_id, task_id
             FROM (
                SELECT 1 AS kind, agent_id, tenant_id, task_id,
                       content_expires_at_unix_milliseconds AS deadline,
                       terminal_at_unix_milliseconds AS terminal_at
                FROM a2a_task
                WHERE content_pruned = 0
                  AND content_expires_at_unix_milliseconds IS NOT NULL
                  AND content_expires_at_unix_milliseconds <= ?1
                UNION ALL
                SELECT 2 AS kind, agent_id, tenant_id, task_id,
                       tombstone_expires_at_unix_milliseconds AS deadline,
                       terminal_at_unix_milliseconds AS terminal_at
                FROM a2a_task
                WHERE content_pruned = 1
                  AND tombstone_expires_at_unix_milliseconds IS NOT NULL
                  AND tombstone_expires_at_unix_milliseconds <= ?1
             )
             ORDER BY deadline, terminal_at, kind, agent_id, tenant_id, task_id
             LIMIT 1",
            params![to_sql(now)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| A2ATaskStoreError::Storage)?;
    row.map(|row| {
        Ok(RetentionCandidate {
            key: task_key_from_storage(row.1, row.2, row.3)?,
            kind: match row.0 {
                1 => RetentionKind::Payload,
                2 => RetentionKind::Tombstone,
                _ => return Err(A2ATaskStoreError::CorruptData),
            },
        })
    })
    .transpose()
}

fn delete_payloads(
    transaction: &Transaction<'_>,
    key: &A2ATaskKey,
) -> Result<(), A2ATaskStoreError> {
    for table in ["a2a_task_message", "a2a_task_artifact"] {
        let sql = format!(
            "DELETE FROM {table}
             WHERE agent_id = ?1 AND tenant_id = ?2 AND task_id = ?3"
        );
        transaction
            .execute(
                &sql,
                params![
                    key.agent_id().as_str(),
                    tenant_value(key),
                    key.task_id().as_str()
                ],
            )
            .map_err(|_| A2ATaskStoreError::Storage)?;
    }
    Ok(())
}

fn require_task_capacity(
    connection: &Connection,
    config: A2ASqliteTaskStoreConfig,
) -> Result<(), A2ATaskStoreError> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM a2a_task", [], |row| row.get(0))
        .map_err(|_| A2ATaskStoreError::Storage)?;
    if usize::try_from(count)
        .ok()
        .is_none_or(|count| count >= config.max_tasks)
    {
        Err(A2ATaskStoreError::CapacityExceeded)
    } else {
        Ok(())
    }
}

fn require_payload_capacity(
    connection: &Connection,
    config: A2ASqliteTaskStoreConfig,
    additional: usize,
) -> Result<(), A2ATaskStoreError> {
    let current = retained_payload_bytes(connection)?;
    if current
        .checked_add(additional)
        .is_none_or(|total| total > config.max_payload_bytes)
    {
        Err(A2ATaskStoreError::CapacityExceeded)
    } else {
        Ok(())
    }
}

fn retained_payload_bytes(connection: &Connection) -> Result<usize, A2ATaskStoreError> {
    let current: i64 = connection
        .query_row(
            "SELECT
                COALESCE((SELECT sum(length(CAST(text AS BLOB))) FROM a2a_task_message), 0) +
                COALESCE((SELECT sum(length(canonical_bytes)) FROM a2a_task_artifact), 0)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| A2ATaskStoreError::Storage)?;
    usize::try_from(current).map_err(|_| A2ATaskStoreError::CorruptData)
}

fn validate_page_limit(limit: usize, configured: usize) -> Result<(), A2ATaskStoreError> {
    if limit == 0 || limit > configured || limit > MAX_PAGE_SIZE {
        Err(A2ATaskStoreError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn tenant_value(key: &A2ATaskKey) -> &str {
    key.tenant().map_or("", A2ATenantId::as_str)
}

fn task_key_from_storage(
    agent_id: String,
    tenant_id: String,
    task_id: String,
) -> Result<A2ATaskKey, A2ATaskStoreError> {
    Ok(A2ATaskKey::new(
        A2AAgentId::parse(agent_id).map_err(|_| A2ATaskStoreError::CorruptData)?,
        if tenant_id.is_empty() {
            None
        } else {
            Some(A2ATenantId::parse(tenant_id).map_err(|_| A2ATaskStoreError::CorruptData)?)
        },
        A2ATaskId::parse(task_id).map_err(|_| A2ATaskStoreError::CorruptData)?,
    ))
}

fn terminal_reasons_equal(
    left: Option<&A2ATerminalReason>,
    right: Option<&A2ATerminalReason>,
) -> bool {
    left.map(A2ATerminalReason::as_str) == right.map(A2ATerminalReason::as_str)
}

const fn is_terminal(state: A2ATaskState) -> bool {
    matches!(
        state,
        A2ATaskState::Completed
            | A2ATaskState::Failed
            | A2ATaskState::Canceled
            | A2ATaskState::Rejected
    )
}

const fn state_code(state: A2ATaskState) -> i64 {
    match state {
        A2ATaskState::Submitted => 1,
        A2ATaskState::Working => 2,
        A2ATaskState::Completed => 3,
        A2ATaskState::Failed => 4,
        A2ATaskState::Canceled => 5,
        A2ATaskState::InputRequired => 6,
        A2ATaskState::Rejected => 7,
        A2ATaskState::AuthRequired => 8,
    }
}

fn state_from_code(value: i64) -> Result<A2ATaskState, A2ATaskStoreError> {
    match value {
        1 => Ok(A2ATaskState::Submitted),
        2 => Ok(A2ATaskState::Working),
        3 => Ok(A2ATaskState::Completed),
        4 => Ok(A2ATaskState::Failed),
        5 => Ok(A2ATaskState::Canceled),
        6 => Ok(A2ATaskState::InputRequired),
        7 => Ok(A2ATaskState::Rejected),
        8 => Ok(A2ATaskState::AuthRequired),
        _ => Err(A2ATaskStoreError::CorruptData),
    }
}

const fn role_code(role: A2ATaskMessageRole) -> i64 {
    match role {
        A2ATaskMessageRole::User => 1,
        A2ATaskMessageRole::Agent => 2,
    }
}

fn role_from_code(value: i64) -> Result<A2ATaskMessageRole, A2ATaskStoreError> {
    match value {
        1 => Ok(A2ATaskMessageRole::User),
        2 => Ok(A2ATaskMessageRole::Agent),
        _ => Err(A2ATaskStoreError::CorruptData),
    }
}

fn parse_bool(value: i64) -> Result<bool, A2ATaskStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(A2ATaskStoreError::CorruptData),
    }
}

fn to_sql(value: u64) -> Result<i64, A2ATaskStoreError> {
    i64::try_from(value).map_err(|_| A2ATaskStoreError::InvalidConfiguration)
}

fn from_sql(value: i64) -> Result<u64, A2ATaskStoreError> {
    u64::try_from(value).map_err(|_| A2ATaskStoreError::CorruptData)
}

fn map_insert_error(error: rusqlite::Error) -> A2ATaskStoreError {
    if let rusqlite::Error::SqliteFailure(failure, _) = error {
        if matches!(
            failure.extended_code,
            rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        ) {
            return A2ATaskStoreError::Conflict;
        }
    }
    A2ATaskStoreError::Storage
}

#[cfg(test)]
fn run_test_barrier(barrier: &Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>) {
    let barriers = barrier.lock().unwrap().take();
    if let Some((arrived, release)) = barriers {
        arrived.wait();
        release.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use KonclaveA2AContracts::wire::{Message, Part, Role, SendMessageRequest, part};
    use KonclaveA2AContracts::{A2A_TEXT_MEDIA_TYPE, validate_initial_send_message_request};
    use KonclaveA2ADomain::{A2AAgentRoute, map_initial_send_message};

    fn creation(created_at: u64) -> A2ATaskCreation {
        let route = A2AAgentRoute::new(
            A2AAgentId::parse("agent-a").unwrap(),
            A2AContextId::parse("context-a").unwrap(),
            Some(A2ATenantId::parse("tenant-a").unwrap()),
            ConversationId::from_bytes([4; ConversationId::LENGTH]),
            DeviceId::from_bytes([5; DeviceId::LENGTH]),
        );
        let request = validate_initial_send_message_request(
            SendMessageRequest {
                tenant: "tenant-a".to_owned(),
                message: Some(Message {
                    message_id: "message-a".to_owned(),
                    context_id: "context-a".to_owned(),
                    task_id: String::new(),
                    role: Role::User as i32,
                    parts: vec![Part {
                        content: Some(part::Content::Text("request".to_owned())),
                        metadata: None,
                        filename: String::new(),
                        media_type: A2A_TEXT_MEDIA_TYPE.to_owned(),
                    }],
                    metadata: None,
                    extensions: vec![],
                    reference_task_ids: vec![],
                }),
                configuration: None,
                metadata: None,
            },
            Some("tenant-a"),
        )
        .unwrap();
        A2ATaskCreation::from_mapping(
            map_initial_send_message(&route, request).unwrap(),
            created_at,
        )
    }

    #[test]
    fn create_failure_rolls_back_context_task_status_and_message() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("tasks.sqlite");
        let store = A2ASqliteTaskStore::open(&path, A2ASqliteTaskStoreConfig::default()).unwrap();
        store
            .test_hooks
            .fail_after_task_insert
            .store(true, Ordering::SeqCst);
        assert_eq!(
            store.create_task(creation(100)).err(),
            Some(A2ATaskStoreError::Storage)
        );
        {
            let connection = store.lock().unwrap();
            for table in [
                "a2a_context",
                "a2a_task",
                "a2a_task_status",
                "a2a_task_message",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0);
            }
        }
        assert!(matches!(
            store.create_task(creation(101)).unwrap(),
            CreateA2ATaskOutcome::Created(_)
        ));
    }

    #[test]
    fn task_message_snapshot_stays_consistent_while_prune_commits() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("tasks.sqlite");
        let config = A2ASqliteTaskStoreConfig {
            max_tasks: 16,
            max_messages_per_task: 8,
            max_artifacts_per_task: 4,
            max_payload_bytes: 1024 * 1024,
            max_prune_batch: 8,
            content_retention_milliseconds: 10,
            idempotency_retention_milliseconds: 20,
            busy_timeout_milliseconds: 1_000,
        };
        let store = Arc::new(A2ASqliteTaskStore::open(&path, config).unwrap());
        let task = match store.create_task(creation(90)).unwrap() {
            CreateA2ATaskOutcome::Created(task) => task,
            CreateA2ATaskOutcome::Existing(_) => panic!("task should be new"),
        };
        let key = task.key().clone();
        store
            .append_message(
                A2ATaskMessage::new(
                    key.clone(),
                    A2AMessageId::parse("response-a").unwrap(),
                    A2ATaskMessageRole::Agent,
                    "response",
                    95,
                )
                .unwrap(),
                95,
            )
            .unwrap();
        store
            .transition_task(A2ATaskTransition::new(
                key.clone(),
                0,
                A2ATaskState::Completed,
                None,
                100,
            ))
            .unwrap();
        let pruning_store = Arc::new(A2ASqliteTaskStore::open(&path, config).unwrap());
        let snapshot_arrived = Arc::new(Barrier::new(2));
        let snapshot_release = Arc::new(Barrier::new(2));
        let prune_arrived = Arc::new(Barrier::new(2));
        let prune_release = Arc::new(Barrier::new(2));
        *store.test_hooks.snapshot_after_task_load.lock().unwrap() =
            Some((snapshot_arrived.clone(), snapshot_release.clone()));
        *pruning_store.test_hooks.prune_before_commit.lock().unwrap() =
            Some((prune_arrived.clone(), prune_release.clone()));

        let snapshot_store = store.clone();
        let snapshot_key = key.clone();
        let snapshot =
            std::thread::spawn(move || snapshot_store.task_with_messages(&snapshot_key, 2));
        snapshot_arrived.wait();
        let pruning = std::thread::spawn(move || pruning_store.prune(110));
        prune_arrived.wait();
        snapshot_release.wait();
        let (task, messages) = snapshot.join().unwrap().unwrap();
        assert!(!task.content_pruned());
        assert_eq!(messages.len(), 2);
        prune_release.wait();
        assert_eq!(pruning.join().unwrap().unwrap().pruned_task_payloads, 1);
        let (task, messages) = store.task_with_messages(&key, 2).unwrap();
        assert!(task.content_pruned());
        assert!(messages.is_empty());
    }
}
