use KonclaveA2AContracts::MAX_A2A_TEXT_BYTES;
use KonclaveA2ADomain::{
    A2AAgentId, A2AArtifactId, A2AContextId, A2ADirectedRequestMapping, A2AMessageId, A2ATaskId,
    A2ATaskState, A2ATenantId,
};
use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};
use sha2::{Digest as _, Sha256};

use crate::A2ATaskStoreError;

const TASK_IDENTITY_DOMAIN: &[u8] = b"konclave-a2a-task-identity-v1\0";
const MESSAGE_IDENTITY_DOMAIN: &[u8] = b"konclave-a2a-task-message-v1\0";
const ARTIFACT_IDENTITY_DOMAIN: &[u8] = b"konclave-a2a-task-artifact-v1\0";
/// Maximum canonical bytes retained for one validated artifact record.
pub const MAX_A2A_STORED_ARTIFACT_BYTES: usize = 1024 * 1024;
/// Maximum byte length of one stable terminal reason code.
pub const MAX_A2A_TERMINAL_REASON_BYTES: usize = 64;

/// Exact task key used by every store operation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct A2ATaskKey {
    agent_id: A2AAgentId,
    tenant: Option<A2ATenantId>,
    task_id: A2ATaskId,
}

impl A2ATaskKey {
    /// Creates one agent- and tenant-scoped task key.
    #[must_use]
    pub const fn new(
        agent_id: A2AAgentId,
        tenant: Option<A2ATenantId>,
        task_id: A2ATaskId,
    ) -> Self {
        Self {
            agent_id,
            tenant,
            task_id,
        }
    }

    /// Returns the published agent identifier.
    #[must_use]
    pub const fn agent_id(&self) -> &A2AAgentId {
        &self.agent_id
    }

    /// Returns the optional tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> Option<&A2ATenantId> {
        self.tenant.as_ref()
    }

    /// Returns the gateway-owned task identifier.
    #[must_use]
    pub const fn task_id(&self) -> &A2ATaskId {
        &self.task_id
    }
}

/// Immutable task creation input produced from one mapped directed request.
pub struct A2ATaskCreation {
    key: A2ATaskKey,
    context_id: A2AContextId,
    source_message_id: A2AMessageId,
    conversation_id: ConversationId,
    target_device_id: DeviceId,
    request_message_id: MessageId,
    request_text: String,
    return_immediately: bool,
    history_length: Option<u32>,
    created_at_unix_milliseconds: u64,
}

impl A2ATaskCreation {
    /// Creates task input by moving one validated domain mapping.
    #[must_use]
    pub fn from_mapping(
        mapping: A2ADirectedRequestMapping,
        created_at_unix_milliseconds: u64,
    ) -> Self {
        let key = A2ATaskKey::new(
            mapping.agent_id().clone(),
            mapping.tenant().cloned(),
            mapping.task_id().clone(),
        );
        let context_id = mapping.context_id().clone();
        let source_message_id = mapping.source_message_id().clone();
        let conversation_id = mapping.conversation_id();
        let target_device_id = mapping.target_device_id();
        let request_message_id = mapping.request_message_id();
        let return_immediately = mapping.return_immediately();
        let history_length = mapping.history_length();
        let request_text = mapping.into_text();
        Self {
            key,
            context_id,
            source_message_id,
            conversation_id,
            target_device_id,
            request_message_id,
            request_text,
            return_immediately,
            history_length,
            created_at_unix_milliseconds,
        }
    }

    /// Returns the exact task key.
    #[must_use]
    pub const fn key(&self) -> &A2ATaskKey {
        &self.key
    }

    /// Returns the configured public context.
    #[must_use]
    pub const fn context_id(&self) -> &A2AContextId {
        &self.context_id
    }

    /// Returns the caller's source message identifier.
    #[must_use]
    pub const fn source_message_id(&self) -> &A2AMessageId {
        &self.source_message_id
    }

    /// Returns the configured Konclave conversation.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the configured exact target device.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the mapped Konclave request identifier.
    #[must_use]
    pub const fn request_message_id(&self) -> MessageId {
        self.request_message_id
    }

    /// Returns the validated plaintext request body.
    #[must_use]
    pub fn request_text(&self) -> &str {
        &self.request_text
    }

    /// Returns whether the caller requested an immediate response.
    #[must_use]
    pub const fn return_immediately(&self) -> bool {
        self.return_immediately
    }

    /// Returns the requested bounded history length.
    #[must_use]
    pub const fn history_length(&self) -> Option<u32> {
        self.history_length
    }

    /// Returns the first-creation display timestamp.
    #[must_use]
    pub const fn created_at_unix_milliseconds(&self) -> u64 {
        self.created_at_unix_milliseconds
    }

    /// Returns a domain-separated digest over every immutable idempotency field.
    #[must_use]
    pub fn identity_digest(&self) -> [u8; 32] {
        let request_text_digest = text_digest(&self.request_text);
        task_identity_digest(
            &self.key,
            &self.context_id,
            &self.source_message_id,
            self.conversation_id,
            self.target_device_id,
            self.request_message_id,
            self.return_immediately,
            self.history_length,
            request_text_digest,
        )
    }

    /// Returns the SHA-256 digest retained after request plaintext expires.
    #[must_use]
    pub fn request_text_digest(&self) -> [u8; 32] {
        text_digest(&self.request_text)
    }
}

/// Sender role for one stored A2A task message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum A2ATaskMessageRole {
    /// Message originated from the A2A requester.
    User,
    /// Message originated from the published A2A agent.
    Agent,
}

/// Bounded append input for one A2A task message.
pub struct A2ATaskMessage {
    key: A2ATaskKey,
    message_id: A2AMessageId,
    role: A2ATaskMessageRole,
    text: String,
    recorded_at_unix_milliseconds: u64,
}

impl A2ATaskMessage {
    /// Creates one bounded message append.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the text is empty or exceeds the initial
    /// A2A text bound.
    pub fn new(
        key: A2ATaskKey,
        message_id: A2AMessageId,
        role: A2ATaskMessageRole,
        text: impl Into<String>,
        recorded_at_unix_milliseconds: u64,
    ) -> Result<Self, A2ATaskStoreError> {
        let text = text.into();
        if text.is_empty() || text.len() > MAX_A2A_TEXT_BYTES {
            return Err(A2ATaskStoreError::InvalidConfiguration);
        }
        Ok(Self {
            key,
            message_id,
            role,
            text,
            recorded_at_unix_milliseconds,
        })
    }

    /// Returns the exact task key.
    #[must_use]
    pub const fn key(&self) -> &A2ATaskKey {
        &self.key
    }

    /// Returns the task-scoped message identifier.
    #[must_use]
    pub const fn message_id(&self) -> &A2AMessageId {
        &self.message_id
    }

    /// Returns the typed message role.
    #[must_use]
    pub const fn role(&self) -> A2ATaskMessageRole {
        self.role
    }

    /// Returns the bounded plaintext body.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the message timestamp.
    #[must_use]
    pub const fn recorded_at_unix_milliseconds(&self) -> u64 {
        self.recorded_at_unix_milliseconds
    }

    /// Returns the exact message idempotency digest.
    #[must_use]
    pub fn identity_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(MESSAGE_IDENTITY_DOMAIN);
        append_task_key(&mut digest, &self.key);
        append_identifier(&mut digest, self.message_id.as_str());
        digest.update([match self.role {
            A2ATaskMessageRole::User => 1,
            A2ATaskMessageRole::Agent => 2,
        }]);
        append_bytes(&mut digest, self.text.as_bytes());
        digest.finalize().into()
    }
}

/// Opaque canonical artifact append produced by the future artifact validator.
pub struct A2ATaskArtifact {
    key: A2ATaskKey,
    artifact_id: A2AArtifactId,
    canonical_bytes: Vec<u8>,
    content_digest: [u8; 32],
    complete: bool,
    recorded_at_unix_milliseconds: u64,
}

impl A2ATaskArtifact {
    /// Creates one bounded opaque artifact append and computes its content digest.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when canonical bytes are empty or oversized.
    pub fn new(
        key: A2ATaskKey,
        artifact_id: A2AArtifactId,
        canonical_bytes: Vec<u8>,
        complete: bool,
        recorded_at_unix_milliseconds: u64,
    ) -> Result<Self, A2ATaskStoreError> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_A2A_STORED_ARTIFACT_BYTES {
            return Err(A2ATaskStoreError::InvalidConfiguration);
        }
        let content_digest = Sha256::digest(&canonical_bytes).into();
        Ok(Self {
            key,
            artifact_id,
            canonical_bytes,
            content_digest,
            complete,
            recorded_at_unix_milliseconds,
        })
    }

    /// Returns the exact task key.
    #[must_use]
    pub const fn key(&self) -> &A2ATaskKey {
        &self.key
    }

    /// Returns the task-scoped artifact identifier.
    #[must_use]
    pub const fn artifact_id(&self) -> &A2AArtifactId {
        &self.artifact_id
    }

    /// Returns the canonical validated artifact bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the SHA-256 digest of the canonical artifact bytes.
    #[must_use]
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns whether this record completes the artifact.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns the artifact timestamp.
    #[must_use]
    pub const fn recorded_at_unix_milliseconds(&self) -> u64 {
        self.recorded_at_unix_milliseconds
    }

    /// Returns the exact artifact idempotency digest.
    #[must_use]
    pub fn identity_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(ARTIFACT_IDENTITY_DOMAIN);
        append_task_key(&mut digest, &self.key);
        append_identifier(&mut digest, self.artifact_id.as_str());
        digest.update(self.content_digest);
        digest.update([u8::from(self.complete)]);
        digest.finalize().into()
    }
}

/// Stable bounded code explaining one terminal task outcome.
#[derive(Clone, PartialEq, Eq)]
pub struct A2ATerminalReason(String);

impl A2ATerminalReason {
    /// Parses one portable machine-readable terminal reason.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for an empty, oversized, or noncanonical code.
    pub fn parse(value: impl Into<String>) -> Result<Self, A2ATaskStoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_A2A_TERMINAL_REASON_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(A2ATaskStoreError::InvalidConfiguration);
        }
        Ok(Self(value))
    }

    /// Returns the canonical reason code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Expected-generation state transition.
pub struct A2ATaskTransition {
    key: A2ATaskKey,
    expected_generation: u64,
    state: A2ATaskState,
    terminal_reason: Option<A2ATerminalReason>,
    occurred_at_unix_milliseconds: u64,
}

impl A2ATaskTransition {
    /// Creates one explicit transition request.
    #[must_use]
    pub const fn new(
        key: A2ATaskKey,
        expected_generation: u64,
        state: A2ATaskState,
        terminal_reason: Option<A2ATerminalReason>,
        occurred_at_unix_milliseconds: u64,
    ) -> Self {
        Self {
            key,
            expected_generation,
            state,
            terminal_reason,
            occurred_at_unix_milliseconds,
        }
    }

    /// Returns the exact task key.
    #[must_use]
    pub const fn key(&self) -> &A2ATaskKey {
        &self.key
    }

    /// Returns the required current generation.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    /// Returns the requested A2A state.
    #[must_use]
    pub const fn state(&self) -> A2ATaskState {
        self.state
    }

    /// Returns the optional terminal reason.
    #[must_use]
    pub const fn terminal_reason(&self) -> Option<&A2ATerminalReason> {
        self.terminal_reason.as_ref()
    }

    /// Returns the transition timestamp.
    #[must_use]
    pub const fn occurred_at_unix_milliseconds(&self) -> u64 {
        self.occurred_at_unix_milliseconds
    }
}

fn append_task_key(digest: &mut Sha256, key: &A2ATaskKey) {
    append_optional_identifier(digest, key.tenant());
    append_identifier(digest, key.agent_id().as_str());
    append_identifier(digest, key.task_id().as_str());
}

#[allow(
    clippy::too_many_arguments,
    reason = "the immutable task identity fields remain explicit"
)]
pub(crate) fn task_identity_digest(
    key: &A2ATaskKey,
    context_id: &A2AContextId,
    source_message_id: &A2AMessageId,
    conversation_id: ConversationId,
    target_device_id: DeviceId,
    request_message_id: MessageId,
    return_immediately: bool,
    history_length: Option<u32>,
    request_text_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(TASK_IDENTITY_DOMAIN);
    append_optional_identifier(&mut digest, key.tenant());
    append_identifier(&mut digest, key.agent_id().as_str());
    append_identifier(&mut digest, key.task_id().as_str());
    append_identifier(&mut digest, context_id.as_str());
    append_identifier(&mut digest, source_message_id.as_str());
    digest.update(conversation_id.as_bytes());
    digest.update(target_device_id.as_bytes());
    digest.update(request_message_id.as_bytes());
    digest.update([u8::from(return_immediately)]);
    match history_length {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
    digest.update(request_text_digest);
    digest.finalize().into()
}

pub(crate) fn text_digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

fn append_optional_identifier(digest: &mut Sha256, value: Option<&A2ATenantId>) {
    append_identifier(digest, value.map_or("", A2ATenantId::as_str));
}

fn append_identifier(digest: &mut Sha256, value: &str) {
    append_bytes(digest, value.as_bytes());
}

fn append_bytes(digest: &mut Sha256, value: &[u8]) {
    let Ok(length) = u32::try_from(value.len()) else {
        unreachable!();
    };
    digest.update(length.to_be_bytes());
    digest.update(value);
}
