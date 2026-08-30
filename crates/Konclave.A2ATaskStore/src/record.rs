use KonclaveA2ADomain::{A2AArtifactId, A2AContextId, A2AMessageId, A2ATaskState};
use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};

use crate::model::{task_identity_digest, text_digest};
use crate::{A2ATaskKey, A2ATaskMessageRole, A2ATerminalReason};

/// Durable task projection returned by a semantic store.
pub struct A2ATaskRecord {
    key: A2ATaskKey,
    context_id: A2AContextId,
    source_message_id: A2AMessageId,
    conversation_id: ConversationId,
    target_device_id: DeviceId,
    request_message_id: MessageId,
    identity_digest: [u8; 32],
    request_text_digest: [u8; 32],
    request_text: Option<String>,
    return_immediately: bool,
    history_length: Option<u32>,
    state: A2ATaskState,
    generation: u64,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
    terminal_at_unix_milliseconds: Option<u64>,
    terminal_reason: Option<A2ATerminalReason>,
    content_pruned: bool,
}

impl A2ATaskRecord {
    /// Creates a record from persistence-owned validated fields.
    #[allow(
        clippy::too_many_arguments,
        reason = "the complete durable task projection remains explicit"
    )]
    #[must_use]
    pub fn new(
        key: A2ATaskKey,
        context_id: A2AContextId,
        source_message_id: A2AMessageId,
        conversation_id: ConversationId,
        target_device_id: DeviceId,
        request_message_id: MessageId,
        identity_digest: [u8; 32],
        request_text_digest: [u8; 32],
        request_text: Option<String>,
        return_immediately: bool,
        history_length: Option<u32>,
        state: A2ATaskState,
        generation: u64,
        created_at_unix_milliseconds: u64,
        updated_at_unix_milliseconds: u64,
        terminal_at_unix_milliseconds: Option<u64>,
        terminal_reason: Option<A2ATerminalReason>,
        content_pruned: bool,
    ) -> Self {
        Self {
            key,
            context_id,
            source_message_id,
            conversation_id,
            target_device_id,
            request_message_id,
            identity_digest,
            request_text_digest,
            request_text,
            return_immediately,
            history_length,
            state,
            generation,
            created_at_unix_milliseconds,
            updated_at_unix_milliseconds,
            terminal_at_unix_milliseconds,
            terminal_reason,
            content_pruned,
        }
    }

    /// Returns the exact task key.
    #[must_use]
    pub const fn key(&self) -> &A2ATaskKey {
        &self.key
    }

    /// Returns the public A2A context.
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

    /// Returns the configured exact target.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the mapped Konclave request identifier.
    #[must_use]
    pub const fn request_message_id(&self) -> MessageId {
        self.request_message_id
    }

    /// Returns the immutable identity digest.
    #[must_use]
    pub const fn identity_digest(&self) -> &[u8; 32] {
        &self.identity_digest
    }

    /// Returns the retained SHA-256 digest of the original request text.
    #[must_use]
    pub const fn request_text_digest(&self) -> &[u8; 32] {
        &self.request_text_digest
    }

    /// Returns request text while retained.
    #[must_use]
    pub fn request_text(&self) -> Option<&str> {
        self.request_text.as_deref()
    }

    /// Returns whether immediate response was requested.
    #[must_use]
    pub const fn return_immediately(&self) -> bool {
        self.return_immediately
    }

    /// Returns the requested history length.
    #[must_use]
    pub const fn history_length(&self) -> Option<u32> {
        self.history_length
    }

    /// Returns current A2A task state.
    #[must_use]
    pub const fn state(&self) -> A2ATaskState {
        self.state
    }

    /// Returns the optimistic transition generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at_unix_milliseconds(&self) -> u64 {
        self.created_at_unix_milliseconds
    }

    /// Returns the latest transition timestamp.
    #[must_use]
    pub const fn updated_at_unix_milliseconds(&self) -> u64 {
        self.updated_at_unix_milliseconds
    }

    /// Returns the terminal timestamp, when terminal.
    #[must_use]
    pub const fn terminal_at_unix_milliseconds(&self) -> Option<u64> {
        self.terminal_at_unix_milliseconds
    }

    /// Returns the terminal reason, when present.
    #[must_use]
    pub const fn terminal_reason(&self) -> Option<&A2ATerminalReason> {
        self.terminal_reason.as_ref()
    }

    /// Returns whether payload rows were removed by retention.
    #[must_use]
    pub const fn content_pruned(&self) -> bool {
        self.content_pruned
    }

    /// Verifies retained task identity fields against the durable digest.
    #[must_use]
    pub fn retained_identity_is_valid(&self) -> bool {
        if self
            .request_text
            .as_ref()
            .is_some_and(|request_text| text_digest(request_text) != self.request_text_digest)
        {
            return false;
        }
        task_identity_digest(
            &self.key,
            &self.context_id,
            &self.source_message_id,
            self.conversation_id,
            self.target_device_id,
            self.request_message_id,
            self.return_immediately,
            self.history_length,
            self.request_text_digest,
        ) == self.identity_digest
    }
}

/// One ordered task-history message.
pub struct StoredA2ATaskMessage {
    sequence: u64,
    message_id: A2AMessageId,
    role: A2ATaskMessageRole,
    text: String,
    recorded_at_unix_milliseconds: u64,
}

impl StoredA2ATaskMessage {
    /// Creates a persistence-owned message result.
    #[must_use]
    pub fn new(
        sequence: u64,
        message_id: A2AMessageId,
        role: A2ATaskMessageRole,
        text: String,
        recorded_at_unix_milliseconds: u64,
    ) -> Self {
        Self {
            sequence,
            message_id,
            role,
            text,
            recorded_at_unix_milliseconds,
        }
    }

    /// Returns the store-assigned sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the task-scoped message identifier.
    #[must_use]
    pub const fn message_id(&self) -> &A2AMessageId {
        &self.message_id
    }

    /// Returns the typed sender role.
    #[must_use]
    pub const fn role(&self) -> A2ATaskMessageRole {
        self.role
    }

    /// Returns the retained plaintext message.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the message timestamp.
    #[must_use]
    pub const fn recorded_at_unix_milliseconds(&self) -> u64 {
        self.recorded_at_unix_milliseconds
    }
}

/// One ordered opaque artifact record.
pub struct StoredA2ATaskArtifact {
    sequence: u64,
    artifact_id: A2AArtifactId,
    content_digest: [u8; 32],
    canonical_bytes: Vec<u8>,
    complete: bool,
    recorded_at_unix_milliseconds: u64,
}

impl StoredA2ATaskArtifact {
    /// Creates a persistence-owned artifact result.
    #[must_use]
    pub fn new(
        sequence: u64,
        artifact_id: A2AArtifactId,
        content_digest: [u8; 32],
        canonical_bytes: Vec<u8>,
        complete: bool,
        recorded_at_unix_milliseconds: u64,
    ) -> Self {
        Self {
            sequence,
            artifact_id,
            content_digest,
            canonical_bytes,
            complete,
            recorded_at_unix_milliseconds,
        }
    }

    /// Returns the store-assigned sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the task-scoped artifact identifier.
    #[must_use]
    pub const fn artifact_id(&self) -> &A2AArtifactId {
        &self.artifact_id
    }

    /// Returns the canonical content digest.
    #[must_use]
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns retained canonical artifact bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
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
}
