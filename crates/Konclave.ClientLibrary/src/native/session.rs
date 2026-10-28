use std::sync::Arc;

use KonclaveDomainCore::{
    AcknowledgeRequest, ApplicationMessage, ConversationId, DeliveryClass, MembershipOperationId,
    MessageId, RelayEnvelope, ReplayPage, ReplayRequest, RoutingId, StoredRelayEnvelope,
};
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Mutex;

use super::{
    NativeApplicationRequest, PreparedApplication, PreparedMembership, ProcessedApplication,
};
use crate::{KonclaveClientError, RelayTransport};

/// Authenticated durable disposition of an exact outbound application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeOutboundStatus {
    /// Exact ciphertext remains eligible for retry.
    Ready,
    /// The relay accepted this exact ciphertext at the original cursor.
    Accepted { cursor: u64 },
    /// This operation expired before acceptance.
    Expired,
    /// Native membership removal permanently prevented this operation.
    Removed,
}

/// Opened exact application evidence selected by conversation and stable message ID.
pub struct NativeOutboundApplication {
    /// Authenticated conversation scope.
    pub conversation_id: ConversationId,
    /// Original protected plaintext and display timestamp.
    pub message: ApplicationMessage,
    /// Original immutable ciphertext, identity, route, and expiry.
    pub envelope: RelayEnvelope,
    /// Durable terminal or retry state.
    pub status: NativeOutboundStatus,
}

/// One bounded, currently eligible exact ciphertext retry.
pub struct NativePendingApplication {
    /// Authenticated conversation scope.
    pub conversation_id: ConversationId,
    /// Original immutable envelope.
    pub envelope: RelayEnvelope,
}

/// Atomic expiry outcome that retains a racing acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeExpiryOutcome {
    /// The exact unaccepted operation is now terminal.
    Expired,
    /// The original operation was already accepted.
    Accepted { cursor: u64 },
}

/// One accepted application; retries retain the original message and cursor.
pub struct NativeSentApplication {
    /// Authenticated conversation scope.
    pub conversation_id: ConversationId,
    /// Original protected plaintext.
    pub message: ApplicationMessage,
    /// Exact accepted relay cursor.
    pub cursor: u64,
}

/// One bounded page after native completion and relay acknowledgment.
pub struct NativeReplayBatch {
    /// Completed non-internal application messages in durable cursor order.
    pub messages: Vec<ProcessedApplication>,
    /// Whether the relay reports another bounded page.
    pub has_more: bool,
}

/// Explicit host operations for shared native relay/session orchestration.
///
/// The host is a trusted native endpoint, not a local-service JSON facade. Its
/// application and membership methods use the shared conversation processor.
/// Journal and MLS writes must fence the same exclusive owner. New admission
/// atomically verifies native authority and the exact live response claim.
///
/// Reads return bounded authenticated evidence; never infer absence from an
/// operational failure. Exact retries retain committed authorization and intent,
/// rather than admitting the operation again. Retry listings and eligibility
/// checks terminalize work whose local sender is no longer a native member.
///
/// The host owns blocking execution, custody and shutdown. It must bound, retain
/// and join any workers it starts, including when a calling future is dropped.
/// The session itself starts no tasks or background workers.
#[async_trait]
pub trait NativeSessionHost: Send + Sync + 'static {
    /// Stable sanitized host failures.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Explicit native admission evidence, not web identity.
    type Authorization: Send + 'static;

    /// Opens exact immutable evidence for an existing stable application identity.
    async fn outbound_application(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<Option<NativeOutboundApplication>, Self::Error>;
    /// Admits, encrypts and durably journals one new application.
    async fn prepare_application(
        &self,
        request: NativeApplicationRequest<Self::Authorization>,
    ) -> Result<PreparedApplication, Self::Error>;
    /// Returns bounded ready applications in original sender-counter order.
    async fn ready_applications(&self) -> Result<Vec<NativePendingApplication>, Self::Error>;
    /// Rechecks current local native membership before retrying an application.
    async fn retry_eligible(&self, conversation: ConversationId) -> Result<bool, Self::Error>;
    /// Atomically terminalizes only the exact unaccepted envelope.
    async fn expire_application(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<NativeExpiryOutcome, Self::Error>;
    /// Verifies and commits the exact relay acceptance.
    async fn accept_application(&self, stored: StoredRelayEnvelope) -> Result<(), Self::Error>;
    /// Returns bounded immutable ready membership operations.
    async fn ready_memberships(&self) -> Result<Vec<PreparedMembership>, Self::Error>;
    /// Verifies acceptance and completes the shared MLS/policy recovery ordering.
    async fn accept_membership(&self, stored: StoredRelayEnvelope) -> Result<(), Self::Error>;
    /// Rejects the exact pending MLS commit before orphaning its journal.
    async fn orphan_membership(&self, operation: MembershipOperationId) -> Result<(), Self::Error>;
    /// Opens/reconciles the conversation and returns its exact route/completed cursor.
    async fn replay_position(
        &self,
        conversation: ConversationId,
    ) -> Result<(RoutingId, u64), Self::Error>;
    /// Completes exact application evidence before returning.
    async fn process_application(
        &self,
        conversation: ConversationId,
        stored: StoredRelayEnvelope,
        now: u64,
    ) -> Result<ProcessedApplication, Self::Error>;
    /// Completes exact authenticated membership evidence before returning.
    async fn process_membership(
        &self,
        conversation: ConversationId,
        stored: StoredRelayEnvelope,
        now: u64,
    ) -> Result<(), Self::Error>;
}

/// Shared ordered send/retry/replay composition with explicitly injected dependencies.
///
/// All producers for the same endpoint must share the submission gate, including
/// host-specific policy and membership operations. Clones share that gate and
/// dependencies; constructing unrelated sessions does not create writer fencing.
pub struct NativeSession<H, T> {
    host: Arc<H>,
    relay: Arc<T>,
    submissions: Arc<Mutex<()>>,
}

impl<H, T> Clone for NativeSession<H, T> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            relay: Arc::clone(&self.relay),
            submissions: Arc::clone(&self.submissions),
        }
    }
}

impl<H: NativeSessionHost, T: RelayTransport> NativeSession<H, T> {
    /// Composes one native host and relay without profile discovery or workers.
    pub fn new(host: Arc<H>, relay: Arc<T>, submissions: Arc<Mutex<()>>) -> Self {
        Self {
            host,
            relay,
            submissions,
        }
    }

    /// Sends one operation or resumes its exact prior immutable evidence.
    ///
    /// # Errors
    ///
    /// Returns host, relay, idempotency, terminal-state or response-integrity failure.
    pub async fn send(
        &self,
        request: NativeApplicationRequest<H::Authorization>,
        now: u64,
    ) -> Result<NativeSentApplication, NativeSessionError<H::Error>> {
        let _submission = self.submissions.lock().await;
        if let Some(existing) = self
            .host
            .outbound_application(request.conversation_id, request.message_id)
            .await
            .map_err(NativeSessionError::Host)?
        {
            if existing.message.content() != &request.content
                || existing.message.reply_to() != request.reply_to
            {
                return Err(NativeSessionError::IdempotencyConflict);
            }
            return match existing.status {
                NativeOutboundStatus::Accepted { cursor } => Ok(NativeSentApplication {
                    conversation_id: existing.conversation_id,
                    message: existing.message,
                    cursor,
                }),
                NativeOutboundStatus::Ready => {
                    if !self
                        .host
                        .retry_eligible(existing.conversation_id)
                        .await
                        .map_err(NativeSessionError::Host)?
                    {
                        return Err(NativeSessionError::OutboundRemoved);
                    }
                    self.submit_prepared(
                        PreparedApplication {
                            conversation_id: existing.conversation_id,
                            message: existing.message,
                            envelope: existing.envelope,
                        },
                        now,
                    )
                    .await
                }
                NativeOutboundStatus::Expired => Err(NativeSessionError::OutboundExpired),
                NativeOutboundStatus::Removed => Err(NativeSessionError::OutboundRemoved),
            };
        }
        self.retry_ready_locked(now).await?;
        let prepared = self
            .host
            .prepare_application(request)
            .await
            .map_err(NativeSessionError::Host)?;
        self.submit_prepared(prepared, now).await
    }

    /// Retries bounded immutable applications and membership work in native order.
    ///
    /// # Errors
    ///
    /// Returns the first host, relay or response-integrity failure.
    pub async fn retry_ready(&self, now: u64) -> Result<usize, NativeSessionError<H::Error>> {
        let _submission = self.submissions.lock().await;
        self.retry_ready_locked(now).await
    }

    async fn retry_ready_locked(&self, now: u64) -> Result<usize, NativeSessionError<H::Error>> {
        let mut accepted = 0usize;
        for pending in self
            .host
            .ready_applications()
            .await
            .map_err(NativeSessionError::Host)?
        {
            if !self
                .host
                .retry_eligible(pending.conversation_id)
                .await
                .map_err(NativeSessionError::Host)?
            {
                continue;
            }
            if pending.envelope.expires_at_unix_seconds() <= now {
                match self
                    .host
                    .expire_application(&pending.envelope)
                    .await
                    .map_err(NativeSessionError::Host)?
                {
                    NativeExpiryOutcome::Expired => continue,
                    NativeExpiryOutcome::Accepted { .. } => {
                        accepted = accepted
                            .checked_add(1)
                            .ok_or(NativeSessionError::Protocol)?;
                        continue;
                    }
                }
            }
            let stored = self
                .relay
                .submit(&pending.envelope)
                .await
                .map_err(NativeSessionError::Relay)?;
            self.host
                .accept_application(stored)
                .await
                .map_err(NativeSessionError::Host)?;
            accepted = accepted
                .checked_add(1)
                .ok_or(NativeSessionError::Protocol)?;
        }
        for pending in self
            .host
            .ready_memberships()
            .await
            .map_err(NativeSessionError::Host)?
        {
            let stored = match self.relay.submit(&pending.envelope).await {
                Ok(stored) => stored,
                Err(error) if error.code() == "relay_stale_epoch" => {
                    self.host
                        .orphan_membership(pending.operation_id)
                        .await
                        .map_err(NativeSessionError::Host)?;
                    return Err(NativeSessionError::Relay(error));
                }
                Err(error) => return Err(NativeSessionError::Relay(error)),
            };
            self.host
                .accept_membership(stored)
                .await
                .map_err(NativeSessionError::Host)?;
            accepted = accepted
                .checked_add(1)
                .ok_or(NativeSessionError::Protocol)?;
        }
        Ok(accepted)
    }

    async fn submit_prepared(
        &self,
        prepared: PreparedApplication,
        now: u64,
    ) -> Result<NativeSentApplication, NativeSessionError<H::Error>> {
        let cursor = if prepared.envelope.expires_at_unix_seconds() <= now {
            match self
                .host
                .expire_application(&prepared.envelope)
                .await
                .map_err(NativeSessionError::Host)?
            {
                NativeExpiryOutcome::Expired => return Err(NativeSessionError::OutboundExpired),
                NativeExpiryOutcome::Accepted { cursor } => cursor,
            }
        } else {
            let stored = self
                .relay
                .submit(&prepared.envelope)
                .await
                .map_err(NativeSessionError::Relay)?;
            let cursor = stored.cursor();
            self.host
                .accept_application(stored)
                .await
                .map_err(NativeSessionError::Host)?;
            cursor
        };
        Ok(NativeSentApplication {
            conversation_id: prepared.conversation_id,
            message: prepared.message,
            cursor,
        })
    }

    /// Replays one bounded page and acknowledges only after durable completion.
    ///
    /// # Errors
    ///
    /// Returns host, relay, invalid request or exact response-integrity failure.
    pub async fn replay_once(
        &self,
        conversation: ConversationId,
        limit: u32,
        now: u64,
    ) -> Result<NativeReplayBatch, NativeSessionError<H::Error>> {
        let (route, after) = self
            .host
            .replay_position(conversation)
            .await
            .map_err(NativeSessionError::Host)?;
        let request =
            ReplayRequest::new(route, after, limit).map_err(|_| NativeSessionError::Protocol)?;
        let page = self
            .relay
            .replay(request)
            .await
            .map_err(NativeSessionError::Relay)?;
        if page.envelopes().len() > limit as usize {
            return Err(NativeSessionError::InvalidRelayResponse);
        }
        self.process_page(conversation, route, after, page, now)
            .await
    }

    /// Processes an explicitly scoped replay/watch page without owning a watch task.
    ///
    /// # Errors
    ///
    /// Rejects invalid page evidence before mutation and propagates completion/ack failures.
    pub async fn process_page(
        &self,
        conversation: ConversationId,
        route: RoutingId,
        after: u64,
        page: ReplayPage,
        now: u64,
    ) -> Result<NativeReplayBatch, NativeSessionError<H::Error>> {
        validate_native_replay_page(after, &page)
            .map_err(|_| NativeSessionError::InvalidRelayResponse)?;
        if page
            .envelopes()
            .iter()
            .any(|stored| stored.envelope().routing_id() != route)
        {
            return Err(NativeSessionError::InvalidRelayResponse);
        }
        let has_more = page.has_more();
        let last = page.envelopes().last().map(StoredRelayEnvelope::cursor);
        let mut messages = Vec::with_capacity(page.envelopes().len());
        for stored in page.envelopes() {
            match stored.envelope().delivery_class() {
                DeliveryClass::GroupApplication => {
                    let processed = self
                        .host
                        .process_application(conversation, stored.clone(), now)
                        .await
                        .map_err(NativeSessionError::Host)?;
                    if !processed.message.content().is_internal() {
                        messages.push(processed);
                    }
                }
                DeliveryClass::GroupCommit => {
                    self.host
                        .process_membership(conversation, stored.clone(), now)
                        .await
                        .map_err(NativeSessionError::Host)?;
                }
                _ => return Err(NativeSessionError::Protocol),
            }
        }
        if let Some(cursor) = last {
            let requested =
                AcknowledgeRequest::new(route, cursor).map_err(|_| NativeSessionError::Protocol)?;
            let effective = self
                .relay
                .acknowledge(requested)
                .await
                .map_err(NativeSessionError::Relay)?;
            validate_native_acknowledgment(requested, effective)
                .map_err(|_| NativeSessionError::InvalidRelayResponse)?;
        }
        Ok(NativeReplayBatch { messages, has_more })
    }
}

/// Pure rejection of contradictory relay evidence.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("relay response contradicts the exact native operation")]
pub struct NativeRelayEvidenceError;

/// Accepts only the requested route and an effective cursor at or ahead of it.
///
/// # Errors
///
/// Rejects a rewritten route or regressed cursor.
pub fn validate_native_acknowledgment(
    requested: AcknowledgeRequest,
    effective: AcknowledgeRequest,
) -> Result<(), NativeRelayEvidenceError> {
    if effective.routing_id() != requested.routing_id() || effective.cursor() < requested.cursor() {
        return Err(NativeRelayEvidenceError);
    }
    Ok(())
}

/// Verifies a complete contiguous bounded cursor page before any native mutation.
///
/// # Errors
///
/// Rejects gaps, duplicates, overflow or a contradictory continuation cursor.
pub fn validate_native_replay_page(
    after: u64,
    page: &ReplayPage,
) -> Result<(), NativeRelayEvidenceError> {
    let mut expected = after;
    for stored in page.envelopes() {
        expected = expected.checked_add(1).ok_or(NativeRelayEvidenceError)?;
        if stored.cursor() != expected {
            return Err(NativeRelayEvidenceError);
        }
    }
    if page.next_cursor() != expected {
        return Err(NativeRelayEvidenceError);
    }
    Ok(())
}

/// Stable session failures with no payload-bearing diagnostics.
#[derive(Debug, Error)]
pub enum NativeSessionError<E> {
    /// The explicit host rejected or failed an operation.
    #[error("native host operation failed")]
    Host(E),
    /// Authenticated relay transport failed.
    #[error("native relay operation failed")]
    Relay(KonclaveClientError),
    /// Request construction or bounded arithmetic was invalid.
    #[error("native session request is invalid")]
    Protocol,
    /// Stable identity was reused with different content or reply correlation.
    #[error("native application identity conflicts with prior intent")]
    IdempotencyConflict,
    /// An unaccepted operation expired permanently.
    #[error("native application expired before acceptance")]
    OutboundExpired,
    /// Native membership removal permanently prevented the operation.
    #[error("native sender is no longer a conversation member")]
    OutboundRemoved,
    /// Relay evidence contradicted the exact operation.
    #[error("native relay response is inconsistent")]
    InvalidRelayResponse,
}
