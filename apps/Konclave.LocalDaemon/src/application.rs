use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use KonclaveClientLibrary::{KonclaveClientError, RelayTransport};
use KonclaveCryptographicCore::MlsWelcome;
use KonclaveDomainCore::{
    AcknowledgeRequest, ApplicationContent, ApplicationMessage, ConversationId, ConversationRole,
    DeviceId, JoinProof, MembershipOperationId, MessageId, ReplayPage, ReplayRequest,
    StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{decode_join_proof, encode_join_proof};
use thiserror::Error;
use tokio::sync::watch;

use crate::conversation::{
    AcceptedMembership, ConversationCoordinator, ConversationCoordinatorError, ConversationSummary,
    MembershipRequestState, PreparedApplication, PreparedMembership, ProcessedApplication,
};
use crate::persistence::{ExpireOutboundResult, HistoryPage, OutboundApplicationStatus};

/// Outbound application input with caller-supplied display and expiry times.
pub(crate) struct SendApplicationRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message_id: MessageId,
    pub(crate) content: ApplicationContent,
    pub(crate) reply_to: Option<MessageId>,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) now_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

/// One accepted application message and its durable relay cursor.
pub(crate) struct SentApplication {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message: ApplicationMessage,
    pub(crate) cursor: u64,
}

/// One accepted membership transition and optional add-member Welcome.
pub(crate) struct SentMembership {
    pub(crate) operation_id: MembershipOperationId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) cursor: u64,
    pub(crate) welcome: Option<Vec<u8>>,
}

/// One bounded replay result after durable local completion and acknowledgment.
pub(crate) struct ReplayBatch {
    pub(crate) messages: Vec<ProcessedApplication>,
    pub(crate) has_more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchConnectionExit {
    Shutdown,
    LocalMemberRemoved,
}

/// Async relay composition over synchronous sealed conversation state.
pub(crate) struct ApplicationService<T> {
    conversations: ConversationCoordinator,
    transport: Arc<T>,
    submissions: Arc<tokio::sync::Mutex<()>>,
}

impl<T> ApplicationService<T> {
    /// Signals when this profile joins a conversation it was not previously in.
    pub(crate) fn membership_changed(&self) -> std::sync::Arc<tokio::sync::Notify> {
        self.conversations.membership_changed()
    }

    /// Returns the authenticated relay transport shared by composed daemon services.
    pub(crate) fn relay_transport(&self) -> Arc<T> {
        Arc::clone(&self.transport)
    }
}

impl<T> Clone for ApplicationService<T> {
    fn clone(&self) -> Self {
        Self {
            conversations: self.conversations.clone(),
            transport: Arc::clone(&self.transport),
            submissions: Arc::clone(&self.submissions),
        }
    }
}

impl<T> ApplicationService<T>
where
    T: RelayTransport + 'static,
{
    /// Creates an application service sharing one authenticated relay transport.
    pub(crate) fn new(conversations: ConversationCoordinator, transport: T) -> Self {
        Self::from_shared(conversations, Arc::new(transport))
    }

    /// Creates an application service over an already shared relay transport.
    pub(crate) fn from_shared(conversations: ConversationCoordinator, transport: Arc<T>) -> Self {
        Self {
            conversations,
            transport,
            submissions: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Encrypts, journals, submits, and accepts one application message.
    ///
    /// Synchronous cryptographic and SQLite work runs on Tokio's blocking pool.
    /// One async submission gate remains held through relay acceptance so sender
    /// counters cannot reach the route out of order.
    /// Network failure leaves the sealed ready envelope available to
    /// [`Self::retry_ready`].
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error without converting
    /// failure into a success-shaped response.
    pub(crate) async fn send(
        &self,
        request: SendApplicationRequest,
    ) -> Result<SentApplication, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        let conversations = self.conversations.clone();
        let conversation_id = request.conversation_id;
        let message_id = request.message_id;
        if let Some(existing) = tokio::task::spawn_blocking(move || {
            conversations.outbound_application(conversation_id, message_id)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??
        {
            if !application_content_equal(existing.message.content(), &request.content)
                || existing.message.reply_to() != request.reply_to
            {
                return Err(ApplicationServiceError::IdempotencyConflict);
            }
            return match existing.status {
                OutboundApplicationStatus::Accepted { cursor } => Ok(SentApplication {
                    conversation_id: existing.conversation_id,
                    message: existing.message,
                    cursor,
                }),
                OutboundApplicationStatus::Ready => {
                    self.submit_prepared(
                        PreparedApplication {
                            conversation_id: existing.conversation_id,
                            message: existing.message,
                            envelope: existing.envelope,
                        },
                        request.now_unix_seconds,
                    )
                    .await
                }
                OutboundApplicationStatus::Expired => Err(ApplicationServiceError::OutboundExpired),
                OutboundApplicationStatus::Removed => Err(ApplicationServiceError::OutboundRemoved),
            };
        }
        self.retry_ready_locked(request.now_unix_seconds).await?;
        let conversations = self.conversations.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            conversations.prepare_application_with_id(
                request.conversation_id,
                request.message_id,
                request.content,
                request.reply_to,
                request.sent_at_unix_milliseconds,
                request.expires_at_unix_seconds,
            )
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        self.submit_prepared(prepared, request.now_unix_seconds)
            .await
    }

    /// Adds one invited device through a durable encrypted membership commit.
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error.
    pub(crate) async fn add_member(
        &self,
        conversation_id: ConversationId,
        join_proof: JoinProof,
        now_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<SentMembership, ApplicationServiceError> {
        let submission = Arc::clone(&self.submissions).lock_owned().await;
        self.retry_application_ready_locked(now_unix_seconds)
            .await?;
        if let Some(existing) = self.find_add_member(conversation_id, &join_proof).await? {
            return self.resume_membership(existing).await;
        }
        self.retry_membership_ready_locked().await?;
        let conversations = self.conversations.clone();
        let (submission, prepared) = tokio::task::spawn_blocking(move || {
            let prepared = conversations.prepare_add_member(
                conversation_id,
                join_proof,
                now_unix_seconds,
                expires_at_unix_seconds,
            );
            (submission, prepared)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)?;
        let _submission = submission;
        let prepared = prepared?;
        self.submit_membership(prepared).await
    }

    /// Resumes an exact add-member journal without creating one when no request was
    /// prepared before a crash.
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error.
    pub(crate) async fn resume_add_member(
        &self,
        conversation_id: ConversationId,
        join_proof: &JoinProof,
        now_unix_seconds: u64,
    ) -> Result<Option<SentMembership>, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        self.retry_application_ready_locked(now_unix_seconds)
            .await?;
        match self.find_add_member(conversation_id, join_proof).await? {
            Some(existing) => self.resume_membership(existing).await.map(Some),
            None => Ok(None),
        }
    }

    /// Removes one device through a durable encrypted membership commit.
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error.
    pub(crate) async fn remove_member(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        now_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<SentMembership, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        self.retry_application_ready_locked(now_unix_seconds)
            .await?;
        let conversations = self.conversations.clone();
        if let Some(existing) = tokio::task::spawn_blocking(move || {
            conversations.resume_remove_member(conversation_id, device_id)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??
        {
            return self.resume_membership(existing).await;
        }
        self.retry_membership_ready_locked().await?;
        let conversations = self.conversations.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            conversations.prepare_remove_member(conversation_id, device_id, expires_at_unix_seconds)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        self.submit_membership(prepared).await
    }

    /// Changes one member role through a durable encrypted membership commit.
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error.
    pub(crate) async fn change_role(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        role: ConversationRole,
        now_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<SentMembership, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        self.retry_application_ready_locked(now_unix_seconds)
            .await?;
        let conversations = self.conversations.clone();
        if let Some(existing) = tokio::task::spawn_blocking(move || {
            conversations.resume_change_role(conversation_id, device_id, role)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??
        {
            return self.resume_membership(existing).await;
        }
        self.retry_membership_ready_locked().await?;
        let conversations = self.conversations.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            conversations.prepare_change_role(
                conversation_id,
                device_id,
                role,
                expires_at_unix_seconds,
            )
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        self.submit_membership(prepared).await
    }

    /// Verifies one relay Commit receipt and accepts its encrypted Welcome.
    ///
    /// # Errors
    ///
    /// Returns a request, relay, task, Welcome, profile, or receipt-integrity error.
    pub(crate) async fn accept_welcome(
        &self,
        conversation_id: ConversationId,
        welcome: MlsWelcome,
        cursor: u64,
    ) -> Result<ConversationSummary, ApplicationServiceError> {
        self.accept_welcome_with_retention(conversation_id, welcome, cursor, false)
            .await
    }

    /// Verifies and accepts a pairing Welcome while retaining its recovery journal
    /// until pairing completion is relay-accepted.
    ///
    /// # Errors
    ///
    /// Returns a request, relay, task, Welcome, profile, or receipt-integrity error.
    pub(crate) async fn accept_pairing_welcome(
        &self,
        conversation_id: ConversationId,
        welcome: MlsWelcome,
        cursor: u64,
    ) -> Result<ConversationSummary, ApplicationServiceError> {
        self.accept_welcome_with_retention(conversation_id, welcome, cursor, true)
            .await
    }

    async fn accept_welcome_with_retention(
        &self,
        conversation_id: ConversationId,
        welcome: MlsWelcome,
        cursor: u64,
        retain_pending_join: bool,
    ) -> Result<ConversationSummary, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        let after_cursor = cursor
            .checked_sub(1)
            .ok_or(ApplicationServiceError::Protocol)?;
        let conversations = self.conversations.clone();
        let routing_id =
            tokio::task::spawn_blocking(move || conversations.pending_join_route(conversation_id))
                .await
                .map_err(|_| ApplicationServiceError::Task)??;
        let page = self
            .transport
            .replay(
                ReplayRequest::new(routing_id, after_cursor, 1)
                    .map_err(|_| ApplicationServiceError::Protocol)?,
            )
            .await?;
        let [receipt] = page.envelopes() else {
            return Err(ApplicationServiceError::InvalidRelayResponse);
        };
        if receipt.cursor() != cursor
            || receipt.envelope().routing_id() != routing_id
            || receipt.envelope().delivery_class() != KonclaveDomainCore::DeliveryClass::GroupCommit
        {
            return Err(ApplicationServiceError::InvalidRelayResponse);
        }
        let receipt = receipt.clone();
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || {
            if retain_pending_join {
                conversations.accept_pairing_welcome(conversation_id, &welcome, &receipt)
            } else {
                conversations.accept_welcome(conversation_id, &welcome, &receipt)
            }
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)?
        .map_err(Into::into)
    }

    /// Retries every bounded ready envelope in deterministic journal order.
    ///
    /// Expired application envelopes become durable terminal operations and do not
    /// block later ready work. Processing stops at the first other relay or
    /// persistence failure.
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error.
    pub(crate) async fn retry_ready(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        self.retry_ready_locked(now_unix_seconds).await
    }

    /// Replays, processes, and acknowledges one bounded page for a conversation.
    ///
    /// The relay acknowledgment is sent only after every returned cursor is durably
    /// complete in the sealed local journal. A processing failure leaves the prior
    /// contiguous cursor unchanged for exact replay.
    ///
    /// # Errors
    ///
    /// Returns a request, task, conversation, relay, or response-integrity error.
    pub(crate) async fn replay_once(
        &self,
        conversation_id: ConversationId,
        limit: u32,
        now_unix_seconds: u64,
    ) -> Result<ReplayBatch, ApplicationServiceError> {
        let (request, routing_id, after_cursor) =
            self.replay_request(conversation_id, limit).await?;
        let page = self.transport.replay(request).await?;
        self.process_page(
            conversation_id,
            routing_id,
            after_cursor,
            page,
            now_unix_seconds,
        )
        .await
    }

    /// Waits for and processes one bounded WebSocket replay page.
    ///
    /// The caller owns cancellation by dropping the returned future. The temporary
    /// watch session is closed normally after the page has been durably processed.
    ///
    /// # Errors
    ///
    /// Returns a request, task, conversation, relay, or response-integrity error.
    pub(crate) async fn watch_once(
        &self,
        conversation_id: ConversationId,
        now_unix_seconds: u64,
    ) -> Result<ReplayBatch, ApplicationServiceError> {
        let (request, routing_id, after_cursor) = self.replay_request(conversation_id, 100).await?;
        let mut watch = self.transport.connect_watch(request).await?;
        let page = watch.next_page().await?;
        let processed = self
            .process_page(
                conversation_id,
                routing_id,
                after_cursor,
                page,
                now_unix_seconds,
            )
            .await;
        let closed = watch.close().await;
        match processed {
            Err(error) => Err(error),
            Ok(batch) => {
                closed?;
                Ok(batch)
            }
        }
    }

    /// Processes every page from one authenticated watch connection until shutdown,
    /// local removal, or a transport failure.
    ///
    /// Empty initial pages confirm the connection and do not end the watch. Relay
    /// acknowledgment still follows durable local processing for every non-empty page.
    ///
    /// # Errors
    ///
    /// Returns a task, clock, request, relay, conversation, or response-integrity
    /// error. The owning supervisor classifies reconnectable transport failures.
    pub(crate) async fn watch_connection_until(
        &self,
        conversation_id: ConversationId,
        shutdown: watch::Receiver<bool>,
    ) -> Result<WatchConnectionExit, ApplicationServiceError> {
        self.watch_connection_until_observed(conversation_id, shutdown, |_| {})
            .await
    }

    async fn watch_connection_until_observed<F>(
        &self,
        conversation_id: ConversationId,
        mut shutdown: watch::Receiver<bool>,
        mut observe_page: F,
    ) -> Result<WatchConnectionExit, ApplicationServiceError>
    where
        F: FnMut(&ReplayPage),
    {
        if !self.is_local_member(conversation_id).await? {
            return Ok(WatchConnectionExit::LocalMemberRemoved);
        }
        let (request, routing_id, mut after_cursor) =
            self.replay_request(conversation_id, 100).await?;
        self.acknowledge_cursor(routing_id, after_cursor).await?;
        let mut watch_session = self.transport.connect_watch(request).await?;
        loop {
            let page = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        watch_session.close().await?;
                        return Ok(WatchConnectionExit::Shutdown);
                    }
                    continue;
                }
                page = watch_session.next_page() => page?,
            };
            observe_page(&page);
            let next_cursor = page.next_cursor();
            self.process_page(
                conversation_id,
                routing_id,
                after_cursor,
                page,
                current_unix_seconds()?,
            )
            .await?;
            after_cursor = next_cursor;
            if !self.is_local_member(conversation_id).await? {
                watch_session.close().await?;
                return Ok(WatchConnectionExit::LocalMemberRemoved);
            }
        }
    }

    /// Lists one bounded page of durable conversation identifiers.
    ///
    /// # Errors
    ///
    /// Returns a blocking-task or profile-store error.
    pub(crate) async fn conversation_page(
        &self,
        after: Option<ConversationId>,
        limit: usize,
    ) -> Result<Vec<ConversationId>, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.conversation_ids(after, limit))
            .await
            .map_err(|_| ApplicationServiceError::Task)?
            .map_err(Into::into)
    }

    /// Returns whether the local profile remains a conversation member.
    ///
    /// # Errors
    ///
    /// Returns a blocking-task, profile-store, or state-lock error.
    pub(crate) async fn is_local_member(
        &self,
        conversation_id: ConversationId,
    ) -> Result<bool, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.is_local_member(conversation_id))
            .await
            .map_err(|_| ApplicationServiceError::Task)?
            .map_err(Into::into)
    }

    async fn replay_request(
        &self,
        conversation_id: ConversationId,
        limit: u32,
    ) -> Result<(ReplayRequest, KonclaveDomainCore::RoutingId, u64), ApplicationServiceError> {
        let conversations = self.conversations.clone();
        let (routing_id, after_cursor) =
            tokio::task::spawn_blocking(move || conversations.replay_position(conversation_id))
                .await
                .map_err(|_| ApplicationServiceError::Task)??;
        let request = ReplayRequest::new(routing_id, after_cursor, limit)
            .map_err(|_| ApplicationServiceError::Protocol)?;
        Ok((request, routing_id, after_cursor))
    }

    async fn acknowledge_cursor(
        &self,
        routing_id: KonclaveDomainCore::RoutingId,
        cursor: u64,
    ) -> Result<(), ApplicationServiceError> {
        if cursor == 0 {
            return Ok(());
        }
        let acknowledgment = AcknowledgeRequest::new(routing_id, cursor)
            .map_err(|_| ApplicationServiceError::Protocol)?;
        let effective = self.transport.acknowledge(acknowledgment).await?;
        validate_acknowledgment(acknowledgment, effective)
    }

    async fn process_page(
        &self,
        conversation_id: ConversationId,
        routing_id: KonclaveDomainCore::RoutingId,
        after_cursor: u64,
        page: ReplayPage,
        now_unix_seconds: u64,
    ) -> Result<ReplayBatch, ApplicationServiceError> {
        validate_replay_page(after_cursor, &page)?;
        let has_more = page.has_more();
        let envelopes = page.envelopes().to_vec();
        let last_cursor = envelopes.last().map(StoredRelayEnvelope::cursor);
        let mut messages = Vec::with_capacity(envelopes.len());
        for stored in envelopes {
            let conversations = self.conversations.clone();
            match stored.envelope().delivery_class() {
                KonclaveDomainCore::DeliveryClass::GroupApplication => {
                    messages.push(
                        tokio::task::spawn_blocking(move || {
                            conversations.process_inbound_application(conversation_id, &stored)
                        })
                        .await
                        .map_err(|_| ApplicationServiceError::Task)??,
                    );
                }
                KonclaveDomainCore::DeliveryClass::GroupCommit => {
                    tokio::task::spawn_blocking(move || {
                        conversations.process_inbound_membership(
                            conversation_id,
                            &stored,
                            now_unix_seconds,
                        )
                    })
                    .await
                    .map_err(|_| ApplicationServiceError::Task)??;
                }
                _ => return Err(ApplicationServiceError::Protocol),
            }
        }
        if let Some(last_cursor) = last_cursor {
            let acknowledgment = AcknowledgeRequest::new(routing_id, last_cursor)
                .map_err(|_| ApplicationServiceError::Protocol)?;
            let effective = self.transport.acknowledge(acknowledgment).await?;
            validate_acknowledgment(acknowledgment, effective)?;
        }
        Ok(ReplayBatch { messages, has_more })
    }

    /// Reads one bounded page of completed sent and received history.
    ///
    /// # Errors
    ///
    /// Returns a task or sealed conversation-history error.
    pub(crate) async fn read(
        &self,
        conversation_id: ConversationId,
        after_cursor: u64,
        limit: usize,
    ) -> Result<HistoryPage, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || {
            conversations.history(conversation_id, after_cursor, limit)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)?
        .map_err(Into::into)
    }

    async fn retry_ready_locked(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, ApplicationServiceError> {
        let applications = self
            .retry_application_ready_locked(now_unix_seconds)
            .await?;
        let memberships = self.retry_membership_ready_locked().await?;
        applications
            .checked_add(memberships)
            .ok_or(ApplicationServiceError::Protocol)
    }

    async fn find_add_member(
        &self,
        conversation_id: ConversationId,
        join_proof: &JoinProof,
    ) -> Result<Option<MembershipRequestState>, ApplicationServiceError> {
        let proof_for_lookup = decode_join_proof(
            &encode_join_proof(join_proof).map_err(|_| ApplicationServiceError::Protocol)?,
        )
        .map_err(|_| ApplicationServiceError::Protocol)?;
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || {
            conversations.resume_add_member(conversation_id, &proof_for_lookup)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)?
        .map_err(Into::into)
    }

    async fn retry_application_ready_locked(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        let pending = tokio::task::spawn_blocking(move || conversations.ready_outbox())
            .await
            .map_err(|_| ApplicationServiceError::Task)??;
        let mut accepted = 0;
        for pending in pending {
            let conversations = self.conversations.clone();
            let conversation_id = pending.conversation_id;
            let eligible = tokio::task::spawn_blocking(move || {
                conversations.outbound_retry_eligible(conversation_id)
            })
            .await
            .map_err(|_| ApplicationServiceError::Task)??;
            if !eligible {
                continue;
            }
            if pending.envelope.expires_at_unix_seconds() <= now_unix_seconds {
                match self.expire_outbound(pending.envelope).await? {
                    ExpireOutboundResult::Expired => continue,
                    ExpireOutboundResult::Accepted { .. } => {
                        accepted += 1;
                        continue;
                    }
                }
            }
            let stored = self.transport.submit(&pending.envelope).await?;
            self.mark_accepted(stored).await?;
            accepted += 1;
        }
        Ok(accepted)
    }

    async fn retry_membership_ready_locked(&self) -> Result<usize, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        let pending = tokio::task::spawn_blocking(move || conversations.ready_membership_outbox())
            .await
            .map_err(|_| ApplicationServiceError::Task)??;
        let mut accepted = 0;
        for pending in pending {
            self.submit_membership(pending).await?;
            accepted += 1;
        }
        Ok(accepted)
    }

    async fn submit_prepared(
        &self,
        prepared: PreparedApplication,
        now_unix_seconds: u64,
    ) -> Result<SentApplication, ApplicationServiceError> {
        if prepared.envelope.expires_at_unix_seconds() <= now_unix_seconds {
            return match self.expire_outbound(prepared.envelope).await? {
                ExpireOutboundResult::Expired => Err(ApplicationServiceError::OutboundExpired),
                ExpireOutboundResult::Accepted { cursor } => Ok(SentApplication {
                    conversation_id: prepared.conversation_id,
                    message: prepared.message,
                    cursor,
                }),
            };
        }
        let stored = self.transport.submit(&prepared.envelope).await?;
        let cursor = stored.cursor();
        self.mark_accepted(stored).await?;
        Ok(SentApplication {
            conversation_id: prepared.conversation_id,
            message: prepared.message,
            cursor,
        })
    }

    async fn expire_outbound(
        &self,
        envelope: KonclaveDomainCore::RelayEnvelope,
    ) -> Result<ExpireOutboundResult, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.expire_outbound_application(&envelope))
            .await
            .map_err(|_| ApplicationServiceError::Task)?
            .map_err(Into::into)
    }

    async fn mark_accepted(
        &self,
        stored: StoredRelayEnvelope,
    ) -> Result<(), ApplicationServiceError> {
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.mark_outbox_accepted(&stored))
            .await
            .map_err(|_| ApplicationServiceError::Task)??;
        Ok(())
    }

    async fn submit_membership(
        &self,
        prepared: PreparedMembership,
    ) -> Result<SentMembership, ApplicationServiceError> {
        let stored = match self.transport.submit(&prepared.envelope).await {
            Ok(stored) => stored,
            Err(error) if error.code() == "relay_stale_epoch" => {
                let conversations = self.conversations.clone();
                let operation_id = prepared.operation_id;
                tokio::task::spawn_blocking(move || conversations.orphan_membership(operation_id))
                    .await
                    .map_err(|_| ApplicationServiceError::Task)??;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        let conversations = self.conversations.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            conversations.mark_membership_outbox_accepted(&stored)
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        Ok(sent_membership(accepted))
    }

    async fn resume_membership(
        &self,
        existing: MembershipRequestState,
    ) -> Result<SentMembership, ApplicationServiceError> {
        match existing {
            MembershipRequestState::Ready(prepared) => self.submit_membership(prepared).await,
            MembershipRequestState::Applied(accepted) => Ok(sent_membership(accepted)),
        }
    }
}

/// Accepts a relay acknowledgment whose effective cursor is at or ahead of the
/// requested cursor.
///
/// Relay retention state is monotonic and shared by every principal-authorized reader
/// of a route, so a concurrent reader or an acknowledgment that outlived a crash can
/// already have advanced it. Only a regressed cursor or a rewritten route contradicts
/// the relay contract.
pub(crate) fn validate_acknowledgment(
    requested: AcknowledgeRequest,
    effective: AcknowledgeRequest,
) -> Result<(), ApplicationServiceError> {
    if effective.routing_id() != requested.routing_id() || effective.cursor() < requested.cursor() {
        return Err(ApplicationServiceError::InvalidRelayResponse);
    }
    Ok(())
}

pub(crate) fn validate_replay_page(
    after_cursor: u64,
    page: &ReplayPage,
) -> Result<(), ApplicationServiceError> {
    let mut expected_cursor = after_cursor;
    for stored in page.envelopes() {
        expected_cursor = expected_cursor
            .checked_add(1)
            .ok_or(ApplicationServiceError::InvalidRelayResponse)?;
        if stored.cursor() != expected_cursor {
            return Err(ApplicationServiceError::InvalidRelayResponse);
        }
    }
    if page.next_cursor() != expected_cursor {
        return Err(ApplicationServiceError::InvalidRelayResponse);
    }
    Ok(())
}

fn sent_membership(accepted: AcceptedMembership) -> SentMembership {
    SentMembership {
        operation_id: accepted.operation_id,
        conversation_id: accepted.conversation_id,
        cursor: accepted.cursor,
        welcome: accepted.welcome,
    }
}

fn application_content_equal(left: &ApplicationContent, right: &ApplicationContent) -> bool {
    match (left, right) {
        (ApplicationContent::Text(left), ApplicationContent::Text(right)) => left == right,
    }
}

/// Stable application-service failures.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum ApplicationServiceError {
    #[error("conversation operation failed")]
    Conversation(#[from] ConversationCoordinatorError),
    #[error("relay operation failed")]
    Relay(#[from] KonclaveClientError),
    #[error("blocking application task failed")]
    Task,
    #[error("application request is invalid")]
    Protocol,
    #[error("application idempotency key conflicts with a prior request")]
    IdempotencyConflict,
    #[error("application message expired before relay acceptance")]
    OutboundExpired,
    #[error("application sender is no longer a conversation member")]
    OutboundRemoved,
    #[error("relay response does not match the requested operation")]
    InvalidRelayResponse,
    #[error("system time is unavailable")]
    SystemTimeUnavailable,
    #[error("watchable conversation capacity is exceeded")]
    WatchCapacityExceeded,
}

fn current_unix_seconds() -> Result<u64, ApplicationServiceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApplicationServiceError::SystemTimeUnavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use KonclaveClientLibrary::{
        RelayAccessCredential, RelayClient, RelayEndpoint, RelayWatchSession,
    };
    use KonclaveCommunityRelay::access::StaticRelayAccess;
    use KonclaveCommunityRelay::application::RelayApplication;
    use KonclaveCommunityRelay::http::{HttpState, router};
    use KonclaveDomainCore::{
        AcknowledgeRequest, ApplicationContent, DeliveryClass, EnvelopeId, ProtocolVersion,
        RelayEnvelope, ReplayPage, ReplayRequest,
    };
    use KonclaveRelayCore::RelayPrincipalId;
    use KonclaveSecretStorage::{
        ExternalWrappingKeyProvider, SealedSqliteMlsStorage, SecretSealer,
    };
    use async_trait::async_trait;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::conversation::tests::{invited_coordinators, paired_coordinators};
    use crate::persistence::{LockedProfile, MessageDirection, ProfileId};

    struct RecordingRelay {
        cursor: AtomicU64,
        fail_submit: AtomicBool,
        fail_acknowledgment: AtomicBool,
        lose_submit_response: AtomicBool,
        envelopes: Mutex<Vec<StoredRelayEnvelope>>,
        replay_pages: Mutex<VecDeque<ReplayPage>>,
        replay_requests: Mutex<Vec<ReplayRequest>>,
        acknowledgments: Mutex<Vec<AcknowledgeRequest>>,
        acknowledged_high_water: Mutex<Vec<(KonclaveDomainCore::RoutingId, u64)>>,
    }

    struct TestRelay {
        _directory: tempfile::TempDir,
        endpoint: String,
        shutdown: watch::Sender<bool>,
        server: JoinHandle<()>,
    }

    impl TestRelay {
        async fn start(token: [u8; RelayPrincipalId::LENGTH]) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let access_path = directory.path().join("access.json");
            let principal = RelayPrincipalId::from_access_token(&token);
            std::fs::write(
                &access_path,
                serde_json::to_vec(&json!({
                    "version": 1,
                    "principals": [{
                        "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                        "grants": [{
                            "route": "*",
                            "permissions": ["send", "replay", "acknowledge"]
                        }]
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
            let access = StaticRelayAccess::load(&access_path).unwrap();
            let application =
                RelayApplication::connect(&directory.path().join("relay.sqlite"), access.clone())
                    .await
                    .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (shutdown, mut shutdown_rx) = watch::channel(false);
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router(
                        HttpState::new("watch-supervisor-test", application),
                        access,
                        shutdown_rx.clone(),
                    ),
                )
                .with_graceful_shutdown(async move {
                    while !*shutdown_rx.borrow() {
                        if shutdown_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
                .unwrap();
            });
            Self {
                _directory: directory,
                endpoint: format!("http://{address}"),
                shutdown,
                server,
            }
        }

        async fn stop(self) {
            self.shutdown.send(true).unwrap();
            timeout(Duration::from_secs(2), self.server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    struct ObservingRelay {
        inner: RelayClient,
        acknowledged: Mutex<Option<oneshot::Sender<()>>>,
    }

    #[async_trait]
    impl RelayTransport for ObservingRelay {
        async fn submit(
            &self,
            envelope: &KonclaveDomainCore::RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            self.inner.submit(envelope).await
        }

        async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
            self.inner.replay(request).await
        }

        async fn acknowledge(
            &self,
            request: AcknowledgeRequest,
        ) -> Result<AcknowledgeRequest, KonclaveClientError> {
            let acknowledged = self.inner.acknowledge(request).await?;
            if let Some(sender) = self.acknowledged.lock().unwrap().take() {
                let _ = sender.send(());
            }
            Ok(acknowledged)
        }

        async fn connect_watch(
            &self,
            request: ReplayRequest,
        ) -> Result<RelayWatchSession, KonclaveClientError> {
            self.inner.connect_watch(request).await
        }
    }

    impl RecordingRelay {
        fn new(fail_submit: bool) -> Self {
            Self {
                cursor: AtomicU64::new(0),
                fail_submit: AtomicBool::new(fail_submit),
                fail_acknowledgment: AtomicBool::new(false),
                lose_submit_response: AtomicBool::new(false),
                envelopes: Mutex::new(Vec::new()),
                replay_pages: Mutex::new(VecDeque::new()),
                replay_requests: Mutex::new(Vec::new()),
                acknowledgments: Mutex::new(Vec::new()),
                acknowledged_high_water: Mutex::new(Vec::new()),
            }
        }

        fn push_replay_page(&self, page: ReplayPage) {
            self.replay_pages.lock().unwrap().push_back(page);
        }

        fn lose_next_submit_response(&self) {
            self.lose_submit_response.store(true, Ordering::SeqCst);
        }

        fn fail_next_acknowledgment(&self) {
            self.fail_acknowledgment.store(true, Ordering::SeqCst);
        }

        /// Raises the route's retention high-water mark the way a concurrent
        /// principal-authorized reader would.
        fn advance_acknowledgment(&self, routing_id: KonclaveDomainCore::RoutingId, cursor: u64) {
            Self::raise(
                &mut self.acknowledged_high_water.lock().unwrap(),
                routing_id,
                cursor,
            );
        }

        fn raise(
            high_water: &mut Vec<(KonclaveDomainCore::RoutingId, u64)>,
            routing_id: KonclaveDomainCore::RoutingId,
            cursor: u64,
        ) -> u64 {
            match high_water
                .iter_mut()
                .find(|(route, _)| *route == routing_id)
            {
                Some((_, effective)) => {
                    *effective = (*effective).max(cursor);
                    *effective
                }
                None => {
                    high_water.push((routing_id, cursor));
                    cursor
                }
            }
        }
    }

    #[async_trait]
    impl RelayTransport for RecordingRelay {
        async fn submit(
            &self,
            envelope: &KonclaveDomainCore::RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            if self.fail_submit.load(Ordering::SeqCst) {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            let cursor = self.cursor.fetch_add(1, Ordering::SeqCst) + 1;
            let stored = StoredRelayEnvelope::new(envelope.clone(), cursor)
                .map_err(|_| KonclaveClientError::InvalidResponse)?;
            self.envelopes.lock().unwrap().push(stored.clone());
            if self.lose_submit_response.swap(false, Ordering::SeqCst) {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            Ok(stored)
        }

        async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
            self.replay_requests.lock().unwrap().push(request);
            Ok(self
                .replay_pages
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    ReplayPage::new(Vec::new(), request.after_cursor(), false).unwrap()
                }))
        }

        async fn acknowledge(
            &self,
            request: AcknowledgeRequest,
        ) -> Result<AcknowledgeRequest, KonclaveClientError> {
            if self.fail_acknowledgment.swap(false, Ordering::SeqCst) {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            self.acknowledgments.lock().unwrap().push(request);
            let effective = Self::raise(
                &mut self.acknowledged_high_water.lock().unwrap(),
                request.routing_id(),
                request.cursor(),
            );
            AcknowledgeRequest::new(request.routing_id(), effective)
                .map_err(|_| KonclaveClientError::InvalidResponse)
        }

        async fn connect_watch(
            &self,
            _request: ReplayRequest,
        ) -> Result<RelayWatchSession, KonclaveClientError> {
            Err(KonclaveClientError::TransportUnavailable)
        }
    }

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
    }

    fn coordinator(root: &Path, profile_name: &str) -> ConversationCoordinator {
        let locked = LockedProfile::acquire(root, ProfileId::parse(profile_name).unwrap()).unwrap();
        let mls_path = locked.mls_database_path();
        let profile_sealer = sealer();
        let mls_storage = SealedSqliteMlsStorage::open(&mls_path, profile_sealer.share()).unwrap();
        let store = locked.open_store(profile_sealer).unwrap();
        let device = store.load_or_create_device().unwrap();
        ConversationCoordinator::new(store, mls_storage, device)
    }

    fn request(conversation_id: ConversationId, text: &str) -> SendApplicationRequest {
        request_at(conversation_id, text, 1_700_000_000, 1_900_000_000)
    }

    fn request_at(
        conversation_id: ConversationId,
        text: &str,
        now_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> SendApplicationRequest {
        let mut message_id = [0_u8; MessageId::LENGTH];
        for (index, byte) in text.bytes().enumerate() {
            message_id[index % MessageId::LENGTH] ^=
                byte.wrapping_add(u8::try_from(index).unwrap_or(u8::MAX));
        }
        SendApplicationRequest {
            conversation_id,
            message_id: MessageId::from_bytes(message_id),
            content: ApplicationContent::text(text).unwrap(),
            reply_to: None,
            sent_at_unix_milliseconds: now_unix_seconds.checked_mul(1_000).unwrap(),
            now_unix_seconds,
            expires_at_unix_seconds,
        }
    }

    #[tokio::test]
    async fn sends_in_sender_counter_order_without_exposing_plaintext() {
        const FIRST_SENTINEL: &str = "first-plaintext-sentinel-936a70";
        const SECOND_SENTINEL: &str = "second-plaintext-sentinel-4e5d18";
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "send-order");
        let conversation = coordinator.create().unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(false));

        let (first, second) = tokio::join!(
            service.send(request(conversation.conversation_id, FIRST_SENTINEL)),
            service.send(request(conversation.conversation_id, SECOND_SENTINEL))
        );
        let mut sent = [first.unwrap(), second.unwrap()];
        sent.sort_by_key(|sent| sent.message.sender_counter());

        assert_eq!(sent[0].conversation_id, conversation.conversation_id);
        assert_eq!(sent[1].conversation_id, conversation.conversation_id);
        assert_eq!(sent[0].message.sender_counter(), 1);
        assert_eq!(sent[1].message.sender_counter(), 2);
        assert_eq!(sent[0].cursor, 1);
        assert_eq!(sent[1].cursor, 2);
        assert!(coordinator.ready_outbox().unwrap().is_empty());
        {
            let envelopes = service.transport.envelopes.lock().unwrap();
            for envelope in envelopes.iter() {
                for sentinel in [FIRST_SENTINEL.as_bytes(), SECOND_SENTINEL.as_bytes()] {
                    assert!(
                        !envelope
                            .envelope()
                            .payload()
                            .windows(sentinel.len())
                            .any(|window| window == sentinel)
                    );
                }
            }
        }
        let history = service
            .read(conversation.conversation_id, 0, 10)
            .await
            .unwrap();
        assert!(history.messages.is_empty());

        let echoed = service.transport.envelopes.lock().unwrap().clone();
        service
            .transport
            .push_replay_page(ReplayPage::new(echoed, 2, false).unwrap());
        let replayed = service
            .replay_once(conversation.conversation_id, 100, 1_800_000_000)
            .await
            .unwrap();
        assert_eq!(replayed.messages.len(), 2);
        assert!(replayed.messages.iter().all(|message| message.duplicate));
        let history = service
            .read(conversation.conversation_id, 0, 10)
            .await
            .unwrap();
        assert_eq!(history.messages.len(), 2);
        assert!(!history.has_more);
        assert_eq!(history.messages[0].direction, MessageDirection::Outbound);
        assert_eq!(history.messages[1].direction, MessageDirection::Outbound);
        assert_eq!(history.messages[0].message.sender_counter(), 1);
        assert_eq!(history.messages[1].message.sender_counter(), 2);
        let first_page = service
            .read(conversation.conversation_id, 0, 1)
            .await
            .unwrap();
        assert_eq!(first_page.messages.len(), 1);
        assert!(first_page.has_more);
        let second_page = service
            .read(
                conversation.conversation_id,
                first_page.messages[0].cursor,
                1,
            )
            .await
            .unwrap();
        assert_eq!(second_page.messages.len(), 1);
        assert!(!second_page.has_more);
    }

    #[tokio::test]
    async fn relay_failure_leaves_a_ready_envelope_for_retry() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "send-retry");
        let conversation = coordinator.create().unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(true));

        assert!(matches!(
            service
                .send(request(conversation.conversation_id, "retry-secret"))
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(coordinator.ready_outbox().unwrap().len(), 1);
        assert!(
            service
                .read(conversation.conversation_id, 0, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );

        service.transport.fail_submit.store(false, Ordering::SeqCst);
        let sent = service
            .send(request(conversation.conversation_id, "after-retry-secret"))
            .await
            .unwrap();
        assert_eq!(sent.message.sender_counter(), 2);
        assert_eq!(sent.cursor, 2);
        assert!(coordinator.ready_outbox().unwrap().is_empty());
        assert_eq!(service.retry_ready(1_800_000_000).await.unwrap(), 0);
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 2);
        let history = service
            .read(conversation.conversation_id, 0, 10)
            .await
            .unwrap();
        assert!(history.messages.is_empty());
    }

    #[tokio::test]
    async fn identical_send_retry_resumes_one_durable_message() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "send-idempotency");
        let conversation = coordinator.create().unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(true));

        assert!(
            service
                .send(request(
                    conversation.conversation_id,
                    "idempotent-retry-secret"
                ))
                .await
                .is_err()
        );
        service.transport.fail_submit.store(false, Ordering::SeqCst);

        let accepted = service
            .send(request(
                conversation.conversation_id,
                "idempotent-retry-secret",
            ))
            .await
            .unwrap();
        let repeated = service
            .send(request_at(
                conversation.conversation_id,
                "idempotent-retry-secret",
                2_000_000_000,
                2_100_000_000,
            ))
            .await
            .unwrap();

        assert_eq!(accepted.message.message_id(), repeated.message.message_id());
        assert_eq!(accepted.cursor, repeated.cursor);
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 1);
        assert!(coordinator.ready_outbox().unwrap().is_empty());

        let mut conflicting = request(conversation.conversation_id, "idempotent-retry-secret");
        conflicting.content = ApplicationContent::text("conflicting-content").unwrap();
        assert!(matches!(
            service.send(conflicting).await,
            Err(ApplicationServiceError::IdempotencyConflict)
        ));
    }

    #[tokio::test]
    async fn own_echo_reconciles_lost_submit_response_for_stable_retry() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "send-own-echo-reconcile");
        let conversation = coordinator.create().unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(false));
        service.transport.lose_next_submit_response();

        assert!(matches!(
            service
                .send(request(
                    conversation.conversation_id,
                    "lost-response-own-echo"
                ))
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(coordinator.ready_outbox().unwrap().len(), 1);
        let stored = service.transport.envelopes.lock().unwrap()[0].clone();
        service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], 1, false).unwrap());

        let replayed = service
            .replay_once(conversation.conversation_id, 100, 1_800_000_000)
            .await
            .unwrap();
        assert_eq!(replayed.messages.len(), 1);
        assert!(replayed.messages[0].duplicate);
        assert_eq!(coordinator.ready_outbox().unwrap().len(), 0);

        let repeated = service
            .send(request(
                conversation.conversation_id,
                "lost-response-own-echo",
            ))
            .await
            .unwrap();
        assert_eq!(repeated.cursor, 1);
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn late_own_echo_supersedes_local_expiry_terminal() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "send-late-own-echo");
        let conversation = coordinator.create().unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(false));
        service.transport.lose_next_submit_response();
        let request = |now_unix_seconds, expires_at_unix_seconds| {
            request_at(
                conversation.conversation_id,
                "late-own-echo-after-expiry",
                now_unix_seconds,
                expires_at_unix_seconds,
            )
        };

        assert!(matches!(
            service.send(request(100, 101)).await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        let stored = service.transport.envelopes.lock().unwrap()[0].clone();
        assert_eq!(service.retry_ready(102).await.unwrap(), 0);
        assert!(coordinator.ready_outbox().unwrap().is_empty());
        assert!(matches!(
            service.send(request(102, 200)).await,
            Err(ApplicationServiceError::OutboundExpired)
        ));

        service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], 1, false).unwrap());
        service
            .replay_once(conversation.conversation_id, 100, 102)
            .await
            .unwrap();

        let accepted = service.send(request(103, 200)).await.unwrap();
        assert_eq!(accepted.cursor, 1);
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn expired_ready_message_does_not_block_another_conversation() {
        let root = tempfile::tempdir().unwrap();
        let initial = coordinator(root.path(), "send-expired-terminal");
        let expired_conversation = initial.create().unwrap();
        let active_conversation = initial.create().unwrap();
        let service = ApplicationService::new(initial.clone(), RecordingRelay::new(true));
        let expired_request = || {
            request_at(
                expired_conversation.conversation_id,
                "expired-never-accepted",
                100,
                101,
            )
        };

        assert!(matches!(
            service.send(expired_request()).await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        service.transport.fail_submit.store(false, Ordering::SeqCst);

        let sent = service
            .send(request_at(
                active_conversation.conversation_id,
                "unrelated-active-message",
                102,
                200,
            ))
            .await
            .unwrap();
        assert_eq!(sent.cursor, 1);
        assert!(initial.ready_outbox().unwrap().is_empty());
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 1);

        drop(service);
        drop(initial);
        let reopened = coordinator(root.path(), "send-expired-terminal");
        let reopened_service =
            ApplicationService::new(reopened.clone(), RecordingRelay::new(false));
        assert!(matches!(
            reopened_service.send(expired_request()).await,
            Err(ApplicationServiceError::OutboundExpired)
        ));
        assert!(reopened.ready_outbox().unwrap().is_empty());
        assert!(
            reopened_service
                .transport
                .envelopes
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn add_member_retry_returns_original_welcome_after_lost_response() {
        let (_root, alice, bob, created, proof) = invited_coordinators();
        let proof_bytes = encode_join_proof(&proof).unwrap();
        let retry_proof = decode_join_proof(&proof_bytes).unwrap();
        let repeated_proof = decode_join_proof(&proof_bytes).unwrap();
        let service = ApplicationService::new(alice.clone(), RecordingRelay::new(true));

        assert!(matches!(
            service
                .add_member(created.conversation_id, proof, 50, 1_900_000_000,)
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(alice.ready_membership_outbox().unwrap().len(), 1);
        service.transport.fail_submit.store(false, Ordering::SeqCst);

        let accepted = service
            .add_member(created.conversation_id, retry_proof, 50, 1_900_000_000)
            .await
            .unwrap();
        let later = service
            .change_role(
                created.conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                60,
                1_900_000_000,
            )
            .await
            .unwrap();
        let repeated = service
            .add_member(created.conversation_id, repeated_proof, 50, 1_900_000_000)
            .await
            .unwrap();

        assert_eq!(later.cursor, 2);
        assert_eq!(accepted.operation_id, repeated.operation_id);
        assert_eq!(accepted.cursor, repeated.cursor);
        assert_eq!(accepted.welcome, repeated.welcome);
        assert!(accepted.welcome.is_some());
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn welcome_acceptance_verifies_relay_receipt_and_sets_replay_baseline() {
        let (_root, alice, bob, created, proof) = invited_coordinators();
        let alice_service = ApplicationService::new(alice, RecordingRelay::new(false));
        let added = alice_service
            .add_member(created.conversation_id, proof, 50, 1_900_000_000)
            .await
            .unwrap();
        let stored = alice_service.transport.envelopes.lock().unwrap()[0].clone();
        let bob_service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        bob_service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], added.cursor, false).unwrap());

        let joined = bob_service
            .accept_welcome(
                created.conversation_id,
                MlsWelcome::from_bytes(&added.welcome.unwrap()).unwrap(),
                added.cursor,
            )
            .await
            .unwrap();

        assert_eq!(joined.epoch, 1);
        assert_eq!(
            bob.replay_position(created.conversation_id).unwrap().1,
            added.cursor
        );
    }

    #[tokio::test]
    async fn welcome_rejects_same_parent_commit_with_a_different_envelope_id() {
        let (_root, alice, bob, created, proof) = invited_coordinators();
        let alice_service = ApplicationService::new(alice, RecordingRelay::new(false));
        let added = alice_service
            .add_member(created.conversation_id, proof, 50, 1_900_000_000)
            .await
            .unwrap();
        let original = alice_service.transport.envelopes.lock().unwrap()[0].clone();
        let wrong = StoredRelayEnvelope::new(
            RelayEnvelope::new(
                ProtocolVersion::application_v1(),
                original.envelope().routing_id(),
                EnvelopeId::from_bytes([99; EnvelopeId::LENGTH]),
                DeliveryClass::GroupCommit,
                original.envelope().expected_parent_epoch(),
                original.envelope().expires_at_unix_seconds(),
                original.envelope().payload().to_vec(),
            )
            .unwrap(),
            original.cursor(),
        )
        .unwrap();
        let welcome = added.welcome.unwrap();
        let bob_service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        bob_service
            .transport
            .push_replay_page(ReplayPage::new(vec![wrong], added.cursor, false).unwrap());

        assert!(matches!(
            bob_service
                .accept_welcome(
                    created.conversation_id,
                    MlsWelcome::from_bytes(&welcome).unwrap(),
                    added.cursor,
                )
                .await,
            Err(ApplicationServiceError::Conversation(
                ConversationCoordinatorError::StateMismatch
            ))
        ));

        bob_service
            .transport
            .push_replay_page(ReplayPage::new(vec![original], added.cursor, false).unwrap());
        let joined = bob_service
            .accept_welcome(
                created.conversation_id,
                MlsWelcome::from_bytes(&welcome).unwrap(),
                added.cursor,
            )
            .await
            .unwrap();
        assert_eq!(joined.epoch, 1);
    }

    #[tokio::test]
    async fn remove_member_retry_returns_original_operation() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let bob_device_id = bob.device_id().unwrap();
        let service = ApplicationService::new(alice, RecordingRelay::new(true));
        assert!(
            service
                .remove_member(conversation_id, bob_device_id, 1_800_000_000, 1_900_000_000,)
                .await
                .is_err()
        );
        service.transport.fail_submit.store(false, Ordering::SeqCst);

        let accepted = service
            .remove_member(conversation_id, bob_device_id, 1_800_000_000, 1_900_000_000)
            .await
            .unwrap();
        let repeated = service
            .remove_member(conversation_id, bob_device_id, 1_800_000_000, 1_900_000_000)
            .await
            .unwrap();

        assert_eq!(accepted.operation_id, repeated.operation_id);
        assert_eq!(accepted.cursor, repeated.cursor);
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn replay_completes_before_acknowledging_and_resumes_from_durable_cursor() {
        let (_root, alice, bob, conversation_id, alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("replayed message").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap();
        let service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], 1, false).unwrap());

        let first = service
            .replay_once(conversation_id, 100, 1_800_000_000)
            .await
            .unwrap();

        assert!(!first.has_more);
        assert_eq!(first.messages.len(), 1);
        assert_eq!(first.messages[0].sender, alice_device_id);
        assert!(!first.messages[0].duplicate);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
        assert_eq!(
            service.transport.acknowledgments.lock().unwrap().as_slice(),
            &[AcknowledgeRequest::new(prepared.envelope.routing_id(), 1,).unwrap()]
        );
        let history = service.read(conversation_id, 0, 10).await.unwrap();
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].direction, MessageDirection::Inbound);
        assert_eq!(history.messages[0].sender, alice_device_id);
        assert!(matches!(
            history.messages[0].message.content(),
            ApplicationContent::Text(body) if body == "replayed message"
        ));

        service
            .transport
            .push_replay_page(ReplayPage::new(Vec::new(), 1, false).unwrap());
        let resumed = service
            .replay_once(conversation_id, 100, 1_800_000_000)
            .await
            .unwrap();
        assert!(resumed.messages.is_empty());
        {
            let requests = service.transport.replay_requests.lock().unwrap();
            assert_eq!(requests[0].after_cursor(), 0);
            assert_eq!(requests[1].after_cursor(), 1);
        }

        service.transport.push_replay_page(
            ReplayPage::new(
                vec![StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap()],
                1,
                false,
            )
            .unwrap(),
        );
        assert!(matches!(
            service
                .replay_once(conversation_id, 100, 1_800_000_000)
                .await,
            Err(ApplicationServiceError::InvalidRelayResponse)
        ));
        assert!(matches!(
            service.watch_once(conversation_id, 1_800_000_000).await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
    }

    #[tokio::test]
    async fn continuous_watch_survives_empty_initial_page_and_processes_later_message() {
        let token = [7_u8; RelayAccessCredential::LENGTH];
        let relay = TestRelay::start(token).await;
        let (_root, alice, bob, conversation_id, alice_device_id) = paired_coordinators();
        let alice_transport = RelayClient::new(
            RelayEndpoint::parse(&relay.endpoint).unwrap(),
            RelayAccessCredential::from_bytes(token),
        )
        .unwrap();
        let bob_transport = RelayClient::new(
            RelayEndpoint::parse(&relay.endpoint).unwrap(),
            RelayAccessCredential::from_bytes(token),
        )
        .unwrap();
        let (empty_page_tx, empty_page_rx) = oneshot::channel();
        let (acknowledged_tx, acknowledged_rx) = oneshot::channel();
        let bob_service = ApplicationService::new(
            bob,
            ObservingRelay {
                inner: bob_transport,
                acknowledged: Mutex::new(Some(acknowledged_tx)),
            },
        );
        let alice_service = ApplicationService::new(alice, alice_transport);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let watch_service = bob_service.clone();
        let mut empty_page_tx = Some(empty_page_tx);
        let watcher = tokio::spawn(async move {
            watch_service
                .watch_connection_until_observed(conversation_id, shutdown_rx, move |page| {
                    if page.envelopes().is_empty()
                        && page.next_cursor() == 0
                        && let Some(sender) = empty_page_tx.take()
                    {
                        let _ = sender.send(());
                    }
                })
                .await
        });

        timeout(Duration::from_secs(2), empty_page_rx)
            .await
            .unwrap()
            .unwrap();
        alice_service
            .send(request(conversation_id, "arrived after empty watch page"))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), acknowledged_rx)
            .await
            .unwrap()
            .unwrap();

        let history = bob_service.read(conversation_id, 0, 10).await.unwrap();
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].sender, alice_device_id);
        assert!(matches!(
            history.messages[0].message.content(),
            ApplicationContent::Text(body) if body == "arrived after empty watch page"
        ));
        shutdown_tx.send(true).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), watcher)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            WatchConnectionExit::Shutdown
        );
        relay.stop().await;
    }

    #[tokio::test]
    async fn watch_reconnect_retries_acknowledgment_after_local_completion() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("ack retry").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap();
        let service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], 1, false).unwrap());
        service.transport.fail_next_acknowledgment();

        assert!(matches!(
            service
                .replay_once(conversation_id, 100, 1_800_000_000)
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        assert!(matches!(
            service
                .watch_connection_until(conversation_id, shutdown_rx)
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(
            service.transport.acknowledgments.lock().unwrap().as_slice(),
            &[AcknowledgeRequest::new(prepared.envelope.routing_id(), 1).unwrap()]
        );
    }

    #[tokio::test]
    async fn watch_accepts_a_retention_cursor_another_session_already_advanced() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("shared route").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let routing_id = prepared.envelope.routing_id();
        let stored = StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap();
        let service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], 1, false).unwrap());
        service
            .replay_once(conversation_id, 100, 1_800_000_000)
            .await
            .unwrap();
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
        service.transport.advance_acknowledgment(routing_id, 2);

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let exit = service
            .watch_connection_until(conversation_id, shutdown_rx)
            .await;

        assert!(
            matches!(
                exit,
                Err(ApplicationServiceError::Relay(
                    KonclaveClientError::TransportUnavailable
                ))
            ),
            "reconnect must reach the transport instead of failing acknowledgment: {exit:?}"
        );
        assert_eq!(
            service.transport.acknowledgments.lock().unwrap().as_slice(),
            &[
                AcknowledgeRequest::new(routing_id, 1).unwrap(),
                AcknowledgeRequest::new(routing_id, 1).unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn replay_rejects_a_gap_before_mutation_then_accepts_the_contiguous_page() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let first = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("contiguous-first").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let second = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("contiguous-second").unwrap(),
                None,
                1_700_000_001_000,
                1_900_000_000,
            )
            .unwrap();
        let first = StoredRelayEnvelope::new(first.envelope, 1).unwrap();
        let second = StoredRelayEnvelope::new(second.envelope, 2).unwrap();
        let service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        service
            .transport
            .push_replay_page(ReplayPage::new(vec![second.clone()], 2, false).unwrap());

        assert!(matches!(
            service.replay_once(conversation_id, 100, 60).await,
            Err(ApplicationServiceError::InvalidRelayResponse)
        ));
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 0);
        assert!(service.transport.acknowledgments.lock().unwrap().is_empty());

        service
            .transport
            .push_replay_page(ReplayPage::new(vec![first, second], 2, false).unwrap());
        let replayed = service.replay_once(conversation_id, 100, 60).await.unwrap();
        assert_eq!(replayed.messages.len(), 2);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 2);
        let routing_id = bob.replay_position(conversation_id).unwrap().0;

        let overflow = ReplayPage::new(
            vec![
                StoredRelayEnvelope::new(
                    RelayEnvelope::new(
                        ProtocolVersion::application_v1(),
                        routing_id,
                        EnvelopeId::from_bytes([98; EnvelopeId::LENGTH]),
                        DeliveryClass::GroupApplication,
                        None,
                        1,
                        vec![1],
                    )
                    .unwrap(),
                    u64::MAX,
                )
                .unwrap(),
            ],
            u64::MAX,
            false,
        )
        .unwrap();
        assert!(matches!(
            validate_replay_page(u64::MAX, &overflow),
            Err(ApplicationServiceError::InvalidRelayResponse)
        ));
    }

    #[tokio::test]
    async fn self_removal_terminalizes_ready_application_without_retry_submission() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let service = ApplicationService::new(bob.clone(), RecordingRelay::new(true));
        let retry = || request(conversation_id, "removed-ready-application");

        assert!(matches!(
            service.send(retry()).await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        let ready_envelope = bob.ready_outbox().unwrap()[0].envelope.clone();
        let removal = alice
            .prepare_remove_member(conversation_id, bob.device_id().unwrap(), 1_900_000_000)
            .unwrap();
        let removal = StoredRelayEnvelope::new(removal.envelope, 1).unwrap();
        alice.mark_membership_outbox_accepted(&removal).unwrap();
        let removed = bob
            .process_inbound_membership(conversation_id, &removal, 60)
            .unwrap();
        assert!(removed.removed_self);

        service.transport.fail_submit.store(false, Ordering::SeqCst);
        assert_eq!(service.retry_ready(60).await.unwrap(), 0);
        assert!(service.transport.envelopes.lock().unwrap().is_empty());
        assert!(matches!(
            service.send(retry()).await,
            Err(ApplicationServiceError::OutboundRemoved)
        ));
        assert!(service.transport.envelopes.lock().unwrap().is_empty());

        let late_echo = StoredRelayEnvelope::new(ready_envelope, 2).unwrap();
        let replayed = bob
            .process_inbound_application(conversation_id, &late_echo)
            .unwrap();
        assert_eq!(replayed.direction, MessageDirection::Outbound);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 2);
    }

    #[tokio::test]
    async fn membership_only_replay_page_applies_and_acknowledges_its_cursor() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap();
        alice.mark_membership_outbox_accepted(&stored).unwrap();
        let service = ApplicationService::new(bob.clone(), RecordingRelay::new(false));
        service
            .transport
            .push_replay_page(ReplayPage::new(vec![stored], 1, false).unwrap());

        let replay = service.replay_once(conversation_id, 100, 60).await.unwrap();

        assert!(replay.messages.is_empty());
        assert_eq!(bob.open(conversation_id).unwrap().group.epoch(), 2);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
        assert_eq!(
            service.transport.acknowledgments.lock().unwrap().as_slice(),
            &[AcknowledgeRequest::new(prepared.envelope.routing_id(), 1).unwrap()]
        );
    }
}
