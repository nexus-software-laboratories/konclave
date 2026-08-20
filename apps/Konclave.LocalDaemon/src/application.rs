use std::sync::Arc;

use KonclaveClientLibrary::{KonclaveClientError, RelayTransport};
use KonclaveDomainCore::{
    AcknowledgeRequest, ApplicationContent, ApplicationMessage, ConversationId, MessageId,
    ReplayPage, ReplayRequest, StoredRelayEnvelope,
};
use thiserror::Error;

use crate::conversation::{
    ConversationCoordinator, ConversationCoordinatorError, PreparedApplication,
    ProcessedApplication,
};
use crate::persistence::HistoryPage;

/// Outbound application input with caller-supplied display and expiry times.
pub(crate) struct SendApplicationRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) content: ApplicationContent,
    pub(crate) reply_to: Option<MessageId>,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

/// One accepted application message and its durable relay cursor.
pub(crate) struct SentApplication {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message: ApplicationMessage,
    pub(crate) cursor: u64,
}

/// One bounded replay result after durable local completion and acknowledgment.
pub(crate) struct ReplayBatch {
    pub(crate) messages: Vec<ProcessedApplication>,
    pub(crate) has_more: bool,
}

/// Async relay composition over synchronous sealed conversation state.
#[derive(Clone)]
pub(crate) struct ApplicationService<T> {
    conversations: ConversationCoordinator,
    transport: Arc<T>,
    submissions: Arc<tokio::sync::Mutex<()>>,
}

impl<T> ApplicationService<T>
where
    T: RelayTransport + 'static,
{
    /// Creates an application service sharing one authenticated relay transport.
    pub(crate) fn new(conversations: ConversationCoordinator, transport: T) -> Self {
        Self {
            conversations,
            transport: Arc::new(transport),
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
        self.retry_ready_locked().await?;
        let conversations = self.conversations.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            conversations.prepare_application(
                request.conversation_id,
                request.content,
                request.reply_to,
                request.sent_at_unix_milliseconds,
                request.expires_at_unix_seconds,
            )
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        self.submit_prepared(prepared).await
    }

    /// Retries every bounded ready envelope in deterministic journal order.
    ///
    /// Processing stops at the first relay or persistence failure. Unattempted and
    /// failed envelopes remain ready for a later retry.
    ///
    /// # Errors
    ///
    /// Returns a task, conversation, relay, or persistence error.
    pub(crate) async fn retry_ready(&self) -> Result<usize, ApplicationServiceError> {
        let _submission = self.submissions.lock().await;
        self.retry_ready_locked().await
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
    ) -> Result<ReplayBatch, ApplicationServiceError> {
        let (request, routing_id, after_cursor) =
            self.replay_request(conversation_id, limit).await?;
        let page = self.transport.replay(request).await?;
        self.process_page(conversation_id, routing_id, after_cursor, page)
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
    ) -> Result<ReplayBatch, ApplicationServiceError> {
        let (request, routing_id, after_cursor) = self.replay_request(conversation_id, 100).await?;
        let mut watch = self.transport.connect_watch(request).await?;
        let page = watch.next_page().await?;
        let processed = self
            .process_page(conversation_id, routing_id, after_cursor, page)
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

    async fn process_page(
        &self,
        conversation_id: ConversationId,
        routing_id: KonclaveDomainCore::RoutingId,
        after_cursor: u64,
        page: ReplayPage,
    ) -> Result<ReplayBatch, ApplicationServiceError> {
        if page.next_cursor() < after_cursor
            || page
                .envelopes()
                .iter()
                .any(|stored| stored.cursor() <= after_cursor)
        {
            return Err(ApplicationServiceError::InvalidRelayResponse);
        }
        let has_more = page.has_more();
        let envelopes = page.envelopes().to_vec();
        let mut messages = Vec::with_capacity(envelopes.len());
        for stored in envelopes {
            let conversations = self.conversations.clone();
            messages.push(
                tokio::task::spawn_blocking(move || {
                    conversations.process_inbound_application(conversation_id, &stored)
                })
                .await
                .map_err(|_| ApplicationServiceError::Task)??,
            );
        }
        if let Some(last) = messages.last() {
            let acknowledgment = AcknowledgeRequest::new(routing_id, last.cursor)
                .map_err(|_| ApplicationServiceError::Protocol)?;
            let effective = self.transport.acknowledge(acknowledgment).await?;
            if effective != acknowledgment {
                return Err(ApplicationServiceError::InvalidRelayResponse);
            }
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

    async fn retry_ready_locked(&self) -> Result<usize, ApplicationServiceError> {
        let conversations = self.conversations.clone();
        let pending = tokio::task::spawn_blocking(move || conversations.ready_outbox())
            .await
            .map_err(|_| ApplicationServiceError::Task)??;
        let mut accepted = 0;
        for pending in pending {
            let stored = self.transport.submit(&pending.envelope).await?;
            self.mark_accepted(stored).await?;
            accepted += 1;
        }
        Ok(accepted)
    }

    async fn submit_prepared(
        &self,
        prepared: PreparedApplication,
    ) -> Result<SentApplication, ApplicationServiceError> {
        let stored = self.transport.submit(&prepared.envelope).await?;
        let cursor = stored.cursor();
        self.mark_accepted(stored).await?;
        Ok(SentApplication {
            conversation_id: prepared.conversation_id,
            message: prepared.message,
            cursor,
        })
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
    #[error("relay response does not match the requested operation")]
    InvalidRelayResponse,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use KonclaveClientLibrary::RelayWatchSession;
    use KonclaveDomainCore::{AcknowledgeRequest, ApplicationContent, ReplayPage, ReplayRequest};
    use KonclaveSecretStorage::{
        ExternalWrappingKeyProvider, SealedSqliteMlsStorage, SecretSealer,
    };
    use async_trait::async_trait;

    use super::*;
    use crate::conversation::tests::paired_coordinators;
    use crate::persistence::{LockedProfile, MessageDirection, ProfileId};

    struct RecordingRelay {
        cursor: AtomicU64,
        fail_submit: AtomicBool,
        envelopes: Mutex<Vec<StoredRelayEnvelope>>,
        replay_pages: Mutex<VecDeque<ReplayPage>>,
        replay_requests: Mutex<Vec<ReplayRequest>>,
        acknowledgments: Mutex<Vec<AcknowledgeRequest>>,
    }

    impl RecordingRelay {
        fn new(fail_submit: bool) -> Self {
            Self {
                cursor: AtomicU64::new(0),
                fail_submit: AtomicBool::new(fail_submit),
                envelopes: Mutex::new(Vec::new()),
                replay_pages: Mutex::new(VecDeque::new()),
                replay_requests: Mutex::new(Vec::new()),
                acknowledgments: Mutex::new(Vec::new()),
            }
        }

        fn push_replay_page(&self, page: ReplayPage) {
            self.replay_pages.lock().unwrap().push_back(page);
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
            self.acknowledgments.lock().unwrap().push(request);
            Ok(request)
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
        SendApplicationRequest {
            conversation_id,
            content: ApplicationContent::text(text).unwrap(),
            reply_to: None,
            sent_at_unix_milliseconds: 1_700_000_000_000,
            expires_at_unix_seconds: 1_900_000_000,
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

        let echoed = service.transport.envelopes.lock().unwrap().clone();
        service
            .transport
            .push_replay_page(ReplayPage::new(echoed, 2, false).unwrap());
        let replayed = service
            .replay_once(conversation.conversation_id, 100)
            .await
            .unwrap();
        assert_eq!(replayed.messages.len(), 2);
        assert!(replayed.messages.iter().all(|message| message.duplicate));
        assert_eq!(
            service
                .read(conversation.conversation_id, 0, 10)
                .await
                .unwrap()
                .messages
                .len(),
            2
        );
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
        assert_eq!(service.retry_ready().await.unwrap(), 0);
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 2);
        let history = service
            .read(conversation.conversation_id, 0, 10)
            .await
            .unwrap();
        assert_eq!(history.messages.len(), 2);
        assert_eq!(history.messages[0].message.sender_counter(), 1);
        assert_eq!(history.messages[1].message.sender_counter(), 2);
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

        let first = service.replay_once(conversation_id, 100).await.unwrap();

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
        let resumed = service.replay_once(conversation_id, 100).await.unwrap();
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
            service.replay_once(conversation_id, 100).await,
            Err(ApplicationServiceError::InvalidRelayResponse)
        ));
        assert!(matches!(
            service.watch_once(conversation_id).await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
    }
}
