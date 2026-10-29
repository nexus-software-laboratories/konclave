use std::sync::Arc;

use KonclaveClientLibrary::native::{
    NativeAcceptedMembership, NativeApplicationRequest, NativeExpiryOutcome,
    NativeOutboundApplication, NativeOutboundStatus, NativePendingApplication, NativeSessionHost,
    PreparedApplication, PreparedMembership, ProcessedApplication,
};
use KonclaveDomainCore::{
    ConversationId, MembershipOperationId, MessageId, RelayEnvelope, RoutingId, StoredRelayEnvelope,
};
use async_trait::async_trait;
use tokio::sync::OwnedMutexGuard;

use crate::activity::ProfileActivityGuard;
use crate::application::ApplicationServiceError;
use crate::conversation::{ConversationCoordinator, ConversationCoordinatorError};
use crate::native_workers::NativeWorkers;
use crate::persistence::{
    CollaborationActionAuthorization, ExpireOutboundResult, OutboundApplicationStatus,
};

/// One admitted native operation whose actual workers retain its ownership.
///
/// Admission is taken once by the caller, not again between recovery checkpoints.
/// A producer also supplies the exact shared submission guard. Cancellation of
/// the async requester cannot release either guard while a callback still runs.
pub(crate) struct DaemonNativeHost {
    conversations: ConversationCoordinator,
    workers: NativeWorkers,
    admission: Arc<ProfileActivityGuard>,
    submission: Option<Arc<OwnedMutexGuard<()>>>,
}

impl DaemonNativeHost {
    pub(crate) fn new(
        conversations: ConversationCoordinator,
        workers: NativeWorkers,
        admission: Arc<ProfileActivityGuard>,
        submission: Option<Arc<OwnedMutexGuard<()>>>,
    ) -> Self {
        Self {
            conversations,
            workers,
            admission,
            submission,
        }
    }

    /// Runs one coordinator callback without transferring ownership to its requester.
    pub(crate) async fn run<R, F>(&self, operation: F) -> Result<R, ApplicationServiceError>
    where
        R: Send + 'static,
        F: FnOnce(&ConversationCoordinator) -> Result<R, ConversationCoordinatorError>
            + Send
            + 'static,
    {
        let conversations = self.conversations.clone();
        let admission = Arc::clone(&self.admission);
        let submission = self.submission.clone();
        self.workers
            .run(move || {
                let result = operation(&conversations);
                drop((admission, submission));
                result
            })
            .await?
            .map_err(Into::into)
    }
}

#[async_trait]
impl NativeSessionHost for DaemonNativeHost {
    type Error = ApplicationServiceError;
    type Authorization = CollaborationActionAuthorization;

    async fn outbound_application(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<Option<NativeOutboundApplication>, Self::Error> {
        self.run(move |coordinator| {
            Ok(coordinator
                .outbound_application(conversation, message)?
                .map(|stored| NativeOutboundApplication {
                    conversation_id: stored.conversation_id,
                    message: stored.message,
                    envelope: stored.envelope,
                    status: match stored.status {
                        OutboundApplicationStatus::Ready => NativeOutboundStatus::Ready,
                        OutboundApplicationStatus::Accepted { cursor } => {
                            NativeOutboundStatus::Accepted { cursor }
                        }

                        OutboundApplicationStatus::Expired => NativeOutboundStatus::Expired,
                        OutboundApplicationStatus::Removed => NativeOutboundStatus::Removed,
                    },
                }))
        })
        .await
    }

    async fn prepare_application(
        &self,
        request: NativeApplicationRequest<Self::Authorization>,
    ) -> Result<PreparedApplication, Self::Error> {
        self.run(move |coordinator| {
            if request.policy_operation {
                coordinator.prepare_collaboration_policy_application_with_id(
                    request.conversation_id,
                    request.message_id,
                    request.content,
                    request.reply_to,
                    request.sent_at_unix_milliseconds,
                    request.expires_at_unix_seconds,
                )
            } else {
                coordinator.prepare_application_with_id(
                    request.conversation_id,
                    request.message_id,
                    request.content,
                    request.reply_to,
                    request.authorization,
                    request.sent_at_unix_milliseconds,
                    request.expires_at_unix_seconds,
                )
            }
        })
        .await
    }

    async fn ready_applications(&self) -> Result<Vec<NativePendingApplication>, Self::Error> {
        self.run(|coordinator| {
            Ok(coordinator
                .ready_outbox()?
                .into_iter()
                .map(|pending| NativePendingApplication {
                    conversation_id: pending.conversation_id,
                    envelope: pending.envelope,
                })
                .collect())
        })
        .await
    }

    async fn retry_eligible(&self, conversation: ConversationId) -> Result<bool, Self::Error> {
        self.run(move |coordinator| coordinator.outbound_retry_eligible(conversation))
            .await
    }

    async fn expire_application(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<NativeExpiryOutcome, Self::Error> {
        let envelope = envelope.clone();
        self.run(move |coordinator| {
            Ok(match coordinator.expire_outbound_application(&envelope)? {
                ExpireOutboundResult::Expired => NativeExpiryOutcome::Expired,
                ExpireOutboundResult::Accepted { cursor } => {
                    NativeExpiryOutcome::Accepted { cursor }
                }
            })
        })
        .await
    }

    async fn accept_application(&self, stored: StoredRelayEnvelope) -> Result<(), Self::Error> {
        self.run(move |coordinator| coordinator.mark_outbox_accepted(&stored))
            .await
    }

    async fn ready_memberships(&self) -> Result<Vec<PreparedMembership>, Self::Error> {
        self.run(ConversationCoordinator::ready_membership_outbox)
            .await
    }

    async fn accept_membership(
        &self,
        stored: StoredRelayEnvelope,
    ) -> Result<NativeAcceptedMembership, Self::Error> {
        self.run(move |coordinator| coordinator.mark_membership_outbox_accepted(&stored))
            .await
    }

    async fn orphan_membership(&self, operation: MembershipOperationId) -> Result<(), Self::Error> {
        self.run(move |coordinator| coordinator.orphan_membership(operation))
            .await
    }

    async fn replay_position(
        &self,
        conversation: ConversationId,
    ) -> Result<(RoutingId, u64), Self::Error> {
        self.run(move |coordinator| coordinator.replay_position(conversation))
            .await
    }

    async fn process_application(
        &self,
        conversation: ConversationId,
        stored: StoredRelayEnvelope,
        now: u64,
    ) -> Result<ProcessedApplication, Self::Error> {
        self.run(move |coordinator| {
            coordinator.process_inbound_application_at(conversation, &stored, now)
        })
        .await
    }

    async fn process_membership(
        &self,
        conversation: ConversationId,
        stored: StoredRelayEnvelope,
        now: u64,
    ) -> Result<(), Self::Error> {
        self.run(move |coordinator| {
            coordinator
                .process_inbound_membership(conversation, &stored, now)
                .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    use super::*;
    use crate::conversation::tests::paired_coordinators;
    use crate::native_workers::NativeWorkerError;

    #[tokio::test]
    async fn cancellation_keeps_real_profile_and_submission_ownership_until_callback_completion() {
        let (_root, coordinator, _peer, _conversation, _device) = paired_coordinators();
        let activity = coordinator.activity().clone();
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let workers = NativeWorkers::new();
        let host = Arc::new(DaemonNativeHost::new(
            coordinator,
            workers.clone(),
            Arc::new(activity.try_begin().unwrap()),
            Some(Arc::new(Arc::clone(&gate).lock_owned().await)),
        ));
        let (entered, running) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let requester = tokio::spawn(async move {
            host.run(move |_| {
                entered.send(()).unwrap();
                blocked.recv().unwrap();
                Ok(())
            })
            .await
        });
        running.await.unwrap();
        requester.abort();
        assert!(requester.await.unwrap_err().is_cancelled());
        activity.begin_closing();
        assert_eq!(activity.in_flight(), 1);
        assert!(gate.try_lock().is_err());
        let mut shutdown = Box::pin(workers.shutdown());
        poll_fn(|context| {
            assert!(matches!(shutdown.as_mut().poll(context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        assert_eq!(activity.in_flight(), 1);
        assert!(gate.try_lock().is_err());
        release.send(()).unwrap();
        shutdown.await.unwrap();
        assert_eq!(activity.in_flight(), 0);
        assert!(gate.try_lock().is_ok());
    }

    #[tokio::test]
    async fn cancelled_callback_failure_remains_observable_to_its_owner() {
        let (_root, coordinator, _peer, _conversation, _device) = paired_coordinators();
        let workers = NativeWorkers::new();
        let admission = Arc::new(coordinator.activity().try_begin().unwrap());
        let host = Arc::new(DaemonNativeHost::new(
            coordinator,
            workers.clone(),
            admission,
            None,
        ));
        let (entered, running) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let requester = tokio::spawn(async move {
            host.run(move |_| {
                entered.send(()).unwrap();
                blocked.recv().unwrap();
                Err::<(), _>(ConversationCoordinatorError::StateUnavailable)
            })
            .await
        });
        running.await.unwrap();
        requester.abort();
        assert!(requester.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        let NativeWorkerError::UnobservedOperation(cause) = workers.shutdown().await.unwrap_err()
        else {
            panic!("the cancelled callback failure was not retained");
        };
        assert!(cause.is::<ConversationCoordinatorError>());
    }
}
