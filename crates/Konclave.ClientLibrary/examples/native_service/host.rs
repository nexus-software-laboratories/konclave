//! Fixed-membership native endpoint over explicitly injected, sealed persistence.
//!
//! Every callback completes synchronously inside `block_in_place` on a checked
//! multi-thread Tokio runtime. No tasks or blocking workers are started. Dropping
//! a caller cannot detach a callback or release its submission guard mid-callback.
//! The operation mutex serializes callbacks, not network-awaiting session futures:
//! the caller must stop admission and own/drain those entire futures before
//! releasing storage ownership. All producers must share one session submission
//! gate and this host; neither mutex replaces the storage owner's fencing.

use std::sync::Mutex;

use KonclaveClientLibrary::native::*;
use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveDomainCore::{
    ConversationId, MembershipOperationId, MessageId, RelayEnvelope, RoutingId, StoredRelayEnvelope,
};
use KonclaveSecretStorage::SealedMlsStorageHandle;
use async_trait::async_trait;
use tokio::runtime::{Handle, RuntimeFlavor};

use super::authority::ServiceAuthorization;
use super::journal::{JournalError, ReservedIntent, ServiceJournal, copy_content};

/// Finite diagnostics contain no payloads, paths, provider state or custody details.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceHostError {
    /// Callbacks require an entered multi-thread Tokio runtime.
    #[error("native service requires a multi-thread runtime")]
    UnsupportedRuntime,
    /// A poisoned operation or identity owner cannot be reused.
    #[error("native service operation owner is unavailable")]
    Unavailable,
    /// The caller selected another conversation.
    #[error("native service conversation scope mismatch")]
    Scope,
    /// Immutable retained evidence is absent or inconsistent.
    #[error("native service evidence is invalid")]
    Evidence,
    /// An incomplete original was explicitly abandoned or expired.
    #[error("native service outbound operation is terminal")]
    Terminal,
    /// Earlier committed work must be submitted before this operation.
    #[error("native service outbound ordering requires reconciliation")]
    Ordering,
    /// This example cannot change its provisioned membership.
    #[error("native service membership operation is unsupported")]
    Unsupported,
    /// The authenticated bounded journal rejected the operation.
    #[error("native service journal operation failed")]
    Journal(#[from] JournalError),
    /// Shared native processing rejected the operation.
    #[error("native service conversation processing failed")]
    Native(#[from] NativeConversationError<JournalError>),
}

/// One owned identity and preprovisioned conversation, with no background workers.
///
/// The injected journal and sealed MLS handle must use the same exclusive storage
/// owner. Retain one host for all session clones and drain complete session futures
/// before releasing that owner. Membership is immutable in this example.
pub struct ServiceNativeHost {
    journal: ServiceJournal,
    mls: SealedMlsStorageHandle,
    identity: Mutex<DeviceIdentity>,
    conversation: ConversationId,
    operations: Mutex<()>,
}

impl ServiceNativeHost {
    /// Opens the journal's own identity and authenticates genuine persisted MLS.
    ///
    /// This does not provision membership, create a group, discover custody or
    /// start workers. Call from an entered multi-thread Tokio runtime.
    ///
    /// # Errors
    /// Rejects unsupported runtimes, missing MLS, foreign scope, poisoned ownership,
    /// unavailable custody, invalid journals and inconsistent native checkpoints.
    pub fn open(
        journal: ServiceJournal,
        mls: SealedMlsStorageHandle,
        conversation: ConversationId,
    ) -> Result<Self, ServiceHostError> {
        require_runtime()?;
        tokio::task::block_in_place(|| {
            let identity = Mutex::new(journal.identity()?);
            let host = Self {
                journal,
                mls,
                identity,
                conversation,
                operations: Mutex::new(()),
            };
            host.locked(|_, _| Ok(()))?;
            Ok(host)
        })
    }

    fn scope(&self, conversation: ConversationId) -> Result<(), ServiceHostError> {
        if conversation != self.conversation {
            return Err(ServiceHostError::Scope);
        }
        Ok(())
    }

    fn run<T>(
        &self,
        operation: impl FnOnce(
            &mut NativeConversationProcessor<'_, ServiceJournal>,
            OpenConversation,
        ) -> Result<T, ServiceHostError>,
    ) -> Result<T, ServiceHostError> {
        require_runtime()?;
        tokio::task::block_in_place(|| self.locked(operation))
    }

    fn locked<T>(
        &self,
        operation: impl FnOnce(
            &mut NativeConversationProcessor<'_, ServiceJournal>,
            OpenConversation,
        ) -> Result<T, ServiceHostError>,
    ) -> Result<T, ServiceHostError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ServiceHostError::Unavailable)?;
        if !self
            .mls
            .contains_group(self.conversation.as_bytes())
            .map_err(|_| NativeConversationError::<JournalError>::SecretStorage)?
        {
            return Err(NativeConversationError::MissingMlsState.into());
        }
        let mut processor =
            NativeConversationProcessor::new(&self.journal, self.mls.clone(), &self.identity);
        let opened = processor.open(self.conversation)?;
        operation(&mut processor, opened)
    }

    fn recover(
        &self,
        processor: &mut NativeConversationProcessor<'_, ServiceJournal>,
        through: Option<u64>,
    ) -> Result<(), ServiceHostError> {
        let mut originals = self.journal.unready_outbox()?;
        originals.sort_by_key(|original| original.reservation.sender_counter);
        for original in originals {
            if through.is_some_and(|counter| original.reservation.sender_counter > counter)
                || original.abandoned
                || original.expired
            {
                continue;
            }
            self.scope(original.reservation.conversation_id)?;
            if original.envelope.is_some() || original.accepted_cursor.is_some() {
                return Err(ServiceHostError::Evidence);
            }
            processor.prepare_reserved_application(
                original.reservation,
                copy_content(original.message.content())?,
                original.message.reply_to(),
                original.message.sent_at_unix_milliseconds(),
                original.expires_at_unix_seconds,
            )?;
        }
        Ok(())
    }

    fn no_earlier_ready(&self, counter: u64) -> Result<(), ServiceHostError> {
        if self.journal.retained_outbox()?.iter().any(|original| {
            original.reservation.sender_counter < counter
                && original.accepted_cursor.is_none()
                && !original.abandoned
                && !original.expired
        }) {
            return Err(ServiceHostError::Ordering);
        }
        Ok(())
    }
}

fn require_runtime() -> Result<(), ServiceHostError> {
    let runtime = Handle::try_current().map_err(|_| ServiceHostError::UnsupportedRuntime)?;
    if runtime.runtime_flavor() != RuntimeFlavor::MultiThread {
        return Err(ServiceHostError::UnsupportedRuntime);
    }
    Ok(())
}

fn outbound(original: ReservedIntent) -> Result<NativeOutboundApplication, ServiceHostError> {
    if original.abandoned {
        return Err(ServiceHostError::Terminal);
    }
    let envelope = original.envelope.ok_or(if original.expired {
        ServiceHostError::Terminal
    } else {
        ServiceHostError::Evidence
    })?;
    let status = if let Some(cursor) = original.accepted_cursor {
        NativeOutboundStatus::Accepted { cursor }
    } else if original.expired {
        NativeOutboundStatus::Expired
    } else {
        NativeOutboundStatus::Ready
    };
    Ok(NativeOutboundApplication {
        conversation_id: original.reservation.conversation_id,
        message: original.message,
        envelope,
        status,
    })
}

#[async_trait]
impl NativeSessionHost for ServiceNativeHost {
    type Error = ServiceHostError;
    type Authorization = ServiceAuthorization;

    async fn outbound_application(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<Option<NativeOutboundApplication>, Self::Error> {
        self.run(|processor, _| {
            self.scope(conversation)?;
            let Some(original) = self
                .journal
                .retained_outbox()?
                .into_iter()
                .find(|original| original.reservation.message_id == message)
            else {
                return Ok(None);
            };
            if original.envelope.is_none() && (original.abandoned || original.expired) {
                return Err(ServiceHostError::Terminal);
            }
            let reservation = original.reservation;
            self.recover(processor, Some(reservation.sender_counter))?;
            let existing = outbound(self.journal.outbound_intent(reservation)?)?;
            if existing.status == NativeOutboundStatus::Ready {
                self.no_earlier_ready(reservation.sender_counter)?;
            }
            Ok(Some(existing))
        })
    }

    async fn prepare_application(
        &self,
        request: NativeApplicationRequest<Self::Authorization>,
    ) -> Result<PreparedApplication, Self::Error> {
        self.run(|processor, _| {
            self.scope(request.conversation_id)?;
            if self
                .journal
                .retained_outbox()?
                .iter()
                .any(|original| original.reservation.message_id == request.message_id)
            {
                return Err(JournalError::Conflict.into());
            }
            self.recover(processor, None)?;
            if !self.journal.ready_outbox()?.is_empty() {
                return Err(ServiceHostError::Ordering);
            }
            Ok(processor.prepare_application(request)?)
        })
    }

    async fn ready_applications(&self) -> Result<Vec<NativePendingApplication>, Self::Error> {
        self.run(|processor, _| {
            self.recover(processor, None)?;
            let mut originals = self.journal.ready_outbox()?;
            originals.sort_by_key(|original| original.reservation.sender_counter);
            originals
                .into_iter()
                .map(|original| {
                    self.scope(original.reservation.conversation_id)?;
                    let existing = outbound(original)?;
                    Ok(NativePendingApplication {
                        conversation_id: existing.conversation_id,
                        envelope: existing.envelope,
                    })
                })
                .collect()
        })
    }

    async fn retry_eligible(&self, conversation: ConversationId) -> Result<bool, Self::Error> {
        self.run(|_, opened| {
            self.scope(conversation)?;
            let identity = self
                .identity
                .lock()
                .map_err(|_| ServiceHostError::Unavailable)?;
            Ok(opened.group.state().member(identity.device_id()).is_some())
        })
    }

    async fn expire_application(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<NativeExpiryOutcome, Self::Error> {
        self.run(|_, opened| {
            if envelope.routing_id() != opened.routing_id {
                return Err(ServiceHostError::Scope);
            }
            let original = self
                .journal
                .retained_outbox()?
                .into_iter()
                .find(|original| original.envelope.as_ref() == Some(envelope))
                .ok_or(ServiceHostError::Evidence)?;
            self.scope(original.reservation.conversation_id)?;
            // NativeSession has already established the exact expiry boundary.
            Ok(self
                .journal
                .expire_outbound(original.reservation, envelope.expires_at_unix_seconds())?)
        })
    }

    async fn accept_application(&self, stored: StoredRelayEnvelope) -> Result<(), Self::Error> {
        self.run(|_, _| Ok(self.journal.accept_outbound(&stored)?))
    }

    async fn ready_memberships(&self) -> Result<Vec<PreparedMembership>, Self::Error> {
        self.run(|_, _| {
            if self
                .journal
                .active_membership_outbox(self.conversation)?
                .is_some()
                || self
                    .journal
                    .active_membership_inbox(self.conversation)?
                    .is_some()
            {
                return Err(ServiceHostError::Unsupported);
            }
            Ok(Vec::new())
        })
    }

    async fn accept_membership(
        &self,
        _stored: StoredRelayEnvelope,
    ) -> Result<NativeAcceptedMembership, Self::Error> {
        self.run(|_, _| Err(ServiceHostError::Unsupported))
    }

    async fn orphan_membership(
        &self,
        _operation: MembershipOperationId,
    ) -> Result<(), Self::Error> {
        self.run(|_, _| Err(ServiceHostError::Unsupported))
    }

    async fn replay_position(
        &self,
        conversation: ConversationId,
    ) -> Result<(RoutingId, u64), Self::Error> {
        self.run(|_, opened| {
            self.scope(conversation)?;
            Ok((opened.routing_id, opened.replay_cursor))
        })
    }

    async fn process_application(
        &self,
        conversation: ConversationId,
        stored: StoredRelayEnvelope,
        now: u64,
    ) -> Result<ProcessedApplication, Self::Error> {
        self.run(|processor, _| {
            self.scope(conversation)?;
            Ok(processor.process_inbound_application(conversation, &stored, now)?)
        })
    }

    async fn process_membership(
        &self,
        conversation: ConversationId,
        _stored: StoredRelayEnvelope,
        _now: u64,
    ) -> Result<(), Self::Error> {
        self.run(|_, _| {
            self.scope(conversation)?;
            Err(ServiceHostError::Unsupported)
        })
    }
}
