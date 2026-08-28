use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use KonclaveClientLibrary::{KonclaveClientError, RelayTransport};
use KonclaveCryptographicCore::{
    MlsWelcome, derive_collaboration_policy_digest,
    derive_collaboration_policy_proposal_message_id,
    derive_collaboration_policy_response_message_id,
};
use KonclaveDomainCore::{
    AcknowledgeRequest, ApplicationContent, ApplicationMessage, CollaborationPolicyDigest,
    CollaborationPolicyProposal, CollaborationPolicyProposalId, CollaborationPolicyResponse,
    CollaborationPolicyResponseOutcome, CollaborationPolicyRevocation, ConversationId,
    ConversationRole, DeviceId, JoinProof, MembershipOperationId, MessageId, ReplayPage,
    ReplayRequest, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_collaboration_policy_bundle, decode_join_proof, encode_collaboration_policy_bundle,
    encode_join_proof,
};
use thiserror::Error;
use tokio::sync::watch;

use crate::conversation::{
    AcceptedMembership, ConversationCoordinator, ConversationCoordinatorError, ConversationSummary,
    MembershipRequestState, PreparedApplication, PreparedMembership, ProcessedApplication,
};
use crate::persistence::{
    CollaborationActionAuthorization, CollaborationPolicyActivationOperation, ExpireOutboundResult,
    HistoryPage, OutboundApplicationStatus, ProfileStoreError, StoredCollaborationPolicyProposal,
};

/// Outbound application input with caller-supplied display and expiry times.
pub(crate) struct SendApplicationRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message_id: MessageId,
    pub(crate) content: ApplicationContent,
    pub(crate) reply_to: Option<MessageId>,
    pub(crate) collaboration_action_authorization: Option<CollaborationActionAuthorization>,
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

pub(crate) struct ProposeCollaborationPolicyRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) proposal_id: CollaborationPolicyProposalId,
    pub(crate) canonical_bundle: Vec<u8>,
    pub(crate) replaces_policy_digest: Option<CollaborationPolicyDigest>,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) now_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

pub(crate) struct ResumeCollaborationPolicyProposalRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) proposal_id: CollaborationPolicyProposalId,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) now_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

pub(crate) struct RespondCollaborationPolicyRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) proposal_id: CollaborationPolicyProposalId,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) now_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

pub(crate) struct RevokeCollaborationPolicyRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message_id: MessageId,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) now_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

pub(crate) struct SentCollaborationPolicyExchange {
    pub(crate) proposal_id: Option<CollaborationPolicyProposalId>,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) message_id: MessageId,
    pub(crate) cursor: u64,
    pub(crate) local_binding_changed: bool,
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
    policy_operations: Arc<tokio::sync::Mutex<()>>,
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
            policy_operations: Arc::clone(&self.policy_operations),
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
            policy_operations: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    async fn serialized_policy_transition<R, F>(
        &self,
        transition: F,
    ) -> Result<(tokio::sync::OwnedMutexGuard<()>, R), ApplicationServiceError>
    where
        R: Send + 'static,
        F: FnOnce() -> Result<R, ApplicationServiceError> + Send + 'static,
    {
        let policy_operation = Arc::clone(&self.policy_operations).lock_owned().await;
        let (policy_operation, result) =
            tokio::task::spawn_blocking(move || (policy_operation, transition()))
                .await
                .map_err(|_| ApplicationServiceError::Task)?;
        Ok((policy_operation, result?))
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
        self.send_with_policy_reservation(request, false).await
    }

    async fn send_policy_operation(
        &self,
        request: SendApplicationRequest,
    ) -> Result<SentApplication, ApplicationServiceError> {
        self.send_with_policy_reservation(request, true).await
    }

    async fn send_with_policy_reservation(
        &self,
        request: SendApplicationRequest,
        policy_operation: bool,
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
            if policy_operation {
                conversations.prepare_collaboration_policy_application_with_id(
                    request.conversation_id,
                    request.message_id,
                    request.content,
                    request.reply_to,
                    request.sent_at_unix_milliseconds,
                    request.expires_at_unix_seconds,
                )
            } else {
                conversations.prepare_application_with_id(
                    request.conversation_id,
                    request.message_id,
                    request.content,
                    request.reply_to,
                    request.collaboration_action_authorization,
                    request.sent_at_unix_milliseconds,
                    request.expires_at_unix_seconds,
                )
            }
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        self.submit_prepared(prepared, request.now_unix_seconds)
            .await
    }

    pub(crate) async fn propose_collaboration_policy(
        &self,
        request: ProposeCollaborationPolicyRequest,
    ) -> Result<SentCollaborationPolicyExchange, ApplicationServiceError> {
        let bundle = decode_collaboration_policy_bundle(&request.canonical_bundle)
            .map_err(|_| ApplicationServiceError::Protocol)?;
        let policy_digest = derive_collaboration_policy_digest(&bundle)
            .map_err(|_| ApplicationServiceError::Protocol)?;
        let local_device = self.conversations.device_id()?;
        let message_id = derive_collaboration_policy_proposal_message_id(
            request.conversation_id,
            local_device,
            request.proposal_id,
        );
        let store = self.conversations.store();
        let canonical_bundle = request.canonical_bundle.clone();
        let (_policy_operation, local_binding_changed) = self
            .serialized_policy_transition(move || {
                Ok(store.apply_collaboration_policy_activation_operation(
                    CollaborationPolicyActivationOperation {
                        conversation_id: request.conversation_id,
                        message_id,
                        proposal_id: request.proposal_id,
                        source_proposal_message_id: None,
                        policy_digest,
                        replaces_policy_digest: request.replaces_policy_digest,
                        canonical_bundle: &canonical_bundle,
                        activated_at_unix_milliseconds: request.sent_at_unix_milliseconds,
                        is_acceptance: false,
                    },
                )?)
            })
            .await?;
        let proposal = CollaborationPolicyProposal::new(
            request.proposal_id,
            policy_digest,
            request.canonical_bundle,
            request.replaces_policy_digest,
        )
        .map_err(|_| ApplicationServiceError::Protocol)?;
        let sent = self
            .send_policy_operation(policy_send_request(
                request.conversation_id,
                message_id,
                ApplicationContent::collaboration_policy_proposal(proposal),
                None,
                request.sent_at_unix_milliseconds,
                request.now_unix_seconds,
                request.expires_at_unix_seconds,
            ))
            .await?;
        Ok(SentCollaborationPolicyExchange {
            proposal_id: Some(request.proposal_id),
            policy_digest,
            message_id: sent.message.message_id(),
            cursor: sent.cursor,
            local_binding_changed,
        })
    }

    pub(crate) async fn resume_collaboration_policy_proposal(
        &self,
        request: ResumeCollaborationPolicyProposalRequest,
    ) -> Result<SentCollaborationPolicyExchange, ApplicationServiceError> {
        let local_device = self.conversations.device_id()?;
        let message_id = derive_collaboration_policy_proposal_message_id(
            request.conversation_id,
            local_device,
            request.proposal_id,
        );
        let store = self.conversations.store();
        let (operation, canonical_bundle) = tokio::task::spawn_blocking(move || {
            let operation = store.collaboration_policy_proposal_operation(
                request.conversation_id,
                message_id,
                request.proposal_id,
            )?;
            let bundle = store
                .collaboration_policy_bundle(operation.policy_digest)?
                .ok_or(ProfileStoreError::CorruptData)?;
            let canonical_bundle = encode_collaboration_policy_bundle(&bundle)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            Ok::<_, ProfileStoreError>((operation, canonical_bundle))
        })
        .await
        .map_err(|_| ApplicationServiceError::Task)??;
        let proposal = CollaborationPolicyProposal::new(
            request.proposal_id,
            operation.policy_digest,
            canonical_bundle,
            operation.replaces_policy_digest,
        )
        .map_err(|_| ApplicationServiceError::Protocol)?;
        let sent = self
            .send_policy_operation(policy_send_request(
                request.conversation_id,
                message_id,
                ApplicationContent::collaboration_policy_proposal(proposal),
                None,
                request.sent_at_unix_milliseconds,
                request.now_unix_seconds,
                request.expires_at_unix_seconds,
            ))
            .await?;
        Ok(SentCollaborationPolicyExchange {
            proposal_id: Some(request.proposal_id),
            policy_digest: operation.policy_digest,
            message_id: sent.message.message_id(),
            cursor: sent.cursor,
            local_binding_changed: operation.binding_changed,
        })
    }

    pub(crate) async fn accept_collaboration_policy(
        &self,
        request: RespondCollaborationPolicyRequest,
    ) -> Result<SentCollaborationPolicyExchange, ApplicationServiceError> {
        self.respond_collaboration_policy(request, CollaborationPolicyResponseOutcome::Accepted)
            .await
    }

    pub(crate) async fn reject_collaboration_policy(
        &self,
        request: RespondCollaborationPolicyRequest,
    ) -> Result<SentCollaborationPolicyExchange, ApplicationServiceError> {
        self.respond_collaboration_policy(request, CollaborationPolicyResponseOutcome::Rejected)
            .await
    }

    async fn respond_collaboration_policy(
        &self,
        request: RespondCollaborationPolicyRequest,
        outcome: CollaborationPolicyResponseOutcome,
    ) -> Result<SentCollaborationPolicyExchange, ApplicationServiceError> {
        let local_device = self.conversations.device_id()?;
        let message_id = derive_collaboration_policy_response_message_id(
            request.conversation_id,
            local_device,
            request.proposal_id,
        );
        let store = self.conversations.store();
        let conversations = self.conversations.clone();
        let (_policy_operation, (proposal_message_id, local_binding_changed)) = self
            .serialized_policy_transition(move || {
                if let Some(operation) = store.collaboration_policy_response_operation(
                    request.conversation_id,
                    message_id,
                    request.proposal_id,
                    request.policy_digest,
                    outcome,
                )? {
                    return Ok((
                        operation.source_proposal_message_id,
                        operation.binding_changed,
                    ));
                }
                let proposal = store
                    .collaboration_policy_proposal(request.conversation_id, request.proposal_id)?;
                validate_collaboration_policy_response_target(
                    &conversations,
                    &proposal,
                    request.policy_digest,
                )?;
                let local_binding_changed = match outcome {
                    CollaborationPolicyResponseOutcome::Accepted => store
                        .apply_collaboration_policy_activation_operation(
                            CollaborationPolicyActivationOperation {
                                conversation_id: request.conversation_id,
                                message_id,
                                proposal_id: request.proposal_id,
                                source_proposal_message_id: Some(proposal.message_id),
                                policy_digest: request.policy_digest,
                                replaces_policy_digest: proposal.replaces_policy_digest,
                                canonical_bundle: &proposal.canonical_bundle,
                                activated_at_unix_milliseconds: request.sent_at_unix_milliseconds,
                                is_acceptance: true,
                            },
                        )?,
                    CollaborationPolicyResponseOutcome::Rejected => store
                        .apply_collaboration_policy_rejection_operation(
                            request.conversation_id,
                            message_id,
                            request.proposal_id,
                            proposal.message_id,
                            request.policy_digest,
                        )?,
                };
                Ok((proposal.message_id, local_binding_changed))
            })
            .await?;
        let response =
            CollaborationPolicyResponse::new(request.proposal_id, request.policy_digest, outcome);
        let sent = self
            .send_policy_operation(policy_send_request(
                request.conversation_id,
                message_id,
                ApplicationContent::CollaborationPolicyResponse(response),
                Some(proposal_message_id),
                request.sent_at_unix_milliseconds,
                request.now_unix_seconds,
                request.expires_at_unix_seconds,
            ))
            .await?;
        Ok(SentCollaborationPolicyExchange {
            proposal_id: Some(request.proposal_id),
            policy_digest: request.policy_digest,
            message_id: sent.message.message_id(),
            cursor: sent.cursor,
            local_binding_changed,
        })
    }

    pub(crate) async fn revoke_collaboration_policy(
        &self,
        request: RevokeCollaborationPolicyRequest,
    ) -> Result<SentCollaborationPolicyExchange, ApplicationServiceError> {
        let revocation_store = self.conversations.store();
        let (_policy_operation, local_binding_changed) = self
            .serialized_policy_transition(move || {
                Ok(
                    revocation_store.apply_collaboration_policy_revocation_operation(
                        request.conversation_id,
                        request.message_id,
                        request.policy_digest,
                    )?,
                )
            })
            .await?;
        let sent = self
            .send_policy_operation(policy_send_request(
                request.conversation_id,
                request.message_id,
                ApplicationContent::CollaborationPolicyRevocation(
                    CollaborationPolicyRevocation::new(request.policy_digest),
                ),
                None,
                request.sent_at_unix_milliseconds,
                request.now_unix_seconds,
                request.expires_at_unix_seconds,
            ))
            .await?;
        Ok(SentCollaborationPolicyExchange {
            proposal_id: None,
            policy_digest: request.policy_digest,
            message_id: sent.message.message_id(),
            cursor: sent.cursor,
            local_binding_changed,
        })
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
        // Recovery is one of the operations ADR 0008 retains a profile for. Admission
        // is refused once the profile is closing, so this never starts work against
        // stores a closer is about to drop. The durable cursor is unchanged, so the
        // same replay is exact when the profile is opened again.
        //
        // This is a top-level operation: no callee takes a second admission, so an
        // admitted replay never waits on the gate again.
        let _admitted = self
            .conversations
            .activity()
            .try_begin()
            .map_err(|_| ApplicationServiceError::ProfileClosing)?;
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
                        return Ok(clean_watch_exit(
                            watch_session.close().await,
                            WatchConnectionExit::Shutdown,
                        ));
                    }
                    continue;
                }
                page = watch_session.next_page() => page?,
            };
            // Waiting on the relay is idle time; holding a page is not. Admission is
            // taken before anything reads the page, and a closing profile refuses it:
            // the page is left unacknowledged and the durable cursor unchanged, so the
            // relay delivers it again after the profile reopens.
            //
            // This is a top-level operation: nothing reached from `process_page` takes
            // a second admission, so an admitted page never waits on the gate again.
            let Ok(admitted) = self.conversations.activity().try_begin() else {
                return Ok(clean_watch_exit(
                    watch_session.close().await,
                    WatchConnectionExit::Shutdown,
                ));
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
            let still_member = self.is_local_member(conversation_id).await?;
            drop(admitted);
            if !still_member {
                return Ok(clean_watch_exit(
                    watch_session.close().await,
                    WatchConnectionExit::LocalMemberRemoved,
                ));
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

fn policy_send_request(
    conversation_id: ConversationId,
    message_id: MessageId,
    content: ApplicationContent,
    reply_to: Option<MessageId>,
    sent_at_unix_milliseconds: u64,
    now_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> SendApplicationRequest {
    SendApplicationRequest {
        conversation_id,
        message_id,
        content,
        reply_to,
        collaboration_action_authorization: None,
        sent_at_unix_milliseconds,
        now_unix_seconds,
        expires_at_unix_seconds,
    }
}

fn validate_collaboration_policy_response_target(
    conversations: &ConversationCoordinator,
    proposal: &StoredCollaborationPolicyProposal,
    expected_digest: CollaborationPolicyDigest,
) -> Result<(), ApplicationServiceError> {
    if proposal.proposer == conversations.device_id()? {
        return Err(ApplicationServiceError::LocalPolicyProposal);
    }
    if proposal.policy_digest != expected_digest {
        return Err(ApplicationServiceError::PolicyProposalMismatch);
    }
    Ok(())
}

fn application_content_equal(left: &ApplicationContent, right: &ApplicationContent) -> bool {
    left == right
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
    #[error("collaboration-policy storage operation failed")]
    PolicyStorage(#[from] ProfileStoreError),
    #[error("collaboration-policy response targets a local proposal")]
    LocalPolicyProposal,
    #[error("collaboration-policy proposal does not match the expected digest")]
    PolicyProposalMismatch,
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
    #[error("the profile is closing and admits no further operations")]
    ProfileClosing,
}

/// Reports a clean watch exit regardless of how the close frame fared.
///
/// Shutdown, refused admission, and local membership removal all finish the session.
/// Nothing after these decisions depends on the relay seeing the close frame.
/// Returning a transport failure here would turn a valid terminal state into a
/// failed task set. Failures on the processing path are unaffected and still
/// propagate.
fn clean_watch_exit(
    closed: Result<(), KonclaveClientError>,
    exit: WatchConnectionExit,
) -> WatchConnectionExit {
    if let Err(error) = closed {
        let outcome = match exit {
            WatchConnectionExit::Shutdown => "shutdown",
            WatchConnectionExit::LocalMemberRemoved => "local_member_removed",
        };
        tracing::debug!(
            error_code = error.code(),
            outcome,
            "relay watch close failed after a clean exit"
        );
    }
    exit
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use KonclaveClientLibrary::{
        RelayAccessCredential, RelayClient, RelayEndpoint, RelayWatchSession,
    };
    use KonclaveDomainCore::{
        AcknowledgeRequest, AdapterConsumerId, AdapterLeaseId, ApplicationContent,
        CollaborationPolicyBundle, CollaborationPolicyEffect, CollaborationPolicyLimits,
        CollaborationPolicyProposal, CollaborationPolicyProposalId, CollaborationPolicyStatement,
        DeliveryClass, EnvelopeId, ProtocolVersion, RelayEnvelope, ReplayPage, ReplayRequest,
    };
    use KonclaveProtocolContracts::v1::encode_collaboration_policy_bundle;
    use KonclaveSecretStorage::{
        ExternalWrappingKeyProvider, SealedSqliteMlsStorage, SecretSealer,
    };
    use async_trait::async_trait;
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::clock::{SystemUnixClock, UnixClock};
    use crate::conversation::tests::{invited_coordinators, paired_coordinators};
    use crate::persistence::{
        CollaborationActionAuthorization, LockedProfile, MessageDirection, ProfileId,
        ProfileStoreError,
    };
    use crate::test_support::TestRelay;

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

    struct MutableClock(AtomicU64);

    impl UnixClock for MutableClock {
        fn now_unix_milliseconds(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
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
        coordinator_with_clock(root, profile_name, Arc::new(SystemUnixClock))
    }

    fn coordinator_with_clock(
        root: &Path,
        profile_name: &str,
        clock: Arc<dyn UnixClock>,
    ) -> ConversationCoordinator {
        let locked = LockedProfile::acquire(root, ProfileId::parse(profile_name).unwrap()).unwrap();
        let mls_path = locked.mls_database_path();
        let profile_sealer = sealer();
        let mls_storage = SealedSqliteMlsStorage::open(&mls_path, profile_sealer.share()).unwrap();
        let store = locked.open_store_with_clock(profile_sealer, clock).unwrap();
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
            collaboration_action_authorization: None,
            sent_at_unix_milliseconds: now_unix_seconds.checked_mul(1_000).unwrap(),
            now_unix_seconds,
            expires_at_unix_seconds,
        }
    }

    fn collaboration_policy_bytes(name: &str, guidance: &str) -> Vec<u8> {
        encode_collaboration_policy_bundle(
            &CollaborationPolicyBundle::new(
                ProtocolVersion::application_v1(),
                name,
                Some(guidance.to_string()),
                vec![
                    CollaborationPolicyStatement::new(
                        "reply",
                        CollaborationPolicyEffect::Allow,
                        "conversation.reply",
                        None,
                    )
                    .unwrap(),
                ],
                vec!["copilot.session-identity".to_string()],
                CollaborationPolicyLimits::default(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn policy_proposal_request(
        conversation_id: ConversationId,
        proposal_id: CollaborationPolicyProposalId,
        canonical_bundle: &[u8],
        replaces_policy_digest: Option<CollaborationPolicyDigest>,
    ) -> ProposeCollaborationPolicyRequest {
        ProposeCollaborationPolicyRequest {
            conversation_id,
            proposal_id,
            canonical_bundle: canonical_bundle.to_vec(),
            replaces_policy_digest,
            sent_at_unix_milliseconds: 1_700_000_000_000,
            now_unix_seconds: 1_700_000_000,
            expires_at_unix_seconds: 1_900_000_000,
        }
    }

    #[tokio::test]
    async fn cancelled_policy_transition_keeps_serialization_until_blocking_work_finishes() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "policy-cancellation");
        let service = ApplicationService::new(coordinator, RecordingRelay::new(false));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_service = service.clone();
        let first = tokio::spawn(async move {
            first_service
                .serialized_policy_transition(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();
        first.abort();
        let _ = first.await;

        let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
        let (done_tx, mut done_rx) = oneshot::channel();
        let second_service = service.clone();
        tokio::spawn(async move {
            attempted_tx.send(()).unwrap();
            let result = second_service.serialized_policy_transition(|| Ok(())).await;
            let _ = done_tx.send(result.is_ok());
        });
        tokio::task::spawn_blocking(move || attempted_rx.recv().unwrap())
            .await
            .unwrap();
        assert!(matches!(
            done_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        release_tx.send(()).unwrap();
        assert!(done_rx.await.unwrap());
    }

    #[tokio::test]
    async fn local_policy_proposal_is_idempotent_and_requires_explicit_replacement() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "policy-local-operations");
        let conversation = coordinator.create().unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(false));
        let first_bytes = collaboration_policy_bytes("first-policy", "Use the first contract.");
        let first_digest = derive_collaboration_policy_digest(
            &decode_collaboration_policy_bundle(&first_bytes).unwrap(),
        )
        .unwrap();
        let first_id = CollaborationPolicyProposalId::from_bytes([11; 16]);

        service.transport.fail_submit.store(true, Ordering::SeqCst);
        assert!(matches!(
            service
                .propose_collaboration_policy(policy_proposal_request(
                    conversation.conversation_id,
                    first_id,
                    &first_bytes,
                    None,
                ))
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(
            coordinator
                .store()
                .active_collaboration_policy(conversation.conversation_id)
                .unwrap()
                .unwrap()
                .digest(),
            first_digest
        );
        service.transport.fail_submit.store(false, Ordering::SeqCst);
        let first = service
            .propose_collaboration_policy(policy_proposal_request(
                conversation.conversation_id,
                first_id,
                &first_bytes,
                None,
            ))
            .await
            .unwrap();
        assert!(first.local_binding_changed);
        let repeated = service
            .propose_collaboration_policy(policy_proposal_request(
                conversation.conversation_id,
                first_id,
                &first_bytes,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(repeated.cursor, first.cursor);
        assert!(repeated.local_binding_changed);
        assert!(matches!(
            service
                .propose_collaboration_policy(policy_proposal_request(
                    conversation.conversation_id,
                    CollaborationPolicyProposalId::from_bytes([16; 16]),
                    &first_bytes,
                    None,
                ))
                .await,
            Err(ApplicationServiceError::PolicyStorage(
                ProfileStoreError::CollaborationPolicyReplacementMismatch
            ))
        ));

        let second_bytes = collaboration_policy_bytes("second-policy", "Use the second contract.");
        let second_id = CollaborationPolicyProposalId::from_bytes([12; 16]);
        assert!(matches!(
            service
                .propose_collaboration_policy(policy_proposal_request(
                    conversation.conversation_id,
                    second_id,
                    &second_bytes,
                    None,
                ))
                .await,
            Err(ApplicationServiceError::PolicyStorage(
                ProfileStoreError::CollaborationPolicyReplacementMismatch
            ))
        ));
        assert_eq!(service.transport.envelopes.lock().unwrap().len(), 1);

        let second = service
            .propose_collaboration_policy(policy_proposal_request(
                conversation.conversation_id,
                second_id,
                &second_bytes,
                Some(first.policy_digest),
            ))
            .await
            .unwrap();
        assert!(second.local_binding_changed);
        let active = coordinator
            .store()
            .active_collaboration_policy(conversation.conversation_id)
            .unwrap()
            .unwrap();
        assert_eq!(active.digest(), second.policy_digest);

        let revocation_request = || RevokeCollaborationPolicyRequest {
            conversation_id: conversation.conversation_id,
            message_id: MessageId::from_bytes([13; MessageId::LENGTH]),
            policy_digest: second.policy_digest,
            sent_at_unix_milliseconds: 1_700_000_000_000,
            now_unix_seconds: 1_700_000_000,
            expires_at_unix_seconds: 1_900_000_000,
        };
        service.transport.fail_submit.store(true, Ordering::SeqCst);
        assert!(matches!(
            service
                .revoke_collaboration_policy(revocation_request())
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert!(
            coordinator
                .store()
                .active_collaboration_policy(conversation.conversation_id)
                .unwrap()
                .is_none()
        );
        service.transport.fail_submit.store(false, Ordering::SeqCst);
        let revoked = service
            .revoke_collaboration_policy(revocation_request())
            .await
            .unwrap();
        assert!(revoked.local_binding_changed);
        assert!(
            coordinator
                .store()
                .active_collaboration_policy(conversation.conversation_id)
                .unwrap()
                .is_none()
        );
        let historical_retry = service
            .propose_collaboration_policy(policy_proposal_request(
                conversation.conversation_id,
                second_id,
                &second_bytes,
                Some(first.policy_digest),
            ))
            .await
            .unwrap();
        assert_eq!(historical_retry.cursor, second.cursor);
        assert!(
            coordinator
                .store()
                .active_collaboration_policy(conversation.conversation_id)
                .unwrap()
                .is_none()
        );
        let resumed = service
            .resume_collaboration_policy_proposal(ResumeCollaborationPolicyProposalRequest {
                conversation_id: conversation.conversation_id,
                proposal_id: second_id,
                sent_at_unix_milliseconds: 1_700_000_000_000,
                now_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_900_000_000,
            })
            .await
            .unwrap();
        assert_eq!(resumed.cursor, second.cursor);
        assert!(resumed.local_binding_changed);
        assert!(
            coordinator
                .store()
                .active_collaboration_policy(conversation.conversation_id)
                .unwrap()
                .is_none()
        );

        let third_id = CollaborationPolicyProposalId::from_bytes([14; 16]);
        service
            .propose_collaboration_policy(policy_proposal_request(
                conversation.conversation_id,
                third_id,
                &second_bytes,
                None,
            ))
            .await
            .unwrap();
        let second_revocation = service
            .revoke_collaboration_policy(RevokeCollaborationPolicyRequest {
                conversation_id: conversation.conversation_id,
                message_id: MessageId::from_bytes([15; MessageId::LENGTH]),
                policy_digest: second.policy_digest,
                sent_at_unix_milliseconds: 1_700_000_000_001,
                now_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_900_000_000,
            })
            .await
            .unwrap();
        assert!(second_revocation.cursor > revoked.cursor);
        assert!(
            coordinator
                .store()
                .active_collaboration_policy(conversation.conversation_id)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn policy_proposal_resume_reconstructs_a_committed_pre_outbox_operation() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "policy-proposal-resume");
        let conversation = coordinator.create().unwrap();
        let canonical_bundle =
            collaboration_policy_bytes("resume-policy", "Use the committed policy.");
        let digest = derive_collaboration_policy_digest(
            &decode_collaboration_policy_bundle(&canonical_bundle).unwrap(),
        )
        .unwrap();
        let proposal_id = CollaborationPolicyProposalId::from_bytes([18; 16]);
        let message_id = derive_collaboration_policy_proposal_message_id(
            conversation.conversation_id,
            coordinator.device_id().unwrap(),
            proposal_id,
        );
        coordinator
            .store()
            .apply_collaboration_policy_activation_operation(
                CollaborationPolicyActivationOperation {
                    conversation_id: conversation.conversation_id,
                    message_id,
                    proposal_id,
                    source_proposal_message_id: None,
                    policy_digest: digest,
                    replaces_policy_digest: None,
                    canonical_bundle: &canonical_bundle,
                    activated_at_unix_milliseconds: 1_700_000_000_000,
                    is_acceptance: false,
                },
            )
            .unwrap();
        assert!(
            coordinator
                .outbound_application(conversation.conversation_id, message_id)
                .unwrap()
                .is_none()
        );
        let service = ApplicationService::new(coordinator, RecordingRelay::new(false));

        let resumed = service
            .resume_collaboration_policy_proposal(ResumeCollaborationPolicyProposalRequest {
                conversation_id: conversation.conversation_id,
                proposal_id,
                sent_at_unix_milliseconds: 1_700_000_000_001,
                now_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_900_000_000,
            })
            .await
            .unwrap();
        assert_eq!(resumed.proposal_id, Some(proposal_id));
        assert_eq!(resumed.policy_digest, digest);
        assert_eq!(resumed.message_id, message_id);
        assert_eq!(resumed.cursor, 1);
        assert!(resumed.local_binding_changed);
    }

    #[tokio::test]
    async fn remote_policy_response_is_informational_and_terminal_outcomes_conflict() {
        let (_root, alice, bob, conversation_id, _) = paired_coordinators();
        let transport = Arc::new(RecordingRelay::new(false));
        let alice_service = ApplicationService::from_shared(alice.clone(), Arc::clone(&transport));
        let bob_service = ApplicationService::from_shared(bob.clone(), Arc::clone(&transport));
        let canonical_bundle =
            collaboration_policy_bytes("shared-policy", "Use the shared contract.");
        let bundle = decode_collaboration_policy_bundle(&canonical_bundle).unwrap();
        let digest = derive_collaboration_policy_digest(&bundle).unwrap();
        let proposal_id = CollaborationPolicyProposalId::from_bytes([21; 16]);
        let proposal_message_id = derive_collaboration_policy_proposal_message_id(
            conversation_id,
            alice.device_id().unwrap(),
            proposal_id,
        );
        let proposal =
            CollaborationPolicyProposal::new(proposal_id, digest, canonical_bundle, None).unwrap();
        alice_service
            .send(policy_send_request(
                conversation_id,
                proposal_message_id,
                ApplicationContent::collaboration_policy_proposal(proposal),
                None,
                1_700_000_000_000,
                1_700_000_000,
                1_900_000_000,
            ))
            .await
            .unwrap();
        assert!(
            alice
                .store()
                .active_collaboration_policy(conversation_id)
                .unwrap()
                .is_none()
        );

        let proposal_envelope = transport.envelopes.lock().unwrap()[0].clone();
        transport
            .push_replay_page(ReplayPage::new(vec![proposal_envelope.clone()], 1, false).unwrap());
        bob_service
            .replay_once(conversation_id, 100, 1_700_000_000)
            .await
            .unwrap();
        let response_request = || RespondCollaborationPolicyRequest {
            conversation_id,
            proposal_id,
            policy_digest: digest,
            sent_at_unix_milliseconds: 1_700_000_000_001,
            now_unix_seconds: 1_700_000_000,
            expires_at_unix_seconds: 1_900_000_000,
        };
        transport.fail_submit.store(true, Ordering::SeqCst);
        assert!(matches!(
            bob_service
                .accept_collaboration_policy(response_request())
                .await,
            Err(ApplicationServiceError::Relay(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert_eq!(
            bob.store()
                .active_collaboration_policy(conversation_id)
                .unwrap()
                .unwrap()
                .digest(),
            digest
        );
        transport.fail_submit.store(false, Ordering::SeqCst);
        let accepted = bob_service
            .accept_collaboration_policy(response_request())
            .await
            .unwrap();
        assert!(accepted.local_binding_changed);
        assert!(matches!(
            bob_service
                .reject_collaboration_policy(response_request())
                .await,
            Err(ApplicationServiceError::PolicyStorage(
                ProfileStoreError::CollaborationPolicyProposalConflict
            ))
        ));
        assert_eq!(
            bob.store()
                .active_collaboration_policy(conversation_id)
                .unwrap()
                .unwrap()
                .digest(),
            digest
        );

        let response_envelope = transport.envelopes.lock().unwrap()[1].clone();
        transport.push_replay_page(
            ReplayPage::new(vec![proposal_envelope, response_envelope], 2, false).unwrap(),
        );
        alice_service
            .replay_once(conversation_id, 100, 1_700_000_000)
            .await
            .unwrap();
        assert!(
            alice
                .store()
                .active_collaboration_policy(conversation_id)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn committed_policy_response_recovers_after_later_proposal_conflict() {
        let (_root, alice, bob, conversation_id, _) = paired_coordinators();
        let transport = Arc::new(RecordingRelay::new(false));
        let alice_service = ApplicationService::from_shared(alice.clone(), Arc::clone(&transport));
        let bob_service = ApplicationService::from_shared(bob.clone(), Arc::clone(&transport));
        let canonical_bundle =
            collaboration_policy_bytes("recoverable-policy", "Use the recoverable contract.");
        let digest = derive_collaboration_policy_digest(
            &decode_collaboration_policy_bundle(&canonical_bundle).unwrap(),
        )
        .unwrap();
        let proposal_id = CollaborationPolicyProposalId::from_bytes([31; 16]);
        let proposal_message_id = derive_collaboration_policy_proposal_message_id(
            conversation_id,
            alice.device_id().unwrap(),
            proposal_id,
        );
        alice_service
            .send(policy_send_request(
                conversation_id,
                proposal_message_id,
                ApplicationContent::collaboration_policy_proposal(
                    CollaborationPolicyProposal::new(
                        proposal_id,
                        digest,
                        canonical_bundle.clone(),
                        None,
                    )
                    .unwrap(),
                ),
                None,
                1_700_000_000_000,
                1_700_000_000,
                1_900_000_000,
            ))
            .await
            .unwrap();
        let proposal_envelope = transport.envelopes.lock().unwrap()[0].clone();
        transport.push_replay_page(ReplayPage::new(vec![proposal_envelope], 1, false).unwrap());
        bob_service
            .replay_once(conversation_id, 100, 1_700_000_000)
            .await
            .unwrap();

        let response_message_id = derive_collaboration_policy_response_message_id(
            conversation_id,
            bob.device_id().unwrap(),
            proposal_id,
        );
        bob.store()
            .apply_collaboration_policy_activation_operation(
                CollaborationPolicyActivationOperation {
                    conversation_id,
                    message_id: response_message_id,
                    proposal_id,
                    source_proposal_message_id: Some(proposal_message_id),
                    policy_digest: digest,
                    replaces_policy_digest: None,
                    canonical_bundle: &canonical_bundle,
                    activated_at_unix_milliseconds: 1_700_000_000_001,
                    is_acceptance: true,
                },
            )
            .unwrap();

        let conflicting_bundle =
            collaboration_policy_bytes("conflicting-policy", "Use a conflicting contract.");
        let conflicting_digest = derive_collaboration_policy_digest(
            &decode_collaboration_policy_bundle(&conflicting_bundle).unwrap(),
        )
        .unwrap();
        alice_service
            .send(policy_send_request(
                conversation_id,
                MessageId::from_bytes([32; MessageId::LENGTH]),
                ApplicationContent::collaboration_policy_proposal(
                    CollaborationPolicyProposal::new(
                        proposal_id,
                        conflicting_digest,
                        conflicting_bundle,
                        None,
                    )
                    .unwrap(),
                ),
                None,
                1_700_000_000_002,
                1_700_000_000,
                1_900_000_000,
            ))
            .await
            .unwrap();
        let conflicting_envelope = transport.envelopes.lock().unwrap()[1].clone();
        transport.push_replay_page(ReplayPage::new(vec![conflicting_envelope], 2, false).unwrap());
        bob_service
            .replay_once(conversation_id, 100, 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(
            bob.store()
                .collaboration_policy_proposal(conversation_id, proposal_id)
                .err(),
            Some(ProfileStoreError::CollaborationPolicyProposalConflict)
        );

        let recovered = bob_service
            .accept_collaboration_policy(RespondCollaborationPolicyRequest {
                conversation_id,
                proposal_id,
                policy_digest: digest,
                sent_at_unix_milliseconds: 1_700_000_000_001,
                now_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_900_000_000,
            })
            .await
            .unwrap();
        assert_eq!(recovered.message_id, response_message_id);
        assert!(recovered.local_binding_changed);
        assert_eq!(transport.envelopes.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn preempted_policy_response_id_cannot_mutate_local_authority() {
        let (_root, alice, bob, conversation_id, _) = paired_coordinators();
        let transport = Arc::new(RecordingRelay::new(false));
        let alice_service = ApplicationService::from_shared(alice.clone(), Arc::clone(&transport));
        let bob_service = ApplicationService::from_shared(bob.clone(), Arc::clone(&transport));
        let proposal_id = CollaborationPolicyProposalId::from_bytes([41; 16]);
        let response_message_id = derive_collaboration_policy_response_message_id(
            conversation_id,
            bob.device_id().unwrap(),
            proposal_id,
        );
        alice_service
            .send(SendApplicationRequest {
                conversation_id,
                message_id: response_message_id,
                content: ApplicationContent::text("preempt the response identifier").unwrap(),
                reply_to: None,
                collaboration_action_authorization: None,
                sent_at_unix_milliseconds: 1_700_000_000_000,
                now_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_900_000_000,
            })
            .await
            .unwrap();
        let preempting_envelope = transport.envelopes.lock().unwrap()[0].clone();
        transport.push_replay_page(ReplayPage::new(vec![preempting_envelope], 1, false).unwrap());
        bob_service
            .replay_once(conversation_id, 100, 1_700_000_000)
            .await
            .unwrap();

        let canonical_bundle =
            collaboration_policy_bytes("preempted-policy", "Use the preempted contract.");
        let digest = derive_collaboration_policy_digest(
            &decode_collaboration_policy_bundle(&canonical_bundle).unwrap(),
        )
        .unwrap();
        let proposal_message_id = derive_collaboration_policy_proposal_message_id(
            conversation_id,
            alice.device_id().unwrap(),
            proposal_id,
        );
        alice_service
            .send(policy_send_request(
                conversation_id,
                proposal_message_id,
                ApplicationContent::collaboration_policy_proposal(
                    CollaborationPolicyProposal::new(proposal_id, digest, canonical_bundle, None)
                        .unwrap(),
                ),
                None,
                1_700_000_000_001,
                1_700_000_000,
                1_900_000_000,
            ))
            .await
            .unwrap();
        let proposal_envelope = transport.envelopes.lock().unwrap()[1].clone();
        transport.push_replay_page(ReplayPage::new(vec![proposal_envelope], 2, false).unwrap());
        bob_service
            .replay_once(conversation_id, 100, 1_700_000_000)
            .await
            .unwrap();

        assert!(matches!(
            bob_service
                .accept_collaboration_policy(RespondCollaborationPolicyRequest {
                    conversation_id,
                    proposal_id,
                    policy_digest: digest,
                    sent_at_unix_milliseconds: 1_700_000_000_002,
                    now_unix_seconds: 1_700_000_000,
                    expires_at_unix_seconds: 1_900_000_000,
                })
                .await,
            Err(ApplicationServiceError::PolicyStorage(
                ProfileStoreError::CollaborationPolicyProposalConflict
            ))
        ));
        assert!(
            bob.store()
                .active_collaboration_policy(conversation_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(transport.envelopes.lock().unwrap().len(), 2);
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
    async fn collaboration_authorization_expires_while_waiting_for_submission() {
        let root = tempfile::tempdir().unwrap();
        let clock = Arc::new(MutableClock(AtomicU64::new(1_000)));
        let coordinator = coordinator_with_clock(root.path(), "policy-send-expiry", clock.clone());
        let conversation = coordinator.create().unwrap();
        let store = coordinator.store();
        let canonical_bundle =
            collaboration_policy_bytes("contract-alignment", "Align the contract.");
        let digest = store
            .store_collaboration_policy_bundle(&canonical_bundle)
            .unwrap();
        store
            .activate_collaboration_policy(conversation.conversation_id, digest, 0)
            .unwrap();
        let consumer_id = AdapterConsumerId::from_bytes([31; AdapterConsumerId::LENGTH]);
        store
            .acquire_adapter_consumer(
                consumer_id,
                AdapterLeaseId::from_bytes([32; AdapterLeaseId::LENGTH]),
                1_000,
                2_000,
            )
            .unwrap();
        let service = ApplicationService::new(coordinator.clone(), RecordingRelay::new(false));
        let mut request = request(conversation.conversation_id, "authorized reply");
        request.collaboration_action_authorization = Some(CollaborationActionAuthorization {
            policy_digest: digest,
            consumer_id,
            not_after_unix_milliseconds: 2_000,
        });
        let message_id = request.message_id;
        let submission = service.submissions.lock().await;
        let mut send = Box::pin(service.send(request));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(send.as_mut(), &mut context).is_pending());

        clock.0.store(2_000, Ordering::SeqCst);
        drop(submission);
        assert!(matches!(
            send.await,
            Err(ApplicationServiceError::Conversation(
                ConversationCoordinatorError::Profile(ProfileStoreError::InvalidAdapterLease)
            ))
        ));
        assert!(
            coordinator
                .outbound_application(conversation.conversation_id, message_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .load_conversation(conversation.conversation_id)
                .unwrap()
                .sender_counter,
            0
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
        let relay = TestRelay::start_static(token).await;
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
        // A page in hand is an in-flight profile operation: the shared service must
        // not evict the profile between arrival and durable processing.
        let watched_activity = bob_service.conversations.activity().clone();
        let observed_in_flight = Arc::new(AtomicUsize::new(0));
        let recorded_in_flight = Arc::clone(&observed_in_flight);
        let watcher = tokio::spawn(async move {
            watch_service
                .watch_connection_until_observed(conversation_id, shutdown_rx, move |page| {
                    recorded_in_flight.fetch_max(watched_activity.in_flight(), Ordering::SeqCst);
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
        assert!(
            observed_in_flight.load(Ordering::SeqCst) >= 1,
            "a received page must mark the profile busy while it is processed"
        );
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
        // Asserted after the worker has stopped: while it runs, the count reflects
        // whichever page it is holding rather than a settled value.
        assert_eq!(
            bob_service.conversations.activity().in_flight(),
            0,
            "a stopped watch worker must leave no operation admitted"
        );
        relay.stop().await;
    }

    #[test]
    fn a_failed_close_does_not_change_a_clean_watch_exit() {
        // A relay that never sees the close frame changes nothing durable: the page
        // was not processed, the cursor did not move, and the profile is stopping.
        assert_eq!(
            clean_watch_exit(
                Err(KonclaveClientError::TransportUnavailable),
                WatchConnectionExit::Shutdown,
            ),
            WatchConnectionExit::Shutdown
        );
        assert_eq!(
            clean_watch_exit(
                Err(KonclaveClientError::Timeout),
                WatchConnectionExit::LocalMemberRemoved,
            ),
            WatchConnectionExit::LocalMemberRemoved
        );
        assert_eq!(
            clean_watch_exit(Ok(()), WatchConnectionExit::Shutdown),
            WatchConnectionExit::Shutdown
        );
    }

    #[tokio::test]
    async fn a_closing_profile_refuses_replay_without_touching_durable_state() {
        let (_root, alice, _bob, conversation_id, _device) = paired_coordinators();
        let service = ApplicationService::new(alice.clone(), RecordingRelay::new(false));
        alice.activity().begin_closing();

        assert!(matches!(
            service
                .replay_once(conversation_id, 100, 1_800_000_000)
                .await,
            Err(ApplicationServiceError::ProfileClosing)
        ));
        assert!(
            service.transport.replay_requests.lock().unwrap().is_empty(),
            "a refused replay must not reach the relay"
        );
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
