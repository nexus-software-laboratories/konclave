use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use KonclaveClientLibrary::{
    KonclaveClientError, PairingCapability, PairingCapabilityText, PairingRendezvousTokenText,
    PairingRendezvousTransport, RelayEndpoint, RelayTransport, create_pairing_rendezvous,
    open_pairing_rendezvous, pairing_rendezvous_take_request,
};
use KonclaveCryptographicCore::{
    KonclaveCryptographicError, MlsWelcome, verify_device_credential_binding, verify_invitation,
    verify_pairing_control,
};
use KonclaveDomainCore::{
    AcknowledgeRequest, ApplicationContent, ConversationId, ConversationRole, DeviceId, JoinProof,
    MessageId, PairingEnvelope, PairingId, PairingInvitationPayload, PairingMessageId,
    PairingStage, PairingWelcomePayload, RepeatPairingOperationId, RepeatPairingRequest,
    RepeatPairingResponse, ReplayRequest, StoredRelayEnvelope, TrustedDeviceAlias,
};
use KonclaveProtocolContracts::{KonclaveProtocolError, v1};
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::application::{
    ApplicationService, ApplicationServiceError, SendApplicationRequest, validate_acknowledgment,
    validate_replay_page,
};
use crate::conversation::{ConversationCoordinator, ConversationCoordinatorError};
use crate::pairing::{
    PairingObservationResult, PairingOperationState, PairingStateError, generate_pairing_message_id,
};
use crate::persistence::pairing::{PairingCheckpoint, PairingPhase, PairingRole};
use crate::persistence::repeat_pairing::{RepeatPairingCheckpoint, RepeatPairingPeerBinding};
use crate::persistence::short_code_pairing::ShortCodePeerBinding;
use crate::persistence::{ProfileStore, ProfileStoreError};
use crate::repeat_pairing::{
    RepeatPairingOperationState, RepeatPairingPhase, RepeatPairingRole, RepeatPairingStateError,
};
use crate::short_code_pairing::ShortCodeStateError;

#[path = "short_code_pairing_service.rs"]
mod short_code;
pub(crate) use short_code::ShortCodePairingStatus;

const PAIRING_REPLAY_LIMIT: u32 = 8;
const ACTIVE_PAIRING_PAGE_SIZE: usize = 32;
pub(crate) const MAX_AUTHORIZATION_WINDOW_SECONDS: u64 = 15 * 60;
const COMPLETION_WINDOW_SECONDS: u64 = 300;
const COMPENSATION_ENVELOPE_EXPIRY: u64 = i64::MAX as u64;
const ACTIVE_REPEAT_PAIRING_PAGE_SIZE: usize = 16;

/// Secret capability returned for the one explicit transfer operation.
///
/// This value implements neither `Clone` nor `Debug` and zeroizes its text on drop.
pub(crate) struct CreatedPairing {
    pub(crate) pairing_id: PairingId,
    pub(crate) capability: PairingCapabilityText,
}

/// Compact secret returned for one explicit cross-device handoff.
///
/// This value implements neither `Clone` nor `Debug` and zeroizes its text on drop.
pub(crate) struct CreatedPairingRendezvous {
    pub(crate) pairing_id: PairingId,
    pub(crate) token: PairingRendezvousTokenText,
}

/// Non-secret status for one durable pairing operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairingStatus {
    pub(crate) pairing_id: PairingId,
    pub(crate) role: PairingRole,
    pub(crate) phase: PairingPhase,
    pub(crate) joiner_device_id: DeviceId,
    pub(crate) requested_role: ConversationRole,
    pub(crate) inviter_device_id: Option<DeviceId>,
    pub(crate) granted_role: Option<ConversationRole>,
    pub(crate) conversation_id: Option<ConversationId>,
    pub(crate) authorization_deadline_unix_seconds: u64,
    pub(crate) completion_deadline_unix_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RepeatPairingStatus {
    pub(crate) operation_id: RepeatPairingOperationId,
    pub(crate) role: RepeatPairingRole,
    pub(crate) phase: RepeatPairingPhase,
    pub(crate) peer_device_id: DeviceId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) pairing_id: Option<PairingId>,
    pub(crate) deadline_unix_seconds: u64,
}

/// Harness-neutral pairing composition over durable daemon and relay services.
pub(crate) struct PairingService<T> {
    conversations: ConversationCoordinator,
    applications: ApplicationService<T>,
    store: Arc<ProfileStore>,
    transport: Arc<T>,
    relay_endpoint: RelayEndpoint,
    mutation_locks: PairingMutationLocks,
    short_code_mutation_locks: short_code::ShortCodeMutationLocks,
    repeat_pairing_mutation_locks: RepeatPairingMutationLocks,
}

impl<T> Clone for PairingService<T> {
    fn clone(&self) -> Self {
        Self {
            conversations: self.conversations.clone(),
            applications: self.applications.clone(),
            store: Arc::clone(&self.store),
            transport: Arc::clone(&self.transport),
            relay_endpoint: self.relay_endpoint.clone(),
            mutation_locks: self.mutation_locks.clone(),
            short_code_mutation_locks: self.short_code_mutation_locks.clone(),
            repeat_pairing_mutation_locks: self.repeat_pairing_mutation_locks.clone(),
        }
    }
}

#[derive(Clone, Default)]
struct PairingMutationLocks {
    gates: Arc<AsyncMutex<BTreeMap<PairingId, Weak<AsyncMutex<()>>>>>,
}

#[derive(Clone, Default)]
struct RepeatPairingMutationLocks {
    gates: Arc<AsyncMutex<BTreeMap<RepeatPairingOperationId, Weak<AsyncMutex<()>>>>>,
}

impl RepeatPairingMutationLocks {
    async fn acquire(&self, operation_id: RepeatPairingOperationId) -> OwnedMutexGuard<()> {
        let gate = {
            let mut gates = self.gates.lock().await;
            gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = gates.get(&operation_id).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(AsyncMutex::new(()));
                gates.insert(operation_id, Arc::downgrade(&gate));
                gate
            }
        };
        gate.lock_owned().await
    }
}

impl PairingMutationLocks {
    /// The returned guard intentionally spans relay and MLS awaits so an irreversible
    /// membership side effect and its pairing checkpoint remain one serialized unit.
    async fn acquire(&self, pairing_id: PairingId) -> OwnedMutexGuard<()> {
        let gate = {
            let mut gates = self.gates.lock().await;
            gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = gates.get(&pairing_id).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(AsyncMutex::new(()));
                gates.insert(pairing_id, Arc::downgrade(&gate));
                gate
            }
        };
        gate.lock_owned().await
    }
}

impl<T> PairingService<T>
where
    T: RelayTransport + 'static,
{
    /// Creates a pairing service sharing the profile's relay transport.
    pub(crate) fn new(
        conversations: ConversationCoordinator,
        applications: ApplicationService<T>,
        relay_endpoint: RelayEndpoint,
    ) -> Self {
        let store = conversations.store();
        let transport = applications.relay_transport();
        Self {
            conversations,
            applications,
            store,
            transport,
            relay_endpoint,
            mutation_locks: PairingMutationLocks::default(),
            short_code_mutation_locks: short_code::ShortCodeMutationLocks::default(),
            repeat_pairing_mutation_locks: RepeatPairingMutationLocks::default(),
        }
    }

    pub(crate) async fn start_repeat_pairing(
        &self,
        alias: TrustedDeviceAlias,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<RepeatPairingStatus, PairingServiceError> {
        require_authorization_window(now_unix_seconds, expires_at_unix_seconds)?;
        let conversations = self.conversations.clone();
        let (resolution, identifiers) = tokio::task::spawn_blocking(move || {
            let resolution = conversations.resolve_trusted_device_alias(&alias)?;
            let identifiers = conversations.generate_repeat_pairing_identifiers()?;
            Ok::<_, ConversationCoordinatorError>((resolution, identifiers))
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        let (operation_id, conversation_id, routing_id) = identifiers;
        let state = RepeatPairingOperationState::initiator(
            operation_id,
            resolution.bootstrap_conversation_id(),
            conversation_id,
            routing_id,
            resolution.device_id(),
            resolution.device_root_public_key(),
            expires_at_unix_seconds,
        );
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.reserve_repeat_pairing(&state, now_unix_seconds))
            .await
            .map_err(|_| PairingServiceError::Task)??;
        self.sync_repeat_pairing(operation_id, now_unix_seconds)
            .await
    }

    pub(crate) async fn repeat_pairing_status(
        &self,
        operation_id: RepeatPairingOperationId,
    ) -> Result<RepeatPairingStatus, PairingServiceError> {
        let checkpoint = self.load_repeat_pairing(operation_id).await?;
        Ok(repeat_pairing_status(&checkpoint.state))
    }

    pub(crate) async fn sync_repeat_pairing(
        &self,
        operation_id: RepeatPairingOperationId,
        now_unix_seconds: u64,
    ) -> Result<RepeatPairingStatus, PairingServiceError> {
        let _mutation = self
            .repeat_pairing_mutation_locks
            .acquire(operation_id)
            .await;
        self.sync_repeat_pairing_locked(operation_id, now_unix_seconds)
            .await
    }

    pub(crate) async fn cancel_repeat_pairing(
        &self,
        operation_id: RepeatPairingOperationId,
        now_unix_seconds: u64,
    ) -> Result<RepeatPairingStatus, PairingServiceError> {
        let _mutation = self
            .repeat_pairing_mutation_locks
            .acquire(operation_id)
            .await;
        let mut checkpoint = self.load_repeat_pairing(operation_id).await?;
        if !checkpoint.state.phase.is_terminal()
            && checkpoint.state.phase != RepeatPairingPhase::Cancelling
        {
            checkpoint.state.phase = RepeatPairingPhase::Cancelling;
            self.checkpoint_repeat_pairing(checkpoint).await?;
        }
        self.sync_repeat_pairing_locked(operation_id, now_unix_seconds)
            .await
    }

    async fn sync_repeat_pairing_locked(
        &self,
        operation_id: RepeatPairingOperationId,
        now_unix_seconds: u64,
    ) -> Result<RepeatPairingStatus, PairingServiceError> {
        for _ in 0..8 {
            let mut checkpoint = self.load_repeat_pairing(operation_id).await?;
            if checkpoint.state.phase.is_terminal() {
                return Ok(repeat_pairing_status(&checkpoint.state));
            }
            if checkpoint.state.phase == RepeatPairingPhase::Cancelling {
                if let Some(pairing_id) = checkpoint.state.pairing_id {
                    let pairing = self.status(pairing_id).await?;
                    if pairing.phase == PairingPhase::Completed {
                        checkpoint.state.phase = RepeatPairingPhase::Completed;
                        self.checkpoint_repeat_pairing(checkpoint).await?;
                        continue;
                    }
                    self.cancel(pairing_id, now_unix_seconds).await?;
                }
                checkpoint.state.phase = RepeatPairingPhase::Cancelled;
                self.checkpoint_repeat_pairing(checkpoint).await?;
                continue;
            }
            if now_unix_seconds >= checkpoint.state.deadline_unix_seconds {
                checkpoint.state.phase = RepeatPairingPhase::Cancelling;
                self.checkpoint_repeat_pairing(checkpoint).await?;
                continue;
            }
            let conversations = self.conversations.clone();
            let bootstrap_conversation_id = checkpoint.state.bootstrap_conversation_id;
            let peer_device_id = checkpoint.state.peer_device_id;
            let peer_root_public_key = checkpoint.state.peer_root_public_key;
            let peer_evidence = tokio::task::spawn_blocking(move || {
                conversations.verify_repeat_pairing_peer(
                    bootstrap_conversation_id,
                    peer_device_id,
                    peer_root_public_key,
                )
            })
            .await
            .map_err(|_| PairingServiceError::Task)?;
            match peer_evidence {
                Ok(()) => {}
                Err(
                    ConversationCoordinatorError::TrustedDeviceRemoved
                    | ConversationCoordinatorError::TrustedDeviceRootMismatch
                    | ConversationCoordinatorError::TrustedDeviceRepeatPairingUnsupported,
                ) => {
                    checkpoint.state.phase = RepeatPairingPhase::Cancelling;
                    self.checkpoint_repeat_pairing(checkpoint).await?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            match checkpoint.state.phase {
                RepeatPairingPhase::InitiatorSendingRequest => {
                    let request = RepeatPairingRequest::new(
                        operation_id,
                        checkpoint.state.peer_device_id,
                        checkpoint.state.new_conversation_id,
                        checkpoint.state.deadline_unix_seconds,
                    )
                    .map_err(KonclaveProtocolError::from)?;
                    self.applications
                        .send(SendApplicationRequest {
                            conversation_id: checkpoint.state.bootstrap_conversation_id,
                            message_id: repeat_pairing_request_message_id(operation_id),
                            content: ApplicationContent::repeat_pairing_request(request),
                            reply_to: None,
                            collaboration_action_authorization: None,
                            sent_at_unix_milliseconds: unix_milliseconds(now_unix_seconds)?,
                            now_unix_seconds,
                            expires_at_unix_seconds: checkpoint.state.deadline_unix_seconds,
                        })
                        .await?;
                    let current = self.load_repeat_pairing(operation_id).await?;
                    if current.generation == checkpoint.generation
                        && current.state.phase == RepeatPairingPhase::InitiatorSendingRequest
                    {
                        checkpoint.state.phase = RepeatPairingPhase::InitiatorAwaitingResponse;
                        self.checkpoint_repeat_pairing(checkpoint).await?;
                        continue;
                    }
                }
                RepeatPairingPhase::InitiatorAwaitingResponse => {
                    return Ok(repeat_pairing_status(&checkpoint.state));
                }
                RepeatPairingPhase::InitiatorRedeemingCapability => {
                    let capability_text = checkpoint
                        .state
                        .capability
                        .as_ref()
                        .ok_or(PairingServiceError::InvalidTransition)?;
                    let capability =
                        match PairingCapability::decode(capability_text, now_unix_seconds) {
                            Ok(capability) => capability,
                            Err(_) => {
                                checkpoint.state.phase = RepeatPairingPhase::Cancelling;
                                self.checkpoint_repeat_pairing(checkpoint).await?;
                                continue;
                            }
                        };
                    if capability.offer().device_id() != checkpoint.state.peer_device_id
                        || capability.offer().device_root_public_key()
                            != checkpoint.state.peer_root_public_key
                        || capability.offer().requested_role() != ConversationRole::Member
                        || capability.offer().expires_at_unix_seconds()
                            != checkpoint.state.deadline_unix_seconds
                        || capability.relay_endpoint().as_str() != self.relay_endpoint.as_str()
                    {
                        checkpoint.state.phase = RepeatPairingPhase::Cancelling;
                        self.checkpoint_repeat_pairing(checkpoint).await?;
                        continue;
                    }
                    let pairing_id = capability.offer().pairing_id();
                    self.redeem_decoded_capability(capability, now_unix_seconds)
                        .await?;
                    checkpoint.state.pairing_id = Some(pairing_id);
                    checkpoint.state.phase = RepeatPairingPhase::InitiatorCreatingConversation;
                    self.checkpoint_repeat_pairing(checkpoint).await?;
                    continue;
                }
                RepeatPairingPhase::InitiatorCreatingConversation => {
                    let conversations = self.conversations.clone();
                    let conversation_id = checkpoint.state.new_conversation_id;
                    let routing_id = checkpoint
                        .state
                        .new_routing_id
                        .ok_or(PairingServiceError::InvalidTransition)?;
                    tokio::task::spawn_blocking(move || {
                        conversations.create_with_identifiers(conversation_id, routing_id)
                    })
                    .await
                    .map_err(|_| PairingServiceError::Task)??;
                    checkpoint.state.phase = RepeatPairingPhase::InitiatorPairing;
                    self.checkpoint_repeat_pairing(checkpoint).await?;
                    continue;
                }
                RepeatPairingPhase::InitiatorPairing => {
                    let pairing_id = checkpoint
                        .state
                        .pairing_id
                        .ok_or(PairingServiceError::InvalidTransition)?;
                    let pairing = self.status(pairing_id).await?;
                    if pairing.phase == PairingPhase::Completed {
                        checkpoint.state.phase = RepeatPairingPhase::Completed;
                        self.checkpoint_repeat_pairing(checkpoint).await?;
                        continue;
                    }
                    if pairing.phase == PairingPhase::InviterAwaitingAuthorization {
                        self.authorize_joiner(
                            pairing_id,
                            checkpoint.state.new_conversation_id,
                            ConversationRole::Member,
                            now_unix_seconds,
                        )
                        .await?;
                    } else {
                        self.replay_once(pairing_id, now_unix_seconds).await?;
                    }
                    return self.repeat_pairing_status(operation_id).await;
                }
                RepeatPairingPhase::ResponderIssuingCapability => {
                    let capability = self
                        .issue_capability(
                            ConversationRole::Member,
                            checkpoint.state.deadline_unix_seconds,
                            now_unix_seconds,
                        )
                        .await?;
                    checkpoint.state.capability = Some(zeroize::Zeroizing::new(
                        capability.encode()?.as_str().to_owned(),
                    ));
                    checkpoint.state.phase = RepeatPairingPhase::ResponderReservingPairing;
                    self.checkpoint_repeat_pairing(checkpoint).await?;
                    continue;
                }
                RepeatPairingPhase::ResponderReservingPairing => {
                    let capability = PairingCapability::decode(
                        checkpoint
                            .state
                            .capability
                            .as_ref()
                            .ok_or(PairingServiceError::InvalidTransition)?,
                        now_unix_seconds,
                    )?;
                    let pairing_id = capability.offer().pairing_id();
                    self.reserve_joiner_capability(capability).await?;
                    checkpoint.state.pairing_id = Some(pairing_id);
                    checkpoint.state.phase = RepeatPairingPhase::ResponderSendingResponse;
                    self.checkpoint_repeat_pairing(checkpoint).await?;
                    continue;
                }
                RepeatPairingPhase::ResponderSendingResponse => {
                    let response = RepeatPairingResponse::new(
                        operation_id,
                        checkpoint.state.peer_device_id,
                        checkpoint.state.new_conversation_id,
                        checkpoint
                            .state
                            .capability
                            .as_ref()
                            .ok_or(PairingServiceError::InvalidTransition)?
                            .as_str(),
                    )
                    .map_err(KonclaveProtocolError::from)?;
                    self.applications
                        .send(SendApplicationRequest {
                            conversation_id: checkpoint.state.bootstrap_conversation_id,
                            message_id: repeat_pairing_response_message_id(operation_id),
                            content: ApplicationContent::repeat_pairing_response(response),
                            reply_to: Some(repeat_pairing_request_message_id(operation_id)),
                            collaboration_action_authorization: None,
                            sent_at_unix_milliseconds: unix_milliseconds(now_unix_seconds)?,
                            now_unix_seconds,
                            expires_at_unix_seconds: checkpoint.state.deadline_unix_seconds,
                        })
                        .await?;
                    checkpoint.state.phase = RepeatPairingPhase::ResponderPairing;
                    self.checkpoint_repeat_pairing(checkpoint).await?;
                    continue;
                }
                RepeatPairingPhase::ResponderPairing => {
                    let pairing_id = checkpoint
                        .state
                        .pairing_id
                        .ok_or(PairingServiceError::InvalidTransition)?;
                    let pairing = self.status(pairing_id).await?;
                    if pairing.phase == PairingPhase::Completed {
                        checkpoint.state.phase = RepeatPairingPhase::Completed;
                        self.checkpoint_repeat_pairing(checkpoint).await?;
                        continue;
                    }
                    if pairing.phase == PairingPhase::JoinerAwaitingInviterAuthorization {
                        self.authorize_inviter(
                            pairing_id,
                            checkpoint.state.peer_device_id,
                            checkpoint.state.new_conversation_id,
                            ConversationRole::Member,
                            now_unix_seconds,
                        )
                        .await?;
                    } else {
                        self.replay_once(pairing_id, now_unix_seconds).await?;
                    }
                    return self.repeat_pairing_status(operation_id).await;
                }
                RepeatPairingPhase::Completed
                | RepeatPairingPhase::Cancelling
                | RepeatPairingPhase::Cancelled => {}
            }
        }
        Err(PairingServiceError::InvalidTransition)
    }

    pub(crate) async fn sync_active_repeat_pairings_once(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let _admitted = self
            .conversations
            .activity()
            .try_begin()
            .map_err(|_| PairingServiceError::ProfileClosing)?;
        let store = Arc::clone(&self.store);
        let operation_ids = tokio::task::spawn_blocking(move || {
            store.active_repeat_pairing_ids(None, ACTIVE_REPEAT_PAIRING_PAGE_SIZE)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        for operation_id in &operation_ids {
            self.sync_repeat_pairing(*operation_id, now_unix_seconds)
                .await?;
        }
        Ok(operation_ids.len())
    }

    /// Issues and durably reserves one joiner capability.
    ///
    /// The returned capability is the only value transferred to the inviter. It must
    /// not be logged, persisted outside the sealed checkpoint, or placed in telemetry.
    ///
    /// # Errors
    ///
    /// Returns a task, identity, capability, sealing, or persistence error.
    pub(crate) async fn create_capability(
        &self,
        requested_role: ConversationRole,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<CreatedPairing, PairingServiceError> {
        let capability = self
            .issue_capability(requested_role, expires_at_unix_seconds, now_unix_seconds)
            .await?;
        let capability_text = capability.encode()?;
        let pairing_id = self.reserve_joiner_capability(capability).await?;
        Ok(CreatedPairing {
            pairing_id,
            capability: capability_text,
        })
    }

    async fn issue_capability(
        &self,
        requested_role: ConversationRole,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<PairingCapability, PairingServiceError> {
        require_authorization_window(now_unix_seconds, expires_at_unix_seconds)?;
        let conversations = self.conversations.clone();
        let relay_endpoint = self.relay_endpoint.clone();
        tokio::task::spawn_blocking(move || {
            conversations.issue_pairing_capability(
                relay_endpoint,
                requested_role,
                expires_at_unix_seconds,
                now_unix_seconds,
            )
        })
        .await
        .map_err(|_| PairingServiceError::Task)?
        .map_err(Into::into)
    }

    async fn reserve_joiner_capability(
        &self,
        capability: PairingCapability,
    ) -> Result<PairingId, PairingServiceError> {
        let pairing_id = capability.offer().pairing_id();
        let state = PairingOperationState::new(PairingRole::Joiner, capability);
        self.reserve_state(&state).await?;
        Ok(pairing_id)
    }

    /// Redeems one transferred capability into an inviter-side authorization request.
    ///
    /// # Errors
    ///
    /// Returns an opaque capability, relay-mismatch, task, sealing, or persistence
    /// error without recording malformed bearer material.
    pub(crate) async fn redeem_capability(
        &self,
        capability_text: &str,
        now_unix_seconds: u64,
    ) -> Result<PairingStatus, PairingServiceError> {
        let capability = PairingCapability::decode(capability_text, now_unix_seconds)?;
        self.redeem_decoded_capability(capability, now_unix_seconds)
            .await
    }

    async fn redeem_decoded_capability(
        &self,
        capability: PairingCapability,
        now_unix_seconds: u64,
    ) -> Result<PairingStatus, PairingServiceError> {
        require_authorization_window(
            now_unix_seconds,
            capability.offer().expires_at_unix_seconds(),
        )?;
        if capability.relay_endpoint().as_str() != self.relay_endpoint.as_str() {
            return Err(PairingServiceError::RelayMismatch);
        }
        let pairing_id = capability.offer().pairing_id();
        let state = PairingOperationState::new(PairingRole::Inviter, capability);
        self.reserve_state(&state).await?;
        self.status(pairing_id).await
    }

    /// Creates and publishes a compact encrypted handoff for the existing pairing flow.
    ///
    /// A failed publication cancels the initial local reservation so capacity is not
    /// silently consumed by a token that was never returned.
    ///
    /// # Errors
    ///
    /// Returns a capability, cryptographic, relay, task, cleanup, or persistence error.
    pub(crate) async fn create_rendezvous(
        &self,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<CreatedPairingRendezvous, PairingServiceError>
    where
        T: PairingRendezvousTransport,
    {
        let capability = self
            .issue_capability(
                ConversationRole::Member,
                expires_at_unix_seconds,
                now_unix_seconds,
            )
            .await?;
        let (token, record) = create_pairing_rendezvous(&capability, now_unix_seconds)?;
        let pairing_id = self.reserve_joiner_capability(capability).await?;
        if let Err(error) = self.transport.publish_pairing_rendezvous(&record).await {
            if self.cancel(pairing_id, now_unix_seconds).await.is_err() {
                return Err(PairingServiceError::RendezvousCleanup);
            }
            return Err(error.into());
        }
        Ok(CreatedPairingRendezvous { pairing_id, token })
    }

    /// Redeems a compact token into the existing inviter-side capability flow.
    ///
    /// # Errors
    ///
    /// Returns one opaque token, relay, capability, relay-mismatch, task, sealing, or
    /// persistence error.
    pub(crate) async fn redeem_rendezvous(
        &self,
        token: &str,
        now_unix_seconds: u64,
    ) -> Result<PairingStatus, PairingServiceError>
    where
        T: PairingRendezvousTransport,
    {
        let request = pairing_rendezvous_take_request(token)?;
        let record = self.transport.take_pairing_rendezvous(request).await?;
        let capability = open_pairing_rendezvous(token, &record, now_unix_seconds)?;
        if capability.offer().requested_role() != ConversationRole::Member {
            return Err(PairingServiceError::InvalidRendezvousRole);
        }
        self.redeem_decoded_capability(capability, now_unix_seconds)
            .await
    }

    /// Returns authenticated non-secret state for one pairing.
    ///
    /// # Errors
    ///
    /// Returns a task, persistence, capability, or checkpoint-authentication error.
    pub(crate) async fn status(
        &self,
        pairing_id: PairingId,
    ) -> Result<PairingStatus, PairingServiceError> {
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        let state = PairingOperationState::from_checkpoint(&checkpoint)?;
        let authorized_invitation = match state.remote_record(PairingStage::Invitation)? {
            Some(record) => Some(v1::decode_pairing_invitation(record.plaintext())?),
            None => state
                .local_record(PairingStage::Invitation)?
                .map(|record| v1::decode_pairing_invitation(record.plaintext()))
                .transpose()?,
        };
        Ok(PairingStatus {
            pairing_id,
            role: checkpoint.role,
            phase: checkpoint.phase,
            joiner_device_id: state.capability().offer().device_id(),
            requested_role: state.capability().offer().requested_role(),
            inviter_device_id: authorized_invitation
                .as_ref()
                .map(|payload| payload.invitation().issuer_device_id()),
            granted_role: authorized_invitation
                .as_ref()
                .map(|payload| payload.invitation().role()),
            conversation_id: state.conversation_id(),
            authorization_deadline_unix_seconds: checkpoint.authorization_deadline_unix_seconds,
            completion_deadline_unix_seconds: checkpoint.completion_deadline_unix_seconds,
        })
    }

    /// Reconciles every bounded active pairing after daemon startup.
    ///
    /// Prepared outbounds retain their exact relay identity. Expired post-Commit
    /// operations enter durable compensation and do not become terminal until the
    /// ordinary MLS removal journal is relay-accepted.
    ///
    /// # Errors
    ///
    /// Returns the first task, checkpoint, relay, MLS, or persistence error.
    pub(crate) async fn recover(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let store = Arc::clone(&self.store);
        let page = tokio::task::spawn_blocking(move || {
            store.active_pairing_ids(None, ACTIVE_PAIRING_PAGE_SIZE)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        for pairing_id in &page {
            self.retry_outbounds(*pairing_id, now_unix_seconds).await?;
        }
        if page.len() == ACTIVE_PAIRING_PAGE_SIZE {
            let store = Arc::clone(&self.store);
            let current = tokio::task::spawn_blocking(move || {
                store.active_pairing_ids(None, ACTIVE_PAIRING_PAGE_SIZE)
            })
            .await
            .map_err(|_| PairingServiceError::Task)??;
            if current.len() == ACTIVE_PAIRING_PAGE_SIZE {
                let store = Arc::clone(&self.store);
                let after = current.last().copied();
                let overflow =
                    tokio::task::spawn_blocking(move || store.active_pairing_ids(after, 1))
                        .await
                        .map_err(|_| PairingServiceError::Task)??;
                if !overflow.is_empty() {
                    return Err(ProfileStoreError::PairingCapacityExceeded.into());
                }
            }
        }
        Ok(page.len())
    }

    /// Reconciles durable outbounds and processes one bounded page for every active
    /// pairing.
    ///
    /// # Errors
    ///
    /// Returns the first task, checkpoint, relay, MLS, or persistence error. Work
    /// completed for earlier pairings remains durable and idempotent.
    pub(crate) async fn sync_active_once(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        // A pairing sweep is one of the operations ADR 0008 retains a profile for.
        // Admission is refused once the profile is closing; every pairing record stays
        // durable, so the next sweep after reopening is exact rather than repeated.
        //
        // This is a top-level operation: the sweep drives pairing replay directly
        // through the transport and store, so nothing it reaches takes a second
        // admission while this one is held.
        let _admitted = self
            .conversations
            .activity()
            .try_begin()
            .map_err(|_| PairingServiceError::ProfileClosing)?;
        self.recover(now_unix_seconds).await?;
        let mut processed = 0_usize;
        let store = Arc::clone(&self.store);
        let page = tokio::task::spawn_blocking(move || {
            store.active_pairing_ids(None, ACTIVE_PAIRING_PAGE_SIZE)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        for pairing_id in page {
            processed = processed
                .checked_add(self.replay_once(pairing_id, now_unix_seconds).await?)
                .ok_or(PairingServiceError::InvalidTransition)?;
        }
        Ok(processed)
    }

    /// Authorizes the capability's joiner for one conversation and granted role.
    ///
    /// The exact encrypted invitation is checkpointed before relay submission.
    ///
    /// # Errors
    ///
    /// Returns an expiry, phase, conversation, protocol, cryptographic, relay, task,
    /// or persistence error.
    pub(crate) async fn authorize_joiner(
        &self,
        pairing_id: PairingId,
        conversation_id: ConversationId,
        granted_role: ConversationRole,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let _mutation = self.mutation_locks.acquire(pairing_id).await;
        let store = Arc::clone(&self.store);
        let short_code_binding =
            tokio::task::spawn_blocking(move || store.short_code_peer_binding(pairing_id))
                .await
                .map_err(|_| PairingServiceError::Task)??;
        let store = Arc::clone(&self.store);
        let repeat_pairing_binding =
            tokio::task::spawn_blocking(move || store.repeat_pairing_peer_binding(pairing_id))
                .await
                .map_err(|_| PairingServiceError::Task)??;
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if checkpoint.role != PairingRole::Inviter {
            return Err(PairingServiceError::InvalidTransition);
        }
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
        match short_code_binding {
            ShortCodePeerBinding::Unlinked => {}
            ShortCodePeerBinding::Verified(peer)
                if peer == state.capability().offer().device_id() => {}
            ShortCodePeerBinding::Verified(_) | ShortCodePeerBinding::Blocked => {
                return Err(PairingServiceError::AuthorizationMismatch);
            }
        }
        match repeat_pairing_binding {
            RepeatPairingPeerBinding::Unlinked => {}
            RepeatPairingPeerBinding::Verified {
                peer_device_id,
                conversation_id: expected_conversation_id,
            } if peer_device_id == state.capability().offer().device_id()
                && expected_conversation_id == conversation_id
                && granted_role == ConversationRole::Member => {}
            RepeatPairingPeerBinding::Verified { .. } | RepeatPairingPeerBinding::Blocked => {
                return Err(PairingServiceError::AuthorizationMismatch);
            }
        }
        if matches!(
            checkpoint.phase,
            PairingPhase::InviterAwaitingJoinProof
                | PairingPhase::InviterAwaitingCompletion
                | PairingPhase::Completed
        ) {
            require_local_invitation(&state, conversation_id, granted_role)?;
            if matches!(
                checkpoint.phase,
                PairingPhase::InviterAwaitingCompletion | PairingPhase::Completed
            ) {
                return Ok(());
            }
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        }
        require_phase(
            &checkpoint,
            PairingRole::Inviter,
            PairingPhase::InviterAwaitingAuthorization,
        )?;
        require_before(
            now_unix_seconds,
            checkpoint.authorization_deadline_unix_seconds,
        )?;
        state.set_conversation_id(conversation_id)?;
        let expected_device_id = state.capability().offer().device_id();
        let conversations = self.conversations.clone();
        let invitation = tokio::task::spawn_blocking(move || {
            conversations.issue_invitation(
                conversation_id,
                expected_device_id,
                granted_role,
                checkpoint.authorization_deadline_unix_seconds,
            )
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        let payload = PairingInvitationPayload::new(
            invitation.invitation,
            invitation.issuer_public_key,
            invitation.peer_bindings,
        )
        .map_err(KonclaveProtocolError::from)?;
        let encoded = v1::encode_pairing_invitation(&payload)?;
        state.prepare_outbound(
            PairingStage::Invitation,
            None,
            checkpoint.authorization_deadline_unix_seconds,
            &encoded,
        )?;
        self.checkpoint_state(
            &checkpoint,
            &state,
            PairingPhase::InviterAwaitingJoinProof,
            None,
            checkpoint.replay_cursor,
        )
        .await?;
        self.retry_outbounds_serialized(pairing_id, now_unix_seconds)
            .await
    }

    /// Authorizes the inviter identity, conversation, and granted role displayed to
    /// the operator, then prepares the exact JoinProof before relay submission.
    ///
    /// # Errors
    ///
    /// Returns an authorization mismatch, expiry, phase, invitation, protocol,
    /// cryptographic, task, relay, or persistence error.
    pub(crate) async fn authorize_inviter(
        &self,
        pairing_id: PairingId,
        expected_inviter_device_id: DeviceId,
        expected_conversation_id: ConversationId,
        expected_granted_role: ConversationRole,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let _mutation = self.mutation_locks.acquire(pairing_id).await;
        let store = Arc::clone(&self.store);
        let short_code_binding =
            tokio::task::spawn_blocking(move || store.short_code_peer_binding(pairing_id))
                .await
                .map_err(|_| PairingServiceError::Task)??;
        let store = Arc::clone(&self.store);
        let repeat_pairing_binding =
            tokio::task::spawn_blocking(move || store.repeat_pairing_peer_binding(pairing_id))
                .await
                .map_err(|_| PairingServiceError::Task)??;
        match short_code_binding {
            ShortCodePeerBinding::Unlinked => {}
            ShortCodePeerBinding::Verified(peer) if peer == expected_inviter_device_id => {}
            ShortCodePeerBinding::Verified(_) | ShortCodePeerBinding::Blocked => {
                return Err(PairingServiceError::AuthorizationMismatch);
            }
        }
        match repeat_pairing_binding {
            RepeatPairingPeerBinding::Unlinked => {}
            RepeatPairingPeerBinding::Verified {
                peer_device_id,
                conversation_id,
            } if peer_device_id == expected_inviter_device_id
                && conversation_id == expected_conversation_id
                && expected_granted_role == ConversationRole::Member => {}
            RepeatPairingPeerBinding::Verified { .. } | RepeatPairingPeerBinding::Blocked => {
                return Err(PairingServiceError::AuthorizationMismatch);
            }
        }
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if checkpoint.role != PairingRole::Joiner {
            return Err(PairingServiceError::InvalidTransition);
        }
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
        if matches!(
            checkpoint.phase,
            PairingPhase::JoinerAwaitingWelcome | PairingPhase::Completed
        ) {
            require_remote_invitation(
                &state,
                expected_inviter_device_id,
                expected_conversation_id,
                expected_granted_role,
            )?;
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        }
        require_phase(
            &checkpoint,
            PairingRole::Joiner,
            PairingPhase::JoinerAwaitingInviterAuthorization,
        )?;
        require_before(
            now_unix_seconds,
            checkpoint.authorization_deadline_unix_seconds,
        )?;
        let invitation_record = state
            .remote_record(PairingStage::Invitation)?
            .ok_or(PairingServiceError::InvalidTransition)?;
        let payload = v1::decode_pairing_invitation(invitation_record.plaintext())?;
        self.verify_invitation_payload(&state, &payload, now_unix_seconds)
            .await?;
        if payload.invitation().issuer_device_id() != expected_inviter_device_id
            || payload.invitation().conversation_id() != expected_conversation_id
            || payload.invitation().role() != expected_granted_role
            || state.conversation_id() != Some(expected_conversation_id)
        {
            return Err(PairingServiceError::AuthorizationMismatch);
        }
        let invitation = v1::decode_invitation(&v1::encode_invitation(payload.invitation())?)?;
        let routing_id = payload
            .invitation()
            .routing_id()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let issuer_public_key = payload.issuer_public_key();
        let peer_bindings = payload.peer_bindings().to_vec();
        let conversations = self.conversations.clone();
        let proof = tokio::task::spawn_blocking(move || {
            conversations.create_join_proof(
                invitation,
                routing_id,
                issuer_public_key,
                peer_bindings,
                now_unix_seconds,
            )
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        let encoded = v1::encode_join_proof(&proof)?;
        state.prepare_outbound(
            PairingStage::JoinProof,
            Some(invitation_record.envelope().message_id()),
            checkpoint.authorization_deadline_unix_seconds,
            &encoded,
        )?;
        self.checkpoint_state(
            &checkpoint,
            &state,
            PairingPhase::JoinerAwaitingWelcome,
            None,
            checkpoint.replay_cursor,
        )
        .await?;
        self.retry_outbounds_serialized(pairing_id, now_unix_seconds)
            .await
    }

    /// Cancels one active pairing without pretending an accepted add-Commit vanished.
    ///
    /// Pre-Commit cancellation is root-signed and submitted when an authenticated
    /// peer identity and reply target are known. Post-Commit inviter cancellation
    /// enters durable MLS compensation immediately and becomes terminal only after
    /// removal is relay-accepted.
    ///
    /// # Errors
    ///
    /// Returns a phase, deadline, signing, protocol, relay, task, MLS, or persistence
    /// error. Repeating the same cancellation resumes its exact durable work.
    pub(crate) async fn cancel(
        &self,
        pairing_id: PairingId,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let _mutation = self.mutation_locks.acquire(pairing_id).await;
        if self
            .compensate_if_required(pairing_id, now_unix_seconds, true)
            .await?
        {
            return Ok(());
        }
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if checkpoint.phase == PairingPhase::Cancelled {
            self.cleanup_terminal_join(&checkpoint).await?;
            return Ok(());
        }
        if checkpoint.phase == PairingPhase::Completed {
            return Err(PairingServiceError::InvalidTransition);
        }
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
        if checkpoint.role == PairingRole::Joiner
            && checkpoint.phase == PairingPhase::JoinerAwaitingWelcome
            && state.local_record(PairingStage::Completion)?.is_some()
        {
            return Err(PairingServiceError::InvalidTransition);
        }
        if checkpoint.role == PairingRole::Inviter
            && checkpoint.phase == PairingPhase::InviterAwaitingCompletion
        {
            self.checkpoint_state(
                &checkpoint,
                &state,
                PairingPhase::Compensating,
                checkpoint.completion_deadline_unix_seconds,
                checkpoint.replay_cursor,
            )
            .await?;
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        }
        if checkpoint.phase == PairingPhase::Compensating {
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        }
        if state.local_record(PairingStage::Cancellation)?.is_some() {
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        }
        let Some(conversation_id) = state.conversation_id() else {
            self.checkpoint_state(
                &checkpoint,
                &state,
                PairingPhase::Cancelled,
                None,
                checkpoint.replay_cursor,
            )
            .await?;
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        };
        let Some(in_reply_to) =
            local_cancellation_reply(&state, checkpoint.role, checkpoint.phase)?
        else {
            self.checkpoint_state(
                &checkpoint,
                &state,
                PairingPhase::Cancelled,
                None,
                checkpoint.replay_cursor,
            )
            .await?;
            return self
                .retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await;
        };
        let expires_at_unix_seconds = cancellation_deadline_for_reply(&state, in_reply_to)?;
        require_before(now_unix_seconds, expires_at_unix_seconds)?;
        let message_id = generate_pairing_message_id()?;
        let conversations = self.conversations.clone();
        let control = tokio::task::spawn_blocking(move || {
            conversations.sign_pairing_control(
                pairing_id,
                message_id,
                PairingStage::Cancellation,
                in_reply_to,
                conversation_id,
            )
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        state.prepare_outbound_with_id(
            message_id,
            PairingStage::Cancellation,
            Some(in_reply_to),
            expires_at_unix_seconds,
            &v1::encode_pairing_control(&control)?,
        )?;
        self.checkpoint_state(
            &checkpoint,
            &state,
            checkpoint.phase,
            checkpoint.completion_deadline_unix_seconds,
            checkpoint.replay_cursor,
        )
        .await?;
        self.retry_outbounds_serialized(pairing_id, now_unix_seconds)
            .await
    }

    /// Replays and durably processes one bounded pairing page.
    ///
    /// Relay acknowledgment advances only after each returned record's state and any
    /// resulting MLS side effect are durable.
    ///
    /// # Errors
    ///
    /// Returns a request, relay, response-integrity, phase, cryptographic, protocol,
    /// MLS, task, or persistence error.
    pub(crate) async fn replay_once(
        &self,
        pairing_id: PairingId,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let _mutation = self.mutation_locks.acquire(pairing_id).await;
        if self
            .compensate_if_required(pairing_id, now_unix_seconds, false)
            .await?
        {
            return Ok(0);
        }
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if checkpoint.phase.is_terminal() {
            self.cleanup_terminal_join(&checkpoint).await?;
            return Ok(0);
        }
        let request = ReplayRequest::new(
            checkpoint.routing_id,
            checkpoint.replay_cursor,
            PAIRING_REPLAY_LIMIT,
        )
        .map_err(|_| PairingServiceError::InvalidRelayResponse)?;
        let page = self.transport.replay(request).await?;
        validate_replay_page(checkpoint.replay_cursor, &page)
            .map_err(|_| PairingServiceError::InvalidRelayResponse)?;
        let has_more = page.has_more();
        let envelopes = page.envelopes().to_vec();
        for stored in &envelopes {
            self.process_stored(pairing_id, stored, now_unix_seconds)
                .await?;
            let acknowledgment = AcknowledgeRequest::new(checkpoint.routing_id, stored.cursor())
                .map_err(|_| PairingServiceError::InvalidRelayResponse)?;
            let effective = self.transport.acknowledge(acknowledgment).await?;
            validate_acknowledgment(acknowledgment, effective)
                .map_err(|_| PairingServiceError::InvalidRelayResponse)?;
            self.retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await?;
        }
        if !has_more {
            self.resume_inviter_commit_if_required(pairing_id, now_unix_seconds, true)
                .await?;
            self.retry_outbounds_serialized(pairing_id, now_unix_seconds)
                .await?;
        }
        Ok(envelopes.len())
    }

    /// Submits every prepared unaccepted pairing envelope with its original identity.
    ///
    /// # Errors
    ///
    /// Returns an expiry, relay, response-integrity, protocol, task, or persistence
    /// error. A failure leaves the exact envelope ready for retry.
    pub(crate) async fn retry_outbounds(
        &self,
        pairing_id: PairingId,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let _mutation = self.mutation_locks.acquire(pairing_id).await;
        self.retry_outbounds_serialized(pairing_id, now_unix_seconds)
            .await
    }

    async fn retry_outbounds_serialized(
        &self,
        pairing_id: PairingId,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        loop {
            if self
                .compensate_if_required(pairing_id, now_unix_seconds, false)
                .await?
            {
                return Ok(());
            }
            let checkpoint = self.load_checkpoint(pairing_id).await?;
            if checkpoint.phase.is_terminal() {
                self.cleanup_terminal_join(&checkpoint).await?;
                return Ok(());
            }
            let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
            let cancellation = state
                .outbounds()
                .iter()
                .filter(|outbound| outbound.accepted_cursor().is_none())
                .find(|outbound| {
                    outbound
                        .pairing_envelope()
                        .is_ok_and(|envelope| envelope.stage() == PairingStage::Cancellation)
                });
            let cancellation_prerequisite = cancellation
                .and_then(|outbound| outbound.pairing_envelope().ok())
                .and_then(|envelope| envelope.in_reply_to())
                .and_then(|in_reply_to| {
                    state.outbounds().iter().find(|outbound| {
                        outbound.accepted_cursor().is_none()
                            && outbound
                                .pairing_envelope()
                                .is_ok_and(|envelope| envelope.message_id() == in_reply_to)
                    })
                });
            let pending = cancellation_prerequisite
                .or(cancellation)
                .or_else(|| {
                    state
                        .outbounds()
                        .iter()
                        .find(|outbound| outbound.accepted_cursor().is_none())
                })
                .map(|outbound| {
                    Ok::<_, PairingStateError>((
                        outbound.pairing_envelope()?.message_id(),
                        outbound.envelope().clone(),
                    ))
                })
                .transpose()?;
            let Some((message_id, envelope)) = pending else {
                return Ok(());
            };
            require_before(now_unix_seconds, envelope.expires_at_unix_seconds())?;
            let stored = self.transport.submit(&envelope).await?;
            if stored.envelope() != &envelope {
                return Err(PairingServiceError::InvalidRelayResponse);
            }
            state.mark_outbound_accepted(message_id, stored.cursor())?;
            let next_phase = terminal_after_submission(&checkpoint, &state)?;
            self.checkpoint_state(
                &checkpoint,
                &state,
                next_phase,
                checkpoint.completion_deadline_unix_seconds,
                checkpoint.replay_cursor,
            )
            .await?;
        }
    }

    async fn process_stored(
        &self,
        pairing_id: PairingId,
        stored: &StoredRelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if stored.cursor() <= checkpoint.replay_cursor {
            return Ok(());
        }
        if checkpoint.replay_cursor.checked_add(1) != Some(stored.cursor()) {
            return Err(PairingServiceError::InvalidRelayResponse);
        }
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
        let pairing = v1::decode_pairing_envelope(stored.envelope().payload())?;
        require_before(now_unix_seconds, pairing.expires_at_unix_seconds())?;
        let observed = state.observe(stored)?;
        match observed {
            PairingObservationResult::LocalEcho => {
                let next_phase = terminal_after_submission(&checkpoint, &state)?;
                self.checkpoint_state(
                    &checkpoint,
                    &state,
                    next_phase,
                    checkpoint.completion_deadline_unix_seconds,
                    stored.cursor(),
                )
                .await
            }
            PairingObservationResult::Duplicate(_) => {
                self.checkpoint_state(
                    &checkpoint,
                    &state,
                    checkpoint.phase,
                    checkpoint.completion_deadline_unix_seconds,
                    stored.cursor(),
                )
                .await
            }
            PairingObservationResult::Added(plaintext) => {
                if checkpoint.role == PairingRole::Inviter
                    && checkpoint.phase == PairingPhase::InviterAwaitingJoinProof
                    && pairing.stage() == PairingStage::JoinProof
                {
                    return self
                        .begin_inviter_commit(
                            &checkpoint,
                            &mut state,
                            &pairing,
                            &plaintext,
                            stored.cursor(),
                            now_unix_seconds,
                        )
                        .await;
                }
                let (next_phase, completion_deadline) = self
                    .process_remote_stage(
                        &checkpoint,
                        &mut state,
                        &pairing,
                        &plaintext,
                        now_unix_seconds,
                    )
                    .await?;
                self.checkpoint_state(
                    &checkpoint,
                    &state,
                    next_phase,
                    completion_deadline,
                    stored.cursor(),
                )
                .await
            }
        }
    }

    async fn begin_inviter_commit(
        &self,
        checkpoint: &PairingCheckpoint,
        state: &mut PairingOperationState,
        pairing: &PairingEnvelope,
        plaintext: &[u8],
        replay_cursor: u64,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        self.checkpoint_inviter_commit(
            checkpoint,
            state,
            pairing,
            plaintext,
            replay_cursor,
            now_unix_seconds,
        )
        .await?;
        Ok(())
    }

    async fn checkpoint_inviter_commit(
        &self,
        checkpoint: &PairingCheckpoint,
        state: &PairingOperationState,
        pairing: &PairingEnvelope,
        plaintext: &[u8],
        replay_cursor: u64,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        require_authorization_record(checkpoint, pairing)?;
        validate_join_proof(state, pairing, plaintext)?;
        let completion_deadline = completion_deadline(
            checkpoint.authorization_deadline_unix_seconds,
            now_unix_seconds,
        )?;
        self.checkpoint_state(
            checkpoint,
            state,
            PairingPhase::InviterAwaitingCompletion,
            Some(completion_deadline),
            replay_cursor,
        )
        .await?;
        Ok(())
    }

    async fn resume_inviter_commit_if_required(
        &self,
        pairing_id: PairingId,
        now_unix_seconds: u64,
        create_if_missing: bool,
    ) -> Result<bool, PairingServiceError> {
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if checkpoint.role != PairingRole::Inviter
            || !matches!(
                checkpoint.phase,
                PairingPhase::InviterAwaitingCompletion | PairingPhase::Compensating
            )
        {
            return Ok(true);
        }
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
        if state.local_record(PairingStage::Welcome)?.is_some() {
            return Ok(true);
        }
        let join_proof = state
            .remote_record(PairingStage::JoinProof)?
            .ok_or(PairingServiceError::InvalidTransition)?;
        let join_proof_message_id = join_proof.envelope().message_id();
        let proof = validate_join_proof(&state, join_proof.envelope(), join_proof.plaintext())?;
        let conversation_id = state
            .conversation_id()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let sent = match self
            .applications
            .resume_add_member(conversation_id, &proof, now_unix_seconds)
            .await?
        {
            Some(sent) => sent,
            None if create_if_missing => {
                self.applications
                    .add_member(
                        conversation_id,
                        proof,
                        now_unix_seconds,
                        checkpoint.authorization_deadline_unix_seconds,
                    )
                    .await?
            }
            None => return Ok(false),
        };
        let welcome = sent.welcome.ok_or(PairingServiceError::InvalidTransition)?;
        let payload = PairingWelcomePayload::new(conversation_id, welcome, sent.cursor)
            .map_err(KonclaveProtocolError::from)?;
        state.prepare_outbound(
            PairingStage::Welcome,
            Some(join_proof_message_id),
            checkpoint
                .completion_deadline_unix_seconds
                .ok_or(PairingServiceError::InvalidTransition)?,
            &v1::encode_pairing_welcome(&payload)?,
        )?;
        self.checkpoint_state(
            &checkpoint,
            &state,
            checkpoint.phase,
            checkpoint.completion_deadline_unix_seconds,
            checkpoint.replay_cursor,
        )
        .await?;
        Ok(true)
    }

    async fn process_remote_stage(
        &self,
        checkpoint: &PairingCheckpoint,
        state: &mut PairingOperationState,
        pairing: &PairingEnvelope,
        plaintext: &[u8],
        now_unix_seconds: u64,
    ) -> Result<(PairingPhase, Option<u64>), PairingServiceError> {
        if pairing.stage() == PairingStage::Cancellation {
            return self.process_remote_cancellation(checkpoint, state, pairing, plaintext);
        }
        match (checkpoint.role, checkpoint.phase, pairing.stage()) {
            (
                PairingRole::Joiner,
                PairingPhase::JoinerAwaitingInvitation,
                PairingStage::Invitation,
            ) => {
                require_authorization_record(checkpoint, pairing)?;
                let payload = v1::decode_pairing_invitation(plaintext)?;
                self.verify_invitation_payload(state, &payload, now_unix_seconds)
                    .await?;
                state.set_conversation_id(payload.invitation().conversation_id())?;
                Ok((PairingPhase::JoinerAwaitingInviterAuthorization, None))
            }
            (PairingRole::Joiner, PairingPhase::JoinerAwaitingWelcome, PairingStage::Welcome) => {
                let join_proof = state
                    .local_record(PairingStage::JoinProof)?
                    .ok_or(PairingServiceError::InvalidTransition)?;
                if pairing.in_reply_to() != Some(join_proof.envelope().message_id()) {
                    return Err(PairingServiceError::InvalidTransition);
                }
                let welcome = v1::decode_pairing_welcome(plaintext)?;
                if Some(welcome.conversation_id()) != state.conversation_id() {
                    return Err(PairingServiceError::AuthorizationMismatch);
                }
                self.applications
                    .accept_pairing_welcome(
                        welcome.conversation_id(),
                        MlsWelcome::from_bytes(welcome.welcome())?,
                        welcome.commit_cursor(),
                    )
                    .await?;
                let message_id = generate_pairing_message_id()?;
                let conversations = self.conversations.clone();
                let conversation_id = welcome.conversation_id();
                let in_reply_to = pairing.message_id();
                let pairing_id = pairing.pairing_id();
                let control = tokio::task::spawn_blocking(move || {
                    conversations.sign_pairing_control(
                        pairing_id,
                        message_id,
                        PairingStage::Completion,
                        in_reply_to,
                        conversation_id,
                    )
                })
                .await
                .map_err(|_| PairingServiceError::Task)??;
                state.prepare_outbound_with_id(
                    message_id,
                    PairingStage::Completion,
                    Some(pairing.message_id()),
                    pairing.expires_at_unix_seconds(),
                    &v1::encode_pairing_control(&control)?,
                )?;
                Ok((PairingPhase::JoinerAwaitingWelcome, None))
            }
            (
                PairingRole::Inviter,
                PairingPhase::InviterAwaitingCompletion,
                PairingStage::Completion,
            ) => {
                if pairing.expires_at_unix_seconds()
                    != checkpoint
                        .completion_deadline_unix_seconds
                        .ok_or(PairingServiceError::InvalidTransition)?
                {
                    return Err(PairingServiceError::InvalidTransition);
                }
                let welcome = state
                    .local_record(PairingStage::Welcome)?
                    .ok_or(PairingServiceError::InvalidTransition)?;
                if pairing.in_reply_to() != Some(welcome.envelope().message_id()) {
                    return Err(PairingServiceError::InvalidTransition);
                }
                let control = v1::decode_pairing_control(plaintext)?;
                let conversation_id = state
                    .conversation_id()
                    .ok_or(PairingServiceError::InvalidTransition)?;
                require_matching_control(pairing, &control, conversation_id)?;
                verify_pairing_control(
                    &control,
                    state.capability().offer().device_root_public_key(),
                )?;
                Ok((
                    PairingPhase::Completed,
                    checkpoint.completion_deadline_unix_seconds,
                ))
            }
            _ => Err(PairingServiceError::InvalidTransition),
        }
    }

    fn process_remote_cancellation(
        &self,
        checkpoint: &PairingCheckpoint,
        state: &PairingOperationState,
        pairing: &PairingEnvelope,
        plaintext: &[u8],
    ) -> Result<(PairingPhase, Option<u64>), PairingServiceError> {
        let conversation_id = state
            .conversation_id()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let reply = pairing
            .in_reply_to()
            .ok_or(PairingServiceError::InvalidTransition)?;
        if pairing.expires_at_unix_seconds() != cancellation_deadline_for_reply(state, reply)? {
            return Err(PairingServiceError::InvalidTransition);
        }
        let control = v1::decode_pairing_control(plaintext)?;
        require_matching_control(pairing, &control, conversation_id)?;
        let peer_public_key = match checkpoint.role {
            PairingRole::Inviter => state.capability().offer().device_root_public_key(),
            PairingRole::Joiner => {
                let invitation = state
                    .remote_record(PairingStage::Invitation)?
                    .ok_or(PairingServiceError::InvalidTransition)?;
                v1::decode_pairing_invitation(invitation.plaintext())?.issuer_public_key()
            }
        };
        verify_pairing_control(&control, peer_public_key)?;
        if checkpoint.role == PairingRole::Inviter
            && checkpoint.phase == PairingPhase::InviterAwaitingCompletion
        {
            Ok((
                PairingPhase::Compensating,
                checkpoint.completion_deadline_unix_seconds,
            ))
        } else if is_cancellable_precommit_phase(checkpoint.phase)
            || checkpoint.phase == PairingPhase::JoinerAwaitingWelcome
        {
            Ok((
                PairingPhase::Cancelled,
                checkpoint.completion_deadline_unix_seconds,
            ))
        } else {
            Err(PairingServiceError::InvalidTransition)
        }
    }

    async fn verify_invitation_payload(
        &self,
        state: &PairingOperationState,
        payload: &PairingInvitationPayload,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let offer = state.capability().offer();
        let local_device_id = {
            let conversations = self.conversations.clone();
            tokio::task::spawn_blocking(move || conversations.device_id())
                .await
                .map_err(|_| PairingServiceError::Task)??
        };
        if local_device_id != offer.device_id()
            || payload.invitation().expected_device_id() != offer.device_id()
            || payload.invitation().expires_at_unix_seconds() != offer.expires_at_unix_seconds()
        {
            return Err(PairingServiceError::AuthorizationMismatch);
        }
        for binding in payload.peer_bindings() {
            verify_device_credential_binding(binding)?;
        }
        let issuer = payload
            .peer_bindings()
            .iter()
            .find(|binding| {
                binding.device_id() == payload.invitation().issuer_device_id()
                    && binding.device_root_public_key() == payload.issuer_public_key()
            })
            .ok_or(PairingServiceError::AuthorizationMismatch)?;
        verify_invitation(
            payload.invitation(),
            issuer.device_root_public_key(),
            now_unix_seconds,
        )?;
        Ok(())
    }

    async fn reserve_state(
        &self,
        state: &PairingOperationState,
    ) -> Result<(), PairingServiceError> {
        let encoded = state.encode()?;
        let pairing_id = state.capability().offer().pairing_id();
        let routing_id = state.capability().key_schedule()?.routing_id();
        let role = state.role();
        let deadline = state.capability().offer().expires_at_unix_seconds();
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            store.reserve_pairing(pairing_id, routing_id, role, deadline, &encoded)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        Ok(())
    }

    async fn load_repeat_pairing(
        &self,
        operation_id: RepeatPairingOperationId,
    ) -> Result<RepeatPairingCheckpoint, PairingServiceError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.load_repeat_pairing(operation_id))
            .await
            .map_err(|_| PairingServiceError::Task)?
            .map_err(Into::into)
    }

    async fn checkpoint_repeat_pairing(
        &self,
        checkpoint: RepeatPairingCheckpoint,
    ) -> Result<(), PairingServiceError> {
        let store = Arc::clone(&self.store);
        let operation_id = checkpoint.state.operation_id;
        let generation = checkpoint.generation;
        tokio::task::spawn_blocking(move || {
            store.checkpoint_repeat_pairing(operation_id, generation, &checkpoint.state)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        Ok(())
    }

    async fn load_checkpoint(
        &self,
        pairing_id: PairingId,
    ) -> Result<PairingCheckpoint, PairingServiceError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.load_pairing(pairing_id))
            .await
            .map_err(|_| PairingServiceError::Task)?
            .map_err(Into::into)
    }

    async fn checkpoint_state(
        &self,
        checkpoint: &PairingCheckpoint,
        state: &PairingOperationState,
        next_phase: PairingPhase,
        completion_deadline_unix_seconds: Option<u64>,
        replay_cursor: u64,
    ) -> Result<(), PairingServiceError> {
        let encoded = state.encode()?;
        let store = Arc::clone(&self.store);
        let pairing_id = checkpoint.pairing_id;
        let generation = checkpoint.generation;
        tokio::task::spawn_blocking(move || {
            store.checkpoint_pairing(
                pairing_id,
                generation,
                next_phase,
                completion_deadline_unix_seconds,
                replay_cursor,
                &encoded,
            )
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        Ok(())
    }

    async fn cleanup_terminal_join(
        &self,
        checkpoint: &PairingCheckpoint,
    ) -> Result<(), PairingServiceError> {
        if checkpoint.role != PairingRole::Joiner || !checkpoint.phase.is_terminal() {
            return Ok(());
        }
        let state = PairingOperationState::from_checkpoint(checkpoint)?;
        let Some(conversation_id) = state.conversation_id() else {
            return if checkpoint.phase == PairingPhase::Cancelled {
                Ok(())
            } else {
                Err(PairingServiceError::InvalidTransition)
            };
        };
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.complete_pairing_join(conversation_id))
            .await
            .map_err(|_| PairingServiceError::Task)??;
        Ok(())
    }

    async fn compensate_if_required(
        &self,
        pairing_id: PairingId,
        now_unix_seconds: u64,
        cancellation_requested: bool,
    ) -> Result<bool, PairingServiceError> {
        let mut checkpoint = self.load_checkpoint(pairing_id).await?;
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
        if checkpoint.role == PairingRole::Inviter
            && matches!(
                checkpoint.phase,
                PairingPhase::InviterAwaitingCompletion | PairingPhase::Compensating
            )
            && state.local_record(PairingStage::Welcome)?.is_none()
        {
            let deadline = checkpoint
                .completion_deadline_unix_seconds
                .ok_or(PairingServiceError::InvalidTransition)?;
            let must_cancel = cancellation_requested
                || now_unix_seconds >= deadline
                || checkpoint.phase == PairingPhase::Compensating;
            if must_cancel && checkpoint.phase == PairingPhase::InviterAwaitingCompletion {
                self.checkpoint_state(
                    &checkpoint,
                    &state,
                    PairingPhase::Compensating,
                    Some(deadline),
                    checkpoint.replay_cursor,
                )
                .await?;
                checkpoint = self.load_checkpoint(pairing_id).await?;
                state = PairingOperationState::from_checkpoint(&checkpoint)?;
            }
            if !self
                .resume_inviter_commit_if_required(pairing_id, now_unix_seconds, false)
                .await?
            {
                if !must_cancel {
                    return Ok(false);
                }
                self.checkpoint_state(
                    &checkpoint,
                    &state,
                    PairingPhase::Cancelled,
                    Some(deadline),
                    checkpoint.replay_cursor,
                )
                .await?;
                return Ok(true);
            }
            checkpoint = self.load_checkpoint(pairing_id).await?;
            state = PairingOperationState::from_checkpoint(&checkpoint)?;
        }
        let joiner_completion_deadline = if checkpoint.phase == PairingPhase::JoinerAwaitingWelcome
        {
            state
                .local_record(PairingStage::Completion)?
                .map(|record| record.envelope().expires_at_unix_seconds())
        } else {
            None
        };
        let should_cancel = joiner_completion_deadline.map_or_else(
            || {
                now_unix_seconds >= checkpoint.authorization_deadline_unix_seconds
                    && (is_precommit_phase(checkpoint.phase)
                        || checkpoint.phase == PairingPhase::JoinerAwaitingWelcome)
            },
            |deadline| now_unix_seconds >= deadline,
        );
        if should_cancel {
            self.checkpoint_state(
                &checkpoint,
                &state,
                PairingPhase::Cancelled,
                None,
                checkpoint.replay_cursor,
            )
            .await?;
            checkpoint = self.load_checkpoint(pairing_id).await?;
            self.cleanup_terminal_join(&checkpoint).await?;
            return Ok(true);
        }
        if checkpoint.role != PairingRole::Inviter {
            return Ok(false);
        }
        if checkpoint.phase == PairingPhase::InviterAwaitingCompletion {
            let deadline = checkpoint
                .completion_deadline_unix_seconds
                .ok_or(PairingServiceError::InvalidTransition)?;
            if !cancellation_requested && now_unix_seconds < deadline {
                return Ok(false);
            }
            self.checkpoint_state(
                &checkpoint,
                &state,
                PairingPhase::Compensating,
                Some(deadline),
                checkpoint.replay_cursor,
            )
            .await?;
            checkpoint = self.load_checkpoint(pairing_id).await?;
        }
        if checkpoint.phase != PairingPhase::Compensating {
            return Ok(false);
        }
        let state = PairingOperationState::from_checkpoint(&checkpoint)?;
        let conversation_id = state
            .conversation_id()
            .ok_or(PairingServiceError::InvalidTransition)?;
        self.applications
            .remove_member(
                conversation_id,
                state.capability().offer().device_id(),
                now_unix_seconds,
                COMPENSATION_ENVELOPE_EXPIRY,
            )
            .await?;
        self.checkpoint_state(
            &checkpoint,
            &state,
            PairingPhase::Cancelled,
            checkpoint.completion_deadline_unix_seconds,
            checkpoint.replay_cursor,
        )
        .await?;
        Ok(true)
    }
}

fn require_phase(
    checkpoint: &PairingCheckpoint,
    role: PairingRole,
    phase: PairingPhase,
) -> Result<(), PairingServiceError> {
    if checkpoint.role == role && checkpoint.phase == phase {
        Ok(())
    } else {
        Err(PairingServiceError::InvalidTransition)
    }
}

fn require_before(now: u64, deadline: u64) -> Result<(), PairingServiceError> {
    if now < deadline {
        Ok(())
    } else {
        Err(PairingServiceError::Expired)
    }
}

fn completion_deadline(
    authorization_deadline: u64,
    commit_started_at: u64,
) -> Result<u64, PairingServiceError> {
    let recovery_deadline = commit_started_at
        .checked_add(COMPLETION_WINDOW_SECONDS)
        .ok_or(PairingServiceError::InvalidTransition)?;
    Ok(recovery_deadline.max(authorization_deadline))
}

fn require_authorization_window(now: u64, deadline: u64) -> Result<(), PairingServiceError> {
    let lifetime = deadline
        .checked_sub(now)
        .ok_or(PairingServiceError::Expired)?;
    if lifetime == 0 || lifetime > MAX_AUTHORIZATION_WINDOW_SECONDS {
        Err(PairingServiceError::InvalidAuthorizationWindow)
    } else {
        Ok(())
    }
}

fn validate_join_proof(
    state: &PairingOperationState,
    pairing: &PairingEnvelope,
    plaintext: &[u8],
) -> Result<JoinProof, PairingServiceError> {
    let invitation = state
        .local_record(PairingStage::Invitation)?
        .ok_or(PairingServiceError::InvalidTransition)?;
    if pairing.in_reply_to() != Some(invitation.envelope().message_id()) {
        return Err(PairingServiceError::InvalidTransition);
    }
    let invitation_payload = v1::decode_pairing_invitation(invitation.plaintext())?;
    let proof = v1::decode_join_proof(plaintext)?;
    if v1::encode_invitation(proof.invitation())?
        != v1::encode_invitation(invitation_payload.invitation())?
        || proof.credential().device_id() != state.capability().offer().device_id()
        || proof.credential().device_root_public_key()
            != state.capability().offer().device_root_public_key()
        || Some(proof.invitation().conversation_id()) != state.conversation_id()
    {
        return Err(PairingServiceError::AuthorizationMismatch);
    }
    verify_device_credential_binding(proof.credential())?;
    Ok(proof)
}

fn require_authorization_record(
    checkpoint: &PairingCheckpoint,
    pairing: &PairingEnvelope,
) -> Result<(), PairingServiceError> {
    if pairing.expires_at_unix_seconds() == checkpoint.authorization_deadline_unix_seconds {
        Ok(())
    } else {
        Err(PairingServiceError::InvalidTransition)
    }
}

fn require_matching_control(
    pairing: &PairingEnvelope,
    control: &KonclaveDomainCore::PairingControl,
    conversation_id: ConversationId,
) -> Result<(), PairingServiceError> {
    if control.pairing_id() == pairing.pairing_id()
        && control.message_id() == pairing.message_id()
        && control.stage() == pairing.stage()
        && Some(control.in_reply_to()) == pairing.in_reply_to()
        && control.conversation_id() == conversation_id
    {
        Ok(())
    } else {
        Err(PairingServiceError::AuthorizationMismatch)
    }
}

fn require_local_invitation(
    state: &PairingOperationState,
    conversation_id: ConversationId,
    granted_role: ConversationRole,
) -> Result<(), PairingServiceError> {
    let record = state
        .local_record(PairingStage::Invitation)?
        .ok_or(PairingServiceError::InvalidTransition)?;
    let payload = v1::decode_pairing_invitation(record.plaintext())?;
    if payload.invitation().conversation_id() == conversation_id
        && payload.invitation().role() == granted_role
        && payload.invitation().expected_device_id() == state.capability().offer().device_id()
        && state.conversation_id() == Some(conversation_id)
    {
        Ok(())
    } else {
        Err(PairingServiceError::AuthorizationMismatch)
    }
}

fn require_remote_invitation(
    state: &PairingOperationState,
    inviter_device_id: DeviceId,
    conversation_id: ConversationId,
    granted_role: ConversationRole,
) -> Result<(), PairingServiceError> {
    let record = state
        .remote_record(PairingStage::Invitation)?
        .ok_or(PairingServiceError::InvalidTransition)?;
    let payload = v1::decode_pairing_invitation(record.plaintext())?;
    if payload.invitation().issuer_device_id() == inviter_device_id
        && payload.invitation().conversation_id() == conversation_id
        && payload.invitation().role() == granted_role
        && state.conversation_id() == Some(conversation_id)
    {
        Ok(())
    } else {
        Err(PairingServiceError::AuthorizationMismatch)
    }
}

fn local_cancellation_reply(
    state: &PairingOperationState,
    role: PairingRole,
    phase: PairingPhase,
) -> Result<Option<PairingMessageId>, PairingServiceError> {
    let record = match (role, phase) {
        (PairingRole::Joiner, PairingPhase::JoinerAwaitingInviterAuthorization) => {
            state.remote_record(PairingStage::Invitation)?
        }
        (PairingRole::Joiner, PairingPhase::JoinerAwaitingWelcome) => {
            match state.remote_record(PairingStage::Welcome)? {
                Some(welcome) => Some(welcome),
                None => state.local_record(PairingStage::JoinProof)?,
            }
        }
        (PairingRole::Inviter, PairingPhase::InviterAwaitingJoinProof) => {
            state.local_record(PairingStage::Invitation)?
        }
        (PairingRole::Inviter, PairingPhase::InviterAwaitingCompletion) => {
            state.local_record(PairingStage::Welcome)?
        }
        _ => None,
    };
    Ok(record.map(|record| record.envelope().message_id()))
}

fn cancellation_deadline_for_reply(
    state: &PairingOperationState,
    in_reply_to: PairingMessageId,
) -> Result<u64, PairingServiceError> {
    for stage in [
        PairingStage::Invitation,
        PairingStage::JoinProof,
        PairingStage::Welcome,
        PairingStage::Completion,
    ] {
        for record in [state.local_record(stage)?, state.remote_record(stage)?]
            .into_iter()
            .flatten()
        {
            if record.envelope().message_id() == in_reply_to {
                return Ok(record.envelope().expires_at_unix_seconds());
            }
        }
    }
    Err(PairingServiceError::InvalidTransition)
}

fn terminal_after_submission(
    checkpoint: &PairingCheckpoint,
    state: &PairingOperationState,
) -> Result<PairingPhase, PairingServiceError> {
    let completion_accepted = state.outbounds().iter().any(|outbound| {
        outbound.accepted_cursor().is_some()
            && outbound
                .pairing_envelope()
                .is_ok_and(|envelope| envelope.stage() == PairingStage::Completion)
    });
    let cancellation_accepted = state.outbounds().iter().any(|outbound| {
        outbound.accepted_cursor().is_some()
            && outbound
                .pairing_envelope()
                .is_ok_and(|envelope| envelope.stage() == PairingStage::Cancellation)
    });
    if cancellation_accepted {
        return if checkpoint.role == PairingRole::Inviter
            && checkpoint.phase == PairingPhase::InviterAwaitingCompletion
        {
            Ok(PairingPhase::Compensating)
        } else {
            Ok(PairingPhase::Cancelled)
        };
    }
    if checkpoint.role == PairingRole::Joiner
        && checkpoint.phase == PairingPhase::JoinerAwaitingWelcome
        && completion_accepted
    {
        Ok(PairingPhase::Completed)
    } else {
        Ok(checkpoint.phase)
    }
}

const fn is_precommit_phase(phase: PairingPhase) -> bool {
    matches!(
        phase,
        PairingPhase::JoinerAwaitingInvitation
            | PairingPhase::JoinerAwaitingInviterAuthorization
            | PairingPhase::JoinerAwaitingWelcome
            | PairingPhase::InviterAwaitingAuthorization
            | PairingPhase::InviterAwaitingJoinProof
    )
}

const fn is_cancellable_precommit_phase(phase: PairingPhase) -> bool {
    matches!(
        phase,
        PairingPhase::JoinerAwaitingInviterAuthorization | PairingPhase::InviterAwaitingJoinProof
    )
}

fn repeat_pairing_status(state: &RepeatPairingOperationState) -> RepeatPairingStatus {
    RepeatPairingStatus {
        operation_id: state.operation_id,
        role: state.role,
        phase: state.phase,
        peer_device_id: state.peer_device_id,
        conversation_id: state.new_conversation_id,
        pairing_id: state.pairing_id,
        deadline_unix_seconds: state.deadline_unix_seconds,
    }
}

fn repeat_pairing_request_message_id(operation_id: RepeatPairingOperationId) -> MessageId {
    MessageId::from_bytes(operation_id.into_bytes())
}

fn repeat_pairing_response_message_id(operation_id: RepeatPairingOperationId) -> MessageId {
    let mut bytes = operation_id.into_bytes();
    bytes[0] ^= 0x80;
    MessageId::from_bytes(bytes)
}

fn unix_milliseconds(seconds: u64) -> Result<u64, PairingServiceError> {
    seconds
        .checked_mul(1_000)
        .ok_or(PairingServiceError::InvalidTransition)
}

/// Stable failures from durable pairing orchestration.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum PairingServiceError {
    #[error("pairing operation expired")]
    Expired,
    #[error("pairing authorization window exceeds the supported bound")]
    InvalidAuthorizationWindow,
    #[error("pairing operation is not in the required phase")]
    InvalidTransition,
    #[error("pairing authorization does not match the authenticated peer")]
    AuthorizationMismatch,
    #[error("pairing capability targets another relay")]
    RelayMismatch,
    #[error("relay response does not match the pairing operation")]
    InvalidRelayResponse,
    #[error("blocking pairing task failed")]
    Task,
    #[error("the profile is closing and admits no further operations")]
    ProfileClosing,
    #[error("pairing rendezvous publication failed and local reservation cleanup failed")]
    RendezvousCleanup,
    #[error("compact pairing rendezvous supports only the member role")]
    InvalidRendezvousRole,
    #[error("short-code pairing exchange was rejected")]
    ShortCodeRejected,
    #[error(transparent)]
    Application(#[from] ApplicationServiceError),
    #[error(transparent)]
    Client(#[from] KonclaveClientError),
    #[error(transparent)]
    Conversation(#[from] ConversationCoordinatorError),
    #[error(transparent)]
    Cryptographic(#[from] KonclaveCryptographicError),
    #[error(transparent)]
    Persistence(#[from] ProfileStoreError),
    #[error(transparent)]
    Protocol(#[from] KonclaveProtocolError),
    #[error(transparent)]
    State(#[from] PairingStateError),
    #[error(transparent)]
    ShortCodeState(#[from] ShortCodeStateError),
    #[error(transparent)]
    RepeatPairingState(#[from] RepeatPairingStateError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use KonclaveClientLibrary::{
        PairingRendezvousPublishResult, PairingRendezvousTransport, RelayTransport,
        RelayWatchSession,
    };
    use KonclaveDomainCore::{
        AcknowledgeRequest, DeliveryClass, EnvelopeId, PairingRendezvousId,
        PairingRendezvousRecord, PairingRendezvousTakeRequest, RelayEnvelope, ReplayPage,
        ReplayRequest, RoutingId, StoredRelayEnvelope,
    };
    use async_trait::async_trait;
    use tokio::sync::{Notify, oneshot};

    use super::*;
    use crate::conversation::tests::{open_coordinator, paired_coordinators};

    const NOW: u64 = 1_700_000_000;
    const DEADLINE: u64 = NOW + 300;

    #[derive(Clone, Default)]
    struct MemoryRelay {
        routes: Arc<Mutex<BTreeMap<RoutingId, Vec<StoredRelayEnvelope>>>>,
        rendezvous: Arc<Mutex<BTreeMap<PairingRendezvousId, PairingRendezvousRecord>>>,
        fail_next_rendezvous_publish: Arc<AtomicBool>,
        fail_next_pairing_submit: Arc<AtomicBool>,
        fail_next_group_commit_submit: Arc<AtomicBool>,
        fail_after_next_group_application_acceptance: Arc<AtomicBool>,
        fail_after_next_group_commit_acceptance: Arc<AtomicBool>,
        pause_next_group_commit_submit: Arc<AtomicBool>,
        group_commit_accepted: Arc<Notify>,
        group_commit_release: Arc<Notify>,
    }

    impl MemoryRelay {
        fn fail_next_rendezvous_publish(&self) {
            self.fail_next_rendezvous_publish
                .store(true, Ordering::SeqCst);
        }

        fn fail_next_pairing_submit(&self) {
            self.fail_next_pairing_submit.store(true, Ordering::SeqCst);
        }

        fn fail_next_group_commit_submit(&self) {
            self.fail_next_group_commit_submit
                .store(true, Ordering::SeqCst);
        }

        fn pause_next_group_commit_after_acceptance(&self) {
            self.pause_next_group_commit_submit
                .store(true, Ordering::SeqCst);
        }

        fn fail_after_next_group_commit_acceptance(&self) {
            self.fail_after_next_group_commit_acceptance
                .store(true, Ordering::SeqCst);
        }

        async fn wait_for_group_commit_acceptance(&self) {
            self.group_commit_accepted.notified().await;
        }

        fn release_group_commit(&self) {
            self.group_commit_release.notify_one();
        }

        fn delivery_count(&self, delivery_class: DeliveryClass) -> usize {
            self.routes
                .lock()
                .unwrap()
                .values()
                .flatten()
                .filter(|stored| stored.envelope().delivery_class() == delivery_class)
                .count()
        }

        fn pairing_stage_count(&self, stage: PairingStage) -> usize {
            self.routes
                .lock()
                .unwrap()
                .values()
                .flatten()
                .filter(|stored| {
                    stored.envelope().delivery_class() == DeliveryClass::Pairing
                        && v1::decode_pairing_envelope(stored.envelope().payload())
                            .is_ok_and(|envelope| envelope.stage() == stage)
                })
                .count()
        }

        fn duplicate_latest_pairing_record(&self) -> u64 {
            self.duplicate_latest_pairing_record_as(0xfe)
        }

        fn duplicate_latest_pairing_record_as(&self, envelope_id: u8) -> u64 {
            let mut routes = self.routes.lock().unwrap();
            let records = routes
                .values_mut()
                .find(|records| {
                    records.last().is_some_and(|stored| {
                        stored.envelope().delivery_class() == DeliveryClass::Pairing
                    })
                })
                .unwrap();
            let original = records.last().unwrap().envelope();
            let duplicate = RelayEnvelope::new(
                original.version(),
                original.routing_id(),
                EnvelopeId::from_bytes([envelope_id; EnvelopeId::LENGTH]),
                original.delivery_class(),
                original.expected_parent_epoch(),
                original.expires_at_unix_seconds(),
                original.payload().to_vec(),
            )
            .unwrap();
            let cursor = u64::try_from(records.len()).unwrap() + 1;
            records.push(StoredRelayEnvelope::new(duplicate, cursor).unwrap());
            cursor
        }
    }

    #[async_trait]
    impl RelayTransport for MemoryRelay {
        async fn submit(
            &self,
            envelope: &RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            if envelope.delivery_class() == DeliveryClass::Pairing
                && self.fail_next_pairing_submit.swap(false, Ordering::SeqCst)
            {
                return Err(KonclaveClientError::TransportUnavailable);
            }

            if envelope.delivery_class() == DeliveryClass::GroupCommit
                && self
                    .fail_next_group_commit_submit
                    .swap(false, Ordering::SeqCst)
            {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            let (
                stored,
                pause_after_acceptance,
                fail_after_acceptance,
                fail_group_application_after_acceptance,
            ) = {
                let mut routes = self
                    .routes
                    .lock()
                    .map_err(|_| KonclaveClientError::TransportUnavailable)?;
                let route = routes.entry(envelope.routing_id()).or_default();
                if let Some(existing) = route
                    .iter()
                    .find(|stored| stored.envelope().envelope_id() == envelope.envelope_id())
                {
                    return if existing.envelope() == envelope {
                        Ok(existing.clone())
                    } else {
                        Err(KonclaveClientError::InvalidResponse)
                    };
                }
                let cursor = u64::try_from(route.len())
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(KonclaveClientError::InvalidResponse)?;
                let stored = StoredRelayEnvelope::new(envelope.clone(), cursor)
                    .map_err(|_| KonclaveClientError::InvalidResponse)?;
                route.push(stored.clone());
                let pause_after_acceptance = envelope.delivery_class()
                    == DeliveryClass::GroupCommit
                    && self
                        .pause_next_group_commit_submit
                        .swap(false, Ordering::SeqCst);
                let fail_after_acceptance = envelope.delivery_class() == DeliveryClass::GroupCommit
                    && self
                        .fail_after_next_group_commit_acceptance
                        .swap(false, Ordering::SeqCst);
                let fail_group_application_after_acceptance = envelope.delivery_class()
                    == DeliveryClass::GroupApplication
                    && self
                        .fail_after_next_group_application_acceptance
                        .swap(false, Ordering::SeqCst);
                (
                    stored,
                    pause_after_acceptance,
                    fail_after_acceptance,
                    fail_group_application_after_acceptance,
                )
            };
            if fail_after_acceptance || fail_group_application_after_acceptance {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            if pause_after_acceptance {
                self.group_commit_accepted.notify_one();
                self.group_commit_release.notified().await;
            }
            Ok(stored)
        }

        async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
            let routing_id = request.routing_id();
            let after_cursor = request.after_cursor();
            let limit = usize::try_from(request.limit())
                .map_err(|_| KonclaveClientError::InvalidResponse)?;
            let routes = self
                .routes
                .lock()
                .map_err(|_| KonclaveClientError::TransportUnavailable)?;
            let available = routes.get(&routing_id).map_or(&[][..], Vec::as_slice);
            let page = available
                .iter()
                .filter(|stored| stored.cursor() > after_cursor)
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            let next_cursor = page
                .last()
                .map_or(after_cursor, StoredRelayEnvelope::cursor);
            let has_more = available.iter().any(|stored| stored.cursor() > next_cursor);
            ReplayPage::new(page, next_cursor, has_more)
                .map_err(|_| KonclaveClientError::InvalidResponse)
        }

        async fn acknowledge(
            &self,
            request: AcknowledgeRequest,
        ) -> Result<AcknowledgeRequest, KonclaveClientError> {
            Ok(request)
        }

        async fn connect_watch(
            &self,
            _: ReplayRequest,
        ) -> Result<RelayWatchSession, KonclaveClientError> {
            Err(KonclaveClientError::TransportUnavailable)
        }
    }

    #[async_trait]
    impl PairingRendezvousTransport for MemoryRelay {
        async fn publish_pairing_rendezvous(
            &self,
            record: &PairingRendezvousRecord,
        ) -> Result<PairingRendezvousPublishResult, KonclaveClientError> {
            if self
                .fail_next_rendezvous_publish
                .swap(false, Ordering::SeqCst)
            {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            let mut records = self
                .rendezvous
                .lock()
                .map_err(|_| KonclaveClientError::TransportUnavailable)?;
            if let Some(existing) = records.get(&record.lookup_id()) {
                return if existing == record {
                    Ok(PairingRendezvousPublishResult::AlreadyPublished)
                } else {
                    Err(KonclaveClientError::RelayRejected {
                        status: 409,
                        relay_code: "relay_pairing_rendezvous_conflict".to_string(),
                    })
                };
            }
            let stored = PairingRendezvousRecord::new(
                record.version(),
                record.lookup_id(),
                record.expires_at_unix_seconds(),
                record.nonce(),
                record.ciphertext().to_vec(),
            )
            .map_err(|_| KonclaveClientError::InvalidResponse)?;
            records.insert(record.lookup_id(), stored);
            Ok(PairingRendezvousPublishResult::Published)
        }

        async fn take_pairing_rendezvous(
            &self,
            request: PairingRendezvousTakeRequest,
        ) -> Result<PairingRendezvousRecord, KonclaveClientError> {
            self.rendezvous
                .lock()
                .map_err(|_| KonclaveClientError::TransportUnavailable)?
                .remove(&request.lookup_id())
                .ok_or_else(|| KonclaveClientError::RelayRejected {
                    status: 404,
                    relay_code: "relay_pairing_rendezvous_unavailable".to_string(),
                })
        }
    }

    fn service(
        conversations: ConversationCoordinator,
        relay: Arc<MemoryRelay>,
        endpoint: &RelayEndpoint,
    ) -> PairingService<MemoryRelay> {
        let applications =
            ApplicationService::from_shared(conversations.clone(), Arc::clone(&relay));
        PairingService::new(conversations, applications, endpoint.clone())
    }

    #[tokio::test]
    async fn trusted_alias_bootstrap_completes_a_second_conversation_without_user_handoff() {
        let (root, alice, bob, bootstrap_conversation_id, alice_device_id) = paired_coordinators();
        let bob_device_id = bob.device_id().unwrap();
        alice
            .set_trusted_device_alias(
                bob_device_id,
                TrustedDeviceAlias::parse("alienware").unwrap(),
            )
            .unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let alice_service = service(alice.clone(), Arc::clone(&relay), &endpoint);
        let bob_service = service(bob.clone(), Arc::clone(&relay), &endpoint);

        let started = alice_service
            .start_repeat_pairing(
                TrustedDeviceAlias::parse("alienware").unwrap(),
                DEADLINE,
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(started.phase, RepeatPairingPhase::InitiatorAwaitingResponse);
        drop(alice_service);
        drop(alice);
        let alice = open_coordinator(root.path(), "alice");
        alice.recover().unwrap();
        let alice_service = service(alice.clone(), Arc::clone(&relay), &endpoint);
        assert!(
            bob_service
                .applications
                .replay_once(bootstrap_conversation_id, 100, NOW)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
        relay
            .fail_after_next_group_application_acceptance
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            bob_service.sync_active_repeat_pairings_once(NOW).await,
            Err(PairingServiceError::Application(
                ApplicationServiceError::Relay(KonclaveClientError::TransportUnavailable)
            ))
        ));
        bob_service
            .sync_active_repeat_pairings_once(NOW)
            .await
            .unwrap();
        assert_eq!(
            bob_service
                .repeat_pairing_status(started.operation_id)
                .await
                .unwrap()
                .phase,
            RepeatPairingPhase::ResponderPairing
        );
        assert!(
            alice_service
                .applications
                .replay_once(bootstrap_conversation_id, 100, NOW)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
        assert_eq!(
            alice_service
                .repeat_pairing_status(started.operation_id)
                .await
                .unwrap()
                .phase,
            RepeatPairingPhase::InitiatorRedeemingCapability
        );
        assert_eq!(alice.remote_event_counts().unwrap(), (0, 0));
        assert_eq!(bob.remote_event_counts().unwrap(), (0, 0));

        for _ in 0..12 {
            alice_service.sync_active_once(NOW).await.unwrap();
            alice_service
                .sync_active_repeat_pairings_once(NOW)
                .await
                .unwrap();
            bob_service.sync_active_once(NOW).await.unwrap();
            bob_service
                .sync_active_repeat_pairings_once(NOW)
                .await
                .unwrap();
            let alice_status = alice_service
                .repeat_pairing_status(started.operation_id)
                .await
                .unwrap();
            if alice_status.phase == RepeatPairingPhase::Completed {
                break;
            }
        }
        let alice_status = alice_service
            .repeat_pairing_status(started.operation_id)
            .await
            .unwrap();
        assert_eq!(alice_status.phase, RepeatPairingPhase::Completed);
        let new_conversation_id = alice_status.conversation_id;
        let alice_conversation = alice.open(new_conversation_id).unwrap();
        let bob_conversation = bob.open(new_conversation_id).unwrap();
        assert_eq!(
            alice_conversation.group.state(),
            bob_conversation.group.state()
        );
        assert_eq!(
            alice_conversation
                .group
                .state()
                .member(bob_device_id)
                .map(KonclaveDomainCore::Member::role),
            Some(ConversationRole::Member)
        );
        assert_eq!(
            bob_conversation
                .group
                .state()
                .member(alice_device_id)
                .map(KonclaveDomainCore::Member::role),
            Some(ConversationRole::Administrator)
        );
        assert!(
            alice_service
                .applications
                .read(bootstrap_conversation_id, 0, 100)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
        assert!(
            bob_service
                .applications
                .read(bootstrap_conversation_id, 0, 100)
                .await
                .unwrap()
                .messages
                .is_empty()
        );

        alice_service
            .applications
            .send(SendApplicationRequest {
                conversation_id: new_conversation_id,
                message_id: MessageId::from_bytes([99; 16]),
                content: ApplicationContent::text("repeat pairing works").unwrap(),
                reply_to: None,
                collaboration_action_authorization: None,
                sent_at_unix_milliseconds: unix_milliseconds(NOW).unwrap(),
                now_unix_seconds: NOW,
                expires_at_unix_seconds: DEADLINE,
            })
            .await
            .unwrap();
        let received = bob_service
            .applications
            .replay_once(new_conversation_id, 100, NOW)
            .await
            .unwrap();
        assert_eq!(received.messages.len(), 1);
        assert!(matches!(
            received.messages[0].message.content(),
            ApplicationContent::Text(body) if body == "repeat pairing works"
        ));
        alice_service
            .store
            .delete_internal_application_markers_for_test(bootstrap_conversation_id)
            .unwrap();
        assert!(matches!(
            alice_service
                .applications
                .read(bootstrap_conversation_id, 0, 100)
                .await,
            Err(ApplicationServiceError::Conversation(
                ConversationCoordinatorError::Profile(ProfileStoreError::CorruptData)
            ))
        ));
    }

    #[tokio::test]
    async fn malformed_repeat_pairing_capability_cancels_only_that_operation() {
        let (_root, alice, bob, bootstrap_conversation_id, alice_device_id) = paired_coordinators();
        let bob_device_id = bob.device_id().unwrap();
        alice
            .set_trusted_device_alias(
                bob_device_id,
                TrustedDeviceAlias::parse("alienware").unwrap(),
            )
            .unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let alice_service = service(alice, Arc::clone(&relay), &endpoint);
        let bob_service = service(bob, Arc::clone(&relay), &endpoint);
        let started = alice_service
            .start_repeat_pairing(
                TrustedDeviceAlias::parse("alienware").unwrap(),
                DEADLINE,
                NOW,
            )
            .await
            .unwrap();
        bob_service
            .applications
            .send(SendApplicationRequest {
                conversation_id: bootstrap_conversation_id,
                message_id: repeat_pairing_response_message_id(started.operation_id),
                content: ApplicationContent::repeat_pairing_response(
                    RepeatPairingResponse::new(
                        started.operation_id,
                        alice_device_id,
                        started.conversation_id,
                        "not-a-capability",
                    )
                    .unwrap(),
                ),
                reply_to: Some(repeat_pairing_request_message_id(started.operation_id)),
                collaboration_action_authorization: None,
                sent_at_unix_milliseconds: unix_milliseconds(NOW).unwrap(),
                now_unix_seconds: NOW,
                expires_at_unix_seconds: DEADLINE,
            })
            .await
            .unwrap();
        alice_service
            .applications
            .replay_once(bootstrap_conversation_id, 100, NOW)
            .await
            .unwrap();
        let cancelled = alice_service
            .sync_repeat_pairing(started.operation_id, NOW)
            .await
            .unwrap();
        assert_eq!(cancelled.phase, RepeatPairingPhase::Cancelled);
    }

    struct PairingFixture {
        _root: tempfile::TempDir,
        inviter: ConversationCoordinator,
        joiner: ConversationCoordinator,
        inviter_service: PairingService<MemoryRelay>,
        joiner_service: PairingService<MemoryRelay>,
        relay: Arc<MemoryRelay>,
        pairing_id: PairingId,
        conversation_id: ConversationId,
        joiner_device_id: DeviceId,
    }

    async fn pairing_awaiting_join_proof() -> PairingFixture {
        let root = tempfile::tempdir().unwrap();
        let inviter = open_coordinator(root.path(), "compensation-inviter");
        let joiner = open_coordinator(root.path(), "compensation-joiner");
        let conversation = inviter.create().unwrap();
        let inviter_device_id = inviter.device_id().unwrap();
        let joiner_device_id = joiner.device_id().unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let inviter_service = service(inviter.clone(), Arc::clone(&relay), &endpoint);
        let joiner_service = service(joiner.clone(), Arc::clone(&relay), &endpoint);
        let created = joiner_service
            .create_capability(ConversationRole::Member, DEADLINE, NOW)
            .await
            .unwrap();
        let pairing_id = created.pairing_id;
        inviter_service
            .redeem_capability(created.capability.as_str(), NOW)
            .await
            .unwrap();
        inviter_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        joiner_service.replay_once(pairing_id, NOW).await.unwrap();
        joiner_service
            .authorize_inviter(
                pairing_id,
                inviter_device_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        PairingFixture {
            _root: root,
            inviter,
            joiner,
            inviter_service,
            joiner_service,
            relay,
            pairing_id,
            conversation_id: conversation.conversation_id,
            joiner_device_id,
        }
    }

    async fn pairing_awaiting_completion() -> PairingFixture {
        let fixture = pairing_awaiting_join_proof().await;
        fixture
            .inviter_service
            .replay_once(fixture.pairing_id, NOW)
            .await
            .unwrap();
        fixture
    }

    async fn checkpoint_inviter_commit_intent(fixture: &PairingFixture) {
        let initial = fixture
            .inviter_service
            .load_checkpoint(fixture.pairing_id)
            .await
            .unwrap();
        let page = fixture
            .relay
            .replay(ReplayRequest::new(initial.routing_id, initial.replay_cursor, 8).unwrap())
            .await
            .unwrap();
        assert_eq!(page.envelopes().len(), 2);
        fixture
            .inviter_service
            .process_stored(fixture.pairing_id, &page.envelopes()[0], NOW)
            .await
            .unwrap();

        let checkpoint = fixture
            .inviter_service
            .load_checkpoint(fixture.pairing_id)
            .await
            .unwrap();
        let stored = &page.envelopes()[1];
        let pairing = v1::decode_pairing_envelope(stored.envelope().payload()).unwrap();
        let mut state = PairingOperationState::from_checkpoint(&checkpoint).unwrap();
        let PairingObservationResult::Added(plaintext) = state.observe(stored).unwrap() else {
            panic!("join proof must be newly observed");
        };
        fixture
            .inviter_service
            .checkpoint_inviter_commit(
                &checkpoint,
                &state,
                &pairing,
                &plaintext,
                stored.cursor(),
                NOW,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn complete_pairing_uses_one_capability_and_recovers_exact_retries() {
        let root = tempfile::tempdir().unwrap();
        let inviter = open_coordinator(root.path(), "pairing-inviter");
        let joiner = open_coordinator(root.path(), "pairing-joiner");
        let conversation = inviter.create().unwrap();
        let inviter_device_id = inviter.device_id().unwrap();
        let joiner_device_id = joiner.device_id().unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let inviter_service = service(inviter.clone(), Arc::clone(&relay), &endpoint);
        let joiner_service = service(joiner.clone(), Arc::clone(&relay), &endpoint);

        let created = joiner_service
            .create_capability(ConversationRole::Member, DEADLINE, NOW)
            .await
            .unwrap();
        let pairing_id = created.pairing_id;
        let redeemed = inviter_service
            .redeem_capability(created.capability.as_str(), NOW)
            .await
            .unwrap();
        assert_eq!(redeemed.joiner_device_id, joiner_device_id);
        assert_eq!(redeemed.phase, PairingPhase::InviterAwaitingAuthorization);

        inviter_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        inviter_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(
            joiner_service.replay_once(pairing_id, NOW).await.unwrap(),
            1
        );
        let awaiting_authorization = joiner_service.status(pairing_id).await.unwrap();
        assert_eq!(
            awaiting_authorization.inviter_device_id,
            Some(inviter_device_id)
        );
        assert_eq!(
            awaiting_authorization.granted_role,
            Some(ConversationRole::Member)
        );
        assert!(matches!(
            joiner_service
                .authorize_inviter(
                    pairing_id,
                    DeviceId::from_bytes([0x55; DeviceId::LENGTH]),
                    conversation.conversation_id,
                    ConversationRole::Member,
                    NOW,
                )
                .await,
            Err(PairingServiceError::AuthorizationMismatch)
        ));
        assert_eq!(
            joiner_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::JoinerAwaitingInviterAuthorization
        );

        joiner_service
            .authorize_inviter(
                pairing_id,
                inviter_device_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        joiner_service
            .authorize_inviter(
                pairing_id,
                inviter_device_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(
            inviter_service.replay_once(pairing_id, NOW).await.unwrap(),
            2
        );
        relay.fail_next_pairing_submit();
        assert!(matches!(
            joiner_service.replay_once(pairing_id, NOW).await,
            Err(PairingServiceError::Client(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert!(
            !joiner
                .store()
                .pending_join_ids(None, 10)
                .unwrap()
                .is_empty()
        );
        joiner.recover().unwrap();
        assert!(
            !joiner
                .store()
                .pending_join_ids(None, 10)
                .unwrap()
                .is_empty()
        );
        let recovered_joiner_service = service(joiner.clone(), Arc::clone(&relay), &endpoint);
        recovered_joiner_service
            .retry_outbounds(pairing_id, NOW)
            .await
            .unwrap();
        assert_eq!(
            recovered_joiner_service
                .status(pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Completed
        );
        assert!(
            joiner
                .store()
                .pending_join_ids(None, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            inviter_service.replay_once(pairing_id, NOW).await.unwrap(),
            2
        );
        assert_eq!(
            inviter_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::Completed
        );

        let inviter_conversation = inviter.open(conversation.conversation_id).unwrap();
        let joiner_conversation = joiner.open(conversation.conversation_id).unwrap();
        assert_eq!(inviter_conversation.group.epoch(), 1);
        assert_eq!(joiner_conversation.group.epoch(), 1);
        assert_eq!(
            inviter_conversation
                .group
                .state()
                .member(joiner_device_id)
                .map(KonclaveDomainCore::Member::role),
            Some(ConversationRole::Member)
        );
    }

    #[tokio::test]
    async fn compact_rendezvous_completes_one_shared_conversation() {
        let root = tempfile::tempdir().unwrap();
        let inviter = open_coordinator(root.path(), "rendezvous-inviter");
        let joiner = open_coordinator(root.path(), "rendezvous-joiner");
        let conversation = inviter.create().unwrap();
        let inviter_device_id = inviter.device_id().unwrap();
        let joiner_device_id = joiner.device_id().unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let inviter_service = service(inviter.clone(), Arc::clone(&relay), &endpoint);
        let joiner_service = service(joiner.clone(), Arc::clone(&relay), &endpoint);

        let created = joiner_service
            .create_rendezvous(DEADLINE, NOW)
            .await
            .unwrap();
        let pairing_id = created.pairing_id;
        let redeemed = inviter_service
            .redeem_rendezvous(created.token.as_str(), NOW)
            .await
            .unwrap();
        assert_eq!(redeemed.pairing_id, pairing_id);
        assert_eq!(redeemed.joiner_device_id, joiner_device_id);
        assert_eq!(redeemed.phase, PairingPhase::InviterAwaitingAuthorization);

        inviter_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(
            joiner_service.replay_once(pairing_id, NOW).await.unwrap(),
            1
        );
        joiner_service
            .authorize_inviter(
                pairing_id,
                inviter_device_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(
            inviter_service.replay_once(pairing_id, NOW).await.unwrap(),
            2
        );
        assert_eq!(
            joiner_service.replay_once(pairing_id, NOW).await.unwrap(),
            2
        );
        assert_eq!(
            inviter_service.replay_once(pairing_id, NOW).await.unwrap(),
            2
        );

        let inviter_status = inviter_service.status(pairing_id).await.unwrap();
        let joiner_status = joiner_service.status(pairing_id).await.unwrap();
        assert_eq!(inviter_status.phase, PairingPhase::Completed);
        assert_eq!(joiner_status.phase, PairingPhase::Completed);
        assert_eq!(
            inviter_status.conversation_id,
            Some(conversation.conversation_id)
        );
        assert_eq!(
            joiner_status.conversation_id,
            inviter_status.conversation_id
        );
        let inviter_conversation = inviter.open(conversation.conversation_id).unwrap();
        let joiner_conversation = joiner.open(conversation.conversation_id).unwrap();
        assert_eq!(inviter_conversation.group.epoch(), 1);
        assert_eq!(joiner_conversation.group.epoch(), 1);
        assert_eq!(
            inviter_conversation
                .group
                .state()
                .member(joiner_device_id)
                .map(KonclaveDomainCore::Member::role),
            Some(ConversationRole::Member)
        );
    }

    #[tokio::test]
    async fn failed_rendezvous_publish_cancels_the_local_reservation() {
        let root = tempfile::tempdir().unwrap();
        let conversations = open_coordinator(root.path(), "rendezvous-publish-failure");
        let relay = Arc::new(MemoryRelay::default());
        relay.fail_next_rendezvous_publish();
        let service = service(
            conversations.clone(),
            relay,
            &RelayEndpoint::parse("https://relay.example.com").unwrap(),
        );

        assert!(matches!(
            service.create_rendezvous(DEADLINE, NOW).await,
            Err(PairingServiceError::Client(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        assert!(
            conversations
                .store()
                .active_pairing_ids(None, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn compact_rendezvous_rejects_administrator_capabilities() {
        let root = tempfile::tempdir().unwrap();
        let inviter = open_coordinator(root.path(), "rendezvous-role-inviter");
        let joiner = open_coordinator(root.path(), "rendezvous-role-joiner");
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let inviter_service = service(inviter.clone(), Arc::clone(&relay), &endpoint);
        let joiner_service = service(joiner, Arc::clone(&relay), &endpoint);
        let created = joiner_service
            .create_capability(ConversationRole::Administrator, DEADLINE, NOW)
            .await
            .unwrap();
        let capability = PairingCapability::decode(created.capability.as_str(), NOW).unwrap();
        let (token, record) = create_pairing_rendezvous(&capability, NOW).unwrap();
        relay.publish_pairing_rendezvous(&record).await.unwrap();

        assert!(matches!(
            inviter_service.redeem_rendezvous(token.as_str(), NOW).await,
            Err(PairingServiceError::InvalidRendezvousRole)
        ));
        assert!(
            inviter
                .store()
                .active_pairing_ids(None, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn completion_deadline_overflow_is_rejected_before_membership_work() {
        assert!(matches!(
            completion_deadline(1, u64::MAX),
            Err(PairingServiceError::InvalidTransition)
        ));
    }

    #[test]
    fn authorization_window_is_positive_and_bounded() {
        assert!(require_authorization_window(NOW, NOW + 1).is_ok());
        assert!(matches!(
            require_authorization_window(NOW, NOW),
            Err(PairingServiceError::InvalidAuthorizationWindow)
        ));
        assert!(matches!(
            require_authorization_window(NOW, NOW + MAX_AUTHORIZATION_WINDOW_SECONDS + 1),
            Err(PairingServiceError::InvalidAuthorizationWindow)
        ));
    }

    #[tokio::test]
    async fn completion_timeout_durably_compensates_until_removal_is_accepted() {
        let fixture = pairing_awaiting_completion().await;
        let status = fixture
            .inviter_service
            .status(fixture.pairing_id)
            .await
            .unwrap();
        assert_eq!(status.phase, PairingPhase::InviterAwaitingCompletion);
        let deadline = status.completion_deadline_unix_seconds.unwrap();
        assert!(
            fixture
                .inviter
                .open(fixture.conversation_id)
                .unwrap()
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_some()
        );

        fixture.relay.fail_next_group_commit_submit();
        assert!(
            fixture
                .inviter_service
                .retry_outbounds(fixture.pairing_id, deadline)
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Compensating
        );
        fixture.inviter.recover().unwrap();
        assert_eq!(fixture.inviter_service.recover(deadline).await.unwrap(), 1);
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Cancelled
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 2);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
        fixture
            .inviter_service
            .retry_outbounds(fixture.pairing_id, deadline)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .inviter
                .open(fixture.conversation_id)
                .unwrap()
                .group
                .epoch(),
            2
        );
    }

    #[tokio::test]
    async fn duplicate_welcome_advances_without_recreating_completion() {
        let fixture = pairing_awaiting_completion().await;
        fixture.relay.fail_next_pairing_submit();
        assert!(
            fixture
                .joiner_service
                .replay_once(fixture.pairing_id, NOW)
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .joiner_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::JoinerAwaitingWelcome
        );
        assert!(matches!(
            fixture.joiner_service.cancel(fixture.pairing_id, NOW).await,
            Err(PairingServiceError::InvalidTransition)
        ));
        assert_eq!(fixture.relay.duplicate_latest_pairing_record(), 4);
        assert_eq!(
            fixture
                .joiner_service
                .replay_once(fixture.pairing_id, NOW)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .joiner_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Completed
        );
        assert!(
            fixture
                .joiner
                .store()
                .pending_join_ids(None, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn signed_precommit_cancellation_terminates_both_endpoints() {
        let root = tempfile::tempdir().unwrap();
        let inviter = open_coordinator(root.path(), "cancel-inviter");
        let joiner = open_coordinator(root.path(), "cancel-joiner");
        let conversation = inviter.create().unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let inviter_service = service(inviter.clone(), Arc::clone(&relay), &endpoint);
        let joiner_service = service(joiner, Arc::clone(&relay), &endpoint);
        let created = joiner_service
            .create_capability(ConversationRole::Member, DEADLINE, NOW)
            .await
            .unwrap();
        let pairing_id = created.pairing_id;
        inviter_service
            .redeem_capability(created.capability.as_str(), NOW)
            .await
            .unwrap();
        inviter_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        joiner_service.replay_once(pairing_id, NOW).await.unwrap();

        joiner_service.cancel(pairing_id, NOW).await.unwrap();
        joiner_service.cancel(pairing_id, NOW).await.unwrap();
        assert_eq!(
            joiner_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        assert_eq!(
            inviter_service.replay_once(pairing_id, NOW).await.unwrap(),
            2
        );
        assert_eq!(
            inviter_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        let inviter_conversation = inviter.open(conversation.conversation_id).unwrap();
        assert_eq!(inviter_conversation.group.epoch(), 0);
        assert_eq!(inviter_conversation.group.state().members().len(), 1);
    }

    #[tokio::test]
    async fn local_postcommit_cancellation_removes_the_joiner_before_terminating() {
        let fixture = pairing_awaiting_completion().await;
        fixture
            .inviter_service
            .cancel(fixture.pairing_id, NOW)
            .await
            .unwrap();
        fixture
            .inviter_service
            .cancel(fixture.pairing_id, NOW)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Cancelled
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 2);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn cancellation_against_prior_frontier_preempts_an_unprepared_commit() {
        let root = tempfile::tempdir().unwrap();
        let inviter = open_coordinator(root.path(), "frontier-inviter");
        let joiner = open_coordinator(root.path(), "frontier-joiner");
        let conversation = inviter.create().unwrap();
        let inviter_device_id = inviter.device_id().unwrap();
        let joiner_device_id = joiner.device_id().unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let inviter_service = service(inviter.clone(), Arc::clone(&relay), &endpoint);
        let joiner_service = service(joiner, Arc::clone(&relay), &endpoint);
        let created = joiner_service
            .create_capability(ConversationRole::Member, DEADLINE, NOW)
            .await
            .unwrap();
        let pairing_id = created.pairing_id;
        inviter_service
            .redeem_capability(created.capability.as_str(), NOW)
            .await
            .unwrap();
        inviter_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        joiner_service.replay_once(pairing_id, NOW).await.unwrap();
        relay.fail_next_pairing_submit();
        assert!(
            joiner_service
                .authorize_inviter(
                    pairing_id,
                    inviter_device_id,
                    conversation.conversation_id,
                    ConversationRole::Member,
                    NOW,
                )
                .await
                .is_err()
        );
        joiner_service.cancel(pairing_id, NOW).await.unwrap();

        assert_eq!(
            inviter_service.replay_once(pairing_id, NOW).await.unwrap(),
            3
        );
        assert_eq!(
            inviter_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        assert_eq!(relay.delivery_count(DeliveryClass::GroupCommit), 0);
        let conversation = inviter.open(conversation.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 0);
        assert!(
            conversation
                .group
                .state()
                .member(joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn lost_add_commit_response_recovers_before_cancellation() {
        let fixture = pairing_awaiting_join_proof().await;
        fixture.relay.fail_after_next_group_commit_acceptance();
        assert!(matches!(
            fixture
                .inviter_service
                .replay_once(fixture.pairing_id, NOW)
                .await,
            Err(PairingServiceError::Application(
                ApplicationServiceError::Relay(KonclaveClientError::TransportUnavailable)
            ))
        ));
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::InviterAwaitingCompletion
        );

        fixture.inviter.recover().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let recovered = service(
            fixture.inviter.clone(),
            Arc::clone(&fixture.relay),
            &endpoint,
        );
        recovered.cancel(fixture.pairing_id, NOW).await.unwrap();

        assert_eq!(
            recovered.status(fixture.pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 2);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn durable_compensation_recovers_uncertain_add_without_sending_welcome() {
        let fixture = pairing_awaiting_join_proof().await;
        fixture.relay.fail_after_next_group_commit_acceptance();
        assert!(
            fixture
                .inviter_service
                .replay_once(fixture.pairing_id, NOW)
                .await
                .is_err()
        );
        let checkpoint = fixture
            .inviter_service
            .load_checkpoint(fixture.pairing_id)
            .await
            .unwrap();
        let state = PairingOperationState::from_checkpoint(&checkpoint).unwrap();
        fixture
            .inviter_service
            .checkpoint_state(
                &checkpoint,
                &state,
                PairingPhase::Compensating,
                checkpoint.completion_deadline_unix_seconds,
                checkpoint.replay_cursor,
            )
            .await
            .unwrap();

        fixture.inviter.recover().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let recovered = service(
            fixture.inviter.clone(),
            Arc::clone(&fixture.relay),
            &endpoint,
        );
        recovered
            .retry_outbounds(fixture.pairing_id, NOW)
            .await
            .unwrap();

        assert_eq!(
            recovered.status(fixture.pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        assert_eq!(fixture.relay.pairing_stage_count(PairingStage::Welcome), 0);
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 2);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn cancellation_after_intent_only_restart_never_creates_an_add_commit() {
        let fixture = pairing_awaiting_join_proof().await;
        checkpoint_inviter_commit_intent(&fixture).await;
        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 0);

        fixture.inviter.recover().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let recovered = service(
            fixture.inviter.clone(),
            Arc::clone(&fixture.relay),
            &endpoint,
        );
        recovered.cancel(fixture.pairing_id, NOW).await.unwrap();

        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 0);
        assert_eq!(
            recovered.status(fixture.pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 0);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn remote_cancellation_preempts_an_unprepared_add_after_restart() {
        let fixture = pairing_awaiting_join_proof().await;
        checkpoint_inviter_commit_intent(&fixture).await;
        fixture
            .joiner_service
            .cancel(fixture.pairing_id, NOW)
            .await
            .unwrap();

        fixture.inviter.recover().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let recovered = service(
            fixture.inviter.clone(),
            Arc::clone(&fixture.relay),
            &endpoint,
        );
        assert_eq!(
            recovered
                .replay_once(fixture.pairing_id, NOW)
                .await
                .unwrap(),
            1
        );

        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 0);
        assert_eq!(
            recovered.status(fixture.pairing_id).await.unwrap().phase,
            PairingPhase::Cancelled
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 0);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn buffered_remote_cancellation_preempts_add_creation() {
        let fixture = pairing_awaiting_join_proof().await;
        fixture
            .joiner_service
            .cancel(fixture.pairing_id, NOW)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .inviter_service
                .replay_once(fixture.pairing_id, NOW)
                .await
                .unwrap(),
            3
        );
        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 0);
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Cancelled
        );
    }

    #[tokio::test]
    async fn add_creation_waits_until_all_pairing_replay_pages_are_clear() {
        let fixture = pairing_awaiting_join_proof().await;
        for envelope_id in 0x10..0x18 {
            fixture
                .relay
                .duplicate_latest_pairing_record_as(envelope_id);
        }
        fixture
            .joiner_service
            .cancel(fixture.pairing_id, NOW)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .inviter_service
                .replay_once(fixture.pairing_id, NOW)
                .await
                .unwrap(),
            usize::try_from(PAIRING_REPLAY_LIMIT).unwrap()
        );
        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 0);
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::InviterAwaitingCompletion
        );

        assert_eq!(
            fixture
                .inviter_service
                .replay_once(fixture.pairing_id, NOW)
                .await
                .unwrap(),
            3
        );
        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 0);
        assert_eq!(
            fixture
                .inviter_service
                .status(fixture.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Cancelled
        );
    }

    #[tokio::test]
    async fn intent_only_restart_starts_add_after_cancellation_replay_is_clear() {
        let fixture = pairing_awaiting_join_proof().await;
        checkpoint_inviter_commit_intent(&fixture).await;
        fixture.inviter.recover().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let recovered = service(
            fixture.inviter.clone(),
            Arc::clone(&fixture.relay),
            &endpoint,
        );

        assert_eq!(
            recovered
                .replay_once(fixture.pairing_id, NOW)
                .await
                .unwrap(),
            0
        );
        assert_eq!(fixture.relay.delivery_count(DeliveryClass::GroupCommit), 1);
        assert_eq!(
            recovered.status(fixture.pairing_id).await.unwrap().phase,
            PairingPhase::InviterAwaitingCompletion
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 1);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_some()
        );
    }

    #[tokio::test]
    async fn mutation_locks_are_pairing_scoped_and_prune_inactive_gates() {
        let locks = PairingMutationLocks::default();
        let first_id = PairingId::from_bytes([1; PairingId::LENGTH]);
        let second_id = PairingId::from_bytes([2; PairingId::LENGTH]);
        let third_id = PairingId::from_bytes([3; PairingId::LENGTH]);

        let first = locks.acquire(first_id).await;
        let first_gate = locks
            .gates
            .lock()
            .await
            .get(&first_id)
            .and_then(Weak::upgrade)
            .unwrap();
        assert!(first_gate.try_lock().is_err());

        let second = locks.acquire(second_id).await;
        assert_eq!(locks.gates.lock().await.len(), 2);

        drop(first);
        drop(first_gate);
        drop(second);
        let _third = locks.acquire(third_id).await;
        let gates = locks.gates.lock().await;
        assert_eq!(gates.len(), 1);
        assert!(gates.contains_key(&third_id));
    }

    #[tokio::test]
    async fn cancellation_serializes_with_an_accepted_add_commit() {
        let fixture = pairing_awaiting_join_proof().await;
        fixture.relay.pause_next_group_commit_after_acceptance();
        let replay_service = fixture.inviter_service.clone();
        let pairing_id = fixture.pairing_id;
        let replay = tokio::spawn(async move { replay_service.replay_once(pairing_id, NOW).await });
        fixture.relay.wait_for_group_commit_acceptance().await;

        let cancellation_service = fixture.inviter_service.clone();
        let (started, cancellation_started) = oneshot::channel();
        let cancellation = tokio::spawn(async move {
            let _ = started.send(());
            cancellation_service.cancel(pairing_id, NOW).await
        });
        cancellation_started.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!cancellation.is_finished());

        fixture.relay.release_group_commit();
        assert_eq!(replay.await.unwrap().unwrap(), 2);
        cancellation.await.unwrap().unwrap();
        assert_eq!(
            fixture
                .inviter_service
                .status(pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Cancelled
        );
        let conversation = fixture.inviter.open(fixture.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 2);
        assert!(
            conversation
                .group
                .state()
                .member(fixture.joiner_device_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn preinvitation_cancellation_and_expiry_need_no_join_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let relay = Arc::new(MemoryRelay::default());
        let joiner = open_coordinator(root.path(), "early-cancellation-joiner");
        let joiner_service = service(joiner, relay, &endpoint);

        let cancelled = joiner_service
            .create_capability(ConversationRole::Member, DEADLINE, NOW)
            .await
            .unwrap();
        joiner_service
            .cancel(cancelled.pairing_id, NOW)
            .await
            .unwrap();
        joiner_service
            .cancel(cancelled.pairing_id, NOW)
            .await
            .unwrap();
        assert_eq!(
            joiner_service
                .replay_once(cancelled.pairing_id, NOW)
                .await
                .unwrap(),
            0
        );

        let expired = joiner_service
            .create_capability(ConversationRole::Member, DEADLINE, NOW)
            .await
            .unwrap();
        joiner_service
            .retry_outbounds(expired.pairing_id, DEADLINE)
            .await
            .unwrap();
        assert_eq!(
            joiner_service
                .status(expired.pairing_id)
                .await
                .unwrap()
                .phase,
            PairingPhase::Cancelled
        );
    }
}
