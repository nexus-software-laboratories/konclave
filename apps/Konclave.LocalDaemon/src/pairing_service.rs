use std::sync::Arc;

use KonclaveClientLibrary::{
    KonclaveClientError, PairingCapability, PairingCapabilityText, RelayEndpoint, RelayTransport,
};
use KonclaveCryptographicCore::{
    KonclaveCryptographicError, MlsWelcome, verify_device_credential_binding, verify_invitation,
    verify_pairing_control,
};
use KonclaveDomainCore::{
    AcknowledgeRequest, ConversationId, ConversationRole, DeviceId, PairingEnvelope, PairingId,
    PairingInvitationPayload, PairingMessageId, PairingStage, PairingWelcomePayload, ReplayRequest,
    StoredRelayEnvelope,
};
use KonclaveProtocolContracts::{KonclaveProtocolError, v1};
use thiserror::Error;

use crate::application::{
    ApplicationService, ApplicationServiceError, validate_acknowledgment, validate_replay_page,
};
use crate::conversation::{ConversationCoordinator, ConversationCoordinatorError};
use crate::pairing::{
    PairingObservationResult, PairingOperationState, PairingStateError, generate_pairing_message_id,
};
use crate::persistence::pairing::{PairingCheckpoint, PairingPhase, PairingRole};
use crate::persistence::{ProfileStore, ProfileStoreError};

const PAIRING_REPLAY_LIMIT: u32 = 8;
const ACTIVE_PAIRING_PAGE_SIZE: usize = 32;
const MAX_AUTHORIZATION_WINDOW_SECONDS: u64 = 15 * 60;
const COMPLETION_WINDOW_SECONDS: u64 = 300;
const COMPENSATION_ENVELOPE_EXPIRY: u64 = i64::MAX as u64;

/// Secret capability returned for the one explicit transfer operation.
///
/// This value implements neither `Clone` nor `Debug` and zeroizes its text on drop.
pub(crate) struct CreatedPairing {
    pub(crate) pairing_id: PairingId,
    pub(crate) capability: PairingCapabilityText,
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

/// Harness-neutral pairing composition over durable daemon and relay services.
pub(crate) struct PairingService<T> {
    conversations: ConversationCoordinator,
    applications: ApplicationService<T>,
    store: Arc<ProfileStore>,
    transport: Arc<T>,
    relay_endpoint: RelayEndpoint,
}

impl<T> Clone for PairingService<T> {
    fn clone(&self) -> Self {
        Self {
            conversations: self.conversations.clone(),
            applications: self.applications.clone(),
            store: Arc::clone(&self.store),
            transport: Arc::clone(&self.transport),
            relay_endpoint: self.relay_endpoint.clone(),
        }
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
        }
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
        require_authorization_window(now_unix_seconds, expires_at_unix_seconds)?;
        let conversations = self.conversations.clone();
        let relay_endpoint = self.relay_endpoint.clone();
        let capability = tokio::task::spawn_blocking(move || {
            conversations.issue_pairing_capability(
                relay_endpoint,
                requested_role,
                expires_at_unix_seconds,
                now_unix_seconds,
            )
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        let pairing_id = capability.offer().pairing_id();
        let capability_text = capability.encode()?;
        let state = PairingOperationState::new(PairingRole::Joiner, capability);
        self.reserve_state(&state).await?;
        Ok(CreatedPairing {
            pairing_id,
            capability: capability_text,
        })
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
        let mut recovered = 0_usize;
        let mut after = None;
        loop {
            let store = Arc::clone(&self.store);
            let page = tokio::task::spawn_blocking(move || {
                store.active_pairing_ids(after, ACTIVE_PAIRING_PAGE_SIZE)
            })
            .await
            .map_err(|_| PairingServiceError::Task)??;
            let page_length = page.len();
            after = page.last().copied();
            for pairing_id in page {
                self.retry_outbounds(pairing_id, now_unix_seconds).await?;
                recovered = recovered
                    .checked_add(1)
                    .ok_or(PairingServiceError::InvalidTransition)?;
            }
            if page_length < ACTIVE_PAIRING_PAGE_SIZE {
                return Ok(recovered);
            }
        }
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
        let checkpoint = self.load_checkpoint(pairing_id).await?;
        if checkpoint.role != PairingRole::Inviter {
            return Err(PairingServiceError::InvalidTransition);
        }
        let mut state = PairingOperationState::from_checkpoint(&checkpoint)?;
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
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
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
        self.retry_outbounds(pairing_id, now_unix_seconds).await
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
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
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
        self.retry_outbounds(pairing_id, now_unix_seconds).await
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
        if self
            .compensate_if_required(pairing_id, now_unix_seconds)
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
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
        }
        if checkpoint.phase == PairingPhase::Compensating {
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
        }
        if state.local_record(PairingStage::Cancellation)?.is_some() {
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
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
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
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
            return self.retry_outbounds(pairing_id, now_unix_seconds).await;
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
        self.retry_outbounds(pairing_id, now_unix_seconds).await
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
        if self
            .compensate_if_required(pairing_id, now_unix_seconds)
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
        let envelopes = page.envelopes().to_vec();
        for stored in &envelopes {
            self.process_stored(pairing_id, stored, now_unix_seconds)
                .await?;
            let acknowledgment = AcknowledgeRequest::new(checkpoint.routing_id, stored.cursor())
                .map_err(|_| PairingServiceError::InvalidRelayResponse)?;
            let effective = self.transport.acknowledge(acknowledgment).await?;
            validate_acknowledgment(acknowledgment, effective)
                .map_err(|_| PairingServiceError::InvalidRelayResponse)?;
            self.retry_outbounds(pairing_id, now_unix_seconds).await?;
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
        loop {
            if self
                .compensate_if_required(pairing_id, now_unix_seconds)
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
            (
                PairingRole::Inviter,
                PairingPhase::InviterAwaitingJoinProof,
                PairingStage::JoinProof,
            ) => {
                require_authorization_record(checkpoint, pairing)?;
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
                let conversation_id = state
                    .conversation_id()
                    .ok_or(PairingServiceError::InvalidTransition)?;
                let completion_deadline = completion_deadline(
                    checkpoint.authorization_deadline_unix_seconds,
                    now_unix_seconds,
                )?;
                let sent = self
                    .applications
                    .add_member(
                        conversation_id,
                        proof,
                        now_unix_seconds,
                        checkpoint.authorization_deadline_unix_seconds,
                    )
                    .await?;
                let welcome = sent.welcome.ok_or(PairingServiceError::InvalidTransition)?;
                let payload = PairingWelcomePayload::new(conversation_id, welcome, sent.cursor)
                    .map_err(KonclaveProtocolError::from)?;
                state.prepare_outbound(
                    PairingStage::Welcome,
                    Some(pairing.message_id()),
                    completion_deadline,
                    &v1::encode_pairing_welcome(&payload)?,
                )?;
                Ok((
                    PairingPhase::InviterAwaitingCompletion,
                    Some(completion_deadline),
                ))
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
        let conversation_id = state
            .conversation_id()
            .ok_or(PairingServiceError::InvalidTransition)?;
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
    ) -> Result<bool, PairingServiceError> {
        let mut checkpoint = self.load_checkpoint(pairing_id).await?;
        let state = PairingOperationState::from_checkpoint(&checkpoint)?;
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
            if now_unix_seconds < deadline {
                return Ok(false);
            }
            let state = PairingOperationState::from_checkpoint(&checkpoint)?;
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
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use KonclaveClientLibrary::{RelayTransport, RelayWatchSession};
    use KonclaveDomainCore::{
        AcknowledgeRequest, DeliveryClass, EnvelopeId, RelayEnvelope, ReplayPage, ReplayRequest,
        RoutingId, StoredRelayEnvelope,
    };
    use async_trait::async_trait;

    use super::*;
    use crate::conversation::tests::open_coordinator;

    const NOW: u64 = 1_700_000_000;
    const DEADLINE: u64 = NOW + 300;

    #[derive(Clone, Default)]
    struct MemoryRelay {
        routes: Arc<Mutex<BTreeMap<RoutingId, Vec<StoredRelayEnvelope>>>>,
        fail_next_pairing_submit: Arc<AtomicBool>,
        fail_next_group_commit_submit: Arc<AtomicBool>,
    }

    impl MemoryRelay {
        fn fail_next_pairing_submit(&self) {
            self.fail_next_pairing_submit.store(true, Ordering::SeqCst);
        }

        fn fail_next_group_commit_submit(&self) {
            self.fail_next_group_commit_submit
                .store(true, Ordering::SeqCst);
        }

        fn duplicate_latest_pairing_record(&self) -> u64 {
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
                EnvelopeId::from_bytes([0xfe; EnvelopeId::LENGTH]),
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

    fn service(
        conversations: ConversationCoordinator,
        relay: Arc<MemoryRelay>,
        endpoint: &RelayEndpoint,
    ) -> PairingService<MemoryRelay> {
        let applications =
            ApplicationService::from_shared(conversations.clone(), Arc::clone(&relay));
        PairingService::new(conversations, applications, endpoint.clone())
    }

    struct AwaitingCompletionFixture {
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

    async fn pairing_awaiting_completion() -> AwaitingCompletionFixture {
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
        inviter_service.replay_once(pairing_id, NOW).await.unwrap();
        AwaitingCompletionFixture {
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
    async fn cancellation_against_prior_frontier_compensates_a_concurrent_commit() {
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
        let conversation = inviter.open(conversation.conversation_id).unwrap();
        assert_eq!(conversation.group.epoch(), 2);
        assert!(
            conversation
                .group
                .state()
                .member(joiner_device_id)
                .is_none()
        );
    }
}
