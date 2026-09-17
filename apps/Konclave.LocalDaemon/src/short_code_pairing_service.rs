use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use KonclaveClientLibrary::{KonclaveClientError, PairingCapability, ShortCodePairingTransport};
use KonclaveCryptographicCore::{
    MAX_SHORT_CODE_PAIRING_PLAINTEXT_BYTES, ShortCodeOpaqueClientLogin,
    ShortCodeOpaqueServerRecord, ShortCodePairingChannel, ShortCodePairingCode,
    derive_short_code_pairing_transcript_hash, generate_short_code_capability_take_id,
    generate_short_code_pairing_attempt_id,
};
use KonclaveDomainCore::{
    ConversationRole, DeviceId, PairingId, ProtocolVersion, ShortCodeAttemptClaimRequest,
    ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest,
    ShortCodeAttemptSnapshot, ShortCodeCapabilityTakeRequest, ShortCodeConfirmationEvent,
    ShortCodeConfirmationRecord, ShortCodeConfirmationState, ShortCodeIdentityRecord,
    ShortCodePairingAttemptId, ShortCodePairingLocator, ShortCodePairingSas, ShortCodeRelayStage,
    transition_short_code_confirmation,
};
use KonclaveProtocolContracts::v1;
use KonclaveSecretStorage::AuthenticatedCiphertext;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use zeroize::Zeroizing;

use super::{PairingService, PairingServiceError, ProfileStoreError, require_before};
use crate::persistence::short_code_pairing::ShortCodeCheckpoint;
use crate::short_code_pairing::{ShortCodeOperationState, ShortCodePhase, ShortCodeRole};

const SHORT_CODE_LIFETIME_SECONDS: u64 = 10 * 60;
const ACTIVE_SHORT_CODE_PAGE_SIZE: usize = 16;
const MAX_SHORT_CODE_ADVANCES: usize = 12;

/// Secret code and non-secret status returned only by explicit creation.
pub(crate) struct CreatedShortCodePairing {
    pub(crate) code: Zeroizing<String>,
    pub(crate) status: ShortCodePairingStatus,
}

/// Non-secret status for one durable short-code verification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShortCodePairingStatus {
    pub(crate) attempt_id: ShortCodePairingAttemptId,
    pub(crate) role: ShortCodeRole,
    pub(crate) phase: ShortCodePhase,
    pub(crate) local_device_id: DeviceId,
    pub(crate) peer_device_id: Option<DeviceId>,
    pub(crate) sas: Option<ShortCodePairingSas>,
    pub(crate) deadline_unix_seconds: u64,
    pub(crate) local_confirmed: bool,
    pub(crate) peer_confirmed: bool,
    pub(crate) pairing_id: Option<PairingId>,
}

/// Result of one explicit bounded short-code synchronization.
pub(crate) struct ShortCodeSyncResult {
    pub(crate) processed_stages: usize,
    pub(crate) status: ShortCodePairingStatus,
}

#[derive(Clone, Default)]
pub(super) struct ShortCodeMutationLocks {
    gates: Arc<AsyncMutex<BTreeMap<ShortCodePairingLocator, Weak<AsyncMutex<()>>>>>,
}

impl ShortCodeMutationLocks {
    async fn acquire(&self, locator: ShortCodePairingLocator) -> OwnedMutexGuard<()> {
        let gate = {
            let mut gates = self.gates.lock().await;
            gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = gates.get(&locator).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(AsyncMutex::new(()));
                gates.insert(locator, Arc::downgrade(&gate));
                gate
            }
        };
        gate.lock_owned().await
    }
}

impl<T> PairingService<T>
where
    T: super::RelayTransport + ShortCodePairingTransport + 'static,
{
    /// Creates and publishes one six-digit OPAQUE attempt.
    ///
    /// # Errors
    ///
    /// Returns a clock, identity, cryptographic, relay, cleanup, or persistence error.
    pub(crate) async fn create_short_code_pairing(
        &self,
        now_unix_seconds: u64,
    ) -> Result<CreatedShortCodePairing, PairingServiceError> {
        let deadline = now_unix_seconds
            .checked_add(SHORT_CODE_LIFETIME_SECONDS)
            .ok_or(PairingServiceError::InvalidTransition)?;
        let code = ShortCodePairingCode::generate()?;
        let locator = code.locator();
        let attempt_id = generate_short_code_pairing_attempt_id()?;
        let local_device_id = self.local_device_id().await?;
        let server_record = ShortCodeOpaqueServerRecord::register(&code, attempt_id)?;
        let state = ShortCodeOperationState::creator(
            locator,
            attempt_id,
            deadline,
            local_device_id,
            server_record,
        );
        self.reserve_short_code_state(&state).await?;
        let publish = ShortCodeAttemptPublishRequest::new(
            ProtocolVersion::application_v1(),
            locator,
            attempt_id,
            deadline,
        )
        .map_err(|_| PairingServiceError::InvalidTransition)?;
        if let Err(error) = self.transport.publish_short_code_attempt(publish).await {
            self.cancel_short_code_by_locator(locator, now_unix_seconds)
                .await
                .map_err(|_| PairingServiceError::RendezvousCleanup)?;
            return Err(error.into());
        }
        let status = self.short_code_status(attempt_id).await?;
        Ok(CreatedShortCodePairing {
            code: Zeroizing::new(code.as_str().to_owned()),
            status,
        })
    }

    /// Claims one six-digit code and advances any immediately available stages.
    ///
    /// # Errors
    ///
    /// Returns an invalid code, relay, authentication, task, or persistence error.
    pub(crate) async fn claim_short_code_pairing(
        &self,
        code: &str,
        now_unix_seconds: u64,
    ) -> Result<ShortCodePairingStatus, PairingServiceError> {
        let code = ShortCodePairingCode::parse(code)?;
        let locator = code.locator();
        match self.load_short_code_by_locator(locator).await {
            Ok(existing) => {
                if existing.role != ShortCodeRole::Claimant {
                    return Err(PairingServiceError::InvalidTransition);
                }
                self.sync_short_code_by_locator(locator, now_unix_seconds)
                    .await?;
                let checkpoint = self.load_short_code_by_locator(locator).await?;
                if checkpoint.attempt_id.is_none() {
                    return Err(PairingServiceError::ShortCodeRejected);
                }
                return status_from_checkpoint(&checkpoint);
            }
            Err(PairingServiceError::Persistence(ProfileStoreError::OperationNotFound)) => {}
            Err(error) => return Err(error),
        }
        let local_device_id = self.local_device_id().await?;
        let (client_login, credential_request) = ShortCodeOpaqueClientLogin::start(code)?;
        let state = ShortCodeOperationState::claimant(
            locator,
            local_device_id,
            client_login,
            credential_request,
        );
        self.reserve_short_code_state(&state).await?;
        self.sync_short_code_by_locator(locator, now_unix_seconds)
            .await?;
        let checkpoint = self.load_short_code_by_locator(locator).await?;
        if checkpoint.attempt_id.is_none() {
            return Err(PairingServiceError::ShortCodeRejected);
        }
        status_from_checkpoint(&checkpoint)
    }

    /// Returns authenticated non-secret short-code state.
    ///
    /// # Errors
    ///
    /// Returns a task, missing-operation, state, or persistence error.
    pub(crate) async fn short_code_status(
        &self,
        attempt_id: ShortCodePairingAttemptId,
    ) -> Result<ShortCodePairingStatus, PairingServiceError> {
        let checkpoint = self.load_short_code(attempt_id).await?;
        status_from_checkpoint(&checkpoint)
    }

    async fn short_code_status_by_locator(
        &self,
        locator: ShortCodePairingLocator,
    ) -> Result<ShortCodePairingStatus, PairingServiceError> {
        let checkpoint = self.load_short_code_by_locator(locator).await?;
        status_from_checkpoint(&checkpoint)
    }

    /// Confirms the exact displayed attempt, peer identity, and SAS.
    ///
    /// # Errors
    ///
    /// Returns an expiry, mismatch, relay, task, cryptographic, or persistence error.
    pub(crate) async fn confirm_short_code_pairing(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        expected_peer_device_id: DeviceId,
        expected_sas: ShortCodePairingSas,
        now_unix_seconds: u64,
    ) -> Result<ShortCodePairingStatus, PairingServiceError> {
        let initial = self.load_short_code(attempt_id).await?;
        let locator = initial.locator;
        let _mutation = self.short_code_mutation_locks.acquire(locator).await;
        let checkpoint = self.load_short_code_by_locator(locator).await?;
        let mut state = checkpoint.state;
        let deadline = state
            .deadline_unix_seconds
            .ok_or(PairingServiceError::InvalidTransition)?;
        require_before(now_unix_seconds, deadline)?;
        if state.attempt_id != Some(attempt_id)
            || state.peer_device_id != Some(expected_peer_device_id)
            || state.sas != Some(expected_sas)
        {
            return Err(PairingServiceError::AuthorizationMismatch);
        }
        let local_already_confirmed = local_confirmed(state.confirmation);
        if !local_already_confirmed {
            let session = state
                .session
                .as_ref()
                .ok_or(PairingServiceError::InvalidTransition)?;
            let transcript = state
                .final_transcript_hash
                .ok_or(PairingServiceError::InvalidTransition)?;
            let confirmation = expected_confirmation(&state)?;
            let plaintext = v1::encode_short_code_confirmation_record(confirmation)?;
            let channel = local_confirmation_channel(state.role);
            let payload = seal_record(session, channel, attempt_id, transcript, &plaintext)?;
            state.local_confirmation = Some(payload);
            state.confirmation = transition_short_code_confirmation(
                state.confirmation,
                ShortCodeConfirmationEvent::LocalConfirmed,
                now_unix_seconds,
                deadline,
            )
            .map_err(|_| PairingServiceError::InvalidTransition)?;
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
        }
        let checkpoint = self.load_short_code_by_locator(locator).await?;
        if let Some(payload) = checkpoint.state.local_confirmation.as_deref() {
            self.publish_short_code_stage(
                attempt_id,
                local_confirmation_stage(checkpoint.role),
                payload,
            )
            .await?;
        }
        self.sync_short_code_locked(locator, now_unix_seconds)
            .await?;
        self.short_code_status_by_locator(locator).await
    }

    /// Synchronizes one bounded short-code exchange.
    ///
    /// # Errors
    ///
    /// Returns a relay, task, cryptographic, state, or persistence error.
    pub(crate) async fn sync_short_code_pairing(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        now_unix_seconds: u64,
    ) -> Result<ShortCodeSyncResult, PairingServiceError> {
        let checkpoint = self.load_short_code(attempt_id).await?;
        let processed_stages = self
            .sync_short_code_by_locator(checkpoint.locator, now_unix_seconds)
            .await?;
        Ok(ShortCodeSyncResult {
            processed_stages,
            status: self.short_code_status(attempt_id).await?,
        })
    }

    /// Cancels one active short-code exchange and any unreleased pairing reservation.
    ///
    /// # Errors
    ///
    /// Returns a relay, pairing-cleanup, task, or persistence error.
    pub(crate) async fn cancel_short_code_pairing(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        now_unix_seconds: u64,
    ) -> Result<ShortCodePairingStatus, PairingServiceError> {
        let checkpoint = self.load_short_code(attempt_id).await?;
        let locator = checkpoint.locator;
        self.cancel_short_code_by_locator(locator, now_unix_seconds)
            .await?;
        self.short_code_status_by_locator(locator).await
    }

    /// Runs ordinary pairing and short-code recovery under one supervisor sweep.
    ///
    /// # Errors
    ///
    /// Returns the first permanent pairing, relay, task, or persistence failure.
    pub(crate) async fn sync_all_active_once(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let pairings = self.sync_active_once(now_unix_seconds).await?;
        let short_codes = self.sync_active_short_codes_once(now_unix_seconds).await?;
        pairings
            .checked_add(short_codes)
            .ok_or(PairingServiceError::InvalidTransition)
    }

    async fn sync_active_short_codes_once(
        &self,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let _admitted = self
            .conversations
            .activity()
            .try_begin()
            .map_err(|_| PairingServiceError::ProfileClosing)?;
        let store = Arc::clone(&self.store);
        let locators = tokio::task::spawn_blocking(move || {
            store.active_short_code_pairing_locators(None, ACTIVE_SHORT_CODE_PAGE_SIZE)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        let mut processed = 0_usize;
        for locator in locators {
            processed = processed
                .checked_add(
                    self.sync_short_code_by_locator(locator, now_unix_seconds)
                        .await?,
                )
                .ok_or(PairingServiceError::InvalidTransition)?;
        }
        Ok(processed)
    }

    async fn sync_short_code_by_locator(
        &self,
        locator: ShortCodePairingLocator,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let _mutation = self.short_code_mutation_locks.acquire(locator).await;
        self.sync_short_code_locked(locator, now_unix_seconds).await
    }

    async fn sync_short_code_locked(
        &self,
        locator: ShortCodePairingLocator,
        now_unix_seconds: u64,
    ) -> Result<usize, PairingServiceError> {
        let mut processed = 0_usize;
        for _ in 0..MAX_SHORT_CODE_ADVANCES {
            let checkpoint = self.load_short_code_by_locator(locator).await?;
            if checkpoint.phase.is_terminal() {
                break;
            }
            let result = self.advance_short_code(checkpoint, now_unix_seconds).await;
            let advanced = match result {
                Ok(advanced) => advanced,
                Err(PairingServiceError::ShortCodeRejected) => {
                    self.cancel_short_code_locked(locator, now_unix_seconds)
                        .await?;
                    true
                }
                Err(error) => return Err(error),
            };
            if !advanced {
                break;
            }
            processed = processed
                .checked_add(1)
                .ok_or(PairingServiceError::InvalidTransition)?;
        }
        Ok(processed)
    }

    async fn advance_short_code(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<bool, PairingServiceError> {
        let deadline = checkpoint.deadline_unix_seconds;
        if deadline.is_some_and(|deadline| now_unix_seconds >= deadline) {
            self.cancel_short_code_locked(checkpoint.locator, now_unix_seconds)
                .await?;
            return Ok(true);
        }
        match checkpoint.phase {
            ShortCodePhase::CreatorAwaitingClaim => {
                self.advance_creator_claim(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::CreatorAwaitingFinalization => {
                self.advance_creator_finalization(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::CreatorAwaitingConfirmation => {
                self.advance_confirmation(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::CreatorPublishingCapability => {
                self.advance_creator_capability(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::ClaimantClaiming => {
                self.advance_claimant_claim(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::ClaimantAwaitingResponse => {
                self.advance_claimant_response(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::ClaimantAwaitingCreatorIdentity => {
                self.advance_claimant_identity(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::ClaimantAwaitingConfirmation => {
                self.advance_confirmation(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::ClaimantTakingCapability => {
                self.advance_claimant_capability(checkpoint, now_unix_seconds)
                    .await
            }
            ShortCodePhase::Cancelling => {
                self.finish_short_code_cancellation(checkpoint, now_unix_seconds)
                    .await?;
                Ok(true)
            }
            ShortCodePhase::CreatorCompleted
            | ShortCodePhase::ClaimantCompleted
            | ShortCodePhase::Cancelled => Ok(false),
        }
    }

    async fn advance_creator_claim(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<bool, PairingServiceError> {
        let snapshot = match self.read_short_code_snapshot(&checkpoint).await {
            Ok(snapshot) => snapshot,
            Err(error) if short_code_service_unavailable(&error) => {
                self.mark_short_code_cancelled(checkpoint, now_unix_seconds)
                    .await?;
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        let Some(request) = snapshot.message(ShortCodeRelayStage::CredentialRequest) else {
            return Ok(false);
        };
        let mut state = checkpoint.state;
        let attempt_id = required_attempt(&state)?;
        let server = state
            .server_record
            .as_ref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let (server_login, response) = server
            .start_login(attempt_id, request)
            .map_err(|_| PairingServiceError::ShortCodeRejected)?;
        state.credential_request = Some(request.to_vec());
        state.credential_response = Some(response);
        state.server_login = Some(server_login);
        state.phase = ShortCodePhase::CreatorAwaitingFinalization;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        let response = state
            .credential_response
            .as_deref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        self.publish_short_code_stage(
            attempt_id,
            ShortCodeRelayStage::CredentialResponse,
            response,
        )
        .await?;
        Ok(true)
    }

    async fn advance_creator_finalization(
        &self,
        checkpoint: ShortCodeCheckpoint,
        _: u64,
    ) -> Result<bool, PairingServiceError> {
        let attempt_id = checkpoint
            .attempt_id
            .ok_or(PairingServiceError::InvalidTransition)?;
        let response = checkpoint
            .state
            .credential_response
            .as_deref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        self.publish_short_code_stage(
            attempt_id,
            ShortCodeRelayStage::CredentialResponse,
            response,
        )
        .await?;
        let snapshot = self.read_short_code_snapshot(&checkpoint).await?;
        let Some(combined) = snapshot.message(ShortCodeRelayStage::ClaimantFinalization) else {
            return Ok(false);
        };
        let (finalization, claimant_identity_payload) =
            v1::decode_short_code_claimant_finalization_record(combined)
                .map_err(|_| PairingServiceError::ShortCodeRejected)?;
        let mut state = checkpoint.state;
        let session = state
            .server_login
            .take()
            .ok_or(PairingServiceError::InvalidTransition)?
            .finish(attempt_id, &finalization)
            .map_err(|_| PairingServiceError::ShortCodeRejected)?;
        let request = state
            .credential_request
            .as_deref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let response = state
            .credential_response
            .as_deref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let base = derive_short_code_pairing_transcript_hash(
            attempt_id,
            &[request, response, &finalization],
        )?;
        let claimant_identity = open_identity(
            &session,
            ShortCodePairingChannel::ClaimantIdentity,
            attempt_id,
            base,
            &claimant_identity_payload,
        )?;
        if claimant_identity.version() != ProtocolVersion::application_v1()
            || claimant_identity.attempt_id() != attempt_id
            || claimant_identity.device_id() == state.local_device_id
        {
            return Err(PairingServiceError::ShortCodeRejected);
        }
        let creator_identity =
            v1::encode_short_code_identity_record(ShortCodeIdentityRecord::new(
                ProtocolVersion::application_v1(),
                attempt_id,
                state.local_device_id,
            ))?;
        let creator_identity_payload = seal_record(
            &session,
            ShortCodePairingChannel::CreatorIdentity,
            attempt_id,
            base,
            &creator_identity,
        )?;
        let final_hash = derive_short_code_pairing_transcript_hash(
            attempt_id,
            &[
                request,
                response,
                &finalization,
                &claimant_identity_payload,
                &creator_identity_payload,
            ],
        )?;
        let sas = session.derive_sas(
            attempt_id,
            final_hash,
            state.local_device_id,
            claimant_identity.device_id(),
        )?;
        state.session = Some(session);
        state.base_transcript_hash = Some(base);
        state.final_transcript_hash = Some(final_hash);
        state.peer_device_id = Some(claimant_identity.device_id());
        state.sas = Some(sas);
        state.claimant_finalization = Some(combined.to_vec());
        state.creator_identity = Some(creator_identity_payload);
        state.phase = ShortCodePhase::CreatorAwaitingConfirmation;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        self.publish_short_code_stage(
            attempt_id,
            ShortCodeRelayStage::CreatorIdentity,
            state
                .creator_identity
                .as_deref()
                .ok_or(PairingServiceError::InvalidTransition)?,
        )
        .await?;
        Ok(true)
    }

    async fn advance_claimant_claim(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<bool, PairingServiceError> {
        let request = checkpoint
            .state
            .credential_request
            .as_deref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let claim = ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::application_v1(),
            checkpoint.locator,
            request.to_vec(),
        )
        .map_err(|_| PairingServiceError::InvalidTransition)?;
        let snapshot = match self.transport.claim_short_code_attempt(&claim).await {
            Ok(snapshot) => snapshot,
            Err(error) if short_code_unavailable(&error) => {
                self.mark_short_code_cancelled(checkpoint, now_unix_seconds)
                    .await?;
                return Ok(true);
            }
            Err(error) => return Err(error.into()),
        };
        validate_claim_snapshot(&snapshot, request, now_unix_seconds)?;
        let mut state = checkpoint.state;
        state.attempt_id = Some(snapshot.attempt_id());
        state.deadline_unix_seconds = Some(snapshot.deadline_unix_seconds());
        state.phase = ShortCodePhase::ClaimantAwaitingResponse;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        Ok(true)
    }

    async fn advance_claimant_response(
        &self,
        checkpoint: ShortCodeCheckpoint,
        _: u64,
    ) -> Result<bool, PairingServiceError> {
        let snapshot = self.read_short_code_snapshot(&checkpoint).await?;
        let Some(response) = snapshot.message(ShortCodeRelayStage::CredentialResponse) else {
            return Ok(false);
        };
        let mut state = checkpoint.state;
        let attempt_id = required_attempt(&state)?;
        let (finalization, session) = state
            .client_login
            .take()
            .ok_or(PairingServiceError::InvalidTransition)?
            .finish(attempt_id, response)
            .map_err(|_| PairingServiceError::ShortCodeRejected)?;
        let request = state
            .credential_request
            .as_deref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let base = derive_short_code_pairing_transcript_hash(
            attempt_id,
            &[request, response, &finalization],
        )?;
        let identity = v1::encode_short_code_identity_record(ShortCodeIdentityRecord::new(
            ProtocolVersion::application_v1(),
            attempt_id,
            state.local_device_id,
        ))?;
        let protected_identity = seal_record(
            &session,
            ShortCodePairingChannel::ClaimantIdentity,
            attempt_id,
            base,
            &identity,
        )?;
        let combined =
            v1::encode_short_code_claimant_finalization_record(&finalization, &protected_identity)?;
        state.credential_response = Some(response.to_vec());
        state.session = Some(session);
        state.base_transcript_hash = Some(base);
        state.claimant_finalization = Some(combined);
        state.phase = ShortCodePhase::ClaimantAwaitingCreatorIdentity;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        self.publish_short_code_stage(
            attempt_id,
            ShortCodeRelayStage::ClaimantFinalization,
            state
                .claimant_finalization
                .as_deref()
                .ok_or(PairingServiceError::InvalidTransition)?,
        )
        .await?;
        Ok(true)
    }

    async fn advance_claimant_identity(
        &self,
        checkpoint: ShortCodeCheckpoint,
        _: u64,
    ) -> Result<bool, PairingServiceError> {
        let attempt_id = checkpoint
            .attempt_id
            .ok_or(PairingServiceError::InvalidTransition)?;
        self.publish_short_code_stage(
            attempt_id,
            ShortCodeRelayStage::ClaimantFinalization,
            checkpoint
                .state
                .claimant_finalization
                .as_deref()
                .ok_or(PairingServiceError::InvalidTransition)?,
        )
        .await?;
        let snapshot = self.read_short_code_snapshot(&checkpoint).await?;
        let Some(creator_identity_payload) = snapshot.message(ShortCodeRelayStage::CreatorIdentity)
        else {
            return Ok(false);
        };
        let mut state = checkpoint.state;
        let session = state
            .session
            .as_ref()
            .ok_or(PairingServiceError::InvalidTransition)?;
        let base = state
            .base_transcript_hash
            .ok_or(PairingServiceError::InvalidTransition)?;
        let creator_identity = open_identity(
            session,
            ShortCodePairingChannel::CreatorIdentity,
            attempt_id,
            base,
            creator_identity_payload,
        )?;
        if creator_identity.version() != ProtocolVersion::application_v1()
            || creator_identity.attempt_id() != attempt_id
            || creator_identity.device_id() == state.local_device_id
        {
            return Err(PairingServiceError::ShortCodeRejected);
        }
        let (finalization, claimant_identity_payload) =
            v1::decode_short_code_claimant_finalization_record(
                state
                    .claimant_finalization
                    .as_deref()
                    .ok_or(PairingServiceError::InvalidTransition)?,
            )?;
        let final_hash = derive_short_code_pairing_transcript_hash(
            attempt_id,
            &[
                state
                    .credential_request
                    .as_deref()
                    .ok_or(PairingServiceError::InvalidTransition)?,
                state
                    .credential_response
                    .as_deref()
                    .ok_or(PairingServiceError::InvalidTransition)?,
                &finalization,
                &claimant_identity_payload,
                creator_identity_payload,
            ],
        )?;
        let sas = session.derive_sas(
            attempt_id,
            final_hash,
            creator_identity.device_id(),
            state.local_device_id,
        )?;
        state.creator_identity = Some(creator_identity_payload.to_vec());
        state.final_transcript_hash = Some(final_hash);
        state.peer_device_id = Some(creator_identity.device_id());
        state.sas = Some(sas);
        state.phase = ShortCodePhase::ClaimantAwaitingConfirmation;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        Ok(true)
    }

    async fn advance_confirmation(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<bool, PairingServiceError> {
        let attempt_id = checkpoint
            .attempt_id
            .ok_or(PairingServiceError::InvalidTransition)?;
        if let Some(identity) = checkpoint.state.creator_identity.as_deref() {
            let stage = match checkpoint.role {
                ShortCodeRole::Creator => ShortCodeRelayStage::CreatorIdentity,
                ShortCodeRole::Claimant => ShortCodeRelayStage::ClaimantFinalization,
            };
            let payload = match checkpoint.role {
                ShortCodeRole::Creator => identity,
                ShortCodeRole::Claimant => checkpoint
                    .state
                    .claimant_finalization
                    .as_deref()
                    .ok_or(PairingServiceError::InvalidTransition)?,
            };
            self.publish_short_code_stage(attempt_id, stage, payload)
                .await?;
        }
        if let Some(payload) = checkpoint.state.local_confirmation.as_deref() {
            self.publish_short_code_stage(
                attempt_id,
                local_confirmation_stage(checkpoint.role),
                payload,
            )
            .await?;
        }
        let snapshot = self.read_short_code_snapshot(&checkpoint).await?;
        let mut state = checkpoint.state;
        let mut changed = false;
        if !peer_confirmed(state.confirmation)
            && let Some(payload) = snapshot.message(peer_confirmation_stage(state.role))
        {
            let session = state
                .session
                .as_ref()
                .ok_or(PairingServiceError::InvalidTransition)?;
            let transcript = state
                .final_transcript_hash
                .ok_or(PairingServiceError::InvalidTransition)?;
            let plaintext = open_record(
                session,
                peer_confirmation_channel(state.role),
                attempt_id,
                transcript,
                payload,
            )?;
            let confirmation = v1::decode_short_code_confirmation_record(&plaintext)
                .map_err(|_| PairingServiceError::ShortCodeRejected)?;
            if confirmation != expected_confirmation(&state)? {
                return Err(PairingServiceError::ShortCodeRejected);
            }
            state.confirmation = transition_short_code_confirmation(
                state.confirmation,
                ShortCodeConfirmationEvent::PeerConfirmed,
                now_unix_seconds,
                state
                    .deadline_unix_seconds
                    .ok_or(PairingServiceError::InvalidTransition)?,
            )
            .map_err(|_| PairingServiceError::ShortCodeRejected)?;
            changed = true;
        }
        if state.confirmation == ShortCodeConfirmationState::Confirmed {
            state.phase = match state.role {
                ShortCodeRole::Creator => ShortCodePhase::CreatorPublishingCapability,
                ShortCodeRole::Claimant => ShortCodePhase::ClaimantTakingCapability,
            };
            changed = true;
        }
        if changed {
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
        }
        Ok(changed)
    }

    async fn advance_creator_capability(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<bool, PairingServiceError> {
        let mut state = checkpoint.state;
        let attempt_id = required_attempt(&state)?;
        let deadline = state
            .deadline_unix_seconds
            .ok_or(PairingServiceError::InvalidTransition)?;
        require_before(now_unix_seconds, deadline)?;
        if state.capability_text.is_none() {
            let capability = self
                .issue_capability(ConversationRole::Member, deadline, now_unix_seconds)
                .await?;
            if capability.offer().device_id() != state.local_device_id {
                return Err(PairingServiceError::AuthorizationMismatch);
            }
            let text = capability.encode()?;
            state.pairing_id = Some(capability.offer().pairing_id());
            state.capability_text = Some(Zeroizing::new(text.as_str().to_owned()));
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
            return Ok(true);
        }
        if state.capability_payload.is_none() {
            let text = state
                .capability_text
                .as_ref()
                .ok_or(PairingServiceError::InvalidTransition)?;
            let capability = PairingCapability::decode(text, now_unix_seconds)?;
            if capability.offer().pairing_id() != required_pairing(&state)?
                || capability.offer().requested_role() != ConversationRole::Member
                || capability.offer().device_id() != state.local_device_id
            {
                return Err(PairingServiceError::AuthorizationMismatch);
            }
            self.reserve_joiner_capability(capability).await?;
            let session = state
                .session
                .as_ref()
                .ok_or(PairingServiceError::InvalidTransition)?;
            let transcript = state
                .final_transcript_hash
                .ok_or(PairingServiceError::InvalidTransition)?;
            state.capability_payload = Some(seal_record(
                session,
                ShortCodePairingChannel::Capability,
                attempt_id,
                transcript,
                text.as_bytes(),
            )?);
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
            return Ok(true);
        }
        self.publish_short_code_stage(
            attempt_id,
            ShortCodeRelayStage::Capability,
            state
                .capability_payload
                .as_deref()
                .ok_or(PairingServiceError::InvalidTransition)?,
        )
        .await?;
        state.capability_text = None;
        state.phase = ShortCodePhase::CreatorCompleted;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        Ok(true)
    }

    async fn advance_claimant_capability(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<bool, PairingServiceError> {
        let mut state = checkpoint.state;
        let attempt_id = required_attempt(&state)?;
        if state.take_id.is_none() {
            state.take_id = Some(generate_short_code_capability_take_id()?);
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
            return Ok(true);
        }
        if state.capability_payload.is_none() {
            let request = ShortCodeCapabilityTakeRequest::new(
                ProtocolVersion::application_v1(),
                attempt_id,
                state
                    .take_id
                    .ok_or(PairingServiceError::InvalidTransition)?,
            );
            state.capability_payload =
                match self.transport.take_short_code_capability(request).await {
                    Ok(payload) => Some(payload),
                    Err(error) if short_code_unavailable(&error) => return Ok(false),
                    Err(error) => return Err(error.into()),
                };
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
            return Ok(true);
        }
        if state.capability_text.is_none() {
            let session = state
                .session
                .as_ref()
                .ok_or(PairingServiceError::InvalidTransition)?;
            let transcript = state
                .final_transcript_hash
                .ok_or(PairingServiceError::InvalidTransition)?;
            let plaintext = open_record(
                session,
                ShortCodePairingChannel::Capability,
                attempt_id,
                transcript,
                state
                    .capability_payload
                    .as_deref()
                    .ok_or(PairingServiceError::InvalidTransition)?,
            )?;
            let text = std::str::from_utf8(&plaintext)
                .map_err(|_| PairingServiceError::ShortCodeRejected)?;
            let capability = PairingCapability::decode(text, now_unix_seconds)
                .map_err(|_| PairingServiceError::ShortCodeRejected)?;
            if capability.offer().requested_role() != ConversationRole::Member
                || capability.offer().device_id()
                    != state
                        .peer_device_id
                        .ok_or(PairingServiceError::InvalidTransition)?
                || capability.relay_endpoint().as_str() != self.relay_endpoint.as_str()
            {
                return Err(PairingServiceError::ShortCodeRejected);
            }
            state.pairing_id = Some(capability.offer().pairing_id());
            state.capability_text = Some(Zeroizing::new(text.to_owned()));
            self.checkpoint_short_code(checkpoint.generation, &state)
                .await?;
            return Ok(true);
        }
        let capability = PairingCapability::decode(
            state
                .capability_text
                .as_deref()
                .ok_or(PairingServiceError::InvalidTransition)?,
            now_unix_seconds,
        )?;
        if capability.offer().pairing_id() != required_pairing(&state)? {
            return Err(PairingServiceError::ShortCodeRejected);
        }
        self.redeem_decoded_capability(capability, now_unix_seconds)
            .await?;
        state.capability_text = None;
        state.phase = ShortCodePhase::ClaimantCompleted;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        Ok(true)
    }

    async fn read_short_code_snapshot(
        &self,
        checkpoint: &ShortCodeCheckpoint,
    ) -> Result<ShortCodeAttemptSnapshot, PairingServiceError> {
        let request = ShortCodeAttemptReadRequest::new(
            ProtocolVersion::application_v1(),
            checkpoint
                .attempt_id
                .ok_or(PairingServiceError::InvalidTransition)?,
        );
        let snapshot = self.transport.read_short_code_attempt(request).await?;
        if snapshot.version() != request.version()
            || snapshot.attempt_id() != request.attempt_id()
            || snapshot.deadline_unix_seconds()
                != checkpoint
                    .deadline_unix_seconds
                    .ok_or(PairingServiceError::InvalidTransition)?
            || snapshot.cancelled()
        {
            return Err(PairingServiceError::ShortCodeRejected);
        }
        Ok(snapshot)
    }

    async fn publish_short_code_stage(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        stage: ShortCodeRelayStage,
        payload: &[u8],
    ) -> Result<(), PairingServiceError> {
        let request = ShortCodeAttemptMessageRequest::new(
            ProtocolVersion::application_v1(),
            attempt_id,
            stage,
            payload.to_vec(),
        )
        .map_err(|_| PairingServiceError::InvalidTransition)?;
        match self.transport.publish_short_code_message(&request).await {
            Ok(_) => Ok(()),
            Err(error) if short_code_conflict(&error) || short_code_unavailable(&error) => {
                Err(PairingServiceError::ShortCodeRejected)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn cancel_short_code_by_locator(
        &self,
        locator: ShortCodePairingLocator,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let _mutation = self.short_code_mutation_locks.acquire(locator).await;
        self.cancel_short_code_locked(locator, now_unix_seconds)
            .await
    }

    async fn cancel_short_code_locked(
        &self,
        locator: ShortCodePairingLocator,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let checkpoint = self.load_short_code_by_locator(locator).await?;
        if checkpoint.phase == ShortCodePhase::Cancelled {
            return Ok(());
        }
        if matches!(
            checkpoint.phase,
            ShortCodePhase::CreatorCompleted | ShortCodePhase::ClaimantCompleted
        ) {
            return Err(PairingServiceError::InvalidTransition);
        }
        if checkpoint.phase == ShortCodePhase::ClaimantClaiming {
            return self
                .mark_short_code_cancelled(checkpoint, now_unix_seconds)
                .await;
        }
        let mut state = checkpoint.state;
        state.phase = ShortCodePhase::Cancelling;
        state.confirmation = ShortCodeConfirmationState::Cancelled;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        let checkpoint = self.load_short_code_by_locator(locator).await?;
        self.finish_short_code_cancellation(checkpoint, now_unix_seconds)
            .await
    }

    async fn finish_short_code_cancellation(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        let attempt_id = checkpoint
            .attempt_id
            .ok_or(PairingServiceError::InvalidTransition)?;
        let request =
            ShortCodeAttemptReadRequest::new(ProtocolVersion::application_v1(), attempt_id);
        match self.transport.cancel_short_code_attempt(request).await {
            Ok(()) => {}
            Err(error) if short_code_unavailable(&error) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(pairing_id) = checkpoint.pairing_id {
            self.cancel(pairing_id, now_unix_seconds).await?;
        }
        self.mark_short_code_cancelled(checkpoint, now_unix_seconds)
            .await
    }

    async fn mark_short_code_cancelled(
        &self,
        checkpoint: ShortCodeCheckpoint,
        now_unix_seconds: u64,
    ) -> Result<(), PairingServiceError> {
        if checkpoint.phase == ShortCodePhase::Cancelled {
            return Ok(());
        }
        let mut state = checkpoint.state;
        state.phase = ShortCodePhase::Cancelled;
        state.confirmation = ShortCodeConfirmationState::Cancelled;
        state.deadline_unix_seconds = state.deadline_unix_seconds.or(Some(now_unix_seconds));
        state.capability_text = None;
        self.checkpoint_short_code(checkpoint.generation, &state)
            .await?;
        Ok(())
    }

    async fn local_device_id(&self) -> Result<DeviceId, PairingServiceError> {
        let conversations = self.conversations.clone();
        tokio::task::spawn_blocking(move || conversations.device_id())
            .await
            .map_err(|_| PairingServiceError::Task)?
            .map_err(Into::into)
    }

    async fn reserve_short_code_state(
        &self,
        state: &ShortCodeOperationState,
    ) -> Result<(), PairingServiceError> {
        let encoded = state
            .encode()
            .map_err(PairingServiceError::ShortCodeState)?;
        let state = ShortCodeOperationState::decode(&encoded)
            .map_err(PairingServiceError::ShortCodeState)?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.reserve_short_code_pairing(&state))
            .await
            .map_err(|_| PairingServiceError::Task)??;
        Ok(())
    }

    async fn load_short_code(
        &self,
        attempt_id: ShortCodePairingAttemptId,
    ) -> Result<ShortCodeCheckpoint, PairingServiceError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.load_short_code_pairing(attempt_id))
            .await
            .map_err(|_| PairingServiceError::Task)?
            .map_err(Into::into)
    }

    async fn load_short_code_by_locator(
        &self,
        locator: ShortCodePairingLocator,
    ) -> Result<ShortCodeCheckpoint, PairingServiceError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.load_short_code_pairing_by_locator(locator))
            .await
            .map_err(|_| PairingServiceError::Task)?
            .map_err(Into::into)
    }

    async fn checkpoint_short_code(
        &self,
        generation: u64,
        state: &ShortCodeOperationState,
    ) -> Result<(), PairingServiceError> {
        let encoded = state
            .encode()
            .map_err(PairingServiceError::ShortCodeState)?;
        let state = ShortCodeOperationState::decode(&encoded)
            .map_err(PairingServiceError::ShortCodeState)?;
        let locator = state.locator;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            store.checkpoint_short_code_pairing(locator, generation, &state)
        })
        .await
        .map_err(|_| PairingServiceError::Task)??;
        Ok(())
    }
}

fn status_from_checkpoint(
    checkpoint: &ShortCodeCheckpoint,
) -> Result<ShortCodePairingStatus, PairingServiceError> {
    Ok(ShortCodePairingStatus {
        attempt_id: checkpoint
            .attempt_id
            .ok_or(PairingServiceError::InvalidTransition)?,
        role: checkpoint.role,
        phase: checkpoint.phase,
        local_device_id: checkpoint.state.local_device_id,
        peer_device_id: checkpoint.state.peer_device_id,
        sas: checkpoint.state.sas,
        deadline_unix_seconds: checkpoint
            .deadline_unix_seconds
            .ok_or(PairingServiceError::InvalidTransition)?,
        local_confirmed: local_confirmed(checkpoint.state.confirmation),
        peer_confirmed: peer_confirmed(checkpoint.state.confirmation),
        pairing_id: checkpoint.pairing_id,
    })
}

fn validate_claim_snapshot(
    snapshot: &ShortCodeAttemptSnapshot,
    expected_credential_request: &[u8],
    now_unix_seconds: u64,
) -> Result<(), PairingServiceError> {
    if snapshot.version() != ProtocolVersion::application_v1()
        || snapshot.cancelled()
        || snapshot.deadline_unix_seconds() <= now_unix_seconds
        || snapshot.deadline_unix_seconds()
            > now_unix_seconds.saturating_add(SHORT_CODE_LIFETIME_SECONDS)
        || snapshot.message(ShortCodeRelayStage::CredentialRequest)
            != Some(expected_credential_request)
    {
        Err(PairingServiceError::ShortCodeRejected)
    } else {
        Ok(())
    }
}

fn required_attempt(
    state: &ShortCodeOperationState,
) -> Result<ShortCodePairingAttemptId, PairingServiceError> {
    state
        .attempt_id
        .ok_or(PairingServiceError::InvalidTransition)
}

fn required_pairing(state: &ShortCodeOperationState) -> Result<PairingId, PairingServiceError> {
    state
        .pairing_id
        .ok_or(PairingServiceError::InvalidTransition)
}

fn expected_confirmation(
    state: &ShortCodeOperationState,
) -> Result<ShortCodeConfirmationRecord, PairingServiceError> {
    let attempt_id = required_attempt(state)?;
    let peer = state
        .peer_device_id
        .ok_or(PairingServiceError::InvalidTransition)?;
    let (creator, claimant) = match state.role {
        ShortCodeRole::Creator => (state.local_device_id, peer),
        ShortCodeRole::Claimant => (peer, state.local_device_id),
    };
    Ok(ShortCodeConfirmationRecord::new(
        ProtocolVersion::application_v1(),
        attempt_id,
        creator,
        claimant,
        state
            .final_transcript_hash
            .ok_or(PairingServiceError::InvalidTransition)?,
        state.sas.ok_or(PairingServiceError::InvalidTransition)?,
    ))
}

fn seal_record(
    session: &KonclaveCryptographicCore::ShortCodeOpaqueSession,
    channel: ShortCodePairingChannel,
    attempt_id: ShortCodePairingAttemptId,
    transcript: KonclaveDomainCore::ShortCodePairingTranscriptHash,
    plaintext: &[u8],
) -> Result<Vec<u8>, PairingServiceError> {
    let ciphertext = session.seal(channel, attempt_id, transcript, plaintext)?;
    v1::encode_short_code_protected_record(ciphertext.nonce(), ciphertext.as_bytes())
        .map_err(Into::into)
}

fn open_record(
    session: &KonclaveCryptographicCore::ShortCodeOpaqueSession,
    channel: ShortCodePairingChannel,
    attempt_id: ShortCodePairingAttemptId,
    transcript: KonclaveDomainCore::ShortCodePairingTranscriptHash,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PairingServiceError> {
    let (nonce, ciphertext) = v1::decode_short_code_protected_record(payload)
        .map_err(|_| PairingServiceError::ShortCodeRejected)?;
    let ciphertext = AuthenticatedCiphertext::from_parts(
        &nonce,
        ciphertext,
        MAX_SHORT_CODE_PAIRING_PLAINTEXT_BYTES,
    )
    .map_err(|_| PairingServiceError::ShortCodeRejected)?;
    session
        .open(channel, attempt_id, transcript, &ciphertext)
        .map_err(|_| PairingServiceError::ShortCodeRejected)
}

fn open_identity(
    session: &KonclaveCryptographicCore::ShortCodeOpaqueSession,
    channel: ShortCodePairingChannel,
    attempt_id: ShortCodePairingAttemptId,
    transcript: KonclaveDomainCore::ShortCodePairingTranscriptHash,
    payload: &[u8],
) -> Result<ShortCodeIdentityRecord, PairingServiceError> {
    let plaintext = open_record(session, channel, attempt_id, transcript, payload)?;
    v1::decode_short_code_identity_record(&plaintext)
        .map_err(|_| PairingServiceError::ShortCodeRejected)
}

const fn local_confirmed(state: ShortCodeConfirmationState) -> bool {
    matches!(
        state,
        ShortCodeConfirmationState::AwaitingPeer | ShortCodeConfirmationState::Confirmed
    )
}

const fn peer_confirmed(state: ShortCodeConfirmationState) -> bool {
    matches!(
        state,
        ShortCodeConfirmationState::AwaitingLocal | ShortCodeConfirmationState::Confirmed
    )
}

const fn local_confirmation_channel(role: ShortCodeRole) -> ShortCodePairingChannel {
    match role {
        ShortCodeRole::Creator => ShortCodePairingChannel::CreatorConfirmation,
        ShortCodeRole::Claimant => ShortCodePairingChannel::ClaimantConfirmation,
    }
}

const fn peer_confirmation_channel(role: ShortCodeRole) -> ShortCodePairingChannel {
    match role {
        ShortCodeRole::Creator => ShortCodePairingChannel::ClaimantConfirmation,
        ShortCodeRole::Claimant => ShortCodePairingChannel::CreatorConfirmation,
    }
}

const fn local_confirmation_stage(role: ShortCodeRole) -> ShortCodeRelayStage {
    match role {
        ShortCodeRole::Creator => ShortCodeRelayStage::CreatorConfirmation,
        ShortCodeRole::Claimant => ShortCodeRelayStage::ClaimantConfirmation,
    }
}

const fn peer_confirmation_stage(role: ShortCodeRole) -> ShortCodeRelayStage {
    match role {
        ShortCodeRole::Creator => ShortCodeRelayStage::ClaimantConfirmation,
        ShortCodeRole::Claimant => ShortCodeRelayStage::CreatorConfirmation,
    }
}

fn short_code_unavailable(error: &KonclaveClientError) -> bool {
    matches!(
        error,
        KonclaveClientError::RelayRejected {
            status: 404 | 410,
            ..
        }
    )
}

fn short_code_service_unavailable(error: &PairingServiceError) -> bool {
    matches!(error, PairingServiceError::Client(error) if short_code_unavailable(error))
}

fn short_code_conflict(error: &KonclaveClientError) -> bool {
    matches!(
        error,
        KonclaveClientError::RelayRejected { status: 409, .. }
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use KonclaveClientLibrary::{
        RelayEndpoint, RelayTransport, RelayWatchSession, ShortCodeAttemptMessageResult,
        ShortCodeAttemptPublishResult,
    };
    use KonclaveDomainCore::{
        AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest, ShortCodeRelayMessage,
        StoredRelayEnvelope,
    };
    use KonclaveRelayCore::{
        RelayError, RelayPrincipalId, ShortCodeCapabilityDecision, ShortCodeClaimDecision,
        ShortCodeMessageDecision, ShortCodePublishDecision, StoredShortCodeAttempt,
        authorize_short_code_cancel, authorize_short_code_read, decide_short_code_capability_take,
        decide_short_code_claim, decide_short_code_message, decide_short_code_publish,
    };
    use async_trait::async_trait;

    use super::*;
    use crate::application::ApplicationService;
    use crate::conversation::tests::open_coordinator;
    use crate::persistence::pairing::PairingPhase;

    const NOW: u64 = 1_700_000_000;

    #[derive(Default)]
    struct MemoryCore {
        routes: BTreeMap<KonclaveDomainCore::RoutingId, Vec<StoredRelayEnvelope>>,
        attempts: BTreeMap<ShortCodePairingLocator, StoredShortCodeAttempt>,
        tamper_creator_identity_for: Option<RelayPrincipalId>,
        fail_after_capability_publish: bool,
    }

    #[derive(Clone)]
    struct MemoryShortCodeRelay {
        core: Arc<Mutex<MemoryCore>>,
        principal: RelayPrincipalId,
    }

    impl MemoryShortCodeRelay {
        fn new(core: Arc<Mutex<MemoryCore>>, principal: u8) -> Self {
            Self {
                core,
                principal: RelayPrincipalId::from_bytes([principal; RelayPrincipalId::LENGTH]),
            }
        }

        fn capability_count(&self) -> usize {
            self.core
                .lock()
                .unwrap()
                .attempts
                .values()
                .filter(|attempt| attempt.message(ShortCodeRelayStage::Capability).is_some())
                .count()
        }

        fn contains_plaintext(&self, value: &[u8]) -> bool {
            self.core
                .lock()
                .unwrap()
                .attempts
                .values()
                .flat_map(|attempt| attempt.messages().values())
                .any(|payload| payload.windows(value.len()).any(|window| window == value))
        }

        fn tamper_creator_identity_for(&self, principal: RelayPrincipalId) {
            self.core.lock().unwrap().tamper_creator_identity_for = Some(principal);
        }

        fn fail_after_capability_publish(&self) {
            self.core.lock().unwrap().fail_after_capability_publish = true;
        }
    }

    #[async_trait]
    impl RelayTransport for MemoryShortCodeRelay {
        async fn submit(
            &self,
            envelope: &RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            let mut core = self.core.lock().unwrap();
            let route = core.routes.entry(envelope.routing_id()).or_default();
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
            let core = self.core.lock().unwrap();
            let records = core.routes.get(&request.routing_id());
            let envelopes = records
                .into_iter()
                .flatten()
                .filter(|stored| stored.cursor() > request.after_cursor())
                .take(request.limit() as usize)
                .cloned()
                .collect::<Vec<_>>();
            let next_cursor = envelopes
                .last()
                .map_or(request.after_cursor(), StoredRelayEnvelope::cursor);
            ReplayPage::new(envelopes, next_cursor, false)
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
    impl ShortCodePairingTransport for MemoryShortCodeRelay {
        async fn publish_short_code_attempt(
            &self,
            request: ShortCodeAttemptPublishRequest,
        ) -> Result<ShortCodeAttemptPublishResult, KonclaveClientError> {
            let mut core = self.core.lock().unwrap();
            let existing = core.attempts.get(&request.locator());
            let decision = decide_short_code_publish(
                self.principal,
                request,
                existing,
                NOW,
                core.attempts.len(),
                core.attempts
                    .values()
                    .filter(|attempt| attempt.owner() == self.principal)
                    .count(),
            )
            .map_err(client_relay_error)?;
            match decision {
                ShortCodePublishDecision::Insert => {
                    core.attempts.insert(
                        request.locator(),
                        StoredShortCodeAttempt::new(self.principal, request),
                    );
                    Ok(ShortCodeAttemptPublishResult::Published)
                }
                ShortCodePublishDecision::Identical => {
                    Ok(ShortCodeAttemptPublishResult::AlreadyPublished)
                }
            }
        }

        async fn claim_short_code_attempt(
            &self,
            request: &ShortCodeAttemptClaimRequest,
        ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError> {
            let mut core = self.core.lock().unwrap();
            let attempt = core
                .attempts
                .get_mut(&request.locator())
                .ok_or_else(unavailable)?;
            match decide_short_code_claim(self.principal, request, Some(&*attempt), NOW, 0, 0)
                .map_err(client_relay_error)?
            {
                ShortCodeClaimDecision::Claim => {
                    attempt
                        .set_claim(self.principal, request.payload().to_vec())
                        .map_err(client_relay_error)?;
                }
                ShortCodeClaimDecision::Identical => {}
            }
            snapshot(attempt)
        }

        async fn publish_short_code_message(
            &self,
            request: &ShortCodeAttemptMessageRequest,
        ) -> Result<ShortCodeAttemptMessageResult, KonclaveClientError> {
            let mut core = self.core.lock().unwrap();
            let attempt = core
                .attempts
                .values_mut()
                .find(|attempt| attempt.publish().attempt_id() == request.attempt_id())
                .ok_or_else(unavailable)?;
            let outcome = match decide_short_code_message(self.principal, request, attempt, NOW)
                .map_err(client_relay_error)?
            {
                ShortCodeMessageDecision::Insert => {
                    attempt
                        .insert_message(request.stage(), request.payload().to_vec())
                        .map_err(client_relay_error)?;
                    ShortCodeAttemptMessageResult::Published
                }
                ShortCodeMessageDecision::Identical => {
                    ShortCodeAttemptMessageResult::AlreadyPublished
                }
            };
            if request.stage() == ShortCodeRelayStage::Capability
                && core.fail_after_capability_publish
            {
                core.fail_after_capability_publish = false;
                return Err(KonclaveClientError::TransportUnavailable);
            }
            Ok(outcome)
        }

        async fn read_short_code_attempt(
            &self,
            request: ShortCodeAttemptReadRequest,
        ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError> {
            let core = self.core.lock().unwrap();
            let attempt = core
                .attempts
                .values()
                .find(|attempt| attempt.publish().attempt_id() == request.attempt_id())
                .ok_or_else(unavailable)?;
            authorize_short_code_read(self.principal, request, attempt, NOW)
                .map_err(client_relay_error)?;
            let snapshot = snapshot(attempt)?;
            if core.tamper_creator_identity_for == Some(self.principal) {
                tamper_creator_identity(snapshot)
            } else {
                Ok(snapshot)
            }
        }

        async fn cancel_short_code_attempt(
            &self,
            request: ShortCodeAttemptReadRequest,
        ) -> Result<(), KonclaveClientError> {
            let mut core = self.core.lock().unwrap();
            let attempt = core
                .attempts
                .values_mut()
                .find(|attempt| attempt.publish().attempt_id() == request.attempt_id())
                .ok_or_else(unavailable)?;
            authorize_short_code_cancel(self.principal, request, attempt)
                .map_err(client_relay_error)?;
            attempt.cancel();
            Ok(())
        }

        async fn take_short_code_capability(
            &self,
            request: ShortCodeCapabilityTakeRequest,
        ) -> Result<Vec<u8>, KonclaveClientError> {
            let mut core = self.core.lock().unwrap();
            let attempt = core
                .attempts
                .values_mut()
                .find(|attempt| attempt.publish().attempt_id() == request.attempt_id())
                .ok_or_else(unavailable)?;
            let decision = decide_short_code_capability_take(self.principal, request, attempt, NOW)
                .map_err(client_relay_error)?;
            let payload = attempt
                .message(ShortCodeRelayStage::Capability)
                .ok_or(KonclaveClientError::InvalidResponse)?
                .to_vec();
            if decision == ShortCodeCapabilityDecision::Consume {
                attempt.consume_capability(request.take_id());
            }
            Ok(payload)
        }
    }

    fn snapshot(
        attempt: &StoredShortCodeAttempt,
    ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError> {
        let messages = attempt
            .messages()
            .iter()
            .filter(|(stage, _)| **stage != ShortCodeRelayStage::Capability)
            .map(|(stage, payload)| ShortCodeRelayMessage::new(*stage, payload.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KonclaveClientError::InvalidResponse)?;
        ShortCodeAttemptSnapshot::new(
            attempt.publish().version(),
            attempt.publish().attempt_id(),
            attempt.publish().deadline_unix_seconds(),
            attempt.cancelled(),
            attempt.capability_consumed(),
            messages,
        )
        .map_err(|_| KonclaveClientError::InvalidResponse)
    }

    fn tamper_creator_identity(
        snapshot: ShortCodeAttemptSnapshot,
    ) -> Result<ShortCodeAttemptSnapshot, KonclaveClientError> {
        let messages = snapshot
            .messages()
            .iter()
            .map(|message| {
                let mut payload = message.payload().to_vec();
                if message.stage() == ShortCodeRelayStage::CreatorIdentity {
                    let first = payload
                        .first_mut()
                        .ok_or(KonclaveClientError::InvalidResponse)?;
                    *first ^= 1;
                }
                ShortCodeRelayMessage::new(message.stage(), payload)
                    .map_err(|_| KonclaveClientError::InvalidResponse)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ShortCodeAttemptSnapshot::new(
            snapshot.version(),
            snapshot.attempt_id(),
            snapshot.deadline_unix_seconds(),
            snapshot.cancelled(),
            snapshot.capability_consumed(),
            messages,
        )
        .map_err(|_| KonclaveClientError::InvalidResponse)
    }

    fn client_relay_error(error: RelayError) -> KonclaveClientError {
        let status = match error {
            RelayError::ExpiredShortCodeAttempt => 410,
            RelayError::ShortCodeAttemptConflict | RelayError::InvalidShortCodeStage => 409,
            RelayError::ShortCodeAttemptUnavailable => 404,
            RelayError::ShortCodeClaimRateLimited
            | RelayError::ShortCodeGlobalCapacityExceeded
            | RelayError::ShortCodeCreatorCapacityExceeded => 429,
            _ => 422,
        };
        KonclaveClientError::RelayRejected {
            status,
            relay_code: error.code().to_string(),
        }
    }

    fn unavailable() -> KonclaveClientError {
        KonclaveClientError::RelayRejected {
            status: 404,
            relay_code: "relay_short_code_pairing_unavailable".to_string(),
        }
    }

    fn service(
        conversations: crate::conversation::ConversationCoordinator,
        transport: MemoryShortCodeRelay,
        endpoint: &RelayEndpoint,
    ) -> PairingService<MemoryShortCodeRelay> {
        let applications = ApplicationService::new(conversations.clone(), transport);
        PairingService::new(conversations, applications, endpoint.clone())
    }

    #[tokio::test]
    async fn mutual_confirmation_releases_one_member_capability_and_existing_pairing() {
        let root = tempfile::tempdir().unwrap();
        let creator = open_coordinator(root.path(), "short-code-creator");
        let claimant = open_coordinator(root.path(), "short-code-claimant");
        let creator_device_id = creator.device_id().unwrap();
        let claimant_device_id = claimant.device_id().unwrap();
        let core = Arc::new(Mutex::new(MemoryCore::default()));
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let creator_transport = MemoryShortCodeRelay::new(Arc::clone(&core), 1);
        let claimant_transport = MemoryShortCodeRelay::new(Arc::clone(&core), 2);
        let creator_service = service(creator.clone(), creator_transport.clone(), &endpoint);
        let claimant_service = service(claimant.clone(), claimant_transport, &endpoint);

        let created = creator_service
            .create_short_code_pairing(NOW)
            .await
            .unwrap();
        let attempt_id = created.status.attempt_id;
        let mut claimant_status = claimant_service
            .claim_short_code_pairing(&created.code, NOW)
            .await
            .unwrap();
        let mut creator_status = created.status;
        for _ in 0..8 {
            creator_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await
                .unwrap();
            claimant_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await
                .unwrap();
            creator_status = creator_service.short_code_status(attempt_id).await.unwrap();
            claimant_status = claimant_service
                .short_code_status(attempt_id)
                .await
                .unwrap();
            if creator_status.sas.is_some() && claimant_status.sas.is_some() {
                break;
            }
        }
        assert_eq!(creator_status.peer_device_id, Some(claimant_device_id));
        assert_eq!(claimant_status.peer_device_id, Some(creator_device_id));
        assert_eq!(
            creator_status.sas.unwrap().value(),
            claimant_status.sas.unwrap().value()
        );
        assert!(matches!(
            creator_service
                .confirm_short_code_pairing(
                    attempt_id,
                    DeviceId::from_bytes([0xfe; DeviceId::LENGTH]),
                    creator_status.sas.unwrap(),
                    NOW,
                )
                .await,
            Err(PairingServiceError::AuthorizationMismatch)
        ));
        assert_eq!(creator_transport.capability_count(), 0);

        creator_service
            .confirm_short_code_pairing(
                attempt_id,
                claimant_device_id,
                creator_status.sas.unwrap(),
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(creator_transport.capability_count(), 0);
        claimant_service
            .confirm_short_code_pairing(
                attempt_id,
                creator_device_id,
                claimant_status.sas.unwrap(),
                NOW,
            )
            .await
            .unwrap();
        for _ in 0..12 {
            if let Err(error) = creator_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await
            {
                panic!("creator short-code sync failed: {error:?}");
            }
            if let Err(error) = claimant_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await
            {
                panic!("claimant short-code sync failed: {error:?}");
            }
            creator_status = creator_service.short_code_status(attempt_id).await.unwrap();
            claimant_status = claimant_service
                .short_code_status(attempt_id)
                .await
                .unwrap();
            if creator_status.pairing_id.is_some() && claimant_status.pairing_id.is_some() {
                break;
            }
        }
        let pairing_id = creator_status.pairing_id.unwrap();
        assert_eq!(claimant_status.pairing_id, Some(pairing_id));
        assert_eq!(creator_transport.capability_count(), 1);
        assert!(!creator_transport.contains_plaintext(creator_device_id.as_bytes()));
        assert!(!creator_transport.contains_plaintext(claimant_device_id.as_bytes()));
        assert!(
            !creator_transport.contains_plaintext(creator_status.sas.unwrap().to_text().as_bytes())
        );
        assert_eq!(
            creator_service
                .status(pairing_id)
                .await
                .unwrap()
                .requested_role,
            ConversationRole::Member
        );
        assert_eq!(
            claimant_service
                .status(pairing_id)
                .await
                .unwrap()
                .requested_role,
            ConversationRole::Member
        );

        let conversation = claimant.create().unwrap();
        claimant_service
            .authorize_joiner(
                pairing_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        creator_service.replay_once(pairing_id, NOW).await.unwrap();
        assert!(matches!(
            creator_service
                .authorize_inviter(
                    pairing_id,
                    DeviceId::from_bytes([0xff; DeviceId::LENGTH]),
                    conversation.conversation_id,
                    ConversationRole::Member,
                    NOW,
                )
                .await,
            Err(PairingServiceError::AuthorizationMismatch)
        ));
        creator_service
            .authorize_inviter(
                pairing_id,
                claimant_device_id,
                conversation.conversation_id,
                ConversationRole::Member,
                NOW,
            )
            .await
            .unwrap();
        claimant_service.replay_once(pairing_id, NOW).await.unwrap();
        creator_service.replay_once(pairing_id, NOW).await.unwrap();
        claimant_service.replay_once(pairing_id, NOW).await.unwrap();
        assert_eq!(
            creator_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::Completed
        );
        assert_eq!(
            claimant_service.status(pairing_id).await.unwrap().phase,
            PairingPhase::Completed
        );
        assert_eq!(
            creator
                .open(conversation.conversation_id)
                .unwrap()
                .group
                .state()
                .member(creator_device_id)
                .map(KonclaveDomainCore::Member::role),
            Some(ConversationRole::Member)
        );
    }

    #[tokio::test]
    async fn capability_publish_response_loss_keeps_verified_peer_binding_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let creator = open_coordinator(root.path(), "response-loss-creator");
        let claimant = open_coordinator(root.path(), "response-loss-claimant");
        let creator_device_id = creator.device_id().unwrap();
        let claimant_device_id = claimant.device_id().unwrap();
        let core = Arc::new(Mutex::new(MemoryCore::default()));
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let creator_transport = MemoryShortCodeRelay::new(Arc::clone(&core), 1);
        let creator_service = service(creator, creator_transport.clone(), &endpoint);
        let claimant_service = service(
            claimant,
            MemoryShortCodeRelay::new(Arc::clone(&core), 2),
            &endpoint,
        );
        let created = creator_service
            .create_short_code_pairing(NOW)
            .await
            .unwrap();
        let attempt_id = created.status.attempt_id;
        claimant_service
            .claim_short_code_pairing(&created.code, NOW)
            .await
            .unwrap();
        for _ in 0..8 {
            creator_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await
                .unwrap();
            claimant_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await
                .unwrap();
            if creator_service
                .short_code_status(attempt_id)
                .await
                .unwrap()
                .sas
                .is_some()
                && claimant_service
                    .short_code_status(attempt_id)
                    .await
                    .unwrap()
                    .sas
                    .is_some()
            {
                break;
            }
        }
        let creator_sas = creator_service
            .short_code_status(attempt_id)
            .await
            .unwrap()
            .sas
            .unwrap();
        let claimant_sas = claimant_service
            .short_code_status(attempt_id)
            .await
            .unwrap()
            .sas
            .unwrap();
        creator_service
            .confirm_short_code_pairing(attempt_id, claimant_device_id, creator_sas, NOW)
            .await
            .unwrap();
        claimant_service
            .confirm_short_code_pairing(attempt_id, creator_device_id, claimant_sas, NOW)
            .await
            .unwrap();
        creator_transport.fail_after_capability_publish();
        assert!(matches!(
            creator_service
                .sync_short_code_pairing(attempt_id, NOW)
                .await,
            Err(PairingServiceError::Client(
                KonclaveClientError::TransportUnavailable
            ))
        ));
        let status = creator_service.short_code_status(attempt_id).await.unwrap();
        assert_eq!(status.phase, ShortCodePhase::CreatorPublishingCapability);
        let pairing_id = status.pairing_id.unwrap();
        let conversation_id = KonclaveDomainCore::ConversationId::from_bytes([9; 32]);
        assert!(matches!(
            creator_service
                .authorize_inviter(
                    pairing_id,
                    DeviceId::from_bytes([0xff; DeviceId::LENGTH]),
                    conversation_id,
                    ConversationRole::Member,
                    NOW,
                )
                .await,
            Err(PairingServiceError::AuthorizationMismatch)
        ));
        assert!(matches!(
            creator_service
                .authorize_inviter(
                    pairing_id,
                    claimant_device_id,
                    conversation_id,
                    ConversationRole::Member,
                    NOW,
                )
                .await,
            Err(PairingServiceError::InvalidTransition)
        ));
        creator_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        assert_eq!(
            creator_service
                .short_code_status(attempt_id)
                .await
                .unwrap()
                .phase,
            ShortCodePhase::CreatorCompleted
        );
    }

    #[tokio::test]
    async fn wrong_code_cancels_without_creating_a_pairing_capability() {
        let root = tempfile::tempdir().unwrap();
        let creator = open_coordinator(root.path(), "wrong-code-creator");
        let claimant = open_coordinator(root.path(), "wrong-code-claimant");
        let core = Arc::new(Mutex::new(MemoryCore::default()));
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let creator_transport = MemoryShortCodeRelay::new(Arc::clone(&core), 1);
        let creator_service = service(creator.clone(), creator_transport.clone(), &endpoint);
        let claimant_service = service(
            claimant.clone(),
            MemoryShortCodeRelay::new(core, 2),
            &endpoint,
        );
        let created = creator_service
            .create_short_code_pairing(NOW)
            .await
            .unwrap();
        let wrong = if created.code.as_str() == "000000" {
            "000001"
        } else {
            "000000"
        };
        let attempt_id = created.status.attempt_id;
        assert!(matches!(
            claimant_service.claim_short_code_pairing(wrong, NOW).await,
            Err(PairingServiceError::ShortCodeRejected)
        ));
        assert_eq!(creator_transport.capability_count(), 0);
        assert!(
            creator
                .store()
                .active_pairing_ids(None, 1)
                .unwrap()
                .is_empty()
        );
        creator_service
            .cancel_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        assert!(
            claimant
                .store()
                .active_pairing_ids(None, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn relay_identity_substitution_cancels_without_releasing_authority() {
        let root = tempfile::tempdir().unwrap();
        let creator = open_coordinator(root.path(), "tamper-creator");
        let claimant = open_coordinator(root.path(), "tamper-claimant");
        let core = Arc::new(Mutex::new(MemoryCore::default()));
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let creator_transport = MemoryShortCodeRelay::new(Arc::clone(&core), 1);
        let claimant_transport = MemoryShortCodeRelay::new(core, 2);
        let creator_service = service(creator.clone(), creator_transport.clone(), &endpoint);
        let claimant_service = service(claimant.clone(), claimant_transport.clone(), &endpoint);
        let created = creator_service
            .create_short_code_pairing(NOW)
            .await
            .unwrap();
        let attempt_id = created.status.attempt_id;
        claimant_service
            .claim_short_code_pairing(&created.code, NOW)
            .await
            .unwrap();
        creator_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        claimant_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        creator_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        claimant_transport.tamper_creator_identity_for(claimant_transport.principal);
        claimant_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        creator_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();

        assert_eq!(
            claimant_service
                .short_code_status(attempt_id)
                .await
                .unwrap()
                .phase,
            ShortCodePhase::Cancelled
        );
        assert_eq!(
            creator_service
                .short_code_status(attempt_id)
                .await
                .unwrap()
                .phase,
            ShortCodePhase::Cancelled
        );
        assert_eq!(creator_transport.capability_count(), 0);
        assert!(
            creator
                .store()
                .active_pairing_ids(None, 1)
                .unwrap()
                .is_empty()
        );
        assert!(
            claimant
                .store()
                .active_pairing_ids(None, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn sealed_opaque_state_resumes_after_creator_restart() {
        let root = tempfile::tempdir().unwrap();
        let creator = open_coordinator(root.path(), "restart-creator");
        let claimant = open_coordinator(root.path(), "restart-claimant");
        let creator_device_id = creator.device_id().unwrap();
        let core = Arc::new(Mutex::new(MemoryCore::default()));
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let creator_transport = MemoryShortCodeRelay::new(Arc::clone(&core), 1);
        let claimant_service = service(
            claimant.clone(),
            MemoryShortCodeRelay::new(Arc::clone(&core), 2),
            &endpoint,
        );
        let creator_service = service(creator.clone(), creator_transport.clone(), &endpoint);
        let created = creator_service
            .create_short_code_pairing(NOW)
            .await
            .unwrap();
        let attempt_id = created.status.attempt_id;
        claimant_service
            .claim_short_code_pairing(&created.code, NOW)
            .await
            .unwrap();
        creator_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        drop(creator_service);
        drop(creator);

        claimant_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        let reopened_creator = open_coordinator(root.path(), "restart-creator");
        assert_eq!(reopened_creator.device_id().unwrap(), creator_device_id);
        let reopened_service = service(
            reopened_creator,
            MemoryShortCodeRelay::new(core, 1),
            &endpoint,
        );
        reopened_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        claimant_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        let creator_status = reopened_service
            .short_code_status(attempt_id)
            .await
            .unwrap();
        let claimant_status = claimant_service
            .short_code_status(attempt_id)
            .await
            .unwrap();
        assert!(creator_status.sas.is_some());
        assert_eq!(
            creator_status.sas.unwrap().value(),
            claimant_status.sas.unwrap().value()
        );
        claimant_service
            .cancel_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
        reopened_service
            .sync_short_code_pairing(attempt_id, NOW)
            .await
            .unwrap();
    }
}
