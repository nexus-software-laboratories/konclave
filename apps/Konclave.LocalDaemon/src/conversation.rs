pub(crate) use KonclaveClientLibrary::native::{
    PreparedApplication, PreparedMembership, ProcessedApplication, ProcessedMembership, OpenConversation,
};
use KonclaveClientLibrary::native::{NativeApplicationRequest, NativeConversationError, NativeConversationProcessor};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use KonclaveClientLibrary::{PairingCapability, RelayEndpoint};
use KonclaveCryptographicCore::{
    DeviceIdentity, MlsConversationClient, MlsWelcome, verify_device_credential_binding,
};
#[cfg(test)]
use KonclaveCryptographicCore::{MlsApplicationMessage, MlsCommit, MlsConversation};
#[cfg(test)]
use KonclaveDomainCore::{ApplicationMessage, EnvelopeId};
use KonclaveDomainCore::{
    ApplicationContent, ConversationId, ConversationRole, ConversationState,
    DeviceCredentialBinding, DeviceId, Ed25519PublicKey, Invitation,
    JoinProof, KonclaveDomainError, Member, MembershipOperationId, MessageDeliveryStatus,
    MessageHistoryQuery, MessageId, PairingControl, PairingId, PairingMessageId,
    PairingStage, ProtocolVersion, RelayEnvelope, RepeatPairingOperationId, RoutingId,
    StoredRelayEnvelope, TrustedDeviceAlias, TrustedDeviceAliasDecision, TrustedDeviceBinding,
    TrustedDeviceBindingStatus, TrustedDeviceEvidence, TrustedDeviceResolution,
    resolve_trusted_device, trusted_device_binding_status,
};
use KonclaveProtocolContracts::v1::{decode_membership_control, encode_join_proof};
#[cfg(test)]
use KonclaveProtocolContracts::v1::decode_membership_commit_bundle;
use KonclaveSecretStorage::SealedSqliteMlsStorage;
use thiserror::Error;

use crate::activity::ProfileActivity;
use crate::clock::{SystemUnixClock, UnixClock};
use crate::pairing::PairingOperationState;
use crate::persistence::pairing::{PairingPhase, PairingRole};
use crate::persistence::{
    CollaborationActionAuthorization, ConversationInsertOptions, ExpireOutboundResult, HistoryPage,
    MAX_CONVERSATION_PAGE_SIZE, MembershipOutboxStatus,
    OutboundReservation, PendingOutbox, ProfileStore, ProfileStoreError,
    StoredOutboundApplication,
};
#[cfg(test)]
use crate::persistence::MembershipInboxOperation;

const MAX_RECOVERED_PAIRINGS: usize = 32;
const MAX_TRUSTED_DEVICE_EVIDENCE: usize = 4_096;

fn trusted_device_domain_error(error: KonclaveDomainError) -> ConversationCoordinatorError {
    match error {
        KonclaveDomainError::TrustedDeviceRootMismatch => {
            ConversationCoordinatorError::TrustedDeviceRootMismatch
        }
        KonclaveDomainError::TrustedDeviceRemoved => {
            ConversationCoordinatorError::TrustedDeviceRemoved
        }
        KonclaveDomainError::TrustedDeviceRepeatPairingUnsupported => {
            ConversationCoordinatorError::TrustedDeviceRepeatPairingUnsupported
        }
        _ => ConversationCoordinatorError::StateMismatch,
    }
}

/// Durable conversation composition over one locked daemon profile.
#[derive(Clone)]
pub(crate) struct ConversationCoordinator {
    store: Arc<ProfileStore>,
    mls_storage: SealedSqliteMlsStorage,
    device: Arc<Mutex<DeviceIdentity>>,
    operations: Arc<Mutex<()>>,
    membership_changed: Arc<tokio::sync::Notify>,
    activity: ProfileActivity,
}

impl ConversationCoordinator {

    fn native_processor(&self) -> NativeConversationProcessor<'_, ProfileStore> {
        NativeConversationProcessor::new(self.store.as_ref(), self.mls_storage.clone(), self.device.as_ref())
    }


    /// Creates a coordinator that owns the profile lock through `store`.
    pub(crate) fn new(
        store: ProfileStore,
        mls_storage: SealedSqliteMlsStorage,
        device: DeviceIdentity,
    ) -> Self {
        Self {
            store: Arc::new(store),
            mls_storage,
            device: Arc::new(Mutex::new(device)),
            operations: Arc::new(Mutex::new(())),
            membership_changed: Arc::new(tokio::sync::Notify::new()),
            activity: ProfileActivity::default(),
        }
    }

    /// Returns the profile's in-flight operation signal.
    ///
    /// Supervised pairing and relay recovery work marks itself here so the shared
    /// service never evicts a profile that is mid-operation.
    pub(crate) fn activity(&self) -> &ProfileActivity {
        &self.activity
    }

    /// Signals when this profile joins a conversation it was not previously in.
    ///
    /// The watch supervisor also rediscovers on a timer, so this only removes the
    /// delay before a brand new conversation starts delivering. A missed signal
    /// therefore degrades latency rather than correctness.
    ///
    pub(crate) fn membership_changed(&self) -> Arc<tokio::sync::Notify> {
        self.membership_changed.clone()
    }

    /// Returns the local device identity without exposing key material.
    ///
    /// # Errors
    ///
    /// Returns a state error when another operation poisoned the identity lock.
    pub(crate) fn device_id(&self) -> Result<DeviceId, ConversationCoordinatorError> {
        self.device
            .lock()
            .map(|device| device.device_id())
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)
    }

    /// Issues one root-signed capability from the profile identity.
    ///
    /// # Errors
    ///
    /// Returns a state or pairing-construction error.
    pub(crate) fn issue_pairing_capability(
        &self,
        relay_endpoint: RelayEndpoint,
        requested_role: ConversationRole,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<PairingCapability, ConversationCoordinatorError> {
        let device = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        PairingCapability::issue(
            &device,
            relay_endpoint,
            requested_role,
            expires_at_unix_seconds,
            now_unix_seconds,
        )
        .map_err(|_| ConversationCoordinatorError::Cryptographic)
    }

    /// Signs one completion or cancellation with the profile device root.
    ///
    /// # Errors
    ///
    /// Returns a state or cryptographic error.
    pub(crate) fn sign_pairing_control(
        &self,
        pairing_id: PairingId,
        message_id: PairingMessageId,
        stage: PairingStage,
        in_reply_to: PairingMessageId,
        conversation_id: ConversationId,
    ) -> Result<PairingControl, ConversationCoordinatorError> {
        self.device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?
            .sign_pairing_control(pairing_id, message_id, stage, in_reply_to, conversation_id)
            .map_err(|_| ConversationCoordinatorError::Cryptographic)
    }

    /// Returns whether the local profile remains a member of one stored conversation.
    ///
    /// # Errors
    ///
    /// Returns a profile or state-lock error.
    /// Returns the sealed profile store this coordinator owns.
    ///
    /// The adapter channel needs remote-event and lease operations without taking a
    /// dependency on conversation or MLS behaviour, so it borrows the same store
    /// rather than duplicating one.
    pub(crate) fn store(&self) -> Arc<ProfileStore> {
        self.store.clone()
    }

    /// Reports pending and claimed remote-event counts.
    ///
    /// # Errors
    ///
    /// Returns a profile-store error.
    pub(crate) fn remote_event_counts(&self) -> Result<(u32, u32), ConversationCoordinatorError> {
        Ok(self.store.remote_event_counts()?)
    }

    /// Returns body-free local evidence without sending, retrying, or renewing work.
    pub(crate) fn message_delivery_status(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        now_unix_milliseconds: u64,
    ) -> Result<MessageDeliveryStatus, ConversationCoordinatorError> {
        Ok(self.store.message_delivery_status(
            conversation_id,
            message_id,
            now_unix_milliseconds,
        )?)
    }

    /// Reports whether automatic delivery is enabled for one conversation.
    ///
    /// # Errors
    ///
    /// Returns a profile-store error.
    pub(crate) fn adapter_delivery_enabled(
        &self,
        conversation_id: ConversationId,
    ) -> Result<bool, ConversationCoordinatorError> {
        Ok(self.store.adapter_delivery_enabled(conversation_id)?)
    }

    /// Enables or mutes automatic delivery for one conversation.
    ///
    /// # Errors
    ///
    /// Returns a profile-store error.
    pub(crate) fn set_adapter_delivery_enabled(
        &self,
        conversation_id: ConversationId,
        enabled: bool,
    ) -> Result<(), ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        Ok(self
            .store
            .set_adapter_delivery_enabled(conversation_id, enabled)?)
    }

    pub(crate) fn is_local_member(
        &self,
        conversation_id: ConversationId,
    ) -> Result<bool, ConversationCoordinatorError> {
        let self_device_id = self.device_id()?;
        Ok(self
            .store
            .load_conversation(conversation_id)?
            .state
            .member(self_device_id)
            .is_some())
    }

    /// Creates and persists one initial administrator conversation.
    ///
    /// Profile state is written before MLS state. If MLS persistence is interrupted,
    /// [`Self::recover`] reconstructs only an epoch-zero missing group from the sealed
    /// profile record.
    ///
    /// # Errors
    ///
    /// Returns a typed randomness, cryptographic, profile, or state error.
    pub(crate) fn create(&self) -> Result<ConversationSummary, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let (conversation_id, routing_id) = {
            let device = self
                .device
                .lock()
                .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
            (
                device
                    .generate_conversation_id()
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
                device
                    .generate_routing_id()
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
            )
        };
        self.create_with_identifiers_unlocked(conversation_id, routing_id)
    }

    pub(crate) fn generate_repeat_pairing_identifiers(
        &self,
    ) -> Result<(RepeatPairingOperationId, ConversationId, RoutingId), ConversationCoordinatorError>
    {
        let device = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let operation_id = RepeatPairingOperationId::from_bytes(
            device
                .generate_message_id()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?
                .into_bytes(),
        );
        Ok((
            operation_id,
            device
                .generate_conversation_id()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
            device
                .generate_routing_id()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
        ))
    }

    pub(crate) fn create_with_identifiers(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
    ) -> Result<ConversationSummary, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.create_with_identifiers_unlocked(conversation_id, routing_id)
    }

    fn create_with_identifiers_unlocked(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
    ) -> Result<ConversationSummary, ConversationCoordinatorError> {
        match self.store.load_conversation(conversation_id) {
            Ok(stored) => {
                if stored.routing_id != routing_id {
                    return Err(ConversationCoordinatorError::StateMismatch);
                }
                return Ok(self.open_unlocked(conversation_id)?.summary());
            }
            Err(ProfileStoreError::ConversationNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let (signing_material, device_id) = {
            let device = self
                .device
                .lock()
                .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
            (
                device
                    .create_conversation_signing_material(conversation_id)
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
                device.device_id(),
            )
        };
        let state = initial_conversation_state(conversation_id, device_id)?;
        let binding = signing_material.binding().clone();
        self.store.insert_conversation_with_adapter_delivery(
            routing_id,
            &signing_material,
            &state,
            &[binding],
            true,
        )?;
        let conversation = self.open_unlocked(conversation_id)?;
        self.membership_changed.notify_one();
        Ok(conversation.summary())
    }

    /// Opens one stored conversation and its sealed MLS group.
    ///
    /// A missing MLS group is reconstructed only for an epoch-zero profile record.
    /// Missing state after any epoch advance fails closed.
    ///
    /// # Errors
    ///
    /// Returns a typed profile, storage, cryptographic, or missing-state error.
    pub(crate) fn open(
        &self,
        conversation_id: ConversationId,
    ) -> Result<OpenConversation, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.open_unlocked(conversation_id)
    }

    fn open_unlocked(
        &self,
        conversation_id: ConversationId,
    ) -> Result<OpenConversation, ConversationCoordinatorError> {
        self.native_processor().open(conversation_id).map_err(Into::into)
    }

    /// Reconciles safe startup states before accepting new operations.
    ///
    /// Unsealed outbound reservations become permanent counter-gap tombstones.
    /// Every stored conversation must then open or safely reconstruct its initial
    /// MLS group.
    ///
    /// # Errors
    ///
    /// Returns the first profile, storage, or cryptographic reconciliation error.
    pub(crate) fn recover(&self) -> Result<(), ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let local_device = self.device_id()?;
        let now_unix_seconds = SystemUnixClock.now_unix_milliseconds() / 1_000;
        for response in self.store.recoverable_directed_request_responses()? {
            let conversation = self
                .store
                .load_conversation(response.reservation.conversation_id)?;
            if response.expires_at_unix_seconds <= now_unix_seconds
                || conversation.state.member(local_device).is_none()
            {
                self.store
                    .abandon_outbound_application(response.reservation)?;
                continue;
            }
            let content = ApplicationContent::text(response.response_text.as_str())
                .map_err(|_| ConversationCoordinatorError::Protocol)?;
            self.prepare_reserved_application(
                response.reservation,
                content,
                Some(response.request_message_id),
                response.sent_at_unix_milliseconds,
                response.expires_at_unix_seconds,
            )?;
        }
        self.store.abandon_unsealed_outbox()?;
        let mut pending_after = None;
        loop {
            let page = self
                .store
                .pending_join_ids(pending_after, MAX_CONVERSATION_PAGE_SIZE)?;
            let page_length = page.len();
            pending_after = page.last().copied();
            for conversation_id in page {
                let retain_for_pairing =
                    self.active_pairing_retains_pending_join(conversation_id)?;
                match self.store.load_conversation(conversation_id) {
                    Ok(_) if !retain_for_pairing => {
                        self.store.delete_pending_join(conversation_id)?;
                    }
                    Ok(_) => {}
                    Err(ProfileStoreError::ConversationNotFound) => {
                        let pending = self.store.load_pending_join(conversation_id)?;
                        let has_group = self
                            .mls_storage
                            .contains_group(conversation_id.as_bytes())
                            .map_err(|_| ConversationCoordinatorError::SecretStorage)?;
                        match (pending.state.is_some(), has_group) {
                            (true, true) => {
                                self.finalize_pending_join_unlocked(
                                    conversation_id,
                                    retain_for_pairing,
                                )?;
                            }
                            (false, true) => {
                                return Err(ConversationCoordinatorError::StateMismatch);
                            }
                            _ => {}
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if page_length < MAX_CONVERSATION_PAGE_SIZE {
                break;
            }
        }
        let mut after = None;
        loop {
            let page = self
                .store
                .conversation_ids(after, MAX_CONVERSATION_PAGE_SIZE)?;
            let page_length = page.len();
            after = page.last().copied();
            for conversation_id in page {
                self.open_unlocked(conversation_id)?;
            }
            if page_length < MAX_CONVERSATION_PAGE_SIZE {
                break;
            }
        }
        Ok(())
    }

    fn active_pairing_retains_pending_join(
        &self,
        conversation_id: ConversationId,
    ) -> Result<bool, ConversationCoordinatorError> {
        let mut after = None;
        loop {
            let pairings = self
                .store
                .active_pairing_ids(after, MAX_RECOVERED_PAIRINGS)?;
            let page_length = pairings.len();
            after = pairings.last().copied();
            for pairing_id in pairings {
                let checkpoint = self.store.load_pairing(pairing_id)?;
                if checkpoint.role == PairingRole::Joiner
                    && checkpoint.phase == PairingPhase::JoinerAwaitingWelcome
                {
                    let state = PairingOperationState::from_checkpoint(&checkpoint)
                        .map_err(|_| ConversationCoordinatorError::StateMismatch)?;
                    if state.conversation_id() == Some(conversation_id) {
                        return Ok(true);
                    }
                }
            }
            if page_length < MAX_RECOVERED_PAIRINGS {
                return Ok(false);
            }
        }
    }

    /// Returns the conversation selected for implicit profile operations.
    ///
    /// # Errors
    ///
    /// Returns a profile corruption or storage error.
    pub(crate) fn active_conversation_id(
        &self,
    ) -> Result<Option<ConversationId>, ConversationCoordinatorError> {
        self.store.active_conversation_id().map_err(Into::into)
    }

    /// Resolves an explicit target or the only remote member in a two-device conversation.
    ///
    /// # Errors
    ///
    /// Returns a profile, state, or target-required error.
    pub(crate) fn directed_request_target(
        &self,
        conversation_id: ConversationId,
        requested: Option<DeviceId>,
    ) -> Result<DeviceId, ConversationCoordinatorError> {
        let conversation = self.store.load_conversation(conversation_id)?;
        if let Some(target) = requested {
            return Ok(target);
        }
        let local_device = self.device_id()?;
        let mut remote = conversation
            .state
            .members()
            .iter()
            .map(|member| member.device_id())
            .filter(|device_id| *device_id != local_device);
        let target = remote
            .next()
            .ok_or(ConversationCoordinatorError::DirectedRequestTargetRequired)?;
        if remote.next().is_some() {
            return Err(ConversationCoordinatorError::DirectedRequestTargetRequired);
        }
        Ok(target)
    }

    /// Selects one existing conversation for implicit profile operations.
    ///
    /// # Errors
    ///
    /// Returns a profile integrity, missing-conversation, sealing, or storage error.
    pub(crate) fn set_active_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<(), ConversationCoordinatorError> {
        self.store
            .set_active_conversation(conversation_id)
            .map_err(Into::into)
    }

    /// Lists one bounded page of local conversation identifiers.
    ///
    /// # Errors
    ///
    /// Returns a profile bounds, corruption, or storage error.
    pub(crate) fn conversation_ids(
        &self,
        after: Option<ConversationId>,
        limit: usize,
    ) -> Result<Vec<ConversationId>, ConversationCoordinatorError> {
        self.store
            .conversation_ids(after, limit)
            .map_err(Into::into)
    }

    /// Lists locally sealed aliases and their status against current authenticated membership.
    ///
    /// # Errors
    ///
    /// Returns a profile, evidence-bound, or conversation integrity error.
    pub(crate) fn trusted_devices(
        &self,
    ) -> Result<Vec<TrustedDeviceSummary>, ConversationCoordinatorError> {
        let bindings = self.store.trusted_device_bindings()?;
        let targets = bindings
            .iter()
            .map(TrustedDeviceBinding::device_id)
            .collect::<BTreeSet<_>>();
        let evidence = self.trusted_device_evidence(&targets)?;
        let mut devices = bindings
            .into_iter()
            .map(|binding| TrustedDeviceSummary {
                alias: binding.alias().as_str().to_owned(),
                device_id: binding.device_id(),
                status: trusted_device_binding_status(&binding, &evidence),
            })
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| left.alias.cmp(&right.alias));
        Ok(devices)
    }

    /// Binds a canonical alias to one exact currently authenticated device root.
    ///
    /// # Errors
    ///
    /// Returns a self-target, removed-device, root-mismatch, collision, profile, or
    /// conversation integrity error.
    pub(crate) fn set_trusted_device_alias(
        &self,
        device_id: DeviceId,
        alias: TrustedDeviceAlias,
    ) -> Result<TrustedDeviceAliasDecision, ConversationCoordinatorError> {
        if device_id == self.device_id()? {
            return Err(ConversationCoordinatorError::TrustedDeviceSelf);
        }
        let existing = self.store.trusted_device_bindings()?;
        let mut targets = existing
            .iter()
            .map(TrustedDeviceBinding::device_id)
            .collect::<BTreeSet<_>>();
        targets.insert(device_id);
        let evidence = self.trusted_device_evidence(&targets)?;
        let mut current_root = None;
        for candidate in evidence
            .iter()
            .filter(|candidate| candidate.device_id() == device_id)
        {
            match current_root {
                None => current_root = Some(candidate.device_root_public_key()),
                Some(root) if root == candidate.device_root_public_key() => {}
                Some(_) => return Err(ConversationCoordinatorError::TrustedDeviceRootMismatch),
            }
        }
        let current_root =
            current_root.ok_or(ConversationCoordinatorError::TrustedDeviceRemoved)?;
        let candidate = TrustedDeviceBinding::new(alias, device_id, current_root);
        self.store
            .store_trusted_device_binding(&candidate, &evidence)
            .map_err(Into::into)
    }

    /// Resolves one alias to an exact device root and deterministic bootstrap conversation.
    ///
    /// # Errors
    ///
    /// Returns a missing, removed, root-mismatch, profile, or conversation integrity
    /// error.
    pub(crate) fn resolve_trusted_device_alias(
        &self,
        alias: &TrustedDeviceAlias,
    ) -> Result<TrustedDeviceResolution, ConversationCoordinatorError> {
        let binding = self.store.trusted_device_binding(alias)?;
        let evidence = self.trusted_device_evidence(&BTreeSet::from([binding.device_id()]))?;
        resolve_trusted_device(&binding, &evidence).map_err(trusted_device_domain_error)
    }

    pub(crate) fn verify_repeat_pairing_peer(
        &self,
        conversation_id: ConversationId,
        peer_device_id: DeviceId,
        peer_root_public_key: Ed25519PublicKey,
    ) -> Result<(), ConversationCoordinatorError> {
        let local_device = self.device_id()?;
        let conversation = self.store.load_conversation(conversation_id)?;
        if conversation.state.member(local_device).is_none()
            || conversation.state.member(peer_device_id).is_none()
        {
            return Err(ConversationCoordinatorError::TrustedDeviceRemoved);
        }
        let binding = conversation
            .bindings
            .iter()
            .find(|binding| binding.binding().device_id() == peer_device_id)
            .ok_or(ConversationCoordinatorError::StateMismatch)?;
        if !conversation.state.members().iter().all(|member| {
            conversation.bindings.iter().any(|binding| {
                binding.binding().device_id() == member.device_id()
                    && binding.binding().supports_repeat_pairing()
            })
        }) {
            return Err(ConversationCoordinatorError::TrustedDeviceRepeatPairingUnsupported);
        }
        if binding.binding().device_root_public_key() == peer_root_public_key {
            Ok(())
        } else {
            Err(ConversationCoordinatorError::TrustedDeviceRootMismatch)
        }
    }

    fn trusted_device_evidence(
        &self,
        targets: &BTreeSet<DeviceId>,
    ) -> Result<Vec<TrustedDeviceEvidence>, ConversationCoordinatorError> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        let local_device = self.device_id()?;
        let mut evidence = Vec::new();
        let mut after = None;
        loop {
            let conversations = self
                .store
                .conversation_ids(after, MAX_CONVERSATION_PAGE_SIZE)?;
            if conversations.is_empty() {
                return Ok(evidence);
            }
            let page_length = conversations.len();
            for conversation_id in conversations {
                after = Some(conversation_id);
                let conversation = self.store.load_conversation(conversation_id)?;
                if conversation.state.member(local_device).is_none() {
                    continue;
                }
                let conversation_supports_repeat_pairing =
                    conversation.state.members().iter().all(|member| {
                        conversation.bindings.iter().any(|binding| {
                            binding.binding().device_id() == member.device_id()
                                && binding.binding().supports_repeat_pairing()
                        })
                    });
                for member in conversation.state.members() {
                    let device_id = member.device_id();
                    if device_id == local_device || !targets.contains(&device_id) {
                        continue;
                    }
                    let binding = conversation
                        .bindings
                        .iter()
                        .find(|binding| binding.binding().device_id() == device_id)
                        .ok_or(ConversationCoordinatorError::StateMismatch)?;
                    if evidence.len() == MAX_TRUSTED_DEVICE_EVIDENCE {
                        return Err(ConversationCoordinatorError::TrustedDeviceEvidenceCapacity);
                    }
                    evidence.push(TrustedDeviceEvidence::new(
                        conversation_id,
                        device_id,
                        binding.binding().device_root_public_key(),
                        conversation_supports_repeat_pairing,
                    ));
                }
            }
            if page_length < MAX_CONVERSATION_PAGE_SIZE {
                return Ok(evidence);
            }
        }
    }

    /// Issues one device-bound invitation package with all current public bindings.
    ///
    /// # Errors
    ///
    /// Returns an authorization, profile, cryptographic, or state error.
    pub(crate) fn issue_invitation(
        &self,
        conversation_id: ConversationId,
        expected_device_id: DeviceId,
        role: ConversationRole,
        expires_at_unix_seconds: u64,
    ) -> Result<InvitationPackage, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let conversation = self.open_unlocked(conversation_id)?;
        let issuer_device_id = self.device_id()?;
        if conversation
            .group
            .state()
            .member(issuer_device_id)
            .map(Member::role)
            != Some(ConversationRole::Administrator)
        {
            return Err(ConversationCoordinatorError::Unauthorized);
        }
        let invitation = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?
            .issue_invitation(
                conversation_id,
                conversation.routing_id,
                expected_device_id,
                role,
                expires_at_unix_seconds,
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let stored = self.store.load_conversation(conversation_id)?;
        Ok(InvitationPackage {
            invitation,
            routing_id: stored.routing_id,
            issuer_public_key: stored
                .bindings
                .iter()
                .find(|binding| binding.binding().device_id() == issuer_device_id)
                .ok_or(ConversationCoordinatorError::StateMismatch)?
                .binding()
                .device_root_public_key(),
            peer_bindings: stored
                .bindings
                .iter()
                .map(|binding| binding.binding().clone())
                .collect(),
        })
    }

    /// Creates and durably stores one invitation-bound JoinProof.
    ///
    /// # Errors
    ///
    /// Returns an invitation, profile, cryptographic, or state error.
    #[allow(
        clippy::too_many_arguments,
        reason = "the invitation capability fields remain explicit"
    )]
    pub(crate) fn create_join_proof(
        &self,
        invitation: Invitation,
        routing_id: RoutingId,
        issuer_public_key: Ed25519PublicKey,
        peer_bindings: Vec<DeviceCredentialBinding>,
        now_unix_seconds: u64,
    ) -> Result<JoinProof, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let conversation_id = invitation.conversation_id();
        if invitation.routing_id() != Some(routing_id) {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        match self.store.load_conversation(conversation_id) {
            Ok(_) => return Err(ConversationCoordinatorError::StateMismatch),
            Err(ProfileStoreError::ConversationNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let requested_invitation = KonclaveProtocolContracts::v1::encode_invitation(&invitation)
            .map_err(|_| ConversationCoordinatorError::Protocol)?;
        let pending = match self.store.load_pending_join(conversation_id) {
            Ok(existing) => {
                let existing_invitation =
                    KonclaveProtocolContracts::v1::encode_invitation(&existing.invitation)
                        .map_err(|_| ConversationCoordinatorError::Protocol)?;
                let same_bindings = existing.peer_bindings.len() == peer_bindings.len()
                    && existing.peer_bindings.iter().all(|existing| {
                        peer_bindings
                            .iter()
                            .any(|expected| expected == existing.binding())
                    });
                if existing_invitation != requested_invitation
                    || existing.routing_id != routing_id
                    || existing.issuer_public_key != issuer_public_key
                    || !same_bindings
                {
                    return Err(ConversationCoordinatorError::StateMismatch);
                }
                if existing.proof.is_some() {
                    return self
                        .store
                        .load_pending_join(conversation_id)?
                        .proof
                        .ok_or(ConversationCoordinatorError::StateMismatch);
                }
                existing
            }
            Err(ProfileStoreError::OperationNotFound) => {
                let device = self
                    .device
                    .lock()
                    .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
                device
                    .verify_invitation(&invitation, issuer_public_key, now_unix_seconds)
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                let signing_material = device
                    .create_conversation_signing_material(conversation_id)
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                self.store.reserve_pending_join(
                    routing_id,
                    &signing_material,
                    &invitation,
                    issuer_public_key,
                    &peer_bindings,
                    now_unix_seconds,
                )?;
                self.store.load_pending_join(conversation_id)?
            }
            Err(error) => return Err(error.into()),
        };
        let device = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let mut client =
            MlsConversationClient::with_storage(pending.signing_material, self.mls_storage.clone())
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        for binding in &peer_bindings {
            client
                .register_verified_binding(
                    verify_device_credential_binding(binding)
                        .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
                )
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        }
        let proof = client
            .create_join_proof(
                &device,
                pending.invitation,
                pending.issuer_public_key,
                now_unix_seconds,
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        self.store
            .store_pending_join_proof(conversation_id, &proof)?;
        Ok(proof)
    }

    /// Returns the signed relay route for one pending join.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, or unauthenticated pending-join error.
    pub(crate) fn pending_join_route(
        &self,
        conversation_id: ConversationId,
    ) -> Result<RoutingId, ConversationCoordinatorError> {
        let pending = self.store.load_pending_join(conversation_id)?;
        if pending.invitation.routing_id() != Some(pending.routing_id) {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        Ok(pending.routing_id)
    }

    /// Accepts one encrypted Welcome and publishes the joined conversation.
    ///
    /// # Errors
    ///
    /// Returns a pending-join, Welcome, profile, MLS, or state-recovery error.
    pub(crate) fn accept_welcome(
        &self,
        conversation_id: ConversationId,
        welcome: &MlsWelcome,
        receipt: &StoredRelayEnvelope,
    ) -> Result<ConversationSummary, ConversationCoordinatorError> {
        self.accept_welcome_with_retention(conversation_id, welcome, receipt, false)
    }

    /// Accepts a pairing Welcome while retaining its exact recovery journal until
    /// the root-signed completion is relay-accepted.
    ///
    /// # Errors
    ///
    /// Returns a pending-join, Welcome, profile, MLS, or state-recovery error.
    pub(crate) fn accept_pairing_welcome(
        &self,
        conversation_id: ConversationId,
        welcome: &MlsWelcome,
        receipt: &StoredRelayEnvelope,
    ) -> Result<ConversationSummary, ConversationCoordinatorError> {
        self.accept_welcome_with_retention(conversation_id, welcome, receipt, true)
    }

    fn accept_welcome_with_retention(
        &self,
        conversation_id: ConversationId,
        welcome: &MlsWelcome,
        receipt: &StoredRelayEnvelope,
        retain_pending_join: bool,
    ) -> Result<ConversationSummary, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let has_group = self
            .mls_storage
            .contains_group(conversation_id.as_bytes())
            .map_err(|_| ConversationCoordinatorError::SecretStorage)?;
        let pending = self.store.load_pending_join(conversation_id)?;
        if pending.state.is_some() && has_group {
            if pending.join_receipt.as_ref() != Some(receipt)
                || pending.expected_commit_envelope_id != Some(receipt.envelope().envelope_id())
            {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
            return self.finalize_pending_join_unlocked(conversation_id, retain_pending_join);
        }
        let proof = pending
            .proof
            .as_ref()
            .ok_or(ConversationCoordinatorError::StateMismatch)?;
        let mut client =
            MlsConversationClient::with_storage(pending.signing_material, self.mls_storage.clone())
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        for binding in pending.peer_bindings {
            client
                .register_verified_binding(binding)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        }
        client
            .restore_join_proof(
                proof,
                pending.issuer_public_key,
                pending.verified_at_unix_seconds,
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let prepared = client
            .prepare_join_group(welcome)
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        if let Some(expected) = &pending.state
            && prepared.state() != expected
        {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        let expected_commit_envelope_id = prepared
            .expected_commit_envelope_id()
            .ok_or(ConversationCoordinatorError::StateMismatch)?;
        if receipt.envelope().envelope_id() != expected_commit_envelope_id {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        self.store.checkpoint_pending_join_state(
            conversation_id,
            prepared.state(),
            expected_commit_envelope_id,
            receipt,
        )?;
        prepared
            .persist()
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        self.finalize_pending_join_unlocked(conversation_id, retain_pending_join)
    }

    fn finalize_pending_join_unlocked(
        &self,
        conversation_id: ConversationId,
        retain_pending_join: bool,
    ) -> Result<ConversationSummary, ConversationCoordinatorError> {
        let pending = self.store.load_pending_join(conversation_id)?;
        let state = pending
            .state
            .clone()
            .ok_or(ConversationCoordinatorError::StateMismatch)?;
        let join_receipt = pending
            .join_receipt
            .as_ref()
            .ok_or(ConversationCoordinatorError::StateMismatch)?;
        if pending.expected_commit_envelope_id != Some(join_receipt.envelope().envelope_id()) {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        let mut bindings = pending
            .peer_bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        bindings.push(pending.signing_material.binding().clone());
        let verified_bindings = bindings
            .iter()
            .map(|binding| {
                verify_device_credential_binding(binding)
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let client =
            MlsConversationClient::with_storage(pending.signing_material, self.mls_storage.clone())
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        client
            .restore_group(state.clone(), verified_bindings, None)
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        match self.store.insert_conversation_at_cursor(
            pending.routing_id,
            &self
                .store
                .load_pending_join(conversation_id)?
                .signing_material,
            &state,
            &bindings,
            ConversationInsertOptions::joined(join_receipt.cursor(), join_receipt),
        ) {
            Ok(()) => {}
            Err(ProfileStoreError::ConversationExists) => {
                let stored = self.store.load_conversation(conversation_id)?;
                if stored.routing_id != pending.routing_id
                    || stored.state != state
                    || stored.replay_cursor != join_receipt.cursor()
                {
                    return Err(ConversationCoordinatorError::StateMismatch);
                }
                self.store
                    .set_adapter_delivery_enabled(conversation_id, true)?;
            }
            Err(error) => return Err(error.into()),
        }
        if !retain_pending_join {
            match self.store.delete_pending_join(conversation_id) {
                Ok(()) | Err(ProfileStoreError::OperationNotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.membership_changed.notify_one();
        Ok(ConversationSummary {
            conversation_id,
            routing_id: pending.routing_id,
            epoch: state.epoch(),
        })
    }

    /// Removes a retained pairing join journal after completion is relay-accepted.
    ///
    /// # Errors
    ///
    /// Returns a profile-store error other than an already-removed journal.
    pub(crate) fn complete_pairing_join(
        &self,
        conversation_id: ConversationId,
    ) -> Result<(), ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        match self.store.delete_pending_join(conversation_id) {
            Ok(()) | Err(ProfileStoreError::OperationNotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Encrypts and journals one outbound application message before transmission.
    ///
    /// MLS sender state is persisted before the ciphertext is returned. Any failure
    /// before the sealed envelope becomes ready permanently abandons the reservation
    /// without rolling its counter back.
    ///
    /// # Errors
    ///
    /// Returns a typed profile, protocol, cryptographic, or state error.
    pub(crate) fn prepare_application(
        &self,
        conversation_id: ConversationId,
        content: ApplicationContent,
        reply_to: Option<MessageId>,
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedApplication, ConversationCoordinatorError> {
        let message_id = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?
            .generate_message_id()
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        self.prepare_application_with_id(
            conversation_id,
            message_id,
            content,
            reply_to,
            None,
            sent_at_unix_milliseconds,
            expires_at_unix_seconds,
        )
    }

    /// Encrypts and journals one caller-identified outbound application message.
    ///
    /// # Errors
    ///
    /// Returns a typed profile, protocol, cryptographic, or state error.
    #[allow(
        clippy::too_many_arguments,
        reason = "the durable application request fields remain explicit"
    )]
    pub(crate) fn prepare_application_with_id(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        content: ApplicationContent,
        reply_to: Option<MessageId>,
        collaboration_action_authorization: Option<CollaborationActionAuthorization>,
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedApplication, ConversationCoordinatorError> {
        self.prepare_application_request(PrepareApplicationRequest {
            conversation_id,
            message_id,
            content,
            reply_to,
            collaboration_action_authorization,
            sent_at_unix_milliseconds,
            expires_at_unix_seconds,
            policy_operation: false,
        })
    }

    /// Encrypts a policy message whose identifier is reserved by a terminal operation.
    ///
    /// # Errors
    ///
    /// Returns a profile, protocol, cryptographic, reservation, or state error.
    pub(crate) fn prepare_collaboration_policy_application_with_id(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        content: ApplicationContent,
        reply_to: Option<MessageId>,
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedApplication, ConversationCoordinatorError> {
        self.prepare_application_request(PrepareApplicationRequest {
            conversation_id,
            message_id,
            content,
            reply_to,
            collaboration_action_authorization: None,
            sent_at_unix_milliseconds,
            expires_at_unix_seconds,
            policy_operation: true,
        })
    }

    fn prepare_application_request(
        &self,
        request: PrepareApplicationRequest,
    ) -> Result<PreparedApplication, ConversationCoordinatorError> {
        let _operation = self.operations.lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.native_processor().prepare_application(NativeApplicationRequest {
            conversation_id: request.conversation_id,
            message_id: request.message_id,
            content: request.content,
            reply_to: request.reply_to,
            authorization: request.collaboration_action_authorization,
            sent_at_unix_milliseconds: request.sent_at_unix_milliseconds,
            expires_at_unix_seconds: request.expires_at_unix_seconds,
            policy_operation: request.policy_operation,
        }).map_err(Into::into)
    }

    /// Loads one ready, accepted, or terminal outbound request by stable message ID.
    ///
    /// # Errors
    ///
    /// Returns a sealed profile, protocol, or storage error.
    pub(crate) fn outbound_application(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<Option<StoredOutboundApplication>, ConversationCoordinatorError> {
        self.store
            .outbound_application(conversation_id, message_id)
            .map_err(Into::into)
    }

    fn prepare_reserved_application(
        &self,
        reservation: OutboundReservation,
        content: ApplicationContent,
        reply_to: Option<MessageId>,
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedApplication, ConversationCoordinatorError> {
        self.native_processor().prepare_reserved_application(reservation, content, reply_to, sent_at_unix_milliseconds, expires_at_unix_seconds).map_err(Into::into)
    }

    /// Creates and journals one add-member commit before relay transmission.
    ///
    /// # Errors
    ///
    /// Returns a join-proof, MLS, profile, protocol, or state error.
    pub(crate) fn prepare_add_member(
        &self,
        conversation_id: ConversationId,
        join_proof: JoinProof,
        now_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedMembership, ConversationCoordinatorError> {
        let _operation = self.operations.lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.native_processor().prepare_add_member(conversation_id, join_proof, now_unix_seconds, expires_at_unix_seconds).map_err(Into::into)
    }

    /// Creates and journals one remove-member commit before relay transmission.
    ///
    /// # Errors
    ///
    /// Returns an authorization, MLS, profile, protocol, or state error.
    pub(crate) fn prepare_remove_member(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedMembership, ConversationCoordinatorError> {
        let _operation = self.operations.lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.native_processor().prepare_remove_member(conversation_id, device_id, expires_at_unix_seconds).map_err(Into::into)
    }

    /// Creates and journals one role-change commit before relay transmission.
    ///
    /// # Errors
    ///
    /// Returns an authorization, MLS, profile, protocol, or state error.
    pub(crate) fn prepare_change_role(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        role: ConversationRole,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedMembership, ConversationCoordinatorError> {
        let _operation = self.operations.lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.native_processor().prepare_change_role(conversation_id, device_id, role, expires_at_unix_seconds).map_err(Into::into)
    }



    /// Loads bounded ready envelopes for idempotent relay retry.
    ///
    /// # Errors
    ///
    /// Returns a profile bounds, authentication, protocol, or storage error.
    pub(crate) fn ready_outbox(&self) -> Result<Vec<PendingOutbox>, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let self_device_id = self.device_id()?;
        let mut eligible = Vec::new();
        for pending in self.store.ready_outbox()? {
            let conversation = self.store.load_conversation(pending.conversation_id)?;
            if conversation.state.member(self_device_id).is_none() {
                self.store
                    .terminalize_removed_outbox(pending.conversation_id)?;
            } else {
                eligible.push(pending);
            }
        }
        Ok(eligible)
    }

    /// Rechecks current sealed membership immediately before one ready retry.
    ///
    /// A removed local device atomically terminalizes any lingering ready rows and
    /// returns `false`, preventing network submission.
    ///
    /// # Errors
    ///
    /// Returns a profile, policy, or storage error.
    pub(crate) fn outbound_retry_eligible(
        &self,
        conversation_id: ConversationId,
    ) -> Result<bool, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let conversation = self.store.load_conversation(conversation_id)?;
        if conversation.state.member(self.device_id()?).is_some() {
            Ok(true)
        } else {
            self.store.terminalize_removed_outbox(conversation_id)?;
            Ok(false)
        }
    }

    /// Loads bounded ready membership envelopes for idempotent relay retry.
    ///
    /// # Errors
    ///
    /// Returns a profile bounds, authentication, protocol, or storage error.
    pub(crate) fn ready_membership_outbox(
        &self,
    ) -> Result<Vec<PreparedMembership>, ConversationCoordinatorError> {
        self.store
            .ready_membership_outbox()?
            .into_iter()
            .map(|pending| {
                Ok(PreparedMembership {
                    operation_id: pending.operation_id,
                    conversation_id: pending.conversation_id,
                    parent_epoch: pending.parent_epoch,
                    envelope: pending.envelope,
                    welcome: pending.welcome,
                })
            })
            .collect()
    }

    /// Returns a prior add-member operation for exact JoinProof retry.
    ///
    /// # Errors
    ///
    /// Returns a profile, protocol, MLS, or recovery error.
    pub(crate) fn resume_add_member(
        &self,
        conversation_id: ConversationId,
        proof: &JoinProof,
    ) -> Result<Option<MembershipRequestState>, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let Some(record) = self.store.membership_outbox_for_invitation(
            conversation_id,
            proof.invitation().invitation_id(),
        )?
        else {
            return Ok(None);
        };
        let (_, stored_proof) = decode_membership_control(&record.control)
            .map_err(|_| ConversationCoordinatorError::Protocol)?;
        let stored_proof = stored_proof.ok_or(ConversationCoordinatorError::StateMismatch)?;
        if encode_join_proof(&stored_proof).map_err(|_| ConversationCoordinatorError::Protocol)?
            != encode_join_proof(proof).map_err(|_| ConversationCoordinatorError::Protocol)?
        {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        self.resume_membership_record(record, true)
    }

    /// Returns a prior remove-member operation when it is active or still current.
    ///
    /// # Errors
    ///
    /// Returns a profile, MLS, or recovery error.
    pub(crate) fn resume_remove_member(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
    ) -> Result<Option<MembershipRequestState>, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let Some(record) = self
            .store
            .membership_outbox_for_removal(conversation_id, device_id)?
        else {
            return Ok(None);
        };
        self.resume_membership_record(record, false)
    }

    /// Returns a prior role operation when it is active or still current.
    ///
    /// # Errors
    ///
    /// Returns a profile, MLS, or recovery error.
    pub(crate) fn resume_change_role(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        role: ConversationRole,
    ) -> Result<Option<MembershipRequestState>, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let Some(record) =
            self.store
                .membership_outbox_for_role(conversation_id, device_id, role)?
        else {
            return Ok(None);
        };
        self.resume_membership_record(record, false)
    }

    fn resume_membership_record(
        &self,
        record: crate::persistence::MembershipOutbox,
        allow_historical_add: bool,
    ) -> Result<Option<MembershipRequestState>, ConversationCoordinatorError> {
        if record.status == MembershipOutboxStatus::Ready {
            return Ok(Some(MembershipRequestState::Ready(PreparedMembership {
                operation_id: record.operation_id,
                conversation_id: record.conversation_id,
                parent_epoch: record.parent_epoch,
                envelope: record.envelope,
                welcome: record.welcome,
            })));
        }
        if record.status == MembershipOutboxStatus::Accepted {
            let _conversation = self.open_unlocked(record.conversation_id)?;
        }
        let record = self.store.load_membership_outbox(record.operation_id)?;
        if record.status != MembershipOutboxStatus::Applied {
            return Ok(None);
        }
        if allow_historical_add {
            self.store.verify_historical_applied_add(&record)?;
        } else {
            let current = self.store.load_conversation(record.conversation_id)?;
            if current.state != record.next_state {
                return Ok(None);
            }
        }
        Ok(Some(MembershipRequestState::Applied(AcceptedMembership {
            operation_id: record.operation_id,
            conversation_id: record.conversation_id,
            cursor: record
                .accepted_cursor
                .ok_or(ConversationCoordinatorError::StateMismatch)?,
            welcome: record.welcome,
        })))
    }

    /// Records relay acceptance and completes the corresponding local MLS epoch.
    ///
    /// # Errors
    ///
    /// Returns a cursor, profile, MLS, or state-recovery error.
    pub(crate) fn mark_membership_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<AcceptedMembership, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let operation_id = self.store.mark_membership_outbox_accepted(stored)?;
        let pending = self.store.load_membership_outbox(operation_id)?;
        let conversation_id = pending.conversation_id;
        let welcome = pending.welcome;
        let _conversation = self.open_unlocked(conversation_id)?;
        Ok(AcceptedMembership {
            operation_id,
            conversation_id,
            cursor: stored.cursor(),
            welcome,
        })
    }

    /// Rejects one local unaccepted commit after a permanent relay conflict.
    ///
    /// # Errors
    ///
    /// Returns a profile, MLS, or state-recovery error.
    pub(crate) fn orphan_membership(
        &self,
        operation_id: MembershipOperationId,
    ) -> Result<(), ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.orphan_membership_unlocked(operation_id)
    }

    fn orphan_membership_unlocked(
        &self,
        operation_id: MembershipOperationId,
    ) -> Result<(), ConversationCoordinatorError> {
        self.native_processor().orphan_membership(operation_id).map_err(Into::into)
    }

    /// Loads one bounded cursor-ordered page of completed local history.
    ///
    /// # Errors
    ///
    /// Returns a profile bounds, corruption, authentication, protocol, or storage
    /// error.
    pub(crate) fn history(
        &self,
        conversation_id: ConversationId,
        after_cursor: u64,
        limit: usize,
    ) -> Result<HistoryPage, ConversationCoordinatorError> {
        self.store
            .load_history(conversation_id, after_cursor, limit)
            .map_err(Into::into)
    }

    /// Reads authenticated sealed history using validated cursor and timestamp bounds.
    ///
    /// # Errors
    ///
    /// Returns a profile, authentication, corruption, protocol, or storage error.
    pub(crate) fn history_query(
        &self,
        conversation_id: ConversationId,
        query: MessageHistoryQuery,
    ) -> Result<HistoryPage, ConversationCoordinatorError> {
        self.store
            .load_history_query(conversation_id, query)
            .map_err(Into::into)
    }

    /// Records one exact relay submission response.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, profile transition, or storage error.
    pub(crate) fn mark_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<(), ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.store.mark_outbox_accepted(stored).map_err(Into::into)
    }

    /// Marks one exact ready application envelope terminal after local expiry.
    ///
    /// # Errors
    ///
    /// Returns a profile integrity, transition, or storage error.
    pub(crate) fn expire_outbound_application(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<ExpireOutboundResult, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.store
            .expire_outbound_application(envelope)
            .map_err(Into::into)
    }

    /// Returns the exact route and durable contiguous replay cursor.
    ///
    /// # Errors
    ///
    /// Returns a profile, storage, cryptographic, or missing-state error.
    pub(crate) fn replay_position(
        &self,
        conversation_id: ConversationId,
    ) -> Result<(RoutingId, u64), ConversationCoordinatorError> {
        let conversation = self.open(conversation_id)?;
        Ok((conversation.routing_id, conversation.replay_cursor))
    }

    /// Journals, decrypts, persists, and completes one inbound application envelope.
    ///
    /// An exact completed replay returns the sealed local message without repeating
    /// cryptographic or application side effects. A message-saved crash state either
    /// reapplies and persists the receiver ratchet or proves that the exact generation
    /// was already consumed.
    ///
    /// # Errors
    ///
    /// Returns a route, profile, protocol, cryptographic, or state mismatch error.
    pub(crate) fn process_inbound_application(
        &self,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
    ) -> Result<ProcessedApplication, ConversationCoordinatorError> {
        self.process_inbound_application_at(conversation_id, stored, self.store.now_unix_seconds())
    }

    pub(crate) fn process_inbound_application_at(
        &self,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<ProcessedApplication, ConversationCoordinatorError> {
        let _operation = self.operations.lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.native_processor().process_inbound_application(conversation_id, stored, now_unix_seconds).map_err(Into::into)
    }

    /// Journals and applies one encrypted membership Commit relay envelope.
    ///
    /// A local relay echo completes from the sealed outbound checkpoint without
    /// attempting MLS self-decryption. A remote transition checkpoints decrypted
    /// control and next policy before persisting the receiver ratchet and new epoch.
    ///
    /// # Errors
    ///
    /// Returns a route, cursor, profile, protocol, cryptographic, or state error.
    pub(crate) fn process_inbound_membership(
        &self,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<ProcessedMembership, ConversationCoordinatorError> {
        let _operation = self.operations.lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        self.native_processor().process_inbound_membership(conversation_id, stored, now_unix_seconds).map_err(Into::into)
    }


}



struct PrepareApplicationRequest {
    conversation_id: ConversationId,
    message_id: MessageId,
    content: ApplicationContent,
    reply_to: Option<MessageId>,
    collaboration_action_authorization: Option<CollaborationActionAuthorization>,
    sent_at_unix_milliseconds: u64,
    expires_at_unix_seconds: u64,
    policy_operation: bool,
}

/// One relay-accepted and locally applied membership transition.
pub(crate) struct AcceptedMembership {
    pub(crate) operation_id: MembershipOperationId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) cursor: u64,
    pub(crate) welcome: Option<Vec<u8>>,
}

pub(crate) enum MembershipRequestState {
    Ready(PreparedMembership),
    Applied(AcceptedMembership),
}

/// Signed invitation plus public routing and credential material for one invitee.
pub(crate) struct InvitationPackage {
    pub(crate) invitation: Invitation,
    pub(crate) routing_id: RoutingId,
    pub(crate) issuer_public_key: Ed25519PublicKey,
    pub(crate) peer_bindings: Vec<DeviceCredentialBinding>,
}

trait OpenConversationSummary {
    fn summary(&self) -> ConversationSummary;
}

impl OpenConversationSummary for OpenConversation {
    fn summary(&self) -> ConversationSummary {
        ConversationSummary {
            conversation_id: self.group.state().conversation_id(),
            routing_id: self.routing_id,
            epoch: self.group.epoch(),
        }
    }
}

/// Non-secret conversation metadata returned to daemon adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConversationSummary {
    pub(crate) conversation_id: ConversationId,
    pub(crate) routing_id: RoutingId,
    pub(crate) epoch: u64,
}

pub(crate) struct TrustedDeviceSummary {
    pub(crate) alias: String,
    pub(crate) device_id: DeviceId,
    pub(crate) status: TrustedDeviceBindingStatus,
}

/// Stable conversation composition failures.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ConversationCoordinatorError {
    #[error("daemon profile operation failed")]
    Profile(#[from] ProfileStoreError),
    #[error("cryptographic conversation operation failed")]
    Cryptographic,
    #[error("sealed MLS storage operation failed")]
    SecretStorage,
    #[error("conversation state lock is unavailable")]
    StateUnavailable,
    #[error("advanced conversation is missing sealed MLS state")]
    MissingMlsState,
    #[error("pending MLS membership state has no durable journal")]
    MissingMembershipJournal,
    #[error("profile and MLS conversation state disagree")]
    StateMismatch,
    #[error("application protocol construction failed")]
    Protocol,
    #[error("directed request target or another remote conversation member is not capable")]
    DirectedRequestUnsupported,
    #[error("directed request target is required for this conversation")]
    DirectedRequestTargetRequired,
    #[error("the local profile device cannot be assigned as a trusted remote device")]
    TrustedDeviceSelf,
    #[error("trusted-device identity has contradictory root evidence")]
    TrustedDeviceRootMismatch,
    #[error("trusted-device identity is no longer a current member")]
    TrustedDeviceRemoved,
    #[error("trusted device has no conversation with repeat-pairing capability")]
    TrustedDeviceRepeatPairingUnsupported,
    #[error("trusted-device evidence exceeded its bounded local limit")]
    TrustedDeviceEvidenceCapacity,
    #[error("conversation operation is not authorized")]
    Unauthorized,
}


impl From<NativeConversationError<ProfileStoreError>> for ConversationCoordinatorError {
    fn from(error: NativeConversationError<ProfileStoreError>) -> Self {
        match error {
            NativeConversationError::Journal(error) => Self::Profile(error),
            NativeConversationError::Cryptographic => Self::Cryptographic,
            NativeConversationError::SecretStorage => Self::SecretStorage,
            NativeConversationError::StateUnavailable => Self::StateUnavailable,
            NativeConversationError::MissingMlsState => Self::MissingMlsState,
            NativeConversationError::MissingMembershipJournal => Self::MissingMembershipJournal,
            NativeConversationError::StateMismatch => Self::StateMismatch,
            NativeConversationError::Protocol => Self::Protocol,
            NativeConversationError::DirectedRequestUnsupported => Self::DirectedRequestUnsupported,
        }
    }
}

fn initial_conversation_state(
    conversation_id: ConversationId,
    device_id: DeviceId,
) -> Result<ConversationState, ConversationCoordinatorError> {
    ConversationState::new(
        ProtocolVersion::application_v1(),
        conversation_id,
        0,
        vec![Member::new(device_id, ConversationRole::Administrator, 0)],
        vec![],
    )
    .map_err(|_| ConversationCoordinatorError::StateMismatch)
}

#[cfg(test)]
fn directed_request_recipients_support(
    state: &ConversationState,
    local_device: DeviceId,
    target: DeviceId,
    supports_directed_requests: impl FnMut(DeviceId) -> bool,
) -> bool {
    KonclaveClientLibrary::native::directed_request_recipients_support(state, local_device, target, supports_directed_requests)
}

#[cfg(test)]
fn decrypt_application(
    group: &mut MlsConversation,
    envelope: &RelayEnvelope,
) -> Result<(DeviceId, ApplicationMessage), ConversationCoordinatorError> {
    KonclaveClientLibrary::native::decrypt_application::<ProfileStoreError>(group, envelope).map_err(Into::into)
}

#[cfg(test)]
fn verify_application_content(
    content: &ApplicationContent,
) -> Result<(), ConversationCoordinatorError> {
    KonclaveClientLibrary::native::verify_application_content::<ProfileStoreError>(content).map_err(Into::into)
}



#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use KonclaveCryptographicCore::{
        ConversationSigningMaterial, MlsWelcome, verify_device_credential_binding,
    };
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;

    #[test]
    fn policy_proposal_content_requires_a_matching_canonical_digest() {
        let canonical_bundle =
            include_bytes!("../../../fixtures/protocol/v1/collaboration-policy-bundle.bin");
        let proposal_id = KonclaveDomainCore::CollaborationPolicyProposalId::from_bytes([1; 16]);
        let digest = KonclaveDomainCore::CollaborationPolicyDigest::from_bytes([
            0xf8, 0x18, 0x9b, 0x64, 0x71, 0x27, 0xaa, 0x9f, 0xf9, 0xd0, 0x3f, 0x5c, 0x2d, 0x04,
            0x8b, 0xcd, 0x8e, 0xb8, 0x60, 0x06, 0x20, 0xbc, 0x17, 0x96, 0xc4, 0xc6, 0x68, 0xfa,
            0x59, 0x90, 0xeb, 0x2e,
        ]);
        let valid = ApplicationContent::collaboration_policy_proposal(
            KonclaveDomainCore::CollaborationPolicyProposal::new(
                proposal_id,
                digest,
                canonical_bundle.to_vec(),
                None,
            )
            .unwrap(),
        );
        assert!(verify_application_content(&valid).is_ok());

        let invalid = ApplicationContent::collaboration_policy_proposal(
            KonclaveDomainCore::CollaborationPolicyProposal::new(
                proposal_id,
                KonclaveDomainCore::CollaborationPolicyDigest::from_bytes([2; 32]),
                canonical_bundle.to_vec(),
                None,
            )
            .unwrap(),
        );
        assert!(matches!(
            verify_application_content(&invalid),
            Err(ConversationCoordinatorError::Cryptographic)
        ));
    }
    use crate::persistence::{LockedProfile, ProfileId};

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
    }

    pub(crate) fn open_coordinator(root: &Path, profile_name: &str) -> ConversationCoordinator {
        let locked = LockedProfile::acquire(root, ProfileId::parse(profile_name).unwrap()).unwrap();
        let mls_path = locked.mls_database_path();
        let profile_sealer = sealer();
        let mls_storage = SealedSqliteMlsStorage::open(&mls_path, profile_sealer.share()).unwrap();
        let store = locked.open_store(profile_sealer).unwrap();
        let device = store.load_or_create_device().unwrap();
        ConversationCoordinator::new(store, mls_storage, device)
    }

    pub(crate) fn paired_coordinators() -> (
        tempfile::TempDir,
        ConversationCoordinator,
        ConversationCoordinator,
        ConversationId,
        DeviceId,
    ) {
        let root = tempfile::tempdir().unwrap();
        let alice_locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("alice").unwrap()).unwrap();
        let bob_locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("bob").unwrap()).unwrap();
        let alice_mls_path = alice_locked.mls_database_path();
        let bob_mls_path = bob_locked.mls_database_path();
        let alice_sealer = sealer();
        let bob_sealer = sealer();
        let alice_material_sealer = alice_sealer.share();
        let bob_material_sealer = bob_sealer.share();
        let alice_mls =
            SealedSqliteMlsStorage::open(&alice_mls_path, alice_sealer.share()).unwrap();
        let bob_mls = SealedSqliteMlsStorage::open(&bob_mls_path, bob_sealer.share()).unwrap();
        let alice_store = alice_locked.open_store(alice_sealer).unwrap();
        let bob_store = bob_locked.open_store(bob_sealer).unwrap();
        let alice_identity = alice_store.load_or_create_device().unwrap();
        let bob_identity = bob_store.load_or_create_device().unwrap();
        let alice_device_id = alice_identity.device_id();
        let conversation_id = alice_identity.generate_conversation_id().unwrap();
        let routing_id = alice_identity.generate_routing_id().unwrap();
        let alice_material = alice_identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let bob_material = bob_identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let alice_binding = alice_material.binding().clone();
        let bob_binding = bob_material.binding().clone();
        let alice_blob = alice_material
            .seal(&alice_material_sealer, b"alice")
            .unwrap();
        let bob_blob = bob_material.seal(&bob_material_sealer, b"bob").unwrap();
        let alice_client = MlsConversationClient::with_storage(
            ConversationSigningMaterial::open(
                &alice_material_sealer,
                b"alice",
                conversation_id,
                &alice_blob,
            )
            .unwrap(),
            alice_mls.clone(),
        )
        .unwrap();
        let mut bob_client = MlsConversationClient::with_storage(
            ConversationSigningMaterial::open(
                &bob_material_sealer,
                b"bob",
                conversation_id,
                &bob_blob,
            )
            .unwrap(),
            bob_mls.clone(),
        )
        .unwrap();
        bob_client
            .register_verified_binding(verify_device_credential_binding(&alice_binding).unwrap())
            .unwrap();
        let mut alice_group = alice_client.create_group().unwrap();
        let invitation = alice_identity
            .issue_invitation(
                conversation_id,
                routing_id,
                bob_identity.device_id(),
                ConversationRole::Member,
                100,
            )
            .unwrap();
        let proof = bob_client
            .create_join_proof(&bob_identity, invitation, alice_identity.public_key(), 50)
            .unwrap();
        let add = alice_group
            .create_add_commit(proof, EnvelopeId::from_bytes([1; EnvelopeId::LENGTH]), 50)
            .unwrap();
        let expected_state = add.next_state().clone();
        let welcome = MlsWelcome::from_bytes(add.welcome().unwrap().as_bytes()).unwrap();
        alice_group.accept_pending_commit().unwrap();
        let bob_group = bob_client.join_group(&welcome).unwrap();
        assert_eq!(alice_group.state(), &expected_state);
        assert_eq!(bob_group.state(), &expected_state);
        drop(alice_group);
        drop(bob_group);
        let bindings = [alice_binding, bob_binding];
        alice_store
            .insert_conversation(routing_id, &alice_material, &expected_state, &bindings)
            .unwrap();
        bob_store
            .insert_conversation(routing_id, &bob_material, &expected_state, &bindings)
            .unwrap();
        (
            root,
            ConversationCoordinator::new(alice_store, alice_mls, alice_identity),
            ConversationCoordinator::new(bob_store, bob_mls, bob_identity),
            conversation_id,
            alice_device_id,
        )
    }

    fn stage_message_saved(
        coordinator: &ConversationCoordinator,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
        persist_ratchet: bool,
    ) {
        let _operation = coordinator.operations.lock().unwrap();
        let mut conversation = coordinator.open_unlocked(conversation_id).unwrap();
        coordinator.store.record_inbox_envelope(stored).unwrap();
        let epoch = conversation.group.epoch();
        let (sender, message) =
            decrypt_application(&mut conversation.group, stored.envelope()).unwrap();
        coordinator
            .store
            .save_inbox_message(conversation_id, stored.cursor(), sender, epoch, &message)
            .unwrap();
        if persist_ratchet {
            conversation.group.persist().unwrap();
        }
    }

    fn stage_own_echo_saved(
        coordinator: &ConversationCoordinator,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
    ) {
        let _operation = coordinator.operations.lock().unwrap();
        coordinator.store.record_inbox_envelope(stored).unwrap();
        let outbound = coordinator
            .store
            .outbound_history_message(conversation_id, stored)
            .unwrap()
            .unwrap();
        coordinator
            .store
            .save_inbox_message(
                conversation_id,
                stored.cursor(),
                outbound.sender,
                outbound.epoch,
                &outbound.message,
            )
            .unwrap();
    }

    fn stage_membership_saved(
        coordinator: &ConversationCoordinator,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
        persist_commit: bool,
    ) {
        let _operation = coordinator.operations.lock().unwrap();
        coordinator
            .store
            .record_membership_inbox_envelope(stored)
            .unwrap();
        let mut conversation = coordinator.open_unlocked(conversation_id).unwrap();
        let bundle = decode_membership_commit_bundle(stored.envelope().payload()).unwrap();
        let encrypted_control =
            MlsApplicationMessage::from_bytes(bundle.encrypted_control()).unwrap();
        let decrypted = conversation
            .group
            .decrypt_application_message(&encrypted_control)
            .unwrap();
        let sender = decrypted.authenticated_sender();
        let (authorization, join_proof) = decode_membership_control(decrypted.plaintext()).unwrap();
        let next_state = conversation
            .group
            .state()
            .apply_membership_authorization(sender, &authorization, conversation.group.epoch() + 1)
            .unwrap();
        let current = coordinator
            .store
            .load_conversation(conversation_id)
            .unwrap();
        let mut bindings = current
            .bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        if let Some(proof) = &join_proof
            && !bindings
                .iter()
                .any(|binding| binding.device_id() == proof.credential().device_id())
        {
            bindings.push(proof.credential().clone());
        }
        coordinator
            .store
            .save_membership_inbox_transition(
                conversation_id,
                stored.cursor(),
                sender,
                authorization.parent_epoch(),
                authorization.operation_id(),
                decrypted.plaintext(),
                &next_state,
                &bindings,
            )
            .unwrap();
        if persist_commit {
            let commit = MlsCommit::from_bytes(bundle.mls_commit()).unwrap();
            conversation
                .group
                .process_membership_commit(&commit, authorization, join_proof, 60)
                .unwrap();
        }
    }

    fn stage_pending_welcome(
        coordinator: &ConversationCoordinator,
        conversation_id: ConversationId,
        welcome: &MlsWelcome,
        receipt: &StoredRelayEnvelope,
        persist_group: bool,
    ) {
        let _operation = coordinator.operations.lock().unwrap();
        let pending = coordinator
            .store
            .load_pending_join(conversation_id)
            .unwrap();
        let proof = pending.proof.as_ref().unwrap();
        let proof = KonclaveProtocolContracts::v1::decode_join_proof(
            &KonclaveProtocolContracts::v1::encode_join_proof(proof).unwrap(),
        )
        .unwrap();
        let mut client = MlsConversationClient::with_storage(
            pending.signing_material,
            coordinator.mls_storage.clone(),
        )
        .unwrap();
        for binding in pending.peer_bindings {
            client.register_verified_binding(binding).unwrap();
        }
        client
            .restore_join_proof(
                &proof,
                pending.issuer_public_key,
                pending.verified_at_unix_seconds,
            )
            .unwrap();
        let prepared = client.prepare_join_group(welcome).unwrap();
        coordinator
            .store
            .checkpoint_pending_join_state(
                conversation_id,
                prepared.state(),
                prepared.expected_commit_envelope_id().unwrap(),
                receipt,
            )
            .unwrap();
        if persist_group {
            prepared.persist().unwrap();
        }
    }

    pub(crate) fn invited_coordinators() -> (
        tempfile::TempDir,
        ConversationCoordinator,
        ConversationCoordinator,
        ConversationSummary,
        JoinProof,
    ) {
        let root = tempfile::tempdir().unwrap();
        let alice = open_coordinator(root.path(), "pending-alice");
        let bob = open_coordinator(root.path(), "pending-bob");
        let created = alice.create().unwrap();
        let invitation = alice
            .issue_invitation(
                created.conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Member,
                100,
            )
            .unwrap();
        let proof = bob
            .create_join_proof(
                invitation.invitation,
                invitation.routing_id,
                invitation.issuer_public_key,
                invitation.peer_bindings,
                50,
            )
            .unwrap();
        (root, alice, bob, created, proof)
    }

    fn pending_join_pair() -> (
        tempfile::TempDir,
        ConversationCoordinator,
        ConversationCoordinator,
        ConversationSummary,
        MlsWelcome,
        StoredRelayEnvelope,
    ) {
        let (root, alice, bob, created, proof) = invited_coordinators();
        let prepared = alice
            .prepare_add_member(created.conversation_id, proof, 50, 1_900_000_000)
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
        let accepted = alice.mark_membership_outbox_accepted(&stored).unwrap();
        let welcome = MlsWelcome::from_bytes(&accepted.welcome.unwrap()).unwrap();
        (root, alice, bob, created, welcome, stored)
    }

    #[test]
    fn creates_reopens_and_lists_a_persisted_conversation() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = open_coordinator(root.path(), "conversation-service");
        let created = coordinator.create().unwrap();
        assert_eq!(created.epoch, 0);
        assert!(
            coordinator
                .store
                .adapter_delivery_enabled(created.conversation_id)
                .unwrap()
        );
        assert_eq!(
            coordinator.active_conversation_id().unwrap(),
            Some(created.conversation_id)
        );
        assert_eq!(
            coordinator.conversation_ids(None, 10).unwrap(),
            vec![created.conversation_id]
        );
        assert!(
            coordinator
                .conversation_ids(Some(created.conversation_id), 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            coordinator.conversation_ids(None, 0).unwrap_err(),
            ConversationCoordinatorError::Profile(ProfileStoreError::InvalidTransition)
        );
        let opened = coordinator.open(created.conversation_id).unwrap();
        assert_eq!(opened.routing_id, created.routing_id);
        assert_eq!(
            opened.group.state().conversation_id(),
            created.conversation_id
        );
        assert_eq!(opened.group.epoch(), 0);
        let device_id = coordinator.device_id().unwrap();
        assert_eq!(
            opened.group.state().member(device_id).map(Member::role),
            Some(ConversationRole::Administrator)
        );
        drop(opened);
        drop(coordinator);

        let reopened = open_coordinator(root.path(), "conversation-service");
        reopened.recover().unwrap();
        assert_eq!(
            reopened.open(created.conversation_id).unwrap().routing_id,
            created.routing_id
        );
    }

    #[test]
    fn membership_commit_is_journaled_applied_and_replayed_idempotently() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let bob_device_id = bob.device_id().unwrap();
        let prepared = alice
            .prepare_change_role(
                conversation_id,
                bob_device_id,
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        assert_eq!(prepared.parent_epoch, 1);
        let stored = StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap();
        let accepted = alice.mark_membership_outbox_accepted(&stored).unwrap();
        assert_eq!(accepted.operation_id, prepared.operation_id);
        assert_eq!(accepted.cursor, 1);
        assert!(accepted.welcome.is_none());
        assert_eq!(alice.open(conversation_id).unwrap().group.epoch(), 2);

        let applied = bob
            .process_inbound_membership(conversation_id, &stored, 60)
            .unwrap();
        assert_eq!(applied.operation_id, prepared.operation_id);
        assert_eq!(applied.sender, alice.device_id().unwrap());
        assert_eq!(applied.epoch, 2);
        assert!(!applied.removed_self);
        assert!(!applied.duplicate);
        assert_eq!(bob.open(conversation_id).unwrap().group.epoch(), 2);
        assert_eq!(
            bob.open(conversation_id)
                .unwrap()
                .group
                .state()
                .member(bob_device_id)
                .unwrap()
                .role(),
            ConversationRole::Administrator
        );

        let duplicate = bob
            .process_inbound_membership(conversation_id, &stored, 60)
            .unwrap();
        assert!(duplicate.duplicate);
        let echo = alice
            .process_inbound_membership(conversation_id, &stored, 60)
            .unwrap();
        assert!(echo.duplicate);
        assert_eq!(alice.replay_position(conversation_id).unwrap().1, 1);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
    }

    #[test]
    fn accepted_outbound_membership_recovers_after_relay_checkpoint() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
        alice
            .store
            .mark_membership_outbox_accepted(&stored)
            .unwrap();

        let recovered = alice.open(conversation_id).unwrap();

        assert_eq!(recovered.group.epoch(), 2);
        assert_eq!(
            alice
                .store
                .load_membership_outbox(prepared.operation_id)
                .unwrap()
                .status,
            MembershipOutboxStatus::Applied
        );
    }

    #[test]
    fn membership_replay_head_reopens_after_later_local_policy_acceptance() {
        let (root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let promoted = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        let promoted = StoredRelayEnvelope::new(promoted.envelope, 1).unwrap();
        alice.mark_membership_outbox_accepted(&promoted).unwrap();
        bob.process_inbound_membership(conversation_id, &promoted, 60)
            .unwrap();

        let later = bob
            .prepare_change_role(
                conversation_id,
                alice.device_id().unwrap(),
                ConversationRole::Member,
                1_900_000_000,
            )
            .unwrap();
        let later = StoredRelayEnvelope::new(later.envelope, 2).unwrap();
        bob.mark_membership_outbox_accepted(&later).unwrap();
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
        assert_eq!(bob.open(conversation_id).unwrap().group.epoch(), 3);

        drop(alice);
        drop(bob);
        let reopened = open_coordinator(root.path(), "bob");
        reopened.recover().unwrap();
        let conversation = reopened.open(conversation_id).unwrap();
        assert_eq!(conversation.replay_cursor, 1);
        assert_eq!(conversation.group.epoch(), 3);
    }

    #[test]
    fn join_replay_head_reopens_after_later_local_policy_acceptance() {
        let root = tempfile::tempdir().unwrap();
        let alice = open_coordinator(root.path(), "join-head-alice");
        let bob = open_coordinator(root.path(), "join-head-bob");
        let created = alice.create().unwrap();
        let invitation = alice
            .issue_invitation(
                created.conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                100,
            )
            .unwrap();
        let proof = bob
            .create_join_proof(
                invitation.invitation,
                invitation.routing_id,
                invitation.issuer_public_key,
                invitation.peer_bindings,
                50,
            )
            .unwrap();
        let add = alice
            .prepare_add_member(created.conversation_id, proof, 50, 1_900_000_000)
            .unwrap();
        let receipt = StoredRelayEnvelope::new(add.envelope, 1).unwrap();
        let accepted = alice.mark_membership_outbox_accepted(&receipt).unwrap();
        let welcome = MlsWelcome::from_bytes(&accepted.welcome.unwrap()).unwrap();
        bob.accept_welcome(created.conversation_id, &welcome, &receipt)
            .unwrap();

        let later = bob
            .prepare_change_role(
                created.conversation_id,
                alice.device_id().unwrap(),
                ConversationRole::Member,
                1_900_000_000,
            )
            .unwrap();
        let later = StoredRelayEnvelope::new(later.envelope, 2).unwrap();
        bob.mark_membership_outbox_accepted(&later).unwrap();
        assert_eq!(bob.replay_position(created.conversation_id).unwrap().1, 1);
        assert_eq!(bob.open(created.conversation_id).unwrap().group.epoch(), 2);

        drop(alice);
        drop(bob);
        let reopened = open_coordinator(root.path(), "join-head-bob");
        reopened.recover().unwrap();
        let conversation = reopened.open(created.conversation_id).unwrap();
        assert_eq!(conversation.replay_cursor, 1);
        assert_eq!(conversation.group.epoch(), 2);
    }

    #[test]
    fn explicit_orphan_rejects_pending_commit_before_hiding_journal() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();

        alice.orphan_membership(prepared.operation_id).unwrap();

        assert_eq!(alice.open(conversation_id).unwrap().group.epoch(), 1);
        assert_eq!(
            alice
                .store
                .load_membership_outbox(prepared.operation_id)
                .unwrap()
                .status,
            MembershipOutboxStatus::Orphaned
        );
    }

    #[test]
    fn stale_epoch_orphan_allows_winning_same_parent_commit_replay() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let promoted = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        let promoted = StoredRelayEnvelope::new(promoted.envelope, 1).unwrap();
        alice.mark_membership_outbox_accepted(&promoted).unwrap();
        bob.process_inbound_membership(conversation_id, &promoted, 60)
            .unwrap();
        alice
            .process_inbound_membership(conversation_id, &promoted, 60)
            .unwrap();

        let stale = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Member,
                1_900_000_000,
            )
            .unwrap();
        let winning = bob
            .prepare_change_role(
                conversation_id,
                alice.device_id().unwrap(),
                ConversationRole::Member,
                1_900_000_000,
            )
            .unwrap();
        let winning = StoredRelayEnvelope::new(winning.envelope, 2).unwrap();
        bob.mark_membership_outbox_accepted(&winning).unwrap();

        {
            let _operation = alice.operations.lock().unwrap();
            let mut conversation = alice.open_unlocked(conversation_id).unwrap();
            conversation.group.reject_pending_commit().unwrap();
        }
        alice.orphan_membership(stale.operation_id).unwrap();
        assert_eq!(
            alice
                .store
                .load_membership_outbox(stale.operation_id)
                .unwrap()
                .status,
            MembershipOutboxStatus::Orphaned
        );

        let applied = alice
            .process_inbound_membership(conversation_id, &winning, 60)
            .unwrap();
        assert_eq!(applied.epoch, 3);
        assert_eq!(alice.replay_position(conversation_id).unwrap().1, 2);
    }

    #[test]
    fn inbound_membership_replays_after_transition_checkpoint() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
        alice.mark_membership_outbox_accepted(&stored).unwrap();
        stage_membership_saved(&bob, conversation_id, &stored, false);

        let recovered = bob
            .process_inbound_membership(conversation_id, &stored, 60)
            .unwrap();

        assert!(recovered.duplicate);
        assert_eq!(bob.open(conversation_id).unwrap().group.epoch(), 2);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
    }

    #[test]
    fn inbound_membership_recovers_after_mls_epoch_persistence() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_change_role(
                conversation_id,
                bob.device_id().unwrap(),
                ConversationRole::Administrator,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
        alice.mark_membership_outbox_accepted(&stored).unwrap();
        stage_membership_saved(&bob, conversation_id, &stored, true);
        assert_eq!(
            bob.store
                .load_conversation(conversation_id)
                .unwrap()
                .state
                .epoch(),
            1
        );

        let recovered = bob.open(conversation_id).unwrap();

        assert_eq!(recovered.group.epoch(), 2);
        assert_eq!(recovered.replay_cursor, 1);
        assert!(matches!(
            bob.store
                .membership_inbox_operation(conversation_id, 1)
                .unwrap(),
            MembershipInboxOperation::Complete(_)
        ));
    }

    #[test]
    fn invitation_join_proof_and_welcome_create_a_durable_peer() {
        let (_root, alice, bob, created, welcome, receipt) = pending_join_pair();

        let joined = bob
            .accept_welcome(created.conversation_id, &welcome, &receipt)
            .unwrap();

        assert_eq!(joined.routing_id, created.routing_id);
        assert_eq!(joined.epoch, 1);
        assert_eq!(
            bob.replay_position(created.conversation_id).unwrap().1,
            receipt.cursor()
        );
        assert_eq!(
            bob.open(created.conversation_id).unwrap().group.state(),
            alice.open(created.conversation_id).unwrap().group.state()
        );
        assert!(
            bob.store
                .adapter_delivery_enabled(created.conversation_id)
                .unwrap()
        );
        assert_eq!(
            bob.active_conversation_id().unwrap(),
            Some(created.conversation_id)
        );
        assert!(bob.store.pending_join_ids(None, 10).unwrap().is_empty());
    }

    #[test]
    fn welcome_retries_after_profile_checkpoint_before_group_persistence() {
        let (_root, _alice, bob, created, welcome, receipt) = pending_join_pair();
        stage_pending_welcome(&bob, created.conversation_id, &welcome, &receipt, false);

        let joined = bob
            .accept_welcome(created.conversation_id, &welcome, &receipt)
            .unwrap();

        assert_eq!(joined.epoch, 1);
        assert_eq!(bob.open(created.conversation_id).unwrap().group.epoch(), 1);
    }

    #[test]
    fn startup_finishes_join_after_group_persistence_before_profile_publication() {
        let (_root, _alice, bob, created, welcome, receipt) = pending_join_pair();
        stage_pending_welcome(&bob, created.conversation_id, &welcome, &receipt, true);

        bob.recover().unwrap();

        assert_eq!(bob.open(created.conversation_id).unwrap().group.epoch(), 1);
        assert!(bob.store.pending_join_ids(None, 10).unwrap().is_empty());
    }

    #[test]
    fn removed_member_applies_commit_and_cannot_send_afterward() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_remove_member(conversation_id, bob.device_id().unwrap(), 1_900_000_000)
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
        alice.mark_membership_outbox_accepted(&stored).unwrap();

        let removed = bob
            .process_inbound_membership(conversation_id, &stored, 60)
            .unwrap();

        assert!(removed.removed_self);
        assert!(matches!(
            bob.prepare_application(
                conversation_id,
                ApplicationContent::text("blocked").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            ),
            Err(ConversationCoordinatorError::Cryptographic)
        ));
    }

    #[test]
    fn recovers_only_a_missing_initial_mls_group() {
        let root = tempfile::tempdir().unwrap();
        let locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("missing-group").unwrap())
                .unwrap();
        let mls_path = locked.mls_database_path();
        let profile_sealer = sealer();
        let mls_storage = SealedSqliteMlsStorage::open(&mls_path, profile_sealer.share()).unwrap();
        let store = locked.open_store(profile_sealer).unwrap();
        let device = store.load_or_create_device().unwrap();
        let conversation_id = device.generate_conversation_id().unwrap();
        let routing_id = device.generate_routing_id().unwrap();
        let material = device
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let state = initial_conversation_state(conversation_id, device.device_id()).unwrap();
        store
            .insert_conversation(routing_id, &material, &state, &[material.binding().clone()])
            .unwrap();
        assert!(
            !mls_storage
                .contains_group(conversation_id.as_bytes())
                .unwrap()
        );
        let coordinator = ConversationCoordinator::new(store, mls_storage.clone(), device);

        coordinator.recover().unwrap();

        assert!(
            mls_storage
                .contains_group(conversation_id.as_bytes())
                .unwrap()
        );
        assert_eq!(
            coordinator.open(conversation_id).unwrap().routing_id,
            routing_id
        );
    }

    #[test]
    fn rejects_missing_mls_state_after_an_epoch_advance() {
        let root = tempfile::tempdir().unwrap();
        let locked = LockedProfile::acquire(
            root.path(),
            ProfileId::parse("missing-advanced-group").unwrap(),
        )
        .unwrap();
        let mls_path = locked.mls_database_path();
        let profile_sealer = sealer();
        let mls_storage = SealedSqliteMlsStorage::open(&mls_path, profile_sealer.share()).unwrap();
        let store = locked.open_store(profile_sealer).unwrap();
        let device = store.load_or_create_device().unwrap();
        let conversation_id = device.generate_conversation_id().unwrap();
        let routing_id = device.generate_routing_id().unwrap();
        let material = device
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            1,
            vec![Member::new(
                device.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        store
            .insert_conversation(routing_id, &material, &state, &[material.binding().clone()])
            .unwrap();
        let coordinator = ConversationCoordinator::new(store, mls_storage, device);

        assert_eq!(
            coordinator.open(conversation_id).err(),
            Some(ConversationCoordinatorError::MissingMlsState)
        );
    }

    #[test]
    fn processes_and_deduplicates_authenticated_inbound_application() {
        let (_root, alice, bob, conversation_id, alice_device_id) = paired_coordinators();
        let prepared = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("hello from alice").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope.clone(), 1).unwrap();

        let received = bob
            .process_inbound_application(conversation_id, &stored)
            .unwrap();
        assert_eq!(received.conversation_id, conversation_id);
        assert_eq!(received.cursor, 1);
        assert_eq!(received.sender, alice_device_id);
        assert_eq!(received.epoch, 1);
        assert_eq!(received.message.sender_counter(), 1);
        assert!(!received.duplicate);
        assert!(matches!(
            received.message.content(),
            ApplicationContent::Text(body) if body == "hello from alice"
        ));

        let duplicate = bob
            .process_inbound_application(conversation_id, &stored)
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(
            duplicate.message.message_id(),
            received.message.message_id()
        );
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 1);
    }

    #[test]
    fn directed_requests_require_a_current_remote_member_target() {
        let (_root, alice, bob, conversation_id, _) = paired_coordinators();
        let alice_device_id = alice.device_id().unwrap();
        let bob_device_id = bob.device_id().unwrap();
        let directed = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::directed_request(bob_device_id, "confirm the contract")
                    .unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        assert!(matches!(
            directed.message.content(),
            ApplicationContent::DirectedRequest(request)
                if request.target_device_id() == bob_device_id
        ));
        for target in [
            alice_device_id,
            DeviceId::from_bytes([99; DeviceId::LENGTH]),
        ] {
            assert_eq!(
                alice
                    .prepare_application(
                        conversation_id,
                        ApplicationContent::directed_request(target, "must not send").unwrap(),
                        None,
                        1_700_000_000_001,
                        1_900_000_000,
                    )
                    .err(),
                Some(ConversationCoordinatorError::DirectedRequestUnsupported)
            );
        }
    }

    #[test]
    fn directed_requests_require_every_remote_recipient_to_support_the_content_kind() {
        let local_device = DeviceId::from_bytes([1; DeviceId::LENGTH]);
        let target = DeviceId::from_bytes([2; DeviceId::LENGTH]);
        let observer = DeviceId::from_bytes([3; DeviceId::LENGTH]);
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes([4; ConversationId::LENGTH]),
            2,
            vec![
                Member::new(local_device, ConversationRole::Administrator, 0),
                Member::new(target, ConversationRole::Member, 1),
                Member::new(observer, ConversationRole::Member, 2),
            ],
            vec![],
        )
        .unwrap();

        assert!(!directed_request_recipients_support(
            &state,
            local_device,
            target,
            |device_id| device_id == target,
        ));
        assert!(directed_request_recipients_support(
            &state,
            local_device,
            target,
            |device_id| device_id == target || device_id == observer,
        ));
    }

    #[test]
    fn directed_request_target_resolves_only_one_remote_member() {
        let root = tempfile::tempdir().unwrap();
        let solo = open_coordinator(root.path(), "request-target-solo");
        let created = solo.create().unwrap();
        assert_eq!(
            solo.directed_request_target(created.conversation_id, None),
            Err(ConversationCoordinatorError::DirectedRequestTargetRequired)
        );

        let (_root, alice, bob, conversation_id, _) = paired_coordinators();
        assert_eq!(
            alice
                .directed_request_target(conversation_id, None)
                .unwrap(),
            bob.device_id().unwrap()
        );
    }

    #[test]
    fn restart_finishes_an_exact_reserved_directed_request_response() {
        use KonclaveDomainCore::{AdapterConsumerId, AdapterLeaseId};

        use crate::persistence::{
            ClaimDirectedRequest, DirectedRequestClaimOutcome, OutboundApplicationStatus,
        };

        let (root, alice, bob, conversation_id, _) = paired_coordinators();
        let bob_device_id = bob.device_id().unwrap();
        let canonical_bundle =
            include_bytes!("../../../fixtures/protocol/v1/collaboration-policy-bundle.bin");
        let policy_digest = bob
            .store
            .store_collaboration_policy_bundle(canonical_bundle)
            .unwrap();
        bob.store
            .activate_collaboration_policy(conversation_id, policy_digest, 100)
            .unwrap();
        bob.store
            .set_adapter_delivery_enabled(conversation_id, true)
            .unwrap();

        let now = SystemUnixClock.now_unix_milliseconds();
        let expires_at = now / 1_000 + 3_600;
        let request = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::directed_request(bob_device_id, "return the agreed contract")
                    .unwrap(),
                None,
                now,
                expires_at,
            )
            .unwrap();
        let request_message_id = request.message.message_id();
        bob.process_inbound_application(
            conversation_id,
            &StoredRelayEnvelope::new(request.envelope, 1).unwrap(),
        )
        .unwrap();

        let consumer_id = AdapterConsumerId::from_bytes([81; AdapterConsumerId::LENGTH]);
        let lease_id = AdapterLeaseId::from_bytes([82; AdapterLeaseId::LENGTH]);
        bob.store
            .acquire_adapter_consumer(consumer_id, lease_id, now, now + 60_000)
            .unwrap();
        let delivery = bob
            .store
            .claim_remote_events(consumer_id, lease_id, now, now + 60_000, 1)
            .unwrap();
        let claim = match bob
            .store
            .claim_directed_request(ClaimDirectedRequest {
                conversation_id,
                request_message_id,
                responder_device_id: bob_device_id,
                notification_id: delivery[0].event.notification_id,
                consumer_id,
                lease_id,
                lease_generation: delivery[0].lease_generation,
                policy_digest,
                now_unix_milliseconds: now,
            })
            .unwrap()
        {
            DirectedRequestClaimOutcome::Claimed(claim) => claim,
            outcome => panic!("directed request was not claimed: {outcome:?}"),
        };
        let response_message_id = MessageId::from_bytes([83; MessageId::LENGTH]);
        let response_envelope_id = EnvelopeId::from_bytes([84; EnvelopeId::LENGTH]);
        bob.store
            .reserve_outbound_collaboration_action(
                conversation_id,
                response_message_id,
                response_envelope_id,
                CollaborationActionAuthorization {
                    policy_digest,
                    consumer_id,
                    not_after_unix_milliseconds: now + 60_000,
                    directed_request_claim: claim,
                },
                &ApplicationContent::text("recovered response").unwrap(),
                Some(request_message_id),
                now,
                expires_at,
            )
            .unwrap();
        drop(alice);
        drop(bob);

        let reopened = open_coordinator(root.path(), "bob");
        reopened.recover().unwrap();
        let recovered = reopened
            .outbound_application(conversation_id, response_message_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.status, OutboundApplicationStatus::Ready);
        assert_eq!(recovered.message.reply_to(), Some(request_message_id));
        assert_eq!(recovered.message.sent_at_unix_milliseconds(), now);
        assert_eq!(recovered.envelope.expires_at_unix_seconds(), expires_at);
        assert_eq!(recovered.envelope.envelope_id(), response_envelope_id);
        assert!(matches!(
            recovered.message.content(),
            ApplicationContent::Text(body) if body == "recovered response"
        ));
    }

    #[test]
    fn recovers_own_echo_after_message_saved_crash() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = open_coordinator(root.path(), "own-echo-message-saved");
        let conversation = coordinator.create().unwrap();
        let prepared = coordinator
            .prepare_application(
                conversation.conversation_id,
                ApplicationContent::text("own echo").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
        coordinator.mark_outbox_accepted(&stored).unwrap();
        stage_own_echo_saved(&coordinator, conversation.conversation_id, &stored);

        let recovered = coordinator
            .process_inbound_application(conversation.conversation_id, &stored)
            .unwrap();

        assert!(recovered.duplicate);
        assert_eq!(
            recovered.message.message_id(),
            prepared.message.message_id()
        );
        assert_eq!(
            coordinator
                .replay_position(conversation.conversation_id)
                .unwrap()
                .1,
            1
        );
    }

    #[test]
    fn rejects_altered_same_id_own_echo_before_cursor_advancement() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = open_coordinator(root.path(), "altered-own-echo");
        let conversation = coordinator.create().unwrap();
        let prepared = coordinator
            .prepare_application(
                conversation.conversation_id,
                ApplicationContent::text("original own echo").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let altered = RelayEnvelope::new(
            prepared.envelope.version(),
            prepared.envelope.routing_id(),
            prepared.envelope.envelope_id(),
            prepared.envelope.delivery_class(),
            prepared.envelope.expected_parent_epoch(),
            prepared.envelope.expires_at_unix_seconds(),
            b"altered-own-echo".to_vec(),
        )
        .unwrap();

        assert_eq!(
            coordinator
                .process_inbound_application(
                    conversation.conversation_id,
                    &StoredRelayEnvelope::new(altered, 1).unwrap(),
                )
                .err(),
            Some(ConversationCoordinatorError::Profile(
                ProfileStoreError::CursorConflict
            ))
        );
        assert_eq!(
            coordinator
                .replay_position(conversation.conversation_id)
                .unwrap()
                .1,
            0
        );
    }

    #[test]
    fn recovers_both_message_saved_receiver_ratchet_crash_points() {
        let (_root, alice, bob, conversation_id, _alice_device_id) = paired_coordinators();
        let first = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("before ratchet persistence").unwrap(),
                None,
                1_700_000_000_000,
                1_900_000_000,
            )
            .unwrap();
        let first_stored = StoredRelayEnvelope::new(first.envelope.clone(), 1).unwrap();
        stage_message_saved(&bob, conversation_id, &first_stored, false);

        let recovered_before = bob
            .process_inbound_application(conversation_id, &first_stored)
            .unwrap();
        assert!(recovered_before.duplicate);
        assert_eq!(recovered_before.message.sender_counter(), 1);

        let second = alice
            .prepare_application(
                conversation_id,
                ApplicationContent::text("after ratchet persistence").unwrap(),
                None,
                1_700_000_000_001,
                1_900_000_000,
            )
            .unwrap();
        let second_stored = StoredRelayEnvelope::new(second.envelope.clone(), 2).unwrap();
        stage_message_saved(&bob, conversation_id, &second_stored, true);

        let recovered_after = bob
            .process_inbound_application(conversation_id, &second_stored)
            .unwrap();
        assert!(recovered_after.duplicate);
        assert_eq!(recovered_after.message.sender_counter(), 2);
        assert_eq!(bob.replay_position(conversation_id).unwrap().1, 2);
    }
}
