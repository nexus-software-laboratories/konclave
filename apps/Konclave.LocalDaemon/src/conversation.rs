use std::sync::{Arc, Mutex};

use KonclaveCryptographicCore::{
    DeviceIdentity, KonclaveCryptographicError, MlsApplicationMessage, MlsCommit, MlsConversation,
    MlsConversationClient, MlsWelcome, OutboundMembershipCommit, verify_device_credential_binding,
};
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, ConversationState,
    DeliveryClass, DeviceCredentialBinding, DeviceId, Ed25519PublicKey, EnvelopeId, Invitation,
    JoinProof, Member, MembershipOperationId, MessageId, NotificationId, ProtocolVersion,
    RelayEnvelope, RoutingId, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_membership_commit_bundle, decode_membership_control,
    encode_application_message, encode_join_proof, encode_membership_control,
};
use KonclaveSecretStorage::SealedSqliteMlsStorage;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::persistence::{
    ExpireOutboundResult, HistoryPage, InboxOperation, MAX_CONVERSATION_PAGE_SIZE,
    MembershipInboxOperation, MembershipOutboxStatus, MessageDirection, OutboundReservation,
    PendingOutbox, ProfileStore, ProfileStoreError, StoredMembershipTransition,
    StoredOutboundApplication,
};

/// Durable conversation composition over one locked daemon profile.
#[derive(Clone)]
pub(crate) struct ConversationCoordinator {
    store: Arc<ProfileStore>,
    mls_storage: SealedSqliteMlsStorage,
    device: Arc<Mutex<DeviceIdentity>>,
    operations: Arc<Mutex<()>>,
}

impl ConversationCoordinator {
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
        }
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

    fn generate_notification_id(&self) -> Result<NotificationId, ConversationCoordinatorError> {
        self.device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?
            .generate_notification_id()
            .map_err(|_| ConversationCoordinatorError::Cryptographic)
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
        let (conversation_id, routing_id, signing_material, device_id) = {
            let device = self
                .device
                .lock()
                .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
            let conversation_id = device
                .generate_conversation_id()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let routing_id = device
                .generate_routing_id()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let signing_material = device
                .create_conversation_signing_material(conversation_id)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            (
                conversation_id,
                routing_id,
                signing_material,
                device.device_id(),
            )
        };
        let state = initial_conversation_state(conversation_id, device_id)?;
        let binding = signing_material.binding().clone();
        self.store
            .insert_conversation(routing_id, &signing_material, &state, &[binding])?;
        let conversation = self.open_unlocked(conversation_id)?;
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
        let stored = self.store.load_conversation(conversation_id)?;
        let pending = self.store.active_membership_outbox(conversation_id)?;
        let inbound = self.store.active_membership_inbox(conversation_id)?;
        let has_group = self
            .mls_storage
            .contains_group(conversation_id.as_bytes())
            .map_err(|_| ConversationCoordinatorError::SecretStorage)?;
        if let Some(MembershipInboxOperation::TransitionSaved(transition)) = inbound {
            if pending.is_some() || !has_group || transition.parent_epoch != stored.state.epoch() {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
            let routing_id = stored.routing_id;
            let replay_cursor = stored.replay_cursor;
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            if let Ok(group) = client.restore_group(stored.state, stored.bindings, None) {
                return Ok(OpenConversation {
                    routing_id,
                    replay_cursor,
                    group,
                });
            }
            let stored = self.store.load_conversation(conversation_id)?;
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let group = client
                .restore_group(transition.next_state, transition.bindings, None)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let notification_id = self.generate_notification_id()?;
            let replay_cursor = self.store.complete_membership_inbox_with_notification(
                conversation_id,
                transition.stored.cursor(),
                notification_id,
            )?;
            return Ok(OpenConversation {
                routing_id,
                replay_cursor,
                group,
            });
        }
        let group = if !has_group {
            if pending.is_some() {
                return Err(ConversationCoordinatorError::MissingMlsState);
            }
            if stored.state.epoch() != 0 {
                return Err(ConversationCoordinatorError::MissingMlsState);
            }
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let expected_state = stored.state;
            let group = client
                .create_group()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            if group.state() != &expected_state {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
            group
        } else if let Some(pending) = pending {
            if pending.parent_epoch != stored.state.epoch()
                || pending.parent_epoch.checked_add(1) != Some(pending.next_state.epoch())
            {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
            let operation_id = pending.operation_id;
            let status = pending.status;
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            match client.restore_group(stored.state, pending.bindings, Some(pending.next_state)) {
                Ok(mut group) => {
                    if status == MembershipOutboxStatus::Accepted {
                        group
                            .accept_pending_commit()
                            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                        self.store.complete_membership_outbox(operation_id)?;
                    }
                    group
                }
                Err(_) if status == MembershipOutboxStatus::Accepted => {
                    let stored = self.store.load_conversation(conversation_id)?;
                    let pending = self.store.load_membership_outbox(operation_id)?;
                    let client = MlsConversationClient::with_storage(
                        stored.signing_material,
                        self.mls_storage.clone(),
                    )
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                    let group = client
                        .restore_group(pending.next_state, pending.bindings, None)
                        .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                    self.store.complete_membership_outbox(operation_id)?;
                    group
                }
                Err(_) if status == MembershipOutboxStatus::Ready => {
                    let stored = self.store.load_conversation(conversation_id)?;
                    let client = MlsConversationClient::with_storage(
                        stored.signing_material,
                        self.mls_storage.clone(),
                    )
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                    let group = client
                        .restore_group(stored.state, stored.bindings, None)
                        .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                    if group.has_pending_membership_commit() {
                        return Err(ConversationCoordinatorError::StateMismatch);
                    }
                    self.store.orphan_membership_outbox(operation_id)?;
                    group
                }
                Err(_) => return Err(ConversationCoordinatorError::StateMismatch),
            }
        } else {
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let group = client
                .restore_group(stored.state, stored.bindings, None)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            if group.has_pending_membership_commit() {
                return Err(ConversationCoordinatorError::MissingMembershipJournal);
            }
            group
        };
        Ok(OpenConversation {
            routing_id: stored.routing_id,
            replay_cursor: stored.replay_cursor,
            group,
        })
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
        self.store.abandon_unsealed_outbox()?;
        let mut pending_after = None;
        loop {
            let page = self
                .store
                .pending_join_ids(pending_after, MAX_CONVERSATION_PAGE_SIZE)?;
            let page_length = page.len();
            pending_after = page.last().copied();
            for conversation_id in page {
                match self.store.load_conversation(conversation_id) {
                    Ok(_) => {
                        self.store.delete_pending_join(conversation_id)?;
                    }
                    Err(ProfileStoreError::ConversationNotFound) => {
                        let pending = self.store.load_pending_join(conversation_id)?;
                        let has_group = self
                            .mls_storage
                            .contains_group(conversation_id.as_bytes())
                            .map_err(|_| ConversationCoordinatorError::SecretStorage)?;
                        match (pending.state.is_some(), has_group) {
                            (true, true) => {
                                self.finalize_pending_join_unlocked(conversation_id)?;
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
            return self.finalize_pending_join_unlocked(conversation_id);
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
        self.finalize_pending_join_unlocked(conversation_id)
    }

    fn finalize_pending_join_unlocked(
        &self,
        conversation_id: ConversationId,
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
            join_receipt.cursor(),
            Some(join_receipt),
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
            }
            Err(error) => return Err(error.into()),
        }
        match self.store.delete_pending_join(conversation_id) {
            Ok(()) | Err(ProfileStoreError::OperationNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(ConversationSummary {
            conversation_id,
            routing_id: pending.routing_id,
            epoch: state.epoch(),
        })
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
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedApplication, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let envelope_id = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?
            .generate_envelope_id()
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let reservation =
            self.store
                .reserve_outbound_application(conversation_id, message_id, envelope_id)?;
        match self.prepare_reserved_application(
            reservation,
            content,
            reply_to,
            sent_at_unix_milliseconds,
            expires_at_unix_seconds,
        ) {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                self.store.abandon_outbound_application(reservation)?;
                Err(error)
            }
        }
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
        let message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            reservation.message_id,
            reservation.sender_counter,
            sent_at_unix_milliseconds,
            reply_to,
            content,
        )
        .map_err(|_| ConversationCoordinatorError::Protocol)?;
        let plaintext = Zeroizing::new(
            encode_application_message(&message)
                .map_err(|_| ConversationCoordinatorError::Protocol)?,
        );
        let mut conversation = self.open_unlocked(reservation.conversation_id)?;
        let sender = self.device_id()?;
        let epoch = conversation.group.epoch();
        let ciphertext = conversation
            .group
            .encrypt_application_message(&plaintext)
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            conversation.routing_id,
            reservation.envelope_id,
            DeliveryClass::GroupApplication,
            None,
            expires_at_unix_seconds,
            ciphertext.into_bytes(),
        )
        .map_err(|_| ConversationCoordinatorError::Protocol)?;
        self.store.store_outbound_message(
            reservation,
            conversation.routing_id,
            sender,
            epoch,
            &message,
        )?;
        self.store.store_outbound_envelope(reservation, &envelope)?;
        Ok(PreparedApplication {
            conversation_id: reservation.conversation_id,
            message,
            envelope,
        })
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
        self.prepare_membership(
            conversation_id,
            expires_at_unix_seconds,
            |group, envelope_id| group.create_add_commit(join_proof, envelope_id, now_unix_seconds),
        )
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
        self.prepare_membership(conversation_id, expires_at_unix_seconds, |group, _| {
            group.create_remove_commit(device_id)
        })
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
        self.prepare_membership(conversation_id, expires_at_unix_seconds, |group, _| {
            group.create_change_role_commit(device_id, role)
        })
    }

    fn prepare_membership(
        &self,
        conversation_id: ConversationId,
        expires_at_unix_seconds: u64,
        create: impl FnOnce(
            &mut MlsConversation,
            EnvelopeId,
        ) -> Result<OutboundMembershipCommit, KonclaveCryptographicError>,
    ) -> Result<PreparedMembership, ConversationCoordinatorError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let envelope_id = self
            .device
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?
            .generate_envelope_id()
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let mut conversation = self.open_unlocked(conversation_id)?;
        let parent_epoch = conversation.group.epoch();
        let outbound = create(&mut conversation.group, envelope_id)
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let operation_id = outbound.authorization().operation_id();
        let control = Zeroizing::new(
            encode_membership_control(outbound.authorization(), outbound.join_proof())
                .map_err(|_| ConversationCoordinatorError::Protocol)?,
        );
        let payload = outbound
            .encode_bundle()
            .map_err(|_| ConversationCoordinatorError::Protocol)?;
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            conversation.routing_id,
            envelope_id,
            DeliveryClass::GroupCommit,
            Some(parent_epoch),
            expires_at_unix_seconds,
            payload,
        )
        .map_err(|_| ConversationCoordinatorError::Protocol)?;
        let stored = self.store.load_conversation(conversation_id)?;
        let mut bindings = stored
            .bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        if let Some(join_proof) = outbound.join_proof() {
            let binding = join_proof.credential().clone();
            verify_device_credential_binding(&binding)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            if !bindings
                .iter()
                .any(|existing| existing.device_id() == binding.device_id())
            {
                bindings.push(binding);
            }
        }
        let welcome = outbound
            .welcome()
            .map(|welcome| welcome.as_bytes().to_vec());
        let journaled = self.store.store_membership_outbox(
            operation_id,
            conversation_id,
            parent_epoch,
            &envelope,
            &control,
            outbound.next_state(),
            &bindings,
            welcome.as_deref(),
        );
        if let Err(error) = journaled {
            conversation
                .group
                .reject_pending_commit()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            return Err(error.into());
        }
        Ok(PreparedMembership {
            operation_id,
            conversation_id,
            parent_epoch,
            envelope,
            welcome,
        })
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
        let initial = self.store.load_membership_outbox(operation_id)?;
        let mut conversation = self.open_unlocked(initial.conversation_id)?;
        let pending = self.store.load_membership_outbox(operation_id)?;
        if pending.status == MembershipOutboxStatus::Orphaned {
            return if conversation.group.has_pending_membership_commit() {
                Err(ConversationCoordinatorError::StateMismatch)
            } else {
                Ok(())
            };
        }
        if pending.status != MembershipOutboxStatus::Ready
            || conversation.group.state().epoch() != pending.parent_epoch
        {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        if conversation.group.has_pending_membership_commit() {
            conversation
                .group
                .reject_pending_commit()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        }
        self.store.orphan_membership_outbox(operation_id)?;
        Ok(())
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
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let mut conversation = self.open_unlocked(conversation_id)?;
        if conversation.routing_id != stored.envelope().routing_id() {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        let recorded_conversation = self.store.record_inbox_envelope(stored)?;
        if recorded_conversation != conversation_id {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        match self
            .store
            .inbox_operation(conversation_id, stored.cursor())?
        {
            InboxOperation::Received { stored } => {
                if let Some(outbound) = self
                    .store
                    .outbound_history_message(conversation_id, &stored)?
                {
                    self.store.save_inbox_message(
                        conversation_id,
                        stored.cursor(),
                        outbound.sender,
                        outbound.epoch,
                        &outbound.message,
                    )?;
                    let notification_id = self.generate_notification_id()?;
                    self.store.complete_inbox_with_notification(
                        conversation_id,
                        stored.cursor(),
                        notification_id,
                    )?;
                    return Ok(ProcessedApplication {
                        conversation_id,
                        cursor: stored.cursor(),
                        envelope_id: stored.envelope().envelope_id(),
                        sender: outbound.sender,
                        epoch: outbound.epoch,
                        message: outbound.message,
                        direction: MessageDirection::Outbound,
                        duplicate: true,
                    });
                }
                let epoch = conversation.group.epoch();
                let (sender, message) =
                    decrypt_application(&mut conversation.group, stored.envelope())?;
                self.store.save_inbox_message(
                    conversation_id,
                    stored.cursor(),
                    sender,
                    epoch,
                    &message,
                )?;
                conversation
                    .group
                    .persist()
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                let notification_id = self.generate_notification_id()?;
                self.store.complete_inbox_with_notification(
                    conversation_id,
                    stored.cursor(),
                    notification_id,
                )?;
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    envelope_id: stored.envelope().envelope_id(),
                    sender,
                    epoch,
                    message,
                    direction: MessageDirection::Inbound,
                    duplicate: false,
                })
            }
            InboxOperation::MessageSaved { stored, message } => {
                if let Some(outbound) = self
                    .store
                    .outbound_history_message(conversation_id, &stored)?
                {
                    if outbound.sender != message.sender
                        || outbound.epoch != message.epoch
                        || !application_messages_equal(&outbound.message, &message.message)?
                    {
                        return Err(ConversationCoordinatorError::StateMismatch);
                    }
                    let notification_id = self.generate_notification_id()?;
                    self.store.complete_inbox_with_notification(
                        conversation_id,
                        stored.cursor(),
                        notification_id,
                    )?;
                    return Ok(ProcessedApplication {
                        conversation_id,
                        cursor: stored.cursor(),
                        envelope_id: stored.envelope().envelope_id(),
                        sender: message.sender,
                        epoch: message.epoch,
                        message: message.message,
                        direction: MessageDirection::Outbound,
                        duplicate: true,
                    });
                }
                if conversation.group.epoch() != message.epoch {
                    return Err(ConversationCoordinatorError::StateMismatch);
                }
                let ciphertext = MlsApplicationMessage::from_bytes(stored.envelope().payload())
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                match conversation.group.decrypt_application_message(&ciphertext) {
                    Ok(decrypted) => {
                        let decoded = decode_application_message(decrypted.plaintext())
                            .map_err(|_| ConversationCoordinatorError::Protocol)?;
                        if decrypted.authenticated_sender() != message.sender
                            || !application_messages_equal(&decoded, &message.message)?
                        {
                            return Err(ConversationCoordinatorError::StateMismatch);
                        }
                        conversation
                            .group
                            .persist()
                            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                    }
                    Err(KonclaveCryptographicError::ApplicationMessageAlreadyProcessed) => {}
                    Err(_) => {
                        return Err(ConversationCoordinatorError::Cryptographic);
                    }
                }
                let notification_id = self.generate_notification_id()?;
                self.store.complete_inbox_with_notification(
                    conversation_id,
                    stored.cursor(),
                    notification_id,
                )?;
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    envelope_id: stored.envelope().envelope_id(),
                    sender: message.sender,
                    epoch: message.epoch,
                    message: message.message,
                    direction: MessageDirection::Inbound,
                    duplicate: true,
                })
            }
            InboxOperation::Complete { stored, message } => {
                let direction = if self
                    .store
                    .outbound_history_message(conversation_id, &stored)?
                    .is_some()
                {
                    MessageDirection::Outbound
                } else {
                    MessageDirection::Inbound
                };
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    envelope_id: stored.envelope().envelope_id(),
                    sender: message.sender,
                    epoch: message.epoch,
                    message: message.message,
                    direction,
                    duplicate: true,
                })
            }
        }
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
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let recorded_conversation = self.store.record_membership_inbox_envelope(stored)?;
        if recorded_conversation != conversation_id {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        if let Some(outbox) = self
            .store
            .membership_outbox_for_envelope(stored.envelope().envelope_id())?
        {
            if outbox.envelope != *stored.envelope() || outbox.conversation_id != conversation_id {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
            if outbox.status == MembershipOutboxStatus::Ready {
                self.store.mark_membership_outbox_accepted(stored)?;
            }
            let conversation = self.open_unlocked(conversation_id)?;
            if conversation.group.state() != &outbox.next_state {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
            let operation_id = self
                .store
                .complete_membership_echo(stored, self.device_id()?)?;
            return Ok(ProcessedMembership {
                conversation_id,
                cursor: stored.cursor(),
                operation_id,
                sender: self.device_id()?,
                epoch: outbox.next_state.epoch(),
                removed_self: outbox.next_state.member(self.device_id()?).is_none(),
                duplicate: true,
            });
        }
        if let Some(local) = self.store.active_membership_outbox(conversation_id)? {
            if local.parent_epoch
                == stored
                    .envelope()
                    .expected_parent_epoch()
                    .unwrap_or(u64::MAX)
                && local.status == MembershipOutboxStatus::Ready
            {
                self.orphan_membership_unlocked(local.operation_id)?;
            } else {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
        }
        match self
            .store
            .membership_inbox_operation(conversation_id, stored.cursor())?
        {
            MembershipInboxOperation::Received { stored } => {
                let mut conversation = self.open_unlocked(conversation_id)?;
                if conversation.routing_id != stored.envelope().routing_id()
                    || conversation.group.epoch()
                        != stored
                            .envelope()
                            .expected_parent_epoch()
                            .ok_or(ConversationCoordinatorError::Protocol)?
                {
                    return Err(ConversationCoordinatorError::StateMismatch);
                }
                let bundle = decode_membership_commit_bundle(stored.envelope().payload())
                    .map_err(|_| ConversationCoordinatorError::Protocol)?;
                let encrypted_control =
                    MlsApplicationMessage::from_bytes(bundle.encrypted_control())
                        .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                let decrypted = conversation
                    .group
                    .decrypt_application_message(&encrypted_control)
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                let sender = decrypted.authenticated_sender();
                let (authorization, join_proof) = decode_membership_control(decrypted.plaintext())
                    .map_err(|_| ConversationCoordinatorError::Protocol)?;
                let next_epoch = conversation
                    .group
                    .epoch()
                    .checked_add(1)
                    .ok_or(ConversationCoordinatorError::StateMismatch)?;
                let next_state = conversation
                    .group
                    .state()
                    .apply_membership_authorization(sender, &authorization, next_epoch)
                    .map_err(|_| ConversationCoordinatorError::StateMismatch)?;
                let current = self.store.load_conversation(conversation_id)?;
                let mut bindings = current
                    .bindings
                    .iter()
                    .map(|binding| binding.binding().clone())
                    .collect::<Vec<_>>();
                if let Some(proof) = &join_proof {
                    let binding = proof.credential().clone();
                    verify_device_credential_binding(&binding)
                        .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
                    if !bindings
                        .iter()
                        .any(|existing| existing.device_id() == binding.device_id())
                    {
                        bindings.push(binding);
                    }
                }
                self.store.save_membership_inbox_transition(
                    conversation_id,
                    stored.cursor(),
                    sender,
                    authorization.parent_epoch(),
                    authorization.operation_id(),
                    decrypted.plaintext(),
                    &next_state,
                    &bindings,
                )?;
                let transition = match self
                    .store
                    .membership_inbox_operation(conversation_id, stored.cursor())?
                {
                    MembershipInboxOperation::TransitionSaved(transition) => transition,
                    _ => return Err(ConversationCoordinatorError::StateMismatch),
                };
                self.process_saved_membership(
                    &mut conversation.group,
                    transition,
                    now_unix_seconds,
                    false,
                )
            }
            MembershipInboxOperation::TransitionSaved(_transition) => {
                let mut conversation = self.open_unlocked(conversation_id)?;
                match self
                    .store
                    .membership_inbox_operation(conversation_id, stored.cursor())?
                {
                    MembershipInboxOperation::Complete(complete) => {
                        Ok(processed_membership(complete, self.device_id()?, true))
                    }
                    MembershipInboxOperation::TransitionSaved(saved) => self
                        .process_saved_membership(
                            &mut conversation.group,
                            saved,
                            now_unix_seconds,
                            true,
                        ),
                    _ => Err(ConversationCoordinatorError::StateMismatch),
                }
            }
            MembershipInboxOperation::Complete(transition) => {
                Ok(processed_membership(transition, self.device_id()?, true))
            }
        }
    }

    fn process_saved_membership(
        &self,
        group: &mut MlsConversation,
        transition: StoredMembershipTransition,
        now_unix_seconds: u64,
        duplicate: bool,
    ) -> Result<ProcessedMembership, ConversationCoordinatorError> {
        if group.epoch() != transition.parent_epoch {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        let bundle = decode_membership_commit_bundle(transition.stored.envelope().payload())
            .map_err(|_| ConversationCoordinatorError::Protocol)?;
        if duplicate {
            let encrypted_control = MlsApplicationMessage::from_bytes(bundle.encrypted_control())
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            let decrypted = group
                .decrypt_application_message(&encrypted_control)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            if decrypted.authenticated_sender() != transition.sender
                || decrypted.plaintext() != transition.control.as_slice()
            {
                return Err(ConversationCoordinatorError::StateMismatch);
            }
        }
        let commit = MlsCommit::from_bytes(bundle.mls_commit())
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let (authorization, join_proof) = decode_membership_control(&transition.control)
            .map_err(|_| ConversationCoordinatorError::Protocol)?;
        let applied = group
            .process_membership_commit(&commit, authorization, join_proof, now_unix_seconds)
            .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        if applied.authenticated_sender() != transition.sender
            || applied.epoch() != transition.next_state.epoch()
            || group.state() != &transition.next_state
        {
            return Err(ConversationCoordinatorError::StateMismatch);
        }
        let notification_id = self.generate_notification_id()?;
        self.store.complete_membership_inbox_with_notification(
            transition.next_state.conversation_id(),
            transition.stored.cursor(),
            notification_id,
        )?;
        Ok(ProcessedMembership {
            conversation_id: transition.next_state.conversation_id(),
            cursor: transition.stored.cursor(),
            operation_id: transition.operation_id,
            sender: transition.sender,
            epoch: applied.epoch(),
            removed_self: applied.removed_self(),
            duplicate,
        })
    }
}

fn processed_membership(
    transition: StoredMembershipTransition,
    self_device_id: DeviceId,
    duplicate: bool,
) -> ProcessedMembership {
    let self_removed = transition.next_state.member(self_device_id).is_none();
    ProcessedMembership {
        conversation_id: transition.next_state.conversation_id(),
        cursor: transition.stored.cursor(),
        operation_id: transition.operation_id,
        sender: transition.sender,
        epoch: transition.next_state.epoch(),
        removed_self: self_removed,
        duplicate,
    }
}

/// One sender-ratcheted application message and its sealed relay envelope.
pub(crate) struct PreparedApplication {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message: ApplicationMessage,
    pub(crate) envelope: RelayEnvelope,
}

/// One pending MLS membership transition and its opaque relay envelope.
pub(crate) struct PreparedMembership {
    pub(crate) operation_id: MembershipOperationId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) parent_epoch: u64,
    pub(crate) envelope: RelayEnvelope,
    pub(crate) welcome: Option<Vec<u8>>,
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

/// One authenticated application message recovered from a relay cursor.
pub(crate) struct ProcessedApplication {
    pub(crate) conversation_id: ConversationId,
    pub(crate) cursor: u64,
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) sender: DeviceId,
    pub(crate) epoch: u64,
    pub(crate) message: ApplicationMessage,
    pub(crate) direction: MessageDirection,
    pub(crate) duplicate: bool,
}

/// One authenticated membership transition recovered from a relay cursor.
pub(crate) struct ProcessedMembership {
    pub(crate) conversation_id: ConversationId,
    pub(crate) cursor: u64,
    pub(crate) operation_id: MembershipOperationId,
    pub(crate) sender: DeviceId,
    pub(crate) epoch: u64,
    pub(crate) removed_self: bool,
    pub(crate) duplicate: bool,
}

/// One opened MLS conversation and its opaque relay route.
pub(crate) struct OpenConversation {
    pub(crate) routing_id: RoutingId,
    pub(crate) replay_cursor: u64,
    pub(crate) group: MlsConversation,
}

impl OpenConversation {
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
    #[error("conversation operation is not authorized")]
    Unauthorized,
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

fn decrypt_application(
    group: &mut MlsConversation,
    envelope: &RelayEnvelope,
) -> Result<(DeviceId, ApplicationMessage), ConversationCoordinatorError> {
    if envelope.delivery_class() != DeliveryClass::GroupApplication {
        return Err(ConversationCoordinatorError::Protocol);
    }
    let ciphertext = MlsApplicationMessage::from_bytes(envelope.payload())
        .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
    let decrypted = group
        .decrypt_application_message(&ciphertext)
        .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
    let sender = decrypted.authenticated_sender();
    let message = decode_application_message(decrypted.plaintext())
        .map_err(|_| ConversationCoordinatorError::Protocol)?;
    Ok((sender, message))
}

fn application_messages_equal(
    left: &ApplicationMessage,
    right: &ApplicationMessage,
) -> Result<bool, ConversationCoordinatorError> {
    let left = Zeroizing::new(
        encode_application_message(left).map_err(|_| ConversationCoordinatorError::Protocol)?,
    );
    let right = Zeroizing::new(
        encode_application_message(right).map_err(|_| ConversationCoordinatorError::Protocol)?,
    );
    Ok(left == right)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use KonclaveCryptographicCore::{
        ConversationSigningMaterial, MlsWelcome, verify_device_credential_binding,
    };
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;
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
