use std::sync::{Arc, Mutex};

use KonclaveCryptographicCore::{
    DeviceIdentity, KonclaveCryptographicError, MlsApplicationMessage, MlsConversation,
    MlsConversationClient,
};
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, ConversationState,
    DeliveryClass, DeviceId, Member, MessageId, ProtocolVersion, RelayEnvelope, RoutingId,
    StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{decode_application_message, encode_application_message};
use KonclaveSecretStorage::SealedSqliteMlsStorage;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::persistence::{
    InboxOperation, MAX_CONVERSATION_PAGE_SIZE, OutboundReservation, PendingOutbox, ProfileStore,
    ProfileStoreError, StoredHistoryMessage,
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
        let has_group = self
            .mls_storage
            .contains_group(conversation_id.as_bytes())
            .map_err(|_| ConversationCoordinatorError::SecretStorage)?;
        let client =
            MlsConversationClient::with_storage(stored.signing_material, self.mls_storage.clone())
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
        let group = if has_group {
            client
                .restore_group(stored.state, stored.bindings, None)
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?
        } else {
            if stored.state.epoch() != 0 {
                return Err(ConversationCoordinatorError::MissingMlsState);
            }
            let expected_state = stored.state;
            let group = client
                .create_group()
                .map_err(|_| ConversationCoordinatorError::Cryptographic)?;
            if group.state() != &expected_state {
                return Err(ConversationCoordinatorError::StateMismatch);
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
        let _operation = self
            .operations
            .lock()
            .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
        let (message_id, envelope_id) = {
            let device = self
                .device
                .lock()
                .map_err(|_| ConversationCoordinatorError::StateUnavailable)?;
            (
                device
                    .generate_message_id()
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
                device
                    .generate_envelope_id()
                    .map_err(|_| ConversationCoordinatorError::Cryptographic)?,
            )
        };
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

    /// Loads bounded ready envelopes for idempotent relay retry.
    ///
    /// # Errors
    ///
    /// Returns a profile bounds, authentication, protocol, or storage error.
    pub(crate) fn ready_outbox(&self) -> Result<Vec<PendingOutbox>, ConversationCoordinatorError> {
        self.store.ready_outbox().map_err(Into::into)
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
    ) -> Result<Vec<StoredHistoryMessage>, ConversationCoordinatorError> {
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
                if let Some(outbound) = self.store.outbound_history_message(
                    conversation_id,
                    stored.envelope().envelope_id(),
                    stored.cursor(),
                )? {
                    self.store.save_inbox_message(
                        conversation_id,
                        stored.cursor(),
                        outbound.sender,
                        outbound.epoch,
                        &outbound.message,
                    )?;
                    self.store
                        .complete_inbox(conversation_id, stored.cursor())?;
                    return Ok(ProcessedApplication {
                        conversation_id,
                        cursor: stored.cursor(),
                        sender: outbound.sender,
                        epoch: outbound.epoch,
                        message: outbound.message,
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
                self.store
                    .complete_inbox(conversation_id, stored.cursor())?;
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    sender,
                    epoch,
                    message,
                    duplicate: false,
                })
            }
            InboxOperation::MessageSaved { stored, message } => {
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
                self.store
                    .complete_inbox(conversation_id, stored.cursor())?;
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    sender: message.sender,
                    epoch: message.epoch,
                    message: message.message,
                    duplicate: true,
                })
            }
            InboxOperation::Complete { stored, message } => Ok(ProcessedApplication {
                conversation_id,
                cursor: stored.cursor(),
                sender: message.sender,
                epoch: message.epoch,
                message: message.message,
                duplicate: true,
            }),
        }
    }
}

/// One sender-ratcheted application message and its sealed relay envelope.
pub(crate) struct PreparedApplication {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message: ApplicationMessage,
    pub(crate) envelope: RelayEnvelope,
}

/// One authenticated application message recovered from a relay cursor.
pub(crate) struct ProcessedApplication {
    pub(crate) conversation_id: ConversationId,
    pub(crate) cursor: u64,
    pub(crate) sender: DeviceId,
    pub(crate) epoch: u64,
    pub(crate) message: ApplicationMessage,
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
    #[error("profile and MLS conversation state disagree")]
    StateMismatch,
    #[error("application protocol construction failed")]
    Protocol,
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

    fn open_coordinator(root: &Path, profile_name: &str) -> ConversationCoordinator {
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
                bob_identity.device_id(),
                ConversationRole::Member,
                100,
            )
            .unwrap();
        let proof = bob_client
            .create_join_proof(&bob_identity, invitation, alice_identity.public_key(), 50)
            .unwrap();
        let add = alice_group.create_add_commit(proof, 50).unwrap();
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
