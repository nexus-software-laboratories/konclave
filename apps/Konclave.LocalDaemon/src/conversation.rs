use std::sync::{Arc, Mutex};

use KonclaveCryptographicCore::{DeviceIdentity, MlsConversation, MlsConversationClient};
use KonclaveDomainCore::{
    ConversationId, ConversationRole, ConversationState, DeviceId, Member, ProtocolVersion,
    RoutingId,
};
use KonclaveSecretStorage::SealedSqliteMlsStorage;
use thiserror::Error;

use crate::persistence::{MAX_CONVERSATION_PAGE_SIZE, ProfileStore, ProfileStoreError};

/// Durable conversation composition over one locked daemon profile.
#[derive(Clone)]
pub(crate) struct ConversationCoordinator {
    store: Arc<ProfileStore>,
    mls_storage: SealedSqliteMlsStorage,
    device: Arc<Mutex<DeviceIdentity>>,
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
        let conversation = self.open(conversation_id)?;
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
        self.store.abandon_unsealed_outbox()?;
        let mut after = None;
        loop {
            let page = self
                .store
                .conversation_ids(after, MAX_CONVERSATION_PAGE_SIZE)?;
            let page_length = page.len();
            after = page.last().copied();
            for conversation_id in page {
                self.open(conversation_id)?;
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
}

/// One opened MLS conversation and its opaque relay route.
pub(crate) struct OpenConversation {
    pub(crate) routing_id: RoutingId,
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
mod tests {
    use std::path::Path;

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
}
