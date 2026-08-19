use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use KonclaveDomainCore::{
    AddMember, ConversationId, ConversationRole, ConversationState, DeviceCredentialBinding,
    DeviceId, Invitation, JoinProof, MAX_APPLICATION_MESSAGE_BYTES, MAX_MLS_KEY_PACKAGE_BYTES,
    MAX_RELAY_PAYLOAD_BYTES, Member, MembershipAuthorization, MembershipChange,
    MembershipOperationId, ProtocolVersion, RemoveMember,
};
use KonclaveProtocolContracts::v1::{
    decode_conversation_state, encode_conversation_state, encode_membership_change,
};
use KonclaveSecretStorage::SealedSqliteMlsStorage;
use mls_rs::client::MlsError;
use mls_rs::client_builder::{
    BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::error::IntoAnyError;
use mls_rs::group::{
    CommitEffect, ContentType, ReceivedMessage, Roster,
    proposal::{AddProposal, Proposal},
};
use mls_rs::identity::{SigningIdentity, basic::BasicCredential};
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle,
};
use mls_rs::{
    CipherSuiteProvider, Client, ExtensionList, Group, GroupStateStorage, IdentityProvider,
    KeyPackageStorage, MlsMessage, MlsMessageDescription, MlsRules,
};
use mls_rs_core::crypto::SignaturePublicKey;
use mls_rs_core::extension::ExtensionType;
use mls_rs_core::group::{EpochRecord, GroupState};
use mls_rs_core::identity::MemberValidationContext;
use mls_rs_core::key_package::KeyPackageData;
use mls_rs_core::time::MlsTime;
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::identity::{CIPHER_SUITE, cipher_suite, configured_provider, credential_binding_hash};
use crate::{
    DeviceIdentity, KonclaveCryptographicError, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding, verify_invitation,
};

type KonclaveMlsConfig = WithMlsRules<
    KonclaveMlsRules,
    WithIdentityProvider<
        KonclaveIdentityProvider,
        WithGroupStateStorage<
            KonclaveStorage,
            WithKeyPackageRepo<
                KonclaveStorage,
                WithCryptoProvider<AwsLcCryptoProvider, BaseConfig>,
            >,
        >,
    >,
>;

type KonclaveMlsClient = Client<KonclaveMlsConfig>;
type KonclaveMlsGroup = Group<KonclaveMlsConfig>;
const MEMBERSHIP_AUTH_DOMAIN: &[u8] = b"konclave-membership-authorization-v1\0";
const CONVERSATION_STATE_DOMAIN: &[u8] = b"konclave-conversation-state-v1\0";
const CONVERSATION_STATE_EXTENSION: ExtensionType = ExtensionType::new(0xff00);
const CONVERSATION_STATE_DIGEST_EXTENSION: ExtensionType = ExtensionType::new(0xff01);

#[derive(Clone)]
enum KonclaveStorage {
    Memory {
        groups: mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage,
        key_packages: mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage,
    },
    Persistent(SealedSqliteMlsStorage),
}

impl KonclaveStorage {
    fn memory() -> Self {
        Self::Memory {
            groups: Default::default(),
            key_packages: Default::default(),
        }
    }
}

#[derive(Debug, Error)]
#[error("Konclave MLS storage failed")]
struct KonclaveStorageError;

impl IntoAnyError for KonclaveStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl GroupStateStorage for KonclaveStorage {
    type Error = KonclaveStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match self {
            Self::Memory { groups, .. } => groups.state(group_id).map_err(|_| KonclaveStorageError),
            Self::Persistent(storage) => storage.state(group_id).map_err(|_| KonclaveStorageError),
        }
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match self {
            Self::Memory { groups, .. } => groups
                .epoch(group_id, epoch_id)
                .map_err(|_| KonclaveStorageError),
            Self::Persistent(storage) => storage
                .epoch(group_id, epoch_id)
                .map_err(|_| KonclaveStorageError),
        }
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Memory { groups, .. } => groups
                .write(state, epoch_inserts, epoch_updates)
                .map_err(|_| KonclaveStorageError),
            Self::Persistent(storage) => storage
                .write(state, epoch_inserts, epoch_updates)
                .map_err(|_| KonclaveStorageError),
        }
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        match self {
            Self::Memory { groups, .. } => groups
                .max_epoch_id(group_id)
                .map_err(|_| KonclaveStorageError),
            Self::Persistent(storage) => storage
                .max_epoch_id(group_id)
                .map_err(|_| KonclaveStorageError),
        }
    }
}

impl KeyPackageStorage for KonclaveStorage {
    type Error = KonclaveStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Memory { key_packages, .. } => {
                KeyPackageStorage::delete(key_packages, id).map_err(|_| KonclaveStorageError)
            }
            Self::Persistent(storage) => storage.delete(id).map_err(|_| KonclaveStorageError),
        }
    }

    fn insert(&mut self, id: Vec<u8>, package: KeyPackageData) -> Result<(), Self::Error> {
        match self {
            Self::Memory { key_packages, .. } => key_packages
                .insert(id, package)
                .map_err(|_| KonclaveStorageError),
            Self::Persistent(storage) => storage
                .insert(id, package)
                .map_err(|_| KonclaveStorageError),
        }
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        match self {
            Self::Memory { key_packages, .. } => {
                KeyPackageStorage::get(key_packages, id).map_err(|_| KonclaveStorageError)
            }
            Self::Persistent(storage) => storage.get(id).map_err(|_| KonclaveStorageError),
        }
    }
}

/// MLS client configured for one device and conversation-scoped signing identity.
pub struct MlsConversationClient {
    client: KonclaveMlsClient,
    policy: PolicyHandle,
    binding: DeviceCredentialBinding,
    join_expectation: Option<JoinExpectation>,
}

impl DeviceIdentity {
    /// Creates an in-memory MLS client with a fresh conversation-scoped signing key.
    ///
    /// Secret persistence is intentionally absent until a key-custody ADR defines a
    /// sealed storage adapter.
    ///
    /// # Errors
    ///
    /// Returns a typed cryptographic error when identity generation or client
    /// configuration fails.
    pub fn create_conversation_client(
        &self,
        conversation_id: ConversationId,
    ) -> Result<MlsConversationClient, KonclaveCryptographicError> {
        let material = self.create_conversation_signing_material(conversation_id)?;
        MlsConversationClient::new(material)
    }
}

impl MlsConversationClient {
    fn new(
        material: crate::ConversationSigningMaterial,
    ) -> Result<Self, KonclaveCryptographicError> {
        Self::new_with_storage(material, KonclaveStorage::memory())
    }

    /// Creates an MLS client backed by sealed SQLite group and KeyPackage storage.
    ///
    /// # Errors
    ///
    /// Returns a typed cryptographic error when client configuration fails.
    pub fn with_storage(
        material: crate::ConversationSigningMaterial,
        storage: SealedSqliteMlsStorage,
    ) -> Result<Self, KonclaveCryptographicError> {
        Self::new_with_storage(material, KonclaveStorage::Persistent(storage))
    }

    fn new_with_storage(
        material: crate::ConversationSigningMaterial,
        storage: KonclaveStorage,
    ) -> Result<Self, KonclaveCryptographicError> {
        let (secret_key, binding) = material.into_parts();
        let hash = credential_binding_hash(&binding)?;
        let policy = PolicyHandle::new(binding.conversation_id());
        policy.register_binding(RegisteredBinding {
            binding: binding.clone(),
            hash,
        })?;
        let rules = KonclaveMlsRules {
            policy: policy.clone(),
        };
        let identity_provider = KonclaveIdentityProvider {
            policy: policy.clone(),
        };
        let credential = BasicCredential::new(binding.device_id().as_bytes().to_vec());
        let signing_identity = SigningIdentity::new(
            credential.into_credential(),
            SignaturePublicKey::new_slice(binding.conversation_signature_public_key().as_bytes()),
        );
        let client = Client::builder()
            .crypto_provider(configured_provider())
            .key_package_repo(storage.clone())
            .group_state_storage(storage)
            .identity_provider(identity_provider)
            .mls_rules(rules)
            .extension_type(CONVERSATION_STATE_DIGEST_EXTENSION)
            .signing_identity(signing_identity, secret_key, CIPHER_SUITE)
            .build();
        Ok(Self {
            client,
            policy,
            binding,
            join_expectation: None,
        })
    }

    /// Returns this device's public conversation credential binding.
    #[must_use]
    pub const fn binding(&self) -> &DeviceCredentialBinding {
        &self.binding
    }

    /// Registers a peer credential already proven authentic under its device root.
    ///
    /// # Errors
    ///
    /// Returns a conversation mismatch or authorization-state error.
    pub fn register_verified_binding(
        &self,
        verified: VerifiedDeviceCredentialBinding,
    ) -> Result<(), KonclaveCryptographicError> {
        if verified.binding().conversation_id() != self.binding.conversation_id() {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        let hash = verified.hash();
        self.policy.register_binding(RegisteredBinding {
            binding: verified.into_binding(),
            hash,
        })
    }

    /// Restores a previously generated join proof before processing its Welcome.
    ///
    /// The matching KeyPackage private data must already exist in this client's
    /// configured sealed storage.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the proof, invitation, credential, or KeyPackage
    /// does not match this client.
    pub fn restore_join_proof(
        &mut self,
        proof: &JoinProof,
        issuer_public_key: KonclaveDomainCore::Ed25519PublicKey,
        now_unix_seconds: u64,
    ) -> Result<(), KonclaveCryptographicError> {
        if self.join_expectation.is_some() {
            return Err(KonclaveCryptographicError::PendingJoinExists);
        }
        verify_invitation(proof.invitation(), issuer_public_key, now_unix_seconds)?;
        if proof.invitation().conversation_id() != self.binding.conversation_id()
            || proof.invitation().expected_device_id() != self.binding.device_id()
            || proof.credential() != &self.binding
        {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        verify_device_credential_binding(proof.credential())?;
        validate_key_package(proof.mls_key_package(), proof.credential())?;
        self.join_expectation = Some(JoinExpectation {
            invitation_id: proof.invitation().invitation_id(),
            issuer_device_id: proof.invitation().issuer_device_id(),
            role: proof.invitation().role(),
        });
        Ok(())
    }

    /// Creates a one-time KeyPackage and invitation-bound join proof.
    ///
    /// The caller durably records the returned proof before transmitting it. After
    /// restart, [`Self::restore_join_proof`] reconnects that record to the sealed
    /// KeyPackage private data.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the invitation is invalid or MLS cannot generate
    /// the KeyPackage.
    pub fn create_join_proof(
        &mut self,
        device_identity: &DeviceIdentity,
        invitation: Invitation,
        issuer_public_key: KonclaveDomainCore::Ed25519PublicKey,
        now_unix_seconds: u64,
    ) -> Result<JoinProof, KonclaveCryptographicError> {
        if self.join_expectation.is_some() {
            return Err(KonclaveCryptographicError::PendingJoinExists);
        }
        device_identity.verify_invitation(&invitation, issuer_public_key, now_unix_seconds)?;
        if invitation.conversation_id() != self.binding.conversation_id() {
            return Err(KonclaveCryptographicError::InvitationConversationMismatch);
        }
        if invitation.expected_device_id() != self.binding.device_id() {
            return Err(KonclaveCryptographicError::InvitationDeviceMismatch);
        }
        let key_package = self
            .client
            .generate_key_package_message(Default::default(), Default::default(), None)
            .map_err(|_| mls_failure("KeyPackage generation"))?;
        let key_package =
            serialize_mls_message(&key_package, "key_package", MAX_MLS_KEY_PACKAGE_BYTES)?;
        let expectation = JoinExpectation {
            invitation_id: invitation.invitation_id(),
            issuer_device_id: invitation.issuer_device_id(),
            role: invitation.role(),
        };
        let proof = JoinProof::new(invitation, self.binding.clone(), key_package)?;
        self.join_expectation = Some(expectation);
        Ok(proof)
    }

    /// Creates the initial MLS group and authenticated administrator state.
    ///
    /// # Errors
    ///
    /// Returns a typed error when MLS group creation or roster validation fails.
    pub fn create_group(self) -> Result<MlsConversation, KonclaveCryptographicError> {
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            self.binding.conversation_id(),
            0,
            vec![Member::new(
                self.binding.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )?;
        self.policy.set_state(state.clone())?;
        let group_context_extensions = authenticated_state_digest_extensions(&state)?;
        let mut group = self
            .client
            .create_group_with_id(
                self.binding.conversation_id().as_bytes().to_vec(),
                group_context_extensions,
                ExtensionList::default(),
                None,
            )
            .map_err(|_| mls_failure("group creation"))?;
        verify_group_state(&group, &state, &self.policy)?;
        persist_group(&mut group, "group creation persistence")?;
        Ok(MlsConversation {
            group,
            policy: self.policy,
            state,
            self_device_id: self.binding.device_id(),
            pending_state: None,
            removed: false,
        })
    }

    /// Restores a sealed MLS group after its policy state and verified bindings have
    /// been loaded by the trusted daemon.
    ///
    /// Supply `pending_state` to later accept a stored outbound commit. It may be
    /// omitted for an orphaned pending commit that the caller will reject and
    /// recreate.
    ///
    /// # Errors
    ///
    /// Returns a typed error when stored MLS state, membership policy, credential
    /// bindings, or pending-commit state disagree.
    pub fn restore_group(
        self,
        state: ConversationState,
        bindings: Vec<VerifiedDeviceCredentialBinding>,
        pending_state: Option<ConversationState>,
    ) -> Result<MlsConversation, KonclaveCryptographicError> {
        if state.conversation_id() != self.binding.conversation_id() {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        for binding in bindings {
            self.register_verified_binding(binding)?;
        }
        self.policy.set_state(state.clone())?;
        let group = self
            .client
            .load_group(state.conversation_id().as_bytes())
            .map_err(|_| mls_failure("group restoration"))?;
        if pending_state.is_some() && !group.has_pending_commit() {
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        if pending_state.as_ref().is_some_and(|pending| {
            pending.conversation_id() != state.conversation_id()
                || state.epoch().checked_add(1) != Some(pending.epoch())
        }) {
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        let removed = state.member(self.binding.device_id()).is_none();
        if removed {
            verify_removed_group_state(&group, &state, self.binding.device_id())?;
        } else {
            verify_group_state(&group, &state, &self.policy)?;
        }
        Ok(MlsConversation {
            group,
            policy: self.policy,
            state,
            self_device_id: self.binding.device_id(),
            pending_state,
            removed,
        })
    }

    /// Joins an MLS group from one Welcome after peer bindings have been supplied.
    ///
    /// Conversation roles and invitation consumption are decoded only from the
    /// signed, encrypted GroupInfo extension carried by the Welcome.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the Welcome, ciphersuite, roster, or state does
    /// not match this conversation.
    pub fn join_group(
        mut self,
        welcome: &MlsWelcome,
    ) -> Result<MlsConversation, KonclaveCryptographicError> {
        let welcome_message =
            parse_mls_message(welcome.as_bytes(), "welcome", MAX_RELAY_PAYLOAD_BYTES)?;
        require_welcome_message(&welcome_message)?;
        let group_info = self
            .client
            .examine_welcome_message(&welcome_message)
            .map_err(|_| mls_failure("Welcome examination"))?;
        let (mut group, member_info) = self
            .client
            .join_group(None, &welcome_message, None)
            .map_err(|_| mls_failure("group join"))?;
        let state = authenticated_state_from_extensions(member_info.group_info_extensions())?;
        require_authenticated_state_digest(&group_info.group_context().extensions, &state)
            .map_err(|_| KonclaveCryptographicError::MembershipAuthorizationMismatch)?;
        let expectation = self
            .join_expectation
            .take()
            .ok_or(KonclaveCryptographicError::MembershipAuthorizationRequired)?;
        let joining_member = state.member(self.binding.device_id());
        if state.conversation_id() != self.binding.conversation_id()
            || joining_member.map(Member::role) != Some(expectation.role)
            || joining_member.map(Member::joined_epoch) != Some(state.epoch())
            || state.member(expectation.issuer_device_id).map(Member::role)
                != Some(ConversationRole::Administrator)
            || !state
                .consumed_invitation_ids()
                .contains(&expectation.invitation_id)
        {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        let commit_sender = group
            .roster()
            .member_with_index(member_info.sender)
            .map_err(|_| KonclaveCryptographicError::RosterMismatch)?;
        let commit_sender = device_id_from_signing_identity(commit_sender.signing_identity())
            .map_err(|_| KonclaveCryptographicError::RosterMismatch)?;
        if state.member(commit_sender).map(Member::role) != Some(ConversationRole::Administrator) {
            return Err(
                KonclaveDomainCore::KonclaveDomainError::UnauthorizedMembershipChange.into(),
            );
        }
        self.policy.set_state(state.clone())?;
        verify_group_state(&group, &state, &self.policy)?;
        persist_group(&mut group, "joined group persistence")?;
        Ok(MlsConversation {
            group,
            policy: self.policy,
            state,
            self_device_id: self.binding.device_id(),
            pending_state: None,
            removed: false,
        })
    }
}

/// In-memory MLS group whose membership transitions require domain authorization.
pub struct MlsConversation {
    group: KonclaveMlsGroup,
    policy: PolicyHandle,
    state: ConversationState,
    self_device_id: DeviceId,
    pending_state: Option<ConversationState>,
    removed: bool,
}

impl MlsConversation {
    /// Returns the authenticated application membership state.
    #[must_use]
    pub const fn state(&self) -> &ConversationState {
        &self.state
    }

    /// Returns the current MLS epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.state.epoch()
    }

    /// Returns a verified public credential binding known to this conversation.
    ///
    /// # Errors
    ///
    /// Returns an authorization-state error when the internal registry is
    /// unavailable.
    pub fn credential_binding(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<DeviceCredentialBinding>, KonclaveCryptographicError> {
        Ok(self
            .policy
            .binding(device_id)?
            .map(|registered| registered.binding))
    }

    /// Creates an authorized add-member commit from a complete join proof.
    ///
    /// The commit remains pending until [`Self::accept_pending_commit`] confirms
    /// relay compare-and-set acceptance. The caller durably records the returned
    /// outbox value before transmission. An orphaned stored pending commit can be
    /// restored without next-state metadata and rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed error when invitation, credential, KeyPackage, authorization,
    /// or MLS validation fails.
    pub fn create_add_commit(
        &mut self,
        join_proof: JoinProof,
        now_unix_seconds: u64,
    ) -> Result<OutboundMembershipCommit, KonclaveCryptographicError> {
        self.ensure_no_pending_commit()?;
        let verified = self.verify_join_proof(&join_proof, now_unix_seconds)?;
        let operation_id = self.random_operation_id()?;
        let add = AddMember::new(
            join_proof.credential().device_id(),
            join_proof.invitation().role(),
            join_proof.invitation().invitation_id(),
            verified.hash(),
        );
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            self.state.conversation_id(),
            self.state.epoch(),
            operation_id,
            MembershipChange::Add(add),
        );
        let next_state = self.state.apply_membership_authorization(
            self.self_device_id,
            &authorization,
            self.next_epoch()?,
        )?;
        self.policy.register_binding(RegisteredBinding {
            binding: verified.into_binding(),
            hash: add.credential_binding_hash(),
        })?;
        let key_package =
            validate_key_package(join_proof.mls_key_package(), join_proof.credential())?;
        let authenticated_data = membership_authenticated_data(&authorization)?;
        let group_info_extensions = authenticated_state_extensions(&next_state)?;
        let group_context_extensions = authenticated_state_digest_extensions(&next_state)?;
        self.policy.prepare(authorization.clone())?;
        let output = match self
            .group
            .commit_builder()
            .set_group_context_ext(group_context_extensions)
            .and_then(|builder| builder.add_member(key_package))
            .and_then(|builder| {
                builder
                    .set_group_info_ext(group_info_extensions)
                    .authenticated_data(authenticated_data)
                    .build()
            }) {
            Ok(output) => output,
            Err(_) => {
                self.group.clear_pending_commit();
                self.policy.clear_pending()?;
                return Err(mls_failure("add-member commit creation"));
            }
        };
        let validated = self.policy.take_validated_state()?;
        if validated != next_state {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        if output.welcome_messages.len() != 1 {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::MissingWelcome);
        }
        if require_conversation_message(
            &output.commit_message,
            self.state.conversation_id(),
            self.state.epoch(),
            ContentType::Commit,
            "add-member commit creation",
        )
        .is_err()
        {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "add-member commit creation",
            });
        }
        let commit = match serialize_mls_message(
            &output.commit_message,
            "commit",
            MAX_RELAY_PAYLOAD_BYTES,
        ) {
            Ok(bytes) => MlsCommit(bytes),
            Err(error) => {
                self.abort_local_pending()?;
                return Err(error);
            }
        };
        let welcome = match serialize_mls_message(
            &output.welcome_messages[0],
            "welcome",
            MAX_RELAY_PAYLOAD_BYTES,
        ) {
            Ok(bytes) => MlsWelcome(bytes),
            Err(error) => {
                self.abort_local_pending()?;
                return Err(error);
            }
        };
        self.pending_state = Some(next_state.clone());
        if let Err(error) = persist_group(&mut self.group, "add-member pending persistence") {
            self.abort_local_pending()?;
            return Err(error);
        }
        Ok(OutboundMembershipCommit {
            commit,
            welcome: Some(welcome),
            authorization,
            join_proof: Some(join_proof),
            next_state,
        })
    }

    /// Creates an authorized remove-member commit.
    ///
    /// The caller durably records the returned outbox value before transmission. An
    /// orphaned stored pending commit can be restored and rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed error when policy validation, roster lookup, or MLS commit
    /// creation fails.
    pub fn create_remove_commit(
        &mut self,
        device_id: DeviceId,
    ) -> Result<OutboundMembershipCommit, KonclaveCryptographicError> {
        self.ensure_no_pending_commit()?;
        let operation_id = self.random_operation_id()?;
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            self.state.conversation_id(),
            self.state.epoch(),
            operation_id,
            MembershipChange::Remove(RemoveMember::new(device_id)),
        );
        let next_state = self.state.apply_membership_authorization(
            self.self_device_id,
            &authorization,
            self.next_epoch()?,
        )?;
        let member_index = roster_index(&self.group.roster(), device_id)?;
        let authenticated_data = membership_authenticated_data(&authorization)?;
        let group_context_extensions = authenticated_state_digest_extensions(&next_state)?;
        self.policy.prepare(authorization.clone())?;
        let output = match self
            .group
            .commit_builder()
            .set_group_context_ext(group_context_extensions)
            .and_then(|builder| builder.remove_member(member_index))
            .map(|builder| builder.authenticated_data(authenticated_data))
            .and_then(|builder| builder.build())
        {
            Ok(output) => output,
            Err(_) => {
                self.group.clear_pending_commit();
                self.policy.clear_pending()?;
                return Err(mls_failure("remove-member commit creation"));
            }
        };
        let validated = self.policy.take_validated_state()?;
        if validated != next_state || !output.welcome_messages.is_empty() {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        if require_conversation_message(
            &output.commit_message,
            self.state.conversation_id(),
            self.state.epoch(),
            ContentType::Commit,
            "remove-member commit creation",
        )
        .is_err()
        {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "remove-member commit creation",
            });
        }
        let commit = match serialize_mls_message(
            &output.commit_message,
            "commit",
            MAX_RELAY_PAYLOAD_BYTES,
        ) {
            Ok(bytes) => MlsCommit(bytes),
            Err(error) => {
                self.abort_local_pending()?;
                return Err(error);
            }
        };
        self.pending_state = Some(next_state.clone());
        if let Err(error) = persist_group(&mut self.group, "remove-member pending persistence") {
            self.abort_local_pending()?;
            return Err(error);
        }
        Ok(OutboundMembershipCommit {
            commit,
            welcome: None,
            authorization,
            join_proof: None,
            next_state,
        })
    }

    /// Creates an authenticated role-change commit that advances the MLS epoch.
    ///
    /// The caller durably records the returned outbox value before transmission. An
    /// orphaned stored pending commit can be restored and rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed error when policy validation or MLS commit creation fails.
    pub fn create_change_role_commit(
        &mut self,
        device_id: DeviceId,
        role: ConversationRole,
    ) -> Result<OutboundMembershipCommit, KonclaveCryptographicError> {
        self.ensure_no_pending_commit()?;
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            self.state.conversation_id(),
            self.state.epoch(),
            self.random_operation_id()?,
            MembershipChange::ChangeRole(KonclaveDomainCore::ChangeMemberRole::new(
                device_id, role,
            )),
        );
        let next_state = self.state.apply_membership_authorization(
            self.self_device_id,
            &authorization,
            self.next_epoch()?,
        )?;
        let authenticated_data = membership_authenticated_data(&authorization)?;
        let group_context_extensions = authenticated_state_digest_extensions(&next_state)?;
        self.policy.prepare(authorization.clone())?;
        let output = match self
            .group
            .commit_builder()
            .set_group_context_ext(group_context_extensions)
            .map(|builder| builder.authenticated_data(authenticated_data))
            .and_then(|builder| builder.build())
        {
            Ok(output) => output,
            Err(_) => {
                self.group.clear_pending_commit();
                self.policy.clear_pending()?;
                return Err(mls_failure("role-change commit creation"));
            }
        };
        let validated = self.policy.take_validated_state()?;
        if validated != next_state || !output.welcome_messages.is_empty() {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        if require_conversation_message(
            &output.commit_message,
            self.state.conversation_id(),
            self.state.epoch(),
            ContentType::Commit,
            "role-change commit creation",
        )
        .is_err()
        {
            self.abort_local_pending()?;
            return Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "role-change commit creation",
            });
        }
        let commit = match serialize_mls_message(
            &output.commit_message,
            "commit",
            MAX_RELAY_PAYLOAD_BYTES,
        ) {
            Ok(bytes) => MlsCommit(bytes),
            Err(error) => {
                self.abort_local_pending()?;
                return Err(error);
            }
        };
        self.pending_state = Some(next_state.clone());
        if let Err(error) = persist_group(&mut self.group, "role-change pending persistence") {
            self.abort_local_pending()?;
            return Err(error);
        }
        Ok(OutboundMembershipCommit {
            commit,
            welcome: None,
            authorization,
            join_proof: None,
            next_state,
        })
    }

    /// Applies the locally generated pending commit after relay acceptance.
    ///
    /// # Errors
    ///
    /// Returns a typed error when no commit is pending or MLS cannot apply it.
    pub fn accept_pending_commit(&mut self) -> Result<(), KonclaveCryptographicError> {
        let next_state = self
            .pending_state
            .as_ref()
            .cloned()
            .ok_or(KonclaveCryptographicError::PendingCommitNotFound)?;
        if !self.group.has_pending_commit() {
            return Err(KonclaveCryptographicError::PendingCommitNotFound);
        }
        let mut candidate = self.group.clone();
        let description = candidate
            .apply_pending_commit()
            .map_err(|_| mls_failure("pending commit application"))?;
        let removed_self = next_state.member(self.self_device_id).is_none();
        require_commit_effect_state_digest(&description.effect, &next_state)?;
        if removed_self != matches!(&description.effect, CommitEffect::Removed { .. }) {
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        if removed_self {
            verify_removed_group_state(&candidate, &next_state, self.self_device_id)?;
        } else {
            verify_group_state(&candidate, &next_state, &self.policy)?;
        }
        persist_group(&mut candidate, "accepted commit persistence")?;
        self.group = candidate;
        self.pending_state = None;
        if removed_self {
            self.policy.commit_state(next_state.clone())?;
            self.state = next_state;
            self.removed = true;
            self.policy.clear_pending()
        } else {
            self.commit_state(next_state)
        }
    }

    /// Discards a locally generated commit rejected by relay compare-and-set.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveCryptographicError::PendingCommitNotFound`] when no commit
    /// is pending.
    pub fn reject_pending_commit(&mut self) -> Result<(), KonclaveCryptographicError> {
        if !self.group.has_pending_commit() {
            return Err(KonclaveCryptographicError::PendingCommitNotFound);
        }
        let mut candidate = self.group.clone();
        candidate.clear_pending_commit();
        persist_group(&mut candidate, "rejected commit persistence")?;
        self.group = candidate;
        self.pending_state = None;
        self.policy.clear_pending()
    }

    /// Processes an incoming commit only when its exact application authorization
    /// and add-member proof have been supplied.
    ///
    /// The caller durably journals these exact inputs before invoking this method so
    /// an interrupted application-policy checkpoint can reconcile with the sealed MLS
    /// epoch after restart.
    ///
    /// # Errors
    ///
    /// Returns a typed error before group mutation when policy, credential, proposal,
    /// or MLS validation fails.
    pub fn process_membership_commit(
        &mut self,
        commit: &MlsCommit,
        authorization: MembershipAuthorization,
        join_proof: Option<JoinProof>,
        now_unix_seconds: u64,
    ) -> Result<AppliedMembershipCommit, KonclaveCryptographicError> {
        self.ensure_no_pending_commit()?;
        match authorization.change() {
            MembershipChange::Add(add) => {
                let proof = join_proof
                    .as_ref()
                    .ok_or(KonclaveCryptographicError::MembershipAuthorizationMismatch)?;
                let verified = self.verify_join_proof(proof, now_unix_seconds)?;
                if add.device_id() != proof.credential().device_id()
                    || add.role() != proof.invitation().role()
                    || add.invitation_id() != proof.invitation().invitation_id()
                    || add.credential_binding_hash() != verified.hash()
                {
                    return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
                }
                self.policy.register_binding(RegisteredBinding {
                    binding: verified.into_binding(),
                    hash: add.credential_binding_hash(),
                })?;
            }
            MembershipChange::Remove(_) => {
                if join_proof.is_some() {
                    return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
                }
            }
            MembershipChange::ChangeRole(_) => {
                if join_proof.is_some() {
                    return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
                }
            }
        }

        let expected_authenticated_data = membership_authenticated_data(&authorization)?;
        let message = parse_mls_message(commit.as_bytes(), "commit", MAX_RELAY_PAYLOAD_BYTES)?;
        require_conversation_message(
            &message,
            self.state.conversation_id(),
            authorization.parent_epoch(),
            ContentType::Commit,
            "membership commit",
        )?;
        self.policy.prepare(authorization)?;
        // MLS decryption can advance secret-tree state before application rules fail.
        // Commit a cloned snapshot only after every cryptographic and policy check passes.
        let mut candidate = self.group.clone();
        let result = candidate.process_incoming_message(message);
        let received = match result {
            Ok(received) => received,
            Err(_) => {
                self.policy.clear_pending()?;
                return Err(mls_failure("incoming membership commit"));
            }
        };
        let ReceivedMessage::Commit(description) = received else {
            self.policy.clear_pending()?;
            return Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "incoming membership commit",
            });
        };
        if description.authenticated_data != expected_authenticated_data {
            self.policy.clear_pending()?;
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        let removed_self = matches!(&description.effect, CommitEffect::Removed { .. });
        let (sender, next_state) = self.policy.take_validated_transition()?;
        require_commit_effect_state_digest(&description.effect, &next_state)?;
        if removed_self {
            verify_removed_group_state(&candidate, &next_state, self.self_device_id)?;
        } else {
            verify_group_state(&candidate, &next_state, &self.policy)?;
        }
        if let Err(error) = persist_group(&mut candidate, "incoming commit persistence") {
            self.policy.clear_pending()?;
            return Err(error);
        }
        self.group = candidate;
        if removed_self {
            self.policy.commit_state(next_state.clone())?;
            self.state = next_state.clone();
            self.removed = true;
            self.policy.clear_pending()?;
        } else {
            self.commit_state(next_state.clone())?;
        }
        Ok(AppliedMembershipCommit {
            authenticated_sender: sender,
            epoch: next_state.epoch(),
            removed_self,
        })
    }

    /// Encrypts one already encoded Konclave application message as MLS
    /// PrivateMessage data.
    ///
    /// # Errors
    ///
    /// Returns a typed error for pending commits, oversized input, or MLS failure.
    pub fn encrypt_application_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<MlsApplicationMessage, KonclaveCryptographicError> {
        self.ensure_no_pending_commit()?;
        if plaintext.len() > MAX_APPLICATION_MESSAGE_BYTES {
            return Err(KonclaveCryptographicError::MlsMessageTooLarge {
                message_kind: "application_plaintext",
                maximum: MAX_APPLICATION_MESSAGE_BYTES,
                actual: plaintext.len(),
            });
        }
        let mut candidate = self.group.clone();
        let message = candidate
            .encrypt_application_message(plaintext, Vec::new())
            .map_err(|_| mls_failure("application encryption"))?;
        require_conversation_message(
            &message,
            self.state.conversation_id(),
            self.state.epoch(),
            ContentType::Application,
            "application encryption",
        )?;
        let ciphertext = MlsApplicationMessage(serialize_mls_message(
            &message,
            "application_ciphertext",
            MAX_RELAY_PAYLOAD_BYTES,
        )?);
        persist_group(&mut candidate, "application encryption persistence")?;
        self.group = candidate;
        Ok(ciphertext)
    }

    /// Authenticates and decrypts one MLS application message.
    ///
    /// Sender attribution is derived from the authenticated MLS roster.
    /// Decryption advances only the in-memory receiver ratchet. The caller durably
    /// records the idempotent application side effect and then calls
    /// [`Self::persist`].
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, wrong-group, non-application, or
    /// cryptographically invalid input.
    pub fn decrypt_application_message(
        &mut self,
        ciphertext: &MlsApplicationMessage,
    ) -> Result<DecryptedApplicationMessage, KonclaveCryptographicError> {
        self.ensure_no_pending_commit()?;
        let message = parse_mls_message(
            ciphertext.as_bytes(),
            "application_ciphertext",
            MAX_RELAY_PAYLOAD_BYTES,
        )?;
        require_conversation_message_kind(
            &message,
            self.state.conversation_id(),
            ContentType::Application,
            "application decryption",
        )?;
        let mut candidate = self.group.clone();
        let received = match candidate.process_incoming_message(message) {
            Ok(received) => received,
            Err(MlsError::KeyMissing(_)) => {
                return Err(KonclaveCryptographicError::ApplicationMessageAlreadyProcessed);
            }
            Err(_) => return Err(mls_failure("application decryption")),
        };
        let ReceivedMessage::ApplicationMessage(description) = received else {
            return Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "application decryption",
            });
        };
        let member = candidate
            .roster()
            .member_with_index(description.sender_index)
            .map_err(|_| KonclaveCryptographicError::RosterMismatch)?;
        let sender = device_id_from_signing_identity(member.signing_identity())
            .map_err(|_| KonclaveCryptographicError::RosterMismatch)?;
        if self.state.member(sender).is_none() {
            return Err(KonclaveCryptographicError::RosterMismatch);
        }
        let plaintext = Zeroizing::new(description.data().to_vec());
        self.group = candidate;
        Ok(DecryptedApplicationMessage {
            authenticated_sender: sender,
            plaintext,
        })
    }

    /// Persists the current MLS state and ratchets.
    ///
    /// For incoming application messages, callers first durably record their
    /// idempotent application side effect, then call this method. A crash between
    /// those operations replays the ciphertext against the prior snapshot, allowing
    /// application-message deduplication to complete recovery without losing content.
    ///
    /// # Errors
    ///
    /// Returns a typed MLS storage error.
    pub fn persist(&mut self) -> Result<(), KonclaveCryptographicError> {
        persist_group(&mut self.group, "explicit group persistence")
    }

    fn verify_join_proof(
        &self,
        proof: &JoinProof,
        now_unix_seconds: u64,
    ) -> Result<VerifiedDeviceCredentialBinding, KonclaveCryptographicError> {
        let issuer = self
            .policy
            .binding(proof.invitation().issuer_device_id())?
            .ok_or(KonclaveCryptographicError::CredentialNotRegistered)?;
        if self
            .state
            .member(proof.invitation().issuer_device_id())
            .map(Member::role)
            != Some(ConversationRole::Administrator)
        {
            return Err(
                KonclaveDomainCore::KonclaveDomainError::UnauthorizedMembershipChange.into(),
            );
        }
        verify_invitation(
            proof.invitation(),
            issuer.binding.device_root_public_key(),
            now_unix_seconds,
        )?;
        if proof.invitation().conversation_id() != self.state.conversation_id()
            || self
                .state
                .consumed_invitation_ids()
                .contains(&proof.invitation().invitation_id())
        {
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        let verified = verify_device_credential_binding(proof.credential())?;
        validate_key_package(proof.mls_key_package(), proof.credential())?;
        Ok(verified)
    }

    fn random_operation_id(&self) -> Result<MembershipOperationId, KonclaveCryptographicError> {
        let provider = configured_provider();
        let cipher_suite = cipher_suite(&provider)?;
        let bytes = cipher_suite
            .random_bytes_vec(MembershipOperationId::LENGTH)
            .map_err(|_| KonclaveCryptographicError::ProviderFailure {
                operation: "membership operation identifier generation",
            })?;
        Ok(MembershipOperationId::from_slice(&bytes)?)
    }

    fn ensure_no_pending_commit(&self) -> Result<(), KonclaveCryptographicError> {
        if self.removed {
            return Err(KonclaveCryptographicError::RemovedFromConversation);
        }
        if self.pending_state.is_some() || self.group.has_pending_commit() {
            return Err(KonclaveCryptographicError::PendingCommitExists);
        }
        Ok(())
    }

    fn next_epoch(&self) -> Result<u64, KonclaveCryptographicError> {
        self.state
            .epoch()
            .checked_add(1)
            .ok_or(KonclaveDomainCore::KonclaveDomainError::InvalidMembershipEpochAdvance.into())
    }

    fn abort_local_pending(&mut self) -> Result<(), KonclaveCryptographicError> {
        self.group.clear_pending_commit();
        self.pending_state = None;
        self.policy.clear_pending()
    }

    fn commit_state(
        &mut self,
        next_state: ConversationState,
    ) -> Result<(), KonclaveCryptographicError> {
        if self.group.current_epoch() != next_state.epoch() {
            self.policy.clear_pending()?;
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        self.policy.commit_state(next_state.clone())?;
        self.state = next_state;
        self.policy.clear_pending()?;
        verify_group_state(&self.group, &self.state, &self.policy)
    }
}

/// Opaque MLS application ciphertext.
pub struct MlsApplicationMessage(Vec<u8>);

impl MlsApplicationMessage {
    /// Parses bounded MLS PrivateMessage application bytes from transport.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the bytes are oversized, malformed, or not an
    /// MLS application message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        let message = parse_mls_message(bytes, "application_ciphertext", MAX_RELAY_PAYLOAD_BYTES)?;
        match message.description() {
            MlsMessageDescription::PrivateProtocolMessage {
                content_type: ContentType::Application,
                ..
            } => Ok(Self(bytes.to_vec())),
            _ => Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "application transport parsing",
            }),
        }
    }

    /// Returns the complete MLS wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the MLS wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Opaque MLS commit bytes.
pub struct MlsCommit(Vec<u8>);

impl MlsCommit {
    /// Parses bounded MLS PrivateMessage commit bytes from transport.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the bytes are oversized, malformed, or not an
    /// MLS commit.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        let message = parse_mls_message(bytes, "commit", MAX_RELAY_PAYLOAD_BYTES)?;
        match message.description() {
            MlsMessageDescription::PrivateProtocolMessage {
                content_type: ContentType::Commit,
                ..
            } => Ok(Self(bytes.to_vec())),
            _ => Err(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "commit transport parsing",
            }),
        }
    }

    /// Returns the complete MLS wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the MLS wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Opaque MLS Welcome bytes.
pub struct MlsWelcome(Vec<u8>);

impl MlsWelcome {
    /// Parses a bounded MLS Welcome from transport.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the bytes are oversized, malformed, use another
    /// ciphersuite, or are not a Welcome.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        let message = parse_mls_message(bytes, "welcome", MAX_RELAY_PAYLOAD_BYTES)?;
        require_welcome_message(&message)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the complete MLS wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the MLS wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Outbound commit plus the exact application authorization used to create it.
pub struct OutboundMembershipCommit {
    commit: MlsCommit,
    welcome: Option<MlsWelcome>,
    authorization: MembershipAuthorization,
    join_proof: Option<JoinProof>,
    next_state: ConversationState,
}

impl OutboundMembershipCommit {
    /// Returns the MLS commit to submit through relay compare-and-set.
    #[must_use]
    pub const fn commit(&self) -> &MlsCommit {
        &self.commit
    }

    /// Returns the Welcome intended for a newly added device.
    #[must_use]
    pub const fn welcome(&self) -> Option<&MlsWelcome> {
        self.welcome.as_ref()
    }

    /// Returns the application membership authorization distributed with the commit.
    #[must_use]
    pub const fn authorization(&self) -> &MembershipAuthorization {
        &self.authorization
    }

    /// Returns the add-member proof distributed to existing members.
    #[must_use]
    pub const fn join_proof(&self) -> Option<&JoinProof> {
        self.join_proof.as_ref()
    }

    /// Returns the authenticated state expected after commit acceptance.
    #[must_use]
    pub const fn next_state(&self) -> &ConversationState {
        &self.next_state
    }
}

/// Metadata from an authenticated incoming membership commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedMembershipCommit {
    authenticated_sender: DeviceId,
    epoch: u64,
    removed_self: bool,
}

impl AppliedMembershipCommit {
    /// Returns the device authenticated as the commit sender.
    #[must_use]
    pub const fn authenticated_sender(self) -> DeviceId {
        self.authenticated_sender
    }

    /// Returns the accepted MLS epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns whether this device was removed by the commit.
    #[must_use]
    pub const fn removed_self(self) -> bool {
        self.removed_self
    }
}

/// Plaintext plus sender identity derived from MLS authentication.
pub struct DecryptedApplicationMessage {
    authenticated_sender: DeviceId,
    plaintext: Zeroizing<Vec<u8>>,
}

impl DecryptedApplicationMessage {
    /// Returns the authenticated device sender.
    #[must_use]
    pub const fn authenticated_sender(&self) -> DeviceId {
        self.authenticated_sender
    }

    /// Returns the decrypted application bytes.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

#[derive(Clone)]
struct KonclaveIdentityProvider {
    policy: PolicyHandle,
}

impl IdentityProvider for KonclaveIdentityProvider {
    type Error = PolicyError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        let group_id = match context {
            MemberValidationContext::ForCommit {
                current_context, ..
            }
            | MemberValidationContext::ForNewGroup { current_context } => {
                Some(current_context.group_id.as_slice())
            }
            _ => None,
        };
        self.policy
            .validate_signing_identity(signing_identity, group_id)
            .map(|_| ())
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Err(PolicyError::Unauthorized)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        self.policy
            .validate_signing_identity(signing_identity, None)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        let predecessor = device_id_from_signing_identity(predecessor)
            .map_err(|_| PolicyError::InvalidIdentity)?;
        let successor_device =
            device_id_from_signing_identity(successor).map_err(|_| PolicyError::InvalidIdentity)?;
        if predecessor != successor_device {
            return Ok(false);
        }
        self.policy.validate_signing_identity(successor, None)?;
        Ok(true)
    }

    fn supported_types(&self) -> Vec<mls_rs::identity::CredentialType> {
        vec![BasicCredential::credential_type()]
    }
}

#[derive(Clone)]
struct KonclaveMlsRules {
    policy: PolicyHandle,
}

impl MlsRules for KonclaveMlsRules {
    type Error = PolicyError;

    fn filter_proposals(
        &self,
        _direction: CommitDirection,
        source: CommitSource,
        current_roster: &Roster,
        current_context: &mls_rs::group::GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        self.policy
            .validate_proposals(source, current_roster, current_context, &proposals)?;
        Ok(proposals)
    }

    fn commit_options(
        &self,
        _new_roster: &Roster,
        _new_context: &mls_rs::group::GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(CommitOptions::new())
    }

    fn encryption_options(
        &self,
        _current_roster: &Roster,
        _current_context: &mls_rs::group::GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::new(true, PaddingMode::Padme))
    }
}

#[derive(Clone)]
struct PolicyHandle {
    inner: Arc<Mutex<PolicyState>>,
}

struct PolicyState {
    conversation_id: ConversationId,
    state: Option<ConversationState>,
    bindings: BTreeMap<DeviceId, RegisteredBinding>,
    pending: Option<MembershipAuthorization>,
    validated: Option<ValidatedTransition>,
}

#[derive(Clone)]
struct RegisteredBinding {
    binding: DeviceCredentialBinding,
    hash: KonclaveDomainCore::CredentialBindingHash,
}

struct JoinExpectation {
    invitation_id: KonclaveDomainCore::InvitationId,
    issuer_device_id: DeviceId,
    role: ConversationRole,
}

struct ValidatedTransition {
    sender: DeviceId,
    state: ConversationState,
}

impl PolicyHandle {
    fn new(conversation_id: ConversationId) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PolicyState {
                conversation_id,
                state: None,
                bindings: BTreeMap::new(),
                pending: None,
                validated: None,
            })),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, PolicyState>, KonclaveCryptographicError> {
        self.inner
            .lock()
            .map_err(|_| KonclaveCryptographicError::AuthorizationStateUnavailable)
    }

    fn register_binding(
        &self,
        registered: RegisteredBinding,
    ) -> Result<(), KonclaveCryptographicError> {
        let mut state = self.lock()?;
        if registered.binding.conversation_id() != state.conversation_id {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        if state
            .bindings
            .get(&registered.binding.device_id())
            .is_some_and(|existing| existing.binding != registered.binding)
        {
            return Err(KonclaveCryptographicError::CredentialSigningKeyMismatch);
        }
        state
            .bindings
            .insert(registered.binding.device_id(), registered);
        Ok(())
    }

    fn binding(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<RegisteredBinding>, KonclaveCryptographicError> {
        Ok(self.lock()?.bindings.get(&device_id).cloned())
    }

    fn validate_signing_identity(
        &self,
        signing_identity: &SigningIdentity,
        group_id: Option<&[u8]>,
    ) -> Result<Vec<u8>, PolicyError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| PolicyError::StateUnavailable)?;
        if group_id.is_some_and(|group_id| group_id != state.conversation_id.as_bytes()) {
            return Err(PolicyError::StateMismatch);
        }
        let device_id = device_id_from_signing_identity(signing_identity)
            .map_err(|_| PolicyError::InvalidIdentity)?;
        let registered = state
            .bindings
            .get(&device_id)
            .ok_or(PolicyError::CredentialMissing)?;
        if signing_identity.signature_key.as_bytes()
            != registered
                .binding
                .conversation_signature_public_key()
                .as_bytes()
        {
            return Err(PolicyError::ProposalMismatch);
        }
        Ok(device_id.as_bytes().to_vec())
    }

    fn set_state(&self, conversation: ConversationState) -> Result<(), KonclaveCryptographicError> {
        let mut state = self.lock()?;
        if conversation.conversation_id() != state.conversation_id {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        state.state = Some(conversation);
        Ok(())
    }

    fn prepare(
        &self,
        authorization: MembershipAuthorization,
    ) -> Result<(), KonclaveCryptographicError> {
        let mut state = self.lock()?;
        if state.pending.is_some() {
            return Err(KonclaveCryptographicError::PendingCommitExists);
        }
        let current = state
            .state
            .as_ref()
            .ok_or(KonclaveCryptographicError::MembershipAuthorizationRequired)?;
        if authorization.conversation_id() != current.conversation_id()
            || authorization.parent_epoch() != current.epoch()
            || authorization.version() != current.version()
        {
            return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
        }
        state.pending = Some(authorization);
        state.validated = None;
        Ok(())
    }

    fn clear_pending(&self) -> Result<(), KonclaveCryptographicError> {
        let mut state = self.lock()?;
        state.pending = None;
        state.validated = None;
        Ok(())
    }

    fn take_validated_state(&self) -> Result<ConversationState, KonclaveCryptographicError> {
        self.lock()?
            .validated
            .take()
            .map(|validated| validated.state)
            .ok_or(KonclaveCryptographicError::MembershipAuthorizationMismatch)
    }

    fn take_validated_transition(
        &self,
    ) -> Result<(DeviceId, ConversationState), KonclaveCryptographicError> {
        self.lock()?
            .validated
            .take()
            .map(|validated| (validated.sender, validated.state))
            .ok_or(KonclaveCryptographicError::MembershipAuthorizationMismatch)
    }

    fn commit_state(
        &self,
        conversation: ConversationState,
    ) -> Result<(), KonclaveCryptographicError> {
        let mut state = self.lock()?;
        state.state = Some(conversation);
        Ok(())
    }

    fn validate_proposals(
        &self,
        source: CommitSource,
        current_roster: &Roster,
        current_context: &mls_rs::group::GroupContext,
        proposals: &ProposalBundle,
    ) -> Result<(), PolicyError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| PolicyError::StateUnavailable)?;
        let conversation = state
            .state
            .as_ref()
            .ok_or(PolicyError::AuthorizationMissing)?;
        if current_context.group_id != conversation.conversation_id().as_bytes()
            || current_context.epoch != conversation.epoch()
            || current_context.cipher_suite != CIPHER_SUITE
        {
            return Err(PolicyError::StateMismatch);
        }
        require_authenticated_state_digest(&current_context.extensions, conversation)
            .map_err(|_| PolicyError::StateDigestMismatch)?;
        let authorization = state
            .pending
            .as_ref()
            .ok_or(PolicyError::AuthorizationMissing)?;
        let source = match source {
            CommitSource::ExistingMember(member) => {
                device_id_from_signing_identity(member.signing_identity())
                    .map_err(|_| PolicyError::InvalidIdentity)?
            }
            CommitSource::NewMember(_) => return Err(PolicyError::Unauthorized),
        };
        let next_epoch = current_context
            .epoch
            .checked_add(1)
            .ok_or(PolicyError::StateMismatch)?;
        let next_state = conversation
            .apply_membership_authorization(source, authorization, next_epoch)
            .map_err(PolicyError::Domain)?;
        if proposals.group_context_ext_proposals().len() != 1 {
            return Err(PolicyError::ProposalMismatch);
        }
        require_authenticated_state_digest(
            &proposals.group_context_ext_proposals()[0].proposal,
            &next_state,
        )
        .map_err(|_| PolicyError::StateDigestMismatch)?;

        match authorization.change() {
            MembershipChange::Add(add) => {
                if proposals.length() != 2 || proposals.add_proposals().len() != 1 {
                    return Err(PolicyError::ProposalMismatch);
                }
                validate_add_proposal(
                    &proposals.add_proposals()[0].proposal,
                    *add,
                    &state.bindings,
                )?;
            }
            MembershipChange::Remove(remove) => {
                if proposals.length() != 2 || proposals.remove_proposals().len() != 1 {
                    return Err(PolicyError::ProposalMismatch);
                }
                let removed = &proposals.remove_proposals()[0].proposal;
                let member = current_roster
                    .member_with_index(removed.to_remove())
                    .map_err(|_| PolicyError::ProposalMismatch)?;
                let removed_device = device_id_from_signing_identity(member.signing_identity())
                    .map_err(|_| PolicyError::InvalidIdentity)?;
                if removed_device != remove.device_id() {
                    return Err(PolicyError::ProposalMismatch);
                }
            }
            MembershipChange::ChangeRole(_) => {
                if proposals.length() != 1 {
                    return Err(PolicyError::ProposalMismatch);
                }
            }
        }
        state.validated = Some(ValidatedTransition {
            sender: source,
            state: next_state,
        });
        Ok(())
    }
}

fn validate_add_proposal(
    proposal: &AddProposal,
    add: AddMember,
    bindings: &BTreeMap<DeviceId, RegisteredBinding>,
) -> Result<(), PolicyError> {
    let signing_identity = proposal.signing_identity();
    let device_id = device_id_from_signing_identity(signing_identity)
        .map_err(|_| PolicyError::InvalidIdentity)?;
    if device_id != add.device_id() {
        return Err(PolicyError::ProposalMismatch);
    }
    let registered = bindings
        .get(&device_id)
        .ok_or(PolicyError::CredentialMissing)?;
    if registered.hash != add.credential_binding_hash()
        || signing_identity.signature_key.as_bytes()
            != registered
                .binding
                .conversation_signature_public_key()
                .as_bytes()
    {
        return Err(PolicyError::ProposalMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
enum PolicyError {
    #[error("authorization state is unavailable")]
    StateUnavailable,
    #[error("membership authorization is missing")]
    AuthorizationMissing,
    #[error("conversation state does not match MLS")]
    StateMismatch,
    #[error("authenticated conversation state digest does not match")]
    StateDigestMismatch,
    #[error("commit sender is unauthorized")]
    Unauthorized,
    #[error("MLS signing identity is invalid")]
    InvalidIdentity,
    #[error("verified credential is missing")]
    CredentialMissing,
    #[error("MLS proposal does not match authorization")]
    ProposalMismatch,
    #[error(transparent)]
    Domain(KonclaveDomainCore::KonclaveDomainError),
}

impl IntoAnyError for PolicyError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn validate_key_package(
    bytes: &[u8],
    binding: &DeviceCredentialBinding,
) -> Result<MlsMessage, KonclaveCryptographicError> {
    let message = parse_mls_message(bytes, "key_package", MAX_MLS_KEY_PACKAGE_BYTES)?;
    let key_package =
        message
            .as_key_package()
            .ok_or(KonclaveCryptographicError::UnexpectedMlsMessage {
                operation: "KeyPackage validation",
            })?;
    if key_package.cipher_suite != CIPHER_SUITE {
        return Err(KonclaveCryptographicError::MlsCipherSuiteMismatch);
    }
    let signing_identity = key_package.signing_identity();
    if device_id_from_signing_identity(signing_identity)? != binding.device_id()
        || signing_identity.signature_key.as_bytes()
            != binding.conversation_signature_public_key().as_bytes()
    {
        return Err(KonclaveCryptographicError::CredentialSigningKeyMismatch);
    }
    Ok(message)
}

fn verify_group_state(
    group: &KonclaveMlsGroup,
    state: &ConversationState,
    policy: &PolicyHandle,
) -> Result<(), KonclaveCryptographicError> {
    if group.group_id() != state.conversation_id().as_bytes() {
        return Err(KonclaveCryptographicError::MlsConversationMismatch);
    }
    if group.cipher_suite() != CIPHER_SUITE {
        return Err(KonclaveCryptographicError::MlsCipherSuiteMismatch);
    }
    if group.current_epoch() != state.epoch() {
        return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
    }
    require_authenticated_state_digest(&group.context().extensions, state)?;
    let members = group.roster().members();
    if members.len() != state.members().len() {
        return Err(KonclaveCryptographicError::RosterMismatch);
    }

    for member in members {
        let device_id = device_id_from_signing_identity(member.signing_identity())
            .map_err(|_| KonclaveCryptographicError::RosterMismatch)?;
        if state.member(device_id).is_none() {
            return Err(KonclaveCryptographicError::RosterMismatch);
        }
        let registered = policy
            .binding(device_id)?
            .ok_or(KonclaveCryptographicError::CredentialNotRegistered)?;
        if member.signing_identity().signature_key.as_bytes()
            != registered
                .binding
                .conversation_signature_public_key()
                .as_bytes()
        {
            return Err(KonclaveCryptographicError::CredentialSigningKeyMismatch);
        }
    }
    Ok(())
}

fn require_commit_effect_state_digest(
    effect: &CommitEffect,
    state: &ConversationState,
) -> Result<(), KonclaveCryptographicError> {
    let new_epoch = match effect {
        CommitEffect::NewEpoch(new_epoch) => new_epoch,
        CommitEffect::Removed { new_epoch, .. } => new_epoch,
        _ => return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch),
    };
    if new_epoch.epoch() != state.epoch() {
        return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
    }
    let mut extensions =
        new_epoch
            .applied_proposals()
            .iter()
            .filter_map(|proposal| match &proposal.proposal {
                Proposal::GroupContextExtensions(extensions) => Some(extensions),
                _ => None,
            });
    let extension = extensions
        .next()
        .ok_or(KonclaveCryptographicError::MembershipAuthorizationMismatch)?;
    if extensions.next().is_some() {
        return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
    }
    require_authenticated_state_digest(extension, state)
}

fn verify_removed_group_state(
    group: &KonclaveMlsGroup,
    state: &ConversationState,
    removed_device_id: DeviceId,
) -> Result<(), KonclaveCryptographicError> {
    if group.group_id() != state.conversation_id().as_bytes() {
        return Err(KonclaveCryptographicError::MlsConversationMismatch);
    }
    if group.cipher_suite() != CIPHER_SUITE {
        return Err(KonclaveCryptographicError::MlsCipherSuiteMismatch);
    }
    if group.current_epoch().checked_add(1) != Some(state.epoch())
        || state.member(removed_device_id).is_some()
        || group.has_pending_commit()
    {
        return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
    }
    Ok(())
}

fn persist_group(
    group: &mut KonclaveMlsGroup,
    operation: &'static str,
) -> Result<(), KonclaveCryptographicError> {
    group.write_to_storage().map_err(|_| mls_failure(operation))
}

fn roster_index(roster: &Roster, device_id: DeviceId) -> Result<u32, KonclaveCryptographicError> {
    for member in roster.members_iter() {
        if device_id_from_signing_identity(member.signing_identity())
            .map_err(|_| KonclaveCryptographicError::RosterMismatch)?
            == device_id
        {
            return Ok(member.index());
        }
    }
    Err(KonclaveDomainCore::KonclaveDomainError::MemberNotFound.into())
}

fn device_id_from_signing_identity(
    signing_identity: &SigningIdentity,
) -> Result<DeviceId, KonclaveCryptographicError> {
    let credential = signing_identity
        .credential
        .as_basic()
        .ok_or(KonclaveCryptographicError::CredentialSigningKeyMismatch)?;
    Ok(DeviceId::from_slice(&credential.identifier)?)
}

fn require_conversation_message(
    message: &MlsMessage,
    conversation_id: ConversationId,
    epoch: u64,
    content_type: ContentType,
    operation: &'static str,
) -> Result<(), KonclaveCryptographicError> {
    match message.description() {
        MlsMessageDescription::PrivateProtocolMessage {
            group_id,
            epoch_id,
            content_type: actual,
        } if group_id == conversation_id.as_bytes()
            && epoch_id == epoch
            && actual == content_type =>
        {
            Ok(())
        }
        _ => Err(KonclaveCryptographicError::UnexpectedMlsMessage { operation }),
    }
}

fn require_conversation_message_kind(
    message: &MlsMessage,
    conversation_id: ConversationId,
    content_type: ContentType,
    operation: &'static str,
) -> Result<(), KonclaveCryptographicError> {
    match message.description() {
        MlsMessageDescription::PrivateProtocolMessage {
            group_id,
            content_type: actual,
            ..
        } if group_id == conversation_id.as_bytes() && actual == content_type => Ok(()),
        _ => Err(KonclaveCryptographicError::UnexpectedMlsMessage { operation }),
    }
}

fn require_welcome_message(message: &MlsMessage) -> Result<(), KonclaveCryptographicError> {
    match message.description() {
        MlsMessageDescription::Welcome { cipher_suite, .. } if cipher_suite == CIPHER_SUITE => {
            Ok(())
        }
        MlsMessageDescription::Welcome { .. } => {
            Err(KonclaveCryptographicError::MlsCipherSuiteMismatch)
        }
        _ => Err(KonclaveCryptographicError::UnexpectedMlsMessage {
            operation: "group join",
        }),
    }
}

fn parse_mls_message(
    bytes: &[u8],
    message_kind: &'static str,
    maximum: usize,
) -> Result<MlsMessage, KonclaveCryptographicError> {
    if bytes.len() > maximum {
        return Err(KonclaveCryptographicError::MlsMessageTooLarge {
            message_kind,
            maximum,
            actual: bytes.len(),
        });
    }
    MlsMessage::from_bytes(bytes).map_err(|_| mls_failure("MLS message parsing"))
}

fn serialize_mls_message(
    message: &MlsMessage,
    message_kind: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, KonclaveCryptographicError> {
    let bytes = message
        .to_bytes()
        .map_err(|_| mls_failure("MLS message serialization"))?;
    if bytes.len() > maximum {
        return Err(KonclaveCryptographicError::MlsMessageTooLarge {
            message_kind,
            maximum,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn membership_authenticated_data(
    authorization: &MembershipAuthorization,
) -> Result<Vec<u8>, KonclaveCryptographicError> {
    let encoded = encode_membership_change(authorization)
        .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
    let mut input = Vec::with_capacity(MEMBERSHIP_AUTH_DOMAIN.len() + encoded.len());
    input.extend_from_slice(MEMBERSHIP_AUTH_DOMAIN);
    input.extend_from_slice(&encoded);
    let provider = configured_provider();
    cipher_suite(&provider)?
        .hash(&input)
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "membership authorization digest",
        })
}

fn authenticated_state_extensions(
    state: &ConversationState,
) -> Result<ExtensionList, KonclaveCryptographicError> {
    let encoded = encode_conversation_state(state)
        .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
    Ok(vec![mls_rs::Extension::new(
        CONVERSATION_STATE_EXTENSION,
        encoded,
    )]
    .into())
}

fn authenticated_state_digest_extensions(
    state: &ConversationState,
) -> Result<ExtensionList, KonclaveCryptographicError> {
    Ok(vec![mls_rs::Extension::new(
        CONVERSATION_STATE_DIGEST_EXTENSION,
        conversation_state_digest(state)?,
    )]
    .into())
}

fn authenticated_state_from_extensions(
    extensions: &ExtensionList,
) -> Result<ConversationState, KonclaveCryptographicError> {
    let extension = extensions
        .get(CONVERSATION_STATE_EXTENSION)
        .ok_or(KonclaveCryptographicError::MissingAuthenticatedState)?;
    decode_conversation_state(&extension.extension_data)
        .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)
}

fn require_authenticated_state_digest(
    extensions: &ExtensionList,
    state: &ConversationState,
) -> Result<(), KonclaveCryptographicError> {
    let extension = extensions
        .get(CONVERSATION_STATE_DIGEST_EXTENSION)
        .ok_or(KonclaveCryptographicError::MissingAuthenticatedState)?;
    if extension.extension_data != conversation_state_digest(state)? {
        return Err(KonclaveCryptographicError::MembershipAuthorizationMismatch);
    }
    Ok(())
}

fn conversation_state_digest(
    state: &ConversationState,
) -> Result<Vec<u8>, KonclaveCryptographicError> {
    let encoded = encode_conversation_state(state)
        .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
    let mut input = Vec::with_capacity(CONVERSATION_STATE_DOMAIN.len() + encoded.len());
    input.extend_from_slice(CONVERSATION_STATE_DOMAIN);
    input.extend_from_slice(&encoded);
    let provider = configured_provider();
    cipher_suite(&provider)?
        .hash(&input)
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "conversation state digest",
        })
}

const fn mls_failure(operation: &'static str) -> KonclaveCryptographicError {
    KonclaveCryptographicError::MlsFailure { operation }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_authorization_digest_vector_is_stable() {
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            ConversationId::from_bytes([30; ConversationId::LENGTH]),
            2,
            MembershipOperationId::from_bytes([31; MembershipOperationId::LENGTH]),
            MembershipChange::Add(AddMember::new(
                DeviceId::from_bytes([32; DeviceId::LENGTH]),
                ConversationRole::Member,
                KonclaveDomainCore::InvitationId::from_bytes(
                    [33; KonclaveDomainCore::InvitationId::LENGTH],
                ),
                KonclaveDomainCore::CredentialBindingHash::from_bytes(
                    [34; KonclaveDomainCore::CredentialBindingHash::LENGTH],
                ),
            )),
        );
        assert_eq!(
            membership_authenticated_data(&authorization).unwrap(),
            decode_hex("16a113081d25c7c07d9ab4c2469999adbd01c13ec98fbad2c6ddff0913d6b37e")
        );
    }

    #[test]
    fn welcome_state_extension_is_required() {
        assert_eq!(
            authenticated_state_from_extensions(&ExtensionList::default()).unwrap_err(),
            KonclaveCryptographicError::MissingAuthenticatedState
        );
        let state = decode_conversation_state(include_bytes!(
            "../../../fixtures/protocol/v1/conversation-state.bin"
        ))
        .unwrap();
        assert_eq!(
            require_authenticated_state_digest(&ExtensionList::default(), &state).unwrap_err(),
            KonclaveCryptographicError::MissingAuthenticatedState
        );
        assert_eq!(
            conversation_state_digest(&state).unwrap(),
            decode_hex("29c6cdd1426a580346380c127d39420b11ac303d2530eb516e794ec9bb49e750")
        );
        let mut wrong = ExtensionList::default();
        wrong.set(mls_rs::Extension::new(
            CONVERSATION_STATE_DIGEST_EXTENSION,
            vec![0; 32],
        ));
        assert_eq!(
            require_authenticated_state_digest(&wrong, &state).unwrap_err(),
            KonclaveCryptographicError::MembershipAuthorizationMismatch
        );
    }

    #[test]
    fn identity_provider_rejects_unbound_successor_key() {
        let conversation_id = ConversationId::from_bytes([1; ConversationId::LENGTH]);
        let device_id = DeviceId::from_bytes([2; DeviceId::LENGTH]);
        let policy = PolicyHandle::new(conversation_id);
        policy
            .register_binding(RegisteredBinding {
                binding: DeviceCredentialBinding::new(
                    ProtocolVersion::application_v1(),
                    device_id,
                    conversation_id,
                    KonclaveDomainCore::SignatureScheme::Ed25519,
                    KonclaveDomainCore::Ed25519PublicKey::from_bytes(
                        [3; KonclaveDomainCore::Ed25519PublicKey::LENGTH],
                    ),
                    KonclaveDomainCore::Ed25519PublicKey::from_bytes(
                        [4; KonclaveDomainCore::Ed25519PublicKey::LENGTH],
                    ),
                    KonclaveDomainCore::Ed25519Signature::from_bytes(
                        [5; KonclaveDomainCore::Ed25519Signature::LENGTH],
                    ),
                ),
                hash: KonclaveDomainCore::CredentialBindingHash::from_bytes(
                    [6; KonclaveDomainCore::CredentialBindingHash::LENGTH],
                ),
            })
            .unwrap();
        let credential = BasicCredential::new(device_id.as_bytes().to_vec());
        let unbound = SigningIdentity::new(
            credential.into_credential(),
            SignaturePublicKey::new(vec![7; KonclaveDomainCore::Ed25519PublicKey::LENGTH]),
        );
        assert!(matches!(
            policy.validate_signing_identity(&unbound, Some(conversation_id.as_bytes())),
            Err(PolicyError::ProposalMismatch)
        ));
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
