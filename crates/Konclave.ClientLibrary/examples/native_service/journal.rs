//! Bounded, single-conversation service journal. Not a production database.
//!
//! The operator supplies custody, namespace, fixed membership and the same owner
//! used by MLS. Slots are independently committed; no cross-slot transaction or
//! rollback/deletion detection is claimed. Retained evidence is never pruned.
//! Replacement/sync errors can follow a visible commit; reconcile exact current
//! evidence rather than assuming a failed return rolled state back.

use std::sync::Arc;

use KonclaveClientLibrary::native::*;
use KonclaveClientLibrary::{RelayAccessCredential, RelayEndpoint};
use KonclaveCryptographicCore::{
    ConversationSigningMaterial, DeviceIdentity, verify_device_credential_binding,
};
use KonclaveDomainCore::*;
use KonclaveProtocolContracts::v1::*;
use KonclaveSecretStorage::{SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer};
use zeroize::Zeroizing;

use super::authority::{
    AuthorityError, CommittedResponse, HandlingClaim, MAX_CLAIMS, ServiceAuthority,
    ServiceAuthorization,
};
use super::storage::{ServiceStorage, SnapshotKind, StorageError};

#[path = "journal_codec.rs"]
mod codec;

const MAX_ROWS: usize = 32;
const MAX_MEMBERS: usize = 32;
const MAX_FIELD: usize = 1024 * 1024;
const MAX_BYTES: usize = 8 * 1024 * 1024;

/// Finite diagnostics exclude paths, payloads and custody details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JournalError {
    /// The common owner rejected the operation.
    #[error("native journal storage failed")]
    Storage(#[from] StorageError),
    /// Explicit local authority rejected admission.
    #[error("native journal authority failed")]
    Authority(#[from] AuthorityError),
    /// Sealing or project credential verification failed.
    #[error("native journal protection failed")]
    Protection,
    /// Missing, malformed, noncanonical or inconsistent durable evidence.
    #[error("native journal evidence is invalid")]
    Invalid,
    /// Caller evidence conflicts with immutable committed evidence.
    #[error("native journal evidence conflicts")]
    Conflict,
    /// The requested endpoint, conversation, route or sender differs.
    #[error("native journal scope mismatch")]
    Scope,
    /// No implicit provisioning or recovery from missing state is allowed.
    #[error("native journal is not provisioned")]
    Missing,
    /// Explicit provisioning never replaces an existing authenticated snapshot.
    #[error("native journal is already provisioned")]
    Provisioned,
    /// Bounded retained evidence or counter space is exhausted.
    #[error("native journal capacity exhausted")]
    Capacity,
    /// Fixed membership cannot be mutated by this example.
    #[error("native journal operation is unsupported")]
    Unsupported,
}

struct Outbox {
    reservation: OutboundReservation,
    epoch: u64,
    expiry: u64,
    intent: Zeroizing<Vec<u8>>,
    saved: bool,
    envelope: Option<RelayEnvelope>,
    abandoned: bool,
    accepted: Option<u64>,
    expired: bool,
}

struct Inbox {
    stored: StoredRelayEnvelope,
    sender: Option<DeviceId>,
    epoch: u64,
    message: Option<Zeroizing<Vec<u8>>>,
    notification: Option<(NotificationId, u64)>,
}

struct Snapshot {
    identity: SealedBlob,
    signing: SealedBlob,
    endpoint: RelayEndpoint,
    credential: SealedBlob,
    state: ConversationState,
    bindings: Vec<DeviceCredentialBinding>,
    route: RoutingId,
    counter: u64,
    cursor: u64,
    authority: ServiceAuthority,
    outbox: Vec<Outbox>,
    inbox: Vec<Inbox>,
}

/// An exact original operation, including intent committed before encryption.
pub struct ReservedIntent {
    /// Permanently consumed identifiers and sender counter.
    pub reservation: OutboundReservation,
    /// Complete original content, reply and display timestamp.
    pub message: ApplicationMessage,
    /// Epoch at the admission commit.
    pub epoch: u64,
    /// Immutable relay expiration.
    pub expires_at_unix_seconds: u64,
    /// Exact ready ciphertext, if encryption was already committed.
    pub envelope: Option<RelayEnvelope>,
    /// Terminal abandonment does not release the claim or identifiers.
    pub abandoned: bool,
    /// Exact known relay acceptance.
    pub accepted_cursor: Option<u64>,
    /// Operator recorded expiry without deleting evidence.
    pub expired: bool,
    /// Original protected plaintext and sender metadata have been checkpointed.
    pub message_saved: bool,
}

/// Clones share actual storage ownership, not a decoded snapshot cache.
#[derive(Clone)]
pub struct ServiceJournal {
    storage: ServiceStorage,
    sealer: Arc<SecretSealer>,
    namespace: Vec<u8>,
    context: SecretRecordContext,
    conversation: ConversationId,
    device: DeviceId,
}

impl ServiceJournal {
    fn handle(
        storage: ServiceStorage,
        sealer: SecretSealer,
        namespace: &[u8],
        conversation: ConversationId,
        device: DeviceId,
    ) -> Result<Self, JournalError> {
        if namespace.is_empty() || namespace.len() > 128 {
            return Err(JournalError::Scope);
        }
        let context = SecretRecordContext::derive(
            SecretRecordKind::LocalOperation,
            &[
                b"native-service-journal-v1",
                namespace,
                conversation.as_bytes(),
                device.as_bytes(),
            ],
        )
        .map_err(|_| JournalError::Protection)?;
        Ok(Self {
            storage,
            sealer: Arc::new(sealer),
            namespace: namespace.to_vec(),
            context,
            conversation,
            device,
        })
    }

    /// Provisions supplied identity and fixed membership only into an absent slot.
    ///
    /// Initial counters/cursor must describe a fresh application journal. MLS may
    /// already be provisioned independently; this does not create or alter MLS.
    /// # Errors
    /// Rejects existing state, unavailable ownership, invalid credentials or bounds.
    pub fn provision(
        storage: ServiceStorage,
        sealer: SecretSealer,
        namespace: &[u8],
        identity: &DeviceIdentity,
        conversation: StoredConversation,
        endpoint: &RelayEndpoint,
        credential: &RelayAccessCredential,
    ) -> Result<Self, JournalError> {
        let journal = Self::handle(
            storage,
            sealer,
            namespace,
            conversation.state.conversation_id(),
            identity.device_id(),
        )?;
        if conversation.sender_counter != 0 || conversation.replay_cursor != 0 {
            return Err(JournalError::Invalid);
        }
        if conversation.bindings.len() > MAX_MEMBERS {
            return Err(JournalError::Capacity);
        }
        let snapshot = Snapshot {
            identity: identity
                .seal(&journal.sealer, namespace)
                .map_err(|_| JournalError::Protection)?,
            signing: conversation
                .signing_material
                .seal(&journal.sealer, namespace)
                .map_err(|_| JournalError::Protection)?,
            endpoint: endpoint.clone(),
            credential: credential
                .seal(&journal.sealer, namespace, endpoint)
                .map_err(|_| JournalError::Protection)?,
            state: conversation.state,
            bindings: conversation
                .bindings
                .into_iter()
                .map(|binding| binding.binding().clone())
                .collect(),
            route: conversation.routing_id,
            counter: 0,
            cursor: 0,
            authority: ServiceAuthority {
                conversation: journal.conversation,
                device: journal.device,
                revision: 1,
                enabled: true,
                claims: Vec::new(),
            },
            outbox: Vec::new(),
            inbox: Vec::new(),
        };
        journal
            .storage
            .update_slot(SnapshotKind::Journal, |current| {
                if let Some(current) = current {
                    journal.decode(current)?;
                    return Err(JournalError::Provisioned);
                }
                journal.validate(&snapshot)?;
                Ok((journal.encode(&snapshot)?, ()))
            })?;
        Ok(journal)
    }

    /// Reopens only existing state with explicit stable scope and custody.
    /// # Errors
    /// Missing, wrong-custody, wrong-namespace and fenced state fail closed.
    pub fn reopen(
        storage: ServiceStorage,
        sealer: SecretSealer,
        namespace: &[u8],
        conversation: ConversationId,
        device: DeviceId,
    ) -> Result<Self, JournalError> {
        let journal = Self::handle(storage, sealer, namespace, conversation, device)?;
        journal.read(|_| Ok(()))?;
        Ok(journal)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Snapshot, JournalError> {
        if bytes.len() > MAX_BYTES + 64 {
            return Err(JournalError::Capacity);
        }
        let blob = SealedBlob::from_bytes(bytes.to_vec()).map_err(|_| JournalError::Protection)?;
        let plaintext = self
            .sealer
            .open(&self.context, &blob)
            .map_err(|_| JournalError::Protection)?;
        let snapshot = codec::decode(&plaintext)?;
        self.validate(&snapshot)?;
        Ok(snapshot)
    }

    fn encode(&self, snapshot: &Snapshot) -> Result<Vec<u8>, JournalError> {
        let plaintext = codec::encode(snapshot)?;
        self.sealer
            .seal(&self.context, &plaintext)
            .map(|blob| blob.as_bytes().to_vec())
            .map_err(|_| JournalError::Protection)
    }

    fn read<R>(
        &self,
        operation: impl FnOnce(&Snapshot) -> Result<R, JournalError>,
    ) -> Result<R, JournalError> {
        let bytes = self
            .storage
            .read_slot(SnapshotKind::Journal)?
            .ok_or(JournalError::Missing)?;
        let snapshot = self.decode(&bytes)?;
        operation(&snapshot)
    }

    fn update<R>(
        &self,
        operation: impl FnOnce(&mut Snapshot) -> Result<R, JournalError>,
    ) -> Result<R, JournalError> {
        self.storage.update_slot(SnapshotKind::Journal, |current| {
            let mut snapshot = self.decode(current.ok_or(JournalError::Missing)?)?;
            let result = operation(&mut snapshot)?;
            self.validate(&snapshot)?;
            Ok((self.encode(&snapshot)?, result))
        })
    }

    fn scope(&self, id: ConversationId) -> Result<(), JournalError> {
        if id != self.conversation {
            return Err(JournalError::Scope);
        }
        Ok(())
    }

    fn validate(&self, snapshot: &Snapshot) -> Result<(), JournalError> {
        self.scope(snapshot.state.conversation_id())?;
        if snapshot.authority.conversation != self.conversation
            || snapshot.authority.device != self.device
            || snapshot.authority.revision == 0
            || snapshot.state.member(self.device).is_none()
        {
            return Err(JournalError::Scope);
        }
        if snapshot.bindings.is_empty()
            || snapshot.endpoint.as_str().len() > 4096
            || snapshot.bindings.len() > MAX_MEMBERS
            || snapshot.bindings.len() != snapshot.state.members().len()
            || snapshot.outbox.len() > MAX_ROWS
            || snapshot.inbox.len() > MAX_ROWS
            || snapshot.authority.claims.len() > MAX_CLAIMS
        {
            return Err(JournalError::Capacity);
        }
        let identity = DeviceIdentity::open(&self.sealer, &self.namespace, &snapshot.identity)
            .map_err(|_| JournalError::Protection)?;
        let signing = ConversationSigningMaterial::open(
            &self.sealer,
            &self.namespace,
            self.conversation,
            &snapshot.signing,
        )
        .map_err(|_| JournalError::Protection)?;
        RelayAccessCredential::open(
            &self.sealer,
            &self.namespace,
            &snapshot.endpoint,
            &snapshot.credential,
        )
        .map_err(|_| JournalError::Protection)?;
        if snapshot.state.version() != ProtocolVersion::application_v1() {
            return Err(JournalError::Invalid);
        }
        if identity.device_id() != self.device || signing.binding().device_id() != self.device {
            return Err(JournalError::Scope);
        }
        for (index, binding) in snapshot.bindings.iter().enumerate() {
            verify_device_credential_binding(binding).map_err(|_| JournalError::Protection)?;
            if binding.conversation_id() != self.conversation
                || snapshot.state.member(binding.device_id()).is_none()
                || snapshot.bindings[..index]
                    .iter()
                    .any(|prior| prior.device_id() == binding.device_id())
                || (binding.device_id() == self.device && binding != signing.binding())
            {
                return Err(JournalError::Scope);
            }
        }
        for (index, row) in snapshot.outbox.iter().enumerate() {
            let message =
                decode_application_message(&row.intent).map_err(|_| JournalError::Invalid)?;
            if message.version() != ProtocolVersion::application_v1()
                || !same_message(&row.intent, &message)?
                || row.reservation.conversation_id != self.conversation
                || row.reservation.message_id != message.message_id()
                || row.reservation.sender_counter != message.sender_counter()
                || row.reservation.sender_counter != index as u64 + 1
                || row.epoch != snapshot.state.epoch()
                || row.expiry == 0
                || snapshot.outbox[..index].iter().any(|prior| {
                    prior.reservation.message_id == row.reservation.message_id
                        || prior.reservation.envelope_id == row.reservation.envelope_id
                })
            {
                return Err(JournalError::Invalid);
            }
            match message.content() {
                ApplicationContent::DirectedRequest(request)
                    if message.reply_to().is_none()
                        && request.target_device_id() != self.device
                        && snapshot.state.member(request.target_device_id()).is_some() => {}
                ApplicationContent::Text(_)
                    if snapshot.authority.claims.iter().any(|claim| {
                        message.reply_to() == Some(claim.request)
                            && claim.response
                                == Some(CommittedResponse {
                                    message: row.reservation.message_id,
                                    envelope: row.reservation.envelope_id,
                                })
                    }) => {}
                _ => return Err(JournalError::Invalid),
            }
            if let Some(envelope) = &row.envelope {
                if envelope.version() != ProtocolVersion::application_v1()
                    || !row.saved
                    || envelope.routing_id() != snapshot.route
                    || envelope.envelope_id() != row.reservation.envelope_id
                    || envelope.expires_at_unix_seconds() != row.expiry
                    || envelope.delivery_class() != DeliveryClass::GroupApplication
                {
                    return Err(JournalError::Invalid);
                }
            }
            if row.accepted == Some(0)
                || (row.accepted.is_some() && row.envelope.is_none())
                || (row.expired && row.accepted.is_some())
                || (row.abandoned && row.envelope.is_some())
                || snapshot.outbox[..index].iter().any(|prior| {
                    match (prior.accepted, row.accepted) {
                        (Some(prior), Some(current)) => prior >= current,
                        _ => false,
                    }
                })
            {
                return Err(JournalError::Invalid);
            }
        }
        if snapshot.counter != snapshot.outbox.len() as u64 {
            return Err(JournalError::Invalid);
        }
        let mut complete = 0;
        for (index, row) in snapshot.inbox.iter().enumerate() {
            if row.stored.cursor() != index as u64 + 1
                || row.stored.envelope().version() != ProtocolVersion::application_v1()
                || row.stored.envelope().routing_id() != snapshot.route
                || row.stored.envelope().delivery_class() != DeliveryClass::GroupApplication
                || row.epoch != snapshot.state.epoch()
                || snapshot.inbox[..index].iter().any(|prior| {
                    prior.stored.envelope().envelope_id() == row.stored.envelope().envelope_id()
                        || prior.stored.envelope().payload() == row.stored.envelope().payload()
                })
            {
                return Err(JournalError::Invalid);
            }
            match (&row.message, row.sender) {
                (Some(bytes), Some(sender)) => {
                    let message =
                        decode_application_message(bytes).map_err(|_| JournalError::Invalid)?;
                    if !same_message(bytes, &message)? {
                        return Err(JournalError::Invalid);
                    }
                    self.check_received(snapshot, index, sender, &message)?;
                }
                (None, None) if row.notification.is_none() => {}
                _ => return Err(JournalError::Invalid),
            }
            if let Some((notification, _)) = row.notification {
                if row.message.is_none()
                    || complete + 1 != row.stored.cursor()
                    || snapshot.inbox[..index]
                        .iter()
                        .any(|prior| prior.notification.is_some_and(|(id, _)| id == notification))
                {
                    return Err(JournalError::Invalid);
                }
                complete += 1;
            }
        }
        if complete != snapshot.cursor {
            return Err(JournalError::Invalid);
        }
        for (index, claim) in snapshot.authority.claims.iter().enumerate() {
            if claim.id == [0; 16]
                || claim.requester == self.device
                || snapshot.authority.claims[..index]
                    .iter()
                    .any(|prior| prior.id == claim.id || prior.request == claim.request)
            {
                return Err(JournalError::Invalid);
            }
            let row = snapshot
                .inbox
                .iter()
                .find(|row| {
                    row.notification.is_some()
                        && row.sender == Some(claim.requester)
                        && row.message.as_ref().is_some_and(|bytes| {
                            decode_application_message(bytes)
                                .is_ok_and(|message| message.message_id() == claim.request)
                        })
                })
                .ok_or(JournalError::Invalid)?;
            let message =
                decode_application_message(row.message.as_ref().ok_or(JournalError::Invalid)?)
                    .map_err(|_| JournalError::Invalid)?;
            if !matches!(message.content(), ApplicationContent::DirectedRequest(request)
                if request.target_device_id() == self.device)
            {
                return Err(JournalError::Invalid);
            }
            if let Some(response) = claim.response {
                if !snapshot.outbox.iter().any(|row| {
                    row.reservation.message_id == response.message
                        && row.reservation.envelope_id == response.envelope
                        && decode_application_message(&row.intent).is_ok_and(|message| {
                            message.reply_to() == Some(claim.request)
                                && matches!(message.content(), ApplicationContent::Text(_))
                        })
                }) {
                    return Err(JournalError::Invalid);
                }
            }
        }
        Ok(())
    }

    fn check_received(
        &self,
        snapshot: &Snapshot,
        index: usize,
        sender: DeviceId,
        message: &ApplicationMessage,
    ) -> Result<(), JournalError> {
        if message.version() != ProtocolVersion::application_v1()
            || snapshot.state.member(sender).is_none()
        {
            return Err(JournalError::Scope);
        }
        match message.content() {
            ApplicationContent::Text(_) if message.reply_to().is_some() => {}
            ApplicationContent::DirectedRequest(request)
                if message.reply_to().is_none()
                    && request.target_device_id() != sender
                    && snapshot.state.member(request.target_device_id()).is_some() => {}
            _ => return Err(JournalError::Unsupported),
        }
        let current = &snapshot.inbox[index];
        if sender == self.device {
            let outbound = snapshot
                .outbox
                .iter()
                .find(|row| row.saved && row.envelope.as_ref() == Some(current.stored.envelope()))
                .ok_or(JournalError::Conflict)?;
            if !same_message(&outbound.intent, message)?
                || outbound
                    .accepted
                    .is_some_and(|cursor| cursor != current.stored.cursor())
            {
                return Err(JournalError::Conflict);
            }
        } else {
            if snapshot
                .outbox
                .iter()
                .any(|row| row.reservation.message_id == message.message_id())
            {
                return Err(JournalError::Conflict);
            }
            if let Some(reply) = message.reply_to() {
                if !matches!(message.content(), ApplicationContent::Text(_))
                    || !snapshot.outbox.iter().any(|row| {
                        row.accepted.is_some()
                            && decode_application_message(&row.intent).is_ok_and(|request| {
                                request.message_id() == reply
                                    && matches!(request.content(), ApplicationContent::DirectedRequest(directed)
                                        if directed.target_device_id() == sender)
                            })
                    })
                {
                    return Err(JournalError::Conflict);
                }
            }
        }
        for prior in &snapshot.inbox[..index] {
            if let Some(bytes) = &prior.message {
                let earlier =
                    decode_application_message(bytes).map_err(|_| JournalError::Invalid)?;
                if earlier.message_id() == message.message_id()
                    || (prior.sender == Some(sender)
                        && earlier.sender_counter() >= message.sender_counter())
                {
                    return Err(JournalError::Conflict);
                }
            }
        }
        if sender != self.device
            && snapshot.inbox[..index].iter().any(|prior| {
                prior.sender == Some(sender)
                    && prior.message.as_ref().is_some_and(|bytes| {
                        decode_application_message(bytes).is_ok_and(|earlier| {
                            message.reply_to().is_some() && earlier.reply_to() == message.reply_to()
                        })
                    })
            })
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }

    /// Opens the same provisioned device; never generates replacement keys.
    /// # Errors
    /// Propagates authentication, custody and owner failures.
    pub fn identity(&self) -> Result<DeviceIdentity, JournalError> {
        self.read(|snapshot| {
            DeviceIdentity::open(&self.sealer, &self.namespace, &snapshot.identity)
                .map_err(|_| JournalError::Protection)
        })
    }

    /// Reopens only the operator-provisioned relay credential and exact endpoint.
    /// # Errors
    /// Propagates custody, scope, authentication and current-owner failures.
    pub fn relay_access(&self) -> Result<(RelayEndpoint, RelayAccessCredential), JournalError> {
        self.read(|snapshot| {
            let credential = RelayAccessCredential::open(
                &self.sealer,
                &self.namespace,
                &snapshot.endpoint,
                &snapshot.credential,
            )
            .map_err(|_| JournalError::Protection)?;
            Ok((snapshot.endpoint.clone(), credential))
        })
    }

    /// Returns the stable namespace to pass to the independently sealed MLS slot.
    /// # Errors
    /// Requires a current authenticated journal load, not a cached handle check.
    pub fn mls_namespace(&self) -> Result<Vec<u8>, JournalError> {
        self.read(|_| Ok(self.namespace.clone()))
    }

    /// Returns current explicit admission generation, not peer-derived authority.
    /// # Errors
    /// Propagates authenticated-load and ownership failures.
    pub fn authorization(&self) -> Result<ServiceAuthorization, JournalError> {
        self.read(|snapshot| {
            Ok(ServiceAuthorization {
                revision: snapshot.authority.revision,
                claim: None,
            })
        })
    }

    /// Commits local revocation/enabling under the same reservation mutex.
    /// # Errors
    /// Propagates owner, custody and generation exhaustion failures.
    pub fn set_enabled(&self, enabled: bool) -> Result<(), JournalError> {
        self.update(|snapshot| snapshot.authority.set_enabled(enabled).map_err(Into::into))
    }

    /// Selects actual completed authenticated inbox evidence and issues a local claim.
    /// # Errors
    /// Rejects duplicate claims, wrong recipients, incomplete messages and stale owners.
    pub fn claim(&self, request: MessageId) -> Result<ServiceAuthorization, JournalError> {
        self.update(|snapshot| {
            let row = snapshot
                .inbox
                .iter()
                .find(|row| {
                    row.notification.is_some()
                        && row.message.as_ref().is_some_and(|bytes| {
                            decode_application_message(bytes)
                                .is_ok_and(|message| message.message_id() == request)
                        })
                })
                .ok_or(JournalError::Missing)?;
            let message = opened_message(row)?;
            let identity = DeviceIdentity::open(&self.sealer, &self.namespace, &snapshot.identity)
                .map_err(|_| JournalError::Protection)?;
            let generated = identity
                .generate_message_id()
                .map_err(|_| JournalError::Protection)?;
            let claim_id = *generated.as_bytes();
            snapshot
                .authority
                .claim(&snapshot.state, &message, claim_id)
                .map_err(Into::into)
        })
    }

    /// Returns exact immutable intent even before ready ciphertext exists.
    /// # Errors
    /// Rejects missing or incorrectly scoped reservations and owner/custody failure.
    pub fn outbound_intent(
        &self,
        reservation: OutboundReservation,
    ) -> Result<ReservedIntent, JournalError> {
        self.read(|snapshot| intent(find_outbox(snapshot, reservation)?))
    }

    /// Enumerates retained intents, including incomplete and terminal operations.
    /// # Errors
    /// Propagates current-owner authentication and decoding failures.
    pub fn retained_outbox(&self) -> Result<Vec<ReservedIntent>, JournalError> {
        self.read(|snapshot| snapshot.outbox.iter().map(intent).collect())
    }

    /// Returns every committed intent lacking ready ciphertext, in sender order.
    ///
    /// Terminal abandoned/expired intents are retained and explicitly marked;
    /// callers must not recover those. Reconcile nonterminal originals before
    /// admitting new work. Ready ciphertext is never returned for re-encryption.
    /// # Errors
    /// Propagates current-owner authentication and decoding failures.
    pub fn unready_outbox(&self) -> Result<Vec<ReservedIntent>, JournalError> {
        self.read(|snapshot| {
            snapshot
                .outbox
                .iter()
                .filter(|row| row.envelope.is_none())
                .map(intent)
                .collect()
        })
    }

    /// Opens exact notification identity and time without manufacturing a retry.
    /// # Errors
    /// Rejects foreign conversations, missing observations and owner/custody failure.
    pub fn notification_evidence(
        &self,
        id: ConversationId,
        cursor: u64,
    ) -> Result<Option<(NotificationId, u64)>, JournalError> {
        self.read(|snapshot| {
            self.scope(id)?;
            snapshot
                .inbox
                .iter()
                .find(|row| row.stored.cursor() == cursor)
                .map(|row| row.notification)
                .ok_or(JournalError::Missing)
        })
    }

    /// Returns ready operations in permanent sender-counter order.
    /// # Errors
    /// Propagates current-owner authenticated-load failures.
    pub fn ready_outbox(&self) -> Result<Vec<ReservedIntent>, JournalError> {
        self.read(|snapshot| {
            snapshot
                .outbox
                .iter()
                .filter(|row| {
                    row.envelope.is_some()
                        && row.accepted.is_none()
                        && !row.abandoned
                        && !row.expired
                })
                .map(intent)
                .collect()
        })
    }

    /// Records exact relay acceptance without replacing original ciphertext.
    /// # Errors
    /// Rejects changed envelopes/cursors or acceptance order conflicts.
    pub fn accept_outbound(&self, stored: &StoredRelayEnvelope) -> Result<(), JournalError> {
        self.update(|snapshot| {
            if stored.envelope().routing_id() != snapshot.route {
                return Err(JournalError::Scope);
            }
            let index = snapshot
                .outbox
                .iter()
                .position(|row| row.envelope.as_ref() == Some(stored.envelope()))
                .ok_or(JournalError::Conflict)?;
            if let Some(cursor) = snapshot.outbox[index].accepted {
                return if cursor == stored.cursor() {
                    Ok(())
                } else {
                    Err(JournalError::Conflict)
                };
            }
            if snapshot.outbox[index].expired
                || snapshot.outbox[index].abandoned
                || snapshot.inbox.iter().any(|row| {
                    (row.stored.envelope().envelope_id() == stored.envelope().envelope_id()
                        || row.stored.cursor() == stored.cursor())
                        && &row.stored != stored
                })
            {
                return Err(JournalError::Conflict);
            }
            if snapshot.outbox[..index].iter().any(|row| {
                (row.accepted.is_none() && !row.abandoned && !row.expired)
                    || row.accepted.is_some_and(|cursor| cursor >= stored.cursor())
            }) || snapshot
                .outbox
                .iter()
                .any(|row| row.accepted == Some(stored.cursor()))
            {
                return Err(JournalError::Conflict);
            }
            snapshot.outbox[index].accepted = Some(stored.cursor());
            Ok(())
        })
    }

    /// Retains expired work and its IDs instead of silently pruning it.
    /// # Errors
    /// Rejects premature expiry, wrong reservations and owner/custody failure.
    pub fn expire_outbound(
        &self,
        reservation: OutboundReservation,
        now: u64,
    ) -> Result<NativeExpiryOutcome, JournalError> {
        self.update(|snapshot| {
            let row = find_outbox_mut(snapshot, reservation)?;
            if let Some(cursor) = row.accepted {
                return Ok(NativeExpiryOutcome::Accepted { cursor });
            }
            if row.envelope.is_none() || row.abandoned {
                return Err(JournalError::Conflict);
            }
            if now < row.expiry {
                return Err(JournalError::Conflict);
            }
            row.expired = true;
            Ok(NativeExpiryOutcome::Expired)
        })
    }
}

fn same_message(bytes: &[u8], message: &ApplicationMessage) -> Result<bool, JournalError> {
    let encoded =
        Zeroizing::new(encode_application_message(message).map_err(|_| JournalError::Invalid)?);
    Ok(bytes == encoded.as_slice())
}

fn copy_content(content: &ApplicationContent) -> Result<ApplicationContent, JournalError> {
    match content {
        ApplicationContent::Text(text) => {
            ApplicationContent::text(text.as_str()).map_err(|_| JournalError::Invalid)
        }
        ApplicationContent::DirectedRequest(request) => {
            ApplicationContent::directed_request(request.target_device_id(), request.body())
                .map_err(|_| JournalError::Invalid)
        }
        _ => Err(JournalError::Unsupported),
    }
}

fn intent(row: &Outbox) -> Result<ReservedIntent, JournalError> {
    Ok(ReservedIntent {
        reservation: row.reservation,
        message: decode_application_message(&row.intent).map_err(|_| JournalError::Invalid)?,
        epoch: row.epoch,
        expires_at_unix_seconds: row.expiry,
        envelope: row.envelope.clone(),
        abandoned: row.abandoned,
        accepted_cursor: row.accepted,
        expired: row.expired,
        message_saved: row.saved,
    })
}

fn find_outbox(
    snapshot: &Snapshot,
    reservation: OutboundReservation,
) -> Result<&Outbox, JournalError> {
    snapshot
        .outbox
        .iter()
        .find(|row| row.reservation == reservation)
        .ok_or(JournalError::Conflict)
}

fn find_outbox_mut(
    snapshot: &mut Snapshot,
    reservation: OutboundReservation,
) -> Result<&mut Outbox, JournalError> {
    snapshot
        .outbox
        .iter_mut()
        .find(|row| row.reservation == reservation)
        .ok_or(JournalError::Conflict)
}

fn opened_message(row: &Inbox) -> Result<StoredApplicationMessage, JournalError> {
    Ok(StoredApplicationMessage {
        cursor: row.stored.cursor(),
        envelope_id: row.stored.envelope().envelope_id(),
        sender: row.sender.ok_or(JournalError::Invalid)?,
        epoch: row.epoch,
        message: decode_application_message(row.message.as_ref().ok_or(JournalError::Invalid)?)
            .map_err(|_| JournalError::Invalid)?,
    })
}

impl NativeConversationJournal for ServiceJournal {
    type Error = JournalError;
    type Authorization = ServiceAuthorization;

    fn load_conversation(&self, id: ConversationId) -> Result<StoredConversation, Self::Error> {
        self.read(|snapshot| {
            self.scope(id)?;
            Ok(StoredConversation {
                routing_id: snapshot.route,
                signing_material: ConversationSigningMaterial::open(
                    &self.sealer,
                    &self.namespace,
                    id,
                    &snapshot.signing,
                )
                .map_err(|_| JournalError::Protection)?,
                state: snapshot.state.clone(),
                bindings: snapshot
                    .bindings
                    .iter()
                    .map(|binding| {
                        verify_device_credential_binding(binding)
                            .map_err(|_| JournalError::Protection)
                    })
                    .collect::<Result<_, _>>()?,
                sender_counter: snapshot.counter,
                replay_cursor: snapshot.cursor,
            })
        })
    }

    fn reserve_application(
        &self,
        request: &NativeApplicationRequest<Self::Authorization>,
        envelope: EnvelopeId,
    ) -> Result<OutboundReservation, Self::Error> {
        self.update(|snapshot| {
            self.scope(request.conversation_id)?;
            if let Some(prior) = snapshot
                .outbox
                .iter()
                .find(|row| row.reservation.message_id == request.message_id)
            {
                let candidate = ApplicationMessage::new(
                    ProtocolVersion::application_v1(),
                    request.message_id,
                    prior.reservation.sender_counter,
                    request.sent_at_unix_milliseconds,
                    request.reply_to,
                    copy_content(&request.content)?,
                )
                .map_err(|_| JournalError::Invalid)?;
                if request.policy_operation
                    || prior.reservation.envelope_id != envelope
                    || prior.expiry != request.expires_at_unix_seconds
                    || !same_message(&prior.intent, &candidate)?
                {
                    return Err(JournalError::Conflict);
                }
                return Ok(prior.reservation);
            }
            if snapshot.outbox.len() == MAX_ROWS {
                return Err(JournalError::Capacity);
            }
            if request.expires_at_unix_seconds == 0
                || snapshot
                    .outbox
                    .iter()
                    .any(|row| row.reservation.envelope_id == envelope)
                || snapshot.inbox.iter().any(|row| {
                    row.stored.envelope().envelope_id() == envelope
                        || row.message.as_ref().is_some_and(|bytes| {
                            decode_application_message(bytes)
                                .is_ok_and(|message| message.message_id() == request.message_id)
                        })
                })
            {
                return Err(JournalError::Conflict);
            }
            let counter = snapshot
                .counter
                .checked_add(1)
                .ok_or(JournalError::Capacity)?;
            let message = ApplicationMessage::new(
                ProtocolVersion::application_v1(),
                request.message_id,
                counter,
                request.sent_at_unix_milliseconds,
                request.reply_to,
                copy_content(&request.content)?,
            )
            .map_err(|_| JournalError::Invalid)?;
            let intent = Zeroizing::new(
                encode_application_message(&message).map_err(|_| JournalError::Invalid)?,
            );
            if intent.len() > MAX_FIELD {
                return Err(JournalError::Capacity);
            }
            snapshot
                .authority
                .reserve(&snapshot.state, request, envelope)?;
            let reservation = OutboundReservation {
                conversation_id: self.conversation,
                message_id: request.message_id,
                envelope_id: envelope,
                sender_counter: counter,
            };
            snapshot.counter = counter;
            snapshot.outbox.push(Outbox {
                reservation,
                epoch: snapshot.state.epoch(),
                expiry: request.expires_at_unix_seconds,
                intent,
                saved: false,
                envelope: None,
                abandoned: false,
                accepted: None,
                expired: false,
            });
            Ok(reservation)
        })
    }

    fn store_outbound_message(
        &self,
        reservation: OutboundReservation,
        route: RoutingId,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), Self::Error> {
        self.update(|snapshot| {
            if route != snapshot.route || sender != self.device {
                return Err(JournalError::Scope);
            }
            let row = find_outbox_mut(snapshot, reservation)?;
            if epoch != row.epoch || !same_message(&row.intent, message)? {
                return Err(JournalError::Conflict);
            }
            if row.abandoned && !row.saved {
                return Err(JournalError::Conflict);
            }
            row.saved = true;
            Ok(())
        })
    }

    fn store_outbound_envelope(
        &self,
        reservation: OutboundReservation,
        envelope: &RelayEnvelope,
    ) -> Result<(), Self::Error> {
        self.update(|snapshot| {
            if envelope.routing_id() != snapshot.route {
                return Err(JournalError::Scope);
            }
            let row = find_outbox_mut(snapshot, reservation)?;
            if let Some(prior) = &row.envelope {
                return if prior == envelope {
                    Ok(())
                } else {
                    Err(JournalError::Conflict)
                };
            }
            if !row.saved
                || row.abandoned
                || envelope.envelope_id() != reservation.envelope_id
                || envelope.delivery_class() != DeliveryClass::GroupApplication
                || envelope.expires_at_unix_seconds() != row.expiry
            {
                return Err(JournalError::Conflict);
            }
            row.envelope = Some(envelope.clone());
            Ok(())
        })
    }

    fn abandon_outbound_application(
        &self,
        reservation: OutboundReservation,
    ) -> Result<(), Self::Error> {
        self.update(|snapshot| {
            let row = find_outbox_mut(snapshot, reservation)?;
            if row.envelope.is_some() {
                return Err(JournalError::Conflict);
            }
            row.abandoned = true;
            Ok(())
        })
    }

    fn record_inbox_envelope(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, Self::Error> {
        self.update(|snapshot| {
            if stored.envelope().routing_id() != snapshot.route {
                return Err(JournalError::Scope);
            }
            if stored.envelope().delivery_class() != DeliveryClass::GroupApplication {
                return Err(JournalError::Unsupported);
            }
            if let Some(prior) = snapshot
                .inbox
                .iter()
                .find(|row| row.stored.cursor() == stored.cursor())
            {
                return if &prior.stored == stored {
                    Ok(self.conversation)
                } else {
                    Err(JournalError::Conflict)
                };
            }
            if snapshot.inbox.len() == MAX_ROWS {
                return Err(JournalError::Capacity);
            }
            if stored.cursor() != snapshot.inbox.len() as u64 + 1
                || snapshot.inbox.iter().any(|row| {
                    row.stored.envelope().envelope_id() == stored.envelope().envelope_id()
                        || row.stored.envelope().payload() == stored.envelope().payload()
                })
                || snapshot.outbox.iter().any(|row| {
                    row.reservation.envelope_id == stored.envelope().envelope_id()
                        && (row.envelope.as_ref() != Some(stored.envelope())
                            || row.accepted.is_some_and(|cursor| cursor != stored.cursor()))
                })
            {
                return Err(JournalError::Conflict);
            }
            snapshot.inbox.push(Inbox {
                stored: stored.clone(),
                sender: None,
                epoch: snapshot.state.epoch(),
                message: None,
                notification: None,
            });
            Ok(self.conversation)
        })
    }

    fn inbox_operation(
        &self,
        id: ConversationId,
        cursor: u64,
    ) -> Result<InboxOperation, Self::Error> {
        self.read(|snapshot| {
            self.scope(id)?;
            let row = snapshot
                .inbox
                .iter()
                .find(|row| row.stored.cursor() == cursor)
                .ok_or(JournalError::Missing)?;
            let stored = row.stored.clone();
            if row.notification.is_some() {
                Ok(InboxOperation::Complete {
                    stored,
                    message: opened_message(row)?,
                })
            } else if row.message.is_some() {
                Ok(InboxOperation::MessageSaved {
                    stored,
                    message: opened_message(row)?,
                })
            } else {
                Ok(InboxOperation::Received { stored })
            }
        })
    }

    fn outbound_history_message(
        &self,
        id: ConversationId,
        stored: &StoredRelayEnvelope,
    ) -> Result<Option<StoredApplicationMessage>, Self::Error> {
        self.read(|snapshot| {
            self.scope(id)?;
            if stored.envelope().routing_id() != snapshot.route {
                return Err(JournalError::Scope);
            }
            let Some(row) = snapshot
                .outbox
                .iter()
                .find(|row| row.saved && row.envelope.as_ref() == Some(stored.envelope()))
            else {
                return Ok(None);
            };
            Ok(Some(StoredApplicationMessage {
                cursor: stored.cursor(),
                envelope_id: stored.envelope().envelope_id(),
                sender: self.device,
                epoch: row.epoch,
                message: decode_application_message(&row.intent)
                    .map_err(|_| JournalError::Invalid)?,
            }))
        })
    }

    fn save_inbox_message(
        &self,
        id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), Self::Error> {
        self.update(|snapshot| {
            self.scope(id)?;
            let index = snapshot
                .inbox
                .iter()
                .position(|row| row.stored.cursor() == cursor)
                .ok_or(JournalError::Missing)?;
            if epoch != snapshot.state.epoch() {
                return Err(JournalError::Scope);
            }
            if let Some(prior) = &snapshot.inbox[index].message {
                return if snapshot.inbox[index].sender == Some(sender)
                    && same_message(prior, message)?
                {
                    Ok(())
                } else {
                    Err(JournalError::Conflict)
                };
            }
            if cursor != snapshot.cursor + 1 {
                return Err(JournalError::Conflict);
            }
            self.check_received(snapshot, index, sender, message)?;
            let bytes = Zeroizing::new(
                encode_application_message(message).map_err(|_| JournalError::Invalid)?,
            );
            if bytes.len() > MAX_FIELD {
                return Err(JournalError::Capacity);
            }
            let row = &mut snapshot.inbox[index];
            row.sender = Some(sender);
            row.message = Some(bytes);
            Ok(())
        })
    }

    fn complete_inbox_with_notification_at(
        &self,
        id: ConversationId,
        cursor: u64,
        notification: NotificationId,
        now: u64,
    ) -> Result<u64, Self::Error> {
        self.update(|snapshot| {
            self.scope(id)?;
            let index = snapshot
                .inbox
                .iter()
                .position(|row| row.stored.cursor() == cursor)
                .ok_or(JournalError::Missing)?;
            if let Some(prior) = snapshot.inbox[index].notification {
                return if prior == (notification, now) {
                    Ok(snapshot.cursor)
                } else {
                    Err(JournalError::Conflict)
                };
            }
            if cursor != snapshot.cursor + 1
                || snapshot.inbox[index].message.is_none()
                || snapshot
                    .inbox
                    .iter()
                    .any(|row| row.notification.is_some_and(|(id, _)| id == notification))
            {
                return Err(JournalError::Conflict);
            }
            snapshot.inbox[index].notification = Some((notification, now));
            snapshot.cursor = cursor;
            Ok(cursor)
        })
    }

    fn active_membership_outbox(
        &self,
        id: ConversationId,
    ) -> Result<Option<MembershipOutbox>, Self::Error> {
        self.read(|_| {
            self.scope(id)?;
            Ok(None)
        })
    }
    fn active_membership_inbox(
        &self,
        id: ConversationId,
    ) -> Result<Option<MembershipInboxOperation>, Self::Error> {
        self.read(|_| {
            self.scope(id)?;
            Ok(None)
        })
    }
    fn membership_outbox_for_envelope(
        &self,
        _id: EnvelopeId,
    ) -> Result<Option<MembershipOutbox>, Self::Error> {
        self.read(|_| Ok(None))
    }
    fn load_membership_outbox(
        &self,
        _id: MembershipOperationId,
    ) -> Result<MembershipOutbox, Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn complete_membership_outbox(&self, _id: MembershipOperationId) -> Result<(), Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn orphan_membership_outbox(&self, _id: MembershipOperationId) -> Result<(), Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn record_membership_inbox_envelope(
        &self,
        _stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn mark_membership_outbox_accepted(
        &self,
        _stored: &StoredRelayEnvelope,
    ) -> Result<MembershipOperationId, Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn complete_membership_echo(
        &self,
        _stored: &StoredRelayEnvelope,
        _device: DeviceId,
    ) -> Result<MembershipOperationId, Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn membership_inbox_operation(
        &self,
        _id: ConversationId,
        _cursor: u64,
    ) -> Result<MembershipInboxOperation, Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn save_membership_inbox_transition(
        &self,
        _id: ConversationId,
        _cursor: u64,
        _sender: DeviceId,
        _parent: u64,
        _operation: MembershipOperationId,
        _control: &[u8],
        _next: &ConversationState,
        _bindings: &[DeviceCredentialBinding],
    ) -> Result<(), Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn complete_membership_inbox_with_notification(
        &self,
        _id: ConversationId,
        _cursor: u64,
        _notification: NotificationId,
    ) -> Result<u64, Self::Error> {
        Err(JournalError::Unsupported)
    }
    fn store_membership_outbox(
        &self,
        _operation: MembershipOperationId,
        _id: ConversationId,
        _parent: u64,
        _envelope: &RelayEnvelope,
        _control: &[u8],
        _next: &ConversationState,
        _bindings: &[DeviceCredentialBinding],
        _welcome: Option<&[u8]>,
    ) -> Result<(), Self::Error> {
        Err(JournalError::Unsupported)
    }
}
