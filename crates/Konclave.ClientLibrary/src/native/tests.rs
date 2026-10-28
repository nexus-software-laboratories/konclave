//! Bounded sealed in-memory composition tests, not evidence of process durability.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use KonclaveCryptographicCore::{
    ConversationSigningMaterial, DeviceIdentity, MlsConversationClient,
    verify_device_credential_binding,
};
use KonclaveDomainCore::*;
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_conversation_state, decode_device_credential_binding,
    encode_application_message, encode_conversation_state, encode_device_credential_binding,
};
use KonclaveSecretStorage::{
    ExternalWrappingKeyProvider, SealedBlob, SealedMlsStorage, SealedMlsStorageHandle,
    SecretRecordContext, SecretRecordKind, SecretSealer, SecretStorageError,
};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use super::journal::*;
use super::processor::{NativeConversationError, NativeConversationProcessor};

const LIMIT: usize = 16;
const MAX_BYTES: usize = 1024 * 1024;
const PROFILE: &[u8] = b"native-test-endpoint";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum Fault {
    #[error("injected journal failure")]
    Injected,
    #[error("unsupported fixture operation")]
    Unsupported,
    #[error("conflicting fixture evidence")]
    Conflict,
    #[error("fixture bound exceeded")]
    Bound,
}

fn sealer() -> SecretSealer {
    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
}

// Only ciphertext produced by SealedMlsStorage crosses this backing boundary.
#[derive(Clone, Default)]
struct MemoryMls(Arc<Mutex<MlsRows>>);

#[derive(Default)]
struct MlsRows {
    groups: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
    epochs: BTreeMap<(Vec<u8>, u64), Zeroizing<Vec<u8>>>,
    packages: BTreeMap<Vec<u8>, KeyPackageData>,
}

fn backend_error() -> SecretStorageError {
    SecretStorageError::MlsStorageBackendFailure {
        operation: "bounded memory fixture",
    }
}

impl GroupStateStorage for MemoryMls {
    type Error = SecretStorageError;

    fn state(&self, id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self
            .0
            .lock()
            .map_err(|_| backend_error())?
            .groups
            .get(id)
            .cloned())
    }

    fn epoch(&self, id: &[u8], epoch: u64) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self
            .0
            .lock()
            .map_err(|_| backend_error())?
            .epochs
            .get(&(id.to_vec(), epoch))
            .cloned())
    }

    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        if state.id.len() > 128
            || state.data.len() > MAX_BYTES
            || inserts.len() + updates.len() > LIMIT
            || inserts
                .iter()
                .chain(&updates)
                .any(|row| row.data.len() > MAX_BYTES)
        {
            return Err(backend_error());
        }
        let mut rows = self.0.lock().map_err(|_| backend_error())?;
        if rows.groups.len() + usize::from(!rows.groups.contains_key(&state.id)) > LIMIT
            || rows.epochs.len() + inserts.len() + updates.len() > LIMIT
        {
            return Err(backend_error());
        }
        let id = state.id.clone();
        rows.groups.insert(state.id, state.data);
        for epoch in inserts.into_iter().chain(updates) {
            rows.epochs.insert((id.clone(), epoch.id), epoch.data);
        }
        Ok(())
    }

    fn max_epoch_id(&self, id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self
            .0
            .lock()
            .map_err(|_| backend_error())?
            .epochs
            .keys()
            .filter(|(group, _)| group == id)
            .map(|(_, epoch)| *epoch)
            .max())
    }
}

impl KeyPackageStorage for MemoryMls {
    type Error = SecretStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.0
            .lock()
            .map_err(|_| backend_error())?
            .packages
            .remove(id);
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, package: KeyPackageData) -> Result<(), Self::Error> {
        if id.len() > 128
            || package.key_package_bytes.len() > MAX_BYTES
            || package.init_key.as_ref().len() > MAX_BYTES
            || package.leaf_node_key.as_ref().len() > MAX_BYTES
        {
            return Err(backend_error());
        }
        let mut rows = self.0.lock().map_err(|_| backend_error())?;
        if rows.packages.len() >= LIMIT && !rows.packages.contains_key(&id) {
            return Err(backend_error());
        }
        rows.packages.insert(id, package);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        Ok(self
            .0
            .lock()
            .map_err(|_| backend_error())?
            .packages
            .get(id)
            .cloned())
    }
}

struct MessageRow {
    id: MessageId,
    sender: DeviceId,
    epoch: u64,
    body: SealedBlob,
}

struct InboxRow {
    stored: StoredRelayEnvelope,
    message: Option<MessageRow>,
    complete: bool,
}

struct PendingMembership {
    operation: MembershipOperationId,
    parent: u64,
    envelope: RelayEnvelope,
    control: SealedBlob,
    next: SealedBlob,
    bindings: Vec<SealedBlob>,
    welcome: Option<Vec<u8>>,
    status: MembershipOutboxStatus,
    accepted_cursor: Option<u64>,
}

struct Rows {
    counter: u64,
    cursor: u64,
    reservations: Vec<OutboundReservation>,
    abandoned: Vec<EnvelopeId>,
    outbound: Option<(OutboundReservation, MessageRow)>,
    envelope: Option<RelayEnvelope>,
    inbox: Option<InboxRow>,
    membership: Option<PendingMembership>,
    notifications: Vec<(NotificationId, u64)>,
    fail: Option<&'static str>,
    events: Vec<&'static str>,
}

struct Journal {
    id: ConversationId,
    route: RoutingId,
    signing: SealedBlob,
    policy: Mutex<SealedBlob>,
    bindings: Mutex<Vec<SealedBlob>>,
    sealer: SecretSealer,
    rows: Mutex<Rows>,
}

impl Journal {
    fn new(device: &DeviceIdentity) -> Self {
        let id = ConversationId::from_bytes([1; 32]);
        let material = device.create_conversation_signing_material(id).unwrap();
        let binding = material.binding().clone();
        let signing = material.seal(&sealer(), PROFILE).unwrap();
        let group = MlsConversationClient::with_storage(
            material,
            SealedMlsStorage::new(MemoryMls::default(), sealer()),
        )
        .unwrap()
        .create_group()
        .unwrap();
        Self {
            id,
            route: RoutingId::from_bytes([2; 32]),
            signing,
            policy: Mutex::new(
                sealer()
                    .seal(
                        &Self::context(SecretRecordKind::ConversationPolicyState, id.as_bytes()),
                        &encode_conversation_state(group.state()).unwrap(),
                    )
                    .unwrap(),
            ),
            bindings: Mutex::new(vec![
                sealer()
                    .seal(
                        &Self::context(
                            SecretRecordKind::ConversationCredentialBinding,
                            id.as_bytes(),
                        ),
                        &encode_device_credential_binding(&binding).unwrap(),
                    )
                    .unwrap(),
            ]),
            sealer: sealer(),
            rows: Mutex::new(Rows {
                counter: 0,
                cursor: 0,
                reservations: vec![],
                abandoned: vec![],
                outbound: None,
                envelope: None,
                inbox: None,
                membership: None,
                notifications: vec![],
                fail: None,
                events: vec![],
            }),
        }
    }

    fn context(kind: SecretRecordKind, id: &[u8]) -> SecretRecordContext {
        SecretRecordContext::derive(kind, &[PROFILE, id]).unwrap()
    }

    fn open_membership(&self, pending: &PendingMembership) -> MembershipOutbox {
        let next = self
            .sealer
            .open(
                &Self::context(
                    SecretRecordKind::ConversationPolicyState,
                    self.id.as_bytes(),
                ),
                &pending.next,
            )
            .unwrap();
        MembershipOutbox {
            operation_id: pending.operation,
            conversation_id: self.id,
            parent_epoch: pending.parent,
            envelope: pending.envelope.clone(),
            control: self
                .sealer
                .open(
                    &Self::context(
                        SecretRecordKind::LocalOperation,
                        pending.operation.as_bytes(),
                    ),
                    &pending.control,
                )
                .unwrap(),
            next_state: decode_conversation_state(&next).unwrap(),
            bindings: pending
                .bindings
                .iter()
                .map(|blob| {
                    let bytes = self
                        .sealer
                        .open(
                            &Self::context(
                                SecretRecordKind::ConversationCredentialBinding,
                                self.id.as_bytes(),
                            ),
                            blob,
                        )
                        .unwrap();
                    verify_device_credential_binding(
                        &decode_device_credential_binding(&bytes).unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
            welcome: pending.welcome.clone(),
            status: pending.status,
            accepted_cursor: pending.accepted_cursor,
        }
    }

    fn step(&self, event: &'static str) -> Result<std::sync::MutexGuard<'_, Rows>, Fault> {
        let mut rows = self.rows.lock().map_err(|_| Fault::Conflict)?;
        if rows.events.len() >= 128 {
            return Err(Fault::Bound);
        }
        rows.events.push(event);
        if rows.fail == Some(event) {
            rows.fail = None;
            return Err(Fault::Injected);
        }
        Ok(rows)
    }

    fn seal_message(
        &self,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> MessageRow {
        let encoded = Zeroizing::new(encode_application_message(message).unwrap());
        assert!(encoded.len() <= MAX_BYTES);
        MessageRow {
            id: message.message_id(),
            sender,
            epoch,
            body: self
                .sealer
                .seal(
                    &self.message_context(message.message_id(), sender, epoch),
                    &encoded,
                )
                .unwrap(),
        }
    }

    fn message_context(&self, id: MessageId, sender: DeviceId, epoch: u64) -> SecretRecordContext {
        SecretRecordContext::derive(
            SecretRecordKind::LocalApplicationMessage,
            &[
                PROFILE,
                self.id.as_bytes(),
                id.as_bytes(),
                sender.as_bytes(),
                &epoch.to_be_bytes(),
            ],
        )
        .unwrap()
    }

    fn open_message(
        &self,
        row: &MessageRow,
        stored: &StoredRelayEnvelope,
    ) -> StoredApplicationMessage {
        let plain = self
            .sealer
            .open(
                &self.message_context(row.id, row.sender, row.epoch),
                &row.body,
            )
            .unwrap();
        StoredApplicationMessage {
            cursor: stored.cursor(),
            envelope_id: stored.envelope().envelope_id(),
            sender: row.sender,
            epoch: row.epoch,
            message: decode_application_message(&plain).unwrap(),
        }
    }
}

impl NativeConversationJournal for Journal {
    type Error = Fault;
    type Authorization = ();

    fn load_conversation(&self, id: ConversationId) -> Result<StoredConversation, Fault> {
        let rows = self.step("load")?;
        if id != self.id {
            return Err(Fault::Conflict);
        }
        let policy = self
            .sealer
            .open(
                &Self::context(SecretRecordKind::ConversationPolicyState, id.as_bytes()),
                &self.policy.lock().unwrap(),
            )
            .unwrap();
        Ok(StoredConversation {
            routing_id: self.route,
            signing_material: ConversationSigningMaterial::open(
                &self.sealer,
                PROFILE,
                id,
                &self.signing,
            )
            .unwrap(),
            state: decode_conversation_state(&policy).unwrap(),
            bindings: self
                .bindings
                .lock()
                .unwrap()
                .iter()
                .map(|blob| {
                    let binding = self
                        .sealer
                        .open(
                            &Self::context(
                                SecretRecordKind::ConversationCredentialBinding,
                                id.as_bytes(),
                            ),
                            blob,
                        )
                        .unwrap();
                    verify_device_credential_binding(
                        &decode_device_credential_binding(&binding).unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
            sender_counter: rows.counter,
            replay_cursor: rows.cursor,
        })
    }

    fn active_membership_outbox(
        &self,
        id: ConversationId,
    ) -> Result<Option<MembershipOutbox>, Fault> {
        let rows = self.step("membership-outbox")?;
        if id != self.id {
            return Err(Fault::Conflict);
        }
        Ok(rows
            .membership
            .as_ref()
            .filter(|pending| {
                matches!(
                    pending.status,
                    MembershipOutboxStatus::Ready | MembershipOutboxStatus::Accepted
                )
            })
            .map(|pending| self.open_membership(pending)))
    }

    fn active_membership_inbox(
        &self,
        id: ConversationId,
    ) -> Result<Option<MembershipInboxOperation>, Fault> {
        let _rows = self.step("membership-inbox")?;
        if id != self.id {
            return Err(Fault::Conflict);
        }
        Ok(None)
    }

    fn reserve_application(
        &self,
        request: &NativeApplicationRequest<()>,
        envelope: EnvelopeId,
    ) -> Result<OutboundReservation, Fault> {
        let mut rows = self.step("reserve")?;
        if request.conversation_id != self.id
            || request.authorization.is_some()
            || request.policy_operation
            || rows
                .reservations
                .iter()
                .any(|r| r.message_id == request.message_id || r.envelope_id == envelope)
        {
            return Err(Fault::Conflict);
        }
        if rows.reservations.len() >= LIMIT {
            return Err(Fault::Bound);
        }
        let counter = rows.counter.checked_add(1).ok_or(Fault::Bound)?;
        let reservation = OutboundReservation {
            conversation_id: self.id,
            message_id: request.message_id,
            envelope_id: envelope,
            sender_counter: counter,
        };
        rows.counter = counter;
        rows.reservations.push(reservation);
        Ok(reservation)
    }

    fn store_outbound_message(
        &self,
        reservation: OutboundReservation,
        route: RoutingId,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), Fault> {
        let mut rows = self.step("outbound-message")?;
        if route != self.route
            || !rows.reservations.contains(&reservation)
            || message.message_id() != reservation.message_id
            || rows.outbound.is_some()
        {
            return Err(Fault::Conflict);
        }
        rows.outbound = Some((reservation, self.seal_message(sender, epoch, message)));
        Ok(())
    }

    fn store_outbound_envelope(
        &self,
        reservation: OutboundReservation,
        envelope: &RelayEnvelope,
    ) -> Result<(), Fault> {
        let mut rows = self.step("outbound-envelope")?;
        if rows.outbound.as_ref().map(|(r, _)| *r) != Some(reservation)
            || envelope.envelope_id() != reservation.envelope_id
            || envelope.routing_id() != self.route
        {
            return Err(Fault::Conflict);
        }
        rows.envelope = Some(envelope.clone());
        Ok(())
    }

    fn abandon_outbound_application(&self, reservation: OutboundReservation) -> Result<(), Fault> {
        let mut rows = self.step("abandon")?;
        if !rows.reservations.contains(&reservation) {
            return Err(Fault::Conflict);
        }
        if rows.abandoned.len() >= LIMIT {
            return Err(Fault::Bound);
        }
        rows.abandoned.push(reservation.envelope_id);
        if rows.outbound.as_ref().map(|(r, _)| *r) == Some(reservation) {
            rows.outbound = None;
            rows.envelope = None;
        }
        Ok(())
    }

    fn record_inbox_envelope(&self, stored: &StoredRelayEnvelope) -> Result<ConversationId, Fault> {
        let mut rows = self.step("record")?;
        if stored.envelope().routing_id() != self.route {
            return Err(Fault::Conflict);
        }
        if let Some(inbox) = &rows.inbox {
            if inbox.stored != *stored {
                return Err(Fault::Conflict);
            }
        } else {
            if stored.cursor() != rows.cursor + 1 {
                return Err(Fault::Conflict);
            }
            rows.inbox = Some(InboxRow {
                stored: stored.clone(),
                message: None,
                complete: false,
            });
        }
        Ok(self.id)
    }

    fn inbox_operation(&self, id: ConversationId, cursor: u64) -> Result<InboxOperation, Fault> {
        let rows = self.step("inbox")?;
        let inbox = rows.inbox.as_ref().ok_or(Fault::Conflict)?;
        if id != self.id || cursor != inbox.stored.cursor() {
            return Err(Fault::Conflict);
        }
        let stored = inbox.stored.clone();
        let Some(message) = &inbox.message else {
            return Ok(InboxOperation::Received { stored });
        };
        let message = self.open_message(message, &stored);
        Ok(if inbox.complete {
            InboxOperation::Complete { stored, message }
        } else {
            InboxOperation::MessageSaved { stored, message }
        })
    }

    fn outbound_history_message(
        &self,
        id: ConversationId,
        stored: &StoredRelayEnvelope,
    ) -> Result<Option<StoredApplicationMessage>, Fault> {
        let rows = self.step("history")?;
        if id != self.id {
            return Err(Fault::Conflict);
        }
        match (&rows.outbound, &rows.envelope) {
            (Some((_, message)), Some(envelope)) if *envelope == *stored.envelope() => {
                Ok(Some(self.open_message(message, stored)))
            }
            (_, Some(envelope)) if envelope.envelope_id() == stored.envelope().envelope_id() => {
                Err(Fault::Conflict)
            }
            _ => Ok(None),
        }
    }

    fn save_inbox_message(
        &self,
        id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), Fault> {
        let mut rows = self.step("save")?;
        let inbox = rows.inbox.as_mut().ok_or(Fault::Conflict)?;
        if id != self.id || cursor != inbox.stored.cursor() || inbox.message.is_some() {
            return Err(Fault::Conflict);
        }
        inbox.message = Some(self.seal_message(sender, epoch, message));
        if rows.fail == Some("save-after") {
            rows.fail = None;
            return Err(Fault::Injected);
        }
        Ok(())
    }

    fn complete_inbox_with_notification_at(
        &self,
        id: ConversationId,
        cursor: u64,
        notification: NotificationId,
        _: u64,
    ) -> Result<u64, Fault> {
        let mut rows = self.step("complete")?;
        if id != self.id
            || cursor != rows.cursor + 1
            || rows.notifications.iter().any(|(stored_id, stored_cursor)| {
                *stored_id == notification || *stored_cursor == cursor
            })
        {
            return Err(Fault::Conflict);
        }
        if rows.notifications.len() >= LIMIT {
            return Err(Fault::Bound);
        }
        let inbox = rows.inbox.as_mut().ok_or(Fault::Conflict)?;
        if inbox.stored.cursor() != cursor || inbox.message.is_none() {
            return Err(Fault::Conflict);
        }
        inbox.complete = true;
        rows.cursor = cursor;
        rows.notifications.push((notification, cursor));
        Ok(cursor)
    }

    fn load_membership_outbox(&self, id: MembershipOperationId) -> Result<MembershipOutbox, Fault> {
        let rows = self.step("load-membership")?;
        let pending = rows.membership.as_ref().ok_or(Fault::Conflict)?;
        if pending.operation != id {
            return Err(Fault::Conflict);
        }
        Ok(self.open_membership(pending))
    }
    fn complete_membership_outbox(&self, id: MembershipOperationId) -> Result<(), Fault> {
        let mut rows = self.step("complete-membership")?;
        let pending = rows.membership.as_mut().ok_or(Fault::Conflict)?;
        if pending.operation != id || pending.status != MembershipOutboxStatus::Accepted {
            return Err(Fault::Conflict);
        }
        *self.policy.lock().unwrap() = pending.next.clone();
        *self.bindings.lock().unwrap() = pending.bindings.clone();
        pending.status = MembershipOutboxStatus::Applied;
        Ok(())
    }
    fn orphan_membership_outbox(&self, id: MembershipOperationId) -> Result<(), Fault> {
        let mut rows = self.step("orphan-membership")?;
        let pending = rows.membership.as_mut().ok_or(Fault::Conflict)?;
        if pending.operation != id || pending.status != MembershipOutboxStatus::Ready {
            return Err(Fault::Conflict);
        }
        pending.status = MembershipOutboxStatus::Orphaned;
        Ok(())
    }
    fn record_membership_inbox_envelope(
        &self,
        _: &StoredRelayEnvelope,
    ) -> Result<ConversationId, Fault> {
        Err(Fault::Unsupported)
    }
    fn membership_outbox_for_envelope(
        &self,
        _: EnvelopeId,
    ) -> Result<Option<MembershipOutbox>, Fault> {
        Err(Fault::Unsupported)
    }
    fn mark_membership_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<MembershipOperationId, Fault> {
        let mut rows = self.step("accept-membership")?;
        let pending = rows.membership.as_mut().ok_or(Fault::Conflict)?;
        if pending.envelope != *stored.envelope() || pending.status != MembershipOutboxStatus::Ready
        {
            return Err(Fault::Conflict);
        }
        pending.status = MembershipOutboxStatus::Accepted;
        pending.accepted_cursor = Some(stored.cursor());
        Ok(pending.operation)
    }
    fn complete_membership_echo(
        &self,
        _: &StoredRelayEnvelope,
        _: DeviceId,
    ) -> Result<MembershipOperationId, Fault> {
        Err(Fault::Unsupported)
    }
    fn membership_inbox_operation(
        &self,
        _: ConversationId,
        _: u64,
    ) -> Result<MembershipInboxOperation, Fault> {
        Err(Fault::Unsupported)
    }
    fn save_membership_inbox_transition(
        &self,
        _: ConversationId,
        _: u64,
        _: DeviceId,
        _: u64,
        _: MembershipOperationId,
        _: &[u8],
        _: &ConversationState,
        _: &[DeviceCredentialBinding],
    ) -> Result<(), Fault> {
        Err(Fault::Unsupported)
    }
    fn complete_membership_inbox_with_notification(
        &self,
        _: ConversationId,
        _: u64,
        _: NotificationId,
    ) -> Result<u64, Fault> {
        Err(Fault::Unsupported)
    }
    fn store_membership_outbox(
        &self,
        operation: MembershipOperationId,
        id: ConversationId,
        parent: u64,
        envelope: &RelayEnvelope,
        control: &[u8],
        next: &ConversationState,
        bindings: &[DeviceCredentialBinding],
        welcome: Option<&[u8]>,
    ) -> Result<(), Fault> {
        if control.len() > MAX_BYTES
            || bindings.len() > LIMIT
            || welcome.is_some_and(|bytes| bytes.len() > MAX_BYTES)
        {
            return Err(Fault::Bound);
        }
        let mut rows = self.step("store-membership")?;
        if id != self.id
            || envelope.routing_id() != self.route
            || envelope.expected_parent_epoch() != Some(parent)
            || parent.checked_add(1) != Some(next.epoch())
            || next.conversation_id() != id
            || rows.membership.is_some()
        {
            return Err(Fault::Conflict);
        }
        rows.membership = Some(PendingMembership {
            operation,
            parent,
            envelope: envelope.clone(),
            control: self
                .sealer
                .seal(
                    &Self::context(SecretRecordKind::LocalOperation, operation.as_bytes()),
                    control,
                )
                .unwrap(),
            next: self
                .sealer
                .seal(
                    &Self::context(SecretRecordKind::ConversationPolicyState, id.as_bytes()),
                    &encode_conversation_state(next).unwrap(),
                )
                .unwrap(),
            bindings: bindings
                .iter()
                .map(|binding| {
                    self.sealer
                        .seal(
                            &Self::context(
                                SecretRecordKind::ConversationCredentialBinding,
                                id.as_bytes(),
                            ),
                            &encode_device_credential_binding(binding).unwrap(),
                        )
                        .unwrap()
                })
                .collect(),
            welcome: welcome.map(<[u8]>::to_vec),
            status: MembershipOutboxStatus::Ready,
            accepted_cursor: None,
        });
        Ok(())
    }
}

struct Fixture {
    device: Mutex<DeviceIdentity>,
    journal: Journal,
    storage: SealedMlsStorageHandle,
    raw: MemoryMls,
}

impl Fixture {
    fn new() -> Self {
        let device = DeviceIdentity::generate().unwrap();
        let journal = Journal::new(&device);
        let raw = MemoryMls::default();
        let storage = SealedMlsStorage::new(raw.clone(), sealer()).into();
        Self {
            device: Mutex::new(device),
            journal,
            storage,
            raw,
        }
    }

    fn processor(&self) -> NativeConversationProcessor<'_, Journal> {
        NativeConversationProcessor::new(&self.journal, self.storage.clone(), &self.device)
    }

    fn request(&self, value: u8) -> NativeApplicationRequest<()> {
        NativeApplicationRequest {
            conversation_id: self.journal.id,
            message_id: MessageId::from_bytes([value; 16]),
            content: ApplicationContent::text("bounded native message").unwrap(),
            reply_to: None,
            authorization: None,
            sent_at_unix_milliseconds: 1,
            expires_at_unix_seconds: 100,
            policy_operation: false,
        }
    }

    fn joiner(&self) -> (DeviceIdentity, MlsConversationClient, JoinProof) {
        let bob = DeviceIdentity::generate().unwrap();
        let mut client = bob.create_conversation_client(self.journal.id).unwrap();
        let stored = self.journal.load_conversation(self.journal.id).unwrap();
        let binding = stored.bindings.into_iter().next().unwrap();
        client.register_verified_binding(binding).unwrap();
        let alice = self.device.lock().unwrap();
        let invitation = alice
            .issue_invitation(
                self.journal.id,
                self.journal.route,
                bob.device_id(),
                ConversationRole::Member,
                100,
            )
            .unwrap();
        let proof = client
            .create_join_proof(&bob, invitation, alice.public_key(), 1)
            .unwrap();
        (bob, client, proof)
    }

    fn incoming(&self) -> StoredRelayEnvelope {
        let (_bob, client, proof) = self.joiner();
        let prepared = self
            .processor()
            .prepare_add_member(self.journal.id, proof, 1, 100)
            .unwrap();
        let welcome =
            KonclaveCryptographicCore::MlsWelcome::from_bytes(prepared.welcome.as_ref().unwrap())
                .unwrap();
        self.journal
            .mark_membership_outbox_accepted(
                &StoredRelayEnvelope::new(prepared.envelope, 1).unwrap(),
            )
            .unwrap();
        drop(self.processor().open(self.journal.id).unwrap());
        let mut group = client.join_group(&welcome).unwrap();
        let message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([9; 16]),
            1,
            1,
            None,
            ApplicationContent::text("remote native message").unwrap(),
        )
        .unwrap();
        let plaintext = Zeroizing::new(encode_application_message(&message).unwrap());
        let ciphertext = group.encrypt_application_message(&plaintext).unwrap();
        StoredRelayEnvelope::new(
            RelayEnvelope::new(
                ProtocolVersion::application_v1(),
                self.journal.route,
                EnvelopeId::from_bytes([8; 16]),
                DeliveryClass::GroupApplication,
                None,
                100,
                ciphertext.into_bytes(),
            )
            .unwrap(),
            1,
        )
        .unwrap()
    }
}

#[test]
fn open_creates_and_restores_a_real_sealed_non_sqlite_group() {
    let fixture = Fixture::new();
    assert!(
        !fixture
            .storage
            .contains_group(fixture.journal.id.as_bytes())
            .unwrap()
    );
    let opened = fixture.processor().open(fixture.journal.id).unwrap();
    assert_eq!(opened.group.epoch(), 0);
    drop(opened);
    assert!(
        fixture
            .storage
            .contains_group(fixture.journal.id.as_bytes())
            .unwrap()
    );
    assert_eq!(
        fixture
            .processor()
            .open(fixture.journal.id)
            .unwrap()
            .group
            .epoch(),
        0
    );
    let raw = fixture.raw.0.lock().unwrap();
    assert!(raw.groups.values().all(|bytes| bytes.starts_with(b"KSC1")));
}

#[test]
fn send_journals_plaintext_before_exact_envelope_and_recovers_saved_echo() {
    let fixture = Fixture::new();
    let prepared = fixture
        .processor()
        .prepare_application(fixture.request(3))
        .unwrap();
    let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
    fixture.journal.rows.lock().unwrap().fail = Some("complete");
    assert!(matches!(
        fixture
            .processor()
            .process_inbound_application(fixture.journal.id, &stored, 1),
        Err(NativeConversationError::Journal(Fault::Injected))
    ));
    {
        let rows = fixture.journal.rows.lock().unwrap();
        assert_eq!(rows.cursor, 0);
        assert!(rows.notifications.is_empty());
        assert!(rows.inbox.as_ref().unwrap().message.is_some());
        assert!(!rows.inbox.as_ref().unwrap().complete);
        let position = |name| rows.events.iter().position(|event| *event == name).unwrap();
        assert!(position("reserve") < position("outbound-message"));
        assert!(position("outbound-message") < position("outbound-envelope"));
        assert!(position("record") < position("save"));
        assert!(position("save") < position("complete"));
    }
    let recovered = fixture
        .processor()
        .process_inbound_application(fixture.journal.id, &stored, 2)
        .unwrap();
    assert!(recovered.duplicate);
    assert_eq!(recovered.direction, MessageDirection::Outbound);
    assert!(
        encode_application_message(&recovered.message).unwrap()
            == encode_application_message(&prepared.message).unwrap()
    );
    assert_eq!(fixture.journal.rows.lock().unwrap().cursor, 1);
    assert_eq!(fixture.journal.rows.lock().unwrap().notifications.len(), 1);
    let duplicate = fixture
        .processor()
        .process_inbound_application(fixture.journal.id, &stored, 3)
        .unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(fixture.journal.rows.lock().unwrap().cursor, 1);
    assert_eq!(fixture.journal.rows.lock().unwrap().notifications.len(), 1);
}

#[test]
fn failed_send_never_reuses_reserved_counter() {
    for boundary in ["outbound-message", "outbound-envelope"] {
        let fixture = Fixture::new();
        fixture.journal.rows.lock().unwrap().fail = Some(boundary);
        assert!(matches!(
            fixture.processor().prepare_application(fixture.request(3)),
            Err(NativeConversationError::Journal(Fault::Injected))
        ));
        let prepared = fixture
            .processor()
            .prepare_application(fixture.request(4))
            .unwrap();
        let rows = fixture.journal.rows.lock().unwrap();
        assert_eq!(rows.counter, 2);
        assert_eq!(rows.reservations[0].sender_counter, 1);
        assert_eq!(rows.reservations[1].sender_counter, 2);
        assert_eq!(rows.abandoned, vec![rows.reservations[0].envelope_id]);
        assert_eq!(
            prepared.message.message_id(),
            rows.reservations[1].message_id
        );
    }
}

#[test]
fn open_propagates_each_typed_journal_read_error() {
    for boundary in ["load", "membership-outbox", "membership-inbox"] {
        let fixture = Fixture::new();
        fixture.journal.rows.lock().unwrap().fail = Some(boundary);
        assert!(matches!(
            fixture.processor().open(fixture.journal.id),
            Err(NativeConversationError::Journal(Fault::Injected))
        ));
        assert!(
            !fixture
                .storage
                .contains_group(fixture.journal.id.as_bytes())
                .unwrap()
        );
    }
}

#[test]
fn altered_echo_evidence_and_cursor_gaps_cannot_complete() {
    let fixture = Fixture::new();
    let prepared = fixture
        .processor()
        .prepare_application(fixture.request(3))
        .unwrap();
    let envelope = prepared.envelope;
    let gap = StoredRelayEnvelope::new(envelope.clone(), 2).unwrap();
    assert!(matches!(
        fixture
            .processor()
            .process_inbound_application(fixture.journal.id, &gap, 1),
        Err(NativeConversationError::Journal(Fault::Conflict))
    ));
    let altered = RelayEnvelope::new(
        envelope.version(),
        envelope.routing_id(),
        envelope.envelope_id(),
        DeliveryClass::GroupApplication,
        None,
        101,
        envelope.payload().to_vec(),
    )
    .unwrap();
    let altered = StoredRelayEnvelope::new(altered, 1).unwrap();
    assert!(matches!(
        fixture
            .processor()
            .process_inbound_application(fixture.journal.id, &altered, 1),
        Err(NativeConversationError::Journal(Fault::Conflict))
    ));
    assert_eq!(fixture.journal.rows.lock().unwrap().cursor, 0);
}

#[test]
fn poisoned_identity_fails_before_application_reservation() {
    let fixture = Fixture::new();
    let _panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = fixture.device.lock().unwrap();
        panic!("synthetic owner failure");
    }));
    assert!(matches!(
        fixture.processor().prepare_application(fixture.request(3)),
        Err(NativeConversationError::StateUnavailable)
    ));
    assert_eq!(fixture.journal.rows.lock().unwrap().counter, 0);
}

#[test]
fn poisoned_sealed_backend_fails_closed_during_open() {
    let fixture = Fixture::new();
    let _panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = fixture.raw.0.lock().unwrap();
        panic!("synthetic storage failure");
    }));
    assert!(matches!(
        fixture.processor().open(fixture.journal.id),
        Err(NativeConversationError::SecretStorage)
    ));
}

#[test]
fn accepted_membership_recovers_after_mls_persistence_before_policy_completion() {
    let fixture = Fixture::new();
    let (bob, _client, proof) = fixture.joiner();
    let prepared = fixture
        .processor()
        .prepare_add_member(fixture.journal.id, proof, 1, 100)
        .unwrap();
    assert_eq!(
        fixture
            .processor()
            .open(fixture.journal.id)
            .unwrap()
            .group
            .epoch(),
        0
    );
    let stored = StoredRelayEnvelope::new(prepared.envelope, 1).unwrap();
    fixture
        .journal
        .mark_membership_outbox_accepted(&stored)
        .unwrap();
    fixture.journal.rows.lock().unwrap().fail = Some("complete-membership");
    assert!(matches!(
        fixture.processor().open(fixture.journal.id),
        Err(NativeConversationError::Journal(Fault::Injected))
    ));
    assert_eq!(
        fixture
            .journal
            .load_conversation(fixture.journal.id)
            .unwrap()
            .state
            .epoch(),
        0
    );
    let opened = fixture.processor().open(fixture.journal.id).unwrap();
    assert_eq!(opened.group.epoch(), 1);
    assert!(opened.group.state().member(bob.device_id()).is_some());
    assert_eq!(
        fixture
            .journal
            .load_conversation(fixture.journal.id)
            .unwrap()
            .state
            .epoch(),
        1
    );
    assert_eq!(
        fixture
            .journal
            .load_membership_outbox(prepared.operation_id)
            .unwrap()
            .status,
        MembershipOutboxStatus::Applied
    );
}

#[test]
fn membership_journal_failure_rejects_pending_mls_commit_before_returning() {
    let fixture = Fixture::new();
    let (_bob, _client, proof) = fixture.joiner();
    fixture.journal.rows.lock().unwrap().fail = Some("store-membership");
    assert!(matches!(
        fixture
            .processor()
            .prepare_add_member(fixture.journal.id, proof, 1, 100),
        Err(NativeConversationError::Journal(Fault::Injected))
    ));
    let opened = fixture.processor().open(fixture.journal.id).unwrap();
    assert_eq!(opened.group.epoch(), 0);
    assert!(!opened.group.has_pending_membership_commit());
}

#[test]
fn membership_parent_mismatch_is_not_recovered_as_success() {
    let fixture = Fixture::new();
    let (_bob, _client, proof) = fixture.joiner();
    fixture
        .processor()
        .prepare_add_member(fixture.journal.id, proof, 1, 100)
        .unwrap();
    fixture
        .journal
        .rows
        .lock()
        .unwrap()
        .membership
        .as_mut()
        .unwrap()
        .parent = 1;
    assert!(matches!(
        fixture.processor().open(fixture.journal.id),
        Err(NativeConversationError::StateMismatch)
    ));
}

#[test]
fn saved_remote_message_recovers_both_receiver_ratchet_windows() {
    for boundary in ["save-after", "complete"] {
        let fixture = Fixture::new();
        let stored = fixture.incoming();
        fixture.journal.rows.lock().unwrap().fail = Some(boundary);
        assert!(matches!(
            fixture
                .processor()
                .process_inbound_application(fixture.journal.id, &stored, 1),
            Err(NativeConversationError::Journal(Fault::Injected))
        ));
        assert_eq!(fixture.journal.rows.lock().unwrap().cursor, 0);
        let recovered = fixture
            .processor()
            .process_inbound_application(fixture.journal.id, &stored, 2)
            .unwrap();
        assert!(recovered.duplicate);
        assert_eq!(recovered.direction, MessageDirection::Inbound);
        assert_eq!(
            recovered.message.message_id(),
            MessageId::from_bytes([9; 16])
        );
        assert_eq!(fixture.journal.rows.lock().unwrap().cursor, 1);
    }
}

#[test]
fn authenticated_but_wrong_saved_remote_evidence_is_rejected_before_completion() {
    for wrong_epoch in [false, true] {
        let fixture = Fixture::new();
        let stored = fixture.incoming();
        fixture.journal.rows.lock().unwrap().fail = Some("save-after");
        assert!(matches!(
            fixture
                .processor()
                .process_inbound_application(fixture.journal.id, &stored, 1),
            Err(NativeConversationError::Journal(Fault::Injected))
        ));
        {
            let mut rows = fixture.journal.rows.lock().unwrap();
            let saved = rows.inbox.as_mut().unwrap().message.as_mut().unwrap();
            if wrong_epoch {
                let original = fixture.journal.open_message(saved, &stored);
                *saved =
                    fixture
                        .journal
                        .seal_message(saved.sender, saved.epoch + 1, &original.message);
            } else {
                let wrong = ApplicationMessage::new(
                    ProtocolVersion::application_v1(),
                    saved.id,
                    1,
                    1,
                    None,
                    ApplicationContent::text("different authenticated checkpoint").unwrap(),
                )
                .unwrap();
                *saved = fixture
                    .journal
                    .seal_message(saved.sender, saved.epoch, &wrong);
            }
        }
        assert!(matches!(
            fixture
                .processor()
                .process_inbound_application(fixture.journal.id, &stored, 2),
            Err(NativeConversationError::StateMismatch)
        ));
        assert_eq!(fixture.journal.rows.lock().unwrap().cursor, 0);
    }
}

#[test]
fn ready_membership_without_pending_mls_state_is_orphaned_not_applied() {
    let fixture = Fixture::new();
    let (_bob, _client, proof) = fixture.joiner();
    let prepared = fixture
        .processor()
        .prepare_add_member(fixture.journal.id, proof, 1, 100)
        .unwrap();
    let mut opened = fixture.processor().open(fixture.journal.id).unwrap();
    opened.group.reject_pending_commit().unwrap();
    drop(opened);
    let recovered = fixture.processor().open(fixture.journal.id).unwrap();
    assert_eq!(recovered.group.epoch(), 0);
    assert!(!recovered.group.has_pending_membership_commit());
    assert_eq!(
        fixture
            .journal
            .load_membership_outbox(prepared.operation_id)
            .unwrap()
            .status,
        MembershipOutboxStatus::Orphaned
    );
}

#[test]
fn advanced_policy_without_mls_state_fails_instead_of_creating_a_new_group() {
    let fixture = Fixture::new();
    let _stored = fixture.incoming();
    let empty: SealedMlsStorageHandle =
        SealedMlsStorage::new(MemoryMls::default(), sealer()).into();
    let mut processor =
        NativeConversationProcessor::new(&fixture.journal, empty.clone(), &fixture.device);
    assert!(matches!(
        processor.open(fixture.journal.id),
        Err(NativeConversationError::MissingMlsState)
    ));
    assert!(!empty.contains_group(fixture.journal.id.as_bytes()).unwrap());
}

#[test]
fn failed_admission_cannot_consume_counter_or_create_mls_state() {
    let fixture = Fixture::new();
    fixture.journal.rows.lock().unwrap().fail = Some("reserve");
    assert!(matches!(
        fixture.processor().prepare_application(fixture.request(3)),
        Err(NativeConversationError::Journal(Fault::Injected))
    ));
    let rows = fixture.journal.rows.lock().unwrap();
    assert_eq!(rows.counter, 0);
    assert!(rows.reservations.is_empty());
    assert!(!rows.events.contains(&"abandon"));
    assert!(
        !fixture
            .storage
            .contains_group(fixture.journal.id.as_bytes())
            .unwrap()
    );
}

#[test]
fn pending_mls_commit_without_exact_membership_journal_fails_closed() {
    let fixture = Fixture::new();
    let (_bob, _client, proof) = fixture.joiner();
    fixture
        .processor()
        .prepare_add_member(fixture.journal.id, proof, 1, 100)
        .unwrap();
    {
        let mut rows = fixture.journal.rows.lock().unwrap();
        let pending = rows.membership.take().unwrap();
        *fixture.journal.bindings.lock().unwrap() = pending.bindings;
    }
    assert!(matches!(
        fixture.processor().open(fixture.journal.id),
        Err(NativeConversationError::MissingMembershipJournal)
    ));
}
