#[path = "../examples/native_service/authority.rs"]
#[allow(dead_code)]
mod authority;
#[path = "../examples/native_service/journal.rs"]
#[allow(dead_code)]
mod journal;
#[path = "../examples/native_service/storage.rs"]
#[allow(dead_code)]
mod storage;

use std::sync::{Arc, Barrier};
use std::thread;

use KonclaveClientLibrary::native::*;
use KonclaveClientLibrary::{RelayAccessCredential, RelayEndpoint};
use KonclaveCryptographicCore::{DeviceIdentity, verify_device_credential_binding};
use KonclaveDomainCore::*;
use KonclaveProtocolContracts::v1::encode_application_message;
use KonclaveSecretStorage::{
    ExternalWrappingKeyProvider, SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer,
};
use authority::{AuthorityError, ServiceAuthorization};
use journal::{JournalError, ServiceJournal};
use storage::{ServiceStorage, SnapshotKind, StorageError};

const NAMESPACE: &[u8] = b"synthetic-native-journal";
const MARKER: &str = "synthetic-immutable-content-not-for-ordinary-storage";

fn sealer(key: u8) -> SecretSealer {
    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([key; 32])).unwrap()
}

struct Fixture {
    owner: ServiceStorage,
    journal: ServiceJournal,
    local: DeviceIdentity,
    peer: DeviceIdentity,
    id: ConversationId,
    route: RoutingId,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix(".native-journal-test-")
            .tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"))
            .unwrap();
        let owner = ServiceStorage::open(directory.path()).unwrap();
        let local = DeviceIdentity::generate().unwrap();
        let peer = DeviceIdentity::generate().unwrap();
        let id = local.generate_conversation_id().unwrap();
        let route = local.generate_routing_id().unwrap();
        let journal = ServiceJournal::provision(
            owner.clone(),
            sealer(7),
            NAMESPACE,
            &local,
            Self::conversation(&local, &peer, id, route),
            &RelayEndpoint::parse("https://relay.example.com").unwrap(),
            &RelayAccessCredential::from_bytes([117; 32]),
        )
        .unwrap();
        Self {
            directory,
            owner,
            journal,
            local,
            peer,
            id,
            route,
        }
    }

    fn conversation(
        local: &DeviceIdentity,
        peer: &DeviceIdentity,
        id: ConversationId,
        route: RoutingId,
    ) -> StoredConversation {
        let signing_material = local.create_conversation_signing_material(id).unwrap();
        let remote = peer.create_conversation_signing_material(id).unwrap();
        let bindings = vec![
            verify_device_credential_binding(signing_material.binding()).unwrap(),
            verify_device_credential_binding(remote.binding()).unwrap(),
        ];
        StoredConversation {
            routing_id: route,
            signing_material,
            state: ConversationState::new(
                ProtocolVersion::application_v1(),
                id,
                0,
                vec![
                    Member::new(local.device_id(), ConversationRole::Administrator, 0),
                    Member::new(peer.device_id(), ConversationRole::Member, 0),
                ],
                vec![],
            )
            .unwrap(),
            bindings,
            sender_counter: 0,
            replay_cursor: 0,
        }
    }

    fn request(&self, value: u8) -> NativeApplicationRequest<ServiceAuthorization> {
        NativeApplicationRequest {
            conversation_id: self.id,
            message_id: MessageId::from_bytes([value; 16]),
            content: ApplicationContent::directed_request(self.peer.device_id(), MARKER).unwrap(),
            reply_to: None,
            authorization: Some(self.journal.authorization().unwrap()),
            sent_at_unix_milliseconds: 12,
            expires_at_unix_seconds: 100,
            policy_operation: false,
        }
    }

    fn envelope(&self, value: u8, payload: u8, cursor: u64) -> StoredRelayEnvelope {
        StoredRelayEnvelope::new(
            RelayEnvelope::new(
                ProtocolVersion::application_v1(),
                self.route,
                EnvelopeId::from_bytes([value; 16]),
                DeliveryClass::GroupApplication,
                None,
                100,
                vec![payload; 32],
            )
            .unwrap(),
            cursor,
        )
        .unwrap()
    }

    fn received(&self, value: u8, counter: u64) -> ApplicationMessage {
        ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([value; 16]),
            counter,
            12,
            None,
            ApplicationContent::directed_request(self.local.device_id(), MARKER).unwrap(),
        )
        .unwrap()
    }

    fn complete_request(&self) -> MessageId {
        let stored = self.envelope(61, 71, 1);
        let message = self.received(81, 1);
        self.journal.record_inbox_envelope(&stored).unwrap();
        self.journal
            .save_inbox_message(self.id, 1, self.peer.device_id(), 0, &message)
            .unwrap();
        self.journal
            .complete_inbox_with_notification_at(
                self.id,
                1,
                NotificationId::from_bytes([91; 16]),
                20,
            )
            .unwrap();
        message.message_id()
    }
}

#[test]
fn provision_reopen_retains_keys_and_sealed_intent_and_rejects_wrong_scope() {
    let fixture = Fixture::new();
    let request = fixture.request(1);
    let envelope = EnvelopeId::from_bytes([11; 16]);
    let reservation = fixture
        .journal
        .reserve_application(&request, envelope)
        .unwrap();
    let before = fixture.journal.load_conversation(fixture.id).unwrap();
    let signing = before.signing_material.binding().clone();
    let ordinary = fixture
        .owner
        .read_slot(SnapshotKind::Journal)
        .unwrap()
        .unwrap();
    assert!(
        !ordinary
            .windows(MARKER.len())
            .any(|bytes| bytes == MARKER.as_bytes())
    );
    assert!(
        !ordinary
            .windows(fixture.local.public_key().as_bytes().len())
            .any(|bytes| bytes == fixture.local.public_key().as_bytes())
    );
    assert!(matches!(
        ServiceJournal::provision(
            fixture.owner.clone(),
            sealer(7),
            NAMESPACE,
            &fixture.local,
            Fixture::conversation(&fixture.local, &fixture.peer, fixture.id, fixture.route),
            &RelayEndpoint::parse("https://relay.example.com").unwrap(),
            &RelayAccessCredential::from_bytes([117; 32]),
        ),
        Err(JournalError::Provisioned)
    ));
    for (key, namespace) in [(8, NAMESPACE), (7, b"wrong-namespace".as_slice())] {
        assert!(
            ServiceJournal::reopen(
                fixture.owner.clone(),
                sealer(key),
                namespace,
                fixture.id,
                fixture.local.device_id(),
            )
            .is_err()
        );
    }
    assert!(matches!(
        fixture
            .journal
            .load_conversation(ConversationId::from_bytes([99; 32])),
        Err(JournalError::Scope)
    ));
    fixture.owner.release().unwrap();
    assert_eq!(
        fixture.journal.set_enabled(false),
        Err(JournalError::Storage(StorageError::Released))
    );
    let owner = ServiceStorage::open(fixture.directory.path()).unwrap();
    let reopened = ServiceJournal::reopen(
        owner.clone(),
        sealer(7),
        NAMESPACE,
        fixture.id,
        fixture.local.device_id(),
    )
    .unwrap();
    assert_eq!(
        reopened.identity().unwrap().device_id(),
        fixture.local.device_id()
    );
    assert_eq!(reopened.mls_namespace().unwrap(), NAMESPACE);
    let (endpoint, credential) = reopened.relay_access().unwrap();
    assert_eq!(
        endpoint.as_str(),
        RelayEndpoint::parse("https://relay.example.com")
            .unwrap()
            .as_str()
    );
    assert_eq!(
        credential.principal_id(),
        RelayAccessCredential::from_bytes([117; 32]).principal_id()
    );
    assert_eq!(
        reopened
            .load_conversation(fixture.id)
            .unwrap()
            .signing_material
            .binding(),
        &signing
    );
    assert_eq!(
        reopened.reserve_application(&request, envelope).unwrap(),
        reservation
    );
    let intent = reopened.outbound_intent(reservation).unwrap();
    assert_eq!(intent.message.sent_at_unix_milliseconds(), 12);
    assert!(
        matches!(intent.message.content(), ApplicationContent::DirectedRequest(request) if request.body() == MARKER)
    );
    assert!(intent.envelope.is_none());
    assert_eq!(reopened.unready_outbox().unwrap().len(), 1);
    assert_eq!(reopened.retained_outbox().unwrap().len(), 1);
    let mut generation =
        std::fs::read(fixture.directory.path().join("native-service.generation")).unwrap();
    let mut value = [0; 8];
    value.copy_from_slice(&generation[8..]);
    generation[8..].copy_from_slice(&(u64::from_be_bytes(value) + 1).to_be_bytes());
    std::fs::write(
        fixture.directory.path().join("native-service.generation"),
        generation,
    )
    .unwrap();
    assert_eq!(
        reopened.set_enabled(false),
        Err(JournalError::Storage(StorageError::Released))
    );
}

#[test]
fn reservation_is_immutable_before_ciphertext_and_revocation_wins_new_admission() {
    let fixture = Fixture::new();
    let request = fixture.request(1);
    let envelope_id = EnvelopeId::from_bytes([11; 16]);
    let reservation = fixture
        .journal
        .reserve_application(&request, envelope_id)
        .unwrap();
    let mut changed = fixture.request(1);
    changed.sent_at_unix_milliseconds += 1;
    assert_eq!(
        fixture.journal.reserve_application(&changed, envelope_id),
        Err(JournalError::Conflict)
    );
    changed.sent_at_unix_milliseconds -= 1;
    changed.expires_at_unix_seconds += 1;
    assert_eq!(
        fixture.journal.reserve_application(&changed, envelope_id),
        Err(JournalError::Conflict)
    );
    let message = fixture
        .journal
        .outbound_intent(reservation)
        .unwrap()
        .message;
    assert_eq!(
        fixture.journal.store_outbound_message(
            reservation,
            fixture.route,
            fixture.peer.device_id(),
            0,
            &message
        ),
        Err(JournalError::Scope)
    );
    fixture
        .journal
        .store_outbound_message(
            reservation,
            fixture.route,
            fixture.local.device_id(),
            0,
            &message,
        )
        .unwrap();
    let stored = fixture.envelope(11, 33, 1);
    fixture
        .journal
        .store_outbound_envelope(reservation, stored.envelope())
        .unwrap();
    assert_eq!(
        fixture
            .journal
            .store_outbound_envelope(reservation, fixture.envelope(11, 34, 1).envelope()),
        Err(JournalError::Conflict)
    );
    assert_eq!(fixture.journal.ready_outbox().unwrap().len(), 1);
    assert!(fixture.journal.unready_outbox().unwrap().is_empty());
    fixture.journal.accept_outbound(&stored).unwrap();
    assert!(fixture.journal.ready_outbox().unwrap().is_empty());
    assert!(
        fixture
            .journal
            .outbound_history_message(fixture.id, &stored)
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .journal
            .outbound_history_message(fixture.id, &fixture.envelope(11, 34, 1))
            .unwrap()
            .is_none()
    );
    let fresh = fixture.request(2);
    fixture.journal.set_enabled(false).unwrap();
    assert_eq!(
        fixture
            .journal
            .reserve_application(&fresh, EnvelopeId::from_bytes([12; 16])),
        Err(JournalError::Authority(AuthorityError::Denied))
    );
    assert_eq!(
        fixture
            .journal
            .reserve_application(&request, envelope_id)
            .unwrap(),
        reservation
    );
    assert_eq!(
        fixture
            .journal
            .load_conversation(fixture.id)
            .unwrap()
            .sender_counter,
        1
    );
    assert_eq!(
        fixture.journal.expire_outbound(reservation, 100).unwrap(),
        NativeExpiryOutcome::Accepted { cursor: 1 }
    );
    assert!(
        !fixture
            .journal
            .outbound_intent(reservation)
            .unwrap()
            .expired
    );
}

#[test]
fn cloned_handles_race_one_completed_claim_and_retain_exact_committed_response() {
    let fixture = Fixture::new();
    let request_id = fixture.complete_request();
    let claim_barrier = Arc::new(Barrier::new(3));
    let mut claim_threads = Vec::new();
    for _ in 0..2 {
        let journal = fixture.journal.clone();
        let barrier = claim_barrier.clone();
        claim_threads.push(thread::spawn(move || {
            barrier.wait();
            journal.claim(request_id)
        }));
    }
    claim_barrier.wait();
    let claims: Vec<_> = claim_threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(claims.iter().filter(|result| result.is_ok()).count(), 1);
    let authorization = claims.into_iter().find_map(Result::ok).unwrap();
    assert!(fixture.journal.claim(request_id).is_err());
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for value in [2, 3] {
        let journal = fixture.journal.clone();
        let barrier = barrier.clone();
        let id = fixture.id;
        threads.push(thread::spawn(move || {
            let request = NativeApplicationRequest {
                conversation_id: id,
                message_id: MessageId::from_bytes([value; 16]),
                content: ApplicationContent::text(MARKER).unwrap(),
                reply_to: Some(request_id),
                authorization: Some(authorization),
                sent_at_unix_milliseconds: u64::from(value),
                expires_at_unix_seconds: 100,
                policy_operation: false,
            };
            barrier.wait();
            journal.reserve_application(&request, EnvelopeId::from_bytes([value + 10; 16]))
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(JournalError::Authority(AuthorityError::Claim))))
            .count(),
        1
    );
    let reservation = results.into_iter().find_map(Result::ok).unwrap();
    let original = fixture.journal.outbound_intent(reservation).unwrap();
    assert_eq!(original.message.reply_to(), Some(request_id));
    assert_eq!(original.reservation.sender_counter, 1);
    fixture
        .journal
        .abandon_outbound_application(reservation)
        .unwrap();
    fixture.journal.set_enabled(false).unwrap();
    let request = NativeApplicationRequest {
        conversation_id: fixture.id,
        message_id: reservation.message_id,
        content: ApplicationContent::text(MARKER).unwrap(),
        reply_to: Some(request_id),
        authorization: None,
        sent_at_unix_milliseconds: original.message.sent_at_unix_milliseconds(),
        expires_at_unix_seconds: 100,
        policy_operation: false,
    };
    assert_eq!(
        fixture
            .journal
            .reserve_application(&request, reservation.envelope_id)
            .unwrap(),
        reservation
    );
    assert!(
        fixture
            .journal
            .outbound_intent(reservation)
            .unwrap()
            .abandoned
    );
    assert_eq!(fixture.journal.retained_outbox().unwrap().len(), 1);
}

#[test]
fn inbox_checkpoints_reject_gaps_replay_and_changed_notification_evidence() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .journal
            .record_inbox_envelope(&fixture.envelope(1, 21, 2)),
        Err(JournalError::Conflict)
    );
    let stored = fixture.envelope(1, 21, 1);
    fixture.journal.record_inbox_envelope(&stored).unwrap();
    assert!(matches!(
        fixture.journal.inbox_operation(fixture.id, 1).unwrap(),
        InboxOperation::Received { .. }
    ));
    assert!(
        fixture
            .journal
            .claim(MessageId::from_bytes([31; 16]))
            .is_err()
    );
    let notification = NotificationId::from_bytes([41; 16]);
    assert_eq!(
        fixture
            .journal
            .complete_inbox_with_notification_at(fixture.id, 1, notification, 5),
        Err(JournalError::Conflict)
    );
    let message = fixture.received(31, 1);
    fixture
        .journal
        .save_inbox_message(fixture.id, 1, fixture.peer.device_id(), 0, &message)
        .unwrap();
    assert!(matches!(
        fixture.journal.inbox_operation(fixture.id, 1).unwrap(),
        InboxOperation::MessageSaved { .. }
    ));
    fixture
        .journal
        .save_inbox_message(fixture.id, 1, fixture.peer.device_id(), 0, &message)
        .unwrap();
    assert_eq!(
        fixture
            .journal
            .complete_inbox_with_notification_at(fixture.id, 1, notification, 5)
            .unwrap(),
        1
    );
    assert_eq!(
        fixture
            .journal
            .complete_inbox_with_notification_at(fixture.id, 1, notification, 6),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        fixture
            .journal
            .notification_evidence(fixture.id, 1)
            .unwrap(),
        Some((notification, 5))
    );
    fixture.journal.record_inbox_envelope(&stored).unwrap();
    assert_eq!(
        fixture
            .journal
            .record_inbox_envelope(&fixture.envelope(2, 21, 2)),
        Err(JournalError::Conflict)
    );
    fixture
        .journal
        .record_inbox_envelope(&fixture.envelope(2, 22, 2))
        .unwrap();
    let replay = fixture.received(32, 1);
    assert_eq!(
        fixture
            .journal
            .save_inbox_message(fixture.id, 2, fixture.peer.device_id(), 0, &replay),
        Err(JournalError::Conflict)
    );
    let response = ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        MessageId::from_bytes([32; 16]),
        2,
        12,
        Some(MessageId::from_bytes([99; 16])),
        ApplicationContent::text("unmatched response").unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .journal
            .save_inbox_message(fixture.id, 2, fixture.peer.device_id(), 0, &response),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        fixture.journal.save_inbox_message(
            fixture.id,
            2,
            fixture.peer.device_id(),
            1,
            &fixture.received(32, 2)
        ),
        Err(JournalError::Scope)
    );
    assert!(
        fixture
            .journal
            .active_membership_inbox(fixture.id)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        fixture
            .journal
            .active_membership_inbox(ConversationId::from_bytes([99; 32])),
        Err(JournalError::Scope)
    ));
    fixture.owner.release().unwrap();
    assert!(matches!(
        fixture.journal.active_membership_inbox(fixture.id),
        Err(JournalError::Storage(StorageError::Released))
    ));
}

#[test]
fn ciphertext_tampering_is_not_absence_and_failed_write_does_not_replace_snapshot() {
    let fixture = Fixture::new();
    let request = fixture.request(1);
    let reservation = fixture
        .journal
        .reserve_application(&request, EnvelopeId::from_bytes([11; 16]))
        .unwrap();
    let before = fixture
        .owner
        .read_slot(SnapshotKind::Journal)
        .unwrap()
        .unwrap();
    let changed = ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        reservation.message_id,
        reservation.sender_counter,
        999,
        None,
        ApplicationContent::text(MARKER).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture.journal.store_outbound_message(
            reservation,
            fixture.route,
            fixture.local.device_id(),
            0,
            &changed
        ),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        fixture
            .owner
            .read_slot(SnapshotKind::Journal)
            .unwrap()
            .unwrap(),
        before
    );
    let clear = encode_application_message(&changed).unwrap();
    assert!(!before.windows(clear.len()).any(|bytes| bytes == clear));
    let mut corrupt = before;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fixture
        .owner
        .replace_slot(SnapshotKind::Journal, &corrupt)
        .unwrap();
    assert!(matches!(
        fixture.journal.load_conversation(fixture.id),
        Err(JournalError::Protection)
    ));
    assert!(matches!(
        fixture.journal.active_membership_outbox(fixture.id),
        Err(JournalError::Protection)
    ));
}

#[test]
fn response_requires_an_exact_accepted_directed_request_and_echo_uses_saved_metadata() {
    let fixture = Fixture::new();
    let request = fixture.request(1);
    let reservation = fixture
        .journal
        .reserve_application(&request, EnvelopeId::from_bytes([11; 16]))
        .unwrap();
    let intent = fixture.journal.outbound_intent(reservation).unwrap();
    fixture
        .journal
        .store_outbound_message(
            reservation,
            fixture.route,
            fixture.local.device_id(),
            intent.epoch,
            &intent.message,
        )
        .unwrap();
    let outbound = fixture.envelope(11, 51, 1);
    fixture
        .journal
        .store_outbound_envelope(reservation, outbound.envelope())
        .unwrap();
    fixture.journal.record_inbox_envelope(&outbound).unwrap();
    fixture
        .journal
        .save_inbox_message(fixture.id, 1, fixture.local.device_id(), 0, &intent.message)
        .unwrap();
    fixture
        .journal
        .complete_inbox_with_notification_at(fixture.id, 1, NotificationId::from_bytes([61; 16]), 1)
        .unwrap();
    let received = fixture.envelope(12, 52, 2);
    fixture.journal.record_inbox_envelope(&received).unwrap();
    let answer = ApplicationMessage::new(
        ProtocolVersion::application_v1(),
        MessageId::from_bytes([2; 16]),
        1,
        21,
        Some(request.message_id),
        ApplicationContent::text(MARKER).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .journal
            .save_inbox_message(fixture.id, 2, fixture.peer.device_id(), 0, &answer),
        Err(JournalError::Conflict)
    );
    fixture.journal.accept_outbound(&outbound).unwrap();
    fixture
        .journal
        .save_inbox_message(fixture.id, 2, fixture.peer.device_id(), 0, &answer)
        .unwrap();
    fixture
        .journal
        .complete_inbox_with_notification_at(fixture.id, 2, NotificationId::from_bytes([62; 16]), 2)
        .unwrap();
    assert_eq!(
        fixture
            .journal
            .load_conversation(fixture.id)
            .unwrap()
            .replay_cursor,
        2
    );
    assert_eq!(
        fixture
            .journal
            .record_inbox_envelope(&fixture.envelope(11, 51, 3)),
        Err(JournalError::Conflict)
    );
}

#[test]
fn authenticated_codec_rejects_unknown_versions_trailing_bytes_and_oversized_counts() {
    let fixture = Fixture::new();
    let sealed = fixture
        .owner
        .read_slot(SnapshotKind::Journal)
        .unwrap()
        .unwrap();
    let context = SecretRecordContext::derive(
        SecretRecordKind::LocalOperation,
        &[
            b"native-service-journal-v1",
            NAMESPACE,
            fixture.id.as_bytes(),
            fixture.local.device_id().as_bytes(),
        ],
    )
    .unwrap();
    let protection = sealer(7);
    let blob = SealedBlob::from_bytes(sealed).unwrap();
    let original = protection.open(&context, &blob).unwrap();
    let mut count_offset = 8;
    for _ in 0..5 {
        let length =
            u64::from_be_bytes(original[count_offset..count_offset + 8].try_into().unwrap())
                as usize;
        count_offset += 8 + length;
    }
    for case in 0..3 {
        let mut malformed = original.clone();
        match case {
            0 => malformed[7] = b'2',
            1 => malformed.push(0),
            _ => malformed[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes()),
        }
        let blob = protection.seal(&context, &malformed).unwrap();
        fixture
            .owner
            .replace_slot(SnapshotKind::Journal, blob.as_bytes())
            .unwrap();
        assert!(fixture.journal.load_conversation(fixture.id).is_err());
    }
}

#[test]
fn retained_capacity_never_recycles_abandoned_counters_or_identifiers() {
    let fixture = Fixture::new();
    for value in 1..=32_u8 {
        let request = fixture.request(value);
        let reservation = fixture
            .journal
            .reserve_application(&request, EnvelopeId::from_bytes([value + 32; 16]))
            .unwrap();
        assert_eq!(reservation.sender_counter, u64::from(value));
        fixture
            .journal
            .abandon_outbound_application(reservation)
            .unwrap();
    }

    assert_eq!(
        fixture
            .journal
            .reserve_application(&fixture.request(33), EnvelopeId::from_bytes([65; 16])),
        Err(JournalError::Capacity)
    );
    assert_eq!(fixture.journal.retained_outbox().unwrap().len(), 32);
    let unready = fixture.journal.unready_outbox().unwrap();
    assert_eq!(unready.len(), 32);
    for (index, intent) in unready.iter().enumerate() {
        assert_eq!(intent.reservation.sender_counter, index as u64 + 1);
        assert!(intent.envelope.is_none());
        assert!(intent.abandoned);
    }
    assert_eq!(
        fixture
            .journal
            .load_conversation(fixture.id)
            .unwrap()
            .sender_counter,
        32
    );
    assert_eq!(
        fixture
            .journal
            .reserve_application(&fixture.request(1), EnvelopeId::from_bytes([33; 16]))
            .unwrap()
            .sender_counter,
        1
    );
}

#[test]
fn committed_expiry_is_terminal_but_never_rewrites_prior_acceptance() {
    let fixture = Fixture::new();
    let reservation = fixture
        .journal
        .reserve_application(&fixture.request(1), EnvelopeId::from_bytes([11; 16]))
        .unwrap();
    let intent = fixture.journal.outbound_intent(reservation).unwrap();
    fixture
        .journal
        .store_outbound_message(
            reservation,
            fixture.route,
            fixture.local.device_id(),
            intent.epoch,
            &intent.message,
        )
        .unwrap();
    let stored = fixture.envelope(11, 51, 1);
    fixture
        .journal
        .store_outbound_envelope(reservation, stored.envelope())
        .unwrap();
    assert_eq!(
        fixture.journal.expire_outbound(reservation, 99),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        fixture.journal.expire_outbound(reservation, 100).unwrap(),
        NativeExpiryOutcome::Expired
    );
    assert_eq!(
        fixture.journal.accept_outbound(&stored),
        Err(JournalError::Conflict)
    );
    assert!(fixture.journal.ready_outbox().unwrap().is_empty());
    assert!(
        fixture
            .journal
            .outbound_intent(reservation)
            .unwrap()
            .expired
    );
}

#[test]
fn actual_retained_inbox_and_claim_capacity_fail_closed() {
    for claim_messages in [false, true] {
        let fixture = Fixture::new();
        let maximum = if claim_messages {
            authority::MAX_CLAIMS
        } else {
            32
        };
        for value in 1..=maximum + 1 {
            let stored = fixture.envelope(value as u8 + 64, value as u8 + 96, value as u64);
            let result = fixture.journal.record_inbox_envelope(&stored);
            if value > maximum && !claim_messages {
                assert_eq!(result, Err(JournalError::Capacity));
                break;
            }
            result.unwrap();
            let message = fixture.received(value as u8, value as u64);
            fixture
                .journal
                .save_inbox_message(
                    fixture.id,
                    value as u64,
                    fixture.peer.device_id(),
                    0,
                    &message,
                )
                .unwrap();
            fixture
                .journal
                .complete_inbox_with_notification_at(
                    fixture.id,
                    value as u64,
                    NotificationId::from_bytes([value as u8 + 128; 16]),
                    1,
                )
                .unwrap();
            if claim_messages {
                let result = fixture.journal.claim(message.message_id());
                if value > maximum {
                    assert!(matches!(
                        result,
                        Err(JournalError::Authority(AuthorityError::Capacity))
                    ));
                } else {
                    result.unwrap();
                }
            }
        }
        let expected_cursor = if claim_messages { maximum + 1 } else { maximum };
        assert_eq!(
            fixture
                .journal
                .load_conversation(fixture.id)
                .unwrap()
                .replay_cursor,
            expected_cursor as u64
        );
    }
}

#[test]
fn live_claim_reopen_preserves_identity_without_bypassing_reservation_authority() {
    let fixture = Fixture::new();
    let request = fixture.complete_request();
    assert!(fixture.journal.pending_claim(request).unwrap().is_none());
    let original = fixture.journal.claim(request).unwrap();
    fixture.owner.release().unwrap();
    assert!(matches!(
        fixture.journal.pending_claim(request),
        Err(JournalError::Storage(StorageError::Released))
    ));
    let owner = ServiceStorage::open(fixture.directory.path()).unwrap();
    let reopened = ServiceJournal::reopen(
        owner.clone(),
        sealer(7),
        NAMESPACE,
        fixture.id,
        fixture.local.device_id(),
    )
    .unwrap();
    let before = owner.read_slot(SnapshotKind::Journal).unwrap().unwrap();
    let recovered = reopened.pending_claim(request).unwrap().unwrap();
    assert_eq!(recovered.claim, original.claim);
    assert_eq!(recovered.revision, original.revision);
    assert_eq!(
        owner.read_slot(SnapshotKind::Journal).unwrap().unwrap(),
        before
    );
    let mut response = NativeApplicationRequest {
        conversation_id: fixture.id,
        message_id: MessageId::from_bytes([1; 16]),
        content: ApplicationContent::text(MARKER).unwrap(),
        reply_to: Some(request),
        authorization: Some(recovered),
        sent_at_unix_milliseconds: 12,
        expires_at_unix_seconds: 100,
        policy_operation: false,
    };
    let envelope = EnvelopeId::from_bytes([11; 16]);
    reopened.set_enabled(false).unwrap();
    response.authorization = reopened.pending_claim(request).unwrap();
    assert_eq!(
        reopened.reserve_application(&response, envelope),
        Err(JournalError::Authority(AuthorityError::Denied))
    );
    reopened.set_enabled(true).unwrap();
    assert_eq!(
        reopened.reserve_application(&response, envelope),
        Err(JournalError::Authority(AuthorityError::Denied))
    );
    response.authorization = reopened.pending_claim(request).unwrap();
    assert_eq!(response.authorization.unwrap().claim, original.claim);
    reopened.reserve_application(&response, envelope).unwrap();
    assert!(reopened.pending_claim(request).unwrap().is_none());
    response.message_id = MessageId::from_bytes([2; 16]);
    assert_eq!(
        reopened.reserve_application(&response, EnvelopeId::from_bytes([12; 16])),
        Err(JournalError::Authority(AuthorityError::Claim))
    );
}
