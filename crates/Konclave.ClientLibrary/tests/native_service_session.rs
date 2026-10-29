//! Real sealed non-SQLite native endpoints with an injected opaque relay fixture.
//! The transport fixture does not establish HTTP, relay authentication or watch behavior.

#[path = "../examples/native_service/authority.rs"]
#[allow(dead_code)]
mod authority;
#[path = "../examples/native_service/host.rs"]
mod host;
#[path = "../examples/native_service/journal.rs"]
#[allow(dead_code)]
mod journal;
#[path = "../examples/native_service/mls.rs"]
#[allow(dead_code)]
mod mls;
#[path = "../examples/native_service/storage.rs"]
#[allow(dead_code)]
mod storage;

use std::process::Command;
use std::sync::{Arc, Mutex};

use KonclaveClientLibrary::native::*;
use KonclaveClientLibrary::{
    KonclaveClientError, RelayAccessCredential, RelayEndpoint, RelayTransport, RelayWatchSession,
};
use KonclaveCryptographicCore::{
    ConversationSigningMaterial, DeviceIdentity, MlsConversationClient, MlsWelcome,
    verify_device_credential_binding,
};
use KonclaveDomainCore::*;
use KonclaveProtocolContracts::v1::encode_conversation_state;
use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SealedMlsStorageHandle, SecretSealer};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use host::ServiceNativeHost;
use journal::ServiceJournal;
use mls::ServiceMlsStorage;
use storage::{ServiceStorage, SnapshotKind};

const REQUESTER: &[u8] = b"synthetic-service-requester";
const RESPONDER: &[u8] = b"synthetic-service-responder";
const REQUEST_BODY: &str = "synthetic native request";
const RESPONSE_BODY: &str = "synthetic exact native response";

fn sealer(key: u8) -> SecretSealer {
    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([key; 32])).unwrap()
}

struct Endpoint {
    owner: ServiceStorage,
    journal: ServiceJournal,
    mls: SealedMlsStorageHandle,
    host: Arc<ServiceNativeHost>,
    gate: Arc<tokio::sync::Mutex<()>>,
    conversation: ConversationId,
    device: DeviceId,
    namespace: &'static [u8],
    key: u8,
    directory: tempfile::TempDir,
}

impl Endpoint {
    fn reopen(&mut self) {
        self.owner.release().unwrap();
        let owner = ServiceStorage::open(self.directory.path()).unwrap();
        let journal = ServiceJournal::reopen(
            owner.clone(),
            sealer(self.key),
            self.namespace,
            self.conversation,
            self.device,
        )
        .unwrap();
        let mls = ServiceMlsStorage::new(owner.clone(), sealer(self.key), self.namespace)
            .unwrap()
            .into_handle();
        let host = Arc::new(
            ServiceNativeHost::open(journal.clone(), mls.clone(), self.conversation).unwrap(),
        );
        self.owner = owner;
        self.journal = journal;
        self.mls = mls;
        self.host = host;
        self.gate = Arc::new(tokio::sync::Mutex::new(()));
    }

    fn session(&self, relay: &Arc<OpaqueRelay>) -> NativeSession<ServiceNativeHost, OpaqueRelay> {
        let transport = Arc::new(OpaqueRelay {
            route: relay.route,
            state: relay.state.clone(),
            completion: Some((self.journal.clone(), self.conversation)),
        });
        NativeSession::new(self.host.clone(), transport, self.gate.clone())
    }

    fn request(
        &self,
        target: DeviceId,
    ) -> NativeApplicationRequest<authority::ServiceAuthorization> {
        NativeApplicationRequest {
            conversation_id: self.conversation,
            message_id: MessageId::from_bytes([1; 16]),
            content: ApplicationContent::directed_request(target, REQUEST_BODY).unwrap(),
            reply_to: None,
            authorization: Some(self.journal.authorization().unwrap()),
            sent_at_unix_milliseconds: 1234,
            expires_at_unix_seconds: 100,
            policy_operation: false,
        }
    }
}

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(".native-service-session-")
        .tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"))
        .unwrap()
}

fn pair() -> (Endpoint, Endpoint, RoutingId) {
    let left_directory = directory();
    let right_directory = directory();
    let left_owner = ServiceStorage::open(left_directory.path()).unwrap();
    let right_owner = ServiceStorage::open(right_directory.path()).unwrap();
    let left_identity = DeviceIdentity::generate().unwrap();
    let right_identity = DeviceIdentity::generate().unwrap();
    let id = left_identity.generate_conversation_id().unwrap();
    let route = left_identity.generate_routing_id().unwrap();
    let left_material = left_identity
        .create_conversation_signing_material(id)
        .unwrap();
    let right_material = right_identity
        .create_conversation_signing_material(id)
        .unwrap();
    let left_saved = left_material.seal(&sealer(7), REQUESTER).unwrap();
    let right_saved = right_material.seal(&sealer(8), RESPONDER).unwrap();
    let left_binding = left_material.binding().clone();
    let right_binding = right_material.binding().clone();
    let left_mls = ServiceMlsStorage::new(left_owner.clone(), sealer(7), REQUESTER)
        .unwrap()
        .into_handle();
    let right_mls = ServiceMlsStorage::new(right_owner.clone(), sealer(8), RESPONDER)
        .unwrap()
        .into_handle();
    let left_client = MlsConversationClient::with_storage(left_material, left_mls.clone()).unwrap();
    let mut right_client =
        MlsConversationClient::with_storage(right_material, right_mls.clone()).unwrap();
    left_client
        .register_verified_binding(verify_device_credential_binding(&right_binding).unwrap())
        .unwrap();
    right_client
        .register_verified_binding(verify_device_credential_binding(&left_binding).unwrap())
        .unwrap();
    let invitation = left_identity
        .issue_invitation(
            id,
            route,
            right_identity.device_id(),
            ConversationRole::Member,
            100,
        )
        .unwrap();
    let proof = right_client
        .create_join_proof(&right_identity, invitation, left_identity.public_key(), 1)
        .unwrap();
    let mut left_group = left_client.create_group().unwrap();
    let commit = left_group
        .create_add_commit(proof, EnvelopeId::from_bytes([77; 16]), 1)
        .unwrap();
    let welcome = MlsWelcome::from_bytes(commit.welcome().unwrap().as_bytes()).unwrap();
    // This fixture explicitly provisions a fixed post-join checkpoint; it does
    // not exercise relay membership acceptance or a live pairing ceremony.
    left_group.accept_pending_commit().unwrap();
    let right_group = right_client.join_group(&welcome).unwrap();
    assert_eq!(
        encode_conversation_state(left_group.state()).unwrap(),
        encode_conversation_state(right_group.state()).unwrap()
    );
    assert_eq!(left_group.epoch(), 1);
    let state = left_group.state().clone();
    drop((left_group, right_group, commit));
    let bindings = || {
        [&left_binding, &right_binding]
            .into_iter()
            .map(|binding| verify_device_credential_binding(binding).unwrap())
            .collect()
    };
    let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
    let left_journal = ServiceJournal::provision(
        left_owner.clone(),
        sealer(7),
        REQUESTER,
        &left_identity,
        StoredConversation {
            routing_id: route,
            signing_material: ConversationSigningMaterial::open(
                &sealer(7),
                REQUESTER,
                id,
                &left_saved,
            )
            .unwrap(),
            state: state.clone(),
            bindings: bindings(),
            sender_counter: 0,
            replay_cursor: 0,
        },
        &endpoint,
        &RelayAccessCredential::from_bytes([17; 32]),
    )
    .unwrap();
    let right_journal = ServiceJournal::provision(
        right_owner.clone(),
        sealer(8),
        RESPONDER,
        &right_identity,
        StoredConversation {
            routing_id: route,
            signing_material: ConversationSigningMaterial::open(
                &sealer(8),
                RESPONDER,
                id,
                &right_saved,
            )
            .unwrap(),
            state,
            bindings: bindings(),
            sender_counter: 0,
            replay_cursor: 0,
        },
        &endpoint,
        &RelayAccessCredential::from_bytes([18; 32]),
    )
    .unwrap();
    let left_host =
        Arc::new(ServiceNativeHost::open(left_journal.clone(), left_mls.clone(), id).unwrap());
    let right_host =
        Arc::new(ServiceNativeHost::open(right_journal.clone(), right_mls.clone(), id).unwrap());
    (
        Endpoint {
            owner: left_owner,
            journal: left_journal,
            mls: left_mls,
            host: left_host,
            gate: Arc::new(tokio::sync::Mutex::new(())),
            conversation: id,
            device: left_identity.device_id(),
            namespace: REQUESTER,
            key: 7,
            directory: left_directory,
        },
        Endpoint {
            owner: right_owner,
            journal: right_journal,
            mls: right_mls,
            host: right_host,
            gate: Arc::new(tokio::sync::Mutex::new(())),
            conversation: id,
            device: right_identity.device_id(),
            namespace: RESPONDER,
            key: 8,
            directory: right_directory,
        },
        route,
    )
}

#[derive(Default)]
struct RelayState {
    accepted: Vec<StoredRelayEnvelope>,
    attempts: Vec<RelayEnvelope>,
    acknowledgments: Vec<u64>,
    lose_receipt: bool,
}

struct OpaqueRelay {
    route: RoutingId,
    state: Arc<Mutex<RelayState>>,
    completion: Option<(ServiceJournal, ConversationId)>,
}

impl OpaqueRelay {
    fn new(route: RoutingId) -> Arc<Self> {
        Arc::new(Self {
            route,
            state: Arc::new(Mutex::new(RelayState::default())),
            completion: None,
        })
    }
}

#[async_trait]
impl RelayTransport for OpaqueRelay {
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
        let mut state = self.state.lock().unwrap();
        if envelope.routing_id() != self.route || state.attempts.len() == 64 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        state.attempts.push(envelope.clone());
        if let Some(prior) = state
            .accepted
            .iter()
            .find(|row| row.envelope().envelope_id() == envelope.envelope_id())
        {
            return if prior.envelope() == envelope {
                Ok(prior.clone())
            } else {
                Err(KonclaveClientError::InvalidResponse)
            };
        }
        if state.accepted.len() == 32 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        let stored =
            StoredRelayEnvelope::new(envelope.clone(), state.accepted.len() as u64 + 1).unwrap();
        state.accepted.push(stored.clone());
        if state.lose_receipt {
            state.lose_receipt = false;
            return Err(KonclaveClientError::TransportUnavailable);
        }
        Ok(stored)
    }

    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
        if request.routing_id() != self.route {
            return Err(KonclaveClientError::InvalidResponse);
        }
        let state = self.state.lock().unwrap();
        let matching = || {
            state
                .accepted
                .iter()
                .filter(|row| row.cursor() > request.after_cursor())
        };
        let envelopes: Vec<_> = matching().take(request.limit() as usize).cloned().collect();
        let more = matching().count() > envelopes.len();
        let next = envelopes
            .last()
            .map_or(request.after_cursor(), StoredRelayEnvelope::cursor);
        ReplayPage::new(envelopes, next, more).map_err(|_| KonclaveClientError::InvalidResponse)
    }

    async fn acknowledge(
        &self,
        request: AcknowledgeRequest,
    ) -> Result<AcknowledgeRequest, KonclaveClientError> {
        // Client-side observation at acknowledgment entry, not relay key custody.
        let (journal, conversation) = self.completion.as_ref().unwrap();
        assert!(
            journal
                .load_conversation(*conversation)
                .unwrap()
                .replay_cursor
                >= request.cursor()
        );
        assert!(
            journal
                .notification_evidence(*conversation, request.cursor())
                .unwrap()
                .is_some()
        );
        let mut state = self.state.lock().unwrap();
        if request.routing_id() != self.route || state.acknowledgments.len() == 64 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        state.acknowledgments.push(request.cursor());
        Ok(request)
    }

    async fn connect_watch(
        &self,
        _: ReplayRequest,
    ) -> Result<RelayWatchSession, KonclaveClientError> {
        Err(KonclaveClientError::InvalidResponse)
    }
}

#[test]
#[ignore = "invoked by the service-session test as a separately owned process"]
fn service_reopen_subprocess_probe() {
    let directory = std::env::var_os("KONCLAVE_NATIVE_SERVICE_REOPEN").unwrap();
    let conversation = ConversationId::from_slice(
        &STANDARD
            .decode(std::env::var("KONCLAVE_NATIVE_SERVICE_CONVERSATION").unwrap())
            .unwrap(),
    )
    .unwrap();
    let device = DeviceId::from_slice(
        &STANDARD
            .decode(std::env::var("KONCLAVE_NATIVE_SERVICE_DEVICE").unwrap())
            .unwrap(),
    )
    .unwrap();
    let owner = ServiceStorage::open(std::path::Path::new(&directory)).unwrap();
    let journal =
        ServiceJournal::reopen(owner.clone(), sealer(8), RESPONDER, conversation, device).unwrap();
    let mls = ServiceMlsStorage::new(owner.clone(), sealer(8), RESPONDER)
        .unwrap()
        .into_handle();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let host = runtime
        .block_on(async { ServiceNativeHost::open(journal, mls, conversation) })
        .unwrap();
    let existing = runtime
        .block_on(host.outbound_application(conversation, MessageId::from_bytes([2; 16])))
        .unwrap()
        .unwrap();
    assert_eq!(
        existing.message.reply_to(),
        Some(MessageId::from_bytes([1; 16]))
    );
    assert_eq!(existing.message.sent_at_unix_milliseconds(), 5678);
    assert_eq!(existing.envelope.expires_at_unix_seconds(), 100);
    assert_eq!(existing.status, NativeOutboundStatus::Ready);
    drop((host, runtime));
    owner.release().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_request_exact_response_survives_process_reopen_and_uncertain_acceptance() {
    let (requester, mut responder, route) = pair();
    let relay = OpaqueRelay::new(route);
    let request = requester
        .session(&relay)
        .send(requester.request(responder.device), 1)
        .await
        .unwrap();
    let batch = responder
        .session(&relay)
        .replay_once(responder.conversation, 4, 1)
        .await
        .unwrap();
    assert_eq!(batch.messages.len(), 1);
    assert_eq!(batch.messages[0].sender, requester.device);
    assert_eq!(
        batch.messages[0].message.message_id(),
        request.message.message_id()
    );
    assert!(matches!(
        batch.messages[0].message.content(),
        ApplicationContent::DirectedRequest(value) if value.target_device_id() == responder.device && value.body() == REQUEST_BODY
    ));
    requester
        .session(&relay)
        .replay_once(requester.conversation, 4, 1)
        .await
        .unwrap();
    let grant = responder
        .journal
        .claim(request.message.message_id())
        .unwrap();
    responder.reopen();
    let recovered = responder
        .journal
        .pending_claim(request.message.message_id())
        .unwrap()
        .unwrap();
    assert_eq!(grant.claim, recovered.claim);
    let mut response = NativeApplicationRequest {
        conversation_id: responder.conversation,
        message_id: MessageId::from_bytes([2; 16]),
        content: ApplicationContent::text(RESPONSE_BODY).unwrap(),
        reply_to: Some(request.message.message_id()),
        authorization: Some(recovered),
        sent_at_unix_milliseconds: 5678,
        expires_at_unix_seconds: 100,
        policy_operation: false,
    };
    let reservation = responder
        .journal
        .reserve_application(&response, EnvelopeId::from_bytes([88; 16]))
        .unwrap();
    responder.journal.set_enabled(false).unwrap();
    responder.owner.release().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "service_reopen_subprocess_probe",
        "--ignored",
        "--nocapture",
    ]);
    command.env("KONCLAVE_NATIVE_SERVICE_REOPEN", responder.directory.path());
    command.env(
        "KONCLAVE_NATIVE_SERVICE_CONVERSATION",
        STANDARD.encode(responder.conversation.as_bytes()),
    );
    command.env(
        "KONCLAVE_NATIVE_SERVICE_DEVICE",
        STANDARD.encode(responder.device.as_bytes()),
    );
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    assert!(
        tokio::task::block_in_place(|| command.status())
            .unwrap()
            .success()
    );
    responder.reopen();
    let exact = responder
        .journal
        .outbound_intent(reservation)
        .unwrap()
        .envelope
        .unwrap();
    response.authorization = None;
    response.sent_at_unix_milliseconds = 9999;
    response.expires_at_unix_seconds = 999;
    relay.state.lock().unwrap().lose_receipt = true;
    assert!(matches!(
        responder.session(&relay).send(response, 2).await,
        Err(NativeSessionError::Relay(
            KonclaveClientError::TransportUnavailable
        ))
    ));
    let stale = responder.host.clone();
    responder.reopen();
    assert!(
        stale
            .outbound_application(responder.conversation, reservation.message_id)
            .await
            .is_err()
    );
    let retried = responder
        .session(&relay)
        .send(
            NativeApplicationRequest {
                conversation_id: responder.conversation,
                message_id: reservation.message_id,
                content: ApplicationContent::text(RESPONSE_BODY).unwrap(),
                reply_to: Some(request.message.message_id()),
                authorization: None,
                sent_at_unix_milliseconds: 9999,
                expires_at_unix_seconds: 999,
                policy_operation: false,
            },
            3,
        )
        .await
        .unwrap();
    assert_eq!(retried.cursor, 2);
    assert_eq!(retried.message.sent_at_unix_milliseconds(), 5678);
    assert!(
        responder
            .journal
            .pending_claim(request.message.message_id())
            .unwrap()
            .is_none()
    );
    {
        let state = relay.state.lock().unwrap();
        assert_eq!(state.accepted.len(), 2);
        assert_eq!(state.attempts.len(), 3);
        assert!(state.attempts[1] == exact);
        assert!(state.attempts[2] == exact);
    }
    let replies = requester
        .session(&relay)
        .replay_once(requester.conversation, 4, 3)
        .await
        .unwrap();
    assert_eq!(replies.messages.len(), 1);
    assert_eq!(replies.messages[0].sender, responder.device);
    assert_eq!(
        replies.messages[0].message.reply_to(),
        Some(request.message.message_id())
    );
    assert!(
        matches!(replies.messages[0].message.content(), ApplicationContent::Text(value) if value.as_str() == RESPONSE_BODY)
    );
    assert_eq!(
        requester
            .journal
            .load_conversation(requester.conversation)
            .unwrap()
            .replay_cursor,
        2
    );
    assert_eq!(relay.state.lock().unwrap().acknowledgments.last(), Some(&2));
    assert!(
        requester
            .session(&relay)
            .replay_once(requester.conversation, 4, 4)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_saved_inbox_recovers_before_and_after_receiver_ratchet_persistence() {
    for persist_receiver in [false, true] {
        let (requester, mut responder, route) = pair();
        let relay = OpaqueRelay::new(route);
        requester
            .session(&relay)
            .send(requester.request(responder.device), 1)
            .await
            .unwrap();
        let stored = relay.state.lock().unwrap().accepted[0].clone();
        let identity = Mutex::new(responder.journal.identity().unwrap());
        let mut processor =
            NativeConversationProcessor::new(&responder.journal, responder.mls.clone(), &identity);
        let mut opened = processor.open(responder.conversation).unwrap();
        responder.journal.record_inbox_envelope(&stored).unwrap();
        let (sender, message) =
            decrypt_application::<journal::JournalError>(&mut opened.group, stored.envelope())
                .unwrap();
        responder
            .journal
            .save_inbox_message(
                responder.conversation,
                stored.cursor(),
                sender,
                opened.group.epoch(),
                &message,
            )
            .unwrap();
        if persist_receiver {
            opened.group.persist().unwrap();
        }
        drop((opened, processor));
        drop(identity);
        responder.reopen();
        let batch = responder
            .session(&relay)
            .replay_once(responder.conversation, 4, 2)
            .await
            .unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].sender, requester.device);
        let before = responder
            .journal
            .notification_evidence(responder.conversation, 1)
            .unwrap()
            .unwrap();
        let duplicate = responder
            .host
            .process_application(responder.conversation, stored, 99)
            .await
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(
            responder
                .journal
                .notification_evidence(responder.conversation, 1)
                .unwrap()
                .unwrap(),
            before
        );
        assert_eq!(
            responder
                .journal
                .load_conversation(responder.conversation)
                .unwrap()
                .replay_cursor,
            1
        );
        assert_eq!(relay.state.lock().unwrap().acknowledgments.as_slice(), &[1]);
    }
}

#[test]
fn unsupported_runtime_fails_without_mutating_authenticated_evidence() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (requester, responder, _) = runtime.block_on(async { pair() });
    drop(runtime);
    let before = requester.owner.read_slot(SnapshotKind::Journal).unwrap();
    let unsupported = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(matches!(
        unsupported.block_on(
            requester
                .host
                .prepare_application(requester.request(responder.device))
        ),
        Err(host::ServiceHostError::UnsupportedRuntime)
    ));
    assert_eq!(
        requester.owner.read_slot(SnapshotKind::Journal).unwrap(),
        before
    );
    assert!(requester.journal.retained_outbox().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_cannot_detach_an_inline_callback_or_drop_its_submission_guard() {
    let (requester, _, _) = pair();
    let owner = requester.owner.clone();
    let (entered, holding) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        owner.update_slot(
            SnapshotKind::Journal,
            |current| -> Result<_, storage::StorageError> {
                entered.send(()).unwrap();
                blocked.recv().unwrap();
                Ok((current.unwrap().to_vec(), ()))
            },
        )
    });
    holding.await.unwrap();
    let gate = requester.gate.clone();
    let host = requester.host.clone();
    let conversation = requester.conversation;
    let (entered, running) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        let _submission = gate.lock_owned().await;
        entered.send(()).unwrap();
        host.outbound_application(conversation, MessageId::from_bytes([99; 16]))
            .await
    });
    running.await.unwrap();
    caller.abort();
    assert!(requester.gate.try_lock().is_err());
    assert!(!caller.is_finished());
    release.send(()).unwrap();
    tokio::task::block_in_place(|| holder.join())
        .unwrap()
        .unwrap();
    assert!(caller.await.unwrap().unwrap().is_none());
    assert!(requester.gate.try_lock().is_ok());
    requester.owner.release().unwrap();
    assert!(requester.host.replay_position(conversation).await.is_err());
}
