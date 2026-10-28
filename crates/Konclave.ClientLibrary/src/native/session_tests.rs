use std::sync::{Arc, Mutex};

use KonclaveDomainCore::{
    AcknowledgeRequest, ApplicationContent, ApplicationMessage, ConversationId, DeliveryClass,
    DeviceId, EnvelopeId, MembershipOperationId, MessageId, ProtocolVersion, RelayEnvelope,
    ReplayPage, ReplayRequest, RoutingId, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{decode_application_message, encode_application_message};
use async_trait::async_trait;
use zeroize::Zeroizing;

use super::*;
use crate::{KonclaveClientError, RelayTransport, RelayWatchSession};

const CONVERSATION: ConversationId = ConversationId::from_bytes([1; 32]);
const ROUTE: RoutingId = RoutingId::from_bytes([2; 32]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum HostError {
    #[error("injected fixture failure")]
    Injected,
    #[error("conflicting fixture evidence")]
    Conflict,
    #[error("unsupported fixture operation")]
    Unsupported,
}

fn copy_message(message: &ApplicationMessage) -> ApplicationMessage {
    let bytes = Zeroizing::new(encode_application_message(message).unwrap());
    decode_application_message(&bytes).unwrap()
}

fn request(id: u8) -> NativeApplicationRequest<()> {
    NativeApplicationRequest {
        conversation_id: CONVERSATION,
        message_id: MessageId::from_bytes([id; 16]),
        content: ApplicationContent::text("synthetic orchestration fixture").unwrap(),
        reply_to: None,
        authorization: None,
        sent_at_unix_milliseconds: 1,
        expires_at_unix_seconds: 100,
        policy_operation: false,
    }
}

fn envelope(id: u8) -> RelayEnvelope {
    RelayEnvelope::new(
        ProtocolVersion::application_v1(),
        ROUTE,
        EnvelopeId::from_bytes([id; 16]),
        DeliveryClass::GroupApplication,
        None,
        100,
        vec![id],
    )
    .unwrap()
}

#[derive(Default)]
struct HostState {
    applications: Vec<NativeOutboundApplication>,
    memberships: Vec<(PreparedMembership, Option<u64>)>,
    orphaned: Vec<MembershipOperationId>,
    cursor: u64,
    fail_cursor: Option<u64>,
    removed: bool,
    prepared: usize,
}

// This fake exercises orchestration, not cryptographic or durable-storage claims.
#[derive(Default)]
struct Host(Mutex<HostState>);

#[async_trait]
impl NativeSessionHost for Host {
    type Error = HostError;
    type Authorization = ();

    async fn outbound_application(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<Option<NativeOutboundApplication>, HostError> {
        if conversation != CONVERSATION {
            return Err(HostError::Conflict);
        }
        Ok(self
            .0
            .lock()
            .unwrap()
            .applications
            .iter()
            .find(|row| row.message.message_id() == message)
            .map(|row| NativeOutboundApplication {
                conversation_id: row.conversation_id,
                message: copy_message(&row.message),
                envelope: row.envelope.clone(),
                status: row.status,
            }))
    }

    async fn prepare_application(
        &self,
        request: NativeApplicationRequest<()>,
    ) -> Result<PreparedApplication, HostError> {
        let mut state = self.0.lock().unwrap();
        if state.applications.len() >= 16
            || request.conversation_id != CONVERSATION
            || request.authorization.is_some()
            || request.policy_operation
            || state.removed
        {
            return Err(HostError::Conflict);
        }
        let message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            request.message_id,
            state.applications.len() as u64 + 1,
            request.sent_at_unix_milliseconds,
            request.reply_to,
            request.content,
        )
        .unwrap();
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            ROUTE,
            EnvelopeId::from_bytes(*request.message_id.as_bytes()),
            DeliveryClass::GroupApplication,
            None,
            request.expires_at_unix_seconds,
            vec![state.applications.len() as u8],
        )
        .unwrap();
        state.applications.push(NativeOutboundApplication {
            conversation_id: CONVERSATION,
            message: copy_message(&message),
            envelope: envelope.clone(),
            status: NativeOutboundStatus::Ready,
        });
        state.prepared += 1;
        Ok(PreparedApplication {
            conversation_id: CONVERSATION,
            message,
            envelope,
        })
    }

    async fn ready_applications(&self) -> Result<Vec<NativePendingApplication>, HostError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .applications
            .iter()
            .filter(|row| row.status == NativeOutboundStatus::Ready)
            .map(|row| NativePendingApplication {
                conversation_id: row.conversation_id,
                envelope: row.envelope.clone(),
            })
            .collect())
    }

    async fn retry_eligible(&self, conversation: ConversationId) -> Result<bool, HostError> {
        if conversation != CONVERSATION {
            return Err(HostError::Conflict);
        }
        let mut state = self.0.lock().unwrap();
        let eligible = !state.removed;
        if !eligible {
            for row in &mut state.applications {
                if row.status == NativeOutboundStatus::Ready {
                    row.status = NativeOutboundStatus::Removed;
                }
            }
        }
        Ok(eligible)
    }

    async fn expire_application(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<NativeExpiryOutcome, HostError> {
        let mut state = self.0.lock().unwrap();
        let row = state
            .applications
            .iter_mut()
            .find(|row| row.envelope == *envelope)
            .ok_or(HostError::Conflict)?;
        match row.status {
            NativeOutboundStatus::Accepted { cursor } => {
                Ok(NativeExpiryOutcome::Accepted { cursor })
            }
            NativeOutboundStatus::Ready => {
                row.status = NativeOutboundStatus::Expired;
                Ok(NativeExpiryOutcome::Expired)
            }
            _ => Err(HostError::Conflict),
        }
    }

    async fn accept_application(&self, stored: StoredRelayEnvelope) -> Result<(), HostError> {
        let mut state = self.0.lock().unwrap();
        let row = state
            .applications
            .iter_mut()
            .find(|row| row.envelope == *stored.envelope())
            .ok_or(HostError::Conflict)?;
        match row.status {
            NativeOutboundStatus::Ready => {
                row.status = NativeOutboundStatus::Accepted {
                    cursor: stored.cursor(),
                }
            }
            NativeOutboundStatus::Accepted { cursor } if cursor == stored.cursor() => {}
            _ => return Err(HostError::Conflict),
        }
        Ok(())
    }

    async fn ready_memberships(&self) -> Result<Vec<PreparedMembership>, HostError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .memberships
            .iter()
            .filter(|(_, cursor)| cursor.is_none())
            .map(|(prepared, _)| copy_membership(prepared))
            .collect())
    }
    async fn accept_membership(
        &self,
        stored: StoredRelayEnvelope,
    ) -> Result<NativeAcceptedMembership, HostError> {
        let mut state = self.0.lock().unwrap();
        let (prepared, cursor) = state
            .memberships
            .iter_mut()
            .find(|(prepared, _)| prepared.envelope == *stored.envelope())
            .ok_or(HostError::Conflict)?;
        if cursor.is_some_and(|cursor| cursor != stored.cursor()) {
            return Err(HostError::Conflict);
        }
        *cursor = Some(stored.cursor());
        Ok(NativeAcceptedMembership {
            operation_id: prepared.operation_id,
            conversation_id: prepared.conversation_id,
            cursor: stored.cursor(),
            welcome: prepared.welcome.clone(),
        })
    }
    async fn orphan_membership(&self, operation: MembershipOperationId) -> Result<(), HostError> {
        let mut state = self.0.lock().unwrap();
        if !state
            .memberships
            .iter()
            .any(|(prepared, cursor)| prepared.operation_id == operation && cursor.is_none())
        {
            return Err(HostError::Conflict);
        }
        state
            .memberships
            .retain(|(prepared, _)| prepared.operation_id != operation);
        state.orphaned.push(operation);
        Ok(())
    }
    async fn replay_position(
        &self,
        conversation: ConversationId,
    ) -> Result<(RoutingId, u64), HostError> {
        if conversation != CONVERSATION {
            return Err(HostError::Conflict);
        }
        Ok((ROUTE, self.0.lock().unwrap().cursor))
    }
    async fn process_application(
        &self,
        conversation: ConversationId,
        stored: StoredRelayEnvelope,
        _: u64,
    ) -> Result<ProcessedApplication, HostError> {
        let mut state = self.0.lock().unwrap();
        if state.fail_cursor == Some(stored.cursor()) {
            state.fail_cursor = None;
            return Err(HostError::Injected);
        }
        if conversation != CONVERSATION
            || stored.envelope().routing_id() != ROUTE
            || stored.cursor() != state.cursor + 1
        {
            return Err(HostError::Conflict);
        }
        state.cursor = stored.cursor();
        Ok(ProcessedApplication {
            conversation_id: CONVERSATION,
            cursor: stored.cursor(),
            envelope_id: stored.envelope().envelope_id(),
            sender: DeviceId::from_bytes([3; 32]),
            epoch: 0,
            message: ApplicationMessage::new(
                ProtocolVersion::application_v1(),
                MessageId::from_bytes([stored.cursor() as u8; 16]),
                stored.cursor(),
                1,
                None,
                ApplicationContent::text("synthetic incoming fixture").unwrap(),
            )
            .unwrap(),
            direction: MessageDirection::Inbound,
            duplicate: false,
        })
    }
    async fn process_membership(
        &self,
        _: ConversationId,
        _: StoredRelayEnvelope,
        _: u64,
    ) -> Result<(), HostError> {
        Err(HostError::Unsupported)
    }
}

#[derive(Default)]
struct RelayState {
    accepted: Vec<StoredRelayEnvelope>,
    replay: Vec<StoredRelayEnvelope>,
    acknowledgments: Vec<AcknowledgeRequest>,
    fail_submit: bool,
    stale_membership: bool,
    wrong_acceptance: bool,
    wrong_ack: bool,
}

#[derive(Default)]
struct Relay(Mutex<RelayState>);

#[async_trait]
impl RelayTransport for Relay {
    async fn submit(
        &self,
        submitted: &RelayEnvelope,
    ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
        let mut state = self.0.lock().unwrap();
        if state.stale_membership && submitted.delivery_class() == DeliveryClass::GroupCommit {
            return Err(KonclaveClientError::RelayRejected {
                status: 409,
                relay_code: "relay_stale_epoch".to_owned(),
            });
        }
        if state.fail_submit {
            state.fail_submit = false;
            return Err(KonclaveClientError::TransportUnavailable);
        }
        if state.wrong_acceptance {
            return Ok(StoredRelayEnvelope::new(envelope(99), 1).unwrap());
        }
        if let Some(existing) = state
            .accepted
            .iter()
            .find(|stored| stored.envelope() == submitted)
        {
            return Ok(existing.clone());
        }
        if state.accepted.len() >= 16 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        let stored =
            StoredRelayEnvelope::new(submitted.clone(), state.accepted.len() as u64 + 1).unwrap();
        state.accepted.push(stored.clone());
        Ok(stored)
    }
    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
        let state = self.0.lock().unwrap();
        let envelopes: Vec<_> = state
            .replay
            .iter()
            .filter(|stored| stored.cursor() > request.after_cursor())
            .cloned()
            .collect();
        let next = envelopes
            .last()
            .map_or(request.after_cursor(), StoredRelayEnvelope::cursor);
        Ok(ReplayPage::new(envelopes, next, false).unwrap())
    }
    async fn acknowledge(
        &self,
        request: AcknowledgeRequest,
    ) -> Result<AcknowledgeRequest, KonclaveClientError> {
        let mut state = self.0.lock().unwrap();
        if state.acknowledgments.len() >= 16 {
            return Err(KonclaveClientError::InvalidResponse);
        }
        state.acknowledgments.push(request);
        if state.wrong_ack {
            return Ok(
                AcknowledgeRequest::new(RoutingId::from_bytes([99; 32]), request.cursor()).unwrap(),
            );
        }
        Ok(request)
    }
    async fn connect_watch(
        &self,
        _: ReplayRequest,
    ) -> Result<RelayWatchSession, KonclaveClientError> {
        Err(KonclaveClientError::InvalidResponse)
    }
}

fn fixture() -> (Arc<Host>, Arc<Relay>, NativeSession<Host, Relay>) {
    let host = Arc::new(Host::default());
    let relay = Arc::new(Relay::default());
    let session = NativeSession::new(
        host.clone(),
        relay.clone(),
        Arc::new(tokio::sync::Mutex::new(())),
    );
    (host, relay, session)
}

fn membership(id: u8) -> PreparedMembership {
    PreparedMembership {
        operation_id: MembershipOperationId::from_bytes([id; 16]),
        conversation_id: CONVERSATION,
        parent_epoch: 0,
        envelope: RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            ROUTE,
            EnvelopeId::from_bytes([id; 16]),
            DeliveryClass::GroupCommit,
            Some(0),
            100,
            vec![id],
        )
        .unwrap(),
        welcome: Some(vec![id]),
    }
}

fn copy_membership(prepared: &PreparedMembership) -> PreparedMembership {
    PreparedMembership {
        operation_id: prepared.operation_id,
        conversation_id: prepared.conversation_id,
        parent_epoch: prepared.parent_epoch,
        envelope: prepared.envelope.clone(),
        welcome: prepared.welcome.clone(),
    }
}

#[tokio::test]
async fn externally_held_gate_rejects_all_foreign_gate_operations_before_effects() {
    let (host, relay, session) = fixture();
    let foreign = Arc::new(tokio::sync::Mutex::new(())).lock_owned().await;
    assert!(matches!(
        session.retry_applications_with_gate(1, &foreign).await,
        Err(NativeSessionError::Protocol)
    ));
    assert!(matches!(
        session.retry_memberships_with_gate(&foreign).await,
        Err(NativeSessionError::Protocol)
    ));
    assert!(matches!(
        session.submit_membership_with_gate(membership(6), &foreign).await,
        Err(NativeSessionError::Protocol)
    ));
    assert!(relay.0.lock().unwrap().accepted.is_empty());
    assert!(host.0.lock().unwrap().orphaned.is_empty());
}

#[tokio::test]
async fn shared_gate_preserves_application_then_exact_membership_retry_and_welcome() {
    let host = Arc::new(Host::default());
    let relay = Arc::new(Relay::default());
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let session = NativeSession::new(host.clone(), relay.clone(), gate.clone());
    host.prepare_application(request(4)).await.unwrap();
    let prepared = membership(6);
    host.0
        .lock()
        .unwrap()
        .memberships
        .push((copy_membership(&prepared), None));
    let held = gate.lock_owned().await;
    assert_eq!(
        session.retry_applications_with_gate(1, &held).await.unwrap(),
        1
    );
    let first = session
        .submit_membership_with_gate(copy_membership(&prepared), &held)
        .await
        .unwrap();
    let exact = session
        .submit_membership_with_gate(prepared, &held)
        .await
        .unwrap();
    assert_eq!(first.cursor, 2);
    assert_eq!(exact.cursor, first.cursor);
    assert_eq!(exact.welcome, Some(vec![6]));
    assert_eq!(
        session.retry_memberships_with_gate(&held).await.unwrap(),
        0
    );
    assert_eq!(relay.0.lock().unwrap().accepted.len(), 2);
}

#[tokio::test]
async fn stale_membership_orphans_only_the_exact_unaccepted_operation() {
    let host = Arc::new(Host::default());
    let relay = Arc::new(Relay::default());
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let session = NativeSession::new(host.clone(), relay.clone(), gate.clone());
    for id in [6, 7] {
        host.0
            .lock()
            .unwrap()
            .memberships
            .push((membership(id), None));
    }
    relay.0.lock().unwrap().stale_membership = true;
    let held = gate.lock_owned().await;
    assert!(matches!(
        session.submit_membership_with_gate(membership(6), &held).await,
        Err(NativeSessionError::Relay(error)) if error.code() == "relay_stale_epoch"
    ));
    let state = host.0.lock().unwrap();
    assert_eq!(
        state.orphaned,
        vec![MembershipOperationId::from_bytes([6; 16])]
    );
    assert_eq!(state.memberships.len(), 1);
    assert_eq!(
        state.memberships[0].0.operation_id,
        MembershipOperationId::from_bytes([7; 16])
    );
    assert!(relay.0.lock().unwrap().accepted.is_empty());
}

#[tokio::test]
async fn exact_retry_retains_original_timestamp_envelope_and_cursor_without_readmission() {
    let (host, relay, session) = fixture();
    let sent = session.send(request(4), 1).await.unwrap();
    let mut retry = request(4);
    retry.sent_at_unix_milliseconds = 999;
    retry.expires_at_unix_seconds = 1000;
    let retried = session.send(retry, 200).await.unwrap();
    assert_eq!(sent.cursor, retried.cursor);
    assert_eq!(retried.message.sent_at_unix_milliseconds(), 1);
    assert_eq!(host.0.lock().unwrap().prepared, 1);
    assert_eq!(relay.0.lock().unwrap().accepted.len(), 1);
}

#[tokio::test]
async fn changed_content_or_reply_cannot_reuse_stable_identity() {
    let (_, relay, session) = fixture();
    session.send(request(4), 1).await.unwrap();
    for changed_reply in [false, true] {
        let mut retry = request(4);
        if changed_reply {
            retry.reply_to = Some(MessageId::from_bytes([8; 16]));
        } else {
            retry.content = ApplicationContent::text("changed intent").unwrap();
        }
        assert!(matches!(
            session.send(retry, 1).await,
            Err(NativeSessionError::IdempotencyConflict)
        ));
    }
    assert_eq!(relay.0.lock().unwrap().accepted.len(), 1);
}

#[tokio::test]
async fn new_generation_drains_older_ready_ciphertext_before_new_admission() {
    let (host, relay, session) = fixture();
    relay.0.lock().unwrap().fail_submit = true;
    assert!(matches!(
        session.send(request(4), 1).await,
        Err(NativeSessionError::Relay(_))
    ));
    let old = host.0.lock().unwrap().applications[0].envelope.clone();
    let sent = session.clone().send(request(5), 1).await.unwrap();
    let state = relay.0.lock().unwrap();
    assert!(*state.accepted[0].envelope() == old);
    assert_eq!(sent.cursor, 2);
    assert_eq!(host.0.lock().unwrap().prepared, 2);
}

#[tokio::test]
async fn terminal_expiry_and_removed_membership_do_not_submit() {
    for removed in [false, true] {
        let (host, relay, session) = fixture();
        relay.0.lock().unwrap().fail_submit = true;
        assert!(session.send(request(4), 1).await.is_err());
        host.0.lock().unwrap().removed = removed;
        assert_eq!(session.retry_ready(100).await.unwrap(), 0);
        let result = session.send(request(4), 1).await;
        assert!(if removed {
            matches!(result, Err(NativeSessionError::OutboundRemoved))
        } else {
            matches!(result, Err(NativeSessionError::OutboundExpired))
        });
        assert!(relay.0.lock().unwrap().accepted.is_empty());
    }
}

#[tokio::test]
async fn contradictory_acceptance_cannot_be_committed_as_success() {
    let (host, relay, session) = fixture();
    relay.0.lock().unwrap().wrong_acceptance = true;
    assert!(matches!(
        session.send(request(4), 1).await,
        Err(NativeSessionError::Host(HostError::Conflict))
    ));
    assert_eq!(
        host.0.lock().unwrap().applications[0].status,
        NativeOutboundStatus::Ready
    );
}

#[tokio::test]
async fn exact_ready_retry_rechecks_membership_without_waiting_for_a_retry_sweep() {
    let (host, relay, session) = fixture();
    relay.0.lock().unwrap().fail_submit = true;
    assert!(session.send(request(4), 1).await.is_err());
    host.0.lock().unwrap().removed = true;
    assert!(matches!(
        session.send(request(4), 1).await,
        Err(NativeSessionError::OutboundRemoved)
    ));
    assert!(relay.0.lock().unwrap().accepted.is_empty());
    assert_eq!(
        host.0.lock().unwrap().applications[0].status,
        NativeOutboundStatus::Removed
    );
}

#[tokio::test]
async fn replay_completes_before_ack_and_resumes_after_partial_host_failure() {
    let (host, relay, session) = fixture();
    relay.0.lock().unwrap().replay = vec![
        StoredRelayEnvelope::new(envelope(4), 1).unwrap(),
        StoredRelayEnvelope::new(envelope(5), 2).unwrap(),
    ];
    host.0.lock().unwrap().fail_cursor = Some(2);
    assert!(matches!(
        session.replay_once(CONVERSATION, 2, 1).await,
        Err(NativeSessionError::Host(HostError::Injected))
    ));
    assert_eq!(host.0.lock().unwrap().cursor, 1);
    assert!(relay.0.lock().unwrap().acknowledgments.is_empty());
    let resumed = session.replay_once(CONVERSATION, 2, 2).await.unwrap();
    assert_eq!(resumed.messages.len(), 1);
    assert_eq!(resumed.messages[0].cursor, 2);
    assert_eq!(relay.0.lock().unwrap().acknowledgments[0].cursor(), 2);
}

#[tokio::test]
async fn replay_gap_wrong_route_or_oversized_page_cannot_mutate_host() {
    for mode in 0..3 {
        let (host, relay, session) = fixture();
        let first = if mode == 1 {
            RelayEnvelope::new(
                ProtocolVersion::application_v1(),
                RoutingId::from_bytes([99; 32]),
                EnvelopeId::from_bytes([4; 16]),
                DeliveryClass::GroupApplication,
                None,
                100,
                vec![4],
            )
            .unwrap()
        } else {
            envelope(4)
        };
        relay.0.lock().unwrap().replay =
            vec![StoredRelayEnvelope::new(first, if mode == 0 { 2 } else { 1 }).unwrap()];
        let limit = if mode == 2 {
            relay
                .0
                .lock()
                .unwrap()
                .replay
                .push(StoredRelayEnvelope::new(envelope(5), 2).unwrap());
            1
        } else {
            2
        };
        assert!(matches!(
            session.replay_once(CONVERSATION, limit, 1).await,
            Err(NativeSessionError::InvalidRelayResponse)
        ));
        assert_eq!(host.0.lock().unwrap().cursor, 0);
        assert!(relay.0.lock().unwrap().acknowledgments.is_empty());
    }
}

#[test]
fn acknowledgment_classifier_covers_route_and_monotonic_cursor_categories() {
    let requested = AcknowledgeRequest::new(ROUTE, 2).unwrap();
    for (route, cursor, valid) in [
        (ROUTE, 1, false),
        (ROUTE, 2, true),
        (ROUTE, 3, true),
        (RoutingId::from_bytes([99; 32]), 2, false),
    ] {
        assert_eq!(
            validate_native_acknowledgment(
                requested,
                AcknowledgeRequest::new(route, cursor).unwrap()
            )
            .is_ok(),
            valid
        );
    }
}

#[test]
fn replay_classifier_covers_empty_gap_continuation_and_overflow_categories() {
    for (after, cursors, next, valid) in [
        (0, vec![], 0, true),
        (1, vec![], 2, false),
        (0, vec![1, 2], 2, true),
        (0, vec![2], 2, false),
        (0, vec![1, 3], 3, false),
        (0, vec![1], 2, false),
        (u64::MAX, vec![u64::MAX], u64::MAX, false),
    ] {
        let stored = cursors
            .into_iter()
            .map(|cursor| StoredRelayEnvelope::new(envelope(4), cursor).unwrap())
            .collect();
        assert_eq!(
            validate_native_replay_page(after, &ReplayPage::new(stored, next, false).unwrap())
                .is_ok(),
            valid
        );
    }
}
