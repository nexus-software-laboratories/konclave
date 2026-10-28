use KonclaveCryptographicCore::{ConversationSigningMaterial, VerifiedDeviceCredentialBinding};
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationState, DeviceCredentialBinding,
    DeviceId, EnvelopeId, MembershipOperationId, MessageId, NotificationId, RelayEnvelope, RoutingId,
    StoredRelayEnvelope,
};
use zeroize::Zeroizing;

/// Authenticated conversation inputs loaded by the endpoint's journal adapter.
///
/// Signing material and bindings must be opened and verified for this exact
/// endpoint and conversation before returning. Do not derive `Debug` or serialize
/// this record into ordinary backing storage.
pub struct StoredConversation {
    /// Opaque relay route bound to the conversation.
    pub routing_id: RoutingId,
    /// Explicitly opened conversation signing identity.
    pub signing_material: ConversationSigningMaterial,
    /// Authenticated complete application policy state.
    pub state: ConversationState,
    /// Independently verified conversation credentials.
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
    /// Highest permanently reserved sender counter.
    pub sender_counter: u64,
    /// Highest durably completed contiguous relay cursor.
    pub replay_cursor: u64,
}

/// One committed sender reservation; counters and identifiers cannot be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundReservation {
    /// Exact conversation scope.
    pub conversation_id: ConversationId,
    /// Stable caller message identity.
    pub message_id: MessageId,
    /// Stable relay envelope identity.
    pub envelope_id: EnvelopeId,
    /// Permanently consumed monotonic sender counter.
    pub sender_counter: u64,
}

/// Application admission input, committed atomically with current host authority.
///
/// For a terminal response, `authorization` identifies the exact live handling
/// claim. The adapter must consume it and save immutable response intent in the
/// same transaction as the reservation. An earlier authorization check is not
/// sufficient. Exact recovery of committed work is not a new admission.
pub struct NativeApplicationRequest<A> {
    /// Exact conversation scope.
    pub conversation_id: ConversationId,
    /// Stable caller-provided idempotency identity.
    pub message_id: MessageId,
    /// Validated content; not an authority to perform an operation.
    pub content: ApplicationContent,
    /// Exact prior message, when responding.
    pub reply_to: Option<MessageId>,
    /// Host-specific authority/claim input, never inferred from message content.
    pub authorization: Option<A>,
    /// Caller display timestamp.
    pub sent_at_unix_milliseconds: u64,
    /// Relay expiry; does not cancel already committed native work.
    pub expires_at_unix_seconds: u64,
    /// Requests the host's existing policy-operation reservation boundary.
    pub policy_operation: bool,
}

/// Durable outbound membership lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipOutboxStatus {
    /// Sealed envelope is ready for exact relay retry.
    Ready = 1,
    /// Relay accepted the exact envelope; local application may need recovery.
    Accepted = 2,
    /// MLS and policy checkpoints have been promoted.
    Applied = 3,
    /// Pending MLS state was rejected before abandoning the operation.
    Orphaned = 4,
}

/// Authenticated outbound membership intent and recovery evidence.
pub struct MembershipOutbox {
    /// Stable membership identity.
    pub operation_id: MembershipOperationId,
    /// Exact conversation.
    pub conversation_id: ConversationId,
    /// Expected prior epoch.
    pub parent_epoch: u64,
    /// Exact immutable relay envelope.
    pub envelope: RelayEnvelope,
    /// Opened authenticated authorization and optional join proof.
    pub control: Zeroizing<Vec<u8>>,
    /// Complete expected next policy state.
    pub next_state: ConversationState,
    /// Verified credentials bound to that state.
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
    /// Optional public encrypted Welcome.
    pub welcome: Option<Vec<u8>>,
    /// Committed lifecycle checkpoint.
    pub status: MembershipOutboxStatus,
    /// Exact accepted cursor, when known.
    pub accepted_cursor: Option<u64>,
}

/// Authenticated inbound membership checkpoint, opened only inside the endpoint.
pub struct StoredMembershipTransition {
    /// Exact received envelope and cursor.
    pub stored: StoredRelayEnvelope,
    /// MLS-authenticated sender.
    pub sender: DeviceId,
    /// Expected prior epoch.
    pub parent_epoch: u64,
    /// Authorized operation identity.
    pub operation_id: MembershipOperationId,
    /// Opened authenticated control.
    pub control: Zeroizing<Vec<u8>>,
    /// Complete authenticated next policy.
    pub next_state: ConversationState,
    /// Verified credentials for restoration.
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
}

/// Committed inbound membership recovery state.
pub enum MembershipInboxOperation {
    /// Ciphertext is journaled, but plaintext has not been checkpointed.
    Received { stored: StoredRelayEnvelope },
    /// Authenticated transition is durable, possibly before MLS persistence.
    TransitionSaved(StoredMembershipTransition),
    /// Transition and contiguous cursor were durably completed.
    Complete(StoredMembershipTransition),
}

/// Opened authenticated application checkpoint.
pub struct StoredApplicationMessage {
    /// Exact relay cursor.
    pub cursor: u64,
    /// Exact relay envelope.
    pub envelope_id: EnvelopeId,
    /// MLS-authenticated sender.
    pub sender: DeviceId,
    /// Authenticated epoch.
    pub epoch: u64,
    /// Opened validated application content.
    pub message: ApplicationMessage,
}

/// Direction derived from authenticated local outbox evidence, not payload claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    /// Exact local outbound echo.
    Outbound = 1,
    /// Remote authenticated message.
    Inbound = 2,
}

/// Committed application inbox recovery state.
pub enum InboxOperation {
    /// Ciphertext is durable, before plaintext processing.
    Received { stored: StoredRelayEnvelope },
    /// Plaintext is durable, potentially before receiver-ratchet persistence.
    MessageSaved {
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
    /// Ratchet and application completion are durable.
    Complete {
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
}

/// Atomic, bounded, authenticated native journal operations for one endpoint.
///
/// Every successful mutation means committed state under current writer ownership,
/// not a queued write. Bind reads/writes to exact endpoint, conversation, route,
/// envelope, cursor and epoch; reject conflicting retries, cursor gaps, stale
/// writers and counter regression. Bound collections and encoded lengths before
/// allocation. Seal content, control, credentials and policy before persistence.
///
/// New admission MUST atomically revalidate current authority and any exact live
/// handling claim, reserve identities/counter and terminalize response intent.
/// Notification completion must atomically advance only the contiguous completed
/// cursor. Recovery must retain immutable evidence rather than inventing success
/// from an MLS error. There is deliberately no transaction spanning this journal
/// and the separately owned MLS provider.
///
/// # Errors
///
/// Every method propagates operational failures through `Error`. No method may
/// convert failed authentication, unavailable ownership or storage into absence.
#[allow(clippy::too_many_arguments, reason = "journal checkpoints preserve exact existing atomic fields")]
pub trait NativeConversationJournal {
    /// Stable host storage/authority failures; error formatting must exclude secrets.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Host-owned admission evidence; never a web or message-derived native grant.
    type Authorization;

    /// Opens and verifies the exact conversation.
    fn load_conversation(&self, id: ConversationId) -> Result<StoredConversation, Self::Error>;
    /// Returns at most one authenticated live outbound membership operation.
    fn active_membership_outbox(&self, id: ConversationId) -> Result<Option<MembershipOutbox>, Self::Error>;
    /// Returns at most one authenticated incomplete inbound membership operation.
    fn active_membership_inbox(&self, id: ConversationId) -> Result<Option<MembershipInboxOperation>, Self::Error>;
    /// Opens the exact membership intent, rejecting scope/identity mismatch.
    fn load_membership_outbox(&self, id: MembershipOperationId) -> Result<MembershipOutbox, Self::Error>;
    /// Promotes the exact accepted next policy after verified MLS persistence.
    fn complete_membership_outbox(&self, id: MembershipOperationId) -> Result<(), Self::Error>;
    /// Terminalizes the exact operation after rejecting pending MLS state.
    fn orphan_membership_outbox(&self, id: MembershipOperationId) -> Result<(), Self::Error>;
    /// Atomically admits and reserves one new operation under current authority.
    fn reserve_application(&self, request: &NativeApplicationRequest<Self::Authorization>, envelope: EnvelopeId) -> Result<OutboundReservation, Self::Error>;
    /// Saves exact protected plaintext and sender metadata for one reservation.
    fn store_outbound_message(&self, reservation: OutboundReservation, route: RoutingId, sender: DeviceId, epoch: u64, message: &ApplicationMessage) -> Result<(), Self::Error>;
    /// Makes the exact sealed envelope ready before any network submission.
    fn store_outbound_envelope(&self, reservation: OutboundReservation, envelope: &RelayEnvelope) -> Result<(), Self::Error>;
    /// Abandons incomplete work without rolling back or reusing its counter.
    fn abandon_outbound_application(&self, reservation: OutboundReservation) -> Result<(), Self::Error>;
    /// Journals one exact ciphertext/cursor observation before decryption.
    fn record_inbox_envelope(&self, stored: &StoredRelayEnvelope) -> Result<ConversationId, Self::Error>;
    /// Opens the exact authenticated inbox state.
    fn inbox_operation(&self, id: ConversationId, cursor: u64) -> Result<InboxOperation, Self::Error>;
    /// Proves a local echo from immutable exact-envelope outbox evidence.
    fn outbound_history_message(&self, id: ConversationId, stored: &StoredRelayEnvelope) -> Result<Option<StoredApplicationMessage>, Self::Error>;
    /// Atomically saves protected plaintext and deduplication before MLS persistence.
    fn save_inbox_message(&self, id: ConversationId, cursor: u64, sender: DeviceId, epoch: u64, message: &ApplicationMessage) -> Result<(), Self::Error>;
    /// Atomically completes exact application evidence and contiguous notification.
    fn complete_inbox_with_notification_at(&self, id: ConversationId, cursor: u64, notification: NotificationId, now: u64) -> Result<u64, Self::Error>;
    /// Journals one exact membership ciphertext before processing.
    fn record_membership_inbox_envelope(&self, stored: &StoredRelayEnvelope) -> Result<ConversationId, Self::Error>;
    /// Finds exact outbound membership evidence, not merely a matching ID.
    fn membership_outbox_for_envelope(&self, id: EnvelopeId) -> Result<Option<MembershipOutbox>, Self::Error>;
    /// Records acceptance only for the exact journaled membership envelope.
    fn mark_membership_outbox_accepted(&self, stored: &StoredRelayEnvelope) -> Result<MembershipOperationId, Self::Error>;
    /// Completes an authenticated self-echo without attempting self-decryption.
    fn complete_membership_echo(&self, stored: &StoredRelayEnvelope, device: DeviceId) -> Result<MembershipOperationId, Self::Error>;
    /// Opens the exact authenticated membership inbox state.
    fn membership_inbox_operation(&self, id: ConversationId, cursor: u64) -> Result<MembershipInboxOperation, Self::Error>;
    /// Saves control and complete next policy before applying the MLS transition.
    fn save_membership_inbox_transition(&self, id: ConversationId, cursor: u64, sender: DeviceId, parent: u64, operation: MembershipOperationId, control: &[u8], next: &ConversationState, bindings: &[DeviceCredentialBinding]) -> Result<(), Self::Error>;
    /// Promotes verified next policy and completes only the contiguous cursor.
    fn complete_membership_inbox_with_notification(&self, id: ConversationId, cursor: u64, notification: NotificationId) -> Result<u64, Self::Error>;
    /// Saves complete protected outbound membership intent before transmission.
    fn store_membership_outbox(&self, operation: MembershipOperationId, id: ConversationId, parent: u64, envelope: &RelayEnvelope, control: &[u8], next: &ConversationState, bindings: &[DeviceCredentialBinding], welcome: Option<&[u8]>) -> Result<(), Self::Error>;
}
