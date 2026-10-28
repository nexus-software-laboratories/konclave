use KonclaveClientLibrary::native::{
    InboxOperation, MembershipInboxOperation, MembershipOutbox, NativeApplicationRequest,
    NativeConversationJournal, OutboundReservation, StoredApplicationMessage, StoredConversation,
};
use KonclaveDomainCore::{
    ApplicationMessage, ConversationId, ConversationState, DeviceCredentialBinding, DeviceId,
    EnvelopeId, MembershipOperationId, NotificationId, RelayEnvelope, RoutingId, StoredRelayEnvelope,
};

use crate::persistence::{CollaborationActionAuthorization, ProfileStore, ProfileStoreError};

impl NativeConversationJournal for ProfileStore {
    type Error = ProfileStoreError;
    type Authorization = CollaborationActionAuthorization;

    fn load_conversation(&self, id: ConversationId) -> Result<StoredConversation, Self::Error> {
        ProfileStore::load_conversation(self, id)
    }

    fn active_membership_outbox(
        &self,
        id: ConversationId,
    ) -> Result<Option<MembershipOutbox>, Self::Error> {
        ProfileStore::active_membership_outbox(self, id)
    }

    fn active_membership_inbox(
        &self,
        id: ConversationId,
    ) -> Result<Option<MembershipInboxOperation>, Self::Error> {
        ProfileStore::active_membership_inbox(self, id)
    }

    fn load_membership_outbox(
        &self,
        id: MembershipOperationId,
    ) -> Result<MembershipOutbox, Self::Error> {
        ProfileStore::load_membership_outbox(self, id)
    }

    fn complete_membership_outbox(&self, id: MembershipOperationId) -> Result<(), Self::Error> {
        ProfileStore::complete_membership_outbox(self, id)
    }

    fn orphan_membership_outbox(&self, id: MembershipOperationId) -> Result<(), Self::Error> {
        ProfileStore::orphan_membership_outbox(self, id)
    }

    fn reserve_application(
        &self,
        request: &NativeApplicationRequest<Self::Authorization>,
        envelope: EnvelopeId,
    ) -> Result<OutboundReservation, Self::Error> {
        if request.policy_operation {
            self.reserve_outbound_collaboration_policy_application(
                request.conversation_id, request.message_id, envelope, &request.content, request.reply_to,
            )
        } else if let Some(authorization) = request.authorization {
            self.reserve_outbound_collaboration_action(
                request.conversation_id, request.message_id, envelope, authorization,
                &request.content, request.reply_to, request.sent_at_unix_milliseconds,
                request.expires_at_unix_seconds,
            )
        } else {
            self.reserve_outbound_application(request.conversation_id, request.message_id, envelope)
        }
    }

    fn store_outbound_message(
        &self,
        reservation: OutboundReservation,
        route: RoutingId,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), Self::Error> {
        ProfileStore::store_outbound_message(self, reservation, route, sender, epoch, message)
    }

    fn store_outbound_envelope(
        &self,
        reservation: OutboundReservation,
        envelope: &RelayEnvelope,
    ) -> Result<(), Self::Error> {
        ProfileStore::store_outbound_envelope(self, reservation, envelope)
    }

    fn abandon_outbound_application(
        &self,
        reservation: OutboundReservation,
    ) -> Result<(), Self::Error> {
        ProfileStore::abandon_outbound_application(self, reservation)
    }

    fn record_inbox_envelope(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, Self::Error> {
        ProfileStore::record_inbox_envelope(self, stored)
    }

    fn inbox_operation(
        &self,
        id: ConversationId,
        cursor: u64,
    ) -> Result<InboxOperation, Self::Error> {
        ProfileStore::inbox_operation(self, id, cursor)
    }

    fn outbound_history_message(
        &self,
        id: ConversationId,
        stored: &StoredRelayEnvelope,
    ) -> Result<Option<StoredApplicationMessage>, Self::Error> {
        ProfileStore::outbound_history_message(self, id, stored)
    }

    fn save_inbox_message(
        &self,
        id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), Self::Error> {
        ProfileStore::save_inbox_message(self, id, cursor, sender, epoch, message)
    }

    fn complete_inbox_with_notification_at(
        &self,
        id: ConversationId,
        cursor: u64,
        notification: NotificationId,
        now: u64,
    ) -> Result<u64, Self::Error> {
        ProfileStore::complete_inbox_with_notification_at(self, id, cursor, notification, now)
    }

    fn record_membership_inbox_envelope(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, Self::Error> {
        ProfileStore::record_membership_inbox_envelope(self, stored)
    }

    fn membership_outbox_for_envelope(
        &self,
        id: EnvelopeId,
    ) -> Result<Option<MembershipOutbox>, Self::Error> {
        ProfileStore::membership_outbox_for_envelope(self, id)
    }

    fn mark_membership_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<MembershipOperationId, Self::Error> {
        ProfileStore::mark_membership_outbox_accepted(self, stored)
    }

    fn complete_membership_echo(
        &self,
        stored: &StoredRelayEnvelope,
        device: DeviceId,
    ) -> Result<MembershipOperationId, Self::Error> {
        ProfileStore::complete_membership_echo(self, stored, device)
    }

    fn membership_inbox_operation(
        &self,
        id: ConversationId,
        cursor: u64,
    ) -> Result<MembershipInboxOperation, Self::Error> {
        ProfileStore::membership_inbox_operation(self, id, cursor)
    }

    fn save_membership_inbox_transition(
        &self,
        id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        parent: u64,
        operation: MembershipOperationId,
        control: &[u8],
        next: &ConversationState,
        bindings: &[DeviceCredentialBinding],
    ) -> Result<(), Self::Error> {
        ProfileStore::save_membership_inbox_transition(self, id, cursor, sender, parent, operation, control, next, bindings)
    }

    fn complete_membership_inbox_with_notification(
        &self,
        id: ConversationId,
        cursor: u64,
        notification: NotificationId,
    ) -> Result<u64, Self::Error> {
        ProfileStore::complete_membership_inbox_with_notification(self, id, cursor, notification)
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
    ) -> Result<(), Self::Error> {
        ProfileStore::store_membership_outbox(self, operation, id, parent, envelope, control, next, bindings, welcome)
    }
}
