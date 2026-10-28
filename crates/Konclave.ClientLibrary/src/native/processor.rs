use std::sync::Mutex;

use KonclaveCryptographicCore::{
    DeviceIdentity, KonclaveCryptographicError, MlsApplicationMessage, MlsCommit, MlsConversation,
    MlsConversationClient, OutboundMembershipCommit, verify_collaboration_policy_proposal,
    verify_device_credential_binding,
};
use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, ConversationId, ConversationRole, ConversationState,
    DeliveryClass, DeviceId, EnvelopeId, JoinProof, MembershipOperationId, MessageId,
    NotificationId, ProtocolVersion, RelayEnvelope, RoutingId, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_membership_commit_bundle, decode_membership_control,
    encode_application_message, encode_membership_control,
};
use thiserror::Error;
use zeroize::Zeroizing;

use super::journal::*;

/// Scoped durable processing for one explicitly owned native endpoint.
///
/// The host must hold its exclusive operation lease for this processor's entire
/// lifetime, and fence both journal and MLS writes against the same writer.
/// Calls are synchronous and must run on a bounded blocking executor. The
/// processor starts no tasks, selects no custody and never opens a local profile.
pub struct NativeConversationProcessor<'a, J> {
    store: &'a J,
    mls_storage: KonclaveSecretStorage::SealedMlsStorageHandle,
    device: &'a Mutex<DeviceIdentity>,
}

impl<'a, J: NativeConversationJournal> NativeConversationProcessor<'a, J> {
    /// Borrows explicitly owned journals, sealed MLS storage and native identity.
    ///
    /// Hold the endpoint's exclusive operation lease before calling this method;
    /// sharing storage does not create cross-process ownership or native authority.
    pub fn new(
        journal: &'a J,
        mls_storage: impl Into<KonclaveSecretStorage::SealedMlsStorageHandle>,
        device: &'a Mutex<DeviceIdentity>,
    ) -> Self {
        Self {
            store: journal,
            mls_storage: mls_storage.into(),
            device,
        }
    }

    fn device_id(&self) -> Result<DeviceId, NativeConversationError<J::Error>> {
        self.device
            .lock()
            .map(|device| device.device_id())
            .map_err(|_| NativeConversationError::StateUnavailable)
    }

    fn generate_notification_id(
        &self,
    ) -> Result<NotificationId, NativeConversationError<J::Error>> {
        self.device
            .lock()
            .map_err(|_| NativeConversationError::StateUnavailable)?
            .generate_notification_id()
            .map_err(|_| NativeConversationError::Cryptographic)
    }

    /// Atomically admits a new operation, then persists its exact ciphertext.
    ///
    /// Current authority/claim validation is part of `reserve_application`, not
    /// an earlier callback. Failure after reservation preserves a permanent gap.
    ///
    /// # Errors
    ///
    /// Returns admission, journal, protocol or cryptographic failure.
    pub fn prepare_application(
        &mut self,
        request: NativeApplicationRequest<J::Authorization>,
    ) -> Result<PreparedApplication, NativeConversationError<J::Error>> {
        if let ApplicationContent::DirectedRequest(directed) = &request.content {
            let stored = self.store.load_conversation(request.conversation_id)?;
            let local = self.device_id()?;
            if !directed_request_recipients_support(
                &stored.state,
                local,
                directed.target_device_id(),
                |device| {
                    stored.bindings.iter().any(|binding| {
                        binding.binding().device_id() == device
                            && binding.binding().supports_directed_requests()
                    })
                },
            ) {
                return Err(NativeConversationError::DirectedRequestUnsupported);
            }
        }
        let envelope = self
            .device
            .lock()
            .map_err(|_| NativeConversationError::StateUnavailable)?
            .generate_envelope_id()
            .map_err(|_| NativeConversationError::Cryptographic)?;
        let reservation = self.store.reserve_application(&request, envelope)?;
        match self.prepare_reserved_application(
            reservation,
            request.content,
            request.reply_to,
            request.sent_at_unix_milliseconds,
            request.expires_at_unix_seconds,
        ) {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                self.store.abandon_outbound_application(reservation)?;
                Err(error)
            }
        }
    }
    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn open(
        &mut self,
        conversation_id: ConversationId,
    ) -> Result<OpenConversation, NativeConversationError<J::Error>> {
        let stored = self.store.load_conversation(conversation_id)?;
        let pending = self.store.active_membership_outbox(conversation_id)?;
        let inbound = self.store.active_membership_inbox(conversation_id)?;
        let has_group = self
            .mls_storage
            .contains_group(conversation_id.as_bytes())
            .map_err(|_| NativeConversationError::SecretStorage)?;
        if let Some(MembershipInboxOperation::TransitionSaved(transition)) = inbound {
            if pending.is_some() || !has_group || transition.parent_epoch != stored.state.epoch() {
                return Err(NativeConversationError::StateMismatch);
            }
            let routing_id = stored.routing_id;
            let replay_cursor = stored.replay_cursor;
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| NativeConversationError::Cryptographic)?;
            if let Ok(group) = client.restore_group(stored.state, stored.bindings, None) {
                return Ok(OpenConversation {
                    routing_id,
                    replay_cursor,
                    group,
                });
            }
            let stored = self.store.load_conversation(conversation_id)?;
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| NativeConversationError::Cryptographic)?;
            let group = client
                .restore_group(transition.next_state, transition.bindings, None)
                .map_err(|_| NativeConversationError::Cryptographic)?;
            let notification_id = self.generate_notification_id()?;
            let replay_cursor = self.store.complete_membership_inbox_with_notification(
                conversation_id,
                transition.stored.cursor(),
                notification_id,
            )?;
            return Ok(OpenConversation {
                routing_id,
                replay_cursor,
                group,
            });
        }
        let group = if !has_group {
            if pending.is_some() {
                return Err(NativeConversationError::MissingMlsState);
            }
            if stored.state.epoch() != 0 {
                return Err(NativeConversationError::MissingMlsState);
            }
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| NativeConversationError::Cryptographic)?;
            let expected_state = stored.state;
            let group = client
                .create_group()
                .map_err(|_| NativeConversationError::Cryptographic)?;
            if group.state() != &expected_state {
                return Err(NativeConversationError::StateMismatch);
            }
            group
        } else if let Some(pending) = pending {
            if pending.parent_epoch != stored.state.epoch()
                || pending.parent_epoch.checked_add(1) != Some(pending.next_state.epoch())
            {
                return Err(NativeConversationError::StateMismatch);
            }
            let operation_id = pending.operation_id;
            let status = pending.status;
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| NativeConversationError::Cryptographic)?;
            match client.restore_group(stored.state, pending.bindings, Some(pending.next_state)) {
                Ok(mut group) => {
                    if status == MembershipOutboxStatus::Accepted {
                        group
                            .accept_pending_commit()
                            .map_err(|_| NativeConversationError::Cryptographic)?;
                        self.store.complete_membership_outbox(operation_id)?;
                    }
                    group
                }
                Err(_) if status == MembershipOutboxStatus::Accepted => {
                    let stored = self.store.load_conversation(conversation_id)?;
                    let pending = self.store.load_membership_outbox(operation_id)?;
                    let client = MlsConversationClient::with_storage(
                        stored.signing_material,
                        self.mls_storage.clone(),
                    )
                    .map_err(|_| NativeConversationError::Cryptographic)?;
                    let group = client
                        .restore_group(pending.next_state, pending.bindings, None)
                        .map_err(|_| NativeConversationError::Cryptographic)?;
                    self.store.complete_membership_outbox(operation_id)?;
                    group
                }
                Err(_) if status == MembershipOutboxStatus::Ready => {
                    let stored = self.store.load_conversation(conversation_id)?;
                    let client = MlsConversationClient::with_storage(
                        stored.signing_material,
                        self.mls_storage.clone(),
                    )
                    .map_err(|_| NativeConversationError::Cryptographic)?;
                    let group = client
                        .restore_group(stored.state, stored.bindings, None)
                        .map_err(|_| NativeConversationError::Cryptographic)?;
                    if group.has_pending_membership_commit() {
                        return Err(NativeConversationError::StateMismatch);
                    }
                    self.store.orphan_membership_outbox(operation_id)?;
                    group
                }
                Err(_) => return Err(NativeConversationError::StateMismatch),
            }
        } else {
            let client = MlsConversationClient::with_storage(
                stored.signing_material,
                self.mls_storage.clone(),
            )
            .map_err(|_| NativeConversationError::Cryptographic)?;
            let group = client
                .restore_group(stored.state, stored.bindings, None)
                .map_err(|_| NativeConversationError::Cryptographic)?;
            if group.has_pending_membership_commit() {
                return Err(NativeConversationError::MissingMembershipJournal);
            }
            group
        };
        Ok(OpenConversation {
            routing_id: stored.routing_id,
            replay_cursor: stored.replay_cursor,
            group,
        })
    }

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn prepare_reserved_application(
        &mut self,
        reservation: OutboundReservation,
        content: ApplicationContent,
        reply_to: Option<MessageId>,
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedApplication, NativeConversationError<J::Error>> {
        verify_application_content(&content)?;
        let message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            reservation.message_id,
            reservation.sender_counter,
            sent_at_unix_milliseconds,
            reply_to,
            content,
        )
        .map_err(|_| NativeConversationError::Protocol)?;
        let plaintext = Zeroizing::new(
            encode_application_message(&message).map_err(|_| NativeConversationError::Protocol)?,
        );
        let mut conversation = self.open(reservation.conversation_id)?;
        let sender = self.device_id()?;
        let epoch = conversation.group.epoch();
        let ciphertext = conversation
            .group
            .encrypt_application_message(&plaintext)
            .map_err(|_| NativeConversationError::Cryptographic)?;
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            conversation.routing_id,
            reservation.envelope_id,
            DeliveryClass::GroupApplication,
            None,
            expires_at_unix_seconds,
            ciphertext.into_bytes(),
        )
        .map_err(|_| NativeConversationError::Protocol)?;
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

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn prepare_add_member(
        &mut self,
        conversation_id: ConversationId,
        join_proof: JoinProof,
        now_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedMembership, NativeConversationError<J::Error>> {
        self.prepare_membership(
            conversation_id,
            expires_at_unix_seconds,
            |group, envelope_id| group.create_add_commit(join_proof, envelope_id, now_unix_seconds),
        )
    }

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn prepare_remove_member(
        &mut self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedMembership, NativeConversationError<J::Error>> {
        self.prepare_membership(conversation_id, expires_at_unix_seconds, |group, _| {
            group.create_remove_commit(device_id)
        })
    }

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn prepare_change_role(
        &mut self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        role: ConversationRole,
        expires_at_unix_seconds: u64,
    ) -> Result<PreparedMembership, NativeConversationError<J::Error>> {
        self.prepare_membership(conversation_id, expires_at_unix_seconds, |group, _| {
            group.create_change_role_commit(device_id, role)
        })
    }

    fn prepare_membership(
        &mut self,
        conversation_id: ConversationId,
        expires_at_unix_seconds: u64,
        create: impl FnOnce(
            &mut MlsConversation,
            EnvelopeId,
        ) -> Result<OutboundMembershipCommit, KonclaveCryptographicError>,
    ) -> Result<PreparedMembership, NativeConversationError<J::Error>> {
        let envelope_id = self
            .device
            .lock()
            .map_err(|_| NativeConversationError::StateUnavailable)?
            .generate_envelope_id()
            .map_err(|_| NativeConversationError::Cryptographic)?;
        let mut conversation = self.open(conversation_id)?;
        let parent_epoch = conversation.group.epoch();
        let outbound = create(&mut conversation.group, envelope_id)
            .map_err(|_| NativeConversationError::Cryptographic)?;
        let operation_id = outbound.authorization().operation_id();
        let control = Zeroizing::new(
            encode_membership_control(outbound.authorization(), outbound.join_proof())
                .map_err(|_| NativeConversationError::Protocol)?,
        );
        let payload = outbound
            .encode_bundle()
            .map_err(|_| NativeConversationError::Protocol)?;
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            conversation.routing_id,
            envelope_id,
            DeliveryClass::GroupCommit,
            Some(parent_epoch),
            expires_at_unix_seconds,
            payload,
        )
        .map_err(|_| NativeConversationError::Protocol)?;
        let stored = self.store.load_conversation(conversation_id)?;
        let mut bindings = stored
            .bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        if let Some(join_proof) = outbound.join_proof() {
            let binding = join_proof.credential().clone();
            verify_device_credential_binding(&binding)
                .map_err(|_| NativeConversationError::Cryptographic)?;
            if !bindings
                .iter()
                .any(|existing| existing.device_id() == binding.device_id())
            {
                bindings.push(binding);
            }
        }
        let welcome = outbound
            .welcome()
            .map(|welcome| welcome.as_bytes().to_vec());
        let journaled = self.store.store_membership_outbox(
            operation_id,
            conversation_id,
            parent_epoch,
            &envelope,
            &control,
            outbound.next_state(),
            &bindings,
            welcome.as_deref(),
        );
        if let Err(error) = journaled {
            conversation
                .group
                .reject_pending_commit()
                .map_err(|_| NativeConversationError::Cryptographic)?;
            return Err(error.into());
        }
        Ok(PreparedMembership {
            operation_id,
            conversation_id,
            parent_epoch,
            envelope,
            welcome,
        })
    }

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn orphan_membership(
        &mut self,
        operation_id: MembershipOperationId,
    ) -> Result<(), NativeConversationError<J::Error>> {
        let initial = self.store.load_membership_outbox(operation_id)?;
        let mut conversation = self.open(initial.conversation_id)?;
        let pending = self.store.load_membership_outbox(operation_id)?;
        if pending.status == MembershipOutboxStatus::Orphaned {
            return if conversation.group.has_pending_membership_commit() {
                Err(NativeConversationError::StateMismatch)
            } else {
                Ok(())
            };
        }
        if pending.status != MembershipOutboxStatus::Ready
            || conversation.group.state().epoch() != pending.parent_epoch
        {
            return Err(NativeConversationError::StateMismatch);
        }
        if conversation.group.has_pending_membership_commit() {
            conversation
                .group
                .reject_pending_commit()
                .map_err(|_| NativeConversationError::Cryptographic)?;
        }
        self.store.orphan_membership_outbox(operation_id)?;
        Ok(())
    }

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn process_inbound_application(
        &mut self,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<ProcessedApplication, NativeConversationError<J::Error>> {
        let mut conversation = self.open(conversation_id)?;
        if conversation.routing_id != stored.envelope().routing_id() {
            return Err(NativeConversationError::StateMismatch);
        }
        let recorded_conversation = self.store.record_inbox_envelope(stored)?;
        if recorded_conversation != conversation_id {
            return Err(NativeConversationError::StateMismatch);
        }
        match self
            .store
            .inbox_operation(conversation_id, stored.cursor())?
        {
            InboxOperation::Received { stored } => {
                if let Some(outbound) = self
                    .store
                    .outbound_history_message(conversation_id, &stored)?
                {
                    self.store.save_inbox_message(
                        conversation_id,
                        stored.cursor(),
                        outbound.sender,
                        outbound.epoch,
                        &outbound.message,
                    )?;
                    let notification_id = self.generate_notification_id()?;
                    self.store.complete_inbox_with_notification_at(
                        conversation_id,
                        stored.cursor(),
                        notification_id,
                        now_unix_seconds,
                    )?;
                    return Ok(ProcessedApplication {
                        conversation_id,
                        cursor: stored.cursor(),
                        envelope_id: stored.envelope().envelope_id(),
                        sender: outbound.sender,
                        epoch: outbound.epoch,
                        message: outbound.message,
                        direction: MessageDirection::Outbound,
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
                    .map_err(|_| NativeConversationError::Cryptographic)?;
                let notification_id = self.generate_notification_id()?;
                self.store.complete_inbox_with_notification_at(
                    conversation_id,
                    stored.cursor(),
                    notification_id,
                    now_unix_seconds,
                )?;
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    envelope_id: stored.envelope().envelope_id(),
                    sender,
                    epoch,
                    message,
                    direction: MessageDirection::Inbound,
                    duplicate: false,
                })
            }
            InboxOperation::MessageSaved { stored, message } => {
                if let Some(outbound) = self
                    .store
                    .outbound_history_message(conversation_id, &stored)?
                {
                    if outbound.sender != message.sender
                        || outbound.epoch != message.epoch
                        || !application_messages_equal(&outbound.message, &message.message)?
                    {
                        return Err(NativeConversationError::StateMismatch);
                    }
                    let notification_id = self.generate_notification_id()?;
                    self.store.complete_inbox_with_notification_at(
                        conversation_id,
                        stored.cursor(),
                        notification_id,
                        now_unix_seconds,
                    )?;
                    return Ok(ProcessedApplication {
                        conversation_id,
                        cursor: stored.cursor(),
                        envelope_id: stored.envelope().envelope_id(),
                        sender: message.sender,
                        epoch: message.epoch,
                        message: message.message,
                        direction: MessageDirection::Outbound,
                        duplicate: true,
                    });
                }
                if conversation.group.epoch() != message.epoch {
                    return Err(NativeConversationError::StateMismatch);
                }
                let ciphertext = MlsApplicationMessage::from_bytes(stored.envelope().payload())
                    .map_err(|_| NativeConversationError::Cryptographic)?;
                match conversation.group.decrypt_application_message(&ciphertext) {
                    Ok(decrypted) => {
                        let decoded = decode_application_message(decrypted.plaintext())
                            .map_err(|_| NativeConversationError::Protocol)?;
                        if decrypted.authenticated_sender() != message.sender
                            || !application_messages_equal(&decoded, &message.message)?
                        {
                            return Err(NativeConversationError::StateMismatch);
                        }
                        conversation
                            .group
                            .persist()
                            .map_err(|_| NativeConversationError::Cryptographic)?;
                    }
                    Err(KonclaveCryptographicError::ApplicationMessageAlreadyProcessed) => {}
                    Err(_) => {
                        return Err(NativeConversationError::Cryptographic);
                    }
                }
                let notification_id = self.generate_notification_id()?;
                self.store.complete_inbox_with_notification_at(
                    conversation_id,
                    stored.cursor(),
                    notification_id,
                    now_unix_seconds,
                )?;
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    envelope_id: stored.envelope().envelope_id(),
                    sender: message.sender,
                    epoch: message.epoch,
                    message: message.message,
                    direction: MessageDirection::Inbound,
                    duplicate: true,
                })
            }
            InboxOperation::Complete { stored, message } => {
                let direction = if self
                    .store
                    .outbound_history_message(conversation_id, &stored)?
                    .is_some()
                {
                    MessageDirection::Outbound
                } else {
                    MessageDirection::Inbound
                };
                Ok(ProcessedApplication {
                    conversation_id,
                    cursor: stored.cursor(),
                    envelope_id: stored.envelope().envelope_id(),
                    sender: message.sender,
                    epoch: message.epoch,
                    message: message.message,
                    direction,
                    duplicate: true,
                })
            }
        }
    }

    /// Executes the existing native journal/MLS recovery ordering.
    ///
    /// # Errors
    ///
    /// Returns exact journal, protocol, MLS, or checkpoint mismatch failures.
    pub fn process_inbound_membership(
        &mut self,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<ProcessedMembership, NativeConversationError<J::Error>> {
        let recorded_conversation = self.store.record_membership_inbox_envelope(stored)?;
        if recorded_conversation != conversation_id {
            return Err(NativeConversationError::StateMismatch);
        }
        if let Some(outbox) = self
            .store
            .membership_outbox_for_envelope(stored.envelope().envelope_id())?
        {
            if outbox.envelope != *stored.envelope() || outbox.conversation_id != conversation_id {
                return Err(NativeConversationError::StateMismatch);
            }
            if outbox.status == MembershipOutboxStatus::Ready {
                self.store.mark_membership_outbox_accepted(stored)?;
            }
            let conversation = self.open(conversation_id)?;
            if conversation.group.state() != &outbox.next_state {
                return Err(NativeConversationError::StateMismatch);
            }
            let operation_id = self
                .store
                .complete_membership_echo(stored, self.device_id()?)?;
            return Ok(ProcessedMembership {
                conversation_id,
                cursor: stored.cursor(),
                operation_id,
                sender: self.device_id()?,
                epoch: outbox.next_state.epoch(),
                removed_self: outbox.next_state.member(self.device_id()?).is_none(),
                duplicate: true,
            });
        }
        if let Some(local) = self.store.active_membership_outbox(conversation_id)? {
            if local.parent_epoch
                == stored
                    .envelope()
                    .expected_parent_epoch()
                    .unwrap_or(u64::MAX)
                && local.status == MembershipOutboxStatus::Ready
            {
                self.orphan_membership(local.operation_id)?;
            } else {
                return Err(NativeConversationError::StateMismatch);
            }
        }
        match self
            .store
            .membership_inbox_operation(conversation_id, stored.cursor())?
        {
            MembershipInboxOperation::Received { stored } => {
                let mut conversation = self.open(conversation_id)?;
                if conversation.routing_id != stored.envelope().routing_id()
                    || conversation.group.epoch()
                        != stored
                            .envelope()
                            .expected_parent_epoch()
                            .ok_or(NativeConversationError::Protocol)?
                {
                    return Err(NativeConversationError::StateMismatch);
                }
                let bundle = decode_membership_commit_bundle(stored.envelope().payload())
                    .map_err(|_| NativeConversationError::Protocol)?;
                let encrypted_control =
                    MlsApplicationMessage::from_bytes(bundle.encrypted_control())
                        .map_err(|_| NativeConversationError::Cryptographic)?;
                let decrypted = conversation
                    .group
                    .decrypt_application_message(&encrypted_control)
                    .map_err(|_| NativeConversationError::Cryptographic)?;
                let sender = decrypted.authenticated_sender();
                let (authorization, join_proof) = decode_membership_control(decrypted.plaintext())
                    .map_err(|_| NativeConversationError::Protocol)?;
                let next_epoch = conversation
                    .group
                    .epoch()
                    .checked_add(1)
                    .ok_or(NativeConversationError::StateMismatch)?;
                let next_state = conversation
                    .group
                    .state()
                    .apply_membership_authorization(sender, &authorization, next_epoch)
                    .map_err(|_| NativeConversationError::StateMismatch)?;
                let current = self.store.load_conversation(conversation_id)?;
                let mut bindings = current
                    .bindings
                    .iter()
                    .map(|binding| binding.binding().clone())
                    .collect::<Vec<_>>();
                if let Some(proof) = &join_proof {
                    let binding = proof.credential().clone();
                    verify_device_credential_binding(&binding)
                        .map_err(|_| NativeConversationError::Cryptographic)?;
                    if !bindings
                        .iter()
                        .any(|existing| existing.device_id() == binding.device_id())
                    {
                        bindings.push(binding);
                    }
                }
                self.store.save_membership_inbox_transition(
                    conversation_id,
                    stored.cursor(),
                    sender,
                    authorization.parent_epoch(),
                    authorization.operation_id(),
                    decrypted.plaintext(),
                    &next_state,
                    &bindings,
                )?;
                let transition = match self
                    .store
                    .membership_inbox_operation(conversation_id, stored.cursor())?
                {
                    MembershipInboxOperation::TransitionSaved(transition) => transition,
                    _ => return Err(NativeConversationError::StateMismatch),
                };
                self.process_saved_membership(
                    &mut conversation.group,
                    transition,
                    now_unix_seconds,
                    false,
                )
            }
            MembershipInboxOperation::TransitionSaved(_transition) => {
                let mut conversation = self.open(conversation_id)?;
                match self
                    .store
                    .membership_inbox_operation(conversation_id, stored.cursor())?
                {
                    MembershipInboxOperation::Complete(complete) => {
                        Ok(processed_membership(complete, self.device_id()?, true))
                    }
                    MembershipInboxOperation::TransitionSaved(saved) => self
                        .process_saved_membership(
                            &mut conversation.group,
                            saved,
                            now_unix_seconds,
                            true,
                        ),
                    _ => Err(NativeConversationError::StateMismatch),
                }
            }
            MembershipInboxOperation::Complete(transition) => {
                Ok(processed_membership(transition, self.device_id()?, true))
            }
        }
    }

    fn process_saved_membership(
        &mut self,
        group: &mut MlsConversation,
        transition: StoredMembershipTransition,
        now_unix_seconds: u64,
        duplicate: bool,
    ) -> Result<ProcessedMembership, NativeConversationError<J::Error>> {
        if group.epoch() != transition.parent_epoch {
            return Err(NativeConversationError::StateMismatch);
        }
        let bundle = decode_membership_commit_bundle(transition.stored.envelope().payload())
            .map_err(|_| NativeConversationError::Protocol)?;
        if duplicate {
            let encrypted_control = MlsApplicationMessage::from_bytes(bundle.encrypted_control())
                .map_err(|_| NativeConversationError::Cryptographic)?;
            let decrypted = group
                .decrypt_application_message(&encrypted_control)
                .map_err(|_| NativeConversationError::Cryptographic)?;
            if decrypted.authenticated_sender() != transition.sender
                || decrypted.plaintext() != transition.control.as_slice()
            {
                return Err(NativeConversationError::StateMismatch);
            }
        }
        let commit = MlsCommit::from_bytes(bundle.mls_commit())
            .map_err(|_| NativeConversationError::Cryptographic)?;
        let (authorization, join_proof) = decode_membership_control(&transition.control)
            .map_err(|_| NativeConversationError::Protocol)?;
        let applied = group
            .process_membership_commit(&commit, authorization, join_proof, now_unix_seconds)
            .map_err(|_| NativeConversationError::Cryptographic)?;
        if applied.authenticated_sender() != transition.sender
            || applied.epoch() != transition.next_state.epoch()
            || group.state() != &transition.next_state
        {
            return Err(NativeConversationError::StateMismatch);
        }
        let notification_id = self.generate_notification_id()?;
        self.store.complete_membership_inbox_with_notification(
            transition.next_state.conversation_id(),
            transition.stored.cursor(),
            notification_id,
        )?;
        Ok(ProcessedMembership {
            conversation_id: transition.next_state.conversation_id(),
            cursor: transition.stored.cursor(),
            operation_id: transition.operation_id,
            sender: transition.sender,
            epoch: applied.epoch(),
            removed_self: applied.removed_self(),
            duplicate,
        })
    }
}

/// Stable failures from native processing without secret-bearing diagnostics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeConversationError<E> {
    /// The host adapter rejected or failed an operation.
    #[error("native journal operation failed")]
    Journal(#[from] E),
    /// Cryptographic processing or verified recovery failed.
    #[error("native cryptographic operation failed")]
    Cryptographic,
    /// Explicit sealed storage was unavailable or failed authentication.
    #[error("sealed MLS storage operation failed")]
    SecretStorage,
    /// The native identity owner was poisoned.
    #[error("native identity owner is unavailable")]
    StateUnavailable,
    /// Advanced policy has no recoverable sealed MLS group.
    #[error("advanced conversation is missing sealed MLS state")]
    MissingMlsState,
    /// Pending MLS state has no exact durable membership intent.
    #[error("pending MLS state has no membership journal")]
    MissingMembershipJournal,
    /// Authenticated durable observations disagree.
    #[error("native checkpoints disagree")]
    StateMismatch,
    /// Application or membership encoding is invalid.
    #[error("native protocol construction failed")]
    Protocol,
    /// A target or current remote member does not support directed requests.
    #[error("directed request target or member is unsupported")]
    DirectedRequestUnsupported,
}

/// Authenticated native operation result; retained inside the endpoint.
pub struct PreparedApplication {
    /// Exact authenticated operation field.
    pub conversation_id: ConversationId,
    /// Exact authenticated operation field.
    pub message: ApplicationMessage,
    /// Exact authenticated operation field.
    pub envelope: RelayEnvelope,
}

/// Authenticated native operation result; retained inside the endpoint.
pub struct PreparedMembership {
    /// Exact authenticated operation field.
    pub operation_id: MembershipOperationId,
    /// Exact authenticated operation field.
    pub conversation_id: ConversationId,
    /// Exact authenticated operation field.
    pub parent_epoch: u64,
    /// Exact authenticated operation field.
    pub envelope: RelayEnvelope,
    /// Exact authenticated operation field.
    pub welcome: Option<Vec<u8>>,
}

/// Authenticated native operation result; retained inside the endpoint.
pub struct ProcessedApplication {
    /// Exact authenticated operation field.
    pub conversation_id: ConversationId,
    /// Exact authenticated operation field.
    pub cursor: u64,
    /// Exact authenticated operation field.
    pub envelope_id: EnvelopeId,
    /// Exact authenticated operation field.
    pub sender: DeviceId,
    /// Exact authenticated operation field.
    pub epoch: u64,
    /// Exact authenticated operation field.
    pub message: ApplicationMessage,
    /// Exact authenticated operation field.
    pub direction: MessageDirection,
    /// Exact authenticated operation field.
    pub duplicate: bool,
}

/// Authenticated native operation result; retained inside the endpoint.
pub struct ProcessedMembership {
    /// Exact authenticated operation field.
    pub conversation_id: ConversationId,
    /// Exact authenticated operation field.
    pub cursor: u64,
    /// Exact authenticated operation field.
    pub operation_id: MembershipOperationId,
    /// Exact authenticated operation field.
    pub sender: DeviceId,
    /// Exact authenticated operation field.
    pub epoch: u64,
    /// Exact authenticated operation field.
    pub removed_self: bool,
    /// Exact authenticated operation field.
    pub duplicate: bool,
}

/// Authenticated native operation result; retained inside the endpoint.
pub struct OpenConversation {
    /// Exact authenticated operation field.
    pub routing_id: RoutingId,
    /// Exact authenticated operation field.
    pub replay_cursor: u64,
    /// Exact authenticated operation field.
    pub group: MlsConversation,
}

fn processed_membership(
    transition: StoredMembershipTransition,
    self_device_id: DeviceId,
    duplicate: bool,
) -> ProcessedMembership {
    let self_removed = transition.next_state.member(self_device_id).is_none();
    ProcessedMembership {
        conversation_id: transition.next_state.conversation_id(),
        cursor: transition.stored.cursor(),
        operation_id: transition.operation_id,
        sender: transition.sender,
        epoch: transition.next_state.epoch(),
        removed_self: self_removed,
        duplicate,
    }
}

/// Classifies whether the exact target and every current remote member support requests.
pub fn directed_request_recipients_support(
    state: &ConversationState,
    local_device: DeviceId,
    target: DeviceId,
    mut supports_directed_requests: impl FnMut(DeviceId) -> bool,
) -> bool {
    target != local_device
        && state.member(target).is_some()
        && state
            .members()
            .iter()
            .map(|member| member.device_id())
            .filter(|device_id| *device_id != local_device)
            .all(&mut supports_directed_requests)
}

/// Decrypts and validates one native application against its MLS-authenticated sender.
///
/// # Errors
///
/// Returns protocol or cryptographic failure without completing journal state.
pub fn decrypt_application<E>(
    group: &mut MlsConversation,
    envelope: &RelayEnvelope,
) -> Result<(DeviceId, ApplicationMessage), NativeConversationError<E>> {
    if envelope.delivery_class() != DeliveryClass::GroupApplication {
        return Err(NativeConversationError::Protocol);
    }
    let ciphertext = MlsApplicationMessage::from_bytes(envelope.payload())
        .map_err(|_| NativeConversationError::Cryptographic)?;
    let decrypted = group
        .decrypt_application_message(&ciphertext)
        .map_err(|_| NativeConversationError::Cryptographic)?;
    let sender = decrypted.authenticated_sender();
    let message = decode_application_message(decrypted.plaintext())
        .map_err(|_| NativeConversationError::Protocol)?;
    verify_application_content(message.content())?;
    Ok((sender, message))
}

/// Verifies authenticated content that carries an independently signed policy proposal.
///
/// # Errors
///
/// Returns cryptographic failure for a contradictory signature or canonical digest.
pub fn verify_application_content<E>(
    content: &ApplicationContent,
) -> Result<(), NativeConversationError<E>> {
    if let ApplicationContent::CollaborationPolicyProposal(proposal) = content {
        verify_collaboration_policy_proposal(proposal)
            .map_err(|_| NativeConversationError::Cryptographic)?;
    }
    Ok(())
}

fn application_messages_equal<E>(
    left: &ApplicationMessage,
    right: &ApplicationMessage,
) -> Result<bool, NativeConversationError<E>> {
    let left = Zeroizing::new(
        encode_application_message(left).map_err(|_| NativeConversationError::Protocol)?,
    );
    let right = Zeroizing::new(
        encode_application_message(right).map_err(|_| NativeConversationError::Protocol)?,
    );
    Ok(left == right)
}
