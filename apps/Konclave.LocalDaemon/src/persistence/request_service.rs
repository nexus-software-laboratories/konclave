use super::*;
use KonclaveDomainCore::{
    RequestServiceError, RequestServiceReplyDecision, RequestServiceRequest,
    classify_request_service_reply,
};

impl ProfileStore {
    pub(super) fn initialize_request_service_schema(&self) -> Result<(), ProfileStoreError> {
        let version: u32 = self
            .lock()?
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        if version == PROFILE_SCHEMA_VERSION {
            self.profile_identity_for_schema_transition(version, version)?;
            return Ok(());
        }
        if version != 22 {
            return Err(ProfileStoreError::UnsupportedSchema);
        }
        let identity =
            self.profile_identity_for_schema_transition(version, PROFILE_SCHEMA_VERSION)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some(identity) = identity
            && transaction
                .execute(
                    "UPDATE daemon_profile SET sealed_device_identity = ?1
                     WHERE singleton_id = 1 AND sealed_device_identity IS NOT NULL",
                    params![identity.as_bytes()],
                )
                .map_err(|_| ProfileStoreError::Storage)?
                != 1
        {
            return Err(ProfileStoreError::CorruptData);
        }
        transaction
            .pragma_update(None, "user_version", PROFILE_SCHEMA_VERSION)
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    pub(crate) fn validate_request_service_application(
        &self,
        conversation_id: ConversationId,
        sender: DeviceId,
        content: &ApplicationContent,
        reply_to: Option<MessageId>,
        candidate_id: MessageId,
    ) -> Result<(), ProfileStoreError> {
        let conversation = self.load_conversation(conversation_id)?;
        let Some(channel) = conversation.state.request_service() else {
            return Ok(());
        };
        let original = if matches!(content, ApplicationContent::Text(_)) {
            match reply_to {
                Some(id) => {
                    let connection = self.lock()?;
                    self.load_history_record(
                        &connection,
                        conversation_id,
                        conversation.routing_id,
                        id,
                    )?
                }
                None => None,
            }
        } else {
            None
        };
        if let Some(original) = &original {
            if !original.complete {
                return Err(RequestServiceError::MissingRequest.into());
            }
            self.verify_history_cursor_binding(
                conversation_id,
                conversation.routing_id,
                original,
                original.cursor.ok_or(ProfileStoreError::CorruptData)?,
            )?;
            validate_reply_witness(original, candidate_id)?;
        }
        channel.validate_application(
            &conversation.state,
            sender,
            content,
            reply_to,
            original.as_ref().map(|original| RequestServiceRequest {
                conversation_id,
                authenticated_sender: original.sender,
                message: &original.message,
            }),
        )?;
        Ok(())
    }

    pub(super) fn request_service_state_in(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
    ) -> Result<ConversationState, ProfileStoreError> {
        let length: i64 = connection
            .query_row(
                "SELECT length(sealed_policy_state) FROM daemon_conversation
                 WHERE conversation_id = ?1 AND routing_id = ?2",
                params![conversation_id.as_bytes(), routing_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_policy_state FROM daemon_conversation WHERE conversation_id = ?1",
                params![conversation_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)? {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &conversation_record_context(
                    &self.locked_profile.profile_id,
                    SecretRecordKind::ConversationPolicyState,
                    conversation_id,
                    Some(routing_id),
                    None,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let state =
            decode_conversation_state(&plaintext).map_err(|_| ProfileStoreError::CorruptData)?;
        if state.conversation_id() != conversation_id {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(state)
    }

    pub(super) fn commit_request_service_reply_in(
        &self,
        connection: &Connection,
        state: &ConversationState,
        routing_id: RoutingId,
        sender: DeviceId,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        let Some(channel) = state.request_service() else {
            return Ok(());
        };
        if !matches!(message.content(), ApplicationContent::Text(_)) {
            channel.validate_application(
                state,
                sender,
                message.content(),
                message.reply_to(),
                None,
            )?;
            return Ok(());
        }
        let request_id = message
            .reply_to()
            .ok_or(RequestServiceError::UnsolicitedText)?;
        let original = self
            .load_history_record(connection, state.conversation_id(), routing_id, request_id)?
            .ok_or(RequestServiceError::MissingRequest)?;
        if !original.complete || original.cursor.is_none() {
            return Err(RequestServiceError::MissingRequest.into());
        }
        channel.validate_application(
            state,
            sender,
            message.content(),
            message.reply_to(),
            Some(RequestServiceRequest {
                conversation_id: state.conversation_id(),
                authenticated_sender: original.sender,
                message: &original.message,
            }),
        )?;
        if validate_reply_witness(&original, message.message_id())?
            == RequestServiceReplyDecision::Retry
        {
            return Ok(());
        }
        let plaintext = encode_history_message_record(
            original.direction,
            original.envelope_id,
            original.sender,
            original.epoch,
            &original.message,
            Some(RequestServiceHistoryReply::Complete(message.message_id())),
        )?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            state.conversation_id(),
            routing_id,
            MESSAGE_HISTORY_RECORD_SCOPE,
            request_id.as_bytes(),
            &plaintext,
        )?;
        if connection
            .execute(
                "UPDATE daemon_message_history SET sealed_message = ?1
             WHERE conversation_id = ?2 AND message_id = ?3 AND status = 2",
                params![
                    blob.as_bytes(),
                    state.conversation_id().as_bytes(),
                    request_id.as_bytes()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        Ok(())
    }
}

fn validate_reply_witness(
    original: &HistoryRecord,
    candidate: MessageId,
) -> Result<RequestServiceReplyDecision, ProfileStoreError> {
    let previous = match original.request_service_reply {
        Some(RequestServiceHistoryReply::Pending) => None,
        Some(RequestServiceHistoryReply::Complete(id)) => Some(id),
        None => return Err(ProfileStoreError::CorruptData),
    };
    classify_request_service_reply(previous, candidate).map_err(Into::into)
}
