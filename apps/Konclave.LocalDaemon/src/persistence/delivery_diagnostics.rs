use KonclaveDomainCore::{
    ApplicationContent, ConversationId, LocalDeliveryObservation, MessageDeliveryObservation,
    MessageDeliveryStatus, MessageId, OutboundDeliveryObservation, RequestHandlingObservation,
    classify_message_delivery,
};
use rusqlite::{OptionalExtension, params};

use super::{
    HistoryRecord, MessageDirection, OutboundApplicationStatus, ProfileStore, ProfileStoreError,
    RemoteEventKind, RemoteEventStatus, from_sql_integer, to_sql_integer,
};

impl ProfileStore {
    /// Reads one bounded authenticated message's local delivery evidence.
    ///
    /// This operation never mutates delivery, renews a lease, or probes the relay.
    /// Internal messages and unsealed reservations have no inspectable outcome.
    pub(crate) fn message_delivery_status(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        now_unix_milliseconds: u64,
    ) -> Result<MessageDeliveryStatus, ProfileStoreError> {
        let conversation = self.load_conversation(conversation_id)?;
        let history = {
            let connection = self.lock()?;
            self.load_history_record(
                &connection,
                conversation_id,
                conversation.routing_id,
                message_id,
            )?
        };
        let Some(history) = history.filter(|record| !record.message.content().is_internal()) else {
            return Ok(MessageDeliveryStatus::NotObserved);
        };
        let observation = match history.direction {
            MessageDirection::Outbound => {
                MessageDeliveryObservation::Outbound(self.outbound_delivery_observation(
                    conversation_id,
                    &history,
                    now_unix_milliseconds / 1_000,
                )?)
            }
            MessageDirection::Inbound => {
                let cursor = history.cursor.ok_or(ProfileStoreError::CorruptData)?;
                self.verify_history_cursor_binding(
                    conversation_id,
                    conversation.routing_id,
                    &history,
                    cursor,
                )?;
                if !history.complete || cursor > conversation.replay_cursor {
                    MessageDeliveryObservation::InboundPrepared
                } else {
                    let local_device = conversation.signing_material.binding().device_id();
                    let connection = self.lock()?;
                    let sequence: Option<i64> = connection
                        .query_row(
                            "SELECT event_sequence
                             FROM daemon_remote_event
                             WHERE conversation_id = ?1 AND relay_cursor = ?2",
                            params![
                                conversation_id.as_bytes().as_slice(),
                                to_sql_integer(cursor)?
                            ],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|_| ProfileStoreError::Storage)?;
                    let notification = if let Some(sequence) = sequence {
                        let (event, state) = self.load_remote_event_record_in(
                            &connection,
                            from_sql_integer(sequence)?,
                        )?;
                        if event.conversation_id != conversation_id
                            || event.relay_cursor != cursor
                            || event.kind != RemoteEventKind::ApplicationMessage
                            || event.sender != history.sender
                            || event.source_identifier != *message_id.as_bytes()
                        {
                            return Err(ProfileStoreError::CorruptData);
                        }
                        match state.status {
                            RemoteEventStatus::Pending => LocalDeliveryObservation::Pending,
                            RemoteEventStatus::Claimed => LocalDeliveryObservation::Claimed,
                            RemoteEventStatus::Acknowledged => {
                                LocalDeliveryObservation::Acknowledged
                            }
                            RemoteEventStatus::Suppressed => LocalDeliveryObservation::Suppressed,
                        }
                    } else {
                        LocalDeliveryObservation::NotRetained
                    };
                    let handling = if matches!(
                        history.message.content(),
                        ApplicationContent::DirectedRequest(request)
                            if request.target_device_id() == local_device
                    ) {
                        self.request_handling_observation_in(
                            &connection,
                            conversation_id,
                            message_id,
                            local_device,
                        )?
                    } else {
                        RequestHandlingObservation::NotRecorded
                    };
                    MessageDeliveryObservation::Inbound {
                        notification,
                        handling,
                    }
                }
            }
        };
        classify_message_delivery(observation, now_unix_milliseconds)
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn outbound_delivery_observation(
        &self,
        conversation_id: ConversationId,
        history: &HistoryRecord,
        now_unix_seconds: u64,
    ) -> Result<OutboundDeliveryObservation, ProfileStoreError> {
        let metadata: Option<(i64, Option<i64>, Vec<u8>, i64)> = self
            .lock()?
            .query_row(
                "SELECT status, length(sealed_envelope),
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    sender_counter
                 FROM daemon_outbox
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    history.message.message_id().as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (status, sealed_length, envelope_id, sender_counter) =
            metadata.ok_or(ProfileStoreError::CorruptData)?;
        if envelope_id.as_slice() != history.envelope_id.as_bytes()
            || from_sql_integer(sender_counter)? != history.message.sender_counter()
        {
            return Err(ProfileStoreError::CorruptData);
        }
        if status == 1 && sealed_length.is_none() && !history.complete && history.cursor.is_none() {
            return Ok(OutboundDeliveryObservation::Prepared);
        }
        let outbound = self
            .outbound_application(conversation_id, history.message.message_id())?
            .ok_or(ProfileStoreError::CorruptData)?;
        match outbound.status {
            OutboundApplicationStatus::Ready => Ok(OutboundDeliveryObservation::Ready),
            OutboundApplicationStatus::Accepted { cursor } => {
                let observed = self.cursor_observation_for_envelope(
                    conversation_id,
                    outbound.envelope.routing_id(),
                    &outbound.envelope,
                )?;
                if observed != Some(cursor) {
                    return Err(ProfileStoreError::CorruptData);
                }
                Ok(OutboundDeliveryObservation::RelayAccepted)
            }
            OutboundApplicationStatus::Expired => {
                if outbound.envelope.expires_at_unix_seconds() > now_unix_seconds {
                    return Err(ProfileStoreError::CorruptData);
                }
                Ok(OutboundDeliveryObservation::Expired)
            }
            OutboundApplicationStatus::Removed => Ok(OutboundDeliveryObservation::Removed),
        }
    }
}
