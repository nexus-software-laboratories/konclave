use super::*;

pub(super) fn candidate_query(order: MessageHistoryOrder) -> String {
    let order = match order {
        MessageHistoryOrder::Ascending => "ASC",
        MessageHistoryOrder::Descending => "DESC",
    };
    format!(
        "SELECT CASE WHEN length(message_id) = 16 THEN message_id END
         FROM daemon_message_history
         WHERE conversation_id = ?1
           AND status = 2
           AND NOT EXISTS (
               SELECT 1
               FROM daemon_internal_application_message AS internal
               WHERE internal.conversation_id = daemon_message_history.conversation_id
                 AND internal.message_id = daemon_message_history.message_id
           )
           AND cursor > ?2
           AND cursor <= ?3
         ORDER BY cursor {order}
         LIMIT ?4"
    )
}

impl ProfileStore {
    /// Scans a bounded authenticated page without exposing sealed timestamps in SQL.
    ///
    /// # Errors
    ///
    /// Rejects storage failures, invalid records, or unauthenticated cursor progress.
    pub(crate) fn load_history_query(
        &self,
        conversation_id: ConversationId,
        query: MessageHistoryQuery,
    ) -> Result<HistoryPage, ProfileStoreError> {
        let conversation = self.load_conversation(conversation_id)?;
        let routing_id = conversation.routing_id;
        let upper_cursor = query
            .before_cursor()
            .map_or(conversation.replay_cursor, |before| {
                conversation.replay_cursor.min(before - 1)
            });
        let message_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(&candidate_query(query.order()))
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(query.after_cursor())?,
                        to_sql_integer(upper_cursor)?,
                        i64::try_from(query.scan_limit() + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut messages = Vec::with_capacity(message_ids.len().min(query.limit()));
        let mut last_scanned_cursor = None;
        let mut scanned_count = 0;
        for message_id in message_ids.iter().take(query.scan_limit()) {
            let message_id =
                MessageId::from_slice(message_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let history = {
                let connection = self.lock()?;
                self.load_history_record(&connection, conversation_id, routing_id, message_id)?
                    .ok_or(ProfileStoreError::CorruptData)?
            };
            let cursor = history.cursor.ok_or(ProfileStoreError::CorruptData)?;
            self.verify_history_cursor_binding(conversation_id, routing_id, &history, cursor)?;
            if cursor > upper_cursor {
                return Err(ProfileStoreError::CorruptData);
            }
            query
                .validate_cursor(cursor, last_scanned_cursor)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            scanned_count += 1;
            last_scanned_cursor = Some(cursor);
            let message = stored_history_message(history).ok_or(ProfileStoreError::CorruptData)?;
            if query.matches_timestamp(message.message.sent_at_unix_milliseconds()) {
                messages.push(message);
                if messages.len() == query.limit() {
                    break;
                }
            }
        }
        let has_more = message_ids.len() > scanned_count;
        let next_cursor = query
            .continuation_cursor(last_scanned_cursor, has_more)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        Ok(HistoryPage {
            messages,
            has_more,
            next_cursor,
        })
    }
}
