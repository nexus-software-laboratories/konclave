use KonclaveCryptographicCore::verify_collaboration_policy_proposal;
use KonclaveDomainCore::{
    ApplicationContent, CollaborationPolicyProposalId, CollaborationPolicyResponseOutcome,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    CollaborationPolicyDigest, ConversationId, MessageId, ProfileId, ProfileStore,
    ProfileStoreError, SealedBlob, SecretRecordContext, SecretRecordKind, from_sql_integer,
    to_sql_integer,
};

const MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS: usize = 4_096;
const MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS_PER_CONVERSATION: usize = 1_024;
const COLLABORATION_POLICY_EXCHANGE_BACKFILL_BATCH: usize = 100;

const EXCHANGE_KIND_PROPOSAL: i64 = 1;
const EXCHANGE_KIND_RESPONSE: i64 = 2;
const EXCHANGE_KIND_REVOCATION: i64 = 3;
const RESPONSE_OUTCOME_ACCEPTED: i64 = 1;
const RESPONSE_OUTCOME_REJECTED: i64 = 2;
const EXCHANGE_RECORD_VERSION: u8 = 1;
const EXCHANGE_RECORD_BYTES: usize = 109;
const EXCHANGE_STATE_VERSION: u8 = 1;
const EXCHANGE_STATE_BYTES: usize = 10;
const MAX_SEALED_EXCHANGE_RECORD_BYTES: usize = EXCHANGE_RECORD_BYTES + 64;
const MAX_SEALED_EXCHANGE_STATE_BYTES: usize = EXCHANGE_STATE_BYTES + 64;
const MAX_PROPOSAL_ASSERTIONS_PER_ID: usize =
    MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS_PER_CONVERSATION;

struct IndexedExchangeMetadata {
    relay_cursor: i64,
    kind: i64,
    proposal_id_storage_type: String,
    proposal_id_length: Option<i64>,
    proposal_id: Option<Vec<u8>>,
    policy_digest: Option<Vec<u8>>,
    response_outcome: Option<i64>,
    sealed_record_length: i64,
}

pub(crate) struct StoredCollaborationPolicyProposal {
    pub(crate) proposal_id: CollaborationPolicyProposalId,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) replaces_policy_digest: Option<CollaborationPolicyDigest>,
    pub(crate) canonical_bundle: Vec<u8>,
    pub(crate) proposer: KonclaveDomainCore::DeviceId,
    pub(crate) message_id: MessageId,
    pub(crate) relay_cursor: u64,
}

pub(super) fn initialize_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_collaboration_policy_exchange (
                conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 32),
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                relay_cursor INTEGER NOT NULL CHECK (relay_cursor >= 1),
                kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 3),
                proposal_id BLOB CHECK (
                    proposal_id IS NULL OR length(proposal_id) = 16
                ),
                policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
                response_outcome INTEGER CHECK (
                    response_outcome IS NULL OR response_outcome BETWEEN 1 AND 2
                ),
                sealed_record BLOB NOT NULL,
                PRIMARY KEY (conversation_id, message_id),
                UNIQUE (conversation_id, relay_cursor),
                FOREIGN KEY (conversation_id, message_id)
                    REFERENCES daemon_message_history(conversation_id, message_id)
                    ON DELETE CASCADE,
                CHECK (
                    (kind = 1 AND proposal_id IS NOT NULL AND response_outcome IS NULL)
                    OR
                    (kind = 2 AND proposal_id IS NOT NULL AND response_outcome IS NOT NULL)
                    OR
                    (kind = 3 AND proposal_id IS NULL AND response_outcome IS NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_collaboration_policy_exchange_proposal_idx
                ON daemon_collaboration_policy_exchange(
                    conversation_id,
                    proposal_id,
                    relay_cursor
                );
             CREATE INDEX daemon_collaboration_policy_exchange_digest_idx
                ON daemon_collaboration_policy_exchange(
                    conversation_id,
                    policy_digest,
                    relay_cursor
                );
             CREATE TABLE daemon_collaboration_policy_exchange_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                sealed_state BLOB
             );
             INSERT INTO daemon_collaboration_policy_exchange_state (
                singleton_id,
                sealed_state
             ) VALUES (1, NULL);
             PRAGMA user_version = 16;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

impl ProfileStore {
    pub(super) fn backfill_collaboration_policy_exchange_records(
        &self,
    ) -> Result<(), ProfileStoreError> {
        let connection = self.lock()?;
        let sealed_state = self.load_collaboration_policy_exchange_state(&connection)?;
        drop(connection);
        if let Some(sealed_state) = sealed_state {
            self.open_collaboration_policy_exchange_state(sealed_state)?;
            return Ok(());
        }

        let mut last_conversation_id: Option<Vec<u8>> = None;
        let mut last_message_id: Option<Vec<u8>> = None;
        loop {
            let batch = {
                let connection = self.lock()?;
                match (&last_conversation_id, &last_message_id) {
                    (None, None) => query_backfill_batch(
                        &connection,
                        "SELECT
                            CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                            CASE WHEN length(message_id) = 16 THEN message_id END,
                            cursor
                         FROM daemon_message_history
                         WHERE status = 2
                         ORDER BY conversation_id, message_id
                         LIMIT ?1",
                        params![
                            i64::try_from(COLLABORATION_POLICY_EXCHANGE_BACKFILL_BATCH)
                                .map_err(|_| ProfileStoreError::SequenceExhausted)?
                        ],
                    )?,
                    (Some(conversation_id), Some(message_id)) => query_backfill_batch(
                        &connection,
                        "SELECT
                            CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                            CASE WHEN length(message_id) = 16 THEN message_id END,
                            cursor
                         FROM daemon_message_history
                         WHERE status = 2
                           AND (conversation_id, message_id) > (?1, ?2)
                         ORDER BY conversation_id, message_id
                         LIMIT ?3",
                        params![
                            conversation_id.as_slice(),
                            message_id.as_slice(),
                            i64::try_from(COLLABORATION_POLICY_EXCHANGE_BACKFILL_BATCH)
                                .map_err(|_| ProfileStoreError::SequenceExhausted)?
                        ],
                    )?,
                    _ => return Err(ProfileStoreError::CorruptData),
                }
            };
            if batch.is_empty() {
                break;
            }
            for metadata in &batch {
                let conversation_id = ConversationId::from_slice(
                    metadata
                        .conversation_id
                        .as_deref()
                        .ok_or(ProfileStoreError::CorruptData)?,
                )
                .map_err(|_| ProfileStoreError::CorruptData)?;
                let message_id = MessageId::from_slice(
                    metadata
                        .message_id
                        .as_deref()
                        .ok_or(ProfileStoreError::CorruptData)?,
                )
                .map_err(|_| ProfileStoreError::CorruptData)?;
                let relay_cursor = from_sql_integer(
                    metadata
                        .relay_cursor
                        .ok_or(ProfileStoreError::CorruptData)?,
                )?;
                let conversation = self.load_conversation(conversation_id)?;
                let connection = self.lock()?;
                let history = self
                    .load_history_record(
                        &connection,
                        conversation_id,
                        conversation.routing_id,
                        message_id,
                    )?
                    .ok_or(ProfileStoreError::CorruptData)?;
                drop(connection);
                if !history.complete || history.cursor != Some(relay_cursor) {
                    return Err(ProfileStoreError::CorruptData);
                }
                self.verify_history_cursor_binding(
                    conversation_id,
                    conversation.routing_id,
                    &history,
                    relay_cursor,
                )?;
                if !matches!(
                    history.message.content(),
                    ApplicationContent::Text(_) | ApplicationContent::DirectedRequest(_)
                ) {
                    let mut connection = self.lock()?;
                    let transaction = connection
                        .transaction()
                        .map_err(|_| ProfileStoreError::Storage)?;
                    self.index_collaboration_policy_exchange_in_with_state(
                        &transaction,
                        conversation_id,
                        relay_cursor,
                        &history.message,
                        false,
                    )?;
                    transaction
                        .commit()
                        .map_err(|_| ProfileStoreError::Storage)?;
                }
            }
            let last = batch.last().ok_or(ProfileStoreError::CorruptData)?;
            last_conversation_id = last.conversation_id.clone();
            last_message_id = last.message_id.clone();
        }

        let connection = self.lock()?;
        let count = collaboration_policy_exchange_count(&connection)?;
        let sealed_state = self.seal_collaboration_policy_exchange_state(count)?;
        let changed = connection
            .execute(
                "UPDATE daemon_collaboration_policy_exchange_state
                 SET sealed_state = ?1
                 WHERE singleton_id = 1 AND sealed_state IS NULL",
                params![sealed_state.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }

    fn advance_collaboration_policy_exchange_state(
        &self,
        connection: &Connection,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let sealed_state = self
            .load_collaboration_policy_exchange_state(connection)?
            .ok_or(ProfileStoreError::CorruptData)?;
        let committed_count = self.open_collaboration_policy_exchange_state(sealed_state)?;
        let actual_count = collaboration_policy_exchange_count(connection)?;
        if committed_count != actual_count {
            return Err(ProfileStoreError::CorruptData);
        }
        let next_count = actual_count
            .checked_add(1)
            .ok_or(ProfileStoreError::CollaborationPolicyCapacityExceeded)?;
        self.seal_collaboration_policy_exchange_state(next_count)
    }

    fn load_collaboration_policy_exchange_state(
        &self,
        connection: &Connection,
    ) -> Result<Option<Vec<u8>>, ProfileStoreError> {
        let length: Option<Option<i64>> = connection
            .query_row(
                "SELECT CASE
                    WHEN sealed_state IS NULL THEN NULL
                    ELSE length(sealed_state)
                 END
                 FROM daemon_collaboration_policy_exchange_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let length = length.ok_or(ProfileStoreError::CorruptData)?;
        let Some(length) = length else {
            return Ok(None);
        };
        validate_sealed_length(length, MAX_SEALED_EXCHANGE_STATE_BYTES)?;
        let sealed_state: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_collaboration_policy_exchange_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(Some(sealed_state))
    }

    fn seal_collaboration_policy_exchange_state(
        &self,
        record_count: usize,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let encoded = encode_collaboration_policy_exchange_state(record_count)?;
        self.sealer
            .seal(
                &collaboration_policy_exchange_state_context(&self.locked_profile.profile_id)?,
                &encoded,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_collaboration_policy_exchange_state(
        &self,
        sealed_state: Vec<u8>,
    ) -> Result<usize, ProfileStoreError> {
        if sealed_state.is_empty() || sealed_state.len() > MAX_SEALED_EXCHANGE_STATE_BYTES {
            return Err(ProfileStoreError::CorruptData);
        }
        let sealed_state =
            SealedBlob::from_bytes(sealed_state).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &collaboration_policy_exchange_state_context(&self.locked_profile.profile_id)?,
                &sealed_state,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        decode_collaboration_policy_exchange_state(&plaintext)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "sealed exchange metadata remains explicit for substitution checks"
    )]
    fn verify_collaboration_policy_exchange_record_seal(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        message_id: MessageId,
        relay_cursor: u64,
        kind: i64,
        proposal_id: Option<CollaborationPolicyProposalId>,
        policy_digest: CollaborationPolicyDigest,
        response_outcome: Option<i64>,
        sealed_record_length: i64,
    ) -> Result<(), ProfileStoreError> {
        let expected_length =
            validate_sealed_length(sealed_record_length, MAX_SEALED_EXCHANGE_RECORD_BYTES)?;
        let sealed_record: Vec<u8> = connection
            .query_row(
                "SELECT sealed_record
                 FROM daemon_collaboration_policy_exchange
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed_record.len() != expected_length {
            return Err(ProfileStoreError::CorruptData);
        }
        let sealed_record =
            SealedBlob::from_bytes(sealed_record).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &collaboration_policy_exchange_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    message_id,
                )?,
                &sealed_record,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let expected = encode_collaboration_policy_exchange_record(
            conversation_id,
            message_id,
            relay_cursor,
            kind,
            proposal_id,
            policy_digest,
            response_outcome,
        )?;
        if plaintext.as_slice() == expected.as_slice() {
            Ok(())
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }

    pub(super) fn index_collaboration_policy_exchange_in(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        relay_cursor: u64,
        message: &KonclaveDomainCore::ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        self.index_collaboration_policy_exchange_in_with_state(
            connection,
            conversation_id,
            relay_cursor,
            message,
            true,
        )
    }

    fn index_collaboration_policy_exchange_in_with_state(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        relay_cursor: u64,
        message: &KonclaveDomainCore::ApplicationMessage,
        update_state: bool,
    ) -> Result<(), ProfileStoreError> {
        let (kind, proposal_id, policy_digest, response_outcome) = match message.content() {
            ApplicationContent::Text(_) | ApplicationContent::DirectedRequest(_) => return Ok(()),
            ApplicationContent::CollaborationPolicyProposal(proposal) => {
                verify_collaboration_policy_proposal(proposal)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                (
                    EXCHANGE_KIND_PROPOSAL,
                    Some(proposal.proposal_id()),
                    proposal.policy_digest(),
                    None,
                )
            }
            ApplicationContent::CollaborationPolicyResponse(response) => (
                EXCHANGE_KIND_RESPONSE,
                Some(response.proposal_id()),
                response.policy_digest(),
                Some(match response.outcome() {
                    CollaborationPolicyResponseOutcome::Accepted => RESPONSE_OUTCOME_ACCEPTED,
                    CollaborationPolicyResponseOutcome::Rejected => RESPONSE_OUTCOME_REJECTED,
                }),
            ),
            ApplicationContent::CollaborationPolicyRevocation(revocation) => (
                EXCHANGE_KIND_REVOCATION,
                None,
                revocation.policy_digest(),
                None,
            ),
        };
        if self.collaboration_policy_exchange_record_exists(
            connection,
            conversation_id,
            message.message_id(),
        )? {
            return self.verify_collaboration_policy_exchange_metadata(
                connection,
                conversation_id,
                relay_cursor,
                message.message_id(),
                kind,
                proposal_id,
                policy_digest,
                response_outcome,
            );
        }
        self.require_collaboration_policy_exchange_capacity(connection, conversation_id)?;
        let encoded_record = encode_collaboration_policy_exchange_record(
            conversation_id,
            message.message_id(),
            relay_cursor,
            kind,
            proposal_id,
            policy_digest,
            response_outcome,
        )?;
        let sealed_record = self
            .sealer
            .seal(
                &collaboration_policy_exchange_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    message.message_id(),
                )?,
                &encoded_record,
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let sealed_state = if update_state {
            Some(self.advance_collaboration_policy_exchange_state(connection)?)
        } else {
            None
        };
        let proposal_id = proposal_id.map(|value| value.into_bytes());
        let changed = connection
            .execute(
                "INSERT INTO daemon_collaboration_policy_exchange (
                    conversation_id,
                    message_id,
                    relay_cursor,
                    kind,
                    proposal_id,
                    policy_digest,
                    response_outcome,
                    sealed_record
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message.message_id().as_bytes().as_slice(),
                    to_sql_integer(relay_cursor)?,
                    kind,
                    proposal_id.as_ref().map(<[u8; 16]>::as_slice),
                    policy_digest.as_bytes().as_slice(),
                    response_outcome,
                    sealed_record.as_bytes()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::Storage);
        }
        if let Some(sealed_state) = sealed_state {
            let changed = connection
                .execute(
                    "UPDATE daemon_collaboration_policy_exchange_state
                     SET sealed_state = ?1
                     WHERE singleton_id = 1",
                    params![sealed_state.as_bytes()],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if changed != 1 {
                return Err(ProfileStoreError::CorruptData);
            }
        }
        Ok(())
    }

    pub(super) fn verify_collaboration_policy_exchange_records(
        &self,
    ) -> Result<(), ProfileStoreError> {
        let metadata = {
            let connection = self.lock()?;
            let sealed_state = self
                .load_collaboration_policy_exchange_state(&connection)?
                .ok_or(ProfileStoreError::CorruptData)?;
            let committed_count = self.open_collaboration_policy_exchange_state(sealed_state)?;
            let count = collaboration_policy_exchange_count(&connection)?;
            if committed_count != count {
                return Err(ProfileStoreError::CorruptData);
            }
            let largest_conversation_count: i64 = connection
                .query_row(
                    "SELECT coalesce(max(record_count), 0)
                     FROM (
                        SELECT count(*) AS record_count
                        FROM daemon_collaboration_policy_exchange
                        GROUP BY conversation_id
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if count > MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS
                || largest_conversation_count < 0
                || usize::try_from(largest_conversation_count)
                    .ok()
                    .is_none_or(|count| {
                        count > MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS_PER_CONVERSATION
                    })
            {
                return Err(ProfileStoreError::CorruptData);
            }
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(message_id) = 16 THEN message_id END,
                        relay_cursor,
                        kind,
                        typeof(proposal_id),
                        length(proposal_id),
                        CASE
                            WHEN typeof(proposal_id) = 'blob'
                                AND length(proposal_id) = 16
                            THEN proposal_id
                        END,
                        CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                        response_outcome,
                        length(sealed_record)
                     FROM daemon_collaboration_policy_exchange
                     ORDER BY conversation_id, relay_cursor",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], exchange_metadata_from_row)
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for metadata in metadata {
            self.load_verified_collaboration_policy_exchange_record(metadata)?;
        }
        Ok(())
    }

    pub(crate) fn collaboration_policy_proposal(
        &self,
        conversation_id: ConversationId,
        proposal_id: CollaborationPolicyProposalId,
    ) -> Result<StoredCollaborationPolicyProposal, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(message_id) = 16 THEN message_id END,
                        relay_cursor,
                        kind,
                        typeof(proposal_id),
                        length(proposal_id),
                        CASE
                            WHEN typeof(proposal_id) = 'blob'
                                AND length(proposal_id) = 16
                            THEN proposal_id
                        END,
                        CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                        response_outcome,
                        length(sealed_record)
                     FROM daemon_collaboration_policy_exchange
                     WHERE conversation_id = ?1
                       AND kind = 1
                       AND proposal_id = ?2
                     ORDER BY relay_cursor
                     LIMIT ?3",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        proposal_id.as_bytes().as_slice(),
                        i64::try_from(MAX_PROPOSAL_ASSERTIONS_PER_ID + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    exchange_metadata_from_row,
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if metadata.is_empty() {
            return Err(ProfileStoreError::CollaborationPolicyProposalNotFound);
        }
        if metadata.len() > MAX_PROPOSAL_ASSERTIONS_PER_ID {
            return Err(ProfileStoreError::CollaborationPolicyProposalConflict);
        }

        let mut selected: Option<StoredCollaborationPolicyProposal> = None;
        for metadata in metadata {
            let history = self.load_verified_collaboration_policy_exchange_record(metadata)?;
            let ApplicationContent::CollaborationPolicyProposal(proposal) =
                history.message.content()
            else {
                return Err(ProfileStoreError::CorruptData);
            };
            let candidate = StoredCollaborationPolicyProposal {
                proposal_id: proposal.proposal_id(),
                policy_digest: proposal.policy_digest(),
                replaces_policy_digest: proposal.replaces_policy_digest(),
                canonical_bundle: proposal.canonical_bundle().to_vec(),
                proposer: history.sender,
                message_id: history.message.message_id(),
                relay_cursor: history.cursor.ok_or(ProfileStoreError::CorruptData)?,
            };
            if let Some(existing) = &selected {
                if existing.proposal_id != candidate.proposal_id
                    || existing.policy_digest != candidate.policy_digest
                    || existing.replaces_policy_digest != candidate.replaces_policy_digest
                    || existing.canonical_bundle != candidate.canonical_bundle
                    || existing.proposer != candidate.proposer
                {
                    return Err(ProfileStoreError::CollaborationPolicyProposalConflict);
                }
            } else {
                selected = Some(candidate);
            }
        }
        selected.ok_or(ProfileStoreError::CollaborationPolicyProposalNotFound)
    }

    fn collaboration_policy_exchange_record_exists(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<bool, ProfileStoreError> {
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM daemon_collaboration_policy_exchange
                    WHERE conversation_id = ?1 AND message_id = ?2
                 )",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn require_collaboration_policy_exchange_capacity(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
    ) -> Result<(), ProfileStoreError> {
        let (total, conversation): (i64, i64) = connection
            .query_row(
                "SELECT
                    count(*),
                    count(CASE WHEN conversation_id = ?1 THEN 1 END)
                 FROM daemon_collaboration_policy_exchange",
                params![conversation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if total < 0
            || conversation < 0
            || usize::try_from(total)
                .ok()
                .is_none_or(|count| count >= MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS)
            || usize::try_from(conversation).ok().is_none_or(|count| {
                count >= MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS_PER_CONVERSATION
            })
        {
            return Err(ProfileStoreError::CollaborationPolicyCapacityExceeded);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "indexed exchange metadata remains explicit for substitution checks"
    )]
    fn verify_collaboration_policy_exchange_metadata(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        relay_cursor: u64,
        message_id: MessageId,
        expected_kind: i64,
        expected_proposal_id: Option<CollaborationPolicyProposalId>,
        expected_policy_digest: CollaborationPolicyDigest,
        expected_response_outcome: Option<i64>,
    ) -> Result<(), ProfileStoreError> {
        let metadata: Option<IndexedExchangeMetadata> = connection
            .query_row(
                "SELECT
                    relay_cursor,
                    kind,
                    typeof(proposal_id),
                    length(proposal_id),
                    CASE
                        WHEN typeof(proposal_id) = 'blob'
                            AND length(proposal_id) = 16
                        THEN proposal_id
                    END,
                    CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                    response_outcome,
                    length(sealed_record)
                 FROM daemon_collaboration_policy_exchange
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| {
                    Ok(IndexedExchangeMetadata {
                        relay_cursor: row.get(0)?,
                        kind: row.get(1)?,
                        proposal_id_storage_type: row.get(2)?,
                        proposal_id_length: row.get(3)?,
                        proposal_id: row.get(4)?,
                        policy_digest: row.get(5)?,
                        response_outcome: row.get(6)?,
                        sealed_record_length: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some(metadata) = metadata else {
            return Err(ProfileStoreError::CorruptData);
        };
        let proposal_id = decode_optional_proposal_id(
            &metadata.proposal_id_storage_type,
            metadata.proposal_id_length,
            metadata.proposal_id,
        )?;
        let policy_digest = CollaborationPolicyDigest::from_slice(
            &metadata
                .policy_digest
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        if from_sql_integer(metadata.relay_cursor)? != relay_cursor
            || metadata.kind != expected_kind
            || proposal_id != expected_proposal_id
            || policy_digest != expected_policy_digest
            || metadata.response_outcome != expected_response_outcome
        {
            return Err(ProfileStoreError::CorruptData);
        }
        self.verify_collaboration_policy_exchange_record_seal(
            connection,
            conversation_id,
            message_id,
            relay_cursor,
            expected_kind,
            expected_proposal_id,
            expected_policy_digest,
            expected_response_outcome,
            metadata.sealed_record_length,
        )
    }

    fn load_verified_collaboration_policy_exchange_record(
        &self,
        metadata: ExchangeMetadata,
    ) -> Result<super::HistoryRecord, ProfileStoreError> {
        let conversation_id = ConversationId::from_slice(
            &metadata
                .conversation_id
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        let message_id =
            MessageId::from_slice(&metadata.message_id.ok_or(ProfileStoreError::CorruptData)?)
                .map_err(|_| ProfileStoreError::CorruptData)?;
        let relay_cursor = from_sql_integer(metadata.relay_cursor)?;
        let proposal_id = decode_optional_proposal_id(
            &metadata.proposal_id_storage_type,
            metadata.proposal_id_length,
            metadata.proposal_id,
        )?;
        let policy_digest = CollaborationPolicyDigest::from_slice(
            &metadata
                .policy_digest
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        let conversation = self.load_conversation(conversation_id)?;
        let connection = self.lock()?;
        self.verify_collaboration_policy_exchange_record_seal(
            &connection,
            conversation_id,
            message_id,
            relay_cursor,
            metadata.kind,
            proposal_id,
            policy_digest,
            metadata.response_outcome,
            metadata.sealed_record_length,
        )?;
        let history = self
            .load_history_record(
                &connection,
                conversation_id,
                conversation.routing_id,
                message_id,
            )?
            .ok_or(ProfileStoreError::CorruptData)?;
        drop(connection);
        if !history.complete || history.cursor != Some(relay_cursor) {
            return Err(ProfileStoreError::CorruptData);
        }
        self.verify_history_cursor_binding(
            conversation_id,
            conversation.routing_id,
            &history,
            relay_cursor,
        )?;
        let (expected_kind, expected_proposal_id, expected_digest, expected_outcome) =
            match history.message.content() {
                ApplicationContent::Text(_) | ApplicationContent::DirectedRequest(_) => {
                    return Err(ProfileStoreError::CorruptData);
                }
                ApplicationContent::CollaborationPolicyProposal(proposal) => {
                    verify_collaboration_policy_proposal(proposal)
                        .map_err(|_| ProfileStoreError::CorruptData)?;
                    (
                        EXCHANGE_KIND_PROPOSAL,
                        Some(proposal.proposal_id()),
                        proposal.policy_digest(),
                        None,
                    )
                }
                ApplicationContent::CollaborationPolicyResponse(response) => (
                    EXCHANGE_KIND_RESPONSE,
                    Some(response.proposal_id()),
                    response.policy_digest(),
                    Some(match response.outcome() {
                        CollaborationPolicyResponseOutcome::Accepted => RESPONSE_OUTCOME_ACCEPTED,
                        CollaborationPolicyResponseOutcome::Rejected => RESPONSE_OUTCOME_REJECTED,
                    }),
                ),
                ApplicationContent::CollaborationPolicyRevocation(revocation) => (
                    EXCHANGE_KIND_REVOCATION,
                    None,
                    revocation.policy_digest(),
                    None,
                ),
            };
        if metadata.kind != expected_kind
            || proposal_id != expected_proposal_id
            || policy_digest != expected_digest
            || metadata.response_outcome != expected_outcome
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(history)
    }
}

struct ExchangeMetadata {
    conversation_id: Option<Vec<u8>>,
    message_id: Option<Vec<u8>>,
    relay_cursor: i64,
    kind: i64,
    proposal_id_storage_type: String,
    proposal_id_length: Option<i64>,
    proposal_id: Option<Vec<u8>>,
    policy_digest: Option<Vec<u8>>,
    response_outcome: Option<i64>,
    sealed_record_length: i64,
}

fn exchange_metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExchangeMetadata> {
    Ok(ExchangeMetadata {
        conversation_id: row.get(0)?,
        message_id: row.get(1)?,
        relay_cursor: row.get(2)?,
        kind: row.get(3)?,
        proposal_id_storage_type: row.get(4)?,
        proposal_id_length: row.get(5)?,
        proposal_id: row.get(6)?,
        policy_digest: row.get(7)?,
        response_outcome: row.get(8)?,
        sealed_record_length: row.get(9)?,
    })
}

fn decode_optional_proposal_id(
    storage_type: &str,
    length: Option<i64>,
    value: Option<Vec<u8>>,
) -> Result<Option<CollaborationPolicyProposalId>, ProfileStoreError> {
    match (storage_type, length, value) {
        ("null", None, None) => Ok(None),
        ("blob", Some(length), Some(value))
            if usize::try_from(length).ok() == Some(CollaborationPolicyProposalId::LENGTH) =>
        {
            CollaborationPolicyProposalId::from_slice(&value)
                .map(Some)
                .map_err(|_| ProfileStoreError::CorruptData)
        }
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn query_backfill_batch<P>(
    connection: &Connection,
    query: &str,
    parameters: P,
) -> Result<Vec<BackfillMetadata>, ProfileStoreError>
where
    P: rusqlite::Params,
{
    let mut statement = connection
        .prepare(query)
        .map_err(|_| ProfileStoreError::Storage)?;
    statement
        .query_map(parameters, |row| {
            Ok(BackfillMetadata {
                conversation_id: row.get(0)?,
                message_id: row.get(1)?,
                relay_cursor: row.get(2)?,
            })
        })
        .map_err(|_| ProfileStoreError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProfileStoreError::Storage)
}

fn collaboration_policy_exchange_count(
    connection: &Connection,
) -> Result<usize, ProfileStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM daemon_collaboration_policy_exchange",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)
}

fn collaboration_policy_exchange_record_context(
    profile_id: &ProfileId,
    conversation_id: ConversationId,
    message_id: MessageId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::CollaborationPolicyExchangeRecord,
        &[
            profile_id.as_bytes(),
            conversation_id.as_bytes(),
            message_id.as_bytes(),
        ],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn collaboration_policy_exchange_state_context(
    profile_id: &ProfileId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::CollaborationPolicyExchangeState,
        &[profile_id.as_bytes()],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn encode_collaboration_policy_exchange_record(
    conversation_id: ConversationId,
    message_id: MessageId,
    relay_cursor: u64,
    kind: i64,
    proposal_id: Option<CollaborationPolicyProposalId>,
    policy_digest: CollaborationPolicyDigest,
    response_outcome: Option<i64>,
) -> Result<Vec<u8>, ProfileStoreError> {
    let kind = u8::try_from(kind).map_err(|_| ProfileStoreError::CorruptData)?;
    let response_outcome = response_outcome
        .map(|value| u8::try_from(value).map_err(|_| ProfileStoreError::CorruptData))
        .transpose()?;
    let mut encoded = Vec::with_capacity(EXCHANGE_RECORD_BYTES);
    encoded.push(EXCHANGE_RECORD_VERSION);
    encoded.extend_from_slice(conversation_id.as_bytes());
    encoded.extend_from_slice(message_id.as_bytes());
    encoded.extend_from_slice(&relay_cursor.to_be_bytes());
    encoded.push(kind);
    encoded.push(u8::from(proposal_id.is_some()));
    encoded.extend_from_slice(
        proposal_id
            .map_or([0; CollaborationPolicyProposalId::LENGTH], |value| {
                value.into_bytes()
            })
            .as_slice(),
    );
    encoded.extend_from_slice(policy_digest.as_bytes());
    encoded.push(u8::from(response_outcome.is_some()));
    encoded.push(response_outcome.unwrap_or(0));
    Ok(encoded)
}

fn encode_collaboration_policy_exchange_state(
    record_count: usize,
) -> Result<Vec<u8>, ProfileStoreError> {
    let record_count =
        u64::try_from(record_count).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    let mut encoded = Vec::with_capacity(EXCHANGE_STATE_BYTES);
    encoded.push(EXCHANGE_STATE_VERSION);
    encoded.push(1);
    encoded.extend_from_slice(&record_count.to_be_bytes());
    Ok(encoded)
}

fn decode_collaboration_policy_exchange_state(bytes: &[u8]) -> Result<usize, ProfileStoreError> {
    if bytes.len() != EXCHANGE_STATE_BYTES || bytes[0] != EXCHANGE_STATE_VERSION || bytes[1] != 1 {
        return Err(ProfileStoreError::CorruptData);
    }
    let count = u64::from_be_bytes(
        bytes[2..]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let count = usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)?;
    if count > MAX_COLLABORATION_POLICY_EXCHANGE_RECORDS {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(count)
}

fn validate_sealed_length(length: i64, maximum: usize) -> Result<usize, ProfileStoreError> {
    let length = usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)?;
    if length == 0 || length > maximum {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(length)
}

struct BackfillMetadata {
    conversation_id: Option<Vec<u8>>,
    message_id: Option<Vec<u8>>,
    relay_cursor: Option<i64>,
}
