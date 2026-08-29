use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveDomainCore::{
    AdapterConsumerId, AdapterLeaseId, ApplicationContent, CollaborationPolicyDigest,
    ConversationId, DeviceId, EnvelopeId, MAX_TEXT_BODY_BYTES, MessageId, NotificationId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use super::{
    MessageDirection, ProfileStore, ProfileStoreError, RemoteEventKind, RemoteEventStatus,
    SealedBlob, SecretRecordContext, SecretRecordKind, from_sql_integer,
    require_active_collaboration_policy_digest, to_sql_integer, verify_active_adapter_consumer_now,
};

const DIRECTED_REQUEST_HANDLING_SCHEMA_VERSION: u32 = 18;
const MAX_DIRECTED_REQUEST_HANDLINGS: usize = 4_096;
const MAX_DIRECTED_REQUEST_HANDLING_ATTEMPTS: u32 = 16;
const HANDLING_STATE_CLAIMED: i64 = 1;
const HANDLING_STATE_COMPLETED_RESPONSE: i64 = 2;
const HANDLING_STATE_COMPLETED_NO_RESPONSE: i64 = 3;
const HANDLING_RECORD_VERSION: u8 = 1;
const HANDLING_RECORD_FIXED_BYTES: usize = 243;
const MAX_HANDLING_RECORD_BYTES: usize = HANDLING_RECORD_FIXED_BYTES + MAX_TEXT_BODY_BYTES;
const MAX_SEALED_HANDLING_RECORD_BYTES: usize = MAX_HANDLING_RECORD_BYTES + 64;
const HANDLING_STATE_RECORD_VERSION: u8 = 1;
const HANDLING_STATE_RECORD_BYTES: usize = 9;
const MAX_SEALED_HANDLING_STATE_BYTES: usize = HANDLING_STATE_RECORD_BYTES + 64;

/// Exact claimed request identity required before one autonomous model turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectedRequestClaim {
    pub(crate) conversation_id: ConversationId,
    pub(crate) request_message_id: MessageId,
    pub(crate) responder_device_id: DeviceId,
    pub(crate) notification_id: NotificationId,
    pub(crate) consumer_id: AdapterConsumerId,
    pub(crate) lease_id: AdapterLeaseId,
    pub(crate) lease_generation: u64,
    pub(crate) claim_expires_at_unix_milliseconds: u64,
    pub(crate) attempt: u32,
    pub(crate) policy_digest: CollaborationPolicyDigest,
}

/// Input used to claim one exact directed request before model enqueue.
#[derive(Clone, Copy)]
pub(crate) struct ClaimDirectedRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) request_message_id: MessageId,
    pub(crate) responder_device_id: DeviceId,
    pub(crate) notification_id: NotificationId,
    pub(crate) consumer_id: AdapterConsumerId,
    pub(crate) lease_id: AdapterLeaseId,
    pub(crate) lease_generation: u64,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) now_unix_milliseconds: u64,
}

/// Exact handling attempt completed without producing an outbound response.
#[derive(Clone, Copy)]
pub(crate) struct CompleteDirectedRequest {
    pub(crate) conversation_id: ConversationId,
    pub(crate) request_message_id: MessageId,
    pub(crate) responder_device_id: DeviceId,
    pub(crate) consumer_id: AdapterConsumerId,
    pub(crate) attempt: u32,
    pub(crate) policy_digest: CollaborationPolicyDigest,
}

/// Exact identity used to revalidate one active request-handling attempt.
#[derive(Clone, Copy)]
pub(crate) struct ActiveDirectedRequestClaim {
    pub(crate) conversation_id: ConversationId,
    pub(crate) request_message_id: MessageId,
    pub(crate) responder_device_id: DeviceId,
    pub(crate) consumer_id: AdapterConsumerId,
    pub(crate) attempt: u32,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) now_unix_milliseconds: u64,
}

/// Durable outcome of attempting to claim one directed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectedRequestClaimOutcome {
    Claimed(DirectedRequestClaim),
    Busy,
    AttemptsExhausted,
    CompletedResponse,
    CompletedNoResponse,
}

pub(crate) struct RecoverableDirectedRequestResponse {
    pub(crate) reservation: super::OutboundReservation,
    pub(crate) request_message_id: MessageId,
    pub(crate) response_text: Zeroizing<String>,
    pub(crate) sent_at_unix_milliseconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandlingState {
    Claimed,
    CompletedResponse,
    CompletedNoResponse,
}

struct DirectedRequestHandling {
    claim: DirectedRequestClaim,
    state: HandlingState,
    response_message_id: Option<MessageId>,
    response_envelope_id: Option<EnvelopeId>,
    response_sender_counter: Option<u64>,
    response_text: Option<Zeroizing<String>>,
    response_sent_at_unix_milliseconds: Option<u64>,
    response_expires_at_unix_seconds: Option<u64>,
}

struct HandlingMetadata {
    conversation_id: Option<Vec<u8>>,
    request_message_id: Option<Vec<u8>>,
    responder_device_id: Option<Vec<u8>>,
    state: i64,
    notification_id: Option<Vec<u8>>,
    consumer_id: Option<Vec<u8>>,
    lease_id: Option<Vec<u8>>,
    lease_generation: i64,
    claim_expires_at_unix_milliseconds: i64,
    attempt: i64,
    policy_digest: Option<Vec<u8>>,
    response_message_storage_type: String,
    response_message_length: Option<i64>,
    response_message_id: Option<Vec<u8>>,
    sealed_handling_length: i64,
}

fn initialize_schema(
    connection: &Connection,
    sealed_initial_state: &SealedBlob,
    migrated_device_identity: Option<&SealedBlob>,
) -> Result<(), ProfileStoreError> {
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| ProfileStoreError::Storage)?;
    transaction
        .execute_batch(
            "CREATE TABLE daemon_directed_request_handling (
                conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 32),
                request_message_id BLOB NOT NULL CHECK (length(request_message_id) = 16),
                responder_device_id BLOB NOT NULL CHECK (length(responder_device_id) = 32),
                state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
                notification_id BLOB NOT NULL CHECK (length(notification_id) = 16),
                consumer_id BLOB NOT NULL CHECK (length(consumer_id) = 16),
                lease_id BLOB NOT NULL CHECK (length(lease_id) = 16),
                lease_generation INTEGER NOT NULL CHECK (lease_generation >= 1),
                claim_expires_at_unix_milliseconds INTEGER NOT NULL
                    CHECK (claim_expires_at_unix_milliseconds >= 1),
                attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 16),
                policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
                response_message_id BLOB CHECK (
                    response_message_id IS NULL OR length(response_message_id) = 16
                ),
                sealed_handling BLOB NOT NULL,
                PRIMARY KEY (
                    conversation_id,
                    request_message_id,
                    responder_device_id
                ),
                FOREIGN KEY (conversation_id, request_message_id)
                    REFERENCES daemon_message_history(conversation_id, message_id)
                    ON DELETE RESTRICT,
                CHECK (
                    (state = 1 AND response_message_id IS NULL)
                    OR (state = 2 AND response_message_id IS NOT NULL)
                    OR (state = 3 AND response_message_id IS NULL)
                )
             ) WITHOUT ROWID;
             CREATE UNIQUE INDEX daemon_directed_request_response_idx
                ON daemon_directed_request_handling(
                    conversation_id,
                    response_message_id
                )
                WHERE response_message_id IS NOT NULL;
             CREATE TABLE daemon_directed_request_handling_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                sealed_state BLOB NOT NULL
             );",
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    if transaction
        .execute(
            "INSERT INTO daemon_directed_request_handling_state (
                singleton_id,
                sealed_state
             ) VALUES (1, ?1)",
            params![sealed_initial_state.as_bytes()],
        )
        .map_err(|_| ProfileStoreError::Storage)?
        != 1
    {
        return Err(ProfileStoreError::Storage);
    }
    if let Some(migrated_device_identity) = migrated_device_identity
        && transaction
            .execute(
                "UPDATE daemon_profile
                 SET sealed_device_identity = ?1
                 WHERE singleton_id = 1 AND sealed_device_identity IS NOT NULL",
                params![migrated_device_identity.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
    {
        return Err(ProfileStoreError::CorruptData);
    }
    transaction
        .pragma_update(
            None,
            "user_version",
            DIRECTED_REQUEST_HANDLING_SCHEMA_VERSION,
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    transaction.commit().map_err(|_| ProfileStoreError::Storage)
}

impl ProfileStore {
    pub(super) fn initialize_directed_request_handling_schema(
        &self,
    ) -> Result<(), ProfileStoreError> {
        let current_version: u32 = self
            .lock()?
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing_identity = self.read_profile_blob(
            "SELECT length(sealed_device_identity)
             FROM daemon_profile
             WHERE singleton_id = 1",
            "SELECT sealed_device_identity
             FROM daemon_profile
             WHERE singleton_id = 1",
        )?;
        let opened_identity = existing_identity
            .as_ref()
            .map(|blob| {
                DeviceIdentity::open_with_profile_schema_floor(
                    &self.sealer,
                    self.locked_profile.profile_id.as_bytes(),
                    blob,
                )
                .map_err(|_| ProfileStoreError::CorruptData)
            })
            .transpose()?;
        if current_version == DIRECTED_REQUEST_HANDLING_SCHEMA_VERSION {
            if let Some((_, floor)) = opened_identity
                && floor != DIRECTED_REQUEST_HANDLING_SCHEMA_VERSION
            {
                return Err(ProfileStoreError::CorruptData);
            }
            return Ok(());
        }
        if current_version != 17 {
            return Err(ProfileStoreError::UnsupportedSchema);
        }
        let migrated_identity = match opened_identity {
            Some((identity, 17)) => Some(
                identity
                    .seal_with_profile_schema_floor(
                        &self.sealer,
                        self.locked_profile.profile_id.as_bytes(),
                        DIRECTED_REQUEST_HANDLING_SCHEMA_VERSION,
                    )
                    .map_err(|_| ProfileStoreError::Cryptographic)?,
            ),
            Some(_) => return Err(ProfileStoreError::CorruptData),
            None => None,
        };
        let sealed_initial_state = self.seal_directed_request_handling_state(0)?;
        let connection = self.lock()?;
        initialize_schema(
            &connection,
            &sealed_initial_state,
            migrated_identity.as_ref(),
        )
    }

    pub(super) fn verify_directed_request_handlings(&self) -> Result<(), ProfileStoreError> {
        let metadata = {
            let connection = self.lock()?;
            let committed_count = self.open_directed_request_handling_state(
                self.load_directed_request_handling_state(&connection)?,
            )?;
            let actual_count = directed_request_handling_count(&connection)?;
            if committed_count != actual_count || actual_count > MAX_DIRECTED_REQUEST_HANDLINGS {
                return Err(ProfileStoreError::CorruptData);
            }
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(request_message_id) = 16
                            THEN request_message_id END,
                        CASE WHEN length(responder_device_id) = 32
                            THEN responder_device_id END,
                        state,
                        CASE WHEN length(notification_id) = 16 THEN notification_id END,
                        CASE WHEN length(consumer_id) = 16 THEN consumer_id END,
                        CASE WHEN length(lease_id) = 16 THEN lease_id END,
                        lease_generation,
                        claim_expires_at_unix_milliseconds,
                        attempt,
                        CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                        typeof(response_message_id),
                        length(response_message_id),
                        CASE WHEN typeof(response_message_id) = 'blob'
                            AND length(response_message_id) = 16
                            THEN response_message_id END,
                        length(sealed_handling)
                     FROM daemon_directed_request_handling
                     ORDER BY conversation_id, request_message_id, responder_device_id",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], handling_metadata_from_row)
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for metadata in metadata {
            let connection = self.lock()?;
            let handling = self.open_directed_request_handling(&connection, metadata)?;
            self.verify_directed_request_message(
                &connection,
                handling.claim.conversation_id,
                handling.claim.request_message_id,
                handling.claim.responder_device_id,
            )?;
            if handling.state == HandlingState::CompletedResponse {
                self.verify_completed_directed_request_response(&connection, &handling)?;
            }
        }
        Ok(())
    }

    pub(crate) fn recoverable_directed_request_responses(
        &self,
    ) -> Result<Vec<RecoverableDirectedRequestResponse>, ProfileStoreError> {
        let connection = self.lock()?;
        let keys = {
            let mut statement = connection
                .prepare(
                    "SELECT
                        h.conversation_id,
                        h.request_message_id,
                        h.responder_device_id
                     FROM daemon_directed_request_handling h
                     INNER JOIN daemon_outbox o
                        ON o.conversation_id = h.conversation_id
                       AND o.message_id = h.response_message_id
                     WHERE h.state = 2 AND o.status = 1
                     ORDER BY o.sender_counter",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if keys.len() > MAX_DIRECTED_REQUEST_HANDLINGS {
            return Err(ProfileStoreError::CorruptData);
        }
        let mut responses = Vec::with_capacity(keys.len());
        for (conversation_id, request_message_id, responder_device_id) in keys {
            let conversation_id = ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let request_message_id = MessageId::from_slice(&request_message_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let responder_device_id = DeviceId::from_slice(&responder_device_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let metadata = load_handling_metadata(
                &connection,
                conversation_id,
                request_message_id,
                responder_device_id,
            )?
            .ok_or(ProfileStoreError::CorruptData)?;
            let handling = self.open_directed_request_handling(&connection, metadata)?;
            self.verify_completed_directed_request_response(&connection, &handling)?;
            let response_message_id = handling
                .response_message_id
                .ok_or(ProfileStoreError::CorruptData)?;
            responses.push(RecoverableDirectedRequestResponse {
                reservation: super::OutboundReservation {
                    conversation_id,
                    message_id: response_message_id,
                    envelope_id: handling
                        .response_envelope_id
                        .ok_or(ProfileStoreError::CorruptData)?,
                    sender_counter: handling
                        .response_sender_counter
                        .ok_or(ProfileStoreError::CorruptData)?,
                },
                request_message_id,
                response_text: Zeroizing::new(
                    handling
                        .response_text
                        .as_deref()
                        .ok_or(ProfileStoreError::CorruptData)?
                        .to_string(),
                ),
                sent_at_unix_milliseconds: handling
                    .response_sent_at_unix_milliseconds
                    .ok_or(ProfileStoreError::CorruptData)?,
                expires_at_unix_seconds: handling
                    .response_expires_at_unix_seconds
                    .filter(|expiry| *expiry > 0)
                    .ok_or(ProfileStoreError::CorruptData)?,
            });
        }
        Ok(responses)
    }

    pub(crate) fn claim_directed_request(
        &self,
        request: ClaimDirectedRequest,
    ) -> Result<DirectedRequestClaimOutcome, ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProfileStoreError::Storage)?;
        require_active_collaboration_policy_digest(
            &transaction,
            request.conversation_id,
            request.policy_digest,
        )?;
        require_current_conversation_member(
            &transaction,
            request.conversation_id,
            request.responder_device_id,
        )?;
        verify_active_adapter_consumer_now(
            &transaction,
            request.consumer_id,
            request.lease_id,
            request.now_unix_milliseconds,
        )?;
        let claim_expiry = self.verify_claimed_directed_request_event(
            &transaction,
            request.conversation_id,
            request.request_message_id,
            request.responder_device_id,
            request.notification_id,
            request.consumer_id,
            request.lease_id,
            request.lease_generation,
            request.now_unix_milliseconds,
        )?;
        let existing = match load_handling_metadata(
            &transaction,
            request.conversation_id,
            request.request_message_id,
            request.responder_device_id,
        )? {
            Some(metadata) => Some(self.open_directed_request_handling(&transaction, metadata)?),
            None => None,
        };
        let is_new = existing.is_none();
        let attempt = match existing.as_ref() {
            Some(existing) => match existing.state {
                HandlingState::CompletedResponse => {
                    return Ok(DirectedRequestClaimOutcome::CompletedResponse);
                }
                HandlingState::CompletedNoResponse => {
                    return Ok(DirectedRequestClaimOutcome::CompletedNoResponse);
                }
                HandlingState::Claimed if claim_matches(&existing.claim, &request) => {
                    return Ok(DirectedRequestClaimOutcome::Claimed(existing.claim));
                }
                HandlingState::Claimed
                    if existing.claim.claim_expires_at_unix_milliseconds
                        > request.now_unix_milliseconds =>
                {
                    return Ok(DirectedRequestClaimOutcome::Busy);
                }
                HandlingState::Claimed
                    if existing.claim.consumer_id == request.consumer_id
                        && existing.claim.lease_id == request.lease_id =>
                {
                    return Ok(DirectedRequestClaimOutcome::Busy);
                }
                HandlingState::Claimed
                    if existing.claim.attempt >= MAX_DIRECTED_REQUEST_HANDLING_ATTEMPTS =>
                {
                    return Ok(DirectedRequestClaimOutcome::AttemptsExhausted);
                }
                HandlingState::Claimed => existing.claim.attempt + 1,
            },
            None => 1,
        };
        let claim = DirectedRequestClaim {
            conversation_id: request.conversation_id,
            request_message_id: request.request_message_id,
            responder_device_id: request.responder_device_id,
            notification_id: request.notification_id,
            consumer_id: request.consumer_id,
            lease_id: request.lease_id,
            lease_generation: request.lease_generation,
            claim_expires_at_unix_milliseconds: claim_expiry,
            attempt,
            policy_digest: request.policy_digest,
        };
        let handling = DirectedRequestHandling {
            claim,
            state: HandlingState::Claimed,
            response_message_id: None,
            response_envelope_id: None,
            response_sender_counter: None,
            response_text: None,
            response_sent_at_unix_milliseconds: None,
            response_expires_at_unix_seconds: None,
        };
        if is_new {
            self.require_directed_request_handling_capacity(&transaction)?;
            let sealed_state = self.advance_directed_request_handling_state(&transaction)?;
            self.insert_directed_request_handling(&transaction, &handling)?;
            self.store_directed_request_handling_state(&transaction, &sealed_state)?;
        } else {
            self.update_directed_request_handling(&transaction, &handling)?;
        }
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(DirectedRequestClaimOutcome::Claimed(claim))
    }

    pub(crate) fn active_directed_request_claim(
        &self,
        request: ActiveDirectedRequestClaim,
    ) -> Result<Option<DirectedRequestClaim>, ProfileStoreError> {
        let connection = self.lock()?;
        require_active_collaboration_policy_digest(
            &connection,
            request.conversation_id,
            request.policy_digest,
        )?;
        require_current_conversation_member(
            &connection,
            request.conversation_id,
            request.responder_device_id,
        )?;
        let Some(metadata) = load_handling_metadata(
            &connection,
            request.conversation_id,
            request.request_message_id,
            request.responder_device_id,
        )?
        else {
            return Ok(None);
        };
        let handling = self.open_directed_request_handling(&connection, metadata)?;
        if handling.state != HandlingState::Claimed
            || handling.claim.consumer_id != request.consumer_id
            || handling.claim.attempt != request.attempt
            || handling.claim.policy_digest != request.policy_digest
            || handling.claim.claim_expires_at_unix_milliseconds <= request.now_unix_milliseconds
        {
            return Ok(None);
        }
        verify_active_adapter_consumer_now(
            &connection,
            handling.claim.consumer_id,
            handling.claim.lease_id,
            request.now_unix_milliseconds,
        )?;
        self.verify_claimed_directed_request_event(
            &connection,
            handling.claim.conversation_id,
            handling.claim.request_message_id,
            handling.claim.responder_device_id,
            handling.claim.notification_id,
            handling.claim.consumer_id,
            handling.claim.lease_id,
            handling.claim.lease_generation,
            request.now_unix_milliseconds,
        )?;
        Ok(Some(handling.claim))
    }

    pub(crate) fn complete_directed_request_without_response(
        &self,
        request: CompleteDirectedRequest,
    ) -> Result<bool, ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProfileStoreError::Storage)?;
        let metadata = load_handling_metadata(
            &transaction,
            request.conversation_id,
            request.request_message_id,
            request.responder_device_id,
        )?
        .ok_or(ProfileStoreError::OperationNotFound)?;
        let existing = self.open_directed_request_handling(&transaction, metadata)?;
        if !completion_matches(&existing.claim, &request) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if existing.state == HandlingState::CompletedNoResponse {
            return Ok(false);
        }
        if existing.state != HandlingState::Claimed {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let completed = DirectedRequestHandling {
            claim: existing.claim,
            state: HandlingState::CompletedNoResponse,
            response_message_id: None,
            response_envelope_id: None,
            response_sender_counter: None,
            response_text: None,
            response_sent_at_unix_milliseconds: None,
            response_expires_at_unix_seconds: None,
        };
        self.update_directed_request_handling(&transaction, &completed)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(true)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the sealed response operation and recovery fields remain explicit"
    )]
    pub(super) fn reserve_directed_request_response_in(
        &self,
        connection: &Connection,
        claim: DirectedRequestClaim,
        reservation: super::OutboundReservation,
        inserted_outbox: bool,
        content: &ApplicationContent,
        reply_to: Option<MessageId>,
        sent_at_unix_milliseconds: u64,
        expires_at_unix_seconds: u64,
        now_unix_milliseconds: u64,
    ) -> Result<(), ProfileStoreError> {
        let ApplicationContent::Text(response_text) = content else {
            return Err(ProfileStoreError::InvalidTransition);
        };
        if reply_to != Some(claim.request_message_id) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let metadata = load_handling_metadata(
            connection,
            claim.conversation_id,
            claim.request_message_id,
            claim.responder_device_id,
        )?
        .ok_or(ProfileStoreError::OperationNotFound)?;
        let existing = self.open_directed_request_handling(connection, metadata)?;
        if existing.state == HandlingState::CompletedResponse
            && existing.claim == claim
            && existing.response_message_id == Some(reservation.message_id)
            && existing.response_envelope_id == Some(reservation.envelope_id)
            && existing.response_sender_counter == Some(reservation.sender_counter)
            && existing.response_text.as_deref().map(String::as_str) == Some(response_text.as_str())
            && existing.response_sent_at_unix_milliseconds == Some(sent_at_unix_milliseconds)
            && existing.response_expires_at_unix_seconds == Some(expires_at_unix_seconds)
        {
            return Ok(());
        }
        if existing.state != HandlingState::Claimed || existing.claim != claim {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if !inserted_outbox {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        self.require_live_directed_request_claim(connection, &claim, now_unix_milliseconds)?;
        if response_message_id_occupied_outside_outbox(
            connection,
            claim.conversation_id,
            reservation.message_id,
        )? {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        let completed = DirectedRequestHandling {
            claim,
            state: HandlingState::CompletedResponse,
            response_message_id: Some(reservation.message_id),
            response_envelope_id: Some(reservation.envelope_id),
            response_sender_counter: Some(reservation.sender_counter),
            response_text: Some(Zeroizing::new(response_text.clone())),
            response_sent_at_unix_milliseconds: Some(sent_at_unix_milliseconds),
            response_expires_at_unix_seconds: Some(expires_at_unix_seconds),
        };
        self.update_directed_request_handling(connection, &completed)
    }

    fn require_live_directed_request_claim(
        &self,
        connection: &Connection,
        claim: &DirectedRequestClaim,
        now_unix_milliseconds: u64,
    ) -> Result<(), ProfileStoreError> {
        if claim.claim_expires_at_unix_milliseconds <= now_unix_milliseconds {
            return Err(ProfileStoreError::InvalidAdapterLease);
        }
        require_active_collaboration_policy_digest(
            connection,
            claim.conversation_id,
            claim.policy_digest,
        )?;
        require_current_conversation_member(
            connection,
            claim.conversation_id,
            claim.responder_device_id,
        )?;
        verify_active_adapter_consumer_now(
            connection,
            claim.consumer_id,
            claim.lease_id,
            now_unix_milliseconds,
        )?;
        self.verify_claimed_directed_request_event(
            connection,
            claim.conversation_id,
            claim.request_message_id,
            claim.responder_device_id,
            claim.notification_id,
            claim.consumer_id,
            claim.lease_id,
            claim.lease_generation,
            now_unix_milliseconds,
        )?;
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable request and delivery claim identities remain explicit"
    )]
    fn verify_claimed_directed_request_event(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        request_message_id: MessageId,
        responder_device_id: DeviceId,
        notification_id: NotificationId,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
        lease_generation: u64,
        now_unix_milliseconds: u64,
    ) -> Result<u64, ProfileStoreError> {
        let sequence: i64 = connection
            .query_row(
                "SELECT event_sequence
                 FROM daemon_remote_event
                 WHERE notification_id = ?1",
                params![notification_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::OperationNotFound)?;
        let (event, state) =
            self.load_remote_event_record_in(connection, from_sql_integer(sequence)?)?;
        if event.notification_id != notification_id
            || event.conversation_id != conversation_id
            || event.kind != RemoteEventKind::ApplicationMessage
            || event.source_identifier.as_slice() != request_message_id.as_bytes()
            || state.status != RemoteEventStatus::Claimed
            || state.consumer_id != Some(consumer_id)
            || state.lease_id != Some(lease_id)
            || state.lease_generation != lease_generation
            || state
                .lease_expires_at_unix_milliseconds
                .is_none_or(|expiry| expiry <= now_unix_milliseconds)
        {
            return Err(ProfileStoreError::InvalidAdapterLease);
        }
        let claim_expiry = state
            .lease_expires_at_unix_milliseconds
            .ok_or(ProfileStoreError::CorruptData)?;
        let (history_cursor, history_sender) = self.verify_directed_request_message(
            connection,
            conversation_id,
            request_message_id,
            responder_device_id,
        )?;
        if history_cursor != event.relay_cursor || history_sender != event.sender {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(claim_expiry)
    }

    fn verify_directed_request_message(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        request_message_id: MessageId,
        responder_device_id: DeviceId,
    ) -> Result<(u64, DeviceId), ProfileStoreError> {
        let routing_id: Vec<u8> = connection
            .query_row(
                "SELECT routing_id
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let routing_id = KonclaveDomainCore::RoutingId::from_slice(&routing_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let history = self
            .load_history_record(connection, conversation_id, routing_id, request_message_id)?
            .ok_or(ProfileStoreError::OperationNotFound)?;
        let ApplicationContent::DirectedRequest(request) = history.message.content() else {
            return Err(ProfileStoreError::InvalidTransition);
        };
        if !history.complete
            || history.direction != MessageDirection::Inbound
            || history.message.message_id() != request_message_id
            || history.sender == responder_device_id
            || request.target_device_id() != responder_device_id
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        Ok((
            history.cursor.ok_or(ProfileStoreError::CorruptData)?,
            history.sender,
        ))
    }

    fn verify_completed_directed_request_response(
        &self,
        connection: &Connection,
        handling: &DirectedRequestHandling,
    ) -> Result<(), ProfileStoreError> {
        let response_message_id = handling
            .response_message_id
            .ok_or(ProfileStoreError::CorruptData)?;
        let response_text = handling
            .response_text
            .as_deref()
            .ok_or(ProfileStoreError::CorruptData)?;
        let outbox: Option<(Vec<u8>, i64, i64)> = connection
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    sender_counter,
                    status
                 FROM daemon_outbox
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    handling.claim.conversation_id.as_bytes().as_slice(),
                    response_message_id.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (envelope_id, sender_counter, outbox_status) =
            outbox.ok_or(ProfileStoreError::CorruptData)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let sender_counter = from_sql_integer(sender_counter)?;
        if handling.response_envelope_id != Some(envelope_id)
            || handling.response_sender_counter != Some(sender_counter)
            || !(1..=4).contains(&outbox_status)
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id: Vec<u8> = connection
            .query_row(
                "SELECT routing_id
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![handling.claim.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let routing_id = KonclaveDomainCore::RoutingId::from_slice(&routing_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let history = self.load_history_record(
            connection,
            handling.claim.conversation_id,
            routing_id,
            response_message_id,
        )?;
        match (outbox_status, history.as_ref()) {
            (1, None) | (4, None) => return Ok(()),
            (1, Some(history)) if !history.complete && history.cursor.is_none() => {}
            (2, Some(history)) if history.complete && history.cursor.is_none() => {}
            (3, Some(history)) if history.complete && history.cursor.is_some() => {}
            _ => return Err(ProfileStoreError::CorruptData),
        }
        let history = history.ok_or(ProfileStoreError::CorruptData)?;
        let ApplicationContent::Text(stored_response) = history.message.content() else {
            return Err(ProfileStoreError::CorruptData);
        };
        if history.direction != MessageDirection::Outbound
            || history.envelope_id != envelope_id
            || history.sender != handling.claim.responder_device_id
            || history.message.sender_counter() != sender_counter
            || history.message.reply_to() != Some(handling.claim.request_message_id)
            || stored_response.as_str() != response_text
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(())
    }

    fn require_directed_request_handling_capacity(
        &self,
        connection: &Connection,
    ) -> Result<(), ProfileStoreError> {
        require_directed_request_handling_capacity_for_count(directed_request_handling_count(
            connection,
        )?)
    }

    fn insert_directed_request_handling(
        &self,
        connection: &Connection,
        handling: &DirectedRequestHandling,
    ) -> Result<(), ProfileStoreError> {
        let sealed = self.seal_directed_request_handling(handling)?;
        let lease_generation = to_sql_integer(handling.claim.lease_generation)?;
        let claim_expiry = to_sql_integer(handling.claim.claim_expires_at_unix_milliseconds)?;
        let response_message_id = handling.response_message_id.map(MessageId::into_bytes);
        if connection
            .execute(
                "INSERT INTO daemon_directed_request_handling (
                    conversation_id,
                    request_message_id,
                    responder_device_id,
                    state,
                    notification_id,
                    consumer_id,
                    lease_id,
                    lease_generation,
                    claim_expires_at_unix_milliseconds,
                    attempt,
                    policy_digest,
                    response_message_id,
                    sealed_handling
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    handling.claim.conversation_id.as_bytes().as_slice(),
                    handling.claim.request_message_id.as_bytes().as_slice(),
                    handling.claim.responder_device_id.as_bytes().as_slice(),
                    handling_state_to_sql(handling.state),
                    handling.claim.notification_id.as_bytes().as_slice(),
                    handling.claim.consumer_id.as_bytes().as_slice(),
                    handling.claim.lease_id.as_bytes().as_slice(),
                    lease_generation,
                    claim_expiry,
                    i64::from(handling.claim.attempt),
                    handling.claim.policy_digest.as_bytes().as_slice(),
                    response_message_id.as_ref().map(<[u8; 16]>::as_slice),
                    sealed.as_bytes(),
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            == 1
        {
            Ok(())
        } else {
            Err(ProfileStoreError::Storage)
        }
    }

    fn update_directed_request_handling(
        &self,
        connection: &Connection,
        handling: &DirectedRequestHandling,
    ) -> Result<(), ProfileStoreError> {
        let sealed = self.seal_directed_request_handling(handling)?;
        let lease_generation = to_sql_integer(handling.claim.lease_generation)?;
        let claim_expiry = to_sql_integer(handling.claim.claim_expires_at_unix_milliseconds)?;
        let response_message_id = handling.response_message_id.map(MessageId::into_bytes);
        let changed = connection
            .execute(
                "UPDATE daemon_directed_request_handling
                 SET state = ?4,
                     notification_id = ?5,
                     consumer_id = ?6,
                     lease_id = ?7,
                     lease_generation = ?8,
                     claim_expires_at_unix_milliseconds = ?9,
                     attempt = ?10,
                     policy_digest = ?11,
                     response_message_id = ?12,
                     sealed_handling = ?13
                 WHERE conversation_id = ?1
                   AND request_message_id = ?2
                   AND responder_device_id = ?3",
                params![
                    handling.claim.conversation_id.as_bytes().as_slice(),
                    handling.claim.request_message_id.as_bytes().as_slice(),
                    handling.claim.responder_device_id.as_bytes().as_slice(),
                    handling_state_to_sql(handling.state),
                    handling.claim.notification_id.as_bytes().as_slice(),
                    handling.claim.consumer_id.as_bytes().as_slice(),
                    handling.claim.lease_id.as_bytes().as_slice(),
                    lease_generation,
                    claim_expiry,
                    i64::from(handling.claim.attempt),
                    handling.claim.policy_digest.as_bytes().as_slice(),
                    response_message_id.as_ref().map(<[u8; 16]>::as_slice),
                    sealed.as_bytes(),
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn open_directed_request_handling(
        &self,
        connection: &Connection,
        metadata: HandlingMetadata,
    ) -> Result<DirectedRequestHandling, ProfileStoreError> {
        let expected = decode_handling_metadata(metadata)?;
        let length: i64 = connection
            .query_row(
                "SELECT length(sealed_handling)
                 FROM daemon_directed_request_handling
                 WHERE conversation_id = ?1
                   AND request_message_id = ?2
                   AND responder_device_id = ?3",
                params![
                    expected.claim.conversation_id.as_bytes().as_slice(),
                    expected.claim.request_message_id.as_bytes().as_slice(),
                    expected.claim.responder_device_id.as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let length = validate_sealed_length(length, MAX_SEALED_HANDLING_RECORD_BYTES)?;
        let sealed: Vec<u8> = connection
            .query_row(
                "SELECT sealed_handling
                 FROM daemon_directed_request_handling
                 WHERE conversation_id = ?1
                   AND request_message_id = ?2
                   AND responder_device_id = ?3",
                params![
                    expected.claim.conversation_id.as_bytes().as_slice(),
                    expected.claim.request_message_id.as_bytes().as_slice(),
                    expected.claim.responder_device_id.as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed.len() != length {
            return Err(ProfileStoreError::CorruptData);
        }
        let sealed = SealedBlob::from_bytes(sealed).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &directed_request_handling_context(
                    &self.locked_profile.profile_id,
                    expected.claim.conversation_id,
                    expected.claim.request_message_id,
                    expected.claim.responder_device_id,
                )?,
                &sealed,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let opened = decode_directed_request_handling(&plaintext)?;
        if handling_metadata_equal(&expected, &opened) {
            Ok(opened)
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }

    fn seal_directed_request_handling(
        &self,
        handling: &DirectedRequestHandling,
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &directed_request_handling_context(
                    &self.locked_profile.profile_id,
                    handling.claim.conversation_id,
                    handling.claim.request_message_id,
                    handling.claim.responder_device_id,
                )?,
                &encode_directed_request_handling(handling)?,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn advance_directed_request_handling_state(
        &self,
        connection: &Connection,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let committed_count = self.open_directed_request_handling_state(
            self.load_directed_request_handling_state(connection)?,
        )?;
        let actual_count = directed_request_handling_count(connection)?;
        if committed_count != actual_count {
            return Err(ProfileStoreError::CorruptData);
        }
        self.seal_directed_request_handling_state(
            actual_count
                .checked_add(1)
                .ok_or(ProfileStoreError::DirectedRequestHandlingCapacityExceeded)?,
        )
    }

    fn load_directed_request_handling_state(
        &self,
        connection: &Connection,
    ) -> Result<Vec<u8>, ProfileStoreError> {
        let length: Option<i64> = connection
            .query_row(
                "SELECT length(sealed_state)
                 FROM daemon_directed_request_handling_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        validate_sealed_length(
            length.ok_or(ProfileStoreError::CorruptData)?,
            MAX_SEALED_HANDLING_STATE_BYTES,
        )?;
        connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_directed_request_handling_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn store_directed_request_handling_state(
        &self,
        connection: &Connection,
        sealed_state: &SealedBlob,
    ) -> Result<(), ProfileStoreError> {
        if connection
            .execute(
                "UPDATE daemon_directed_request_handling_state
                 SET sealed_state = ?1
                 WHERE singleton_id = 1",
                params![sealed_state.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            == 1
        {
            Ok(())
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }

    fn seal_directed_request_handling_state(
        &self,
        record_count: usize,
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &directed_request_handling_state_context(&self.locked_profile.profile_id)?,
                &encode_handling_state(record_count)?,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_directed_request_handling_state(
        &self,
        sealed_state: Vec<u8>,
    ) -> Result<usize, ProfileStoreError> {
        validate_sealed_bytes(&sealed_state, MAX_SEALED_HANDLING_STATE_BYTES)?;
        let sealed_state =
            SealedBlob::from_bytes(sealed_state).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &directed_request_handling_state_context(&self.locked_profile.profile_id)?,
                &sealed_state,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        decode_handling_state(&plaintext)
    }
}

fn load_handling_metadata(
    connection: &Connection,
    conversation_id: ConversationId,
    request_message_id: MessageId,
    responder_device_id: DeviceId,
) -> Result<Option<HandlingMetadata>, ProfileStoreError> {
    connection
        .query_row(
            "SELECT
                CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                CASE WHEN length(request_message_id) = 16 THEN request_message_id END,
                CASE WHEN length(responder_device_id) = 32 THEN responder_device_id END,
                state,
                CASE WHEN length(notification_id) = 16 THEN notification_id END,
                CASE WHEN length(consumer_id) = 16 THEN consumer_id END,
                CASE WHEN length(lease_id) = 16 THEN lease_id END,
                lease_generation,
                claim_expires_at_unix_milliseconds,
                attempt,
                CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                typeof(response_message_id),
                length(response_message_id),
                CASE WHEN typeof(response_message_id) = 'blob'
                    AND length(response_message_id) = 16
                    THEN response_message_id END,
                length(sealed_handling)
             FROM daemon_directed_request_handling
             WHERE conversation_id = ?1
               AND request_message_id = ?2
               AND responder_device_id = ?3",
            params![
                conversation_id.as_bytes().as_slice(),
                request_message_id.as_bytes().as_slice(),
                responder_device_id.as_bytes().as_slice(),
            ],
            handling_metadata_from_row,
        )
        .optional()
        .map_err(|_| ProfileStoreError::Storage)
}

fn handling_metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HandlingMetadata> {
    Ok(HandlingMetadata {
        conversation_id: row.get(0)?,
        request_message_id: row.get(1)?,
        responder_device_id: row.get(2)?,
        state: row.get(3)?,
        notification_id: row.get(4)?,
        consumer_id: row.get(5)?,
        lease_id: row.get(6)?,
        lease_generation: row.get(7)?,
        claim_expires_at_unix_milliseconds: row.get(8)?,
        attempt: row.get(9)?,
        policy_digest: row.get(10)?,
        response_message_storage_type: row.get(11)?,
        response_message_length: row.get(12)?,
        response_message_id: row.get(13)?,
        sealed_handling_length: row.get(14)?,
    })
}

fn decode_handling_metadata(
    metadata: HandlingMetadata,
) -> Result<DirectedRequestHandling, ProfileStoreError> {
    let state = handling_state_from_sql(metadata.state)?;
    let response_message_id = match (
        metadata.response_message_storage_type.as_str(),
        metadata.response_message_length,
        metadata.response_message_id,
    ) {
        ("null", None, None) => None,
        ("blob", Some(length), Some(value))
            if usize::try_from(length).ok() == Some(MessageId::LENGTH)
                && value.len() == MessageId::LENGTH =>
        {
            Some(MessageId::from_slice(&value).map_err(|_| ProfileStoreError::CorruptData)?)
        }
        _ => return Err(ProfileStoreError::CorruptData),
    };
    if (state == HandlingState::CompletedResponse) != response_message_id.is_some() {
        return Err(ProfileStoreError::CorruptData);
    }
    validate_sealed_length(
        metadata.sealed_handling_length,
        MAX_SEALED_HANDLING_RECORD_BYTES,
    )?;
    Ok(DirectedRequestHandling {
        claim: DirectedRequestClaim {
            conversation_id: ConversationId::from_slice(
                &metadata
                    .conversation_id
                    .ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
            request_message_id: MessageId::from_slice(
                &metadata
                    .request_message_id
                    .ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
            responder_device_id: DeviceId::from_slice(
                &metadata
                    .responder_device_id
                    .ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
            notification_id: NotificationId::from_slice(
                &metadata
                    .notification_id
                    .ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
            consumer_id: AdapterConsumerId::from_slice(
                &metadata.consumer_id.ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
            lease_id: AdapterLeaseId::from_slice(
                &metadata.lease_id.ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
            lease_generation: from_sql_integer(metadata.lease_generation)?,
            claim_expires_at_unix_milliseconds: from_sql_integer(
                metadata.claim_expires_at_unix_milliseconds,
            )?,
            attempt: u32::try_from(metadata.attempt).map_err(|_| ProfileStoreError::CorruptData)?,
            policy_digest: CollaborationPolicyDigest::from_slice(
                &metadata
                    .policy_digest
                    .ok_or(ProfileStoreError::CorruptData)?,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?,
        },
        state,
        response_message_id,
        response_envelope_id: None,
        response_sender_counter: None,
        response_text: None,
        response_sent_at_unix_milliseconds: None,
        response_expires_at_unix_seconds: None,
    })
}

fn claim_matches(claim: &DirectedRequestClaim, request: &ClaimDirectedRequest) -> bool {
    claim.conversation_id == request.conversation_id
        && claim.request_message_id == request.request_message_id
        && claim.responder_device_id == request.responder_device_id
        && claim.notification_id == request.notification_id
        && claim.consumer_id == request.consumer_id
        && claim.lease_id == request.lease_id
        && claim.lease_generation == request.lease_generation
        && claim.policy_digest == request.policy_digest
}

fn completion_matches(claim: &DirectedRequestClaim, request: &CompleteDirectedRequest) -> bool {
    claim.conversation_id == request.conversation_id
        && claim.request_message_id == request.request_message_id
        && claim.responder_device_id == request.responder_device_id
        && claim.consumer_id == request.consumer_id
        && claim.attempt == request.attempt
        && claim.policy_digest == request.policy_digest
}

fn require_current_conversation_member(
    connection: &Connection,
    conversation_id: ConversationId,
    device_id: DeviceId,
) -> Result<(), ProfileStoreError> {
    let is_member: bool = connection
        .query_row(
            "SELECT EXISTS (
                SELECT 1
                FROM daemon_conversation_binding
                WHERE conversation_id = ?1 AND device_id = ?2
             )",
            params![
                conversation_id.as_bytes().as_slice(),
                device_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    if !is_member {
        return Err(ProfileStoreError::InvalidTransition);
    }
    Ok(())
}

fn handling_state_to_sql(state: HandlingState) -> i64 {
    match state {
        HandlingState::Claimed => HANDLING_STATE_CLAIMED,
        HandlingState::CompletedResponse => HANDLING_STATE_COMPLETED_RESPONSE,
        HandlingState::CompletedNoResponse => HANDLING_STATE_COMPLETED_NO_RESPONSE,
    }
}

fn handling_state_from_sql(value: i64) -> Result<HandlingState, ProfileStoreError> {
    match value {
        HANDLING_STATE_CLAIMED => Ok(HandlingState::Claimed),
        HANDLING_STATE_COMPLETED_RESPONSE => Ok(HandlingState::CompletedResponse),
        HANDLING_STATE_COMPLETED_NO_RESPONSE => Ok(HandlingState::CompletedNoResponse),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn encode_directed_request_handling(
    handling: &DirectedRequestHandling,
) -> Result<Vec<u8>, ProfileStoreError> {
    let response_text = handling.response_text.as_deref().map(String::as_bytes);
    let response_length = response_text.map_or(0, <[u8]>::len);
    let response_present = handling.response_message_id.is_some()
        && handling.response_envelope_id.is_some()
        && handling
            .response_sender_counter
            .is_some_and(|counter| counter > 0)
        && response_length > 0
        && handling.response_sent_at_unix_milliseconds.is_some()
        && handling
            .response_expires_at_unix_seconds
            .is_some_and(|expiry| expiry > 0);
    if response_length > MAX_TEXT_BODY_BYTES
        || (handling.state == HandlingState::CompletedResponse) != response_present
        || (handling.state != HandlingState::CompletedResponse)
            && (handling.response_message_id.is_some()
                || handling.response_envelope_id.is_some()
                || handling.response_sender_counter.is_some()
                || response_text.is_some()
                || handling.response_sent_at_unix_milliseconds.is_some()
                || handling.response_expires_at_unix_seconds.is_some())
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut encoded = Vec::with_capacity(HANDLING_RECORD_FIXED_BYTES + response_length);
    encoded.push(HANDLING_RECORD_VERSION);
    encoded.extend_from_slice(handling.claim.conversation_id.as_bytes());
    encoded.extend_from_slice(handling.claim.request_message_id.as_bytes());
    encoded.extend_from_slice(handling.claim.responder_device_id.as_bytes());
    encoded.push(
        u8::try_from(handling_state_to_sql(handling.state))
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    encoded.extend_from_slice(handling.claim.notification_id.as_bytes());
    encoded.extend_from_slice(handling.claim.consumer_id.as_bytes());
    encoded.extend_from_slice(handling.claim.lease_id.as_bytes());
    encoded.extend_from_slice(&handling.claim.lease_generation.to_be_bytes());
    encoded.extend_from_slice(
        &handling
            .claim
            .claim_expires_at_unix_milliseconds
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&handling.claim.attempt.to_be_bytes());
    encoded.extend_from_slice(handling.claim.policy_digest.as_bytes());
    encoded.push(u8::from(handling.response_message_id.is_some()));
    encoded.extend_from_slice(
        handling
            .response_message_id
            .map_or([0; MessageId::LENGTH], MessageId::into_bytes)
            .as_slice(),
    );
    encoded.extend_from_slice(
        handling
            .response_envelope_id
            .map_or([0; EnvelopeId::LENGTH], EnvelopeId::into_bytes)
            .as_slice(),
    );
    encoded.extend_from_slice(
        &handling
            .response_sender_counter
            .unwrap_or_default()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &handling
            .response_sent_at_unix_milliseconds
            .unwrap_or_default()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &handling
            .response_expires_at_unix_seconds
            .unwrap_or_default()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &u32::try_from(response_length)
            .map_err(|_| ProfileStoreError::CorruptData)?
            .to_be_bytes(),
    );
    if let Some(response_text) = response_text {
        encoded.extend_from_slice(response_text);
    }
    Ok(encoded)
}

fn decode_directed_request_handling(
    bytes: &[u8],
) -> Result<DirectedRequestHandling, ProfileStoreError> {
    if bytes.len() < HANDLING_RECORD_FIXED_BYTES || bytes[0] != HANDLING_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut rest = &bytes[1..];
    let conversation_id = ConversationId::from_bytes(take_array(&mut rest)?);
    let request_message_id = MessageId::from_bytes(take_array(&mut rest)?);
    let responder_device_id = DeviceId::from_bytes(take_array(&mut rest)?);
    let state = handling_state_from_sql(i64::from(take_array::<1>(&mut rest)?[0]))?;
    let notification_id = NotificationId::from_bytes(take_array(&mut rest)?);
    let consumer_id = AdapterConsumerId::from_bytes(take_array(&mut rest)?);
    let lease_id = AdapterLeaseId::from_bytes(take_array(&mut rest)?);
    let lease_generation = u64::from_be_bytes(take_array(&mut rest)?);
    let claim_expires_at_unix_milliseconds = u64::from_be_bytes(take_array(&mut rest)?);
    let attempt = u32::from_be_bytes(take_array(&mut rest)?);
    let policy_digest = CollaborationPolicyDigest::from_bytes(take_array(&mut rest)?);
    let response_present = match take_array::<1>(&mut rest)?[0] {
        0 => false,
        1 => true,
        _ => return Err(ProfileStoreError::CorruptData),
    };
    let response_bytes = take_array::<{ MessageId::LENGTH }>(&mut rest)?;
    let response_message_id = response_present.then(|| MessageId::from_bytes(response_bytes));
    if !response_present && response_bytes != [0; MessageId::LENGTH] {
        return Err(ProfileStoreError::CorruptData);
    }
    let response_envelope_bytes = take_array::<{ EnvelopeId::LENGTH }>(&mut rest)?;
    let response_envelope_id =
        response_present.then(|| EnvelopeId::from_bytes(response_envelope_bytes));
    if !response_present && response_envelope_bytes != [0; EnvelopeId::LENGTH] {
        return Err(ProfileStoreError::CorruptData);
    }
    let response_sender_counter = u64::from_be_bytes(take_array(&mut rest)?);
    let response_sent_at_unix_milliseconds = u64::from_be_bytes(take_array(&mut rest)?);
    let response_expires_at_unix_seconds = u64::from_be_bytes(take_array(&mut rest)?);
    let response_length = usize::try_from(u32::from_be_bytes(take_array(&mut rest)?))
        .map_err(|_| ProfileStoreError::CorruptData)?;
    if response_length > MAX_TEXT_BODY_BYTES || rest.len() != response_length {
        return Err(ProfileStoreError::CorruptData);
    }
    let response_text = if response_length == 0 {
        None
    } else {
        Some(Zeroizing::new(
            String::from_utf8(rest.to_vec()).map_err(|_| ProfileStoreError::CorruptData)?,
        ))
    };
    if (state == HandlingState::CompletedResponse)
        != (response_message_id.is_some()
            && response_envelope_id.is_some()
            && response_sender_counter > 0
            && response_text.is_some()
            && response_expires_at_unix_seconds > 0)
    {
        return Err(ProfileStoreError::CorruptData);
    }
    if state != HandlingState::CompletedResponse
        && (response_message_id.is_some()
            || response_envelope_id.is_some()
            || response_sender_counter != 0
            || response_text.is_some()
            || response_sent_at_unix_milliseconds != 0
            || response_expires_at_unix_seconds != 0)
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let claim = DirectedRequestClaim {
        conversation_id,
        request_message_id,
        responder_device_id,
        notification_id,
        consumer_id,
        lease_id,
        lease_generation,
        claim_expires_at_unix_milliseconds,
        attempt,
        policy_digest,
    };
    if claim.lease_generation == 0
        || claim.claim_expires_at_unix_milliseconds == 0
        || claim.attempt == 0
        || claim.attempt > MAX_DIRECTED_REQUEST_HANDLING_ATTEMPTS
    {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(DirectedRequestHandling {
        claim,
        state,
        response_message_id,
        response_envelope_id,
        response_sender_counter: response_present.then_some(response_sender_counter),
        response_text,
        response_sent_at_unix_milliseconds: response_present
            .then_some(response_sent_at_unix_milliseconds),
        response_expires_at_unix_seconds: response_present
            .then_some(response_expires_at_unix_seconds),
    })
}

fn handling_metadata_equal(
    left: &DirectedRequestHandling,
    right: &DirectedRequestHandling,
) -> bool {
    left.claim == right.claim
        && left.state == right.state
        && left.response_message_id == right.response_message_id
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], ProfileStoreError> {
    if rest.len() < N {
        return Err(ProfileStoreError::CorruptData);
    }
    let (head, tail) = rest.split_at(N);
    *rest = tail;
    head.try_into().map_err(|_| ProfileStoreError::CorruptData)
}

fn directed_request_handling_context(
    profile_id: &super::ProfileId,
    conversation_id: ConversationId,
    request_message_id: MessageId,
    responder_device_id: DeviceId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::DirectedRequestHandling,
        &[
            profile_id.as_bytes(),
            conversation_id.as_bytes(),
            request_message_id.as_bytes(),
            responder_device_id.as_bytes(),
        ],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn directed_request_handling_state_context(
    profile_id: &super::ProfileId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::DirectedRequestHandlingState,
        &[profile_id.as_bytes()],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn encode_handling_state(record_count: usize) -> Result<Vec<u8>, ProfileStoreError> {
    let count = u64::try_from(record_count).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    let mut encoded = Vec::with_capacity(HANDLING_STATE_RECORD_BYTES);
    encoded.push(HANDLING_STATE_RECORD_VERSION);
    encoded.extend_from_slice(&count.to_be_bytes());
    Ok(encoded)
}

fn decode_handling_state(bytes: &[u8]) -> Result<usize, ProfileStoreError> {
    if bytes.len() != HANDLING_STATE_RECORD_BYTES || bytes[0] != HANDLING_STATE_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let count = u64::from_be_bytes(
        bytes[1..]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let count = usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)?;
    if count > MAX_DIRECTED_REQUEST_HANDLINGS {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(count)
}

fn directed_request_handling_count(connection: &Connection) -> Result<usize, ProfileStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM daemon_directed_request_handling",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)
}

fn require_directed_request_handling_capacity_for_count(
    count: usize,
) -> Result<(), ProfileStoreError> {
    if count >= MAX_DIRECTED_REQUEST_HANDLINGS {
        Err(ProfileStoreError::DirectedRequestHandlingCapacityExceeded)
    } else {
        Ok(())
    }
}

fn response_message_id_occupied_outside_outbox(
    connection: &Connection,
    conversation_id: ConversationId,
    response_message_id: MessageId,
) -> Result<bool, ProfileStoreError> {
    connection
        .query_row(
            "SELECT
                EXISTS(
                    SELECT 1 FROM daemon_message_history
                    WHERE conversation_id = ?1 AND message_id = ?2
                )
                OR EXISTS(
                    SELECT 1 FROM daemon_collaboration_policy_operation
                    WHERE conversation_id = ?1 AND message_id = ?2
                )
                OR EXISTS(
                    SELECT 1 FROM daemon_directed_request_handling
                    WHERE conversation_id = ?1 AND response_message_id = ?2
                )",
            params![
                conversation_id.as_bytes().as_slice(),
                response_message_id.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn validate_sealed_length(length: i64, maximum: usize) -> Result<usize, ProfileStoreError> {
    let length = usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)?;
    if length == 0 || length > maximum {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(length)
}

fn validate_sealed_bytes(bytes: &[u8], maximum: usize) -> Result<(), ProfileStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(ProfileStoreError::CorruptData)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_request_handling_capacity_has_an_exact_boundary() {
        assert!(
            require_directed_request_handling_capacity_for_count(
                MAX_DIRECTED_REQUEST_HANDLINGS - 1
            )
            .is_ok()
        );
        assert_eq!(
            require_directed_request_handling_capacity_for_count(MAX_DIRECTED_REQUEST_HANDLINGS),
            Err(ProfileStoreError::DirectedRequestHandlingCapacityExceeded)
        );
        assert_eq!(
            require_directed_request_handling_capacity_for_count(
                MAX_DIRECTED_REQUEST_HANDLINGS + 1
            ),
            Err(ProfileStoreError::DirectedRequestHandlingCapacityExceeded)
        );
    }
}
