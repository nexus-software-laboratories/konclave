use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use KonclaveClientLibrary::{RelayAccessCredential, RelayEndpoint};
use KonclaveCryptographicCore::{
    ConversationSigningMaterial, DeviceIdentity, MlsWelcome, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding,
};
use KonclaveDomainCore::{
    AdapterConsumerId, AdapterLeaseId, ApplicationMessage, ConversationId, ConversationRole,
    ConversationState, DeliveryClass, DeviceCredentialBinding, DeviceId, Ed25519PublicKey,
    EnvelopeId, Invitation, InvitationId, JoinProof, MAX_MEMBERS, MembershipChange,
    MembershipOperationId, MessageId, NotificationId, RelayEnvelope, RoutingId,
    StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_conversation_state, decode_device_credential_binding,
    decode_invitation, decode_join_proof, decode_membership_control, decode_relay_envelope,
    encode_application_message, encode_conversation_state, encode_device_credential_binding,
    encode_invitation, encode_join_proof, encode_relay_envelope,
};
use KonclaveSecretStorage::{
    MAX_SECRET_PLAINTEXT_BYTES, SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer,
};
use fs4::{FileExt, TryLockError};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use zeroize::Zeroizing;

const PROFILE_SCHEMA_VERSION: u32 = 10;
const MAX_PROFILE_ID_BYTES: usize = 32;
const MAX_SEALED_RECORD_BYTES: usize = MAX_SECRET_PLAINTEXT_BYTES + 64;
const MAX_LOCAL_BINDINGS: usize = MAX_MEMBERS + 1;
pub(crate) const MAX_CONVERSATION_PAGE_SIZE: usize = 100;
const MAX_PENDING_OUTBOX: usize = 32;
const MAX_MESSAGE_PAGE_SIZE: usize = 100;
const LOCAL_RECORD_VERSION: u8 = 1;
const OUTBOX_RECORD_SCOPE: u8 = 1;
const INBOX_ENVELOPE_RECORD_SCOPE: u8 = 2;
const INBOX_MESSAGE_RECORD_SCOPE: u8 = 3;
const CURSOR_OBSERVATION_RECORD_SCOPE: u8 = 4;
const SENDER_COUNTER_RECORD_SCOPE: u8 = 5;
const MESSAGE_HISTORY_RECORD_SCOPE: u8 = 6;
const MEMBERSHIP_OUTBOX_RECORD_SCOPE: u8 = 7;
const MEMBERSHIP_INBOX_ENVELOPE_RECORD_SCOPE: u8 = 8;
const MEMBERSHIP_INBOX_TRANSITION_RECORD_SCOPE: u8 = 9;
const PENDING_JOIN_RECORD_SCOPE: u8 = 10;
const PENDING_JOIN_PROOF_RECORD_SCOPE: u8 = 11;
const PENDING_JOIN_RECEIPT_RECORD_SCOPE: u8 = 12;
const REPLAY_HEAD_RECORD_SCOPE: u8 = 13;
const REMOTE_EVENT_RECORD_SCOPE: u8 = 14;
const REMOTE_EVENT_STATE_RECORD_SCOPE: u8 = 15;
const REMOTE_EVENT_RECORD_VERSION: u8 = 1;
const REMOTE_EVENT_HEAD_RECORD_VERSION: u8 = 1;
const REMOTE_EVENT_HEAD_RECORD_SCOPE: u8 = 16;
const REMOTE_EVENT_POLICY_RECORD_VERSION: u8 = 1;
const REMOTE_EVENT_POLICY_RECORD_SCOPE: u8 = 17;
const REMOTE_EVENT_FLOOR_RECORD_SCOPE: u8 = 18;
const MAX_REMOTE_EVENT_BATCH: usize = 50;
const MAX_REMOTE_EVENT_BATCH_BYTES: usize = 1024 * 1024;
const MAX_PENDING_REMOTE_EVENTS: usize = 1_024;
const MAX_PENDING_REMOTE_EVENTS_PER_CONVERSATION: usize = 128;
const MAX_PENDING_REMOTE_EVENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_REMOTE_EVENT_BYTES_PER_CONVERSATION: usize = 1024 * 1024;
const MAX_REMOTE_EVENT_TERMINAL_RECORDS: usize = 256;
const MAX_REMOTE_EVENT_RECORDS: usize =
    MAX_PENDING_REMOTE_EVENTS + MAX_REMOTE_EVENT_TERMINAL_RECORDS;
const MAX_ADAPTER_LEASE_MILLISECONDS: u64 = 5 * 60 * 1_000;
const OUTBOX_TERMINAL_REASON_EXPIRED: i64 = 1;
const OUTBOX_TERMINAL_REASON_REMOVED: i64 = 2;
const PENDING_JOIN_CHECKPOINT_VERSION: u8 = 1;
const REPLAY_HEAD_VERSION_V1: u8 = 1;
const REPLAY_HEAD_VERSION_V2: u8 = 2;

type InboxMessageMetadata = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, i64);
type HistoryMetadata = (Vec<u8>, Option<i64>, i64, i64, Vec<u8>, i64, i64, i64);
type PendingJoinMetadata = (
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
);
type PendingJoinBlobs = (
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
type MembershipRequestColumns = (Option<i64>, Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>);
type ConversationMetadata = (Vec<u8>, i64, i64, i64, i64, Option<i64>);
type OutboundApplicationMetadata = (Vec<u8>, i64, Option<i64>, Option<i64>);
type RemoteEventStorageMetadata = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    Option<i64>,
    i64,
    i64,
);

/// Portable, filesystem-safe local profile identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProfileId(String);

impl ProfileId {
    /// Parses a non-empty ASCII profile identifier.
    ///
    /// # Errors
    ///
    /// Returns a validation error for unsafe characters or excessive length.
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self, ProfileStoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROFILE_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProfileStoreError::InvalidProfileId);
        }

        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Exclusive profile directory and its deterministic database paths.
pub(crate) struct LockedProfile {
    profile_id: ProfileId,
    directory: PathBuf,
    _lock: File,
}

impl LockedProfile {
    /// Creates the profile directory and acquires its non-blocking exclusive lock.
    ///
    /// # Errors
    ///
    /// Returns a typed I/O or lock-conflict error.
    pub(crate) fn acquire(root: &Path, profile_id: ProfileId) -> Result<Self, ProfileStoreError> {
        let directory = root.join(profile_id.as_str());
        std::fs::create_dir_all(&directory).map_err(|_| ProfileStoreError::Io)?;
        let lock_path = directory.join("profile.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|_| ProfileStoreError::Io)?;
        match FileExt::try_lock(&lock) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(ProfileStoreError::ProfileLocked),
            Err(TryLockError::Error(_)) => return Err(ProfileStoreError::Io),
        }
        Ok(Self {
            profile_id,
            directory,
            _lock: lock,
        })
    }

    #[must_use]
    pub(crate) fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub(crate) fn mls_database_path(&self) -> PathBuf {
        self.directory.join("mls.sqlite")
    }

    fn profile_database_path(&self) -> PathBuf {
        self.directory.join("profile.sqlite")
    }

    /// Opens the sealed application store while retaining this profile lock.
    ///
    /// # Errors
    ///
    /// Returns a typed SQLite, schema, or profile-identity error.
    pub(crate) fn open_store(
        self,
        sealer: SecretSealer,
    ) -> Result<ProfileStore, ProfileStoreError> {
        let connection =
            Connection::open(self.profile_database_path()).map_err(|_| ProfileStoreError::Io)?;
        let source_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        if source_version == 2 {
            validate_v2_outbound_migration(&connection)?;
        }
        initialize_schema(&connection)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT profile_id FROM daemon_profile WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        match existing {
            Some(existing) if existing != self.profile_id.as_str() => {
                return Err(ProfileStoreError::ProfileMismatch);
            }
            Some(_) => {}
            None => {
                connection
                    .execute(
                        "INSERT INTO daemon_profile (singleton_id, profile_id)
                         VALUES (1, ?1)",
                        params![self.profile_id.as_str()],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
            }
        }
        let store = ProfileStore {
            connection: Mutex::new(connection),
            sealer: Arc::new(sealer),
            locked_profile: self,
        };
        store.verify_remote_event_journal()?;
        store.invalidate_remote_event_leases()?;
        store.migrate_legacy_history()?;
        Ok(store)
    }
}

/// Sealed profile, relay, conversation-policy, and credential persistence.
pub(crate) struct ProfileStore {
    connection: Mutex<Connection>,
    sealer: Arc<SecretSealer>,
    locked_profile: LockedProfile,
}

impl ProfileStore {
    /// Returns the path owned by the sealed MLS storage adapter.
    #[must_use]
    pub(crate) fn mls_database_path(&self) -> PathBuf {
        self.locked_profile.mls_database_path()
    }

    /// Enables or mutes automatic adapter delivery for one conversation.
    ///
    /// Muting affects future remote events only. Relay replay and sealed history
    /// continue independently.
    ///
    /// # Errors
    ///
    /// Returns a missing-conversation or storage error.
    pub(crate) fn set_adapter_delivery_enabled(
        &self,
        conversation_id: ConversationId,
        enabled: bool,
    ) -> Result<(), ProfileStoreError> {
        let routing_id = self.conversation_routing_id(conversation_id)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::RemoteEventDeliveryPolicy,
            conversation_id,
            routing_id,
            REMOTE_EVENT_POLICY_RECORD_SCOPE,
            conversation_id.as_bytes(),
            &encode_remote_event_delivery_policy(enabled),
        )?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_conversation
                 SET sealed_adapter_delivery_policy = ?1
                 WHERE conversation_id = ?2",
                params![blob.as_bytes(), conversation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::ConversationNotFound)
        }
    }

    /// Acquires or renews the single active adapter consumer lease.
    ///
    /// # Errors
    ///
    /// Returns a lease-range, active-consumer, sequence, or storage error.
    pub(crate) fn acquire_adapter_consumer(
        &self,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
        now_unix_milliseconds: u64,
        expires_at_unix_milliseconds: u64,
    ) -> Result<(), ProfileStoreError> {
        validate_adapter_lease_window(now_unix_milliseconds, expires_at_unix_milliseconds)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.reclaim_expired_remote_events_in(&transaction, now_unix_milliseconds)?;
        let existing: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT
                    CASE WHEN length(consumer_id) = 16 THEN consumer_id END,
                    CASE WHEN length(lease_id) = 16 THEN lease_id END,
                    lease_expires_at_unix_milliseconds
                 FROM daemon_adapter_consumer
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some((existing_consumer, existing_lease, existing_expiry)) = existing {
            let existing_consumer = AdapterConsumerId::from_slice(&existing_consumer)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let existing_lease = AdapterLeaseId::from_slice(&existing_lease)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let existing_expiry = from_sql_integer(existing_expiry)?;
            if existing_expiry > now_unix_milliseconds
                && (existing_consumer != consumer_id || existing_lease != lease_id)
            {
                return Err(ProfileStoreError::AdapterConsumerActive);
            }
            transaction
                .execute(
                    "DELETE FROM daemon_adapter_consumer WHERE singleton_id = 1",
                    [],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        transaction
            .execute(
                "INSERT INTO daemon_adapter_consumer (
                    singleton_id,
                    consumer_id,
                    lease_id,
                    lease_expires_at_unix_milliseconds
                 ) VALUES (1, ?1, ?2, ?3)",
                params![
                    consumer_id.as_bytes().as_slice(),
                    lease_id.as_bytes().as_slice(),
                    to_sql_integer(expires_at_unix_milliseconds)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Releases the active consumer and makes its unacknowledged claims pending.
    ///
    /// # Errors
    ///
    /// Returns a stale-lease or storage error.
    pub(crate) fn release_adapter_consumer(
        &self,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
    ) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let active: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT
                    CASE WHEN length(consumer_id) = 16 THEN consumer_id END,
                    CASE WHEN length(lease_id) = 16 THEN lease_id END
                 FROM daemon_adapter_consumer
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        match active {
            None => return Ok(()),
            Some((active_consumer, active_lease))
                if active_consumer.as_slice() == consumer_id.as_bytes()
                    && active_lease.as_slice() == lease_id.as_bytes() => {}
            Some(_) => return Err(ProfileStoreError::InvalidAdapterLease),
        }
        let claimed_sequences = {
            let mut statement = transaction
                .prepare(
                    "SELECT event_sequence
                     FROM daemon_remote_event
                     WHERE status = 2
                       AND lease_consumer_id = ?1
                       AND lease_id = ?2
                     ORDER BY event_sequence",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        consumer_id.as_bytes().as_slice(),
                        lease_id.as_bytes().as_slice()
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for sequence in claimed_sequences {
            let (event, state) =
                self.load_remote_event_record_in(&transaction, from_sql_integer(sequence)?)?;
            if state.status != RemoteEventStatus::Claimed
                || state.consumer_id != Some(consumer_id)
                || state.lease_id != Some(lease_id)
            {
                return Err(ProfileStoreError::CorruptData);
            }
            self.store_remote_event_delivery_state_in(
                &transaction,
                &event,
                &RemoteEventDeliveryState {
                    status: RemoteEventStatus::Pending,
                    consumer_id: None,
                    lease_id: None,
                    lease_generation: state.lease_generation,
                    lease_expires_at_unix_milliseconds: None,
                },
            )?;
        }
        transaction
            .execute(
                "DELETE FROM daemon_adapter_consumer
                 WHERE singleton_id = 1 AND consumer_id = ?1 AND lease_id = ?2",
                params![
                    consumer_id.as_bytes().as_slice(),
                    lease_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Claims a bounded fair batch of pending remote events.
    ///
    /// # Errors
    ///
    /// Returns a bounds, stale-lease, malformed-record, protocol, or storage error.
    pub(crate) fn claim_remote_events(
        &self,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
        now_unix_milliseconds: u64,
        expires_at_unix_milliseconds: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRemoteEvent>, ProfileStoreError> {
        if limit == 0 || limit > MAX_REMOTE_EVENT_BATCH {
            return Err(ProfileStoreError::InvalidTransition);
        }
        validate_adapter_lease_window(now_unix_milliseconds, expires_at_unix_milliseconds)?;
        let claimed = {
            let mut connection = self.lock()?;
            let transaction = connection
                .transaction()
                .map_err(|_| ProfileStoreError::Storage)?;
            // A claim is the adapter's proof of life, so it renews the lease it
            // already holds. Without this the lease would lapse at its attach-time
            // expiry and delivery would stop mid-conversation.
            renew_active_adapter_lease(
                &transaction,
                consumer_id,
                lease_id,
                now_unix_milliseconds,
                expires_at_unix_milliseconds,
            )?;
            self.reclaim_expired_remote_events_in(&transaction, now_unix_milliseconds)?;
            let candidates = {
                let mut statement = transaction
                    .prepare(
                        "WITH ranked AS (
                            SELECT
                                e.event_sequence,
                                CASE e.event_kind
                                    WHEN 1 THEN length(i.sealed_message)
                                    ELSE length(m.sealed_transition)
                                END AS delivery_length,
                                ROW_NUMBER() OVER (
                                    PARTITION BY e.conversation_id
                                    ORDER BY e.event_sequence
                                ) AS conversation_rank
                            FROM daemon_remote_event e
                            LEFT JOIN daemon_inbox i
                              ON i.conversation_id = e.conversation_id
                             AND i.cursor = e.relay_cursor
                             AND e.event_kind = 1
                            LEFT JOIN daemon_membership_inbox m
                              ON m.conversation_id = e.conversation_id
                             AND m.cursor = e.relay_cursor
                             AND e.event_kind BETWEEN 2 AND 5
                            WHERE e.status = 1
                         )
                         SELECT event_sequence, delivery_length
                         FROM ranked
                         ORDER BY conversation_rank, event_sequence
                         LIMIT ?1",
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                statement
                    .query_map(
                        params![
                            i64::try_from(limit)
                                .map_err(|_| ProfileStoreError::SequenceExhausted)?
                        ],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileStoreError::Storage)?
            };
            let mut selected = Vec::with_capacity(candidates.len());
            let mut selected_bytes = 0_usize;
            for (sequence, delivery_length) in candidates {
                validate_blob_length(delivery_length)?;
                let delivery_length =
                    usize::try_from(delivery_length).map_err(|_| ProfileStoreError::CorruptData)?;
                if selected_bytes
                    .checked_add(delivery_length)
                    .is_none_or(|total| total > MAX_REMOTE_EVENT_BATCH_BYTES)
                {
                    if selected.is_empty() {
                        return Err(ProfileStoreError::RemoteEventCapacityExceeded);
                    }
                    break;
                }
                selected_bytes += delivery_length;
                let sequence = from_sql_integer(sequence)?;
                let (event, state) = self.load_remote_event_record_in(&transaction, sequence)?;
                if state.status != RemoteEventStatus::Pending {
                    return Err(ProfileStoreError::InvalidTransition);
                }
                let generation = state
                    .lease_generation
                    .checked_add(1)
                    .ok_or(ProfileStoreError::SequenceExhausted)?;
                self.store_remote_event_delivery_state_in(
                    &transaction,
                    &event,
                    &RemoteEventDeliveryState {
                        status: RemoteEventStatus::Claimed,
                        consumer_id: Some(consumer_id),
                        lease_id: Some(lease_id),
                        lease_generation: generation,
                        lease_expires_at_unix_milliseconds: Some(expires_at_unix_milliseconds),
                    },
                )?;
                selected.push((sequence, generation));
            }
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
            selected
        };

        claimed
            .into_iter()
            .map(|(sequence, generation)| {
                Ok(ClaimedRemoteEvent {
                    event: self.load_remote_event_by_sequence(sequence)?,
                    lease_generation: generation,
                })
            })
            .collect()
    }

    /// Acknowledges one event accepted by the active harness adapter.
    ///
    /// # Errors
    ///
    /// Returns a missing-event, stale-lease, sequence, or storage error.
    pub(crate) fn acknowledge_remote_event(
        &self,
        notification_id: NotificationId,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
        lease_generation: u64,
        now_unix_milliseconds: u64,
    ) -> Result<(), ProfileStoreError> {
        self.finish_remote_event_claim(
            notification_id,
            consumer_id,
            lease_id,
            lease_generation,
            now_unix_milliseconds,
            RemoteEventStatus::Acknowledged,
        )
    }

    /// Counts pending and claimed remote events for bounded status reporting.
    ///
    /// Terminal records are excluded because they represent completed work rather
    /// than a backlog an adapter can act on.
    ///
    /// # Errors
    ///
    /// Returns a storage or range error.
    pub(crate) fn remote_event_counts(&self) -> Result<(u32, u32), ProfileStoreError> {
        let connection = self.lock()?;
        let pending: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM daemon_remote_event WHERE status = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let claimed: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM daemon_remote_event WHERE status = 2",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok((
            u32::try_from(pending).map_err(|_| ProfileStoreError::CorruptData)?,
            u32::try_from(claimed).map_err(|_| ProfileStoreError::CorruptData)?,
        ))
    }

    /// Releases one claimed event for later delivery.
    ///
    /// # Errors
    ///
    /// Returns a missing-event, stale-lease, sequence, or storage error.
    pub(crate) fn release_remote_event(
        &self,
        notification_id: NotificationId,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
        lease_generation: u64,
        now_unix_milliseconds: u64,
    ) -> Result<(), ProfileStoreError> {
        self.finish_remote_event_claim(
            notification_id,
            consumer_id,
            lease_id,
            lease_generation,
            now_unix_milliseconds,
            RemoteEventStatus::Pending,
        )
    }

    /// Removes a bounded contiguous prefix of acknowledged or suppressed events.
    ///
    /// The sealed floor preserves sequence and chain integrity after terminal rows
    /// are removed.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed-record, sequence, or storage error.
    pub(crate) fn prune_terminal_remote_events(
        &self,
        limit: usize,
    ) -> Result<usize, ProfileStoreError> {
        if limit == 0 || limit > MAX_REMOTE_EVENT_BATCH {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let pruned = self.prune_terminal_remote_events_in(&transaction, limit)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(pruned)
    }

    fn prune_terminal_remote_events_in(
        &self,
        connection: &Connection,
        limit: usize,
    ) -> Result<usize, ProfileStoreError> {
        let current_floor = self.load_remote_event_floor_in(connection)?;
        let floor_sequence = current_floor.as_ref().map_or(0, |value| value.sequence);
        let sequences = {
            let mut statement = connection
                .prepare(
                    "SELECT event_sequence
                     FROM daemon_remote_event
                     WHERE event_sequence > ?1
                     ORDER BY event_sequence
                     LIMIT ?2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        to_sql_integer(floor_sequence)?,
                        i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut previous_notification = current_floor.as_ref().map(|value| value.notification_id);
        let mut terminal = Vec::with_capacity(sequences.len());
        for sequence in sequences {
            let sequence = from_sql_integer(sequence)?;
            let (event, state) = self.load_remote_event_record_in(connection, sequence)?;
            if event.sequence
                != floor_sequence
                    .checked_add(
                        u64::try_from(terminal.len() + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?,
                    )
                    .ok_or(ProfileStoreError::SequenceExhausted)?
                || event.previous_notification_id != previous_notification
            {
                return Err(ProfileStoreError::CorruptData);
            }
            if !matches!(
                state.status,
                RemoteEventStatus::Acknowledged | RemoteEventStatus::Suppressed
            ) {
                break;
            }
            previous_notification = Some(event.notification_id);
            terminal.push(event);
        }
        let Some(new_floor) = terminal.last() else {
            return Ok(0);
        };
        let new_floor = RemoteEventHead {
            sequence: new_floor.sequence,
            notification_id: new_floor.notification_id,
        };
        let floor_blob = self.seal_remote_event_floor(&new_floor)?;
        for event in &terminal {
            let deleted = connection
                .execute(
                    "DELETE FROM daemon_remote_event
                     WHERE event_sequence = ?1 AND notification_id = ?2",
                    params![
                        to_sql_integer(event.sequence)?,
                        event.notification_id.as_bytes().as_slice()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if deleted != 1 {
                return Err(ProfileStoreError::InvalidTransition);
            }
        }
        let updated = connection
            .execute(
                "UPDATE daemon_profile
                 SET remote_event_floor_sequence = ?1,
                     sealed_remote_event_floor = ?2
                 WHERE singleton_id = 1 AND remote_event_floor_sequence = ?3",
                params![
                    to_sql_integer(new_floor.sequence)?,
                    floor_blob.as_bytes(),
                    to_sql_integer(floor_sequence)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if updated != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        Ok(terminal.len())
    }

    fn prune_excess_terminal_remote_events_in(
        &self,
        connection: &Connection,
    ) -> Result<(), ProfileStoreError> {
        let terminal_count: i64 = connection
            .query_row(
                "SELECT count(*)
                 FROM daemon_remote_event
                 WHERE status IN (3, 4)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let terminal_count =
            usize::try_from(terminal_count).map_err(|_| ProfileStoreError::CorruptData)?;
        let excess = terminal_count.saturating_sub(MAX_REMOTE_EVENT_TERMINAL_RECORDS);
        if excess > 0 {
            self.prune_terminal_remote_events_in(connection, excess.min(MAX_REMOTE_EVENT_BATCH))?;
        }
        Ok(())
    }

    fn finish_remote_event_claim(
        &self,
        notification_id: NotificationId,
        consumer_id: AdapterConsumerId,
        lease_id: AdapterLeaseId,
        lease_generation: u64,
        now_unix_milliseconds: u64,
        target: RemoteEventStatus,
    ) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let sequence: Option<i64> = transaction
            .query_row(
                "SELECT event_sequence
                 FROM daemon_remote_event
                 WHERE notification_id = ?1",
                params![notification_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (event, state) = self.load_remote_event_record_in(
            &transaction,
            from_sql_integer(sequence.ok_or(ProfileStoreError::OperationNotFound)?)?,
        )?;
        if event.notification_id != notification_id {
            return Err(ProfileStoreError::CorruptData);
        }
        if state.status == RemoteEventStatus::Acknowledged
            && target == RemoteEventStatus::Acknowledged
        {
            return Ok(());
        }
        if state.status == RemoteEventStatus::Pending && target == RemoteEventStatus::Pending {
            return Ok(());
        }
        if state.status != RemoteEventStatus::Claimed
            || state.consumer_id != Some(consumer_id)
            || state.lease_id != Some(lease_id)
            || state.lease_generation != lease_generation
            || state
                .lease_expires_at_unix_milliseconds
                .is_none_or(|expiry| expiry <= now_unix_milliseconds)
        {
            return Err(ProfileStoreError::InvalidAdapterLease);
        }
        verify_active_adapter_consumer_now(
            &transaction,
            consumer_id,
            lease_id,
            now_unix_milliseconds,
        )?;
        self.store_remote_event_delivery_state_in(
            &transaction,
            &event,
            &RemoteEventDeliveryState {
                status: target,
                consumer_id: None,
                lease_id: None,
                lease_generation,
                lease_expires_at_unix_milliseconds: None,
            },
        )?;
        if target == RemoteEventStatus::Acknowledged {
            self.prune_excess_terminal_remote_events_in(&transaction)?;
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    fn verify_remote_event_journal(&self) -> Result<(), ProfileStoreError> {
        let connection = self.lock()?;
        let (next_sequence, head) = self.load_remote_event_head_in(&connection)?;
        let floor = self.load_remote_event_floor_in(&connection)?;
        let count: i64 = connection
            .query_row("SELECT count(*) FROM daemon_remote_event", [], |row| {
                row.get(0)
            })
            .map_err(|_| ProfileStoreError::Storage)?;
        let count = from_sql_integer(count)?;
        if next_sequence == 1 {
            return if head.is_none() && floor.is_none() && count == 0 {
                Ok(())
            } else {
                Err(ProfileStoreError::CorruptData)
            };
        }
        let head = head.ok_or(ProfileStoreError::CorruptData)?;
        let floor_sequence = floor.as_ref().map_or(0, |value| value.sequence);
        if floor_sequence > head.sequence
            || head.sequence.checked_add(1) != Some(next_sequence)
            || count != head.sequence - floor_sequence
        {
            return Err(ProfileStoreError::CorruptData);
        }
        if head.sequence == floor_sequence {
            if floor.as_ref().map(|value| value.notification_id) != Some(head.notification_id) {
                return Err(ProfileStoreError::CorruptData);
            }
        } else {
            let stored_notification: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT CASE WHEN length(notification_id) = 16 THEN notification_id END
                     FROM daemon_remote_event
                     WHERE event_sequence = ?1",
                    params![to_sql_integer(head.sequence)?],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ProfileStoreError::Storage)?;
            if stored_notification.as_deref() != Some(head.notification_id.as_bytes()) {
                return Err(ProfileStoreError::CorruptData);
            }
        }
        drop(connection);
        let mut after_sequence = floor_sequence;
        let mut previous_notification = floor.map(|value| value.notification_id);
        loop {
            let sequences = {
                let connection = self.lock()?;
                let mut statement = connection
                    .prepare(
                        "SELECT event_sequence
                         FROM daemon_remote_event
                         WHERE event_sequence > ?1
                         ORDER BY event_sequence
                         LIMIT ?2",
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                statement
                    .query_map(
                        params![
                            to_sql_integer(after_sequence)?,
                            i64::try_from(MAX_MESSAGE_PAGE_SIZE)
                                .map_err(|_| ProfileStoreError::SequenceExhausted)?
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileStoreError::Storage)?
            };
            if sequences.is_empty() {
                break;
            }
            for sequence in &sequences {
                let sequence = from_sql_integer(*sequence)?;
                let record = {
                    let connection = self.lock()?;
                    self.load_remote_event_record_in(&connection, sequence)?.0
                };
                if after_sequence.checked_add(1) != Some(sequence)
                    || record.previous_notification_id != previous_notification
                {
                    return Err(ProfileStoreError::CorruptData);
                }
                self.load_remote_event_by_sequence(sequence)?;
                after_sequence = sequence;
                previous_notification = Some(record.notification_id);
            }
        }
        if after_sequence != head.sequence || previous_notification != Some(head.notification_id) {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(())
    }

    fn load_remote_event_head_in(
        &self,
        connection: &Connection,
    ) -> Result<(u64, Option<RemoteEventHead>), ProfileStoreError> {
        let (next_sequence, head_length): (i64, Option<i64>) = connection
            .query_row(
                "SELECT next_remote_event_sequence, length(sealed_remote_event_head)
                 FROM daemon_profile
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let next_sequence = from_sql_integer(next_sequence)?;
        let Some(head_length) = head_length else {
            return Ok((next_sequence, None));
        };
        validate_blob_length(head_length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_remote_event_head
                 FROM daemon_profile
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len()
            != usize::try_from(head_length).map_err(|_| ProfileStoreError::CorruptData)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &remote_event_head_record_context(&self.locked_profile.profile_id)?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let head = decode_remote_event_head(&plaintext)?;
        if head.sequence.checked_add(1) != Some(next_sequence) {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok((next_sequence, Some(head)))
    }

    fn seal_remote_event_head(
        &self,
        head: &RemoteEventHead,
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &remote_event_head_record_context(&self.locked_profile.profile_id)?,
                &encode_remote_event_head(head),
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn load_remote_event_floor_in(
        &self,
        connection: &Connection,
    ) -> Result<Option<RemoteEventHead>, ProfileStoreError> {
        let (floor_sequence, floor_length): (i64, Option<i64>) = connection
            .query_row(
                "SELECT remote_event_floor_sequence, length(sealed_remote_event_floor)
                 FROM daemon_profile
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let floor_sequence = from_sql_integer(floor_sequence)?;
        let Some(floor_length) = floor_length else {
            return if floor_sequence == 0 {
                Ok(None)
            } else {
                Err(ProfileStoreError::CorruptData)
            };
        };
        if floor_sequence == 0 {
            return Err(ProfileStoreError::CorruptData);
        }
        validate_blob_length(floor_length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_remote_event_floor
                 FROM daemon_profile
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len()
            != usize::try_from(floor_length).map_err(|_| ProfileStoreError::CorruptData)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &remote_event_floor_record_context(&self.locked_profile.profile_id)?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let floor = decode_remote_event_head(&plaintext)?;
        if floor.sequence != floor_sequence {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(Some(floor))
    }

    fn seal_remote_event_floor(
        &self,
        floor: &RemoteEventHead,
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &remote_event_floor_record_context(&self.locked_profile.profile_id)?,
                &encode_remote_event_head(floor),
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn invalidate_remote_event_leases(&self) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let sequences = {
            let mut statement = transaction
                .prepare(
                    "SELECT event_sequence
                     FROM daemon_remote_event
                     WHERE status = 2
                     ORDER BY event_sequence",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| row.get::<_, i64>(0))
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for sequence in sequences {
            let (event, state) =
                self.load_remote_event_record_in(&transaction, from_sql_integer(sequence)?)?;
            if state.status != RemoteEventStatus::Claimed {
                return Err(ProfileStoreError::CorruptData);
            }
            self.store_remote_event_delivery_state_in(
                &transaction,
                &event,
                &RemoteEventDeliveryState {
                    status: RemoteEventStatus::Pending,
                    consumer_id: None,
                    lease_id: None,
                    lease_generation: state.lease_generation,
                    lease_expires_at_unix_milliseconds: None,
                },
            )?;
        }
        transaction
            .execute("DELETE FROM daemon_adapter_consumer", [])
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    fn load_remote_event_by_sequence(
        &self,
        sequence: u64,
    ) -> Result<RemoteEvent, ProfileStoreError> {
        let (record, _) = {
            let connection = self.lock()?;
            self.load_remote_event_record_in(&connection, sequence)?
        };
        let notification_id = record.notification_id;
        let conversation_id = record.conversation_id;
        let relay_cursor = record.relay_cursor;
        let kind = record.kind;
        let sender = record.sender;
        let source_identifier = record.source_identifier;

        let payload = match kind {
            RemoteEventKind::ApplicationMessage => {
                let message_id = MessageId::from_slice(&source_identifier)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                let message = self.load_message_at(conversation_id, relay_cursor)?;
                if message.sender != sender || message.message.message_id() != message_id {
                    return Err(ProfileStoreError::CorruptData);
                }
                RemoteEventPayload::ApplicationMessage(message.message)
            }
            RemoteEventKind::MemberAdded
            | RemoteEventKind::MemberRemoved
            | RemoteEventKind::MemberRoleChanged
            | RemoteEventKind::LocalAccessRemoved => {
                let operation_id = MembershipOperationId::from_slice(&source_identifier)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                let transition =
                    match self.membership_inbox_operation(conversation_id, relay_cursor)? {
                        MembershipInboxOperation::Complete(transition) => transition,
                        _ => return Err(ProfileStoreError::CorruptData),
                    };
                if transition.sender != sender || transition.operation_id != operation_id {
                    return Err(ProfileStoreError::CorruptData);
                }
                let (authorization, _) = decode_membership_control(&transition.control)
                    .map_err(|_| ProfileStoreError::Protocol)?;
                match (kind, authorization.change()) {
                    (RemoteEventKind::MemberAdded, MembershipChange::Add(change)) => {
                        RemoteEventPayload::MemberAdded {
                            device_id: change.device_id(),
                            role: change.role(),
                        }
                    }
                    (RemoteEventKind::MemberRemoved, MembershipChange::Remove(change)) => {
                        RemoteEventPayload::MemberRemoved {
                            device_id: change.device_id(),
                        }
                    }
                    (RemoteEventKind::MemberRoleChanged, MembershipChange::ChangeRole(change)) => {
                        RemoteEventPayload::MemberRoleChanged {
                            device_id: change.device_id(),
                            role: change.role(),
                        }
                    }
                    (RemoteEventKind::LocalAccessRemoved, MembershipChange::Remove(change)) => {
                        RemoteEventPayload::LocalAccessRemoved {
                            device_id: change.device_id(),
                        }
                    }
                    _ => return Err(ProfileStoreError::CorruptData),
                }
            }
        };
        Ok(RemoteEvent {
            sequence,
            notification_id,
            conversation_id,
            relay_cursor,
            sender,
            payload,
        })
    }

    fn load_remote_event_record_in(
        &self,
        connection: &Connection,
        sequence: u64,
    ) -> Result<(RemoteEventRecord, RemoteEventDeliveryState), ProfileStoreError> {
        let metadata: Option<RemoteEventStorageMetadata> = connection
            .query_row(
                "SELECT
                    CASE WHEN length(e.notification_id) = 16 THEN e.notification_id END,
                    CASE WHEN length(e.conversation_id) = 32 THEN e.conversation_id END,
                    CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                    e.relay_cursor,
                    e.event_kind,
                    e.status,
                    CASE WHEN length(e.sender_device_id) = 32 THEN e.sender_device_id END,
                    CASE WHEN length(e.source_identifier) = 16 THEN e.source_identifier END,
                    CASE
                        WHEN e.lease_consumer_id IS NULL THEN NULL
                        WHEN length(e.lease_consumer_id) = 16 THEN e.lease_consumer_id
                    END,
                    CASE
                        WHEN e.lease_id IS NULL THEN NULL
                        WHEN length(e.lease_id) = 16 THEN e.lease_id
                    END,
                    e.lease_generation,
                    e.lease_expires_at_unix_milliseconds,
                    length(e.sealed_event),
                    length(e.sealed_delivery_state)
                 FROM daemon_remote_event e
                 JOIN daemon_conversation c USING (conversation_id)
                 WHERE e.event_sequence = ?1",
                params![to_sql_integer(sequence)?],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (
            notification_id,
            conversation_id,
            routing_id,
            relay_cursor,
            kind,
            status,
            sender,
            source_identifier,
            lease_consumer_id,
            lease_id,
            lease_generation,
            lease_expires_at,
            event_length,
            state_length,
        ) = metadata.ok_or(ProfileStoreError::OperationNotFound)?;
        validate_blob_length(event_length)?;
        validate_blob_length(state_length)?;
        let (sealed_event, sealed_state): (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT sealed_event, sealed_delivery_state
                 FROM daemon_remote_event
                 WHERE event_sequence = ?1",
                params![to_sql_integer(sequence)?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed_event.len()
            != usize::try_from(event_length).map_err(|_| ProfileStoreError::CorruptData)?
            || sealed_state.len()
                != usize::try_from(state_length).map_err(|_| ProfileStoreError::CorruptData)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let notification_id = NotificationId::from_slice(&notification_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let sender = DeviceId::from_slice(&sender).map_err(|_| ProfileStoreError::CorruptData)?;
        let source_identifier: [u8; 16] = source_identifier
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let event_plaintext = self.open_operation_record(
            SecretRecordKind::RemoteEvent,
            conversation_id,
            routing_id,
            REMOTE_EVENT_RECORD_SCOPE,
            notification_id.as_bytes(),
            sealed_event,
        )?;
        let event = decode_remote_event_record(conversation_id, &event_plaintext)?;
        let state_plaintext = self.open_operation_record(
            SecretRecordKind::RemoteEventDeliveryState,
            conversation_id,
            routing_id,
            REMOTE_EVENT_STATE_RECORD_SCOPE,
            notification_id.as_bytes(),
            sealed_state,
        )?;
        let delivery_state = decode_remote_event_delivery_state(&state_plaintext)?;
        let column_status = remote_event_status(status)?;
        let column_consumer = lease_consumer_id
            .map(|value| {
                AdapterConsumerId::from_slice(&value).map_err(|_| ProfileStoreError::CorruptData)
            })
            .transpose()?;
        let column_lease = lease_id
            .map(|value| {
                AdapterLeaseId::from_slice(&value).map_err(|_| ProfileStoreError::CorruptData)
            })
            .transpose()?;
        let column_expiry = lease_expires_at.map(from_sql_integer).transpose()?;
        if event.sequence != sequence
            || event.notification_id != notification_id
            || event.conversation_id != conversation_id
            || event.routing_id != routing_id
            || event.relay_cursor != from_sql_integer(relay_cursor)?
            || event.kind != remote_event_kind(kind)?
            || event.sender != sender
            || event.source_identifier != source_identifier
            || delivery_state.status != column_status
            || delivery_state.consumer_id != column_consumer
            || delivery_state.lease_id != column_lease
            || delivery_state.lease_generation != from_sql_integer(lease_generation)?
            || delivery_state.lease_expires_at_unix_milliseconds != column_expiry
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok((event, delivery_state))
    }

    fn store_remote_event_delivery_state_in(
        &self,
        connection: &Connection,
        event: &RemoteEventRecord,
        state: &RemoteEventDeliveryState,
    ) -> Result<(), ProfileStoreError> {
        let plaintext = encode_remote_event_delivery_state(state)?;
        let sealed = self.seal_operation_record(
            SecretRecordKind::RemoteEventDeliveryState,
            event.conversation_id,
            event.routing_id,
            REMOTE_EVENT_STATE_RECORD_SCOPE,
            event.notification_id.as_bytes(),
            &plaintext,
        )?;
        let changed = connection
            .execute(
                "UPDATE daemon_remote_event
                 SET status = ?1,
                     sealed_delivery_state = ?2,
                     lease_consumer_id = ?3,
                     lease_id = ?4,
                     lease_generation = ?5,
                     lease_expires_at_unix_milliseconds = ?6
                 WHERE event_sequence = ?7",
                params![
                    state.status as i64,
                    sealed.as_bytes(),
                    state.consumer_id.map(|value| value.into_bytes().to_vec()),
                    state.lease_id.map(|value| value.into_bytes().to_vec()),
                    to_sql_integer(state.lease_generation)?,
                    state
                        .lease_expires_at_unix_milliseconds
                        .map(to_sql_integer)
                        .transpose()?,
                    to_sql_integer(event.sequence)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn reclaim_expired_remote_events_in(
        &self,
        connection: &Connection,
        now_unix_milliseconds: u64,
    ) -> Result<(), ProfileStoreError> {
        let sequences = {
            let mut statement = connection
                .prepare(
                    "SELECT event_sequence
                     FROM daemon_remote_event
                     WHERE status = 2
                       AND lease_expires_at_unix_milliseconds <= ?1
                     ORDER BY event_sequence",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(params![to_sql_integer(now_unix_milliseconds)?], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for sequence in sequences {
            let (event, state) =
                self.load_remote_event_record_in(connection, from_sql_integer(sequence)?)?;
            if state.status != RemoteEventStatus::Claimed {
                return Err(ProfileStoreError::CorruptData);
            }
            self.store_remote_event_delivery_state_in(
                connection,
                &event,
                &RemoteEventDeliveryState {
                    status: RemoteEventStatus::Pending,
                    consumer_id: None,
                    lease_id: None,
                    lease_generation: state.lease_generation,
                    lease_expires_at_unix_milliseconds: None,
                },
            )?;
        }
        Ok(())
    }

    /// Reports whether automatic delivery is enabled for one conversation.
    ///
    /// # Errors
    ///
    /// Returns a missing-conversation, integrity, or storage error. A conversation
    /// with no policy record reads as muted, so a profile migrated from an earlier
    /// schema never begins delivering without an explicit decision.
    pub(crate) fn adapter_delivery_enabled(
        &self,
        conversation_id: ConversationId,
    ) -> Result<bool, ProfileStoreError> {
        let routing_id = self.conversation_routing_id(conversation_id)?;
        let connection = self.lock()?;
        self.adapter_delivery_enabled_in(&connection, conversation_id, routing_id)
    }

    fn adapter_delivery_enabled_in(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
    ) -> Result<bool, ProfileStoreError> {
        let length: Option<i64> = connection
            .query_row(
                "SELECT length(sealed_adapter_delivery_policy)
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let Some(length) = length else {
            return Ok(false);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_adapter_delivery_policy
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)? {
            return Err(ProfileStoreError::CorruptData);
        }
        let plaintext = self.open_operation_record(
            SecretRecordKind::RemoteEventDeliveryPolicy,
            conversation_id,
            routing_id,
            REMOTE_EVENT_POLICY_RECORD_SCOPE,
            conversation_id.as_bytes(),
            bytes,
        )?;
        decode_remote_event_delivery_policy(&plaintext)
    }

    fn remote_event_delivery_length_in(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        relay_cursor: u64,
        kind: RemoteEventKind,
    ) -> Result<usize, ProfileStoreError> {
        let length: Option<i64> = connection
            .query_row(
                "SELECT CASE ?1
                    WHEN 1 THEN (
                        SELECT length(sealed_message)
                        FROM daemon_inbox
                        WHERE conversation_id = ?2 AND cursor = ?3
                    )
                    ELSE (
                        SELECT length(sealed_transition)
                        FROM daemon_membership_inbox
                        WHERE conversation_id = ?2 AND cursor = ?3
                    )
                 END",
                params![
                    kind as i64,
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(relay_cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let length = length.ok_or(ProfileStoreError::CorruptData)?;
        validate_blob_length(length)?;
        usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)
    }

    fn pending_remote_event_bytes_in(
        &self,
        connection: &Connection,
        conversation_id: Option<ConversationId>,
    ) -> Result<usize, ProfileStoreError> {
        let bytes: i64 = connection
            .query_row(
                "SELECT COALESCE(SUM(
                    CASE e.event_kind
                        WHEN 1 THEN length(i.sealed_message)
                        ELSE length(m.sealed_transition)
                    END
                 ), 0)
                 FROM daemon_remote_event e
                 LEFT JOIN daemon_inbox i
                   ON i.conversation_id = e.conversation_id
                  AND i.cursor = e.relay_cursor
                  AND e.event_kind = 1
                 LEFT JOIN daemon_membership_inbox m
                   ON m.conversation_id = e.conversation_id
                  AND m.cursor = e.relay_cursor
                  AND e.event_kind BETWEEN 2 AND 5
                 WHERE e.status IN (1, 2)
                   AND (?1 IS NULL OR e.conversation_id = ?1)",
                params![conversation_id.map(|value| value.into_bytes().to_vec())],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        usize::try_from(bytes).map_err(|_| ProfileStoreError::CorruptData)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "authenticated remote-event identity remains explicit"
    )]
    fn insert_remote_event_in(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        relay_cursor: u64,
        notification_id: NotificationId,
        kind: RemoteEventKind,
        sender: DeviceId,
        self_device_id: DeviceId,
        source_identifier: [u8; 16],
    ) -> Result<(), ProfileStoreError> {
        if sender == self_device_id {
            return Ok(());
        }
        self.prune_excess_terminal_remote_events_in(connection)?;
        let total_events: i64 = connection
            .query_row("SELECT count(*) FROM daemon_remote_event", [], |row| {
                row.get(0)
            })
            .map_err(|_| ProfileStoreError::Storage)?;
        if usize::try_from(total_events)
            .ok()
            .is_none_or(|count| count >= MAX_REMOTE_EVENT_RECORDS)
        {
            return Err(ProfileStoreError::RemoteEventCapacityExceeded);
        }
        let status = if self.adapter_delivery_enabled_in(connection, conversation_id, routing_id)? {
            RemoteEventStatus::Pending
        } else {
            RemoteEventStatus::Suppressed
        };
        if status == RemoteEventStatus::Pending {
            let delivery_length = self.remote_event_delivery_length_in(
                connection,
                conversation_id,
                relay_cursor,
                kind,
            )?;
            let profile_pending: i64 = connection
                .query_row(
                    "SELECT count(*)
                     FROM daemon_remote_event
                     WHERE status IN (1, 2)",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            let conversation_pending: i64 = connection
                .query_row(
                    "SELECT count(*)
                     FROM daemon_remote_event
                     WHERE conversation_id = ?1 AND status IN (1, 2)",
                    params![conversation_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            let profile_pending_bytes = self.pending_remote_event_bytes_in(connection, None)?;
            let conversation_pending_bytes =
                self.pending_remote_event_bytes_in(connection, Some(conversation_id))?;
            if usize::try_from(profile_pending)
                .ok()
                .is_none_or(|count| count >= MAX_PENDING_REMOTE_EVENTS)
                || usize::try_from(conversation_pending)
                    .ok()
                    .is_none_or(|count| count >= MAX_PENDING_REMOTE_EVENTS_PER_CONVERSATION)
                || profile_pending_bytes
                    .checked_add(delivery_length)
                    .is_none_or(|bytes| bytes > MAX_PENDING_REMOTE_EVENT_BYTES)
                || conversation_pending_bytes
                    .checked_add(delivery_length)
                    .is_none_or(|bytes| bytes > MAX_PENDING_REMOTE_EVENT_BYTES_PER_CONVERSATION)
            {
                return Err(ProfileStoreError::RemoteEventCapacityExceeded);
            }
        }
        let (sequence, previous_head) = self.load_remote_event_head_in(connection)?;
        if (sequence == 1) != previous_head.is_none() {
            return Err(ProfileStoreError::CorruptData);
        }
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        let event = RemoteEventRecord {
            sequence,
            notification_id,
            conversation_id,
            routing_id,
            relay_cursor,
            kind,
            sender,
            source_identifier,
            previous_notification_id: previous_head.as_ref().map(|head| head.notification_id),
        };
        let event_blob = self.seal_operation_record(
            SecretRecordKind::RemoteEvent,
            conversation_id,
            routing_id,
            REMOTE_EVENT_RECORD_SCOPE,
            notification_id.as_bytes(),
            &encode_remote_event_record(&event),
        )?;
        let delivery_state = RemoteEventDeliveryState {
            status,
            consumer_id: None,
            lease_id: None,
            lease_generation: 0,
            lease_expires_at_unix_milliseconds: None,
        };
        let state_blob = self.seal_operation_record(
            SecretRecordKind::RemoteEventDeliveryState,
            conversation_id,
            routing_id,
            REMOTE_EVENT_STATE_RECORD_SCOPE,
            notification_id.as_bytes(),
            &encode_remote_event_delivery_state(&delivery_state)?,
        )?;
        let head_blob = self.seal_remote_event_head(&RemoteEventHead {
            sequence,
            notification_id,
        })?;
        connection
            .execute(
                "INSERT INTO daemon_remote_event (
                    event_sequence,
                    notification_id,
                    conversation_id,
                    relay_cursor,
                    event_kind,
                    status,
                    sender_device_id,
                    source_identifier,
                    sealed_event,
                    sealed_delivery_state,
                    lease_consumer_id,
                    lease_id,
                    lease_generation,
                    lease_expires_at_unix_milliseconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, 0, NULL)",
                params![
                    to_sql_integer(sequence)?,
                    notification_id.as_bytes().as_slice(),
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(relay_cursor)?,
                    kind as i64,
                    status as i64,
                    sender.as_bytes().as_slice(),
                    source_identifier.as_slice(),
                    event_blob.as_bytes(),
                    state_blob.as_bytes()
                ],
            )
            .map_err(map_operation_insert_error)?;
        let updated = connection
            .execute(
                "UPDATE daemon_profile
                 SET next_remote_event_sequence = ?1,
                     sealed_remote_event_head = ?2
                 WHERE singleton_id = 1 AND next_remote_event_sequence = ?3",
                params![
                    to_sql_integer(next_sequence)?,
                    head_blob.as_bytes(),
                    to_sql_integer(sequence)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if updated != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if status == RemoteEventStatus::Suppressed {
            self.prune_excess_terminal_remote_events_in(connection)?;
        }
        Ok(())
    }

    fn migrate_legacy_history(&self) -> Result<(), ProfileStoreError> {
        let missing_outbound: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*)
                 FROM daemon_outbox o
                 LEFT JOIN daemon_message_history h
                   ON h.conversation_id = o.conversation_id
                  AND h.message_id = o.message_id
                 WHERE o.status IN (2, 3) AND h.message_id IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if missing_outbound != 0 {
            return Err(ProfileStoreError::LegacyOutboundRecoveryUnsupported);
        }
        let mut after_conversation: Option<Vec<u8>> = None;
        let mut after_cursor = 0_i64;
        loop {
            let batch = {
                let connection = self.lock()?;
                let mut statement = connection
                    .prepare(
                        "SELECT
                            CASE WHEN length(i.conversation_id) = 32
                                THEN i.conversation_id
                            END,
                            i.cursor,
                            CASE WHEN length(i.envelope_id) = 16
                                THEN i.envelope_id
                            END,
                            i.status
                         FROM daemon_inbox i
                         LEFT JOIN daemon_message_history h
                           ON h.conversation_id = i.conversation_id
                          AND h.message_id = i.message_id
                         WHERE i.status IN (2, 3)
                           AND h.message_id IS NULL
                           AND (
                                ?1 IS NULL
                                OR i.conversation_id > ?1
                                OR (
                                    i.conversation_id = ?1
                                    AND i.cursor > ?2
                                )
                           )
                         ORDER BY i.conversation_id, i.cursor
                         LIMIT ?3",
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                statement
                    .query_map(
                        params![
                            after_conversation.as_deref(),
                            after_cursor,
                            i64::try_from(MAX_MESSAGE_PAGE_SIZE)
                                .map_err(|_| ProfileStoreError::SequenceExhausted)?
                        ],
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        },
                    )
                    .map_err(|_| ProfileStoreError::Storage)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileStoreError::Storage)?
            };
            if batch.is_empty() {
                break;
            }
            let batch_length = batch.len();
            let last = batch
                .last()
                .cloned()
                .ok_or(ProfileStoreError::CorruptData)?;
            for (conversation_id, cursor, envelope_id, status) in batch {
                let conversation_id = ConversationId::from_slice(&conversation_id)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                let cursor = from_sql_integer(cursor)?;
                let envelope_id = EnvelopeId::from_slice(&envelope_id)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                let routing_id = self.conversation_routing_id(conversation_id)?;
                let message = self.load_message_at(conversation_id, cursor)?;
                if message.envelope_id != envelope_id {
                    return Err(ProfileStoreError::CorruptData);
                }
                let mut connection = self.lock()?;
                let transaction = connection
                    .transaction()
                    .map_err(|_| ProfileStoreError::Storage)?;
                self.insert_or_verify_history(
                    &transaction,
                    conversation_id,
                    routing_id,
                    envelope_id,
                    Some(cursor),
                    MessageDirection::Inbound,
                    message.sender,
                    message.epoch,
                    &message.message,
                )?;
                if status == 3
                    && !self.complete_history(
                        &transaction,
                        conversation_id,
                        routing_id,
                        message.message.message_id(),
                        envelope_id,
                        cursor,
                    )?
                {
                    return Err(ProfileStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProfileStoreError::Storage)?;
            }
            after_conversation = Some(last.0);
            after_cursor = last.1;
            if batch_length < MAX_MESSAGE_PAGE_SIZE {
                break;
            }
        }
        Ok(())
    }

    /// Reopens the profile device root or generates and seals it exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed storage or cryptographic error.
    pub(crate) fn load_or_create_device(&self) -> Result<DeviceIdentity, ProfileStoreError> {
        let existing = self.read_profile_blob(
            "SELECT length(sealed_device_identity) FROM daemon_profile WHERE singleton_id = 1",
            "SELECT sealed_device_identity FROM daemon_profile WHERE singleton_id = 1",
        )?;
        if let Some(blob) = existing {
            return DeviceIdentity::open(
                &self.sealer,
                self.locked_profile.profile_id.as_bytes(),
                &blob,
            )
            .map_err(|_| ProfileStoreError::Cryptographic);
        }

        let identity = DeviceIdentity::generate().map_err(|_| ProfileStoreError::Cryptographic)?;
        let blob = identity
            .seal(&self.sealer, self.locked_profile.profile_id.as_bytes())
            .map_err(|_| ProfileStoreError::Cryptographic)?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_profile
                 SET sealed_device_identity = ?1
                 WHERE singleton_id = 1 AND sealed_device_identity IS NULL",
                params![blob.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::Storage);
        }
        Ok(identity)
    }

    /// Stores one normalized relay endpoint and sealed bearer credential.
    ///
    /// # Errors
    ///
    /// Returns a typed sealing or storage error.
    pub(crate) fn configure_relay(
        &self,
        endpoint: &RelayEndpoint,
        credential: &RelayAccessCredential,
    ) -> Result<(), ProfileStoreError> {
        let blob = credential
            .seal(
                &self.sealer,
                self.locked_profile.profile_id.as_bytes(),
                endpoint,
            )
            .map_err(|_| ProfileStoreError::Credential)?;
        self.lock()?
            .execute(
                "UPDATE daemon_profile
                 SET relay_endpoint = ?1, sealed_relay_credential = ?2
                 WHERE singleton_id = 1",
                params![endpoint.as_str(), blob.as_bytes()],
            )
            .map(|_| ())
            .map_err(|_| ProfileStoreError::Storage)
    }

    /// Loads the configured relay endpoint and bearer credential.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, or storage error.
    pub(crate) fn relay_configuration(
        &self,
    ) -> Result<(RelayEndpoint, RelayAccessCredential), ProfileStoreError> {
        let connection = self.lock()?;
        let (endpoint, length): (Option<String>, Option<i64>) = connection
            .query_row(
                "SELECT relay_endpoint, length(sealed_relay_credential)
                 FROM daemon_profile WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let endpoint = endpoint.ok_or(ProfileStoreError::RelayNotConfigured)?;
        let length = length.ok_or(ProfileStoreError::RelayNotConfigured)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_relay_credential
                 FROM daemon_profile WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        drop(connection);
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let endpoint =
            RelayEndpoint::parse(&endpoint).map_err(|_| ProfileStoreError::CorruptData)?;
        let credential = RelayAccessCredential::open(
            &self.sealer,
            self.locked_profile.profile_id.as_bytes(),
            &endpoint,
            &blob,
        )
        .map_err(|_| ProfileStoreError::Credential)?;
        Ok((endpoint, credential))
    }

    /// Inserts one conversation's sealed signing material and authenticated policy.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, sealing, duplicate, or storage error.
    pub(crate) fn insert_conversation(
        &self,
        routing_id: RoutingId,
        signing_material: &ConversationSigningMaterial,
        state: &ConversationState,
        bindings: &[DeviceCredentialBinding],
    ) -> Result<(), ProfileStoreError> {
        self.insert_conversation_at_cursor(routing_id, signing_material, state, bindings, 0, None)
    }

    /// Inserts one joined conversation at its verified relay baseline cursor.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, sealing, duplicate, sequence, or storage error.
    pub(crate) fn insert_conversation_at_cursor(
        &self,
        routing_id: RoutingId,
        signing_material: &ConversationSigningMaterial,
        state: &ConversationState,
        bindings: &[DeviceCredentialBinding],
        replay_cursor: u64,
        replay_receipt: Option<&StoredRelayEnvelope>,
    ) -> Result<(), ProfileStoreError> {
        let conversation_id = signing_material.binding().conversation_id();
        if state.conversation_id() != conversation_id {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        if replay_cursor == 0 && replay_receipt.is_some()
            || replay_cursor > 0
                && replay_receipt.is_none_or(|receipt| {
                    receipt.cursor() != replay_cursor
                        || receipt.envelope().routing_id() != routing_id
                })
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        validate_bindings(state, signing_material.binding(), bindings)?;
        let signing_blob = signing_material
            .seal(&self.sealer, self.locked_profile.profile_id.as_bytes())
            .map_err(|_| ProfileStoreError::Cryptographic)?;
        let state_bytes =
            encode_conversation_state(state).map_err(|_| ProfileStoreError::Protocol)?;
        let state_blob = self.seal_conversation_record(
            SecretRecordKind::ConversationPolicyState,
            conversation_id,
            Some(routing_id),
            None,
            &state_bytes,
        )?;
        let mut sealed_bindings = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let bytes = encode_device_credential_binding(binding)
                .map_err(|_| ProfileStoreError::Protocol)?;
            let blob = self.seal_conversation_record(
                SecretRecordKind::ConversationCredentialBinding,
                conversation_id,
                None,
                Some(binding.device_id()),
                &bytes,
            )?;
            sealed_bindings.push((binding.device_id(), blob));
        }
        let replay_head = replay_receipt
            .map(|receipt| {
                self.seal_replay_head(
                    conversation_id,
                    routing_id,
                    0,
                    replay_cursor,
                    ReplayCompletionKind::Join,
                    state,
                    state,
                    receipt.envelope(),
                )
            })
            .transpose()?;

        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "INSERT INTO daemon_conversation (
                    conversation_id,
                    routing_id,
                    sealed_signing_material,
                    sealed_policy_state,
                    sender_counter,
                    replay_cursor,
                    sealed_replay_head
                 ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
                params![
                    conversation_id.as_bytes().as_slice(),
                    routing_id.as_bytes().as_slice(),
                    signing_blob.as_bytes(),
                    state_blob.as_bytes(),
                    to_sql_integer(replay_cursor)?,
                    replay_head.as_ref().map(SealedBlob::as_bytes)
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(ref details, _)
                    if details.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    ProfileStoreError::ConversationExists
                }
                _ => ProfileStoreError::Storage,
            })?;
        for (device_id, blob) in sealed_bindings {
            transaction
                .execute(
                    "INSERT INTO daemon_conversation_binding (
                        conversation_id, device_id, sealed_binding
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        conversation_id.as_bytes().as_slice(),
                        device_id.as_bytes().as_slice(),
                        blob.as_bytes()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        if let Some(receipt) = replay_receipt {
            self.insert_or_verify_cursor_observation(
                &transaction,
                conversation_id,
                routing_id,
                replay_cursor,
                receipt.envelope(),
            )?;
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Reserves one invitation-bound conversation signing key before KeyPackage
    /// generation.
    ///
    /// # Errors
    ///
    /// Returns a validation, duplicate, sealing, protocol, or storage error.
    #[allow(
        clippy::too_many_arguments,
        reason = "the pending join capability fields remain explicit"
    )]
    pub(crate) fn reserve_pending_join(
        &self,
        routing_id: RoutingId,
        signing_material: &ConversationSigningMaterial,
        invitation: &Invitation,
        issuer_public_key: Ed25519PublicKey,
        peer_bindings: &[DeviceCredentialBinding],
        verified_at_unix_seconds: u64,
    ) -> Result<(), ProfileStoreError> {
        let conversation_id = invitation.conversation_id();
        if verified_at_unix_seconds == 0
            || invitation.routing_id() != Some(routing_id)
            || signing_material.binding().conversation_id() != conversation_id
            || signing_material.binding().device_id() != invitation.expected_device_id()
            || invitation.issuer_device_id() == signing_material.binding().device_id()
            || peer_bindings.is_empty()
            || peer_bindings.len() > MAX_MEMBERS
            || peer_bindings.iter().any(|binding| {
                binding.conversation_id() != conversation_id
                    || binding.device_id() == signing_material.binding().device_id()
            })
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut issuer_found = false;
        for binding in peer_bindings {
            verify_device_credential_binding(binding)
                .map_err(|_| ProfileStoreError::Cryptographic)?;
            if !seen.insert(binding.device_id()) {
                return Err(ProfileStoreError::DuplicateOperation);
            }
            if binding.device_id() == invitation.issuer_device_id()
                && binding.device_root_public_key() == issuer_public_key
            {
                issuer_found = true;
            }
        }
        if !issuer_found {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let signing_blob = signing_material
            .seal(&self.sealer, self.locked_profile.profile_id.as_bytes())
            .map_err(|_| ProfileStoreError::Cryptographic)?;
        let encoded = encode_pending_join_record(invitation, issuer_public_key, peer_bindings)?;
        let join_blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            PENDING_JOIN_RECORD_SCOPE,
            conversation_id.as_bytes(),
            &encoded,
        )?;
        let inserted = self.lock()?.execute(
            "INSERT INTO daemon_pending_join (
                conversation_id,
                routing_id,
                status,
                verified_at_unix_seconds,
                sealed_signing_material,
                sealed_join,
                sealed_proof,
                sealed_state
             ) VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL, NULL)",
            params![
                conversation_id.as_bytes().as_slice(),
                routing_id.as_bytes().as_slice(),
                to_sql_integer(verified_at_unix_seconds)?,
                signing_blob.as_bytes(),
                join_blob.as_bytes()
            ],
        );
        match inserted {
            Ok(1) => Ok(()),
            Ok(_) => Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                let existing = self.load_pending_join(conversation_id)?;
                let existing_invitation = encode_invitation(&existing.invitation)
                    .map_err(|_| ProfileStoreError::Protocol)?;
                let expected_invitation =
                    encode_invitation(invitation).map_err(|_| ProfileStoreError::Protocol)?;
                if existing.routing_id == routing_id
                    && existing.verified_at_unix_seconds == verified_at_unix_seconds
                    && existing.signing_material.binding() == signing_material.binding()
                    && existing_invitation == expected_invitation
                    && existing.issuer_public_key == issuer_public_key
                    && same_verified_bindings(&existing.peer_bindings, peer_bindings)
                    && existing.proof.is_none()
                    && existing.state.is_none()
                {
                    Ok(())
                } else {
                    Err(ProfileStoreError::DuplicateOperation)
                }
            }

            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Attaches the generated one-time KeyPackage proof to a pending join.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, transition, sealing, protocol, or storage error.
    pub(crate) fn store_pending_join_proof(
        &self,
        conversation_id: ConversationId,
        proof: &JoinProof,
    ) -> Result<(), ProfileStoreError> {
        let pending = self.load_pending_join(conversation_id)?;
        let pending_invitation =
            encode_invitation(&pending.invitation).map_err(|_| ProfileStoreError::Protocol)?;
        let proof_invitation =
            encode_invitation(proof.invitation()).map_err(|_| ProfileStoreError::Protocol)?;
        if proof_invitation != pending_invitation
            || proof.credential() != pending.signing_material.binding()
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let encoded = encode_join_proof(proof).map_err(|_| ProfileStoreError::Protocol)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            pending.routing_id,
            PENDING_JOIN_PROOF_RECORD_SCOPE,
            conversation_id.as_bytes(),
            &encoded,
        )?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_pending_join
             SET status = 2, sealed_proof = ?1
             WHERE conversation_id = ?2 AND status = 1",
                params![blob.as_bytes(), conversation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.load_pending_join(conversation_id)?;
        if existing
            .proof
            .as_ref()
            .is_some_and(|existing| encode_join_proof(existing).ok() == Some(encoded))
        {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Loads one durable pending join capability.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, protocol, or storage error.
    pub(crate) fn load_pending_join(
        &self,
        conversation_id: ConversationId,
    ) -> Result<PendingJoin, ProfileStoreError> {
        let metadata: Option<PendingJoinMetadata> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    status,
                    verified_at_unix_seconds,
                    length(sealed_signing_material),
                    length(sealed_join),
                    length(sealed_proof),
                    length(sealed_state),
                    join_cursor,
                    CASE WHEN length(join_envelope_id) = 16 THEN join_envelope_id END,
                    length(sealed_join_receipt)
                 FROM daemon_pending_join
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (
            routing_id,
            status,
            verified_at,
            signing_length,
            join_length,
            proof_length,
            state_length,
            join_cursor,
            join_envelope_id,
            receipt_length,
        ) = metadata.ok_or(ProfileStoreError::OperationNotFound)?;
        if !matches!(
            (
                status,
                proof_length,
                state_length,
                join_cursor,
                join_envelope_id.as_ref(),
                receipt_length
            ),
            (1, None, None, None, None, None)
                | (2, Some(_), None, None, None, None)
                | (3, Some(_), Some(_), Some(_), Some(_), Some(_))
        ) {
            return Err(ProfileStoreError::CorruptData);
        }
        validate_blob_length(signing_length)?;
        validate_blob_length(join_length)?;
        if let Some(length) = proof_length {
            validate_blob_length(length)?;
        }
        if let Some(length) = state_length {
            validate_blob_length(length)?;
        }
        if let Some(length) = receipt_length {
            validate_blob_length(length)?;
        }
        let (signing_bytes, join_bytes, proof_bytes, state_bytes, receipt_bytes): PendingJoinBlobs =
            self.lock()?
                .query_row(
                    "SELECT
                    sealed_signing_material,
                    sealed_join,
                    sealed_proof,
                    sealed_state,
                    sealed_join_receipt
                 FROM daemon_pending_join
                 WHERE conversation_id = ?1",
                    params![conversation_id.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        if signing_bytes.len() != usize::try_from(signing_length).unwrap_or_default()
            || join_bytes.len() != usize::try_from(join_length).unwrap_or_default()
            || proof_bytes.as_ref().map(Vec::len)
                != proof_length.and_then(|length| usize::try_from(length).ok())
            || state_bytes.as_ref().map(Vec::len)
                != state_length.and_then(|length| usize::try_from(length).ok())
            || receipt_bytes.as_ref().map(Vec::len)
                != receipt_length.and_then(|length| usize::try_from(length).ok())
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let signing_blob =
            SealedBlob::from_bytes(signing_bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let signing_material = ConversationSigningMaterial::open(
            &self.sealer,
            self.locked_profile.profile_id.as_bytes(),
            conversation_id,
            &signing_blob,
        )
        .map_err(|_| ProfileStoreError::Cryptographic)?;
        let join_plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            PENDING_JOIN_RECORD_SCOPE,
            conversation_id.as_bytes(),
            join_bytes,
        )?;
        let (invitation, issuer_public_key, peer_bindings) =
            decode_pending_join_record(conversation_id, &join_plaintext)?;
        if invitation.expected_device_id() != signing_material.binding().device_id() {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let proof = proof_bytes
            .map(|bytes| {
                let plaintext = self.open_operation_record(
                    SecretRecordKind::LocalOperation,
                    conversation_id,
                    routing_id,
                    PENDING_JOIN_PROOF_RECORD_SCOPE,
                    conversation_id.as_bytes(),
                    bytes,
                )?;
                let proof =
                    decode_join_proof(&plaintext).map_err(|_| ProfileStoreError::Protocol)?;
                if proof.credential() != signing_material.binding()
                    || encode_invitation(proof.invitation())
                        .map_err(|_| ProfileStoreError::Protocol)?
                        != encode_invitation(&invitation)
                            .map_err(|_| ProfileStoreError::Protocol)?
                {
                    return Err(ProfileStoreError::ConversationMismatch);
                }
                Ok(proof)
            })
            .transpose()?;
        let checkpoint = state_bytes
            .map(|bytes| {
                let blob =
                    SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
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
                decode_pending_join_checkpoint(&plaintext)
            })
            .transpose()?;
        let (state, expected_commit_envelope_id) = checkpoint
            .map(|(state, envelope_id)| (Some(state), Some(envelope_id)))
            .unwrap_or((None, None));
        let join_receipt = match (join_cursor, join_envelope_id, receipt_bytes) {
            (Some(cursor), Some(envelope_id), Some(bytes)) => {
                let cursor = from_sql_integer(cursor)?;
                let envelope_id = EnvelopeId::from_slice(&envelope_id)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                let plaintext = self.open_operation_record(
                    SecretRecordKind::LocalOperation,
                    conversation_id,
                    routing_id,
                    PENDING_JOIN_RECEIPT_RECORD_SCOPE,
                    envelope_id.as_bytes(),
                    bytes,
                )?;
                let stored = decode_inbox_envelope_record(&plaintext)?;
                if stored.cursor() != cursor
                    || stored.envelope().envelope_id() != envelope_id
                    || stored.envelope().routing_id() != routing_id
                    || stored.envelope().delivery_class() != DeliveryClass::GroupCommit
                {
                    return Err(ProfileStoreError::CorruptData);
                }
                Some(stored)
            }
            (None, None, None) => None,
            _ => return Err(ProfileStoreError::CorruptData),
        };
        if expected_commit_envelope_id
            != join_receipt
                .as_ref()
                .map(|receipt| receipt.envelope().envelope_id())
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(PendingJoin {
            conversation_id,
            routing_id,
            verified_at_unix_seconds: from_sql_integer(verified_at)?,
            signing_material,
            invitation,
            proof,
            issuer_public_key,
            peer_bindings,
            state,
            expected_commit_envelope_id,
            join_receipt,
        })
    }

    /// Checkpoints the authenticated Welcome state before joined-group persistence.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, transition, sealing, protocol, or storage error.
    pub(crate) fn checkpoint_pending_join_state(
        &self,
        conversation_id: ConversationId,
        state: &ConversationState,
        expected_commit_envelope_id: EnvelopeId,
        receipt: &StoredRelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let pending = self.load_pending_join(conversation_id)?;
        let proof = pending
            .proof
            .as_ref()
            .ok_or(ProfileStoreError::InvalidTransition)?;
        let mut bindings = pending
            .peer_bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        bindings.push(pending.signing_material.binding().clone());
        if state.conversation_id() != conversation_id
            || state
                .member(pending.signing_material.binding().device_id())
                .is_none()
            || !state
                .consumed_invitation_ids()
                .contains(&proof.invitation().invitation_id())
            || receipt.envelope().routing_id() != pending.routing_id
            || receipt.envelope().delivery_class() != DeliveryClass::GroupCommit
            || receipt.envelope().envelope_id() != expected_commit_envelope_id
            || receipt
                .envelope()
                .expected_parent_epoch()
                .and_then(|epoch| epoch.checked_add(1))
                != Some(state.epoch())
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        validate_bindings(state, pending.signing_material.binding(), &bindings)?;
        let state_bytes = encode_pending_join_checkpoint(state, expected_commit_envelope_id)?;
        let state_blob = self.seal_conversation_record(
            SecretRecordKind::ConversationPolicyState,
            conversation_id,
            Some(pending.routing_id),
            None,
            &state_bytes,
        )?;
        let receipt_bytes = encode_inbox_envelope_record(receipt)?;
        let receipt_blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            pending.routing_id,
            PENDING_JOIN_RECEIPT_RECORD_SCOPE,
            receipt.envelope().envelope_id().as_bytes(),
            &receipt_bytes,
        )?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_pending_join
             SET status = 3,
                 sealed_state = ?1,
                 join_cursor = ?2,
                 join_envelope_id = ?3,
                 sealed_join_receipt = ?4
             WHERE conversation_id = ?5 AND status = 2",
                params![
                    state_blob.as_bytes(),
                    to_sql_integer(receipt.cursor())?,
                    receipt.envelope().envelope_id().as_bytes().as_slice(),
                    receipt_blob.as_bytes(),
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.load_pending_join(conversation_id)?;
        if existing.state.as_ref() == Some(state)
            && existing.expected_commit_envelope_id == Some(expected_commit_envelope_id)
            && existing.join_receipt.as_ref() == Some(receipt)
        {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Deletes a finalized pending join capability.
    ///
    /// # Errors
    ///
    /// Returns a missing or storage error.
    pub(crate) fn delete_pending_join(
        &self,
        conversation_id: ConversationId,
    ) -> Result<(), ProfileStoreError> {
        let changed = self
            .lock()?
            .execute(
                "DELETE FROM daemon_pending_join WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::OperationNotFound)
        }
    }

    /// Lists one bounded page of pending join identifiers.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed-row, or storage error.
    pub(crate) fn pending_join_ids(
        &self,
        after: Option<ConversationId>,
        limit: usize,
    ) -> Result<Vec<ConversationId>, ProfileStoreError> {
        if !(1..=MAX_CONVERSATION_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let limit = i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?;
        let query = match after {
            Some(_) => {
                "SELECT CASE WHEN length(conversation_id) = 32 THEN conversation_id END
                 FROM daemon_pending_join
                 WHERE conversation_id > ?1
                 ORDER BY conversation_id
                 LIMIT ?2"
            }
            None => {
                "SELECT CASE WHEN length(conversation_id) = 32 THEN conversation_id END
                 FROM daemon_pending_join
                 ORDER BY conversation_id
                 LIMIT ?1"
            }
        };
        let identifiers = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(query)
                .map_err(|_| ProfileStoreError::Storage)?;
            match after {
                Some(after) => statement
                    .query_map(params![after.as_bytes().as_slice(), limit], |row| {
                        row.get::<_, Vec<u8>>(0)
                    })
                    .map_err(|_| ProfileStoreError::Storage)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileStoreError::Storage)?,
                None => statement
                    .query_map(params![limit], |row| row.get::<_, Vec<u8>>(0))
                    .map_err(|_| ProfileStoreError::Storage)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileStoreError::Storage)?,
            }
        };
        identifiers
            .into_iter()
            .map(|identifier| {
                ConversationId::from_slice(&identifier).map_err(|_| ProfileStoreError::CorruptData)
            })
            .collect()
    }

    /// Loads and verifies one complete local conversation record.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, malformed, authentication, credential, or storage
    /// error.
    pub(crate) fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<StoredConversation, ProfileStoreError> {
        let metadata: Option<ConversationMetadata> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    length(sealed_signing_material),
                    length(sealed_policy_state),
                    sender_counter,
                    replay_cursor,
                    length(sealed_replay_head)
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (
            routing_id,
            signing_length,
            state_length,
            sender_counter,
            replay_cursor,
            replay_head_length,
        ) = metadata.ok_or(ProfileStoreError::ConversationNotFound)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        validate_blob_length(signing_length)?;
        validate_blob_length(state_length)?;
        let (signing_bytes, state_bytes, replay_head_bytes): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) =
            self.lock()?
                .query_row(
                    "SELECT
                    sealed_signing_material,
                    sealed_policy_state,
                    sealed_replay_head
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                    params![conversation_id.as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        if signing_bytes.len() != usize::try_from(signing_length).unwrap_or_default()
            || state_bytes.len() != usize::try_from(state_length).unwrap_or_default()
            || replay_head_bytes.as_ref().map(Vec::len)
                != replay_head_length.and_then(|length| usize::try_from(length).ok())
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let signing_blob =
            SealedBlob::from_bytes(signing_bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let signing_material = ConversationSigningMaterial::open(
            &self.sealer,
            self.locked_profile.profile_id.as_bytes(),
            conversation_id,
            &signing_blob,
        )
        .map_err(|_| ProfileStoreError::Cryptographic)?;
        let state_blob =
            SealedBlob::from_bytes(state_bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let state_plaintext = self
            .sealer
            .open(
                &conversation_record_context(
                    &self.locked_profile.profile_id,
                    SecretRecordKind::ConversationPolicyState,
                    conversation_id,
                    Some(routing_id),
                    None,
                )?,
                &state_blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let state =
            decode_conversation_state(&state_plaintext).map_err(|_| ProfileStoreError::Protocol)?;
        if state.conversation_id() != conversation_id {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let bindings = self.load_bindings(conversation_id)?;
        let binding_values = bindings
            .iter()
            .map(|binding| binding.binding())
            .cloned()
            .collect::<Vec<_>>();
        validate_bindings(&state, signing_material.binding(), &binding_values)?;
        let replay_cursor = from_sql_integer(replay_cursor)?;
        match (replay_cursor, replay_head_length, replay_head_bytes) {
            (0, None, None) => {}
            (0, _, _) => return Err(ProfileStoreError::CorruptData),
            (_, Some(length), Some(bytes)) => {
                validate_blob_length(length)?;
                let head = self.open_replay_head(conversation_id, routing_id, bytes)?;
                let legacy = head.version == ReplayHeadVersion::V1;
                let head = if legacy {
                    self.migrate_v1_replay_head(conversation_id, routing_id, head)?
                } else {
                    head
                };
                self.verify_replay_position(
                    conversation_id,
                    routing_id,
                    &state,
                    replay_cursor,
                    &head,
                )?;
                if legacy {
                    let migrated = self.seal_replay_head(
                        conversation_id,
                        routing_id,
                        head.previous_cursor,
                        head.cursor,
                        head.kind,
                        &head.completion_state,
                        &head.policy_state,
                        &head.envelope,
                    )?;
                    let changed = self
                        .lock()?
                        .execute(
                            "UPDATE daemon_conversation
                             SET sealed_replay_head = ?1
                             WHERE conversation_id = ?2",
                            params![migrated.as_bytes(), conversation_id.as_bytes().as_slice()],
                        )
                        .map_err(|_| ProfileStoreError::Storage)?;
                    if changed != 1 {
                        return Err(ProfileStoreError::Storage);
                    }
                }
            }
            _ => return Err(ProfileStoreError::CorruptData),
        }
        Ok(StoredConversation {
            routing_id,
            signing_material,
            state,
            bindings,
            sender_counter: from_sql_integer(sender_counter)?,
            replay_cursor,
        })
    }

    /// Lists one bounded page of local conversation identifiers.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed-row, or storage error.
    pub(crate) fn conversation_ids(
        &self,
        after: Option<ConversationId>,
        limit: usize,
    ) -> Result<Vec<ConversationId>, ProfileStoreError> {
        if !(1..=MAX_CONVERSATION_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let limit = i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?;
        let identifiers = {
            let connection = self.lock()?;
            match after {
                Some(after) => {
                    let mut statement = connection
                        .prepare(
                            "SELECT
                                CASE WHEN length(conversation_id) = 32
                                    THEN conversation_id
                                END
                             FROM daemon_conversation
                             WHERE conversation_id > ?1
                             ORDER BY conversation_id
                             LIMIT ?2",
                        )
                        .map_err(|_| ProfileStoreError::Storage)?;
                    statement
                        .query_map(params![after.as_bytes().as_slice(), limit], |row| {
                            row.get::<_, Vec<u8>>(0)
                        })
                        .map_err(|_| ProfileStoreError::Storage)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ProfileStoreError::Storage)?
                }
                None => {
                    let mut statement = connection
                        .prepare(
                            "SELECT
                                CASE WHEN length(conversation_id) = 32
                                    THEN conversation_id
                                END
                             FROM daemon_conversation
                             ORDER BY conversation_id
                             LIMIT ?1",
                        )
                        .map_err(|_| ProfileStoreError::Storage)?;
                    statement
                        .query_map(params![limit], |row| row.get::<_, Vec<u8>>(0))
                        .map_err(|_| ProfileStoreError::Storage)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ProfileStoreError::Storage)?
                }
            }
        };
        identifiers
            .into_iter()
            .map(|identifier| {
                ConversationId::from_slice(&identifier).map_err(|_| ProfileStoreError::CorruptData)
            })
            .collect()
    }

    /// Atomically reserves one sender counter and idempotency identifiers.
    ///
    /// # Errors
    ///
    /// Returns a missing-conversation, duplicate, sequence, or storage error.
    pub(crate) fn reserve_outbound_application(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        envelope_id: EnvelopeId,
    ) -> Result<OutboundReservation, ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing = {
            let mut statement = transaction
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(message_id) = 16 THEN message_id END,
                        CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                        sender_counter,
                        status,
                        terminal_reason
                     FROM daemon_outbox
                     WHERE envelope_id = ?1
                        OR (conversation_id = ?2 AND message_id = ?3)
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        envelope_id.as_bytes().as_slice(),
                        conversation_id.as_bytes().as_slice(),
                        message_id.as_bytes().as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<i64>>(5)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if !existing.is_empty() {
            if existing.len() != 1
                || ConversationId::from_slice(&existing[0].0).ok() != Some(conversation_id)
                || MessageId::from_slice(&existing[0].1).ok() != Some(message_id)
                || EnvelopeId::from_slice(&existing[0].2).ok() != Some(envelope_id)
            {
                return Err(ProfileStoreError::DuplicateOperation);
            }
            if existing[0].4 != 1 || existing[0].5.is_some() {
                return Err(ProfileStoreError::InvalidTransition);
            }
            return Ok(OutboundReservation {
                conversation_id,
                message_id,
                envelope_id,
                sender_counter: from_sql_integer(existing[0].3)?,
            });
        }
        let pending: i64 = transaction
            .query_row(
                "SELECT count(*) FROM daemon_outbox
                 WHERE status = 1
                    OR (status = 2 AND terminal_reason IS NULL)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if usize::try_from(pending)
            .ok()
            .is_none_or(|pending| pending >= MAX_PENDING_OUTBOX)
        {
            return Err(ProfileStoreError::OutboxCapacityExceeded);
        }
        let current: i64 = transaction
            .query_row(
                "SELECT sender_counter FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let sender_counter = from_sql_integer(current)?
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        transaction
            .execute(
                "UPDATE daemon_conversation SET sender_counter = ?1
                 WHERE conversation_id = ?2",
                params![
                    to_sql_integer(sender_counter)?,
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "INSERT INTO daemon_outbox (
                    envelope_id, conversation_id, message_id, sender_counter, status
                 ) VALUES (?1, ?2, ?3, ?4, 1)",
                params![
                    envelope_id.as_bytes().as_slice(),
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice(),
                    to_sql_integer(sender_counter)?
                ],
            )
            .map_err(map_operation_insert_error)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(OutboundReservation {
            conversation_id,
            message_id,
            envelope_id,
            sender_counter,
        })
    }

    /// Attaches one encrypted relay envelope to its reserved outbox operation.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, transition, sealing, protocol, or storage error.
    pub(crate) fn store_outbound_envelope(
        &self,
        reservation: OutboundReservation,
        envelope: &RelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let routing_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT routing_id FROM daemon_conversation WHERE conversation_id = ?1",
                params![reservation.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        if envelope.delivery_class() != DeliveryClass::GroupApplication {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if envelope.envelope_id() != reservation.envelope_id
            || envelope.routing_id()
                != RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let encoded = encode_outbox_record(reservation, envelope)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            reservation.conversation_id,
            envelope.routing_id(),
            OUTBOX_RECORD_SCOPE,
            reservation.envelope_id.as_bytes(),
            &encoded,
        )?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_outbox
                 SET sealed_envelope = ?1, status = 2
                 WHERE envelope_id = ?2
                   AND conversation_id = ?3
                   AND message_id = ?4
                   AND sender_counter = ?5
                   AND status = 1",
                params![
                    blob.as_bytes(),
                    reservation.envelope_id.as_bytes().as_slice(),
                    reservation.conversation_id.as_bytes().as_slice(),
                    reservation.message_id.as_bytes().as_slice(),
                    to_sql_integer(reservation.sender_counter)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.load_outbox_record(reservation.envelope_id)?;
        if existing.reservation == reservation && existing.envelope == *envelope {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Stores one sealed outbound plaintext record before its envelope becomes ready.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, duplicate, transition, sealing, protocol, or storage error.
    pub(crate) fn store_outbound_message(
        &self,
        reservation: OutboundReservation,
        routing_id: RoutingId,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        if message.message_id() != reservation.message_id
            || message.sender_counter() != reservation.sender_counter
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let stored_routing_id = self.conversation_routing_id(reservation.conversation_id)?;
        if stored_routing_id != routing_id {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let status: Option<i64> = transaction
            .query_row(
                "SELECT status FROM daemon_outbox
                 WHERE envelope_id = ?1
                   AND conversation_id = ?2
                   AND message_id = ?3
                   AND sender_counter = ?4",
                params![
                    reservation.envelope_id.as_bytes().as_slice(),
                    reservation.conversation_id.as_bytes().as_slice(),
                    reservation.message_id.as_bytes().as_slice(),
                    to_sql_integer(reservation.sender_counter)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        if status != Some(1) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        self.insert_or_verify_history(
            &transaction,
            reservation.conversation_id,
            routing_id,
            reservation.envelope_id,
            None,
            MessageDirection::Outbound,
            sender,
            epoch,
            message,
        )?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Loads every bounded ready outbox envelope for retry.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, count, or storage error.
    pub(crate) fn ready_outbox(&self) -> Result<Vec<PendingOutbox>, ProfileStoreError> {
        let count: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*) FROM daemon_outbox
                 WHERE status = 2 AND terminal_reason IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if count < 0
            || usize::try_from(count)
                .ok()
                .is_none_or(|count| count > MAX_PENDING_OUTBOX)
        {
            return Err(ProfileStoreError::OutboxCapacityExceeded);
        }
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(o.conversation_id) = 32 THEN o.conversation_id END,
                        CASE WHEN length(o.message_id) = 16 THEN o.message_id END,
                        CASE WHEN length(o.envelope_id) = 16 THEN o.envelope_id END,
                        o.sender_counter,
                        CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                        length(o.sealed_envelope)
                     FROM daemon_outbox o
                     JOIN daemon_conversation c
                       ON c.conversation_id = o.conversation_id
                     WHERE o.status = 2 AND o.terminal_reason IS NULL
                     ORDER BY o.conversation_id, o.sender_counter",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut pending = Vec::with_capacity(metadata.len());
        for (conversation_id, message_id, envelope_id, sender_counter, routing_id, length) in
            metadata
        {
            validate_blob_length(length)?;
            let bytes: Vec<u8> = self
                .lock()?
                .query_row(
                    "SELECT sealed_envelope FROM daemon_outbox WHERE envelope_id = ?1",
                    params![&envelope_id],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if bytes.len() != usize::try_from(length).unwrap_or_default() {
                return Err(ProfileStoreError::CorruptData);
            }
            let conversation_id = ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let envelope_id =
                EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let message_id =
                MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let routing_id =
                RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let sender_counter = from_sql_integer(sender_counter)?;
            let record =
                self.open_outbox_record(conversation_id, routing_id, envelope_id, bytes)?;
            if record.reservation
                != (OutboundReservation {
                    conversation_id,
                    message_id,
                    envelope_id,
                    sender_counter,
                })
                || record.envelope.envelope_id() != envelope_id
                || record.envelope.routing_id() != routing_id
            {
                return Err(ProfileStoreError::CorruptData);
            }
            pending.push(PendingOutbox {
                conversation_id,
                envelope: record.envelope,
            });
        }
        Ok(pending)
    }

    /// Terminalizes every ready application envelope for a conversation whose
    /// authenticated current policy no longer contains the local device.
    ///
    /// # Errors
    ///
    /// Returns a policy, transition, or storage error.
    pub(crate) fn terminalize_removed_outbox(
        &self,
        conversation_id: ConversationId,
    ) -> Result<usize, ProfileStoreError> {
        let conversation = self.load_conversation(conversation_id)?;
        if conversation
            .state
            .member(conversation.signing_material.binding().device_id())
            .is_some()
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let changed = terminalize_removed_outbox_in_transaction(&transaction, conversation_id)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(changed)
    }

    /// Loads one ready, accepted, or terminal outbound application by its stable
    /// message ID.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, transition, or storage error.
    pub(crate) fn outbound_application(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<Option<StoredOutboundApplication>, ProfileStoreError> {
        let metadata: Option<OutboundApplicationMetadata> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    status,
                    accepted_cursor,
                    terminal_reason
                 FROM daemon_outbox
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((envelope_id, status, accepted_cursor, terminal_reason)) = metadata else {
            return Ok(None);
        };
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let outbox = self.load_outbox_record(envelope_id)?;
        if outbox.reservation.conversation_id != conversation_id
            || outbox.reservation.message_id != message_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id = outbox.envelope.routing_id();
        let connection = self.lock()?;
        let history = self
            .load_history_record(&connection, conversation_id, routing_id, message_id)?
            .ok_or(ProfileStoreError::CorruptData)?;
        drop(connection);
        if history.direction != MessageDirection::Outbound || history.envelope_id != envelope_id {
            return Err(ProfileStoreError::CorruptData);
        }
        let accepted_cursor = accepted_cursor.map(from_sql_integer).transpose()?;
        let terminal_reason = outbox_terminal_reason(terminal_reason)?;
        let status = match (status, accepted_cursor, terminal_reason, history.cursor) {
            (2, None, None, None) => OutboundApplicationStatus::Ready,
            (2, None, Some(OutboxTerminalReason::Expired), None) => {
                OutboundApplicationStatus::Expired
            }
            (2, None, Some(OutboxTerminalReason::Removed), None) => {
                let conversation = self.load_conversation(conversation_id)?;
                if conversation
                    .state
                    .member(conversation.signing_material.binding().device_id())
                    .is_some()
                {
                    return Err(ProfileStoreError::CorruptData);
                }
                OutboundApplicationStatus::Removed
            }
            (3, Some(cursor), None, Some(history_cursor)) if cursor == history_cursor => {
                OutboundApplicationStatus::Accepted { cursor }
            }
            _ => return Err(ProfileStoreError::CorruptData),
        };
        Ok(Some(StoredOutboundApplication {
            conversation_id,
            message: history.message,
            envelope: outbox.envelope,
            status,
        }))
    }

    /// Converts unsealed reservations into durable counter-gap tombstones.
    ///
    /// This recovery transition is valid only before new outbound work begins.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the transition cannot be persisted.
    pub(crate) fn abandon_unsealed_outbox(&self) -> Result<usize, ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let changed = transaction
            .execute("UPDATE daemon_outbox SET status = 4 WHERE status = 1", [])
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "DELETE FROM daemon_message_history
                 WHERE direction = 1
                   AND status = 1
                   AND cursor IS NULL
                   AND envelope_id IN (
                        SELECT envelope_id FROM daemon_outbox WHERE status = 4
                   )",
                [],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(changed)
    }

    /// Converts one exact unsealed reservation into a durable counter-gap tombstone.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, invalid transition, sequence, or storage error.
    pub(crate) fn abandon_outbound_application(
        &self,
        reservation: OutboundReservation,
    ) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE daemon_outbox SET status = 4
                 WHERE envelope_id = ?1
                   AND conversation_id = ?2
                   AND message_id = ?3
                   AND sender_counter = ?4
                   AND status = 1",
                params![
                    reservation.envelope_id.as_bytes().as_slice(),
                    reservation.conversation_id.as_bytes().as_slice(),
                    reservation.message_id.as_bytes().as_slice(),
                    to_sql_integer(reservation.sender_counter)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            transaction
                .execute(
                    "DELETE FROM daemon_message_history
                     WHERE conversation_id = ?1
                       AND message_id = ?2
                       AND envelope_id = ?3
                       AND direction = 1
                       AND status = 1
                       AND cursor IS NULL",
                    params![
                        reservation.conversation_id.as_bytes().as_slice(),
                        reservation.message_id.as_bytes().as_slice(),
                        reservation.envelope_id.as_bytes().as_slice()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
            return Ok(());
        }
        let state: Option<(Vec<u8>, Vec<u8>, i64, i64)> = transaction
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    CASE WHEN length(message_id) = 16 THEN message_id END,
                    sender_counter,
                    status
                 FROM daemon_outbox
                 WHERE envelope_id = ?1",
                params![reservation.envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        if state.is_some_and(|(conversation_id, message_id, sender_counter, status)| {
            ConversationId::from_slice(&conversation_id).ok() == Some(reservation.conversation_id)
                && MessageId::from_slice(&message_id).ok() == Some(reservation.message_id)
                && from_sql_integer(sender_counter).ok() == Some(reservation.sender_counter)
                && status == 4
        }) {
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Marks one exact ready application envelope terminal when it expired locally.
    ///
    /// A later authenticated relay echo may still prove that a prior submission was
    /// accepted and supersede this local terminal reason.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, invalid transition, authentication, or storage
    /// error.
    pub(crate) fn expire_outbound_application(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<ExpireOutboundResult, ProfileStoreError> {
        let envelope_id = envelope.envelope_id();
        let record = self.load_outbox_record(envelope_id)?;
        if record.envelope != *envelope {
            return Err(ProfileStoreError::CursorConflict);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let history = self
            .load_history_record(
                &transaction,
                record.reservation.conversation_id,
                record.envelope.routing_id(),
                record.reservation.message_id,
            )?
            .ok_or(ProfileStoreError::CorruptData)?;
        if history.direction != MessageDirection::Outbound || history.envelope_id != envelope_id {
            return Err(ProfileStoreError::CorruptData);
        }
        let state: Option<(i64, Option<i64>, Option<i64>)> = transaction
            .query_row(
                "SELECT status, accepted_cursor, terminal_reason
                 FROM daemon_outbox
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let result = match state {
            Some((2, None, None)) if history.cursor.is_none() => {
                let changed = transaction
                    .execute(
                        "UPDATE daemon_outbox
                         SET terminal_reason = ?1
                         WHERE envelope_id = ?2
                           AND status = 2
                           AND terminal_reason IS NULL",
                        params![
                            OUTBOX_TERMINAL_REASON_EXPIRED,
                            envelope_id.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if changed != 1 {
                    return Err(ProfileStoreError::InvalidTransition);
                }
                ExpireOutboundResult::Expired
            }
            Some((2, None, terminal_reason))
                if outbox_terminal_reason(terminal_reason)?
                    == Some(OutboxTerminalReason::Expired)
                    && history.cursor.is_none() =>
            {
                ExpireOutboundResult::Expired
            }
            Some((3, Some(cursor), None)) => {
                let cursor = from_sql_integer(cursor)?;
                if history.cursor != Some(cursor) {
                    return Err(ProfileStoreError::CorruptData);
                }
                self.verify_cursor_observation(
                    &transaction,
                    record.reservation.conversation_id,
                    record.envelope.routing_id(),
                    cursor,
                    &record.envelope,
                )?;
                ExpireOutboundResult::Accepted { cursor }
            }
            _ => return Err(ProfileStoreError::InvalidTransition),
        };
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(result)
    }

    /// Marks a ready outbox operation accepted at one durable relay cursor.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, invalid transition, sequence, or storage error.
    pub(crate) fn mark_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id = stored.envelope().envelope_id();
        let cursor = stored.cursor();
        let record = self.load_outbox_record(envelope_id)?;
        if record.envelope != *stored.envelope() {
            return Err(ProfileStoreError::CursorConflict);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.accept_outbox_in_transaction(&transaction, &record, cursor, false)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    fn accept_outbox_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        record: &OutboxRecord,
        cursor: u64,
        accept_terminal: bool,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id = record.envelope.envelope_id();
        let state: Option<(i64, Option<i64>, Option<i64>)> = transaction
            .query_row(
                "SELECT status, accepted_cursor, terminal_reason
                 FROM daemon_outbox
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        match state {
            Some((2, None, terminal_reason))
                if terminal_reason.is_none()
                    || accept_terminal && outbox_terminal_reason(terminal_reason)?.is_some() =>
            {
                self.insert_or_verify_cursor_observation(
                    transaction,
                    record.reservation.conversation_id,
                    record.envelope.routing_id(),
                    cursor,
                    &record.envelope,
                )?;
                let changed = transaction
                    .execute(
                        "UPDATE daemon_outbox
                         SET status = 3,
                             accepted_cursor = ?1,
                             terminal_reason = NULL
                         WHERE envelope_id = ?2 AND status = 2",
                        params![to_sql_integer(cursor)?, envelope_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if changed != 1 {
                    return Err(ProfileStoreError::InvalidTransition);
                }
            }
            Some((3, Some(accepted), None)) if from_sql_integer(accepted)? == cursor => {
                self.verify_cursor_observation(
                    transaction,
                    record.reservation.conversation_id,
                    record.envelope.routing_id(),
                    cursor,
                    &record.envelope,
                )?;
            }
            _ => return Err(ProfileStoreError::InvalidTransition),
        }
        if !self.assign_history_cursor(
            transaction,
            record.reservation.conversation_id,
            record.envelope.routing_id(),
            record.reservation.message_id,
            envelope_id,
            cursor,
        )? {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(())
    }

    /// Stores one pending MLS membership transition and its opaque relay envelope.
    ///
    /// # Errors
    ///
    /// Returns a validation, duplicate, sealing, protocol, or storage error.
    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated membership journal fields remain explicit"
    )]
    pub(crate) fn store_membership_outbox(
        &self,
        operation_id: MembershipOperationId,
        conversation_id: ConversationId,
        parent_epoch: u64,
        envelope: &RelayEnvelope,
        control: &[u8],
        next_state: &ConversationState,
        bindings: &[DeviceCredentialBinding],
        welcome: Option<&[u8]>,
    ) -> Result<(), ProfileStoreError> {
        let current = self.load_conversation(conversation_id)?;
        if current.state.epoch() != parent_epoch
            || parent_epoch.checked_add(1) != Some(next_state.epoch())
            || next_state.conversation_id() != conversation_id
            || envelope.routing_id() != current.routing_id
            || envelope.delivery_class() != DeliveryClass::GroupCommit
            || envelope.expected_parent_epoch() != Some(parent_epoch)
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        validate_bindings(next_state, current.signing_material.binding(), bindings)?;
        let encoded = encode_membership_outbox_record(
            operation_id,
            parent_epoch,
            envelope,
            control,
            next_state,
            bindings,
            welcome,
        )?;
        let request = membership_request_metadata(control)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            current.routing_id,
            MEMBERSHIP_OUTBOX_RECORD_SCOPE,
            operation_id.as_bytes(),
            &encoded,
        )?;
        let pending: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*)
             FROM daemon_membership_outbox
             WHERE status IN (1, 2) AND operation_id != ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if usize::try_from(pending)
            .ok()
            .is_none_or(|pending| pending >= MAX_PENDING_OUTBOX)
        {
            return Err(ProfileStoreError::OutboxCapacityExceeded);
        }
        let inserted = self.lock()?.execute(
            "INSERT INTO daemon_membership_outbox (
                operation_id,
                conversation_id,
                envelope_id,
                parent_epoch,
                status,
                sealed_operation,
                accepted_cursor,
                change_kind,
                subject_device_id,
                subject_invitation_id,
                subject_role
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, NULL, ?6, ?7, ?8, ?9)",
            params![
                operation_id.as_bytes().as_slice(),
                conversation_id.as_bytes().as_slice(),
                envelope.envelope_id().as_bytes().as_slice(),
                to_sql_integer(parent_epoch)?,
                blob.as_bytes(),
                request.kind,
                request.device_id.as_bytes().as_slice(),
                request.invitation_id.map(|value| value.as_bytes().to_vec()),
                request.role
            ],
        );
        match inserted {
            Ok(1) => Ok(()),
            Ok(_) => Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                match self.load_membership_outbox(operation_id) {
                    Ok(existing)
                        if membership_outbox_matches(
                            &existing,
                            conversation_id,
                            parent_epoch,
                            envelope,
                            control,
                            next_state,
                            bindings,
                            welcome,
                        )? && existing.status == MembershipOutboxStatus::Ready =>
                    {
                        Ok(())
                    }
                    _ => Err(ProfileStoreError::DuplicateOperation),
                }
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Loads one membership operation by its authenticated operation identifier.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, protocol, or storage error.
    pub(crate) fn load_membership_outbox(
        &self,
        operation_id: MembershipOperationId,
    ) -> Result<MembershipOutbox, ProfileStoreError> {
        self.load_membership_outbox_where(
            "WHERE m.operation_id = ?1",
            operation_id.as_bytes().as_slice(),
        )?
        .ok_or(ProfileStoreError::OperationNotFound)
    }

    /// Loads a locally journaled membership transition by relay envelope.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, duplicate, or storage error.
    pub(crate) fn membership_outbox_for_envelope(
        &self,
        envelope_id: EnvelopeId,
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        self.load_membership_outbox_where(
            "WHERE m.envelope_id = ?1",
            envelope_id.as_bytes().as_slice(),
        )
    }

    /// Loads the latest local add-member transition for one invitation.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, duplicate, or storage error.
    pub(crate) fn membership_outbox_for_invitation(
        &self,
        conversation_id: ConversationId,
        invitation_id: InvitationId,
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        self.membership_outbox_for_request(conversation_id, 1, None, Some(invitation_id), None)
    }

    /// Loads the latest local remove-member transition for one device.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, duplicate, or storage error.
    pub(crate) fn membership_outbox_for_removal(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        self.membership_outbox_for_request(conversation_id, 2, Some(device_id), None, None)
    }

    /// Loads the latest local role transition for one device and role.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, duplicate, or storage error.
    pub(crate) fn membership_outbox_for_role(
        &self,
        conversation_id: ConversationId,
        device_id: DeviceId,
        role: KonclaveDomainCore::ConversationRole,
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        self.membership_outbox_for_request(
            conversation_id,
            3,
            Some(device_id),
            None,
            Some(conversation_role_value(role)),
        )
    }

    /// Loads the single ready or relay-accepted transition for one conversation.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, duplicate, or storage error.
    pub(crate) fn active_membership_outbox(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        let parent_epoch = self.load_conversation(conversation_id)?.state.epoch();
        let operation_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(operation_id) = 16 THEN operation_id END
                     FROM daemon_membership_outbox
                     WHERE conversation_id = ?1 AND parent_epoch = ?2
                     ORDER BY operation_id
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(parent_epoch)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if operation_ids.len() > 1 {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        let Some(operation_id) = operation_ids.into_iter().next() else {
            return Ok(None);
        };
        let operation_id = MembershipOperationId::from_slice(&operation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let record = self.load_membership_outbox(operation_id)?;
        if let Some(cursor) = self.cursor_observation_for_envelope(
            record.conversation_id,
            record.envelope.routing_id(),
            &record.envelope,
        )? {
            self.normalize_membership_acceptance(
                record.operation_id,
                record.conversation_id,
                record.envelope.routing_id(),
                cursor,
                &record.envelope,
            )?;
            return self.load_membership_outbox(record.operation_id).map(Some);
        }
        self.normalize_membership_ready(record.operation_id)?;
        self.load_membership_outbox(record.operation_id).map(Some)
    }

    /// Loads every ready membership envelope in deterministic journal order.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, count, or storage error.
    pub(crate) fn ready_membership_outbox(
        &self,
    ) -> Result<Vec<MembershipOutbox>, ProfileStoreError> {
        let operation_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(operation_id) = 16 THEN operation_id END
                     FROM daemon_membership_outbox
                     WHERE status = 1
                     ORDER BY conversation_id, parent_epoch",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if operation_ids.len() > MAX_PENDING_OUTBOX {
            return Err(ProfileStoreError::OutboxCapacityExceeded);
        }
        operation_ids
            .into_iter()
            .map(|operation_id| {
                let operation_id = MembershipOperationId::from_slice(&operation_id)
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                self.load_membership_outbox(operation_id)
            })
            .collect()
    }

    /// Records the exact relay cursor accepted for one membership envelope.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, transition, authentication, or storage error.
    pub(crate) fn mark_membership_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<MembershipOperationId, ProfileStoreError> {
        let operation_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
                 FROM daemon_membership_outbox
                 WHERE envelope_id = ?1",
                params![stored.envelope().envelope_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::OperationNotFound)?;
        let operation_id = MembershipOperationId::from_slice(&operation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let record = self.load_membership_outbox(operation_id)?;
        if record.envelope != *stored.envelope() {
            return Err(ProfileStoreError::CursorConflict);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let state: (i64, Option<i64>) = transaction
            .query_row(
                "SELECT status, accepted_cursor
                 FROM daemon_membership_outbox
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        match state {
            (1, None) => {
                self.insert_or_verify_cursor_observation(
                    &transaction,
                    record.conversation_id,
                    record.envelope.routing_id(),
                    stored.cursor(),
                    &record.envelope,
                )?;
                let changed = transaction
                    .execute(
                        "UPDATE daemon_membership_outbox
                         SET status = 2, accepted_cursor = ?1
                         WHERE operation_id = ?2 AND status = 1",
                        params![
                            to_sql_integer(stored.cursor())?,
                            operation_id.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if changed != 1 {
                    return Err(ProfileStoreError::InvalidTransition);
                }
            }
            (2 | 3, Some(cursor)) if from_sql_integer(cursor)? == stored.cursor() => {
                self.verify_cursor_observation(
                    &transaction,
                    record.conversation_id,
                    record.envelope.routing_id(),
                    stored.cursor(),
                    &record.envelope,
                )?;
            }
            _ => return Err(ProfileStoreError::InvalidTransition),
        }
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(operation_id)
    }

    /// Atomically publishes an accepted membership policy and marks it applied.
    ///
    /// The caller persists the corresponding MLS epoch before invoking this method.
    ///
    /// # Errors
    ///
    /// Returns a transition, sealing, protocol, credential, or storage error.
    pub(crate) fn complete_membership_outbox(
        &self,
        operation_id: MembershipOperationId,
    ) -> Result<(), ProfileStoreError> {
        let record = self.load_membership_outbox(operation_id)?;
        if record.status == MembershipOutboxStatus::Applied {
            return self.verify_applied_membership(&record);
        }
        if record.status != MembershipOutboxStatus::Accepted {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let current = self.load_conversation(record.conversation_id)?;
        let self_removed = record
            .next_state
            .member(current.signing_material.binding().device_id())
            .is_none();
        let bindings =
            final_membership_bindings(&record, current.signing_material.binding().device_id());
        let binding_values = bindings
            .iter()
            .map(|binding| binding.binding())
            .cloned()
            .collect::<Vec<_>>();
        validate_bindings(
            &record.next_state,
            current.signing_material.binding(),
            &binding_values,
        )?;
        let advanced_replay_head = self.advance_replay_head_state(&current, &record.next_state)?;
        let state_bytes = encode_conversation_state(&record.next_state)
            .map_err(|_| ProfileStoreError::Protocol)?;
        let state_blob = self.seal_conversation_record(
            SecretRecordKind::ConversationPolicyState,
            record.conversation_id,
            Some(record.envelope.routing_id()),
            None,
            &state_bytes,
        )?;
        let mut sealed_bindings = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let bytes = encode_device_credential_binding(binding.binding())
                .map_err(|_| ProfileStoreError::Protocol)?;
            let blob = self.seal_conversation_record(
                SecretRecordKind::ConversationCredentialBinding,
                record.conversation_id,
                None,
                Some(binding.binding().device_id()),
                &bytes,
            )?;
            sealed_bindings.push((binding.binding().device_id(), blob));
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let accepted_cursor = record
            .accepted_cursor
            .ok_or(ProfileStoreError::InvalidTransition)?;
        let acceptance: (i64, Option<i64>) = transaction
            .query_row(
                "SELECT status, accepted_cursor
                 FROM daemon_membership_outbox
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if acceptance.0 != MembershipOutboxStatus::Accepted as i64
            || acceptance.1.map(from_sql_integer).transpose()? != Some(accepted_cursor)
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        self.verify_cursor_observation(
            &transaction,
            record.conversation_id,
            record.envelope.routing_id(),
            accepted_cursor,
            &record.envelope,
        )?;
        let changed = transaction
            .execute(
                "UPDATE daemon_conversation
                 SET sealed_policy_state = ?1,
                     sealed_replay_head = ?2
                 WHERE conversation_id = ?3
                   AND EXISTS (
                        SELECT 1
                        FROM daemon_membership_outbox
                        WHERE operation_id = ?4 AND status = 2
                   )",
                params![
                    state_blob.as_bytes(),
                    advanced_replay_head.as_ref().map(SealedBlob::as_bytes),
                    record.conversation_id.as_bytes().as_slice(),
                    operation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if self_removed {
            terminalize_removed_outbox_in_transaction(&transaction, record.conversation_id)?;
        }
        transaction
            .execute(
                "DELETE FROM daemon_conversation_binding WHERE conversation_id = ?1",
                params![record.conversation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        for (device_id, blob) in sealed_bindings {
            transaction
                .execute(
                    "INSERT INTO daemon_conversation_binding (
                        conversation_id, device_id, sealed_binding
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        record.conversation_id.as_bytes().as_slice(),
                        device_id.as_bytes().as_slice(),
                        blob.as_bytes()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        let changed = transaction
            .execute(
                "UPDATE daemon_membership_outbox
                 SET status = 3
                 WHERE operation_id = ?1 AND status = 2",
                params![operation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Marks one unaccepted local commit as orphaned after MLS pending-state removal.
    ///
    /// # Errors
    ///
    /// Returns a transition or storage error.
    pub(crate) fn orphan_membership_outbox(
        &self,
        operation_id: MembershipOperationId,
    ) -> Result<(), ProfileStoreError> {
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_membership_outbox
             SET status = 4
             WHERE operation_id = ?1 AND status = 1",
                params![operation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(());
        }
        let status: Option<i64> = self
            .lock()?
            .query_row(
                "SELECT status FROM daemon_membership_outbox WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        if status == Some(MembershipOutboxStatus::Orphaned as i64) {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Journals one received encrypted membership Commit before MLS processing.
    ///
    /// # Errors
    ///
    /// Returns a route, cursor conflict, duplicate, sealing, protocol, or storage
    /// error.
    pub(crate) fn record_membership_inbox_envelope(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, ProfileStoreError> {
        let envelope = stored.envelope();
        if envelope.delivery_class() != DeliveryClass::GroupCommit {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let conversation_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT conversation_id FROM daemon_conversation WHERE routing_id = ?1",
                params![envelope.routing_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let encoded = encode_inbox_envelope_record(stored)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            envelope.routing_id(),
            MEMBERSHIP_INBOX_ENVELOPE_RECORD_SCOPE,
            envelope.envelope_id().as_bytes(),
            &encoded,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let observation_inserted = self.insert_or_verify_cursor_observation(
            &transaction,
            conversation_id,
            envelope.routing_id(),
            stored.cursor(),
            envelope,
        )?;
        let insert = transaction.execute(
            "INSERT INTO daemon_membership_inbox (
                conversation_id, cursor, envelope_id, status, sealed_envelope
             ) VALUES (?1, ?2, ?3, 1, ?4)",
            params![
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(stored.cursor())?,
                envelope.envelope_id().as_bytes().as_slice(),
                blob.as_bytes()
            ],
        );
        match insert {
            Ok(1) => {
                let count: i64 = transaction
                    .query_row(
                        "SELECT
                            (SELECT count(*) FROM daemon_inbox
                             WHERE conversation_id = ?1 AND status < 3)
                            +
                            (SELECT count(*) FROM daemon_membership_inbox
                             WHERE conversation_id = ?1 AND status < 3)",
                        params![conversation_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if usize::try_from(count)
                    .ok()
                    .is_none_or(|count| count > MAX_MESSAGE_PAGE_SIZE)
                {
                    return Err(ProfileStoreError::InboxCapacityExceeded);
                }
                transaction
                    .commit()
                    .map_err(|_| ProfileStoreError::Storage)?;
                Ok(conversation_id)
            }
            Ok(_) => Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                if observation_inserted {
                    return Err(ProfileStoreError::CorruptData);
                }
                drop(transaction);
                drop(connection);
                let existing = self.load_membership_inbox_envelope(
                    conversation_id,
                    stored.cursor(),
                    envelope.envelope_id(),
                )?;
                if &existing == stored {
                    Ok(conversation_id)
                } else {
                    Err(ProfileStoreError::DuplicateOperation)
                }
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Seals one decrypted membership control and its validated next policy before
    /// MLS epoch persistence.
    ///
    /// # Errors
    ///
    /// Returns a transition, authorization, sealing, protocol, or storage error.
    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated membership checkpoint fields remain explicit"
    )]
    pub(crate) fn save_membership_inbox_transition(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        parent_epoch: u64,
        operation_id: MembershipOperationId,
        control: &[u8],
        next_state: &ConversationState,
        bindings: &[DeviceCredentialBinding],
    ) -> Result<(), ProfileStoreError> {
        let (authorization, _) =
            decode_membership_control(control).map_err(|_| ProfileStoreError::Protocol)?;
        let current = self.load_conversation(conversation_id)?;
        if authorization.conversation_id() != conversation_id
            || authorization.operation_id() != operation_id
            || authorization.parent_epoch() != parent_epoch
            || current.state.epoch() != parent_epoch
            || current
                .state
                .apply_membership_authorization(sender, &authorization, next_state.epoch())
                .map_err(|_| ProfileStoreError::ConversationMismatch)?
                != *next_state
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        validate_bindings(next_state, current.signing_material.binding(), bindings)?;
        self.save_membership_inbox_transition_record(
            conversation_id,
            cursor,
            sender,
            parent_epoch,
            operation_id,
            control,
            next_state,
            bindings,
        )
    }

    /// Loads one exact membership inbox operation for replay or recovery.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, protocol, or storage error.
    pub(crate) fn membership_inbox_operation(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<MembershipInboxOperation, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    status
                 FROM daemon_membership_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (envelope_id, status) = metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let stored = self.load_membership_inbox_envelope(conversation_id, cursor, envelope_id)?;
        match status {
            1 => Ok(MembershipInboxOperation::Received { stored }),
            2 => Ok(MembershipInboxOperation::TransitionSaved(
                self.load_membership_inbox_transition(conversation_id, cursor, stored)?,
            )),
            3 => Ok(MembershipInboxOperation::Complete(
                self.load_membership_inbox_transition(conversation_id, cursor, stored)?,
            )),
            _ => Err(ProfileStoreError::CorruptData),
        }
    }

    /// Returns the single incomplete membership checkpoint for startup recovery.
    ///
    /// # Errors
    ///
    /// Returns a duplicate, malformed, authentication, protocol, or storage error.
    pub(crate) fn active_membership_inbox(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Option<MembershipInboxOperation>, ProfileStoreError> {
        let cursors = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT cursor
                     FROM daemon_membership_inbox
                     WHERE conversation_id = ?1 AND status < 3
                     ORDER BY cursor
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(params![conversation_id.as_bytes().as_slice()], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if cursors.len() > 1 {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        cursors
            .into_iter()
            .next()
            .map(from_sql_integer)
            .transpose()?
            .map(|cursor| self.membership_inbox_operation(conversation_id, cursor))
            .transpose()
    }

    /// Publishes one MLS-persisted incoming membership policy and advances replay.
    ///
    /// # Errors
    ///
    /// Returns a cursor, transition, sealing, protocol, credential, or storage error.
    #[cfg(test)]
    pub(crate) fn complete_membership_inbox(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<u64, ProfileStoreError> {
        self.complete_membership_inbox_with_notification(
            conversation_id,
            cursor,
            NotificationId::from_bytes([u8::try_from(cursor).unwrap_or(0); NotificationId::LENGTH]),
        )
    }

    pub(crate) fn complete_membership_inbox_with_notification(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        notification_id: NotificationId,
    ) -> Result<u64, ProfileStoreError> {
        let operation = self.membership_inbox_operation(conversation_id, cursor)?;
        let already_complete = matches!(operation, MembershipInboxOperation::Complete(_));
        let transition = match operation {
            MembershipInboxOperation::TransitionSaved(transition)
            | MembershipInboxOperation::Complete(transition) => transition,
            MembershipInboxOperation::Received { .. } => {
                return Err(ProfileStoreError::InvalidTransition);
            }
        };
        if transition.stored.cursor() != cursor {
            return Err(ProfileStoreError::CorruptData);
        }
        let current = self.load_conversation(conversation_id)?;
        let self_removed = transition
            .next_state
            .member(current.signing_material.binding().device_id())
            .is_none();
        let bindings =
            final_transition_bindings(&transition, current.signing_material.binding().device_id());
        let binding_values = bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        validate_bindings(
            &transition.next_state,
            current.signing_material.binding(),
            &binding_values,
        )?;
        let state_bytes = encode_conversation_state(&transition.next_state)
            .map_err(|_| ProfileStoreError::Protocol)?;
        let state_blob = self.seal_conversation_record(
            SecretRecordKind::ConversationPolicyState,
            conversation_id,
            Some(transition.stored.envelope().routing_id()),
            None,
            &state_bytes,
        )?;
        let mut sealed_bindings = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let bytes = encode_device_credential_binding(binding.binding())
                .map_err(|_| ProfileStoreError::Protocol)?;
            let blob = self.seal_conversation_record(
                SecretRecordKind::ConversationCredentialBinding,
                conversation_id,
                None,
                Some(binding.binding().device_id()),
                &bytes,
            )?;
            sealed_bindings.push((binding.binding().device_id(), blob));
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.verify_cursor_observation(
            &transaction,
            conversation_id,
            transition.stored.envelope().routing_id(),
            cursor,
            transition.stored.envelope(),
        )?;
        let current_cursor: i64 = transaction
            .query_row(
                "SELECT replay_cursor FROM daemon_conversation WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let current_cursor = from_sql_integer(current_cursor)?;
        if current_cursor != current.replay_cursor {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if current_cursor >= cursor {
            return if already_complete {
                Ok(current_cursor)
            } else {
                Err(ProfileStoreError::CorruptData)
            };
        }
        if current_cursor.checked_add(1) != Some(cursor) {
            return Err(ProfileStoreError::CursorGap);
        }
        let (authorization, _) = decode_membership_control(&transition.control)
            .map_err(|_| ProfileStoreError::Protocol)?;
        if authorization.operation_id() != transition.operation_id {
            return Err(ProfileStoreError::CorruptData);
        }
        let self_device_id = current.signing_material.binding().device_id();
        let event_kind = match authorization.change() {
            MembershipChange::Add(_) => RemoteEventKind::MemberAdded,
            MembershipChange::Remove(change) if change.device_id() == self_device_id => {
                RemoteEventKind::LocalAccessRemoved
            }
            MembershipChange::Remove(_) => RemoteEventKind::MemberRemoved,
            MembershipChange::ChangeRole(_) => RemoteEventKind::MemberRoleChanged,
        };
        let replay_head = self.seal_replay_head(
            conversation_id,
            transition.stored.envelope().routing_id(),
            current_cursor,
            cursor,
            ReplayCompletionKind::Membership,
            &transition.next_state,
            &transition.next_state,
            transition.stored.envelope(),
        )?;
        self.insert_remote_event_in(
            &transaction,
            conversation_id,
            transition.stored.envelope().routing_id(),
            cursor,
            notification_id,
            event_kind,
            transition.sender,
            self_device_id,
            transition.operation_id.into_bytes(),
        )?;
        transaction
            .execute(
                "UPDATE daemon_conversation
                 SET sealed_policy_state = ?1,
                     replay_cursor = ?2,
                     sealed_replay_head = ?3
                 WHERE conversation_id = ?4",
                params![
                    state_blob.as_bytes(),
                    to_sql_integer(cursor)?,
                    replay_head.as_bytes(),
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "DELETE FROM daemon_conversation_binding WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if self_removed {
            terminalize_removed_outbox_in_transaction(&transaction, conversation_id)?;
        }
        for (device_id, blob) in sealed_bindings {
            transaction
                .execute(
                    "INSERT INTO daemon_conversation_binding (
                        conversation_id, device_id, sealed_binding
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        conversation_id.as_bytes().as_slice(),
                        device_id.as_bytes().as_slice(),
                        blob.as_bytes()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        let changed = transaction
            .execute(
                "UPDATE daemon_membership_inbox SET status = 3
                 WHERE conversation_id = ?1 AND cursor = ?2 AND status = 2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(cursor)
    }

    /// Completes the relay echo of an already applied local membership transition.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, transition, cursor, sealing, protocol, or storage error.
    pub(crate) fn complete_membership_echo(
        &self,
        stored: &StoredRelayEnvelope,
        sender: DeviceId,
    ) -> Result<MembershipOperationId, ProfileStoreError> {
        let outbox = self
            .membership_outbox_for_envelope(stored.envelope().envelope_id())?
            .ok_or(ProfileStoreError::OperationNotFound)?;
        if outbox.status != MembershipOutboxStatus::Applied || outbox.envelope != *stored.envelope()
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let bindings = outbox
            .bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        self.save_membership_inbox_transition_record(
            outbox.conversation_id,
            stored.cursor(),
            sender,
            outbox.parent_epoch,
            outbox.operation_id,
            &outbox.control,
            &outbox.next_state,
            &bindings,
        )?;
        self.complete_membership_inbox_with_notification(
            outbox.conversation_id,
            stored.cursor(),
            NotificationId::from_bytes(stored.envelope().envelope_id().into_bytes()),
        )?;
        Ok(outbox.operation_id)
    }

    /// Journals one received relay envelope before cryptographic processing.
    ///
    /// An exact duplicate is idempotent; any conflicting identifier or cursor fails.
    ///
    /// # Errors
    ///
    /// Returns a route, cursor conflict, duplicate, sealing, protocol, or storage
    /// error.
    pub(crate) fn record_inbox_envelope(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, ProfileStoreError> {
        let envelope = stored.envelope();
        if envelope.delivery_class() != DeliveryClass::GroupApplication {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let conversation_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT conversation_id FROM daemon_conversation WHERE routing_id = ?1",
                params![envelope.routing_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let encoded = encode_inbox_envelope_record(stored)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            envelope.routing_id(),
            INBOX_ENVELOPE_RECORD_SCOPE,
            envelope.envelope_id().as_bytes(),
            &encoded,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let observation_inserted = self.insert_or_verify_cursor_observation(
            &transaction,
            conversation_id,
            envelope.routing_id(),
            stored.cursor(),
            envelope,
        )?;
        let insert = transaction.execute(
            "INSERT INTO daemon_inbox (
                conversation_id, cursor, envelope_id, status, sealed_envelope
             ) VALUES (?1, ?2, ?3, 1, ?4)",
            params![
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(stored.cursor())?,
                envelope.envelope_id().as_bytes().as_slice(),
                blob.as_bytes()
            ],
        );
        match insert {
            Ok(_) => {
                let replay_cursor: i64 = transaction
                    .query_row(
                        "SELECT replay_cursor FROM daemon_conversation
                         WHERE conversation_id = ?1",
                        params![conversation_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                let replay_cursor = from_sql_integer(replay_cursor)?;
                let cursor_window = u64::try_from(MAX_MESSAGE_PAGE_SIZE)
                    .map_err(|_| ProfileStoreError::SequenceExhausted)?;
                if stored.cursor() > replay_cursor.saturating_add(cursor_window) {
                    return Err(ProfileStoreError::InboxCapacityExceeded);
                }
                let count: i64 = transaction
                    .query_row(
                        "SELECT count(*) FROM daemon_inbox
                         WHERE conversation_id = ?1 AND status < 3",
                        params![conversation_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if usize::try_from(count)
                    .ok()
                    .is_none_or(|count| count > MAX_MESSAGE_PAGE_SIZE)
                {
                    return Err(ProfileStoreError::InboxCapacityExceeded);
                }
                transaction
                    .commit()
                    .map_err(|_| ProfileStoreError::Storage)?;
                Ok(conversation_id)
            }
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                if observation_inserted {
                    return Err(ProfileStoreError::CorruptData);
                }
                drop(transaction);
                drop(connection);
                let existing = self.load_conflicting_inbox(
                    conversation_id,
                    stored.cursor(),
                    envelope.envelope_id(),
                )?;
                if &existing == stored {
                    Ok(conversation_id)
                } else {
                    Err(ProfileStoreError::DuplicateOperation)
                }
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Stores a decoded application message plus its authenticated MLS sender and
    /// epoch before ratchet persistence.
    ///
    /// # Errors
    ///
    /// Returns a duplicate, transition, sealing, protocol, or storage error.
    pub(crate) fn save_inbox_message(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        sender_epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(envelope_id) = 16 THEN envelope_id END
                 FROM daemon_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id.ok_or(ProfileStoreError::InvalidTransition)?)
                .map_err(|_| ProfileStoreError::CorruptData)?;
        let stored_envelope = self.load_inbox_envelope(envelope_id)?;
        if stored_envelope.cursor() != cursor {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id = stored_envelope.envelope().routing_id();
        let plaintext =
            encode_inbox_message_record(cursor, envelope_id, sender, sender_epoch, message)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            conversation_id,
            routing_id,
            INBOX_MESSAGE_RECORD_SCOPE,
            message.message_id().as_bytes(),
            &plaintext,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let update = transaction.execute(
            "UPDATE daemon_inbox
             SET sender_device_id = ?1,
                 sender_epoch = ?2,
                 message_id = ?3,
                 sender_counter = ?4,
                 sealed_message = ?5,
                 status = 2
             WHERE conversation_id = ?6 AND cursor = ?7 AND status = 1",
            params![
                sender.as_bytes().as_slice(),
                to_sql_integer(sender_epoch)?,
                message.message_id().as_bytes().as_slice(),
                to_sql_integer(message.sender_counter())?,
                blob.as_bytes(),
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(cursor)?
            ],
        );
        match update {
            Ok(1) => {
                self.insert_or_verify_history(
                    &transaction,
                    conversation_id,
                    routing_id,
                    envelope_id,
                    Some(cursor),
                    MessageDirection::Inbound,
                    sender,
                    sender_epoch,
                    message,
                )?;
                transaction.commit().map_err(|_| ProfileStoreError::Storage)
            }
            Ok(_) => {
                drop(transaction);
                drop(connection);
                let existing = self.load_message_at(conversation_id, cursor)?;
                if existing.sender == sender
                    && existing.epoch == sender_epoch
                    && application_messages_equal(&existing.message, message)?
                {
                    let mut connection = self.lock()?;
                    let transaction = connection
                        .transaction()
                        .map_err(|_| ProfileStoreError::Storage)?;
                    self.insert_or_verify_history(
                        &transaction,
                        conversation_id,
                        routing_id,
                        envelope_id,
                        Some(cursor),
                        MessageDirection::Inbound,
                        sender,
                        sender_epoch,
                        message,
                    )?;
                    transaction
                        .commit()
                        .map_err(|_| ProfileStoreError::Storage)?;
                    Ok(())
                } else {
                    Err(ProfileStoreError::InvalidTransition)
                }
            }
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                drop(transaction);
                drop(connection);
                Err(ProfileStoreError::DuplicateOperation)
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Loads one exact inbox operation for recovery or idempotent replay.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, protocol, or storage error.
    pub(crate) fn inbox_operation(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<InboxOperation, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    status
                 FROM daemon_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (envelope_id, status) = metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let stored = self.load_inbox_envelope(envelope_id)?;
        if stored.cursor() != cursor {
            return Err(ProfileStoreError::CorruptData);
        }
        match status {
            1 => Ok(InboxOperation::Received { stored }),
            2 => Ok(InboxOperation::MessageSaved {
                stored,
                message: self.load_message_at(conversation_id, cursor)?,
            }),
            3 => Ok(InboxOperation::Complete {
                stored,
                message: self.load_message_at(conversation_id, cursor)?,
            }),
            _ => Err(ProfileStoreError::CorruptData),
        }
    }

    /// Loads and cursor-binds one locally sent message echoed by the relay.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, malformed, authentication, protocol, or storage
    /// error.
    pub(crate) fn outbound_history_message(
        &self,
        conversation_id: ConversationId,
        stored: &StoredRelayEnvelope,
    ) -> Result<Option<StoredHistoryMessage>, ProfileStoreError> {
        let envelope_id = stored.envelope().envelope_id();
        let cursor = stored.cursor();
        let routing_id = self.conversation_routing_id(conversation_id)?;
        let message_id: Option<Vec<u8>> = {
            let connection = self.lock()?;
            connection
                .query_row(
                    "SELECT CASE WHEN length(message_id) = 16 THEN message_id END
                     FROM daemon_message_history
                     WHERE conversation_id = ?1
                       AND envelope_id = ?2
                       AND direction = 1",
                    params![
                        conversation_id.as_bytes().as_slice(),
                        envelope_id.as_bytes().as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let Some(message_id) = message_id else {
            return Ok(None);
        };
        let message_id =
            MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let outbox = self.load_outbox_record(envelope_id)?;
        if outbox.reservation.conversation_id != conversation_id
            || outbox.reservation.message_id != message_id
            || outbox.envelope != *stored.envelope()
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.accept_outbox_in_transaction(&transaction, &outbox, cursor, true)?;
        let history = self
            .load_history_record(&transaction, conversation_id, routing_id, message_id)?
            .ok_or(ProfileStoreError::CorruptData)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(Some(StoredHistoryMessage {
            cursor,
            direction: history.direction,
            envelope_id: history.envelope_id,
            sender: history.sender,
            epoch: history.epoch,
            message: history.message,
        }))
    }

    /// Loads bounded incomplete inbox operations in durable cursor order.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, count, or storage error.
    pub(crate) fn incomplete_inbox(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Vec<PendingInbox>, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        cursor,
                        CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                        status
                     FROM daemon_inbox
                     WHERE conversation_id = ?1 AND status < 3
                     ORDER BY cursor
                     LIMIT ?2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        i64::try_from(MAX_MESSAGE_PAGE_SIZE + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if metadata.len() > MAX_MESSAGE_PAGE_SIZE {
            return Err(ProfileStoreError::InboxCapacityExceeded);
        }
        let mut pending = Vec::with_capacity(metadata.len());
        for (cursor, envelope_id, status) in metadata {
            let cursor = from_sql_integer(cursor)?;
            let envelope_id =
                EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let stored = self.load_inbox_envelope(envelope_id)?;
            if stored.cursor() != cursor {
                return Err(ProfileStoreError::CorruptData);
            }
            pending.push(match status {
                1 => PendingInbox::Received {
                    conversation_id,
                    stored,
                },
                2 => PendingInbox::MessageSaved {
                    conversation_id,
                    stored,
                    message: self.load_message_at(conversation_id, cursor)?,
                },
                _ => return Err(ProfileStoreError::CorruptData),
            });
        }
        Ok(pending)
    }

    /// Marks one saved inbox message complete and advances only the next contiguous
    /// durable cursor.
    ///
    /// # Errors
    ///
    /// Returns a cursor gap, sender-counter regression, transition, sequence, or
    /// storage error.
    #[cfg(test)]
    pub(crate) fn complete_inbox(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<u64, ProfileStoreError> {
        self.complete_inbox_with_notification(
            conversation_id,
            cursor,
            NotificationId::from_bytes([u8::try_from(cursor).unwrap_or(0); NotificationId::LENGTH]),
        )
    }

    pub(crate) fn complete_inbox_with_notification(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        notification_id: NotificationId,
    ) -> Result<u64, ProfileStoreError> {
        let conversation = self.load_conversation(conversation_id)?;
        let message = self.load_message_at(conversation_id, cursor)?;
        let envelope = self.load_inbox_envelope(message.envelope_id)?;
        if envelope.cursor() != cursor
            || envelope.envelope().routing_id() != conversation.routing_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.verify_cursor_observation(
            &transaction,
            conversation_id,
            envelope.envelope().routing_id(),
            cursor,
            envelope.envelope(),
        )?;
        let current: i64 = transaction
            .query_row(
                "SELECT replay_cursor FROM daemon_conversation WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let current = from_sql_integer(current)?;
        if current != conversation.replay_cursor {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let high_water = self.load_sender_high_water(
            &transaction,
            conversation_id,
            message.sender,
            message.epoch,
        )?;
        if cursor <= current {
            let status: Option<i64> = transaction
                .query_row(
                    "SELECT status FROM daemon_inbox
                     WHERE conversation_id = ?1 AND cursor = ?2",
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(cursor)?
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ProfileStoreError::Storage)?;
            return if status == Some(3)
                && high_water.is_some_and(|counter| counter >= message.message.sender_counter())
            {
                Ok(current)
            } else {
                Err(ProfileStoreError::CorruptData)
            };
        }
        if current.checked_add(1) != Some(cursor) {
            return Err(ProfileStoreError::CursorGap);
        }
        if let Some(high_water) = high_water {
            let sender_counter = message.message.sender_counter();
            if sender_counter <= high_water {
                return Err(ProfileStoreError::SenderCounterRegression);
            }
        }
        let replay_head = self.seal_replay_head(
            conversation_id,
            conversation.routing_id,
            current,
            cursor,
            ReplayCompletionKind::Application,
            &conversation.state,
            &conversation.state,
            envelope.envelope(),
        )?;
        self.store_sender_high_water(
            &transaction,
            conversation_id,
            message.sender,
            message.epoch,
            message.message.sender_counter(),
        )?;
        if !self.complete_history(
            &transaction,
            conversation_id,
            envelope.envelope().routing_id(),
            message.message.message_id(),
            message.envelope_id,
            cursor,
        )? {
            return Err(ProfileStoreError::CorruptData);
        }
        self.insert_remote_event_in(
            &transaction,
            conversation_id,
            conversation.routing_id,
            cursor,
            notification_id,
            RemoteEventKind::ApplicationMessage,
            message.sender,
            conversation.signing_material.binding().device_id(),
            message.message.message_id().into_bytes(),
        )?;
        let changed = transaction
            .execute(
                "UPDATE daemon_inbox SET status = 3
                 WHERE conversation_id = ?1 AND cursor = ?2 AND status = 2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE daemon_conversation
                 SET replay_cursor = ?1, sealed_replay_head = ?2
                 WHERE conversation_id = ?3",
                params![
                    to_sql_integer(cursor)?,
                    replay_head.as_bytes(),
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(cursor)
    }

    /// Loads a bounded page of completed local application messages.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed, authentication, protocol, or storage error.
    pub(crate) fn load_messages(
        &self,
        conversation_id: ConversationId,
        after_cursor: u64,
        limit: usize,
    ) -> Result<Vec<StoredApplicationMessage>, ProfileStoreError> {
        if !(1..=MAX_MESSAGE_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        self.conversation_routing_id(conversation_id)?;
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT cursor
                     FROM daemon_inbox
                     WHERE conversation_id = ?1 AND cursor > ?2 AND status = 3
                     ORDER BY cursor
                     LIMIT ?3",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(after_cursor)?,
                        i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut messages = Vec::with_capacity(metadata.len());
        for cursor in metadata {
            messages.push(self.load_message_at(conversation_id, from_sql_integer(cursor)?)?);
        }
        Ok(messages)
    }

    /// Loads one bounded cursor-ordered page of completed sent and received messages.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed, authentication, protocol, or storage error.
    pub(crate) fn load_history(
        &self,
        conversation_id: ConversationId,
        after_cursor: u64,
        limit: usize,
    ) -> Result<HistoryPage, ProfileStoreError> {
        if !(1..=MAX_MESSAGE_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let conversation = self.load_conversation(conversation_id)?;
        let routing_id = conversation.routing_id;
        let message_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT CASE WHEN length(message_id) = 16 THEN message_id END
                     FROM daemon_message_history
                     WHERE conversation_id = ?1
                       AND status = 2
                       AND cursor > ?2
                       AND cursor <= ?3
                     ORDER BY cursor
                     LIMIT ?4",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(after_cursor)?,
                        to_sql_integer(conversation.replay_cursor)?,
                        i64::try_from(limit + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let has_more = message_ids.len() > limit;
        let mut messages = Vec::with_capacity(message_ids.len().min(limit));
        for message_id in message_ids.into_iter().take(limit) {
            let message_id =
                MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let connection = self.lock()?;
            let history = self
                .load_history_record(&connection, conversation_id, routing_id, message_id)?
                .ok_or(ProfileStoreError::CorruptData)?;
            drop(connection);
            let cursor = history.cursor.ok_or(ProfileStoreError::CorruptData)?;
            match history.direction {
                MessageDirection::Outbound => {
                    let outbox = self.load_outbox_record(history.envelope_id)?;
                    if outbox.reservation.conversation_id != conversation_id {
                        return Err(ProfileStoreError::CorruptData);
                    }
                    let connection = self.lock()?;
                    self.verify_cursor_observation(
                        &connection,
                        conversation_id,
                        routing_id,
                        cursor,
                        &outbox.envelope,
                    )?;
                }
                MessageDirection::Inbound => {
                    let inbox = self.load_inbox_envelope(history.envelope_id)?;
                    if inbox.cursor() != cursor {
                        return Err(ProfileStoreError::CorruptData);
                    }
                }
            }
            messages.push(stored_history_message(history).ok_or(ProfileStoreError::CorruptData)?);
        }
        Ok(HistoryPage { messages, has_more })
    }

    fn cursor_observation_for_envelope(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        envelope: &RelayEnvelope,
    ) -> Result<Option<u64>, ProfileStoreError> {
        let envelope_id = envelope.envelope_id();
        let metadata: Option<(Vec<u8>, i64, Vec<u8>, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    cursor,
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    length(sealed_observation)
                 FROM daemon_cursor_observation
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((stored_conversation, cursor, stored_envelope, length)) = metadata else {
            return Ok(None);
        };
        if ConversationId::from_slice(&stored_conversation).ok() != Some(conversation_id)
            || EnvelopeId::from_slice(&stored_envelope).ok() != Some(envelope_id)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        validate_blob_length(length)?;
        let cursor = from_sql_integer(cursor)?;
        let connection = self.lock()?;
        self.verify_cursor_observation(&connection, conversation_id, routing_id, cursor, envelope)?;
        Ok(Some(cursor))
    }

    fn verify_replay_position(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        state: &ConversationState,
        cursor: u64,
        head: &ReplayHead,
    ) -> Result<(), ProfileStoreError> {
        if head.cursor != cursor
            || head.policy_state != *state
            || head.completion_state.conversation_id() != conversation_id
            || head.policy_state.conversation_id() != conversation_id
            || head.completion_state.version() != head.policy_state.version()
            || head.completion_state.epoch() > head.policy_state.epoch()
            || head.envelope.routing_id() != routing_id
            || head.kind != ReplayCompletionKind::Join
                && head.previous_cursor.checked_add(1) != Some(cursor)
            || head.kind == ReplayCompletionKind::Join && head.previous_cursor != 0
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let observed = self.load_cursor_observation(conversation_id, routing_id, cursor)?;
        if observed.envelope() != &head.envelope {
            return Err(ProfileStoreError::CursorConflict);
        }
        match head.kind {
            ReplayCompletionKind::Application => {
                let message = self.load_message_at(conversation_id, cursor)?;
                if message.envelope_id == head.envelope.envelope_id() {
                    Ok(())
                } else {
                    Err(ProfileStoreError::CursorConflict)
                }
            }
            ReplayCompletionKind::Membership => {
                let transition =
                    self.load_membership_inbox_transition(conversation_id, cursor, observed)?;
                if transition.next_state == head.completion_state {
                    Ok(())
                } else {
                    Err(ProfileStoreError::ConversationMismatch)
                }
            }
            ReplayCompletionKind::Join
                if head.envelope.delivery_class() == DeliveryClass::GroupCommit
                    && head
                        .envelope
                        .expected_parent_epoch()
                        .and_then(|epoch| epoch.checked_add(1))
                        == Some(head.completion_state.epoch()) =>
            {
                let inbox_count: i64 = self
                    .lock()?
                    .query_row(
                        "SELECT
                            (SELECT count(*) FROM daemon_inbox
                             WHERE conversation_id = ?1 AND cursor = ?2)
                            +
                            (SELECT count(*) FROM daemon_membership_inbox
                             WHERE conversation_id = ?1 AND cursor = ?2)",
                        params![
                            conversation_id.as_bytes().as_slice(),
                            to_sql_integer(cursor)?
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if inbox_count == 0 {
                    Ok(())
                } else {
                    Err(ProfileStoreError::CorruptData)
                }
            }
            ReplayCompletionKind::Join => Err(ProfileStoreError::CorruptData),
        }
    }

    fn migrate_v1_replay_head(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        mut head: ReplayHead,
    ) -> Result<ReplayHead, ProfileStoreError> {
        if head.version != ReplayHeadVersion::V1 {
            return Err(ProfileStoreError::CorruptData);
        }
        if head.kind == ReplayCompletionKind::Membership {
            let observed =
                self.load_cursor_observation(conversation_id, routing_id, head.cursor)?;
            if observed.envelope() != &head.envelope {
                return Err(ProfileStoreError::CursorConflict);
            }
            head.completion_state = self
                .load_membership_inbox_transition(conversation_id, head.cursor, observed)?
                .next_state;
        }
        if head.completion_state.conversation_id() != conversation_id
            || head.completion_state.version() != head.policy_state.version()
            || head.completion_state.epoch() > head.policy_state.epoch()
        {
            return Err(ProfileStoreError::CorruptData);
        }
        head.version = ReplayHeadVersion::V2;
        Ok(head)
    }

    fn load_cursor_observation(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
    ) -> Result<StoredRelayEnvelope, ProfileStoreError> {
        let (envelope_id, length): (Vec<u8>, i64) = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    length(sealed_observation)
                 FROM daemon_cursor_observation
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::CursorConflict)?;
        validate_blob_length(length)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_observation
                 FROM daemon_cursor_observation
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            CURSOR_OBSERVATION_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        let observed = decode_cursor_observation(&plaintext)?;
        if observed.cursor() != cursor
            || observed.envelope().envelope_id() != envelope_id
            || observed.envelope().routing_id() != routing_id
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        Ok(observed)
    }

    fn normalize_membership_acceptance(
        &self,
        operation_id: MembershipOperationId,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
        envelope: &RelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.verify_cursor_observation(
            &transaction,
            conversation_id,
            routing_id,
            cursor,
            envelope,
        )?;
        let changed = transaction
            .execute(
                "UPDATE daemon_membership_outbox
                 SET status = 2, accepted_cursor = ?1
                 WHERE operation_id = ?2
                   AND conversation_id = ?3
                   AND envelope_id = ?4",
                params![
                    to_sql_integer(cursor)?,
                    operation_id.as_bytes().as_slice(),
                    conversation_id.as_bytes().as_slice(),
                    envelope.envelope_id().as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    fn normalize_membership_ready(
        &self,
        operation_id: MembershipOperationId,
    ) -> Result<(), ProfileStoreError> {
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_membership_outbox
                 SET status = 1, accepted_cursor = NULL
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn insert_or_verify_cursor_observation(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
        envelope: &RelayEnvelope,
    ) -> Result<bool, ProfileStoreError> {
        let envelope_id = envelope.envelope_id();
        let plaintext = encode_cursor_observation(cursor, envelope)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            CURSOR_OBSERVATION_RECORD_SCOPE,
            envelope_id.as_bytes(),
            &plaintext,
        )?;
        match transaction.execute(
            "INSERT INTO daemon_cursor_observation (
                conversation_id, cursor, envelope_id, sealed_observation
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(cursor)?,
                envelope_id.as_bytes().as_slice(),
                blob.as_bytes()
            ],
        ) {
            Ok(1) => Ok(true),
            Ok(_) => Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                self.verify_cursor_observation(
                    transaction,
                    conversation_id,
                    routing_id,
                    cursor,
                    envelope,
                )?;
                Ok(false)
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    fn verify_cursor_observation(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
        envelope: &RelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id = envelope.envelope_id();
        let metadata = {
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        cursor,
                        CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                        length(sealed_observation)
                     FROM daemon_cursor_observation
                     WHERE (conversation_id = ?1 AND cursor = ?2)
                        OR envelope_id = ?3
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(cursor)?,
                        envelope_id.as_bytes().as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if metadata.len() != 1
            || ConversationId::from_slice(&metadata[0].0).ok() != Some(conversation_id)
            || from_sql_integer(metadata[0].1).ok() != Some(cursor)
            || EnvelopeId::from_slice(&metadata[0].2).ok() != Some(envelope_id)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        validate_blob_length(metadata[0].3)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_observation
                 FROM daemon_cursor_observation
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(metadata[0].3).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            CURSOR_OBSERVATION_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        let observed = decode_cursor_observation(&plaintext)?;
        if observed.cursor() != cursor || observed.envelope() != envelope {
            return Err(ProfileStoreError::CursorConflict);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "history identity and authenticated message fields remain explicit"
    )]
    fn insert_or_verify_history(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        envelope_id: EnvelopeId,
        cursor: Option<u64>,
        direction: MessageDirection,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        let plaintext =
            encode_history_message_record(direction, envelope_id, sender, epoch, message)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            conversation_id,
            routing_id,
            MESSAGE_HISTORY_RECORD_SCOPE,
            message.message_id().as_bytes(),
            &plaintext,
        )?;
        let insert = connection.execute(
            "INSERT INTO daemon_message_history (
                conversation_id,
                message_id,
                envelope_id,
                cursor,
                direction,
                status,
                sender_device_id,
                sender_epoch,
                sender_counter,
                sealed_message
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9)",
            params![
                conversation_id.as_bytes().as_slice(),
                message.message_id().as_bytes().as_slice(),
                envelope_id.as_bytes().as_slice(),
                cursor.map(to_sql_integer).transpose()?,
                direction as i64,
                sender.as_bytes().as_slice(),
                to_sql_integer(epoch)?,
                to_sql_integer(message.sender_counter())?,
                blob.as_bytes()
            ],
        );
        match insert {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation => {}
            Err(_) => return Err(ProfileStoreError::Storage),
        }
        let existing = self
            .load_history_record(
                connection,
                conversation_id,
                routing_id,
                message.message_id(),
            )?
            .ok_or(ProfileStoreError::DuplicateOperation)?;
        if existing.envelope_id != envelope_id
            || existing.sender != sender
            || existing.epoch != epoch
            || !application_messages_equal(&existing.message, message)?
        {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        match (existing.cursor, cursor) {
            (Some(existing), Some(candidate)) if existing != candidate => {
                return Err(ProfileStoreError::CursorConflict);
            }
            (None, Some(cursor)) => {
                connection
                    .execute(
                        "UPDATE daemon_message_history SET cursor = ?1
                         WHERE conversation_id = ?2
                           AND message_id = ?3
                           AND cursor IS NULL",
                        params![
                            to_sql_integer(cursor)?,
                            conversation_id.as_bytes().as_slice(),
                            message.message_id().as_bytes().as_slice()
                        ],
                    )
                    .map_err(map_history_update_error)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn load_history_record(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        message_id: MessageId,
    ) -> Result<Option<HistoryRecord>, ProfileStoreError> {
        let metadata: Option<HistoryMetadata> = connection
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    cursor,
                    direction,
                    status,
                    CASE WHEN length(sender_device_id) = 32
                        THEN sender_device_id
                    END,
                    sender_epoch,
                    sender_counter,
                    length(sealed_message)
                 FROM daemon_message_history
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((envelope_id, cursor, direction, status, sender, epoch, sender_counter, length)) =
            metadata
        else {
            return Ok(None);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_message
                 FROM daemon_message_history
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    SecretRecordKind::LocalApplicationMessage,
                    conversation_id,
                    routing_id,
                    MESSAGE_HISTORY_RECORD_SCOPE,
                    message_id.as_bytes(),
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let (stored_direction, stored_envelope, stored_sender, stored_epoch, message) =
            decode_history_message_record(&plaintext)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let sender = DeviceId::from_slice(&sender).map_err(|_| ProfileStoreError::CorruptData)?;
        let epoch = from_sql_integer(epoch)?;
        if stored_envelope != envelope_id
            || stored_sender != sender
            || stored_epoch != epoch
            || message.message_id() != message_id
            || message.sender_counter() != from_sql_integer(sender_counter)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let direction = match direction {
            1 => MessageDirection::Outbound,
            2 => MessageDirection::Inbound,
            _ => return Err(ProfileStoreError::CorruptData),
        };
        if stored_direction != direction {
            return Err(ProfileStoreError::CorruptData);
        }
        let complete = match status {
            1 => false,
            2 => true,
            _ => return Err(ProfileStoreError::CorruptData),
        };
        Ok(Some(HistoryRecord {
            cursor: cursor.map(from_sql_integer).transpose()?,
            direction,
            envelope_id,
            sender,
            epoch,
            message,
            complete,
        }))
    }

    fn assign_history_cursor(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        message_id: MessageId,
        envelope_id: EnvelopeId,
        cursor: u64,
    ) -> Result<bool, ProfileStoreError> {
        let Some(history) =
            self.load_history_record(connection, conversation_id, routing_id, message_id)?
        else {
            return Ok(false);
        };
        if history.envelope_id != envelope_id
            || history.cursor.is_some_and(|existing| existing != cursor)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        if history.cursor == Some(cursor) {
            return Ok(true);
        }
        let changed = connection
            .execute(
                "UPDATE daemon_message_history
                 SET cursor = ?1
                 WHERE conversation_id = ?2
                   AND message_id = ?3
                   AND cursor IS NULL",
                params![
                    to_sql_integer(cursor)?,
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
            )
            .map_err(map_history_update_error)?;
        if changed == 1 {
            Ok(true)
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn complete_history(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        message_id: MessageId,
        envelope_id: EnvelopeId,
        cursor: u64,
    ) -> Result<bool, ProfileStoreError> {
        let Some(history) =
            self.load_history_record(connection, conversation_id, routing_id, message_id)?
        else {
            return Ok(false);
        };
        if history.envelope_id != envelope_id
            || history.cursor.is_some_and(|existing| existing != cursor)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        if history.complete && history.cursor == Some(cursor) {
            return Ok(true);
        }
        let changed = connection
            .execute(
                "UPDATE daemon_message_history
                 SET cursor = ?1, status = 2
                 WHERE conversation_id = ?2
                   AND message_id = ?3
                   AND status = 1",
                params![
                    to_sql_integer(cursor)?,
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
            )
            .map_err(map_history_update_error)?;
        if changed == 1 {
            Ok(true)
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn load_sender_high_water(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        sender: DeviceId,
        epoch: u64,
    ) -> Result<Option<u64>, ProfileStoreError> {
        let metadata: Option<(i64, i64)> = connection
            .query_row(
                "SELECT highest_counter, length(sealed_state)
                 FROM daemon_sender_counter
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = ?3",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender.as_bytes().as_slice(),
                    to_sql_integer(epoch)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((highest_counter, length)) = metadata else {
            return Ok(None);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_sender_counter
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = ?3",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender.as_bytes().as_slice(),
                    to_sql_integer(epoch)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &sender_counter_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    sender,
                    epoch,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let (stored_sender, stored_epoch, stored_counter) =
            decode_sender_counter_state(&plaintext)?;
        let highest_counter = from_sql_integer(highest_counter)?;
        if stored_sender != sender || stored_epoch != epoch || stored_counter != highest_counter {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(Some(highest_counter))
    }

    fn store_sender_high_water(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        sender: DeviceId,
        epoch: u64,
        highest_counter: u64,
    ) -> Result<(), ProfileStoreError> {
        let plaintext = encode_sender_counter_state(sender, epoch, highest_counter)?;
        let blob = self
            .sealer
            .seal(
                &sender_counter_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    sender,
                    epoch,
                )?,
                &plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        connection
            .execute(
                "INSERT INTO daemon_sender_counter (
                    conversation_id,
                    sender_device_id,
                    sender_epoch,
                    highest_counter,
                    sealed_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (conversation_id, sender_device_id, sender_epoch)
                 DO UPDATE SET
                    highest_counter = excluded.highest_counter,
                    sealed_state = excluded.sealed_state",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender.as_bytes().as_slice(),
                    to_sql_integer(epoch)?,
                    to_sql_integer(highest_counter)?,
                    blob.as_bytes()
                ],
            )
            .map(|_| ())
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn load_membership_outbox_where(
        &self,
        predicate: &str,
        value: &[u8],
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        let query = format!(
            "SELECT
                CASE WHEN length(m.operation_id) = 16 THEN m.operation_id END,
                CASE WHEN length(m.conversation_id) = 32 THEN m.conversation_id END,
                m.parent_epoch,
                CASE WHEN length(m.envelope_id) = 16 THEN m.envelope_id END,
                m.status,
                m.accepted_cursor,
                CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                length(m.sealed_operation)
             FROM daemon_membership_outbox m
             JOIN daemon_conversation c
               ON c.conversation_id = m.conversation_id
             {predicate}
             LIMIT 2"
        );
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(&query)
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(params![value], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if metadata.len() > 1 {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        let Some((
            operation_id,
            conversation_id,
            parent_epoch,
            envelope_id,
            status,
            accepted_cursor,
            routing_id,
            sealed_length,
        )) = metadata.into_iter().next()
        else {
            return Ok(None);
        };
        validate_blob_length(sealed_length)?;
        let sealed_operation: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_operation
                 FROM daemon_membership_outbox
                 WHERE operation_id = ?1",
                params![&operation_id],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed_operation.len() != usize::try_from(sealed_length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let operation_id = MembershipOperationId::from_slice(&operation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let parent_epoch = from_sql_integer(parent_epoch)?;
        let status = membership_outbox_status(status)?;
        let accepted_cursor = accepted_cursor.map(from_sql_integer).transpose()?;
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            MEMBERSHIP_OUTBOX_RECORD_SCOPE,
            operation_id.as_bytes(),
            sealed_operation,
        )?;
        let decoded = decode_membership_outbox_record(conversation_id, operation_id, &plaintext)?;
        let request_columns: MembershipRequestColumns = self
            .lock()?
            .query_row(
                "SELECT
                change_kind,
                subject_device_id,
                subject_invitation_id,
                subject_role
             FROM daemon_membership_outbox
             WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let expected_request = membership_request_metadata(&decoded.control)?;
        if (request_columns.0.is_some()
            || request_columns.1.is_some()
            || request_columns.2.is_some()
            || request_columns.3.is_some())
            && (request_columns.0 != Some(expected_request.kind)
                || request_columns
                    .1
                    .as_deref()
                    .and_then(|value| DeviceId::from_slice(value).ok())
                    != Some(expected_request.device_id)
                || request_columns
                    .2
                    .as_deref()
                    .and_then(|value| InvitationId::from_slice(value).ok())
                    != expected_request.invitation_id
                || request_columns.3 != expected_request.role)
        {
            return Err(ProfileStoreError::CorruptData);
        }
        if decoded.parent_epoch != parent_epoch
            || decoded.envelope.envelope_id() != envelope_id
            || decoded.envelope.routing_id() != routing_id
            || status == MembershipOutboxStatus::Ready && accepted_cursor.is_some()
            || matches!(
                status,
                MembershipOutboxStatus::Accepted | MembershipOutboxStatus::Applied
            ) && accepted_cursor.is_none()
            || status == MembershipOutboxStatus::Orphaned && accepted_cursor.is_some()
        {
            return Err(ProfileStoreError::CorruptData);
        }
        if let Some(cursor) = accepted_cursor.filter(|_| {
            matches!(
                status,
                MembershipOutboxStatus::Accepted | MembershipOutboxStatus::Applied
            )
        }) {
            let connection = self.lock()?;
            self.verify_cursor_observation(
                &connection,
                conversation_id,
                routing_id,
                cursor,
                &decoded.envelope,
            )?;
        }
        Ok(Some(MembershipOutbox {
            operation_id,
            conversation_id,
            parent_epoch,
            envelope: decoded.envelope,
            control: decoded.control,
            next_state: decoded.next_state,
            bindings: decoded.bindings,
            welcome: decoded.welcome,
            status,
            accepted_cursor,
        }))
    }

    fn membership_outbox_for_request(
        &self,
        conversation_id: ConversationId,
        kind: i64,
        device_id: Option<DeviceId>,
        invitation_id: Option<InvitationId>,
        role: Option<i64>,
    ) -> Result<Option<MembershipOutbox>, ProfileStoreError> {
        let operation_id: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
                 FROM daemon_membership_outbox
                 WHERE conversation_id = ?1
                   AND change_kind = ?2
                   AND (?3 IS NULL OR subject_device_id = ?3)
                   AND (?4 IS NULL OR subject_invitation_id = ?4)
                   AND (?5 IS NULL OR subject_role = ?5)
                   AND status != 4
                 ORDER BY parent_epoch DESC
                 LIMIT 1",
                params![
                    conversation_id.as_bytes().as_slice(),
                    kind,
                    device_id.map(|value| value.as_bytes().to_vec()),
                    invitation_id.map(|value| value.as_bytes().to_vec()),
                    role
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        operation_id
            .map(|operation_id| {
                MembershipOperationId::from_slice(&operation_id)
                    .map_err(|_| ProfileStoreError::CorruptData)
                    .and_then(|operation_id| self.load_membership_outbox(operation_id))
            })
            .transpose()
    }

    fn verify_applied_membership(
        &self,
        record: &MembershipOutbox,
    ) -> Result<(), ProfileStoreError> {
        let stored = self.load_conversation(record.conversation_id)?;
        let expected =
            final_membership_bindings(record, stored.signing_material.binding().device_id());
        if stored.state != record.next_state
            || stored.bindings.len() != expected.len()
            || !stored.bindings.iter().all(|binding| {
                expected
                    .iter()
                    .any(|expected| expected.binding() == binding.binding())
            })
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn verify_historical_applied_add(
        &self,
        record: &MembershipOutbox,
    ) -> Result<(), ProfileStoreError> {
        if record.status != MembershipOutboxStatus::Applied || record.accepted_cursor.is_none() {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let (authorization, proof) =
            decode_membership_control(&record.control).map_err(|_| ProfileStoreError::Protocol)?;
        let proof = proof.ok_or(ProfileStoreError::CorruptData)?;
        let MembershipChange::Add(add) = authorization.change() else {
            return Err(ProfileStoreError::InvalidTransition);
        };
        let verified = verify_device_credential_binding(proof.credential())
            .map_err(|_| ProfileStoreError::Cryptographic)?;
        let welcome = record
            .welcome
            .as_deref()
            .ok_or(ProfileStoreError::CorruptData)?;
        MlsWelcome::from_bytes(welcome).map_err(|_| ProfileStoreError::Cryptographic)?;
        if authorization.operation_id() != record.operation_id
            || authorization.conversation_id() != record.conversation_id
            || authorization.parent_epoch() != record.parent_epoch
            || record.parent_epoch.checked_add(1) != Some(record.next_state.epoch())
            || add.device_id() != proof.credential().device_id()
            || add.role() != proof.invitation().role()
            || add.invitation_id() != proof.invitation().invitation_id()
            || add.credential_binding_hash() != verified.hash()
            || record
                .next_state
                .member(add.device_id())
                .is_none_or(|member| {
                    member.role() != add.role()
                        || member.joined_epoch() != record.next_state.epoch()
                })
            || !record
                .next_state
                .consumed_invitation_ids()
                .contains(&add.invitation_id())
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let current = self.load_conversation(record.conversation_id)?;
        if current.state.version() != record.next_state.version()
            || current.state.conversation_id() != record.next_state.conversation_id()
            || current.state.epoch() < record.next_state.epoch()
            || !record
                .next_state
                .consumed_invitation_ids()
                .iter()
                .all(|invitation_id| {
                    current
                        .state
                        .consumed_invitation_ids()
                        .contains(invitation_id)
                })
            || current.state.epoch() == record.next_state.epoch()
                && current.state != record.next_state
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated replay-head fields remain explicit"
    )]
    fn seal_replay_head(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        previous_cursor: u64,
        cursor: u64,
        kind: ReplayCompletionKind,
        completion_state: &ConversationState,
        policy_state: &ConversationState,
        envelope: &RelayEnvelope,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let plaintext = encode_replay_head(
            previous_cursor,
            cursor,
            kind,
            completion_state,
            policy_state,
            envelope,
        )?;
        self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            REPLAY_HEAD_RECORD_SCOPE,
            conversation_id.as_bytes(),
            &plaintext,
        )
    }

    fn open_replay_head(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        bytes: Vec<u8>,
    ) -> Result<ReplayHead, ProfileStoreError> {
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            REPLAY_HEAD_RECORD_SCOPE,
            conversation_id.as_bytes(),
            bytes,
        )?;
        decode_replay_head(&plaintext)
    }

    fn advance_replay_head_state(
        &self,
        conversation: &StoredConversation,
        next_state: &ConversationState,
    ) -> Result<Option<SealedBlob>, ProfileStoreError> {
        if conversation.replay_cursor == 0 {
            return Ok(None);
        }
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_replay_head
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![next_state.conversation_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let head =
            self.open_replay_head(next_state.conversation_id(), conversation.routing_id, bytes)?;
        self.verify_replay_position(
            next_state.conversation_id(),
            conversation.routing_id,
            &conversation.state,
            conversation.replay_cursor,
            &head,
        )?;
        if head.policy_state != conversation.state
            || next_state.version() != conversation.state.version()
            || next_state.conversation_id() != conversation.state.conversation_id()
            || conversation.state.epoch().checked_add(1) != Some(next_state.epoch())
        {
            return Err(ProfileStoreError::CorruptData);
        }
        self.seal_replay_head(
            next_state.conversation_id(),
            conversation.routing_id,
            head.previous_cursor,
            head.cursor,
            head.kind,
            &head.completion_state,
            next_state,
            &head.envelope,
        )
        .map(Some)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated membership checkpoint fields remain explicit"
    )]
    fn save_membership_inbox_transition_record(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        parent_epoch: u64,
        operation_id: MembershipOperationId,
        control: &[u8],
        next_state: &ConversationState,
        bindings: &[DeviceCredentialBinding],
    ) -> Result<(), ProfileStoreError> {
        let envelope_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(envelope_id) = 16 THEN envelope_id END
                 FROM daemon_membership_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::InvalidTransition)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let stored = self.load_membership_inbox_envelope(conversation_id, cursor, envelope_id)?;
        let plaintext = encode_membership_inbox_transition(
            cursor,
            envelope_id,
            sender,
            parent_epoch,
            operation_id,
            control,
            next_state,
            bindings,
        )?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            stored.envelope().routing_id(),
            MEMBERSHIP_INBOX_TRANSITION_RECORD_SCOPE,
            operation_id.as_bytes(),
            &plaintext,
        )?;
        let update = self.lock()?.execute(
            "UPDATE daemon_membership_inbox
             SET sender_device_id = ?1,
                 parent_epoch = ?2,
                 operation_id = ?3,
                 sealed_transition = ?4,
                 status = 2
             WHERE conversation_id = ?5 AND cursor = ?6 AND status = 1",
            params![
                sender.as_bytes().as_slice(),
                to_sql_integer(parent_epoch)?,
                operation_id.as_bytes().as_slice(),
                blob.as_bytes(),
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(cursor)?
            ],
        );
        match update {
            Ok(1) => Ok(()),
            Ok(_) => {
                let existing =
                    self.load_membership_inbox_transition(conversation_id, cursor, stored)?;
                if existing.sender == sender
                    && existing.parent_epoch == parent_epoch
                    && existing.operation_id == operation_id
                    && existing.control.as_slice() == control
                    && existing.next_state == *next_state
                    && same_verified_bindings(&existing.bindings, bindings)
                {
                    Ok(())
                } else {
                    Err(ProfileStoreError::InvalidTransition)
                }
            }
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(ProfileStoreError::DuplicateOperation)
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    fn load_membership_inbox_envelope(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        envelope_id: EnvelopeId,
    ) -> Result<StoredRelayEnvelope, ProfileStoreError> {
        let (routing_id, length): (Vec<u8>, i64) = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                    length(i.sealed_envelope)
                 FROM daemon_membership_inbox i
                 JOIN daemon_conversation c
                   ON c.conversation_id = i.conversation_id
                 WHERE i.conversation_id = ?1
                   AND i.cursor = ?2
                   AND i.envelope_id = ?3",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?,
                    envelope_id.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_envelope
                 FROM daemon_membership_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            MEMBERSHIP_INBOX_ENVELOPE_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        let stored = decode_inbox_envelope_record(&plaintext)?;
        if stored.cursor() != cursor
            || stored.envelope().envelope_id() != envelope_id
            || stored.envelope().routing_id() != routing_id
            || stored.envelope().delivery_class() != DeliveryClass::GroupCommit
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(stored)
    }

    fn load_membership_inbox_transition(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        stored: StoredRelayEnvelope,
    ) -> Result<StoredMembershipTransition, ProfileStoreError> {
        let metadata: (Vec<u8>, i64, Vec<u8>, i64) = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(sender_device_id) = 32 THEN sender_device_id END,
                    parent_epoch,
                    CASE WHEN length(operation_id) = 16 THEN operation_id END,
                    length(sealed_transition)
                 FROM daemon_membership_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2 AND status BETWEEN 2 AND 3",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let sender =
            DeviceId::from_slice(&metadata.0).map_err(|_| ProfileStoreError::CorruptData)?;
        let parent_epoch = from_sql_integer(metadata.1)?;
        let operation_id = MembershipOperationId::from_slice(&metadata.2)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        validate_blob_length(metadata.3)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_transition
                 FROM daemon_membership_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(metadata.3).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            stored.envelope().routing_id(),
            MEMBERSHIP_INBOX_TRANSITION_RECORD_SCOPE,
            operation_id.as_bytes(),
            bytes,
        )?;
        let transition = decode_membership_inbox_transition(
            conversation_id,
            cursor,
            stored.envelope().envelope_id(),
            &plaintext,
        )?;
        if transition.sender != sender
            || transition.parent_epoch != parent_epoch
            || transition.operation_id != operation_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(StoredMembershipTransition {
            stored,
            sender,
            parent_epoch,
            operation_id,
            control: transition.control,
            next_state: transition.next_state,
            bindings: transition.bindings,
        })
    }

    fn seal_operation_record(
        &self,
        kind: SecretRecordKind,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        scope: u8,
        record_id: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    kind,
                    conversation_id,
                    routing_id,
                    scope,
                    record_id,
                )?,
                plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_operation_record(
        &self,
        kind: SecretRecordKind,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        scope: u8,
        record_id: &[u8],
        bytes: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        self.sealer
            .open(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    kind,
                    conversation_id,
                    routing_id,
                    scope,
                    record_id,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn open_outbox_record(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        envelope_id: EnvelopeId,
        bytes: Vec<u8>,
    ) -> Result<OutboxRecord, ProfileStoreError> {
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            OUTBOX_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        decode_outbox_record(conversation_id, envelope_id, &plaintext)
    }

    fn load_outbox_record(
        &self,
        envelope_id: EnvelopeId,
    ) -> Result<OutboxRecord, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, Vec<u8>, Option<i64>)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    length(sealed_envelope)
                 FROM daemon_outbox
                 JOIN daemon_conversation USING (conversation_id)
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (conversation_id, routing_id, length) =
            metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        let length = length.ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_envelope FROM daemon_outbox WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        self.open_outbox_record(
            ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?,
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?,
            envelope_id,
            bytes,
        )
    }

    fn load_inbox_envelope(
        &self,
        envelope_id: EnvelopeId,
    ) -> Result<StoredRelayEnvelope, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, Vec<u8>, i64, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    cursor,
                    length(sealed_envelope)
                 FROM daemon_inbox
                 JOIN daemon_conversation USING (conversation_id)
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (conversation_id, routing_id, cursor, length) =
            metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_envelope FROM daemon_inbox WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            INBOX_ENVELOPE_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        let stored = decode_inbox_envelope_record(&plaintext)?;
        if stored.cursor() != from_sql_integer(cursor)?
            || stored.envelope().envelope_id() != envelope_id
            || stored.envelope().routing_id() != routing_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        {
            let connection = self.lock()?;
            self.verify_cursor_observation(
                &connection,
                conversation_id,
                routing_id,
                stored.cursor(),
                stored.envelope(),
            )?;
        }
        Ok(stored)
    }

    fn load_conflicting_inbox(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        envelope_id: EnvelopeId,
    ) -> Result<StoredRelayEnvelope, ProfileStoreError> {
        let envelope_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT CASE WHEN length(envelope_id) = 16 THEN envelope_id END
                     FROM daemon_inbox
                     WHERE envelope_id = ?1
                        OR (conversation_id = ?2 AND cursor = ?3)
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        envelope_id.as_bytes().as_slice(),
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(cursor)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if envelope_ids.len() != 1
            || EnvelopeId::from_slice(&envelope_ids[0]).ok() != Some(envelope_id)
        {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        self.load_inbox_envelope(envelope_id)
    }

    fn load_message_at(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<StoredApplicationMessage, ProfileStoreError> {
        let metadata: Option<InboxMessageMetadata> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                    CASE WHEN length(i.envelope_id) = 16 THEN i.envelope_id END,
                    CASE WHEN length(i.sender_device_id) = 32 THEN i.sender_device_id END,
                    i.sender_epoch,
                    i.sender_counter,
                    CASE WHEN length(i.message_id) = 16 THEN i.message_id END,
                    length(i.sealed_message)
                 FROM daemon_inbox i
                 JOIN daemon_conversation c
                   ON c.conversation_id = i.conversation_id
                 WHERE i.conversation_id = ?1 AND i.cursor = ?2 AND i.status >= 2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (routing_id, envelope_id, sender, sender_epoch, sender_counter, message_id, length) =
            metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_message FROM daemon_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let sender = DeviceId::from_slice(&sender).map_err(|_| ProfileStoreError::CorruptData)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let message_id =
            MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            conversation_id,
            routing_id,
            INBOX_MESSAGE_RECORD_SCOPE,
            message_id.as_bytes(),
            bytes,
        )?;
        let stored = decode_inbox_message_record(&plaintext)?;
        if stored.cursor != cursor
            || stored.envelope_id != envelope_id
            || stored.sender != sender
            || stored.epoch != from_sql_integer(sender_epoch)?
            || stored.message.message_id() != message_id
            || stored.message.sender_counter() != from_sql_integer(sender_counter)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(stored)
    }

    fn conversation_routing_id(
        &self,
        conversation_id: ConversationId,
    ) -> Result<RoutingId, ProfileStoreError> {
        let routing_id: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(routing_id) = 32 THEN routing_id END
                 FROM daemon_conversation WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        RoutingId::from_slice(&routing_id.ok_or(ProfileStoreError::ConversationNotFound)?)
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn load_bindings(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Vec<VerifiedDeviceCredentialBinding>, ProfileStoreError> {
        let count: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*) FROM daemon_conversation_binding
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if count < 1
            || usize::try_from(count)
                .ok()
                .is_none_or(|count| count > MAX_LOCAL_BINDINGS)
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(device_id) = 32 THEN device_id END,
                        length(sealed_binding)
                     FROM daemon_conversation_binding
                     WHERE conversation_id = ?1
                     ORDER BY device_id",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(params![conversation_id.as_bytes().as_slice()], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut bindings = Vec::with_capacity(metadata.len());
        for (device_id, length) in metadata {
            validate_blob_length(length)?;
            let bytes: Vec<u8> = self
                .lock()?
                .query_row(
                    "SELECT sealed_binding
                     FROM daemon_conversation_binding
                     WHERE conversation_id = ?1 AND device_id = ?2",
                    params![conversation_id.as_bytes().as_slice(), &device_id],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if bytes.len() != usize::try_from(length).unwrap_or_default() {
                return Err(ProfileStoreError::CorruptData);
            }
            let device_id =
                DeviceId::from_slice(&device_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
            let plaintext = self
                .sealer
                .open(
                    &conversation_record_context(
                        &self.locked_profile.profile_id,
                        SecretRecordKind::ConversationCredentialBinding,
                        conversation_id,
                        None,
                        Some(device_id),
                    )?,
                    &blob,
                )
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let binding = decode_device_credential_binding(&plaintext)
                .map_err(|_| ProfileStoreError::Protocol)?;
            if binding.conversation_id() != conversation_id || binding.device_id() != device_id {
                return Err(ProfileStoreError::ConversationMismatch);
            }
            bindings.push(
                verify_device_credential_binding(&binding)
                    .map_err(|_| ProfileStoreError::Cryptographic)?,
            );
        }
        Ok(bindings)
    }

    fn seal_conversation_record(
        &self,
        kind: SecretRecordKind,
        conversation_id: ConversationId,
        routing_id: Option<RoutingId>,
        device_id: Option<DeviceId>,
        plaintext: &[u8],
    ) -> Result<SealedBlob, ProfileStoreError> {
        let context = conversation_record_context(
            &self.locked_profile.profile_id,
            kind,
            conversation_id,
            routing_id,
            device_id,
        )?;
        self.sealer
            .seal(&context, plaintext)
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn read_profile_blob(
        &self,
        length_query: &str,
        value_query: &str,
    ) -> Result<Option<SealedBlob>, ProfileStoreError> {
        let length: Option<i64> = self
            .lock()?
            .query_row(length_query, [], |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some(length) = length else {
            return Ok(None);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(value_query, [], |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        SealedBlob::from_bytes(bytes)
            .map(Some)
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ProfileStoreError> {
        self.connection
            .lock()
            .map_err(|_| ProfileStoreError::Storage)
    }
}

/// Reopened conversation inputs for the cryptographic client and relay transport.
pub(crate) struct StoredConversation {
    pub routing_id: RoutingId,
    pub signing_material: ConversationSigningMaterial,
    pub state: ConversationState,
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
    pub sender_counter: u64,
    pub replay_cursor: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundReservation {
    pub conversation_id: ConversationId,
    pub message_id: MessageId,
    pub envelope_id: EnvelopeId,
    pub sender_counter: u64,
}

pub(crate) struct PendingOutbox {
    pub conversation_id: ConversationId,
    pub envelope: RelayEnvelope,
}

pub(crate) struct StoredOutboundApplication {
    pub conversation_id: ConversationId,
    pub message: ApplicationMessage,
    pub envelope: RelayEnvelope,
    pub status: OutboundApplicationStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboundApplicationStatus {
    Ready,
    Accepted { cursor: u64 },
    Expired,
    Removed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpireOutboundResult {
    Expired,
    Accepted { cursor: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MembershipOutboxStatus {
    Ready = 1,
    Accepted = 2,
    Applied = 3,
    Orphaned = 4,
}

pub(crate) struct MembershipOutbox {
    pub operation_id: MembershipOperationId,
    pub conversation_id: ConversationId,
    pub parent_epoch: u64,
    pub envelope: RelayEnvelope,
    pub control: Zeroizing<Vec<u8>>,
    pub next_state: ConversationState,
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
    pub welcome: Option<Vec<u8>>,
    pub status: MembershipOutboxStatus,
    pub accepted_cursor: Option<u64>,
}

pub(crate) struct StoredMembershipTransition {
    pub stored: StoredRelayEnvelope,
    pub sender: DeviceId,
    pub parent_epoch: u64,
    pub operation_id: MembershipOperationId,
    pub control: Zeroizing<Vec<u8>>,
    pub next_state: ConversationState,
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
}

pub(crate) enum MembershipInboxOperation {
    Received { stored: StoredRelayEnvelope },
    TransitionSaved(StoredMembershipTransition),
    Complete(StoredMembershipTransition),
}

pub(crate) struct PendingJoin {
    pub conversation_id: ConversationId,
    pub routing_id: RoutingId,
    pub verified_at_unix_seconds: u64,
    pub signing_material: ConversationSigningMaterial,
    pub invitation: Invitation,
    pub proof: Option<JoinProof>,
    pub issuer_public_key: Ed25519PublicKey,
    pub peer_bindings: Vec<VerifiedDeviceCredentialBinding>,
    pub state: Option<ConversationState>,
    pub expected_commit_envelope_id: Option<EnvelopeId>,
    pub join_receipt: Option<StoredRelayEnvelope>,
}

struct OutboxRecord {
    reservation: OutboundReservation,
    envelope: RelayEnvelope,
}

struct MembershipOutboxRecord {
    parent_epoch: u64,
    envelope: RelayEnvelope,
    control: Zeroizing<Vec<u8>>,
    next_state: ConversationState,
    bindings: Vec<VerifiedDeviceCredentialBinding>,
    welcome: Option<Vec<u8>>,
}

struct MembershipInboxTransitionRecord {
    sender: DeviceId,
    parent_epoch: u64,
    operation_id: MembershipOperationId,
    control: Zeroizing<Vec<u8>>,
    next_state: ConversationState,
    bindings: Vec<VerifiedDeviceCredentialBinding>,
}

struct MembershipRequestMetadata {
    kind: i64,
    device_id: DeviceId,
    invitation_id: Option<InvitationId>,
    role: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayCompletionKind {
    Application = 1,
    Membership = 2,
    Join = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayHeadVersion {
    V1,
    V2,
}

struct ReplayHead {
    version: ReplayHeadVersion,
    previous_cursor: u64,
    cursor: u64,
    kind: ReplayCompletionKind,
    completion_state: ConversationState,
    policy_state: ConversationState,
    envelope: RelayEnvelope,
}

struct HistoryRecord {
    cursor: Option<u64>,
    direction: MessageDirection,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    epoch: u64,
    message: ApplicationMessage,
    complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteEventStatus {
    Pending = 1,
    Claimed = 2,
    Acknowledged = 3,
    Suppressed = 4,
}

struct RemoteEventRecord {
    sequence: u64,
    notification_id: NotificationId,
    conversation_id: ConversationId,
    routing_id: RoutingId,
    relay_cursor: u64,
    kind: RemoteEventKind,
    sender: DeviceId,
    source_identifier: [u8; 16],
    previous_notification_id: Option<NotificationId>,
}

struct RemoteEventDeliveryState {
    status: RemoteEventStatus,
    consumer_id: Option<AdapterConsumerId>,
    lease_id: Option<AdapterLeaseId>,
    lease_generation: u64,
    lease_expires_at_unix_milliseconds: Option<u64>,
}

struct RemoteEventHead {
    sequence: u64,
    notification_id: NotificationId,
}

pub(crate) struct StoredApplicationMessage {
    pub cursor: u64,
    pub envelope_id: EnvelopeId,
    pub sender: DeviceId,
    pub epoch: u64,
    pub message: ApplicationMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageDirection {
    Outbound = 1,
    Inbound = 2,
}

pub(crate) struct StoredHistoryMessage {
    pub(crate) cursor: u64,
    pub(crate) direction: MessageDirection,
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) sender: DeviceId,
    pub(crate) epoch: u64,
    pub(crate) message: ApplicationMessage,
}

pub(crate) struct HistoryPage {
    pub(crate) messages: Vec<StoredHistoryMessage>,
    pub(crate) has_more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteEventKind {
    ApplicationMessage = 1,
    MemberAdded = 2,
    MemberRemoved = 3,
    MemberRoleChanged = 4,
    LocalAccessRemoved = 5,
}

pub(crate) enum RemoteEventPayload {
    ApplicationMessage(ApplicationMessage),
    MemberAdded {
        device_id: DeviceId,
        role: ConversationRole,
    },
    MemberRemoved {
        device_id: DeviceId,
    },
    MemberRoleChanged {
        device_id: DeviceId,
        role: ConversationRole,
    },
    LocalAccessRemoved {
        device_id: DeviceId,
    },
}

pub(crate) struct RemoteEvent {
    pub(crate) sequence: u64,
    pub(crate) notification_id: NotificationId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) relay_cursor: u64,
    pub(crate) sender: DeviceId,
    pub(crate) payload: RemoteEventPayload,
}

pub(crate) struct ClaimedRemoteEvent {
    pub(crate) event: RemoteEvent,
    pub(crate) lease_generation: u64,
}

pub(crate) enum PendingInbox {
    Received {
        conversation_id: ConversationId,
        stored: StoredRelayEnvelope,
    },
    MessageSaved {
        conversation_id: ConversationId,
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
}

pub(crate) enum InboxOperation {
    Received {
        stored: StoredRelayEnvelope,
    },
    MessageSaved {
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
    Complete {
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
}

/// Stable profile locking, sealing, schema, and validation failures.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ProfileStoreError {
    #[error("profile identifier is invalid")]
    InvalidProfileId,
    #[error("profile is already locked by another daemon")]
    ProfileLocked,
    #[error("profile filesystem operation failed")]
    Io,
    #[error("profile storage operation failed")]
    Storage,
    #[error("profile database schema is unsupported")]
    UnsupportedSchema,
    #[error("profile database belongs to another profile")]
    ProfileMismatch,
    #[error("profile data is malformed or unauthenticated")]
    CorruptData,
    #[error("profile relay is not configured")]
    RelayNotConfigured,
    #[error("profile relay credential is unavailable")]
    Credential,
    #[error("conversation already exists")]
    ConversationExists,
    #[error("conversation does not exist")]
    ConversationNotFound,
    #[error("conversation data does not agree")]
    ConversationMismatch,
    #[error("conversation protocol encoding failed")]
    Protocol,
    #[error("conversation cryptographic operation failed")]
    Cryptographic,
    #[error("local operation identifier or counter already exists")]
    DuplicateOperation,
    #[error("local operation does not exist")]
    OperationNotFound,
    #[error("legacy outbound operation has no recoverable sealed plaintext")]
    LegacyOutboundRecoveryUnsupported,
    #[error("local operation state transition is invalid")]
    InvalidTransition,
    #[error("local cursor sequence contains a gap")]
    CursorGap,
    #[error("relay cursor maps to a conflicting envelope")]
    CursorConflict,
    #[error("authenticated sender counter regressed")]
    SenderCounterRegression,
    #[error("local sequence exhausted its supported range")]
    SequenceExhausted,
    #[error("local outbox reached its pending-operation limit")]
    OutboxCapacityExceeded,
    #[error("local inbox reached its incomplete-operation limit")]
    InboxCapacityExceeded,
    #[error("local remote-event journal reached its pending-operation limit")]
    RemoteEventCapacityExceeded,
    #[error("another local adapter consumer owns the profile")]
    AdapterConsumerActive,
    #[error("local adapter lease is missing, expired, or stale")]
    InvalidAdapterLease,
}

fn validate_v2_outbound_migration(connection: &Connection) -> Result<(), ProfileStoreError> {
    let unrecoverable: i64 = connection
        .query_row(
            "SELECT count(*) FROM daemon_outbox WHERE status IN (2, 3)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    if unrecoverable == 0 {
        Ok(())
    } else {
        Err(ProfileStoreError::LegacyOutboundRecoveryUnsupported)
    }
}

fn initialize_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| ProfileStoreError::Storage)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| ProfileStoreError::Storage)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| ProfileStoreError::Storage)?;
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| ProfileStoreError::Storage)?;
    match version {
        PROFILE_SCHEMA_VERSION => return Ok(()),
        9 => return initialize_remote_event_schema(connection),
        8 => {
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        7 => {
            initialize_outbox_terminal_schema(connection)?;
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        6 => {
            initialize_replay_head_schema(connection)?;
            initialize_outbox_terminal_schema(connection)?;
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        5 => {
            initialize_pending_join_receipt_schema(connection)?;
            initialize_replay_head_schema(connection)?;
            initialize_outbox_terminal_schema(connection)?;
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        4 => {
            initialize_pending_join_schema(connection)?;
            initialize_pending_join_receipt_schema(connection)?;
            initialize_replay_head_schema(connection)?;
            initialize_outbox_terminal_schema(connection)?;
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        3 => {
            initialize_membership_outbox_schema(connection)?;
            initialize_pending_join_schema(connection)?;
            initialize_pending_join_receipt_schema(connection)?;
            initialize_replay_head_schema(connection)?;
            initialize_outbox_terminal_schema(connection)?;
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        2 => {
            initialize_message_history_schema(connection)?;
            initialize_membership_outbox_schema(connection)?;
            initialize_pending_join_schema(connection)?;
            initialize_pending_join_receipt_schema(connection)?;
            initialize_replay_head_schema(connection)?;
            initialize_outbox_terminal_schema(connection)?;
            initialize_outbox_removed_terminal_schema(connection)?;
            return initialize_remote_event_schema(connection);
        }
        0 => connection
            .execute_batch(
                "BEGIN;
             CREATE TABLE daemon_profile (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                profile_id TEXT NOT NULL UNIQUE,
                sealed_device_identity BLOB,
                relay_endpoint TEXT,
                sealed_relay_credential BLOB,
                CHECK (
                    (relay_endpoint IS NULL AND sealed_relay_credential IS NULL)
                    OR
                    (relay_endpoint IS NOT NULL AND sealed_relay_credential IS NOT NULL)
                )
             );
             CREATE TABLE daemon_conversation (
                conversation_id BLOB PRIMARY KEY CHECK (length(conversation_id) = 32),
                routing_id BLOB NOT NULL UNIQUE CHECK (length(routing_id) = 32),
                sealed_signing_material BLOB NOT NULL,
                sealed_policy_state BLOB NOT NULL,
                sender_counter INTEGER NOT NULL CHECK (sender_counter >= 0),
                replay_cursor INTEGER NOT NULL CHECK (replay_cursor >= 0)
             ) WITHOUT ROWID;
             CREATE TABLE daemon_conversation_binding (
                conversation_id BLOB NOT NULL,
                device_id BLOB NOT NULL CHECK (length(device_id) = 32),
                sealed_binding BLOB NOT NULL,
                PRIMARY KEY (conversation_id, device_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             PRAGMA user_version = 1;
             COMMIT;",
            )
            .map_err(|_| ProfileStoreError::Storage)?,
        1 => {}
        _ => return Err(ProfileStoreError::UnsupportedSchema),
    }
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_outbox (
                envelope_id BLOB PRIMARY KEY CHECK (length(envelope_id) = 16),
                conversation_id BLOB NOT NULL,
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                sender_counter INTEGER NOT NULL CHECK (sender_counter >= 1),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 4),
                sealed_envelope BLOB,
                accepted_cursor INTEGER,
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (conversation_id, message_id),
                UNIQUE (conversation_id, sender_counter),
                CHECK (
                    (status = 1 AND sealed_envelope IS NULL AND accepted_cursor IS NULL)
                    OR
                    (status = 2 AND sealed_envelope IS NOT NULL AND accepted_cursor IS NULL)
                    OR
                    (status = 3 AND sealed_envelope IS NOT NULL
                        AND accepted_cursor IS NOT NULL AND accepted_cursor >= 1)
                    OR
                    (status = 4 AND sealed_envelope IS NULL AND accepted_cursor IS NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_outbox_status_idx
                ON daemon_outbox(status, conversation_id, sender_counter);
             CREATE TABLE daemon_cursor_observation (
                conversation_id BLOB NOT NULL,
                cursor INTEGER NOT NULL CHECK (cursor >= 1),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                sealed_observation BLOB NOT NULL,
                PRIMARY KEY (conversation_id, cursor),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             CREATE TABLE daemon_inbox (
                conversation_id BLOB NOT NULL,
                cursor INTEGER NOT NULL CHECK (cursor >= 1),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 3),
                sealed_envelope BLOB NOT NULL,
                sender_device_id BLOB,
                sender_epoch INTEGER,
                message_id BLOB,
                sender_counter INTEGER,
                sealed_message BLOB,
                PRIMARY KEY (conversation_id, cursor),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (conversation_id, message_id),
                UNIQUE (
                    conversation_id,
                    sender_device_id,
                    sender_epoch,
                    sender_counter
                ),
                CHECK (
                    (status = 1
                        AND sender_device_id IS NULL
                        AND sender_epoch IS NULL
                        AND message_id IS NULL
                        AND sender_counter IS NULL
                        AND sealed_message IS NULL)
                    OR
                    (status BETWEEN 2 AND 3
                        AND sender_device_id IS NOT NULL
                        AND length(sender_device_id) = 32
                        AND sender_epoch IS NOT NULL
                        AND sender_epoch >= 0
                        AND message_id IS NOT NULL
                        AND length(message_id) = 16
                        AND sender_counter IS NOT NULL
                        AND sender_counter >= 1
                        AND sealed_message IS NOT NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_inbox_pending_idx
                ON daemon_inbox(conversation_id, cursor)
                WHERE status < 3;
             CREATE TABLE daemon_sender_counter (
                conversation_id BLOB NOT NULL,
                sender_device_id BLOB NOT NULL CHECK (length(sender_device_id) = 32),
                sender_epoch INTEGER NOT NULL CHECK (sender_epoch >= 0),
                highest_counter INTEGER NOT NULL CHECK (highest_counter >= 1),
                sealed_state BLOB NOT NULL,
                PRIMARY KEY (conversation_id, sender_device_id, sender_epoch),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             PRAGMA user_version = 2;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    initialize_message_history_schema(connection)?;
    initialize_membership_outbox_schema(connection)?;
    initialize_pending_join_schema(connection)?;
    initialize_pending_join_receipt_schema(connection)?;
    initialize_replay_head_schema(connection)?;
    initialize_outbox_terminal_schema(connection)?;
    initialize_outbox_removed_terminal_schema(connection)?;
    initialize_remote_event_schema(connection)
}

fn initialize_message_history_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_message_history (
                conversation_id BLOB NOT NULL,
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                cursor INTEGER,
                direction INTEGER NOT NULL CHECK (direction BETWEEN 1 AND 2),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 2),
                sender_device_id BLOB NOT NULL CHECK (length(sender_device_id) = 32),
                sender_epoch INTEGER NOT NULL CHECK (sender_epoch >= 0),
                sender_counter INTEGER NOT NULL CHECK (sender_counter >= 1),
                sealed_message BLOB NOT NULL,
                PRIMARY KEY (conversation_id, message_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (
                    conversation_id,
                    sender_device_id,
                    sender_epoch,
                    sender_counter
                ),
                CHECK (
                    (direction = 1 AND (cursor IS NULL OR cursor >= 1))
                    OR
                    (direction = 2 AND cursor IS NOT NULL AND cursor >= 1)
                ),
                CHECK (
                    (status = 1)
                    OR
                    (status = 2 AND cursor IS NOT NULL AND cursor >= 1)
                )
             ) WITHOUT ROWID;
             CREATE UNIQUE INDEX daemon_message_history_cursor_idx
                ON daemon_message_history(conversation_id, cursor)
                WHERE cursor IS NOT NULL;
             CREATE INDEX daemon_message_history_page_idx
                ON daemon_message_history(conversation_id, cursor)
                WHERE status = 2;
             PRAGMA user_version = 3;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initialize_membership_outbox_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_membership_outbox (
                operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
                conversation_id BLOB NOT NULL,
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                parent_epoch INTEGER NOT NULL CHECK (parent_epoch >= 0),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 4),
                sealed_operation BLOB NOT NULL,
                accepted_cursor INTEGER,
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                CHECK (
                    (status = 1 AND accepted_cursor IS NULL)
                    OR
                    (status BETWEEN 2 AND 3
                        AND accepted_cursor IS NOT NULL AND accepted_cursor >= 1)
                    OR
                    (status = 4 AND accepted_cursor IS NULL)
                )
             ) WITHOUT ROWID;
             CREATE UNIQUE INDEX daemon_membership_outbox_active_idx
                ON daemon_membership_outbox(conversation_id)
                WHERE status IN (1, 2);
             CREATE INDEX daemon_membership_outbox_status_idx
                ON daemon_membership_outbox(status, conversation_id, parent_epoch);
             CREATE TABLE daemon_membership_inbox (
                conversation_id BLOB NOT NULL,
                cursor INTEGER NOT NULL CHECK (cursor >= 1),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 3),
                sealed_envelope BLOB NOT NULL,
                sender_device_id BLOB,
                parent_epoch INTEGER,
                operation_id BLOB UNIQUE,
                sealed_transition BLOB,
                PRIMARY KEY (conversation_id, cursor),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                CHECK (
                    (status = 1
                        AND sender_device_id IS NULL
                        AND parent_epoch IS NULL
                        AND operation_id IS NULL
                        AND sealed_transition IS NULL)
                    OR
                    (status BETWEEN 2 AND 3
                        AND sender_device_id IS NOT NULL
                        AND length(sender_device_id) = 32
                        AND parent_epoch IS NOT NULL
                        AND parent_epoch >= 0
                        AND operation_id IS NOT NULL
                        AND length(operation_id) = 16
                        AND sealed_transition IS NOT NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_membership_inbox_pending_idx
                ON daemon_membership_inbox(conversation_id, cursor)
                WHERE status < 3;
             PRAGMA user_version = 4;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initialize_pending_join_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             ALTER TABLE daemon_membership_outbox ADD COLUMN change_kind INTEGER;
             ALTER TABLE daemon_membership_outbox ADD COLUMN subject_device_id BLOB;
             ALTER TABLE daemon_membership_outbox ADD COLUMN subject_invitation_id BLOB;
             ALTER TABLE daemon_membership_outbox ADD COLUMN subject_role INTEGER;
             CREATE UNIQUE INDEX daemon_membership_outbox_epoch_idx
                ON daemon_membership_outbox(conversation_id, parent_epoch);
             CREATE INDEX daemon_membership_outbox_request_idx
                ON daemon_membership_outbox(
                    conversation_id,
                    change_kind,
                    subject_device_id,
                    subject_invitation_id,
                    subject_role,
                    parent_epoch
                );
             CREATE TABLE daemon_pending_join (
                conversation_id BLOB PRIMARY KEY CHECK (length(conversation_id) = 32),
                routing_id BLOB NOT NULL UNIQUE CHECK (length(routing_id) = 32),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 3),
                verified_at_unix_seconds INTEGER NOT NULL
                    CHECK (verified_at_unix_seconds >= 1),
                sealed_signing_material BLOB NOT NULL,
                sealed_join BLOB NOT NULL,
                sealed_proof BLOB,
                sealed_state BLOB,
                CHECK (
                    (status = 1 AND sealed_proof IS NULL AND sealed_state IS NULL)
                    OR
                    (status = 2 AND sealed_proof IS NOT NULL AND sealed_state IS NULL)
                    OR
                    (status = 3 AND sealed_proof IS NOT NULL AND sealed_state IS NOT NULL)
                )
             ) WITHOUT ROWID;
             PRAGMA user_version = 5;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initialize_pending_join_receipt_schema(
    connection: &Connection,
) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             ALTER TABLE daemon_pending_join ADD COLUMN join_cursor INTEGER;
             ALTER TABLE daemon_pending_join ADD COLUMN join_envelope_id BLOB;
             ALTER TABLE daemon_pending_join ADD COLUMN sealed_join_receipt BLOB;
             PRAGMA user_version = 6;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initialize_replay_head_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             ALTER TABLE daemon_conversation ADD COLUMN sealed_replay_head BLOB;
             PRAGMA user_version = 7;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initialize_outbox_terminal_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             ALTER TABLE daemon_outbox
                ADD COLUMN terminal_reason INTEGER
                CHECK (
                    terminal_reason IS NULL
                    OR (status = 2 AND terminal_reason = 1)
                );
             PRAGMA user_version = 8;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initialize_outbox_removed_terminal_schema(
    connection: &Connection,
) -> Result<(), ProfileStoreError> {
    let result = connection.execute_batch(
        "BEGIN;
         ALTER TABLE daemon_outbox RENAME TO daemon_outbox_v8;
         CREATE TABLE daemon_outbox (
            envelope_id BLOB PRIMARY KEY CHECK (length(envelope_id) = 16),
            conversation_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK (length(message_id) = 16),
            sender_counter INTEGER NOT NULL CHECK (sender_counter >= 1),
            status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 4),
            sealed_envelope BLOB,
            accepted_cursor INTEGER,
            terminal_reason INTEGER,
            FOREIGN KEY (conversation_id)
                REFERENCES daemon_conversation(conversation_id)
                ON DELETE CASCADE,
            UNIQUE (conversation_id, message_id),
            UNIQUE (conversation_id, sender_counter),
            CHECK (
                (status = 1
                    AND sealed_envelope IS NULL
                    AND accepted_cursor IS NULL
                    AND terminal_reason IS NULL)
                OR
                (status = 2
                    AND sealed_envelope IS NOT NULL
                    AND accepted_cursor IS NULL
                    AND (terminal_reason IS NULL OR terminal_reason IN (1, 2)))
                OR
                (status = 3
                    AND sealed_envelope IS NOT NULL
                    AND accepted_cursor IS NOT NULL
                    AND accepted_cursor >= 1
                    AND terminal_reason IS NULL)
                OR
                (status = 4
                    AND sealed_envelope IS NULL
                    AND accepted_cursor IS NULL
                    AND terminal_reason IS NULL)
            )
         ) WITHOUT ROWID;
         INSERT INTO daemon_outbox (
            envelope_id,
            conversation_id,
            message_id,
            sender_counter,
            status,
            sealed_envelope,
            accepted_cursor,
            terminal_reason
         )
         SELECT
            envelope_id,
            conversation_id,
            message_id,
            sender_counter,
            status,
            sealed_envelope,
            accepted_cursor,
            terminal_reason
         FROM daemon_outbox_v8;
         DROP TABLE daemon_outbox_v8;
         CREATE INDEX daemon_outbox_status_idx
            ON daemon_outbox(status, conversation_id, sender_counter);
         PRAGMA user_version = 9;
         COMMIT;",
    );
    match result {
        Ok(()) => Ok(()),
        Err(_) => {
            connection
                .execute_batch("ROLLBACK;")
                .map_err(|_| ProfileStoreError::Storage)?;
            Err(ProfileStoreError::Storage)
        }
    }
}

fn initialize_remote_event_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             ALTER TABLE daemon_conversation
                ADD COLUMN sealed_adapter_delivery_policy BLOB;
             ALTER TABLE daemon_profile
                ADD COLUMN next_remote_event_sequence INTEGER NOT NULL DEFAULT 1
                CHECK (next_remote_event_sequence >= 1);
             ALTER TABLE daemon_profile
                ADD COLUMN sealed_remote_event_head BLOB;
             ALTER TABLE daemon_profile
                ADD COLUMN remote_event_floor_sequence INTEGER NOT NULL DEFAULT 0
                CHECK (remote_event_floor_sequence >= 0);
             ALTER TABLE daemon_profile
                ADD COLUMN sealed_remote_event_floor BLOB;
             CREATE TABLE daemon_remote_event (
                event_sequence INTEGER PRIMARY KEY AUTOINCREMENT
                    CHECK (event_sequence >= 1),
                notification_id BLOB NOT NULL UNIQUE
                    CHECK (length(notification_id) = 16),
                conversation_id BLOB NOT NULL,
                relay_cursor INTEGER NOT NULL CHECK (relay_cursor >= 1),
                event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 5),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 4),
                sender_device_id BLOB NOT NULL CHECK (length(sender_device_id) = 32),
                source_identifier BLOB NOT NULL CHECK (length(source_identifier) = 16),
                sealed_event BLOB NOT NULL,
                sealed_delivery_state BLOB NOT NULL,
                lease_consumer_id BLOB,
                lease_id BLOB,
                lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
                lease_expires_at_unix_milliseconds INTEGER,
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (conversation_id, relay_cursor),
                CHECK (
                    (status = 1
                        AND lease_consumer_id IS NULL
                        AND lease_id IS NULL
                        AND lease_expires_at_unix_milliseconds IS NULL)
                    OR
                    (status = 2
                        AND lease_consumer_id IS NOT NULL
                        AND length(lease_consumer_id) = 16
                        AND lease_id IS NOT NULL
                        AND length(lease_id) = 16
                        AND lease_generation >= 1
                        AND lease_expires_at_unix_milliseconds IS NOT NULL
                        AND lease_expires_at_unix_milliseconds >= 1)
                    OR
                    (status IN (3, 4)
                        AND lease_consumer_id IS NULL
                        AND lease_id IS NULL
                        AND lease_expires_at_unix_milliseconds IS NULL)
                )
             );
             CREATE INDEX daemon_remote_event_pending_idx
                ON daemon_remote_event(status, event_sequence)
                WHERE status = 1;
             CREATE INDEX daemon_remote_event_conversation_idx
                ON daemon_remote_event(conversation_id, status, event_sequence);
             CREATE TABLE daemon_adapter_consumer (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                consumer_id BLOB NOT NULL CHECK (length(consumer_id) = 16),
                lease_id BLOB NOT NULL CHECK (length(lease_id) = 16),
                lease_expires_at_unix_milliseconds INTEGER NOT NULL
                    CHECK (lease_expires_at_unix_milliseconds >= 1)
             );
             PRAGMA user_version = 10;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn validate_bindings(
    state: &ConversationState,
    self_binding: &DeviceCredentialBinding,
    bindings: &[DeviceCredentialBinding],
) -> Result<(), ProfileStoreError> {
    if bindings.is_empty() || bindings.len() > MAX_LOCAL_BINDINGS {
        return Err(ProfileStoreError::ConversationMismatch);
    }
    let mut device_ids = BTreeSet::new();
    for binding in bindings {
        if binding.conversation_id() != state.conversation_id()
            || !device_ids.insert(binding.device_id())
            || verify_device_credential_binding(binding).is_err()
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
    }
    if bindings
        .iter()
        .find(|binding| binding.device_id() == self_binding.device_id())
        != Some(self_binding)
        || !device_ids.contains(&self_binding.device_id())
        || state
            .members()
            .iter()
            .any(|member| !device_ids.contains(&member.device_id()))
    {
        return Err(ProfileStoreError::ConversationMismatch);
    }
    Ok(())
}

fn encode_remote_event_record(record: &RemoteEventRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 8
            + NotificationId::LENGTH
            + ConversationId::LENGTH
            + RoutingId::LENGTH
            + 8
            + 1
            + DeviceId::LENGTH
            + 16
            + 1
            + NotificationId::LENGTH,
    );
    bytes.push(REMOTE_EVENT_RECORD_VERSION);
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.extend_from_slice(record.notification_id.as_bytes());
    bytes.extend_from_slice(record.conversation_id.as_bytes());
    bytes.extend_from_slice(record.routing_id.as_bytes());
    bytes.extend_from_slice(&record.relay_cursor.to_be_bytes());
    bytes.push(record.kind as u8);
    bytes.extend_from_slice(record.sender.as_bytes());
    bytes.extend_from_slice(&record.source_identifier);
    match record.previous_notification_id {
        Some(previous) => {
            bytes.push(1);
            bytes.extend_from_slice(previous.as_bytes());
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; NotificationId::LENGTH]);
        }
    }
    bytes
}

fn encode_remote_event_head(head: &RemoteEventHead) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 8 + NotificationId::LENGTH);
    bytes.push(REMOTE_EVENT_HEAD_RECORD_VERSION);
    bytes.extend_from_slice(&head.sequence.to_be_bytes());
    bytes.extend_from_slice(head.notification_id.as_bytes());
    bytes
}

fn decode_remote_event_head(bytes: &[u8]) -> Result<RemoteEventHead, ProfileStoreError> {
    const NOTIFICATION_START: usize = 1 + 8;
    const RECORD_LENGTH: usize = NOTIFICATION_START + NotificationId::LENGTH;
    if bytes.len() != RECORD_LENGTH || bytes[0] != REMOTE_EVENT_HEAD_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(RemoteEventHead {
        sequence: decode_positive_u64(&bytes[1..NOTIFICATION_START])?,
        notification_id: NotificationId::from_slice(&bytes[NOTIFICATION_START..])
            .map_err(|_| ProfileStoreError::CorruptData)?,
    })
}

fn encode_remote_event_delivery_policy(enabled: bool) -> [u8; 2] {
    [
        REMOTE_EVENT_POLICY_RECORD_VERSION,
        if enabled { 1 } else { 0 },
    ]
}

fn decode_remote_event_delivery_policy(bytes: &[u8]) -> Result<bool, ProfileStoreError> {
    match bytes {
        [REMOTE_EVENT_POLICY_RECORD_VERSION, 0] => Ok(false),
        [REMOTE_EVENT_POLICY_RECORD_VERSION, 1] => Ok(true),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn decode_remote_event_record(
    conversation_id: ConversationId,
    bytes: &[u8],
) -> Result<RemoteEventRecord, ProfileStoreError> {
    const SEQUENCE_START: usize = 1;
    const NOTIFICATION_START: usize = SEQUENCE_START + 8;
    const CONVERSATION_START: usize = NOTIFICATION_START + NotificationId::LENGTH;
    const ROUTING_START: usize = CONVERSATION_START + ConversationId::LENGTH;
    const CURSOR_START: usize = ROUTING_START + RoutingId::LENGTH;
    const KIND_START: usize = CURSOR_START + 8;
    const SENDER_START: usize = KIND_START + 1;
    const SOURCE_START: usize = SENDER_START + DeviceId::LENGTH;
    const PREVIOUS_FLAG: usize = SOURCE_START + 16;
    const PREVIOUS_START: usize = PREVIOUS_FLAG + 1;
    const RECORD_LENGTH: usize = PREVIOUS_START + NotificationId::LENGTH;
    if bytes.len() != RECORD_LENGTH || bytes[0] != REMOTE_EVENT_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let stored_conversation = ConversationId::from_slice(&bytes[CONVERSATION_START..ROUTING_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    if stored_conversation != conversation_id {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(RemoteEventRecord {
        sequence: decode_u64(&bytes[SEQUENCE_START..NOTIFICATION_START])?,
        notification_id: NotificationId::from_slice(&bytes[NOTIFICATION_START..CONVERSATION_START])
            .map_err(|_| ProfileStoreError::CorruptData)?,
        conversation_id,
        routing_id: RoutingId::from_slice(&bytes[ROUTING_START..CURSOR_START])
            .map_err(|_| ProfileStoreError::CorruptData)?,
        relay_cursor: decode_positive_u64(&bytes[CURSOR_START..KIND_START])?,
        kind: remote_event_kind(i64::from(bytes[KIND_START]))?,
        sender: DeviceId::from_slice(&bytes[SENDER_START..SOURCE_START])
            .map_err(|_| ProfileStoreError::CorruptData)?,
        source_identifier: bytes[SOURCE_START..PREVIOUS_FLAG]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
        previous_notification_id: match bytes[PREVIOUS_FLAG] {
            0 if bytes[PREVIOUS_START..].iter().all(|byte| *byte == 0) => None,
            1 => Some(
                NotificationId::from_slice(&bytes[PREVIOUS_START..])
                    .map_err(|_| ProfileStoreError::CorruptData)?,
            ),
            _ => return Err(ProfileStoreError::CorruptData),
        },
    })
}

fn encode_remote_event_delivery_state(
    state: &RemoteEventDeliveryState,
) -> Result<Vec<u8>, ProfileStoreError> {
    let mut bytes = Vec::with_capacity(1 + 1 + 8 + 1 + 16 + 16 + 8);
    bytes.push(REMOTE_EVENT_RECORD_VERSION);
    bytes.push(state.status as u8);
    bytes.extend_from_slice(&state.lease_generation.to_be_bytes());
    match (
        state.consumer_id,
        state.lease_id,
        state.lease_expires_at_unix_milliseconds,
    ) {
        (None, None, None)
            if matches!(
                state.status,
                RemoteEventStatus::Pending
                    | RemoteEventStatus::Acknowledged
                    | RemoteEventStatus::Suppressed
            ) =>
        {
            bytes.push(0);
        }
        (Some(consumer_id), Some(lease_id), Some(expires_at))
            if state.status == RemoteEventStatus::Claimed
                && state.lease_generation >= 1
                && expires_at >= 1 =>
        {
            bytes.push(1);
            bytes.extend_from_slice(consumer_id.as_bytes());
            bytes.extend_from_slice(lease_id.as_bytes());
            bytes.extend_from_slice(&expires_at.to_be_bytes());
        }
        _ => return Err(ProfileStoreError::InvalidTransition),
    }
    Ok(bytes)
}

fn decode_remote_event_delivery_state(
    bytes: &[u8],
) -> Result<RemoteEventDeliveryState, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + 1 + 8 + 1;
    const CLAIMED_LENGTH: usize =
        HEADER_LENGTH + AdapterConsumerId::LENGTH + AdapterLeaseId::LENGTH + 8;
    if bytes.len() < HEADER_LENGTH || bytes[0] != REMOTE_EVENT_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let status = remote_event_status(i64::from(bytes[1]))?;
    let lease_generation = decode_u64(&bytes[2..10])?;
    match bytes[10] {
        0 if bytes.len() == HEADER_LENGTH
            && matches!(
                status,
                RemoteEventStatus::Pending
                    | RemoteEventStatus::Acknowledged
                    | RemoteEventStatus::Suppressed
            ) =>
        {
            Ok(RemoteEventDeliveryState {
                status,
                consumer_id: None,
                lease_id: None,
                lease_generation,
                lease_expires_at_unix_milliseconds: None,
            })
        }
        1 if bytes.len() == CLAIMED_LENGTH && status == RemoteEventStatus::Claimed => {
            let consumer_end = HEADER_LENGTH + AdapterConsumerId::LENGTH;
            let lease_end = consumer_end + AdapterLeaseId::LENGTH;
            let expires_at = decode_positive_u64(&bytes[lease_end..CLAIMED_LENGTH])?;
            if lease_generation == 0 {
                return Err(ProfileStoreError::CorruptData);
            }
            Ok(RemoteEventDeliveryState {
                status,
                consumer_id: Some(
                    AdapterConsumerId::from_slice(&bytes[HEADER_LENGTH..consumer_end])
                        .map_err(|_| ProfileStoreError::CorruptData)?,
                ),
                lease_id: Some(
                    AdapterLeaseId::from_slice(&bytes[consumer_end..lease_end])
                        .map_err(|_| ProfileStoreError::CorruptData)?,
                ),
                lease_generation,
                lease_expires_at_unix_milliseconds: Some(expires_at),
            })
        }
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn encode_outbox_record(
    reservation: OutboundReservation,
    envelope: &RelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + MessageId::LENGTH + 8 + envelope.len());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(reservation.message_id.as_bytes());
    record.extend_from_slice(&reservation.sender_counter.to_be_bytes());
    record.extend_from_slice(&envelope);
    Ok(record)
}

fn decode_outbox_record(
    conversation_id: ConversationId,
    envelope_id: EnvelopeId,
    record: &[u8],
) -> Result<OutboxRecord, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + MessageId::LENGTH + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let message_id = MessageId::from_slice(&record[1..1 + MessageId::LENGTH])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let sender_counter = decode_positive_u64(&record[1 + MessageId::LENGTH..HEADER_LENGTH])?;
    let envelope =
        decode_relay_envelope(&record[HEADER_LENGTH..]).map_err(|_| ProfileStoreError::Protocol)?;
    if envelope.envelope_id() != envelope_id {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(OutboxRecord {
        reservation: OutboundReservation {
            conversation_id,
            message_id,
            envelope_id,
            sender_counter,
        },
        envelope,
    })
}

fn encode_membership_outbox_record(
    operation_id: MembershipOperationId,
    parent_epoch: u64,
    envelope: &RelayEnvelope,
    control: &[u8],
    next_state: &ConversationState,
    bindings: &[DeviceCredentialBinding],
    welcome: Option<&[u8]>,
) -> Result<Vec<u8>, ProfileStoreError> {
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let (authorization, _) =
        decode_membership_control(control).map_err(|_| ProfileStoreError::Protocol)?;
    if authorization.operation_id() != operation_id
        || authorization.parent_epoch() != parent_epoch
        || authorization.conversation_id() != next_state.conversation_id()
    {
        return Err(ProfileStoreError::ConversationMismatch);
    }
    let state = encode_conversation_state(next_state).map_err(|_| ProfileStoreError::Protocol)?;
    let binding_count =
        u16::try_from(bindings.len()).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    let mut encoded_bindings = Vec::with_capacity(bindings.len());
    for binding in bindings {
        encoded_bindings.push(
            encode_device_credential_binding(binding).map_err(|_| ProfileStoreError::Protocol)?,
        );
    }
    let mut record = Vec::new();
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(operation_id.as_bytes());
    record.extend_from_slice(&parent_epoch.to_be_bytes());
    append_length_prefixed(&mut record, &envelope)?;
    append_length_prefixed(&mut record, control)?;
    append_length_prefixed(&mut record, &state)?;
    record.extend_from_slice(&binding_count.to_be_bytes());
    for binding in encoded_bindings {
        append_length_prefixed(&mut record, &binding)?;
    }
    match welcome {
        Some(welcome) => {
            record.push(1);
            append_length_prefixed(&mut record, welcome)?;
        }
        None => record.push(0),
    }
    if record.len() > MAX_SECRET_PLAINTEXT_BYTES {
        return Err(ProfileStoreError::OutboxCapacityExceeded);
    }
    Ok(record)
}

fn encode_replay_head(
    previous_cursor: u64,
    cursor: u64,
    kind: ReplayCompletionKind,
    completion_state: &ConversationState,
    policy_state: &ConversationState,
    envelope: &RelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    if cursor == 0 || previous_cursor >= cursor {
        return Err(ProfileStoreError::InvalidTransition);
    }
    if completion_state.conversation_id() != policy_state.conversation_id()
        || completion_state.version() != policy_state.version()
        || completion_state.epoch() > policy_state.epoch()
    {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let completion_state =
        encode_conversation_state(completion_state).map_err(|_| ProfileStoreError::Protocol)?;
    let policy_state =
        encode_conversation_state(policy_state).map_err(|_| ProfileStoreError::Protocol)?;
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::new();
    record.push(REPLAY_HEAD_VERSION_V2);
    record.extend_from_slice(&previous_cursor.to_be_bytes());
    record.extend_from_slice(&cursor.to_be_bytes());
    record.push(kind as u8);
    append_length_prefixed(&mut record, &completion_state)?;
    append_length_prefixed(&mut record, &policy_state)?;
    append_length_prefixed(&mut record, &envelope)?;
    Ok(record)
}

#[cfg(test)]
fn encode_replay_head_v1(
    previous_cursor: u64,
    cursor: u64,
    kind: ReplayCompletionKind,
    state: &ConversationState,
    envelope: &RelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    if cursor == 0 || previous_cursor >= cursor {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let state = encode_conversation_state(state).map_err(|_| ProfileStoreError::Protocol)?;
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::new();
    record.push(REPLAY_HEAD_VERSION_V1);
    record.extend_from_slice(&previous_cursor.to_be_bytes());
    record.extend_from_slice(&cursor.to_be_bytes());
    record.push(kind as u8);
    append_length_prefixed(&mut record, &state)?;
    append_length_prefixed(&mut record, &envelope)?;
    Ok(record)
}

fn decode_replay_head(record: &[u8]) -> Result<ReplayHead, ProfileStoreError> {
    const PREVIOUS_START: usize = 1;
    const CURSOR_START: usize = PREVIOUS_START + 8;
    const KIND_INDEX: usize = CURSOR_START + 8;
    const HEADER_LENGTH: usize = KIND_INDEX + 1;
    if record.len() <= HEADER_LENGTH
        || !matches!(record[0], REPLAY_HEAD_VERSION_V1 | REPLAY_HEAD_VERSION_V2)
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let version = match record[0] {
        REPLAY_HEAD_VERSION_V1 => ReplayHeadVersion::V1,
        REPLAY_HEAD_VERSION_V2 => ReplayHeadVersion::V2,
        _ => return Err(ProfileStoreError::CorruptData),
    };
    let previous_cursor = decode_u64(&record[PREVIOUS_START..CURSOR_START])?;
    let cursor = decode_positive_u64(&record[CURSOR_START..KIND_INDEX])?;
    if previous_cursor >= cursor {
        return Err(ProfileStoreError::CorruptData);
    }
    let kind = match record[KIND_INDEX] {
        1 => ReplayCompletionKind::Application,
        2 => ReplayCompletionKind::Membership,
        3 => ReplayCompletionKind::Join,
        _ => return Err(ProfileStoreError::CorruptData),
    };
    let mut remaining = &record[HEADER_LENGTH..];
    let completion_state = decode_conversation_state(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    let policy_state = if version == ReplayHeadVersion::V2 {
        decode_conversation_state(take_length_prefixed(&mut remaining)?)
            .map_err(|_| ProfileStoreError::Protocol)?
    } else {
        completion_state.clone()
    };
    let envelope = decode_relay_envelope(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    if !remaining.is_empty()
        || completion_state.conversation_id() != policy_state.conversation_id()
        || completion_state.version() != policy_state.version()
        || completion_state.epoch() > policy_state.epoch()
    {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(ReplayHead {
        version,
        previous_cursor,
        cursor,
        kind,
        completion_state,
        policy_state,
        envelope,
    })
}

fn membership_request_metadata(
    control: &[u8],
) -> Result<MembershipRequestMetadata, ProfileStoreError> {
    let (authorization, _) =
        decode_membership_control(control).map_err(|_| ProfileStoreError::Protocol)?;
    Ok(match authorization.change() {
        MembershipChange::Add(add) => MembershipRequestMetadata {
            kind: 1,
            device_id: add.device_id(),
            invitation_id: Some(add.invitation_id()),
            role: Some(conversation_role_value(add.role())),
        },
        MembershipChange::Remove(remove) => MembershipRequestMetadata {
            kind: 2,
            device_id: remove.device_id(),
            invitation_id: None,
            role: None,
        },
        MembershipChange::ChangeRole(change) => MembershipRequestMetadata {
            kind: 3,
            device_id: change.device_id(),
            invitation_id: None,
            role: Some(conversation_role_value(change.role())),
        },
    })
}

const fn conversation_role_value(role: KonclaveDomainCore::ConversationRole) -> i64 {
    match role {
        KonclaveDomainCore::ConversationRole::Administrator => 1,
        KonclaveDomainCore::ConversationRole::Member => 2,
    }
}

fn encode_pending_join_checkpoint(
    state: &ConversationState,
    expected_commit_envelope_id: EnvelopeId,
) -> Result<Vec<u8>, ProfileStoreError> {
    let state = encode_conversation_state(state).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + EnvelopeId::LENGTH + 2 + state.len());
    record.push(PENDING_JOIN_CHECKPOINT_VERSION);
    record.extend_from_slice(expected_commit_envelope_id.as_bytes());
    append_length_prefixed(&mut record, &state)?;
    Ok(record)
}

fn decode_pending_join_checkpoint(
    record: &[u8],
) -> Result<(ConversationState, EnvelopeId), ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + EnvelopeId::LENGTH;
    if record.len() <= HEADER_LENGTH || record[0] != PENDING_JOIN_CHECKPOINT_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let expected_commit_envelope_id = EnvelopeId::from_slice(&record[1..HEADER_LENGTH])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let mut remaining = &record[HEADER_LENGTH..];
    let state = decode_conversation_state(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    if !remaining.is_empty() {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok((state, expected_commit_envelope_id))
}

fn encode_pending_join_record(
    invitation: &Invitation,
    issuer_public_key: Ed25519PublicKey,
    peer_bindings: &[DeviceCredentialBinding],
) -> Result<Vec<u8>, ProfileStoreError> {
    let invitation = encode_invitation(invitation).map_err(|_| ProfileStoreError::Protocol)?;
    let binding_count =
        u16::try_from(peer_bindings.len()).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    let mut record = Vec::new();
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(issuer_public_key.as_bytes());
    append_length_prefixed(&mut record, &invitation)?;
    record.extend_from_slice(&binding_count.to_be_bytes());
    for binding in peer_bindings {
        let binding =
            encode_device_credential_binding(binding).map_err(|_| ProfileStoreError::Protocol)?;
        append_length_prefixed(&mut record, &binding)?;
    }
    if record.len() > MAX_SECRET_PLAINTEXT_BYTES {
        return Err(ProfileStoreError::OutboxCapacityExceeded);
    }
    Ok(record)
}

fn decode_pending_join_record(
    conversation_id: ConversationId,
    record: &[u8],
) -> Result<
    (
        Invitation,
        Ed25519PublicKey,
        Vec<VerifiedDeviceCredentialBinding>,
    ),
    ProfileStoreError,
> {
    const HEADER_LENGTH: usize = 1 + Ed25519PublicKey::LENGTH;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let issuer_public_key = Ed25519PublicKey::from_slice(&record[1..HEADER_LENGTH])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let mut remaining = &record[HEADER_LENGTH..];
    let invitation = decode_invitation(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    let binding_count = usize::from(take_u16(&mut remaining)?);
    if binding_count == 0 || binding_count > MAX_MEMBERS {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut peer_bindings = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let binding = decode_device_credential_binding(take_length_prefixed(&mut remaining)?)
            .map_err(|_| ProfileStoreError::Protocol)?;
        peer_bindings.push(
            verify_device_credential_binding(&binding)
                .map_err(|_| ProfileStoreError::Cryptographic)?,
        );
    }
    if !remaining.is_empty()
        || invitation.conversation_id() != conversation_id
        || !peer_bindings.iter().any(|binding| {
            binding.binding().device_id() == invitation.issuer_device_id()
                && binding.binding().device_root_public_key() == issuer_public_key
        })
    {
        return Err(ProfileStoreError::ConversationMismatch);
    }
    Ok((invitation, issuer_public_key, peer_bindings))
}

fn decode_membership_outbox_record(
    conversation_id: ConversationId,
    operation_id: MembershipOperationId,
    record: &[u8],
) -> Result<MembershipOutboxRecord, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + MembershipOperationId::LENGTH + 8;
    if record.len() <= HEADER_LENGTH
        || record[0] != LOCAL_RECORD_VERSION
        || record[1..1 + MembershipOperationId::LENGTH] != operation_id.as_bytes()[..]
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let parent_epoch = decode_u64(&record[1 + MembershipOperationId::LENGTH..HEADER_LENGTH])?;
    let mut remaining = &record[HEADER_LENGTH..];
    let envelope = decode_relay_envelope(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    let control = Zeroizing::new(take_length_prefixed(&mut remaining)?.to_vec());
    let (authorization, _) =
        decode_membership_control(&control).map_err(|_| ProfileStoreError::Protocol)?;
    let next_state = decode_conversation_state(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    let binding_count = usize::from(take_u16(&mut remaining)?);
    if binding_count == 0 || binding_count > MAX_LOCAL_BINDINGS {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut bindings = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let binding = decode_device_credential_binding(take_length_prefixed(&mut remaining)?)
            .map_err(|_| ProfileStoreError::Protocol)?;
        bindings.push(
            verify_device_credential_binding(&binding)
                .map_err(|_| ProfileStoreError::Cryptographic)?,
        );
    }
    let welcome = match take_byte(&mut remaining)? {
        0 => None,
        1 => Some(take_length_prefixed(&mut remaining)?.to_vec()),
        _ => return Err(ProfileStoreError::CorruptData),
    };
    if !remaining.is_empty()
        || next_state.conversation_id() != conversation_id
        || parent_epoch.checked_add(1) != Some(next_state.epoch())
        || authorization.conversation_id() != conversation_id
        || authorization.parent_epoch() != parent_epoch
        || authorization.operation_id() != operation_id
        || envelope.delivery_class() != DeliveryClass::GroupCommit
        || envelope.expected_parent_epoch() != Some(parent_epoch)
    {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(MembershipOutboxRecord {
        parent_epoch,
        envelope,
        control,
        next_state,
        bindings,
        welcome,
    })
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProfileStoreError> {
    let length = u32::try_from(value.len()).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn take_length_prefixed<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], ProfileStoreError> {
    if input.len() < 4 {
        return Err(ProfileStoreError::CorruptData);
    }
    let length = u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    *input = &input[4..];
    let length = usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)?;
    if input.len() < length {
        return Err(ProfileStoreError::CorruptData);
    }
    let (value, remaining) = input.split_at(length);
    *input = remaining;
    Ok(value)
}

fn take_u16(input: &mut &[u8]) -> Result<u16, ProfileStoreError> {
    if input.len() < 2 {
        return Err(ProfileStoreError::CorruptData);
    }
    let value = u16::from_be_bytes(
        input[..2]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    *input = &input[2..];
    Ok(value)
}

fn take_byte(input: &mut &[u8]) -> Result<u8, ProfileStoreError> {
    let value = input
        .first()
        .copied()
        .ok_or(ProfileStoreError::CorruptData)?;
    *input = &input[1..];
    Ok(value)
}

fn terminalize_removed_outbox_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    conversation_id: ConversationId,
) -> Result<usize, ProfileStoreError> {
    transaction
        .execute(
            "UPDATE daemon_outbox
             SET terminal_reason = ?1
             WHERE conversation_id = ?2
               AND status = 2
               AND terminal_reason IS NULL",
            params![
                OUTBOX_TERMINAL_REASON_REMOVED,
                conversation_id.as_bytes().as_slice()
            ],
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn membership_outbox_status(value: i64) -> Result<MembershipOutboxStatus, ProfileStoreError> {
    match value {
        1 => Ok(MembershipOutboxStatus::Ready),
        2 => Ok(MembershipOutboxStatus::Accepted),
        3 => Ok(MembershipOutboxStatus::Applied),
        4 => Ok(MembershipOutboxStatus::Orphaned),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboxTerminalReason {
    Expired,
    Removed,
}

fn outbox_terminal_reason(
    value: Option<i64>,
) -> Result<Option<OutboxTerminalReason>, ProfileStoreError> {
    match value {
        None => Ok(None),
        Some(OUTBOX_TERMINAL_REASON_EXPIRED) => Ok(Some(OutboxTerminalReason::Expired)),
        Some(OUTBOX_TERMINAL_REASON_REMOVED) => Ok(Some(OutboxTerminalReason::Removed)),
        Some(_) => Err(ProfileStoreError::CorruptData),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the authenticated membership journal fields remain explicit"
)]
fn membership_outbox_matches(
    existing: &MembershipOutbox,
    conversation_id: ConversationId,
    parent_epoch: u64,
    envelope: &RelayEnvelope,
    control: &[u8],
    next_state: &ConversationState,
    bindings: &[DeviceCredentialBinding],
    welcome: Option<&[u8]>,
) -> Result<bool, ProfileStoreError> {
    let same_bindings = existing.bindings.len() == bindings.len()
        && existing.bindings.iter().all(|existing| {
            bindings
                .iter()
                .any(|expected| expected == existing.binding())
        });
    Ok(existing.conversation_id == conversation_id
        && existing.parent_epoch == parent_epoch
        && existing.envelope == *envelope
        && existing.control.as_slice() == control
        && existing.next_state == *next_state
        && same_bindings
        && existing.welcome.as_deref() == welcome)
}

fn final_membership_bindings(
    record: &MembershipOutbox,
    self_device_id: DeviceId,
) -> Vec<&VerifiedDeviceCredentialBinding> {
    record
        .bindings
        .iter()
        .filter(|binding| {
            let device_id = binding.binding().device_id();
            device_id == self_device_id || record.next_state.member(device_id).is_some()
        })
        .collect()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the authenticated membership checkpoint fields remain explicit"
)]
fn encode_membership_inbox_transition(
    cursor: u64,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    parent_epoch: u64,
    operation_id: MembershipOperationId,
    control: &[u8],
    next_state: &ConversationState,
    bindings: &[DeviceCredentialBinding],
) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
    if cursor == 0 || control.is_empty() {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let state = encode_conversation_state(next_state).map_err(|_| ProfileStoreError::Protocol)?;
    let binding_count =
        u16::try_from(bindings.len()).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    let mut record = Zeroizing::new(Vec::new());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&cursor.to_be_bytes());
    record.extend_from_slice(envelope_id.as_bytes());
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&parent_epoch.to_be_bytes());
    record.extend_from_slice(operation_id.as_bytes());
    append_length_prefixed(&mut record, control)?;
    append_length_prefixed(&mut record, &state)?;
    record.extend_from_slice(&binding_count.to_be_bytes());
    for binding in bindings {
        let binding =
            encode_device_credential_binding(binding).map_err(|_| ProfileStoreError::Protocol)?;
        append_length_prefixed(&mut record, &binding)?;
    }
    if record.len() > MAX_SECRET_PLAINTEXT_BYTES {
        return Err(ProfileStoreError::InboxCapacityExceeded);
    }
    Ok(record)
}

fn decode_membership_inbox_transition(
    conversation_id: ConversationId,
    cursor: u64,
    envelope_id: EnvelopeId,
    record: &[u8],
) -> Result<MembershipInboxTransitionRecord, ProfileStoreError> {
    const CURSOR_START: usize = 1;
    const ENVELOPE_START: usize = CURSOR_START + 8;
    const SENDER_START: usize = ENVELOPE_START + EnvelopeId::LENGTH;
    const EPOCH_START: usize = SENDER_START + DeviceId::LENGTH;
    const OPERATION_START: usize = EPOCH_START + 8;
    const HEADER_LENGTH: usize = OPERATION_START + MembershipOperationId::LENGTH;
    if record.len() <= HEADER_LENGTH
        || record[0] != LOCAL_RECORD_VERSION
        || decode_positive_u64(&record[CURSOR_START..ENVELOPE_START])? != cursor
        || EnvelopeId::from_slice(&record[ENVELOPE_START..SENDER_START])
            .map_err(|_| ProfileStoreError::CorruptData)?
            != envelope_id
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let sender = DeviceId::from_slice(&record[SENDER_START..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let parent_epoch = decode_u64(&record[EPOCH_START..OPERATION_START])?;
    let operation_id = MembershipOperationId::from_slice(&record[OPERATION_START..HEADER_LENGTH])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let mut remaining = &record[HEADER_LENGTH..];
    let control = Zeroizing::new(take_length_prefixed(&mut remaining)?.to_vec());
    let (authorization, _) =
        decode_membership_control(&control).map_err(|_| ProfileStoreError::Protocol)?;
    let next_state = decode_conversation_state(take_length_prefixed(&mut remaining)?)
        .map_err(|_| ProfileStoreError::Protocol)?;
    let binding_count = usize::from(take_u16(&mut remaining)?);
    if binding_count == 0 || binding_count > MAX_LOCAL_BINDINGS {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut bindings = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let binding = decode_device_credential_binding(take_length_prefixed(&mut remaining)?)
            .map_err(|_| ProfileStoreError::Protocol)?;
        bindings.push(
            verify_device_credential_binding(&binding)
                .map_err(|_| ProfileStoreError::Cryptographic)?,
        );
    }
    if !remaining.is_empty()
        || authorization.conversation_id() != conversation_id
        || authorization.parent_epoch() != parent_epoch
        || authorization.operation_id() != operation_id
        || next_state.conversation_id() != conversation_id
        || parent_epoch.checked_add(1) != Some(next_state.epoch())
    {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(MembershipInboxTransitionRecord {
        sender,
        parent_epoch,
        operation_id,
        control,
        next_state,
        bindings,
    })
}

fn same_verified_bindings(
    existing: &[VerifiedDeviceCredentialBinding],
    expected: &[DeviceCredentialBinding],
) -> bool {
    existing.len() == expected.len()
        && existing.iter().all(|existing| {
            expected
                .iter()
                .any(|expected| expected == existing.binding())
        })
}

fn final_transition_bindings(
    transition: &StoredMembershipTransition,
    self_device_id: DeviceId,
) -> Vec<&VerifiedDeviceCredentialBinding> {
    transition
        .bindings
        .iter()
        .filter(|binding| {
            let device_id = binding.binding().device_id();
            device_id == self_device_id || transition.next_state.member(device_id).is_some()
        })
        .collect()
}

fn encode_cursor_observation(
    cursor: u64,
    envelope: &RelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    if cursor == 0 {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + 8 + envelope.len());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&cursor.to_be_bytes());
    record.extend_from_slice(&envelope);
    Ok(record)
}

fn decode_cursor_observation(record: &[u8]) -> Result<StoredRelayEnvelope, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let cursor = decode_positive_u64(&record[1..9])?;
    let envelope =
        decode_relay_envelope(&record[HEADER_LENGTH..]).map_err(|_| ProfileStoreError::Protocol)?;
    StoredRelayEnvelope::new(envelope, cursor).map_err(|_| ProfileStoreError::CorruptData)
}

fn encode_sender_counter_state(
    sender: DeviceId,
    epoch: u64,
    highest_counter: u64,
) -> Result<Vec<u8>, ProfileStoreError> {
    if highest_counter == 0 {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut record = Vec::with_capacity(1 + DeviceId::LENGTH + 8 + 8);
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&epoch.to_be_bytes());
    record.extend_from_slice(&highest_counter.to_be_bytes());
    Ok(record)
}

fn decode_sender_counter_state(record: &[u8]) -> Result<(DeviceId, u64, u64), ProfileStoreError> {
    const EPOCH_START: usize = 1 + DeviceId::LENGTH;
    const COUNTER_START: usize = EPOCH_START + 8;
    const RECORD_LENGTH: usize = COUNTER_START + 8;
    if record.len() != RECORD_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let sender = DeviceId::from_slice(&record[1..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let epoch = u64::from_be_bytes(
        record[EPOCH_START..COUNTER_START]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let highest_counter = decode_positive_u64(&record[COUNTER_START..])?;
    Ok((sender, epoch, highest_counter))
}

fn encode_inbox_envelope_record(
    stored: &StoredRelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    let envelope =
        encode_relay_envelope(stored.envelope()).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + 8 + envelope.len());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&stored.cursor().to_be_bytes());
    record.extend_from_slice(&envelope);
    Ok(record)
}

fn decode_inbox_envelope_record(record: &[u8]) -> Result<StoredRelayEnvelope, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let cursor = decode_positive_u64(&record[1..HEADER_LENGTH])?;
    let envelope =
        decode_relay_envelope(&record[HEADER_LENGTH..]).map_err(|_| ProfileStoreError::Protocol)?;
    StoredRelayEnvelope::new(envelope, cursor).map_err(|_| ProfileStoreError::CorruptData)
}

fn encode_inbox_message_record(
    cursor: u64,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    sender_epoch: u64,
    message: &ApplicationMessage,
) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
    if cursor == 0 {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let message = Zeroizing::new(
        encode_application_message(message).map_err(|_| ProfileStoreError::Protocol)?,
    );
    let mut record = Zeroizing::new(Vec::with_capacity(
        1 + 8 + EnvelopeId::LENGTH + DeviceId::LENGTH + 8 + message.len(),
    ));
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&cursor.to_be_bytes());
    record.extend_from_slice(envelope_id.as_bytes());
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&sender_epoch.to_be_bytes());
    record.extend_from_slice(&message);
    Ok(record)
}

fn decode_inbox_message_record(
    record: &[u8],
) -> Result<StoredApplicationMessage, ProfileStoreError> {
    const ENVELOPE_ID_START: usize = 1 + 8;
    const SENDER_START: usize = ENVELOPE_ID_START + EnvelopeId::LENGTH;
    const EPOCH_START: usize = SENDER_START + DeviceId::LENGTH;
    const HEADER_LENGTH: usize = EPOCH_START + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let cursor = decode_positive_u64(&record[1..9])?;
    let envelope_id = EnvelopeId::from_slice(&record[ENVELOPE_ID_START..SENDER_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let sender = DeviceId::from_slice(&record[SENDER_START..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let epoch = u64::from_be_bytes(
        record[EPOCH_START..HEADER_LENGTH]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let message = decode_application_message(&record[HEADER_LENGTH..])
        .map_err(|_| ProfileStoreError::Protocol)?;
    Ok(StoredApplicationMessage {
        cursor,
        envelope_id,
        sender,
        epoch,
        message,
    })
}

fn encode_history_message_record(
    direction: MessageDirection,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    epoch: u64,
    message: &ApplicationMessage,
) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
    let message = Zeroizing::new(
        encode_application_message(message).map_err(|_| ProfileStoreError::Protocol)?,
    );
    let mut record = Zeroizing::new(Vec::with_capacity(
        2 + EnvelopeId::LENGTH + DeviceId::LENGTH + 8 + message.len(),
    ));
    record.push(LOCAL_RECORD_VERSION);
    record.push(direction as u8);
    record.extend_from_slice(envelope_id.as_bytes());
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&epoch.to_be_bytes());
    record.extend_from_slice(&message);
    Ok(record)
}

fn decode_history_message_record(
    record: &[u8],
) -> Result<
    (
        MessageDirection,
        EnvelopeId,
        DeviceId,
        u64,
        ApplicationMessage,
    ),
    ProfileStoreError,
> {
    const ENVELOPE_START: usize = 2;
    const SENDER_START: usize = ENVELOPE_START + EnvelopeId::LENGTH;
    const EPOCH_START: usize = SENDER_START + DeviceId::LENGTH;
    const HEADER_LENGTH: usize = EPOCH_START + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let direction = match record[1] {
        1 => MessageDirection::Outbound,
        2 => MessageDirection::Inbound,
        _ => return Err(ProfileStoreError::CorruptData),
    };
    let envelope_id = EnvelopeId::from_slice(&record[ENVELOPE_START..SENDER_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let sender = DeviceId::from_slice(&record[SENDER_START..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let epoch = u64::from_be_bytes(
        record[EPOCH_START..HEADER_LENGTH]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let message = decode_application_message(&record[HEADER_LENGTH..])
        .map_err(|_| ProfileStoreError::Protocol)?;
    Ok((direction, envelope_id, sender, epoch, message))
}

fn decode_positive_u64(bytes: &[u8]) -> Result<u64, ProfileStoreError> {
    let value = decode_u64(bytes)?;
    if value == 0 {
        Err(ProfileStoreError::CorruptData)
    } else {
        Ok(value)
    }
}

fn decode_u64(bytes: &[u8]) -> Result<u64, ProfileStoreError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| ProfileStoreError::CorruptData)
}

fn application_messages_equal(
    left: &ApplicationMessage,
    right: &ApplicationMessage,
) -> Result<bool, ProfileStoreError> {
    let left =
        Zeroizing::new(encode_application_message(left).map_err(|_| ProfileStoreError::Protocol)?);
    let right =
        Zeroizing::new(encode_application_message(right).map_err(|_| ProfileStoreError::Protocol)?);
    Ok(left == right)
}

fn stored_history_message(history: HistoryRecord) -> Option<StoredHistoryMessage> {
    if !history.complete {
        return None;
    }
    Some(StoredHistoryMessage {
        cursor: history.cursor?,
        direction: history.direction,
        envelope_id: history.envelope_id,
        sender: history.sender,
        epoch: history.epoch,
        message: history.message,
    })
}

fn conversation_record_context(
    profile_id: &ProfileId,
    kind: SecretRecordKind,
    conversation_id: ConversationId,
    routing_id: Option<RoutingId>,
    device_id: Option<DeviceId>,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(
        1 + profile_id.as_bytes().len()
            + ConversationId::LENGTH
            + routing_id.map_or(0, |_| RoutingId::LENGTH)
            + device_id.map_or(0, |_| DeviceId::LENGTH),
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.extend_from_slice(conversation_id.as_bytes());
    if let Some(routing_id) = routing_id {
        identifier.extend_from_slice(routing_id.as_bytes());
    }
    if let Some(device_id) = device_id {
        identifier.extend_from_slice(device_id.as_bytes());
    }
    SecretRecordContext::new(kind, identifier).map_err(|_| ProfileStoreError::Storage)
}

fn operation_record_context(
    profile_id: &ProfileId,
    kind: SecretRecordKind,
    conversation_id: ConversationId,
    routing_id: RoutingId,
    scope: u8,
    record_id: &[u8],
) -> Result<SecretRecordContext, ProfileStoreError> {
    if scope == 0 || !matches!(record_id.len(), EnvelopeId::LENGTH | ConversationId::LENGTH) {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut identifier = Vec::with_capacity(
        2 + profile_id.as_bytes().len()
            + ConversationId::LENGTH
            + RoutingId::LENGTH
            + record_id.len(),
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.extend_from_slice(conversation_id.as_bytes());
    identifier.extend_from_slice(routing_id.as_bytes());
    identifier.push(scope);
    identifier.extend_from_slice(record_id);
    SecretRecordContext::new(kind, identifier).map_err(|_| ProfileStoreError::Storage)
}

fn remote_event_head_record_context(
    profile_id: &ProfileId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(2 + profile_id.as_bytes().len());
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.push(REMOTE_EVENT_HEAD_RECORD_SCOPE);
    SecretRecordContext::new(SecretRecordKind::RemoteEventJournalHead, identifier)
        .map_err(|_| ProfileStoreError::Storage)
}

fn remote_event_floor_record_context(
    profile_id: &ProfileId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(2 + profile_id.as_bytes().len());
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.push(REMOTE_EVENT_FLOOR_RECORD_SCOPE);
    SecretRecordContext::new(SecretRecordKind::RemoteEventJournalHead, identifier)
        .map_err(|_| ProfileStoreError::Storage)
}

fn sender_counter_record_context(
    profile_id: &ProfileId,
    conversation_id: ConversationId,
    sender: DeviceId,
    epoch: u64,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(
        2 + profile_id.as_bytes().len() + ConversationId::LENGTH + DeviceId::LENGTH + 8,
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.extend_from_slice(conversation_id.as_bytes());
    identifier.push(SENDER_COUNTER_RECORD_SCOPE);
    identifier.extend_from_slice(sender.as_bytes());
    identifier.extend_from_slice(&epoch.to_be_bytes());
    SecretRecordContext::new(SecretRecordKind::LocalOperation, identifier)
        .map_err(|_| ProfileStoreError::Storage)
}

fn remote_event_kind(value: i64) -> Result<RemoteEventKind, ProfileStoreError> {
    match value {
        1 => Ok(RemoteEventKind::ApplicationMessage),
        2 => Ok(RemoteEventKind::MemberAdded),
        3 => Ok(RemoteEventKind::MemberRemoved),
        4 => Ok(RemoteEventKind::MemberRoleChanged),
        5 => Ok(RemoteEventKind::LocalAccessRemoved),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn remote_event_status(value: i64) -> Result<RemoteEventStatus, ProfileStoreError> {
    match value {
        1 => Ok(RemoteEventStatus::Pending),
        2 => Ok(RemoteEventStatus::Claimed),
        3 => Ok(RemoteEventStatus::Acknowledged),
        4 => Ok(RemoteEventStatus::Suppressed),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn validate_adapter_lease_window(
    now_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
) -> Result<(), ProfileStoreError> {
    if expires_at_unix_milliseconds <= now_unix_milliseconds
        || expires_at_unix_milliseconds
            .checked_sub(now_unix_milliseconds)
            .is_none_or(|duration| duration > MAX_ADAPTER_LEASE_MILLISECONDS)
    {
        return Err(ProfileStoreError::InvalidAdapterLease);
    }
    Ok(())
}

/// Confirms the caller still holds the live consumer lease and extends it.
///
/// An expired lease is never renewed and a different consumer is never admitted, so
/// renewal cannot take back a lease that expiry has already made available.
fn renew_active_adapter_lease(
    connection: &Connection,
    consumer_id: AdapterConsumerId,
    lease_id: AdapterLeaseId,
    now_unix_milliseconds: u64,
    requested_expiry: u64,
) -> Result<(), ProfileStoreError> {
    validate_adapter_lease_window(now_unix_milliseconds, requested_expiry)?;
    let active: Option<(Vec<u8>, Vec<u8>, i64)> = connection
        .query_row(
            "SELECT
                CASE WHEN length(consumer_id) = 16 THEN consumer_id END,
                CASE WHEN length(lease_id) = 16 THEN lease_id END,
                lease_expires_at_unix_milliseconds
             FROM daemon_adapter_consumer
             WHERE singleton_id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| ProfileStoreError::Storage)?;
    let (active_consumer, active_lease, active_expiry) =
        active.ok_or(ProfileStoreError::InvalidAdapterLease)?;
    if active_consumer.as_slice() != consumer_id.as_bytes()
        || active_lease.as_slice() != lease_id.as_bytes()
        || from_sql_integer(active_expiry)? <= now_unix_milliseconds
    {
        return Err(ProfileStoreError::InvalidAdapterLease);
    }
    if requested_expiry > from_sql_integer(active_expiry)? {
        connection
            .execute(
                "UPDATE daemon_adapter_consumer
                 SET lease_expires_at_unix_milliseconds = ?1
                 WHERE singleton_id = 1 AND consumer_id = ?2 AND lease_id = ?3",
                params![
                    to_sql_integer(requested_expiry)?,
                    consumer_id.as_bytes().as_slice(),
                    lease_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
    }
    Ok(())
}

fn verify_active_adapter_consumer_now(
    connection: &Connection,
    consumer_id: AdapterConsumerId,
    lease_id: AdapterLeaseId,
    now_unix_milliseconds: u64,
) -> Result<(), ProfileStoreError> {
    let active_expiry: Option<i64> = connection
        .query_row(
            "SELECT lease_expires_at_unix_milliseconds
             FROM daemon_adapter_consumer
             WHERE singleton_id = 1 AND consumer_id = ?1 AND lease_id = ?2",
            params![
                consumer_id.as_bytes().as_slice(),
                lease_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ProfileStoreError::Storage)?;
    if active_expiry
        .map(from_sql_integer)
        .transpose()?
        .is_none_or(|expiry| expiry <= now_unix_milliseconds)
    {
        return Err(ProfileStoreError::InvalidAdapterLease);
    }
    Ok(())
}

fn validate_blob_length(length: i64) -> Result<(), ProfileStoreError> {
    if length <= 0
        || usize::try_from(length)
            .ok()
            .is_none_or(|length| length > MAX_SEALED_RECORD_BYTES)
    {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(())
}

fn from_sql_integer(value: i64) -> Result<u64, ProfileStoreError> {
    u64::try_from(value).map_err(|_| ProfileStoreError::CorruptData)
}

fn to_sql_integer(value: u64) -> Result<i64, ProfileStoreError> {
    i64::try_from(value).map_err(|_| ProfileStoreError::SequenceExhausted)
}

fn map_operation_insert_error(error: rusqlite::Error) -> ProfileStoreError {
    match error {
        rusqlite::Error::SqliteFailure(ref details, _)
            if details.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ProfileStoreError::DuplicateOperation
        }
        _ => ProfileStoreError::Storage,
    }
}

fn map_history_update_error(error: rusqlite::Error) -> ProfileStoreError {
    match error {
        rusqlite::Error::SqliteFailure(ref details, _)
            if details.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ProfileStoreError::CursorConflict
        }
        _ => ProfileStoreError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use KonclaveDomainCore::{
        ApplicationContent, ChangeMemberRole, ConversationRole, MAX_TEXT_BODY_BYTES, Member,
        MembershipAuthorization, MembershipChange, ProtocolVersion, RemoveMember,
    };
    use KonclaveProtocolContracts::v1::encode_membership_control;
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
    }

    struct ConversationFixture {
        root: tempfile::TempDir,
        profile_id: ProfileId,
        store: ProfileStore,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        device_id: DeviceId,
    }

    fn conversation_fixture(name: &str) -> ConversationFixture {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse(name).unwrap();
        let store = LockedProfile::acquire(root.path(), profile_id.clone())
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let identity = store.load_or_create_device().unwrap();
        let conversation_id = identity.generate_conversation_id().unwrap();
        let material = identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            0,
            vec![Member::new(
                identity.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let routing_id = RoutingId::from_bytes([9; RoutingId::LENGTH]);
        store
            .insert_conversation(routing_id, &material, &state, &[material.binding().clone()])
            .unwrap();
        ConversationFixture {
            root,
            profile_id,
            store,
            conversation_id,
            routing_id,
            device_id: identity.device_id(),
        }
    }

    fn remote_membership_fixture(name: &str) -> (ConversationFixture, DeviceId) {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse(name).unwrap();
        let store = LockedProfile::acquire(root.path(), profile_id.clone())
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let local = store.load_or_create_device().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let conversation_id = remote.generate_conversation_id().unwrap();
        let local_material = local
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let remote_material = remote
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            0,
            vec![
                Member::new(remote.device_id(), ConversationRole::Administrator, 0),
                Member::new(local.device_id(), ConversationRole::Member, 0),
            ],
            vec![],
        )
        .unwrap();
        let routing_id = RoutingId::from_bytes([19; RoutingId::LENGTH]);
        store
            .insert_conversation(
                routing_id,
                &local_material,
                &state,
                &[
                    remote_material.binding().clone(),
                    local_material.binding().clone(),
                ],
            )
            .unwrap();
        (
            ConversationFixture {
                root,
                profile_id,
                store,
                conversation_id,
                routing_id,
                device_id: local.device_id(),
            },
            remote.device_id(),
        )
    }

    fn complete_remote_membership_event(
        fixture: &ConversationFixture,
        sender: DeviceId,
        identifier: u8,
        change: MembershipChange,
    ) {
        let current = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        let operation_id =
            MembershipOperationId::from_bytes([identifier; MembershipOperationId::LENGTH]);
        let authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            fixture.conversation_id,
            current.state.epoch(),
            operation_id,
            change,
        );
        let next_state = current
            .state
            .apply_membership_authorization(sender, &authorization, current.state.epoch() + 1)
            .unwrap();
        let control = encode_membership_control(&authorization, None).unwrap();
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            fixture.routing_id,
            EnvelopeId::from_bytes([identifier; EnvelopeId::LENGTH]),
            DeliveryClass::GroupCommit,
            Some(current.state.epoch()),
            1_900_000_000,
            vec![identifier],
        )
        .unwrap();
        let stored = StoredRelayEnvelope::new(envelope, 1).unwrap();
        fixture
            .store
            .record_membership_inbox_envelope(&stored)
            .unwrap();
        let bindings = current
            .bindings
            .iter()
            .map(VerifiedDeviceCredentialBinding::binding)
            .cloned()
            .collect::<Vec<_>>();
        fixture
            .store
            .save_membership_inbox_transition(
                fixture.conversation_id,
                1,
                sender,
                current.state.epoch(),
                operation_id,
                &control,
                &next_state,
                &bindings,
            )
            .unwrap();
        fixture
            .store
            .complete_membership_inbox_with_notification(
                fixture.conversation_id,
                1,
                NotificationId::from_bytes([identifier; NotificationId::LENGTH]),
            )
            .unwrap();
    }

    fn application_message(id: u8, sender_counter: u64, text: &str) -> ApplicationMessage {
        ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([id; MessageId::LENGTH]),
            sender_counter,
            1_700_000_000_000,
            None,
            ApplicationContent::text(text).unwrap(),
        )
        .unwrap()
    }

    fn relay_envelope(routing_id: RoutingId, id: u8, payload: &[u8]) -> RelayEnvelope {
        RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            routing_id,
            EnvelopeId::from_bytes([id; EnvelopeId::LENGTH]),
            DeliveryClass::GroupApplication,
            None,
            1_900_000_000,
            payload.to_vec(),
        )
        .unwrap()
    }

    fn membership_transition(
        fixture: &ConversationFixture,
        identifier: u8,
    ) -> (
        MembershipOperationId,
        RelayEnvelope,
        Vec<u8>,
        ConversationState,
        Vec<DeviceCredentialBinding>,
    ) {
        let operation_id =
            MembershipOperationId::from_bytes([identifier; MembershipOperationId::LENGTH]);
        let control = encode_membership_control(
            &MembershipAuthorization::new(
                ProtocolVersion::application_v1(),
                fixture.conversation_id,
                0,
                operation_id,
                MembershipChange::ChangeRole(ChangeMemberRole::new(
                    fixture.device_id,
                    ConversationRole::Administrator,
                )),
            ),
            None,
        )
        .unwrap();
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            fixture.routing_id,
            EnvelopeId::from_bytes([identifier; EnvelopeId::LENGTH]),
            DeliveryClass::GroupCommit,
            Some(0),
            1_900_000_000,
            vec![identifier],
        )
        .unwrap();
        let stored = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        let next_state = ConversationState::new(
            ProtocolVersion::application_v1(),
            fixture.conversation_id,
            1,
            vec![Member::new(
                fixture.device_id,
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let bindings = stored
            .bindings
            .iter()
            .map(VerifiedDeviceCredentialBinding::binding)
            .cloned()
            .collect();
        (operation_id, envelope, control, next_state, bindings)
    }

    fn stage_inbox_message(
        fixture: &ConversationFixture,
        cursor: u64,
        identifier: u8,
        sender_epoch: u64,
        sender_counter: u64,
    ) {
        let envelope = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, identifier, &[identifier]),
            cursor,
        )
        .unwrap();
        fixture.store.record_inbox_envelope(&envelope).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                cursor,
                fixture.device_id,
                sender_epoch,
                &application_message(
                    identifier.wrapping_add(100),
                    sender_counter,
                    &format!("message-{identifier}"),
                ),
            )
            .unwrap();
    }

    fn stage_remote_inbox_message(
        fixture: &ConversationFixture,
        cursor: u64,
        identifier: u8,
        sender: DeviceId,
        sender_counter: u64,
    ) -> ApplicationMessage {
        stage_remote_inbox_for(
            &fixture.store,
            fixture.conversation_id,
            fixture.routing_id,
            cursor,
            identifier,
            sender,
            sender_counter,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "remote inbox identity remains explicit in persistence tests"
    )]
    fn stage_remote_inbox_for(
        store: &ProfileStore,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
        identifier: u8,
        sender: DeviceId,
        sender_counter: u64,
    ) -> ApplicationMessage {
        let envelope = StoredRelayEnvelope::new(
            relay_envelope(routing_id, identifier, &[identifier]),
            cursor,
        )
        .unwrap();
        store.record_inbox_envelope(&envelope).unwrap();
        let message = application_message(
            identifier.wrapping_add(100),
            sender_counter,
            &format!("remote-message-{identifier}"),
        );
        store
            .save_inbox_message(conversation_id, cursor, sender, 0, &message)
            .unwrap();
        message
    }

    fn create_v1_profile_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE daemon_profile (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    profile_id TEXT NOT NULL UNIQUE,
                    sealed_device_identity BLOB,
                    relay_endpoint TEXT,
                    sealed_relay_credential BLOB,
                    CHECK (
                        (relay_endpoint IS NULL AND sealed_relay_credential IS NULL)
                        OR
                        (relay_endpoint IS NOT NULL AND sealed_relay_credential IS NOT NULL)
                    )
                 );
                 CREATE TABLE daemon_conversation (
                    conversation_id BLOB PRIMARY KEY CHECK (length(conversation_id) = 32),
                    routing_id BLOB NOT NULL UNIQUE CHECK (length(routing_id) = 32),
                    sealed_signing_material BLOB NOT NULL,
                    sealed_policy_state BLOB NOT NULL,
                    sender_counter INTEGER NOT NULL CHECK (sender_counter >= 0),
                    replay_cursor INTEGER NOT NULL CHECK (replay_cursor >= 0)
                 ) WITHOUT ROWID;
                 CREATE TABLE daemon_conversation_binding (
                    conversation_id BLOB NOT NULL,
                    device_id BLOB NOT NULL CHECK (length(device_id) = 32),
                    sealed_binding BLOB NOT NULL,
                    PRIMARY KEY (conversation_id, device_id),
                    FOREIGN KEY (conversation_id)
                        REFERENCES daemon_conversation(conversation_id)
                        ON DELETE CASCADE
                 ) WITHOUT ROWID;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
    }

    fn downgrade_v5_to_v4(connection: &Connection) {
        downgrade_v6_to_v5(connection);
        connection
            .execute_batch(
                "DROP TABLE daemon_pending_join;
                 DROP INDEX daemon_membership_outbox_epoch_idx;
                 DROP INDEX daemon_membership_outbox_request_idx;
                 ALTER TABLE daemon_membership_outbox DROP COLUMN change_kind;
                 ALTER TABLE daemon_membership_outbox DROP COLUMN subject_device_id;
                 ALTER TABLE daemon_membership_outbox DROP COLUMN subject_invitation_id;
                 ALTER TABLE daemon_membership_outbox DROP COLUMN subject_role;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
    }

    fn downgrade_v6_to_v5(connection: &Connection) {
        downgrade_v7_to_v6(connection);
        connection
            .execute_batch(
                "ALTER TABLE daemon_pending_join DROP COLUMN join_cursor;
                 ALTER TABLE daemon_pending_join DROP COLUMN join_envelope_id;
                 ALTER TABLE daemon_pending_join DROP COLUMN sealed_join_receipt;
                 PRAGMA user_version = 5;",
            )
            .unwrap();
    }

    fn downgrade_v7_to_v6(connection: &Connection) {
        downgrade_v8_to_v7(connection);
        connection
            .execute_batch(
                "ALTER TABLE daemon_conversation DROP COLUMN sealed_replay_head;
                 PRAGMA user_version = 6;",
            )
            .unwrap();
    }

    fn downgrade_v8_to_v7(connection: &Connection) {
        downgrade_v9_to_v8(connection);
        connection
            .execute_batch(
                "ALTER TABLE daemon_outbox DROP COLUMN terminal_reason;
                 PRAGMA user_version = 7;",
            )
            .unwrap();
    }

    fn downgrade_v9_to_v8(connection: &Connection) {
        downgrade_v10_to_v9(connection);
        connection
            .execute_batch(
                "ALTER TABLE daemon_outbox RENAME TO daemon_outbox_v9;
                 CREATE TABLE daemon_outbox (
                    envelope_id BLOB PRIMARY KEY CHECK (length(envelope_id) = 16),
                    conversation_id BLOB NOT NULL,
                    message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                    sender_counter INTEGER NOT NULL CHECK (sender_counter >= 1),
                    status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 4),
                    sealed_envelope BLOB,
                    accepted_cursor INTEGER,
                    terminal_reason INTEGER
                        CHECK (
                            terminal_reason IS NULL
                            OR (status = 2 AND terminal_reason = 1)
                        ),
                    FOREIGN KEY (conversation_id)
                        REFERENCES daemon_conversation(conversation_id)
                        ON DELETE CASCADE,
                    UNIQUE (conversation_id, message_id),
                    UNIQUE (conversation_id, sender_counter),
                    CHECK (
                        (status = 1 AND sealed_envelope IS NULL AND accepted_cursor IS NULL)
                        OR
                        (status = 2 AND sealed_envelope IS NOT NULL AND accepted_cursor IS NULL)
                        OR
                        (status = 3 AND sealed_envelope IS NOT NULL
                            AND accepted_cursor IS NOT NULL AND accepted_cursor >= 1)
                        OR
                        (status = 4 AND sealed_envelope IS NULL AND accepted_cursor IS NULL)
                    )
                 ) WITHOUT ROWID;
                 INSERT INTO daemon_outbox (
                    envelope_id,
                    conversation_id,
                    message_id,
                    sender_counter,
                    status,
                    sealed_envelope,
                    accepted_cursor,
                    terminal_reason
                 )
                 SELECT
                    envelope_id,
                    conversation_id,
                    message_id,
                    sender_counter,
                    status,
                    sealed_envelope,
                    accepted_cursor,
                    terminal_reason
                 FROM daemon_outbox_v9;
                 DROP TABLE daemon_outbox_v9;
                 CREATE INDEX daemon_outbox_status_idx
                    ON daemon_outbox(status, conversation_id, sender_counter);
                 PRAGMA user_version = 8;",
            )
            .unwrap();
    }

    fn downgrade_v10_to_v9(connection: &Connection) {
        connection
            .execute_batch(
                "DROP TABLE daemon_adapter_consumer;
                 DROP TABLE daemon_remote_event;
                 ALTER TABLE daemon_conversation DROP COLUMN sealed_adapter_delivery_policy;
                 ALTER TABLE daemon_profile DROP COLUMN sealed_remote_event_floor;
                 ALTER TABLE daemon_profile DROP COLUMN remote_event_floor_sequence;
                 ALTER TABLE daemon_profile DROP COLUMN sealed_remote_event_head;
                 ALTER TABLE daemon_profile DROP COLUMN next_remote_event_sequence;
                 PRAGMA user_version = 9;",
            )
            .unwrap();
    }

    #[test]
    fn membership_outbox_transitions_publish_policy_atomically() {
        let fixture = conversation_fixture("membership-outbox-test");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&fixture, 41);
        let welcome = b"opaque-welcome";
        fixture
            .store
            .store_membership_outbox(
                operation_id,
                fixture.conversation_id,
                0,
                &envelope,
                &control,
                &next_state,
                &bindings,
                Some(welcome),
            )
            .unwrap();
        fixture
            .store
            .store_membership_outbox(
                operation_id,
                fixture.conversation_id,
                0,
                &envelope,
                &control,
                &next_state,
                &bindings,
                Some(welcome),
            )
            .unwrap();
        let ready = fixture.store.ready_membership_outbox().unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].operation_id, operation_id);
        assert_eq!(ready[0].status, MembershipOutboxStatus::Ready);
        assert_eq!(ready[0].welcome.as_deref(), Some(welcome.as_slice()));
        assert_eq!(
            fixture
                .store
                .active_membership_outbox(fixture.conversation_id)
                .unwrap()
                .unwrap()
                .next_state,
            next_state
        );

        let stored = StoredRelayEnvelope::new(envelope.clone(), 7).unwrap();
        assert_eq!(
            fixture
                .store
                .mark_membership_outbox_accepted(&stored)
                .unwrap(),
            operation_id
        );
        fixture
            .store
            .mark_membership_outbox_accepted(&stored)
            .unwrap();
        let accepted = fixture.store.load_membership_outbox(operation_id).unwrap();
        assert_eq!(accepted.status, MembershipOutboxStatus::Accepted);
        assert_eq!(accepted.accepted_cursor, Some(7));
        assert_eq!(
            fixture.store.mark_membership_outbox_accepted(
                &StoredRelayEnvelope::new(envelope.clone(), 8).unwrap()
            ),
            Err(ProfileStoreError::InvalidTransition)
        );

        fixture
            .store
            .complete_membership_outbox(operation_id)
            .unwrap();
        fixture
            .store
            .complete_membership_outbox(operation_id)
            .unwrap();
        let applied = fixture.store.load_membership_outbox(operation_id).unwrap();
        assert_eq!(applied.status, MembershipOutboxStatus::Applied);
        assert!(
            fixture
                .store
                .active_membership_outbox(fixture.conversation_id)
                .unwrap()
                .is_none()
        );
        assert!(fixture.store.ready_membership_outbox().unwrap().is_empty());
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .state,
            next_state
        );
    }

    #[test]
    fn membership_outbox_orphans_only_unaccepted_commits() {
        let fixture = conversation_fixture("membership-orphan-test");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&fixture, 42);
        fixture
            .store
            .store_membership_outbox(
                operation_id,
                fixture.conversation_id,
                0,
                &envelope,
                &control,
                &next_state,
                &bindings,
                None,
            )
            .unwrap();
        fixture
            .store
            .orphan_membership_outbox(operation_id)
            .unwrap();
        fixture
            .store
            .orphan_membership_outbox(operation_id)
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_membership_outbox(operation_id)
                .unwrap()
                .status,
            MembershipOutboxStatus::Orphaned
        );
        assert_eq!(
            fixture
                .store
                .active_membership_outbox(fixture.conversation_id)
                .unwrap()
                .unwrap()
                .status,
            MembershipOutboxStatus::Ready
        );
    }

    #[test]
    fn membership_acceptance_requires_exact_sealed_cursor_observation() {
        let forged = conversation_fixture("membership-forged-acceptance");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&forged, 44);
        forged
            .store
            .store_membership_outbox(
                operation_id,
                forged.conversation_id,
                0,
                &envelope,
                &control,
                &next_state,
                &bindings,
                None,
            )
            .unwrap();
        forged
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_membership_outbox
                 SET status = 2, accepted_cursor = 9
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            forged.store.load_membership_outbox(operation_id).err(),
            Some(ProfileStoreError::CursorConflict)
        );

        let tampered = conversation_fixture("membership-cursor-tamper");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&tampered, 45);
        tampered
            .store
            .store_membership_outbox(
                operation_id,
                tampered.conversation_id,
                0,
                &envelope,
                &control,
                &next_state,
                &bindings,
                None,
            )
            .unwrap();
        tampered
            .store
            .mark_membership_outbox_accepted(&StoredRelayEnvelope::new(envelope, 7).unwrap())
            .unwrap();
        tampered
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_membership_outbox SET accepted_cursor = 8
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            tampered.store.load_membership_outbox(operation_id).err(),
            Some(ProfileStoreError::CursorConflict)
        );
        assert_eq!(
            tampered
                .store
                .complete_membership_outbox(operation_id)
                .err(),
            Some(ProfileStoreError::CursorConflict)
        );

        let hidden = conversation_fixture("membership-hidden-acceptance");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&hidden, 46);
        hidden
            .store
            .store_membership_outbox(
                operation_id,
                hidden.conversation_id,
                0,
                &envelope,
                &control,
                &next_state,
                &bindings,
                None,
            )
            .unwrap();
        hidden
            .store
            .mark_membership_outbox_accepted(
                &StoredRelayEnvelope::new(envelope.clone(), 7).unwrap(),
            )
            .unwrap();
        for (status, accepted_cursor) in [(3, Some(7)), (4, None)] {
            hidden
                .store
                .lock()
                .unwrap()
                .execute(
                    "UPDATE daemon_membership_outbox
                     SET status = ?1, accepted_cursor = ?2
                     WHERE operation_id = ?3",
                    params![status, accepted_cursor, operation_id.as_bytes().as_slice()],
                )
                .unwrap();
            let recovered = hidden
                .store
                .active_membership_outbox(hidden.conversation_id)
                .unwrap()
                .unwrap();
            assert_eq!(recovered.status, MembershipOutboxStatus::Accepted);
            assert_eq!(recovered.accepted_cursor, Some(7));
        }
        hidden
            .store
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM daemon_cursor_observation WHERE envelope_id = ?1",
                params![envelope.envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        hidden
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_membership_outbox
                 SET status = 4, accepted_cursor = NULL
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            hidden
                .store
                .active_membership_outbox(hidden.conversation_id)
                .unwrap()
                .unwrap()
                .status,
            MembershipOutboxStatus::Ready
        );
    }

    #[test]
    fn membership_inbox_checkpoints_transition_before_policy_publication() {
        let fixture = conversation_fixture("membership-inbox-test");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&fixture, 43);
        let stored = StoredRelayEnvelope::new(envelope, 1).unwrap();
        assert_eq!(
            fixture
                .store
                .record_membership_inbox_envelope(&stored)
                .unwrap(),
            fixture.conversation_id
        );
        fixture
            .store
            .record_membership_inbox_envelope(&stored)
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .active_membership_inbox(fixture.conversation_id)
                .unwrap(),
            Some(MembershipInboxOperation::Received { .. })
        ));
        fixture
            .store
            .save_membership_inbox_transition(
                fixture.conversation_id,
                1,
                fixture.device_id,
                0,
                operation_id,
                &control,
                &next_state,
                &bindings,
            )
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .membership_inbox_operation(fixture.conversation_id, 1)
                .unwrap(),
            MembershipInboxOperation::TransitionSaved(_)
        ));
        assert_eq!(
            fixture
                .store
                .complete_membership_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .store
                .complete_membership_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        let conversation = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        assert_eq!(conversation.state, next_state);
        assert_eq!(conversation.replay_cursor, 1);
        assert!(
            fixture
                .store
                .active_membership_inbox(fixture.conversation_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn replay_cursor_rejects_incomplete_or_unapplied_observations() {
        let application = conversation_fixture("application-replay-cursor-tamper");
        let application_envelope =
            StoredRelayEnvelope::new(relay_envelope(application.routing_id, 51, b"ciphertext"), 1)
                .unwrap();
        application
            .store
            .record_inbox_envelope(&application_envelope)
            .unwrap();
        application
            .store
            .save_inbox_message(
                application.conversation_id,
                1,
                application.device_id,
                0,
                &application_message(53, 1, "saved-before-completion"),
            )
            .unwrap();
        application
            .store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE daemon_inbox SET status = 3;
                 UPDATE daemon_conversation SET replay_cursor = 1;",
            )
            .unwrap();
        assert_eq!(
            application
                .store
                .load_conversation(application.conversation_id)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );

        let membership = conversation_fixture("membership-replay-cursor-tamper");
        let (operation_id, envelope, control, next_state, bindings) =
            membership_transition(&membership, 52);
        let receipt = StoredRelayEnvelope::new(envelope, 1).unwrap();
        membership
            .store
            .record_membership_inbox_envelope(&receipt)
            .unwrap();
        membership
            .store
            .save_membership_inbox_transition(
                membership.conversation_id,
                1,
                membership.device_id,
                0,
                operation_id,
                &control,
                &next_state,
                &bindings,
            )
            .unwrap();
        membership
            .store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE daemon_membership_inbox SET status = 3;
                 UPDATE daemon_conversation SET replay_cursor = 1;",
            )
            .unwrap();
        assert_eq!(
            membership
                .store
                .load_conversation(membership.conversation_id)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn valid_v1_replay_head_migrates_to_separated_v2_authority() {
        let fixture = conversation_fixture("replay-head-v1-payload");
        stage_inbox_message(&fixture, 1, 54, 0, 1);
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        let stored = match fixture
            .store
            .inbox_operation(fixture.conversation_id, 1)
            .unwrap()
        {
            InboxOperation::Complete { stored, .. } => stored,
            _ => panic!("expected completed inbox"),
        };
        let conversation = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        let v1 = encode_replay_head_v1(
            0,
            1,
            ReplayCompletionKind::Application,
            &conversation.state,
            stored.envelope(),
        )
        .unwrap();
        let v1 = fixture
            .store
            .seal_operation_record(
                SecretRecordKind::LocalOperation,
                fixture.conversation_id,
                fixture.routing_id,
                REPLAY_HEAD_RECORD_SCOPE,
                fixture.conversation_id.as_bytes(),
                &v1,
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation
                 SET sealed_replay_head = ?1
                 WHERE conversation_id = ?2",
                params![v1.as_bytes(), fixture.conversation_id.as_bytes().as_slice()],
            )
            .unwrap();

        fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        let bytes: Vec<u8> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_replay_head FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![fixture.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let migrated = fixture
            .store
            .open_replay_head(fixture.conversation_id, fixture.routing_id, bytes)
            .unwrap();
        assert_eq!(migrated.version, ReplayHeadVersion::V2);
        assert_eq!(migrated.completion_state, conversation.state);
        assert_eq!(migrated.policy_state, conversation.state);
    }

    #[test]
    fn progressed_v1_membership_head_recovers_historical_completion_state() {
        let fixture = conversation_fixture("v1-membership-progress");
        let (first_operation, first_envelope, first_control, first_state, first_bindings) =
            membership_transition(&fixture, 55);
        let first_receipt = StoredRelayEnvelope::new(first_envelope, 1).unwrap();
        fixture
            .store
            .record_membership_inbox_envelope(&first_receipt)
            .unwrap();
        fixture
            .store
            .save_membership_inbox_transition(
                fixture.conversation_id,
                1,
                fixture.device_id,
                0,
                first_operation,
                &first_control,
                &first_state,
                &first_bindings,
            )
            .unwrap();
        fixture
            .store
            .complete_membership_inbox(fixture.conversation_id, 1)
            .unwrap();

        let current = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        let second_operation =
            MembershipOperationId::from_bytes([56; MembershipOperationId::LENGTH]);
        let second_authorization = MembershipAuthorization::new(
            ProtocolVersion::application_v1(),
            fixture.conversation_id,
            1,
            second_operation,
            MembershipChange::ChangeRole(ChangeMemberRole::new(
                fixture.device_id,
                ConversationRole::Administrator,
            )),
        );
        let second_control = encode_membership_control(&second_authorization, None).unwrap();
        let second_state = current
            .state
            .apply_membership_authorization(fixture.device_id, &second_authorization, 2)
            .unwrap();
        let second_envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            fixture.routing_id,
            EnvelopeId::from_bytes([56; EnvelopeId::LENGTH]),
            DeliveryClass::GroupCommit,
            Some(1),
            1_900_000_000,
            vec![56],
        )
        .unwrap();
        let second_bindings = current
            .bindings
            .iter()
            .map(|binding| binding.binding().clone())
            .collect::<Vec<_>>();
        fixture
            .store
            .store_membership_outbox(
                second_operation,
                fixture.conversation_id,
                1,
                &second_envelope,
                &second_control,
                &second_state,
                &second_bindings,
                None,
            )
            .unwrap();
        let second_receipt = StoredRelayEnvelope::new(second_envelope, 2).unwrap();
        fixture
            .store
            .mark_membership_outbox_accepted(&second_receipt)
            .unwrap();
        fixture
            .store
            .complete_membership_outbox(second_operation)
            .unwrap();

        let current = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        let v1 = encode_replay_head_v1(
            0,
            1,
            ReplayCompletionKind::Membership,
            &current.state,
            first_receipt.envelope(),
        )
        .unwrap();
        let v1 = fixture
            .store
            .seal_operation_record(
                SecretRecordKind::LocalOperation,
                fixture.conversation_id,
                fixture.routing_id,
                REPLAY_HEAD_RECORD_SCOPE,
                fixture.conversation_id.as_bytes(),
                &v1,
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation
                 SET sealed_replay_head = ?1
                 WHERE conversation_id = ?2",
                params![v1.as_bytes(), fixture.conversation_id.as_bytes().as_slice()],
            )
            .unwrap();

        let reopened = fixture
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap();
        assert_eq!(reopened.state, second_state);
        let bytes: Vec<u8> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_replay_head FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![fixture.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let migrated = fixture
            .store
            .open_replay_head(fixture.conversation_id, fixture.routing_id, bytes)
            .unwrap();
        assert_eq!(migrated.version, ReplayHeadVersion::V2);
        assert_eq!(migrated.completion_state, first_state);
        assert_eq!(migrated.policy_state, second_state);
    }

    #[test]
    fn pending_join_reserves_proof_and_welcome_state_in_order() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("pending-join-test").unwrap();
        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let bob = store.load_or_create_device().unwrap();
        let alice = DeviceIdentity::generate().unwrap();
        let conversation_id = alice.generate_conversation_id().unwrap();
        let routing_id = alice.generate_routing_id().unwrap();
        let alice_material = alice
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let bob_material = bob
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let invitation = alice
            .issue_invitation(
                conversation_id,
                routing_id,
                bob.device_id(),
                ConversationRole::Member,
                100,
            )
            .unwrap();
        let invitation_copy = decode_invitation(&encode_invitation(&invitation).unwrap()).unwrap();
        store
            .reserve_pending_join(
                routing_id,
                &bob_material,
                &invitation,
                alice.public_key(),
                &[alice_material.binding().clone()],
                50,
            )
            .unwrap();
        let reserved = store.load_pending_join(conversation_id).unwrap();
        assert!(reserved.proof.is_none());
        assert!(reserved.state.is_none());
        let proof =
            JoinProof::new(invitation_copy, bob_material.binding().clone(), vec![7]).unwrap();
        store
            .store_pending_join_proof(conversation_id, &proof)
            .unwrap();
        store
            .store_pending_join_proof(conversation_id, &proof)
            .unwrap();
        assert!(
            store
                .load_pending_join(conversation_id)
                .unwrap()
                .proof
                .is_some()
        );
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            1,
            vec![
                Member::new(alice.device_id(), ConversationRole::Administrator, 0),
                Member::new(bob.device_id(), ConversationRole::Member, 1),
            ],
            vec![proof.invitation().invitation_id()],
        )
        .unwrap();
        let receipt = StoredRelayEnvelope::new(
            RelayEnvelope::new(
                ProtocolVersion::application_v1(),
                routing_id,
                EnvelopeId::from_bytes([11; EnvelopeId::LENGTH]),
                DeliveryClass::GroupCommit,
                Some(0),
                1_900_000_000,
                vec![12],
            )
            .unwrap(),
            7,
        )
        .unwrap();
        let expected_commit_envelope_id = receipt.envelope().envelope_id();
        store
            .checkpoint_pending_join_state(
                conversation_id,
                &state,
                expected_commit_envelope_id,
                &receipt,
            )
            .unwrap();
        store
            .checkpoint_pending_join_state(
                conversation_id,
                &state,
                expected_commit_envelope_id,
                &receipt,
            )
            .unwrap();
        let checkpointed = store.load_pending_join(conversation_id).unwrap();
        assert_eq!(checkpointed.state, Some(state));
        assert_eq!(
            checkpointed.expected_commit_envelope_id,
            Some(expected_commit_envelope_id)
        );
        assert!(checkpointed.join_receipt.as_ref() == Some(&receipt));
        assert_eq!(
            store.pending_join_ids(None, 10).unwrap(),
            vec![conversation_id]
        );
        store.delete_pending_join(conversation_id).unwrap();
        assert!(store.pending_join_ids(None, 10).unwrap().is_empty());
    }

    #[test]
    fn outbox_reservations_and_transitions_are_durable_and_idempotent() {
        let fixture = conversation_fixture("outbox-test");
        let message_id = MessageId::from_bytes([1; MessageId::LENGTH]);
        let envelope_id = EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]);
        let reservation = fixture
            .store
            .reserve_outbound_application(fixture.conversation_id, message_id, envelope_id)
            .unwrap();
        assert_eq!(reservation.sender_counter, 1);
        assert_eq!(
            fixture
                .store
                .reserve_outbound_application(fixture.conversation_id, message_id, envelope_id)
                .unwrap(),
            reservation
        );
        assert!(fixture.store.ready_outbox().unwrap().is_empty());

        let envelope = relay_envelope(fixture.routing_id, 2, b"opaque-outbox-ciphertext");
        fixture
            .store
            .store_outbound_message(
                reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &application_message(1, 1, "outbox message"),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(reservation, &envelope)
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(reservation, &envelope)
            .unwrap();
        let ready = fixture.store.ready_outbox().unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].conversation_id, fixture.conversation_id);
        assert!(ready[0].envelope == envelope);

        let ConversationFixture {
            root,
            profile_id,
            store,
            conversation_id,
            ..
        } = fixture;
        drop(store);
        let reopened = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let ready = reopened.ready_outbox().unwrap();
        assert_eq!(ready.len(), 1);
        assert!(ready[0].envelope == envelope);
        let accepted = StoredRelayEnvelope::new(envelope.clone(), 7).unwrap();
        reopened.mark_outbox_accepted(&accepted).unwrap();
        reopened.mark_outbox_accepted(&accepted).unwrap();
        assert_eq!(
            reopened.mark_outbox_accepted(&StoredRelayEnvelope::new(envelope.clone(), 8).unwrap()),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert!(reopened.ready_outbox().unwrap().is_empty());

        let second = reopened
            .reserve_outbound_application(
                conversation_id,
                MessageId::from_bytes([3; MessageId::LENGTH]),
                EnvelopeId::from_bytes([4; EnvelopeId::LENGTH]),
            )
            .unwrap();
        assert_eq!(second.sender_counter, 2);
        reopened.abandon_outbound_application(second).unwrap();
        reopened.abandon_outbound_application(second).unwrap();
        assert_eq!(
            reopened.reserve_outbound_application(
                conversation_id,
                second.message_id,
                second.envelope_id,
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            reopened.reserve_outbound_application(
                conversation_id,
                MessageId::from_bytes([5; MessageId::LENGTH]),
                envelope_id,
            ),
            Err(ProfileStoreError::DuplicateOperation)
        );
        assert_eq!(
            reopened
                .load_conversation(conversation_id)
                .unwrap()
                .sender_counter,
            2
        );
    }

    #[test]
    fn cursor_observations_reject_relay_equivocation_in_both_directions() {
        let fixture = conversation_fixture("cursor-observation-test");
        let first_reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([1; EnvelopeId::LENGTH]),
            )
            .unwrap();
        let first = relay_envelope(fixture.routing_id, 1, b"first");
        fixture
            .store
            .store_outbound_message(
                first_reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &application_message(1, 1, "first outbound"),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(first_reservation, &first)
            .unwrap();
        let altered_response = RelayEnvelope::new(
            first.version(),
            first.routing_id(),
            first.envelope_id(),
            first.delivery_class(),
            first.expected_parent_epoch(),
            first.expires_at_unix_seconds(),
            b"altered-response".to_vec(),
        )
        .unwrap();
        assert_eq!(
            fixture
                .store
                .mark_outbox_accepted(&StoredRelayEnvelope::new(altered_response, 1).unwrap()),
            Err(ProfileStoreError::CursorConflict)
        );
        fixture
            .store
            .mark_outbox_accepted(&StoredRelayEnvelope::new(first.clone(), 1).unwrap())
            .unwrap();
        let sealed_observation: Vec<u8> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_observation FROM daemon_cursor_observation
                 WHERE conversation_id = ?1 AND cursor = 1",
                params![fixture.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET accepted_cursor = 2
                 WHERE envelope_id = ?1",
                params![first.envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .mark_outbox_accepted(&StoredRelayEnvelope::new(first.clone(), 2).unwrap()),
            Err(ProfileStoreError::CursorConflict)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET accepted_cursor = 1
                 WHERE envelope_id = ?1",
                params![first.envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_cursor_observation
                 SET sealed_observation = (
                    SELECT sealed_envelope FROM daemon_outbox WHERE envelope_id = ?1
                 )
                 WHERE conversation_id = ?2 AND cursor = 1",
                params![
                    first.envelope_id().as_bytes().as_slice(),
                    fixture.conversation_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .mark_outbox_accepted(&StoredRelayEnvelope::new(first.clone(), 1).unwrap()),
            Err(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_cursor_observation SET sealed_observation = ?1
                 WHERE conversation_id = ?2 AND cursor = 1",
                params![
                    sealed_observation,
                    fixture.conversation_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        let altered_first = RelayEnvelope::new(
            first.version(),
            first.routing_id(),
            first.envelope_id(),
            first.delivery_class(),
            first.expected_parent_epoch(),
            first.expires_at_unix_seconds(),
            b"altered-first".to_vec(),
        )
        .unwrap();
        assert_eq!(
            fixture
                .store
                .record_inbox_envelope(&StoredRelayEnvelope::new(altered_first, 1).unwrap()),
            Err(ProfileStoreError::CursorConflict)
        );
        let conflicting_first = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, 2, b"conflicting-first"),
            1,
        )
        .unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&conflicting_first),
            Err(ProfileStoreError::CursorConflict)
        );
        fixture
            .store
            .record_inbox_envelope(&StoredRelayEnvelope::new(first.clone(), 1).unwrap())
            .unwrap();

        let second =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 3, b"second"), 2).unwrap();
        fixture.store.record_inbox_envelope(&second).unwrap();
        let conflicting_reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([4; MessageId::LENGTH]),
                EnvelopeId::from_bytes([4; EnvelopeId::LENGTH]),
            )
            .unwrap();
        let conflicting_second = relay_envelope(fixture.routing_id, 4, b"conflicting-second");
        fixture
            .store
            .store_outbound_envelope(conflicting_reservation, &conflicting_second)
            .unwrap();
        assert_eq!(
            fixture.store.mark_outbox_accepted(
                &StoredRelayEnvelope::new(conflicting_second.clone(), 2).unwrap()
            ),
            Err(ProfileStoreError::CursorConflict)
        );
        assert_eq!(fixture.store.ready_outbox().unwrap().len(), 1);
    }

    #[test]
    fn inbox_transitions_enforce_deduplication_and_contiguous_completion() {
        let fixture = conversation_fixture("inbox-test");
        let envelope = relay_envelope(fixture.routing_id, 1, b"opaque-inbox-ciphertext");
        let stored = StoredRelayEnvelope::new(envelope.clone(), 1).unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&stored).unwrap(),
            fixture.conversation_id
        );
        assert_eq!(
            fixture.store.record_inbox_envelope(&stored).unwrap(),
            fixture.conversation_id
        );
        let conflict =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 2, b"different"), 1)
                .unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&conflict),
            Err(ProfileStoreError::CursorConflict)
        );
        let moved_duplicate = StoredRelayEnvelope::new(envelope, 2).unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&moved_duplicate),
            Err(ProfileStoreError::CursorConflict)
        );

        let pending = fixture
            .store
            .incomplete_inbox(fixture.conversation_id)
            .unwrap();
        assert!(matches!(
            pending.as_slice(),
            [PendingInbox::Received {
                conversation_id,
                stored
            }] if *conversation_id == fixture.conversation_id && stored.cursor() == 1
        ));

        let message = application_message(3, 1, "sealed-inbox-plaintext");
        fixture
            .store
            .save_inbox_message(fixture.conversation_id, 1, fixture.device_id, 0, &message)
            .unwrap();
        fixture
            .store
            .save_inbox_message(fixture.conversation_id, 1, fixture.device_id, 0, &message)
            .unwrap();
        let pending = fixture
            .store
            .incomplete_inbox(fixture.conversation_id)
            .unwrap();
        assert!(matches!(
            pending.as_slice(),
            [PendingInbox::MessageSaved {
                conversation_id,
                stored,
                message
            }] if *conversation_id == fixture.conversation_id
                && stored.cursor() == 1
                && message.cursor == 1
                && message.sender == fixture.device_id
                && message.epoch == 0
                && message.message.message_id() == MessageId::from_bytes([3; MessageId::LENGTH])
        ));

        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        assert!(
            fixture
                .store
                .incomplete_inbox(fixture.conversation_id)
                .unwrap()
                .is_empty()
        );
        let messages = fixture
            .store
            .load_messages(fixture.conversation_id, 0, 10)
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].cursor, 1);
        assert_eq!(messages[0].envelope_id, stored.envelope().envelope_id());
        assert_eq!(messages[0].sender, fixture.device_id);
        assert!(application_messages_equal(&messages[0].message, &message).unwrap());

        let gap_envelope =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 4, b"gap"), 3).unwrap();
        fixture.store.record_inbox_envelope(&gap_envelope).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                3,
                fixture.device_id,
                0,
                &application_message(4, 2, "gap"),
            )
            .unwrap();
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 3),
            Err(ProfileStoreError::CursorGap)
        );
    }

    #[test]
    fn inbox_window_preserves_capacity_for_missing_head_cursor() {
        let fixture = conversation_fixture("inbox-window");
        for cursor in 2_u64..=100 {
            stage_inbox_message(&fixture, cursor, u8::try_from(cursor).unwrap(), 0, cursor);
        }
        let cursor_101 =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 101, b"cursor-101"), 101)
                .unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&cursor_101),
            Err(ProfileStoreError::InboxCapacityExceeded)
        );

        stage_inbox_message(&fixture, 1, 1, 0, 1);
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        stage_inbox_message(&fixture, 101, 101, 0, 101);
        for cursor in 2_u64..=101 {
            assert_eq!(
                fixture
                    .store
                    .complete_inbox(fixture.conversation_id, cursor)
                    .unwrap(),
                cursor
            );
        }
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            101
        );
    }

    #[test]
    fn completed_inbox_rejects_sender_counter_regressions_per_epoch() {
        let fixture = conversation_fixture("sender-counter-regression-test");
        stage_inbox_message(&fixture, 1, 1, 4, 10);
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        let sealed_high_water: Vec<u8> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_state FROM daemon_sender_counter
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = 4",
                params![
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_sender_counter SET highest_counter = 9
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = 4",
                params![
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 1),
            Err(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_sender_counter
                 SET highest_counter = 10,
                     sealed_state = (
                        SELECT sealed_observation
                        FROM daemon_cursor_observation
                        WHERE conversation_id = ?1 AND cursor = 1
                     )
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = 4",
                params![
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 1),
            Err(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_sender_counter SET sealed_state = ?1
                 WHERE conversation_id = ?2
                   AND sender_device_id = ?3
                   AND sender_epoch = 4",
                params![
                    sealed_high_water,
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        stage_inbox_message(&fixture, 2, 2, 5, 1);
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 2)
                .unwrap(),
            2
        );
        stage_inbox_message(&fixture, 3, 3, 4, 9);
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 3),
            Err(ProfileStoreError::SenderCounterRegression)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            2
        );
        assert_eq!(
            fixture
                .store
                .incomplete_inbox(fixture.conversation_id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn recovered_abandoned_sender_counter_gap_allows_next_authenticated_counter() {
        let fixture = conversation_fixture("counter-gap-recovery");
        let first_reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([1; EnvelopeId::LENGTH]),
            )
            .unwrap();
        let first_message = application_message(1, 1, "counter one");
        let first_envelope = relay_envelope(fixture.routing_id, 1, b"counter-one");
        fixture
            .store
            .store_outbound_message(
                first_reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &first_message,
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(first_reservation, &first_envelope)
            .unwrap();
        let first = StoredRelayEnvelope::new(first_envelope, 1).unwrap();
        fixture.store.record_inbox_envelope(&first).unwrap();
        let first_history = fixture
            .store
            .outbound_history_message(fixture.conversation_id, &first)
            .unwrap()
            .unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                1,
                first_history.sender,
                first_history.epoch,
                &first_history.message,
            )
            .unwrap();
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([2; MessageId::LENGTH]),
                EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            )
            .unwrap();
        assert_eq!(reservation.sender_counter, 2);
        fixture
            .store
            .store_outbound_message(
                reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &application_message(2, 2, "encrypted-before-crash"),
            )
            .unwrap();

        let root = fixture.root.path().to_path_buf();
        let profile_id = fixture.profile_id.clone();
        let conversation_id = fixture.conversation_id;
        let routing_id = fixture.routing_id;
        let device_id = fixture.device_id;
        drop(fixture.store);
        let reopened = LockedProfile::acquire(&root, profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        assert_eq!(reopened.abandon_unsealed_outbox().unwrap(), 1);

        let third_reservation = reopened
            .reserve_outbound_application(
                conversation_id,
                MessageId::from_bytes([3; MessageId::LENGTH]),
                EnvelopeId::from_bytes([3; EnvelopeId::LENGTH]),
            )
            .unwrap();
        assert_eq!(third_reservation.sender_counter, 3);
        let third_message = application_message(3, 3, "counter three");
        let third_envelope = relay_envelope(routing_id, 3, b"counter-three-after-recovery");
        reopened
            .store_outbound_message(third_reservation, routing_id, device_id, 0, &third_message)
            .unwrap();
        reopened
            .store_outbound_envelope(third_reservation, &third_envelope)
            .unwrap();
        let third = StoredRelayEnvelope::new(third_envelope, 2).unwrap();
        reopened.record_inbox_envelope(&third).unwrap();
        let third_history = reopened
            .outbound_history_message(conversation_id, &third)
            .unwrap()
            .unwrap();
        reopened
            .save_inbox_message(
                conversation_id,
                2,
                third_history.sender,
                third_history.epoch,
                &third_history.message,
            )
            .unwrap();
        assert_eq!(reopened.complete_inbox(conversation_id, 2).unwrap(), 2);
        assert_eq!(
            reopened
                .load_conversation(conversation_id)
                .unwrap()
                .replay_cursor,
            2
        );
        let connection = reopened.lock().unwrap();
        assert_eq!(
            reopened
                .load_sender_high_water(&connection, conversation_id, device_id, 0)
                .unwrap(),
            Some(3)
        );
    }

    #[test]
    fn application_journal_rejects_other_delivery_classes() {
        let fixture = conversation_fixture("journal-class-test");
        let envelope_id = EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]);
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                envelope_id,
            )
            .unwrap();
        let commit = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            fixture.routing_id,
            envelope_id,
            DeliveryClass::GroupCommit,
            Some(0),
            1_900_000_000,
            vec![1],
        )
        .unwrap();
        assert_eq!(
            fixture.store.store_outbound_envelope(reservation, &commit),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            fixture
                .store
                .record_inbox_envelope(&StoredRelayEnvelope::new(commit, 1).unwrap()),
            Err(ProfileStoreError::InvalidTransition)
        );
    }

    #[test]
    fn incomplete_inbox_reopens_received_and_message_saved_states() {
        let fixture = conversation_fixture("inbox-recovery-test");
        let first = StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 1, b"received"), 1)
            .unwrap();
        let second =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 2, b"message-saved"), 2)
                .unwrap();
        fixture.store.record_inbox_envelope(&first).unwrap();
        fixture.store.record_inbox_envelope(&second).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                2,
                fixture.device_id,
                0,
                &application_message(3, 1, "saved"),
            )
            .unwrap();

        let ConversationFixture {
            root,
            profile_id,
            store,
            conversation_id,
            device_id,
            ..
        } = fixture;
        drop(store);
        let reopened = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let pending = reopened.incomplete_inbox(conversation_id).unwrap();
        assert!(matches!(
            pending.as_slice(),
            [
                PendingInbox::Received { stored: first, .. },
                PendingInbox::MessageSaved {
                    stored: second,
                    message,
                    ..
                }
            ] if first.cursor() == 1
                && second.cursor() == 2
                && message.cursor == 2
                && message.sender == device_id
                && message.epoch == 0
        ));
    }

    #[test]
    fn journal_reads_reject_unknown_conversations_and_invalid_page_bounds() {
        let fixture = conversation_fixture("journal-read-validation-test");
        let unknown = ConversationId::from_bytes([8; ConversationId::LENGTH]);
        assert_eq!(
            fixture.store.incomplete_inbox(unknown).err(),
            Some(ProfileStoreError::ConversationNotFound)
        );
        assert_eq!(
            fixture.store.load_messages(unknown, 0, 10).err(),
            Some(ProfileStoreError::ConversationNotFound)
        );
        assert_eq!(
            fixture
                .store
                .load_messages(fixture.conversation_id, 0, 0)
                .err(),
            Some(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            fixture
                .store
                .load_messages(fixture.conversation_id, 0, MAX_MESSAGE_PAGE_SIZE + 1)
                .err(),
            Some(ProfileStoreError::InvalidTransition)
        );
    }

    #[test]
    fn journal_sealing_hides_payload_and_message_sentinels() {
        let fixture = conversation_fixture("sealed-journal-test");
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(
                reservation,
                &relay_envelope(fixture.routing_id, 2, b"OUTBOX-CIPHERTEXT-SENTINEL"),
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, 3, b"INBOX-CIPHERTEXT-SENTINEL"),
            1,
        )
        .unwrap();
        fixture.store.record_inbox_envelope(&stored).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                1,
                fixture.device_id,
                0,
                &application_message(4, 1, "PLAINTEXT-MESSAGE-SENTINEL"),
            )
            .unwrap();
        let sealed_records: Vec<Vec<u8>> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                    (SELECT sealed_envelope FROM daemon_outbox LIMIT 1),
                    (SELECT sealed_observation FROM daemon_cursor_observation LIMIT 1),
                    (SELECT sealed_message FROM daemon_message_history LIMIT 1),
                    sealed_envelope,
                    sealed_message
                 FROM daemon_inbox LIMIT 1",
                [],
                |row| {
                    Ok(vec![
                        row.get(0)?,
                        row.get(1)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(2)?,
                    ])
                },
            )
            .unwrap();
        for (sealed, sentinel) in sealed_records.iter().zip([
            b"OUTBOX-CIPHERTEXT-SENTINEL".as_slice(),
            b"INBOX-CIPHERTEXT-SENTINEL".as_slice(),
            b"INBOX-CIPHERTEXT-SENTINEL".as_slice(),
            b"PLAINTEXT-MESSAGE-SENTINEL".as_slice(),
            b"PLAINTEXT-MESSAGE-SENTINEL".as_slice(),
        ]) {
            assert!(
                !sealed
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
            );
        }
    }

    #[test]
    fn journal_metadata_and_record_scope_tampering_fails_closed() {
        let fixture = conversation_fixture("journal-tamper-test");
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(
                reservation,
                &relay_envelope(fixture.routing_id, 2, b"outbound"),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET message_id = ?1",
                params![
                    MessageId::from_bytes([8; MessageId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.ready_outbox().err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET message_id = ?1, sender_counter = 2",
                params![reservation.message_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture.store.ready_outbox().err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute("UPDATE daemon_outbox SET sender_counter = 1", [])
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation SET routing_id = ?1",
                params![
                    RoutingId::from_bytes([8; RoutingId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.ready_outbox().err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation SET routing_id = ?1",
                params![fixture.routing_id.as_bytes().as_slice()],
            )
            .unwrap();

        let stored =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 3, b"inbound"), 1).unwrap();
        fixture.store.record_inbox_envelope(&stored).unwrap();
        let message = application_message(4, 1, "message");
        fixture
            .store
            .save_inbox_message(fixture.conversation_id, 1, fixture.device_id, 0, &message)
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute("UPDATE daemon_inbox SET cursor = 2", [])
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_inbox_envelope(stored.envelope().envelope_id())
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET cursor = 1, sender_device_id = ?1",
                params![
                    DeviceId::from_bytes([8; DeviceId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET sender_device_id = ?1, sender_counter = 2",
                params![fixture.device_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET sender_counter = 1, sender_epoch = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET sender_epoch = 0, envelope_id = ?1",
                params![
                    EnvelopeId::from_bytes([7; EnvelopeId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET envelope_id = ?1,
                     sealed_envelope = (SELECT sealed_envelope FROM daemon_outbox LIMIT 1)",
                params![stored.envelope().envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_inbox_envelope(stored.envelope().envelope_id())
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn history_hides_accepted_outbound_until_contiguous_echo_completion() {
        let fixture = conversation_fixture("history-contiguous-frontier");
        let message_id = MessageId::from_bytes([71; MessageId::LENGTH]);
        let envelope_id = EnvelopeId::from_bytes([72; EnvelopeId::LENGTH]);
        let reservation = fixture
            .store
            .reserve_outbound_application(fixture.conversation_id, message_id, envelope_id)
            .unwrap();
        let outbound_message = application_message(71, 1, "outbound-at-two");
        let outbound_envelope = relay_envelope(fixture.routing_id, 72, b"outbound-ciphertext");
        fixture
            .store
            .store_outbound_message(
                reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &outbound_message,
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(reservation, &outbound_envelope)
            .unwrap();
        fixture
            .store
            .mark_outbox_accepted(&StoredRelayEnvelope::new(outbound_envelope.clone(), 2).unwrap())
            .unwrap();
        assert!(
            fixture
                .store
                .load_history(fixture.conversation_id, 0, 10)
                .unwrap()
                .messages
                .is_empty()
        );

        let inbound = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, 73, b"inbound-ciphertext"),
            1,
        )
        .unwrap();
        fixture.store.record_inbox_envelope(&inbound).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                1,
                DeviceId::from_bytes([74; DeviceId::LENGTH]),
                0,
                &application_message(74, 1, "inbound-at-one"),
            )
            .unwrap();
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        let first_page = fixture
            .store
            .load_history(fixture.conversation_id, 0, 10)
            .unwrap();
        assert_eq!(first_page.messages.len(), 1);
        assert_eq!(first_page.messages[0].cursor, 1);

        let echo = StoredRelayEnvelope::new(outbound_envelope, 2).unwrap();
        fixture.store.record_inbox_envelope(&echo).unwrap();
        let outbound = fixture
            .store
            .outbound_history_message(fixture.conversation_id, &echo)
            .unwrap()
            .unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                2,
                outbound.sender,
                outbound.epoch,
                &outbound.message,
            )
            .unwrap();
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 2)
            .unwrap();
        let complete = fixture
            .store
            .load_history(fixture.conversation_id, 0, 10)
            .unwrap();
        assert_eq!(
            complete
                .messages
                .iter()
                .map(|message| message.cursor)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn outbox_capacity_and_sequence_failures_do_not_consume_counters() {
        let fixture = conversation_fixture("outbox-capacity-test");
        for value in 1..=MAX_PENDING_OUTBOX {
            let value = u8::try_from(value).unwrap();
            let reservation = fixture
                .store
                .reserve_outbound_application(
                    fixture.conversation_id,
                    MessageId::from_bytes([value; MessageId::LENGTH]),
                    EnvelopeId::from_bytes([value; EnvelopeId::LENGTH]),
                )
                .unwrap();
            assert_eq!(reservation.sender_counter, u64::from(value));
        }
        assert_eq!(
            fixture.store.reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([100; MessageId::LENGTH]),
                EnvelopeId::from_bytes([100; EnvelopeId::LENGTH]),
            ),
            Err(ProfileStoreError::OutboxCapacityExceeded)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .sender_counter,
            MAX_PENDING_OUTBOX as u64
        );
        assert_eq!(
            fixture.store.abandon_unsealed_outbox().unwrap(),
            MAX_PENDING_OUTBOX
        );
        assert_eq!(
            fixture.store.reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([1; EnvelopeId::LENGTH]),
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            fixture
                .store
                .reserve_outbound_application(
                    fixture.conversation_id,
                    MessageId::from_bytes([100; MessageId::LENGTH]),
                    EnvelopeId::from_bytes([100; EnvelopeId::LENGTH]),
                )
                .unwrap()
                .sender_counter,
            (MAX_PENDING_OUTBOX + 1) as u64
        );

        fixture
            .store
            .lock()
            .unwrap()
            .execute("DELETE FROM daemon_outbox", [])
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation SET sender_counter = ?1",
                params![i64::MAX],
            )
            .unwrap();
        assert_eq!(
            fixture.store.reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([101; MessageId::LENGTH]),
                EnvelopeId::from_bytes([101; EnvelopeId::LENGTH]),
            ),
            Err(ProfileStoreError::SequenceExhausted)
        );
        let (counter, outbox_count): (i64, i64) = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                    sender_counter,
                    (SELECT count(*) FROM daemon_outbox)
                 FROM daemon_conversation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(counter, i64::MAX);
        assert_eq!(outbox_count, 0);
    }

    #[test]
    fn concurrent_outbox_reservations_allocate_unique_monotonic_counters() {
        let fixture = conversation_fixture("outbox-concurrency-test");
        let ConversationFixture {
            root: _root,
            store,
            conversation_id,
            ..
        } = fixture;
        let store = Arc::new(store);
        let mut workers = Vec::new();
        for value in 1..=16 {
            let store = Arc::clone(&store);
            workers.push(std::thread::spawn(move || {
                store
                    .reserve_outbound_application(
                        conversation_id,
                        MessageId::from_bytes([value; MessageId::LENGTH]),
                        EnvelopeId::from_bytes([value; EnvelopeId::LENGTH]),
                    )
                    .unwrap()
                    .sender_counter
            }));
        }
        let mut counters = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        counters.sort_unstable();
        assert_eq!(counters, (1..=16).collect::<Vec<_>>());
        assert_eq!(
            store
                .load_conversation(conversation_id)
                .unwrap()
                .sender_counter,
            16
        );
    }

    #[test]
    fn profile_lock_identity_and_relay_configuration_reopen() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("default").unwrap();
        let locked = LockedProfile::acquire(root.path(), profile_id.clone()).unwrap();
        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id.clone()).err(),
            Some(ProfileStoreError::ProfileLocked)
        );
        let store = locked.open_store(sealer()).unwrap();
        let first_device = store.load_or_create_device().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com/base").unwrap();
        let credential = RelayAccessCredential::from_bytes([8; RelayAccessCredential::LENGTH]);
        store.configure_relay(&endpoint, &credential).unwrap();
        drop(store);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        assert_eq!(
            store.load_or_create_device().unwrap().device_id(),
            first_device.device_id()
        );
        let (reopened_endpoint, reopened_credential) = store.relay_configuration().unwrap();
        assert_eq!(reopened_endpoint.as_str(), endpoint.as_str());
        assert!(RelayClient::new(reopened_endpoint, reopened_credential).is_ok());
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_profile
                 SET relay_endpoint = 'https://other.example.com/'
                 WHERE singleton_id = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            store.relay_configuration().err(),
            Some(ProfileStoreError::Credential)
        );
    }

    #[test]
    fn profile_lock_is_exclusive_across_processes() {
        if let Ok(root) = std::env::var("KONCLAVE_PROFILE_LOCK_CHILD_ROOT") {
            assert_eq!(
                LockedProfile::acquire(
                    Path::new(&root),
                    ProfileId::parse("cross-process").unwrap(),
                )
                .err(),
                Some(ProfileStoreError::ProfileLocked)
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let _locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("cross-process").unwrap())
                .unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "persistence::tests::profile_lock_is_exclusive_across_processes",
                "--nocapture",
            ])
            .env("KONCLAVE_PROFILE_LOCK_CHILD_ROOT", root.path())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn profile_store_rejects_unknown_schema_versions() {
        let root = tempfile::tempdir().unwrap();
        let locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("schema-test").unwrap()).unwrap();
        let connection = Connection::open(locked.profile_database_path()).unwrap();
        connection
            .pragma_update(None, "user_version", PROFILE_SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);
        assert_eq!(
            locked.open_store(sealer()).err(),
            Some(ProfileStoreError::UnsupportedSchema)
        );
    }

    #[test]
    fn profile_schema_migrates_v1_to_v10_transactionally() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("migration-test").unwrap();
        let locked = LockedProfile::acquire(root.path(), profile_id).unwrap();
        let database_path = locked.profile_database_path();
        create_v1_profile_database(&database_path);
        let store = locked.open_store(sealer()).unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        for table in [
            "daemon_outbox",
            "daemon_cursor_observation",
            "daemon_inbox",
            "daemon_sender_counter",
            "daemon_message_history",
            "daemon_membership_outbox",
            "daemon_membership_inbox",
            "daemon_pending_join",
        ] {
            let exists: i64 = store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1);
        }
    }

    #[test]
    fn profile_schema_migrates_v9_to_v10_remote_event_journal() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("remote-event-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v10_to_v9(&connection);
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let connection = store.lock().unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let event_table: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_remote_event'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let consumer_table: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_adapter_consumer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(event_table, 1);
        assert_eq!(consumer_table, 1);
    }

    #[test]
    fn failed_v10_remote_event_migration_preserves_v9_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("remote-event-migration-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v10_to_v9(&connection);
        connection
            .execute("CREATE TABLE daemon_remote_event (sentinel INTEGER)", [])
            .unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let event_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_remote_event')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 9);
        assert_eq!(event_columns, 1);
    }

    #[test]
    fn profile_schema_migrates_v2_to_v10() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("message-history-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v7_to_v6(&connection);
        connection
            .execute("DROP TABLE daemon_message_history", [])
            .unwrap();
        connection
            .execute("DROP TABLE daemon_membership_outbox", [])
            .unwrap();
        connection
            .execute("DROP TABLE daemon_membership_inbox", [])
            .unwrap();
        connection
            .execute("DROP TABLE daemon_pending_join", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let history_exists: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_message_history'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let membership_exists: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_membership_outbox'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(history_exists, 1);
        assert_eq!(membership_exists, 1);
    }

    #[test]
    fn legacy_history_rehydrates_inbox_and_rejects_unrecoverable_outbox() {
        let inbound = conversation_fixture("legacy-inbox-history");
        for cursor in 1_u64..=101 {
            let identifier = u8::try_from(cursor).unwrap();
            stage_inbox_message(&inbound, cursor, identifier, 0, cursor);
            inbound
                .store
                .complete_inbox(inbound.conversation_id, cursor)
                .unwrap();
        }
        inbound
            .store
            .lock()
            .unwrap()
            .execute("DELETE FROM daemon_message_history", [])
            .unwrap();
        let inbound_root = inbound.root.path().to_path_buf();
        let inbound_profile = inbound.profile_id.clone();
        let inbound_conversation = inbound.conversation_id;
        drop(inbound.store);
        let reopened = LockedProfile::acquire(&inbound_root, inbound_profile)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let history = reopened.load_history(inbound_conversation, 0, 100).unwrap();
        assert_eq!(history.messages.len(), 100);
        assert!(history.has_more);
        assert_eq!(history.messages[0].cursor, 1);
        let final_page = reopened
            .load_history(inbound_conversation, 100, 100)
            .unwrap();
        assert_eq!(final_page.messages.len(), 1);
        assert_eq!(final_page.messages[0].cursor, 101);

        for (profile, accepted) in [
            ("legacy-ready-outbox", false),
            ("legacy-accepted-outbox", true),
        ] {
            let outbound = conversation_fixture(profile);
            let reservation = outbound
                .store
                .reserve_outbound_application(
                    outbound.conversation_id,
                    MessageId::from_bytes([82; MessageId::LENGTH]),
                    EnvelopeId::from_bytes([83; EnvelopeId::LENGTH]),
                )
                .unwrap();
            let message = application_message(82, 1, "legacy outbound");
            let envelope = relay_envelope(outbound.routing_id, 83, b"legacy-outbound-ciphertext");
            outbound
                .store
                .store_outbound_message(
                    reservation,
                    outbound.routing_id,
                    outbound.device_id,
                    0,
                    &message,
                )
                .unwrap();
            outbound
                .store
                .store_outbound_envelope(reservation, &envelope)
                .unwrap();
            if accepted {
                outbound
                    .store
                    .mark_outbox_accepted(&StoredRelayEnvelope::new(envelope, 1).unwrap())
                    .unwrap();
            }
            outbound
                .store
                .lock()
                .unwrap()
                .execute_batch(
                    "DELETE FROM daemon_message_history;
                     PRAGMA user_version = 2;",
                )
                .unwrap();
            let root = outbound.root.path().to_path_buf();
            let profile_id = outbound.profile_id.clone();
            let database_path = outbound.store.locked_profile.profile_database_path();
            drop(outbound.store);
            assert_eq!(
                LockedProfile::acquire(&root, profile_id)
                    .unwrap()
                    .open_store(sealer())
                    .err(),
                Some(ProfileStoreError::LegacyOutboundRecoveryUnsupported)
            );
            let connection = Connection::open(database_path).unwrap();
            let version: u32 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(version, 2);
        }
    }

    #[test]
    fn profile_schema_migrates_v3_to_v10_membership_journal() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("membership-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v7_to_v6(&connection);
        connection
            .execute("DROP TABLE daemon_membership_outbox", [])
            .unwrap();
        connection
            .execute("DROP TABLE daemon_membership_inbox", [])
            .unwrap();
        connection
            .execute("DROP TABLE daemon_pending_join", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 3).unwrap();
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let membership_exists: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_membership_outbox'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(membership_exists, 1);
    }

    #[test]
    fn profile_schema_migrates_v6_to_v10_with_replay_heads() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("replay-head-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v7_to_v6(&connection);
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let replay_head_columns: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*)
                 FROM pragma_table_info('daemon_conversation')
                 WHERE name = 'sealed_replay_head'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(replay_head_columns, 1);
    }

    #[test]
    fn v7_migration_fails_closed_for_nonzero_cursor_without_replay_head() {
        let fixture = conversation_fixture("replay-head-backfill");
        stage_inbox_message(&fixture, 1, 61, 0, 1);
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        let database_path = fixture.store.locked_profile.profile_database_path();
        let profile_id = fixture.profile_id.clone();
        let root_path = fixture.root.path().to_path_buf();
        drop(fixture.store);
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v7_to_v6(&connection);
        drop(connection);

        let store = LockedProfile::acquire(&root_path, profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();

        assert_eq!(
            store.load_conversation(fixture.conversation_id).err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn failed_v7_replay_head_migration_preserves_v6_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("replay-head-migration-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v7_to_v6(&connection);
        connection
            .execute(
                "ALTER TABLE daemon_conversation ADD COLUMN sealed_replay_head BLOB",
                [],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let replay_head_columns: i64 = connection
            .query_row(
                "SELECT count(*)
                 FROM pragma_table_info('daemon_conversation')
                 WHERE name = 'sealed_replay_head'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 6);
        assert_eq!(replay_head_columns, 1);
    }

    #[test]
    fn profile_schema_migrates_v7_to_v10_outbox_terminal_reasons() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("outbox-terminal-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v8_to_v7(&connection);
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let terminal_reason_columns: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_outbox')
                 WHERE name = 'terminal_reason'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(terminal_reason_columns, 1);
    }

    #[test]
    fn profile_schema_migrates_v8_to_v10_removed_terminal_reason() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("outbox-removed-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v9_to_v8(&connection);
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let connection = store.lock().unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_outbox'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert!(schema.contains("terminal_reason IN (1, 2)"));
    }

    #[test]
    fn failed_v9_removed_terminal_migration_preserves_v8_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("outbox-removed-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v9_to_v8(&connection);
        connection
            .execute("CREATE TABLE daemon_outbox_v8 (sentinel INTEGER)", [])
            .unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let tables: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name IN ('daemon_outbox', 'daemon_outbox_v8')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 8);
        assert_eq!(tables, 2);
    }

    #[test]
    fn failed_v8_outbox_terminal_migration_preserves_v7_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("outbox-terminal-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v8_to_v7(&connection);
        connection
            .execute(
                "ALTER TABLE daemon_outbox ADD COLUMN terminal_reason INTEGER",
                [],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
    }

    #[test]
    fn profile_schema_migrates_v5_to_v10_join_receipts() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("join-receipt-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v6_to_v5(&connection);
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let receipt_columns: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*)
                 FROM pragma_table_info('daemon_pending_join')
                 WHERE name IN (
                    'join_cursor',
                    'join_envelope_id',
                    'sealed_join_receipt'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(receipt_columns, 3);
    }

    #[test]
    fn failed_v6_join_receipt_migration_preserves_v5_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("join-receipt-migration-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v6_to_v5(&connection);
        connection
            .execute(
                "ALTER TABLE daemon_pending_join ADD COLUMN join_cursor INTEGER",
                [],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let receipt_columns: i64 = connection
            .query_row(
                "SELECT count(*)
                 FROM pragma_table_info('daemon_pending_join')
                 WHERE name IN (
                    'join_cursor',
                    'join_envelope_id',
                    'sealed_join_receipt'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 5);
        assert_eq!(receipt_columns, 1);
    }

    #[test]
    fn profile_schema_migrates_v4_to_v10_pending_joins() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("pending-join-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v5_to_v4(&connection);
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let pending_exists: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_pending_join'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(pending_exists, 1);
    }

    #[test]
    fn failed_v5_pending_join_migration_preserves_v4_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("pending-join-migration-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        downgrade_v5_to_v4(&connection);
        connection
            .execute("CREATE TABLE daemon_pending_join (sentinel INTEGER)", [])
            .unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let pending_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_pending_join')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 4);
        assert_eq!(pending_columns, 1);
    }

    #[test]
    fn failed_v4_membership_migration_preserves_v3_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("membership-migration-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute("DROP TABLE daemon_membership_outbox", [])
            .unwrap();
        connection
            .execute("DROP TABLE daemon_membership_inbox", [])
            .unwrap();
        connection
            .execute(
                "CREATE TABLE daemon_membership_outbox (sentinel INTEGER)",
                [],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 3).unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let membership_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_membership_outbox')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 3);
        assert_eq!(membership_columns, 1);
    }

    #[test]
    fn failed_v3_history_migration_preserves_v2_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("message-history-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute("DROP TABLE daemon_message_history", [])
            .unwrap();
        connection
            .execute("CREATE TABLE daemon_message_history (sentinel INTEGER)", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let history_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_message_history')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 2);
        assert_eq!(history_columns, 1);
    }

    #[test]
    fn failed_profile_schema_migration_preserves_v1() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("migration-rollback-test").unwrap();
        let locked = LockedProfile::acquire(root.path(), profile_id).unwrap();
        let database_path = locked.profile_database_path();
        create_v1_profile_database(&database_path);
        Connection::open(&database_path)
            .unwrap()
            .execute("CREATE TABLE daemon_outbox (sentinel INTEGER)", [])
            .unwrap();
        assert_eq!(
            locked.open_store(sealer()).err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let inbox_exists: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_inbox'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let outbox_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_outbox')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inbox_exists, 0);
        assert_eq!(outbox_columns, 1);
    }

    #[test]
    fn conversation_records_reopen_with_verified_sealed_state() {
        let root = tempfile::tempdir().unwrap();
        let store =
            LockedProfile::acquire(root.path(), ProfileId::parse("conversation-test").unwrap())
                .unwrap()
                .open_store(sealer())
                .unwrap();
        let identity = store.load_or_create_device().unwrap();
        let conversation_id = identity.generate_conversation_id().unwrap();
        let material = identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let binding = material.binding().clone();
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            0,
            vec![Member::new(
                identity.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let routing_id = RoutingId::from_bytes([9; RoutingId::LENGTH]);
        store
            .insert_conversation(routing_id, &material, &state, &[binding])
            .unwrap();
        assert_eq!(
            store.conversation_ids(None, 10).unwrap(),
            vec![conversation_id]
        );
        let encoded_state = encode_conversation_state(&state).unwrap();
        let encoded_binding = encode_device_credential_binding(material.binding()).unwrap();
        let (sealed_state, sealed_binding): (Vec<u8>, Vec<u8>) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT c.sealed_policy_state, b.sealed_binding
                 FROM daemon_conversation c
                 JOIN daemon_conversation_binding b
                   ON b.conversation_id = c.conversation_id
                 WHERE c.conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            !sealed_state
                .windows(encoded_state.len())
                .any(|window| window == encoded_state)
        );
        assert!(
            !sealed_binding
                .windows(encoded_binding.len())
                .any(|window| window == encoded_binding)
        );

        let reopened = store.load_conversation(conversation_id).unwrap();
        assert_eq!(reopened.routing_id, routing_id);
        assert_eq!(reopened.state, state);
        assert_eq!(reopened.bindings.len(), 1);
        assert_eq!(reopened.sender_counter, 0);
        assert_eq!(reopened.replay_cursor, 0);
        assert_eq!(
            reopened.signing_material.binding().device_id(),
            identity.device_id()
        );
        assert_eq!(
            store
                .insert_conversation(
                    routing_id,
                    &reopened.signing_material,
                    &reopened.state,
                    &[reopened.bindings[0].binding().clone()],
                )
                .unwrap_err(),
            ProfileStoreError::ConversationExists
        );
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation
                 SET routing_id = ?1
                 WHERE conversation_id = ?2",
                params![
                    RoutingId::from_bytes([10; RoutingId::LENGTH])
                        .as_bytes()
                        .as_slice(),
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            store.load_conversation(conversation_id).err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn a_claim_renews_the_lease_it_already_holds() {
        // The daemon attaches once and then claims repeatedly, always asking for a
        // full window from the current instant. Before renewal existed, the second
        // request exceeded the attach-time expiry and every claim after attachment
        // failed as stale, which stopped delivery entirely.
        let fixture = conversation_fixture("adapter-lease-renewal");
        let consumer = AdapterConsumerId::from_bytes([9; AdapterConsumerId::LENGTH]);
        let lease = AdapterLeaseId::from_bytes([9; AdapterLeaseId::LENGTH]);
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        fixture
            .store
            .acquire_adapter_consumer(consumer, lease, 1_000, 61_000)
            .unwrap();

        fixture
            .store
            .claim_remote_events(consumer, lease, 5_000, 65_000, 1)
            .expect("an active consumer must be able to extend its own lease");

        stage_remote_inbox_message(
            &fixture,
            1,
            1,
            DeviceId::from_bytes([44; DeviceId::LENGTH]),
            1,
        );
        let notification_id = NotificationId::from_bytes([9; NotificationId::LENGTH]);
        fixture
            .store
            .complete_inbox_with_notification(fixture.conversation_id, 1, notification_id)
            .unwrap();
        let claimed = fixture
            .store
            .claim_remote_events(consumer, lease, 62_000, 122_000, 1)
            .expect("a renewed lease must remain usable past its original expiry");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].event.notification_id, notification_id);

        // Renewal is not a way back in: a lease that already lapsed stays lapsed.
        let lapsed = AdapterLeaseId::from_bytes([10; AdapterLeaseId::LENGTH]);
        assert!(matches!(
            fixture
                .store
                .claim_remote_events(consumer, lapsed, 62_000, 122_000, 1),
            Err(ProfileStoreError::InvalidAdapterLease)
        ));
    }

    #[test]
    fn remote_events_are_suppressed_while_muted_and_claimed_after_enablement() {
        let fixture = conversation_fixture("remote-event-delivery");
        let remote_sender = DeviceId::from_bytes([44; DeviceId::LENGTH]);
        let first = stage_remote_inbox_message(&fixture, 1, 1, remote_sender, 1);
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                1,
                NotificationId::from_bytes([1; NotificationId::LENGTH]),
            )
            .unwrap();
        fixture
            .store
            .acquire_adapter_consumer(
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                1_000,
                2_000,
            )
            .unwrap();
        assert!(
            fixture
                .store
                .claim_remote_events(
                    AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                    AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                    1_000,
                    1_500,
                    10,
                )
                .unwrap()
                .is_empty()
        );
        let suppressed = fixture.store.load_remote_event_by_sequence(1).unwrap();
        assert_eq!(
            suppressed.notification_id,
            NotificationId::from_bytes([1; 16])
        );
        assert!(matches!(
            suppressed.payload,
            RemoteEventPayload::ApplicationMessage(ref message)
                if application_messages_equal(message, &first).unwrap()
        ));

        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        let second = stage_remote_inbox_message(&fixture, 2, 2, remote_sender, 2);
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                2,
                NotificationId::from_bytes([2; NotificationId::LENGTH]),
            )
            .unwrap();
        let claimed = fixture
            .store
            .claim_remote_events(
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                1_000,
                1_500,
                10,
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].event.sequence, 2);
        assert_eq!(
            claimed[0].event.notification_id,
            NotificationId::from_bytes([2; NotificationId::LENGTH])
        );
        assert!(matches!(
            claimed[0].event.payload,
            RemoteEventPayload::ApplicationMessage(ref message)
                if application_messages_equal(message, &second).unwrap()
        ));
        fixture
            .store
            .acknowledge_remote_event(
                claimed[0].event.notification_id,
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                claimed[0].lease_generation,
                1_100,
            )
            .unwrap();
        assert!(
            fixture
                .store
                .claim_remote_events(
                    AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                    AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                    1_100,
                    1_500,
                    10,
                )
                .unwrap()
                .is_empty()
        );
        fixture
            .store
            .acknowledge_remote_event(
                claimed[0].event.notification_id,
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                claimed[0].lease_generation,
                1_100,
            )
            .unwrap();
        assert_eq!(fixture.store.prune_terminal_remote_events(10).unwrap(), 2);
        assert_eq!(
            fixture.store.load_remote_event_by_sequence(1).err(),
            Some(ProfileStoreError::OperationNotFound)
        );
        stage_remote_inbox_message(&fixture, 3, 3, remote_sender, 3);
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                3,
                NotificationId::from_bytes([3; NotificationId::LENGTH]),
            )
            .unwrap();
        let after_prune = fixture
            .store
            .claim_remote_events(
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                1_200,
                1_400,
                10,
            )
            .unwrap();
        assert_eq!(after_prune.len(), 1);
        assert_eq!(after_prune[0].event.sequence, 3);
        let ConversationFixture {
            root,
            profile_id,
            store,
            ..
        } = fixture;
        drop(store);
        LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
    }

    #[test]
    fn remote_event_leases_expire_and_reject_stale_acknowledgment() {
        let fixture = conversation_fixture("remote-event-lease");
        let first_consumer = AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]);
        let first_lease = AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]);
        let second_consumer = AdapterConsumerId::from_bytes([2; AdapterConsumerId::LENGTH]);
        let second_lease = AdapterLeaseId::from_bytes([2; AdapterLeaseId::LENGTH]);
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        stage_remote_inbox_message(
            &fixture,
            1,
            1,
            DeviceId::from_bytes([44; DeviceId::LENGTH]),
            1,
        );
        let notification_id = NotificationId::from_bytes([1; NotificationId::LENGTH]);
        fixture
            .store
            .complete_inbox_with_notification(fixture.conversation_id, 1, notification_id)
            .unwrap();
        fixture
            .store
            .acquire_adapter_consumer(first_consumer, first_lease, 1_000, 2_000)
            .unwrap();
        let first_claim = fixture
            .store
            .claim_remote_events(first_consumer, first_lease, 1_000, 1_500, 1)
            .unwrap();
        assert_eq!(first_claim.len(), 1);
        assert_eq!(
            fixture
                .store
                .acquire_adapter_consumer(second_consumer, second_lease, 1_600, 2_100,),
            Err(ProfileStoreError::AdapterConsumerActive)
        );
        fixture
            .store
            .acquire_adapter_consumer(second_consumer, second_lease, 2_000, 2_500)
            .unwrap();
        let second_claim = fixture
            .store
            .claim_remote_events(second_consumer, second_lease, 2_000, 2_400, 1)
            .unwrap();
        assert_eq!(second_claim.len(), 1);
        assert_eq!(second_claim[0].event.notification_id, notification_id);
        assert_eq!(second_claim[0].lease_generation, 2);
        assert_eq!(
            fixture.store.acknowledge_remote_event(
                notification_id,
                first_consumer,
                first_lease,
                first_claim[0].lease_generation,
                2_000,
            ),
            Err(ProfileStoreError::InvalidAdapterLease)
        );
        fixture
            .store
            .release_remote_event(
                notification_id,
                second_consumer,
                second_lease,
                second_claim[0].lease_generation,
                2_100,
            )
            .unwrap();
        let third_claim = fixture
            .store
            .claim_remote_events(second_consumer, second_lease, 2_100, 2_400, 1)
            .unwrap();
        assert_eq!(third_claim.len(), 1);
        assert_eq!(third_claim[0].lease_generation, 3);
        fixture
            .store
            .acknowledge_remote_event(
                notification_id,
                second_consumer,
                second_lease,
                third_claim[0].lease_generation,
                2_200,
            )
            .unwrap();
    }

    #[test]
    fn remote_event_claims_are_recovered_after_daemon_restart() {
        let fixture = conversation_fixture("remote-event-restart");
        let conversation_id = fixture.conversation_id;
        fixture
            .store
            .set_adapter_delivery_enabled(conversation_id, true)
            .unwrap();
        stage_remote_inbox_message(
            &fixture,
            1,
            1,
            DeviceId::from_bytes([44; DeviceId::LENGTH]),
            1,
        );
        let notification_id = NotificationId::from_bytes([1; NotificationId::LENGTH]);
        fixture
            .store
            .complete_inbox_with_notification(conversation_id, 1, notification_id)
            .unwrap();
        fixture
            .store
            .acquire_adapter_consumer(
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                1_000,
                2_000,
            )
            .unwrap();
        let first = fixture
            .store
            .claim_remote_events(
                AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]),
                AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]),
                1_000,
                1_500,
                1,
            )
            .unwrap();
        assert_eq!(first[0].lease_generation, 1);

        let ConversationFixture {
            root,
            profile_id,
            store,
            ..
        } = fixture;
        drop(store);
        let reopened = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let consumer = AdapterConsumerId::from_bytes([2; AdapterConsumerId::LENGTH]);
        let lease = AdapterLeaseId::from_bytes([2; AdapterLeaseId::LENGTH]);
        reopened
            .acquire_adapter_consumer(consumer, lease, 2_000, 2_500)
            .unwrap();
        let recovered = reopened
            .claim_remote_events(consumer, lease, 2_000, 2_400, 1)
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].event.notification_id, notification_id);
        assert_eq!(recovered[0].lease_generation, 2);
    }

    #[test]
    fn remote_event_state_and_journal_deletion_tampering_fail_closed() {
        let fixture = conversation_fixture("remote-event-tampering");
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        stage_remote_inbox_message(
            &fixture,
            1,
            1,
            DeviceId::from_bytes([44; DeviceId::LENGTH]),
            1,
        );
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                1,
                NotificationId::from_bytes([1; NotificationId::LENGTH]),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_remote_event SET status = 3 WHERE event_sequence = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            fixture.store.load_remote_event_by_sequence(1).err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_remote_event SET status = 1 WHERE event_sequence = 1",
                [],
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM daemon_remote_event WHERE event_sequence = 1",
                [],
            )
            .unwrap();

        let ConversationFixture {
            root,
            profile_id,
            store,
            ..
        } = fixture;
        drop(store);
        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn local_application_echoes_do_not_create_remote_events() {
        let fixture = conversation_fixture("remote-event-local-echo");
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        stage_inbox_message(&fixture, 1, 1, 0, 1);
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                1,
                NotificationId::from_bytes([1; NotificationId::LENGTH]),
            )
            .unwrap();
        let (count, next_sequence): (i64, i64) = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                    (SELECT count(*) FROM daemon_remote_event),
                    next_remote_event_sequence
                 FROM daemon_profile
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(next_sequence, 1);
    }

    #[test]
    fn remote_event_delivery_policy_tampering_cannot_enable_delivery() {
        let fixture = conversation_fixture("remote-event-policy-tampering");
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation
                 SET sealed_adapter_delivery_policy =
                     zeroblob(length(sealed_adapter_delivery_policy))
                 WHERE conversation_id = ?1",
                params![fixture.conversation_id.as_bytes().as_slice()],
            )
            .unwrap();
        stage_remote_inbox_message(
            &fixture,
            1,
            1,
            DeviceId::from_bytes([44; DeviceId::LENGTH]),
            1,
        );
        assert_eq!(
            fixture.store.complete_inbox_with_notification(
                fixture.conversation_id,
                1,
                NotificationId::from_bytes([1; NotificationId::LENGTH]),
            ),
            Err(ProfileStoreError::CorruptData)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            0
        );
    }

    #[test]
    fn remote_membership_events_preserve_role_and_self_removal_semantics() {
        let (role_fixture, remote_administrator) = remote_membership_fixture("remote-role-event");
        role_fixture
            .store
            .set_adapter_delivery_enabled(role_fixture.conversation_id, true)
            .unwrap();
        complete_remote_membership_event(
            &role_fixture,
            remote_administrator,
            31,
            MembershipChange::ChangeRole(ChangeMemberRole::new(
                role_fixture.device_id,
                ConversationRole::Administrator,
            )),
        );
        let role_event = role_fixture.store.load_remote_event_by_sequence(1).unwrap();
        assert_eq!(role_event.sender, remote_administrator);
        assert!(matches!(
            role_event.payload,
            RemoteEventPayload::MemberRoleChanged {
                device_id,
                role: ConversationRole::Administrator
            } if device_id == role_fixture.device_id
        ));

        let (remove_fixture, remote_administrator) =
            remote_membership_fixture("remote-removal-event");
        remove_fixture
            .store
            .set_adapter_delivery_enabled(remove_fixture.conversation_id, true)
            .unwrap();
        complete_remote_membership_event(
            &remove_fixture,
            remote_administrator,
            32,
            MembershipChange::Remove(RemoveMember::new(remove_fixture.device_id)),
        );
        let removal_event = remove_fixture
            .store
            .load_remote_event_by_sequence(1)
            .unwrap();
        assert!(matches!(
            removal_event.payload,
            RemoteEventPayload::LocalAccessRemoved { device_id }
                if device_id == remove_fixture.device_id
        ));
    }

    #[test]
    fn remote_event_capacity_backpressures_before_advancing_replay() {
        let fixture = conversation_fixture("remote-event-capacity");
        let remote_sender = DeviceId::from_bytes([44; DeviceId::LENGTH]);
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        for cursor in 1..=MAX_PENDING_REMOTE_EVENTS_PER_CONVERSATION {
            let identifier = u8::try_from(cursor).unwrap();
            stage_remote_inbox_message(
                &fixture,
                u64::try_from(cursor).unwrap(),
                identifier,
                remote_sender,
                u64::try_from(cursor).unwrap(),
            );
            fixture
                .store
                .complete_inbox_with_notification(
                    fixture.conversation_id,
                    u64::try_from(cursor).unwrap(),
                    NotificationId::from_bytes([identifier; NotificationId::LENGTH]),
                )
                .unwrap();
        }
        let blocked_cursor = MAX_PENDING_REMOTE_EVENTS_PER_CONVERSATION + 1;
        let identifier = u8::try_from(blocked_cursor).unwrap();
        stage_remote_inbox_message(
            &fixture,
            u64::try_from(blocked_cursor).unwrap(),
            identifier,
            remote_sender,
            u64::try_from(blocked_cursor).unwrap(),
        );
        assert_eq!(
            fixture.store.complete_inbox_with_notification(
                fixture.conversation_id,
                u64::try_from(blocked_cursor).unwrap(),
                NotificationId::from_bytes([identifier; NotificationId::LENGTH]),
            ),
            Err(ProfileStoreError::RemoteEventCapacityExceeded)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            u64::try_from(MAX_PENDING_REMOTE_EVENTS_PER_CONVERSATION).unwrap()
        );
    }

    #[test]
    fn remote_event_byte_capacity_backpressures_below_the_count_limit() {
        let fixture = conversation_fixture("remote-event-byte-capacity");
        let remote_sender = DeviceId::from_bytes([44; DeviceId::LENGTH]);
        let body = "x".repeat(MAX_TEXT_BODY_BYTES);
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        let mut completed = 0_u64;
        let mut blocked = false;
        for cursor in 1_u64..=10 {
            let identifier = u8::try_from(cursor).unwrap();
            let envelope = StoredRelayEnvelope::new(
                relay_envelope(fixture.routing_id, identifier, &[identifier]),
                cursor,
            )
            .unwrap();
            fixture.store.record_inbox_envelope(&envelope).unwrap();
            let message = ApplicationMessage::new(
                ProtocolVersion::application_v1(),
                MessageId::from_bytes([identifier; MessageId::LENGTH]),
                cursor,
                1_700_000_000_000,
                None,
                ApplicationContent::text(&body).unwrap(),
            )
            .unwrap();
            fixture
                .store
                .save_inbox_message(fixture.conversation_id, cursor, remote_sender, 0, &message)
                .unwrap();
            match fixture.store.complete_inbox_with_notification(
                fixture.conversation_id,
                cursor,
                NotificationId::from_bytes([identifier; NotificationId::LENGTH]),
            ) {
                Ok(_) => completed = cursor,
                Err(ProfileStoreError::RemoteEventCapacityExceeded) => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("unexpected completion error: {error}"),
            }
        }
        assert!(blocked);
        assert!(completed > 0);
        assert!(completed < u64::try_from(MAX_PENDING_REMOTE_EVENTS_PER_CONVERSATION).unwrap());
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            completed
        );
    }

    #[test]
    fn remote_event_claims_are_fair_between_conversations() {
        let fixture = conversation_fixture("remote-event-fairness");
        let identity = fixture.store.load_or_create_device().unwrap();
        let second_conversation = identity.generate_conversation_id().unwrap();
        let second_routing = RoutingId::from_bytes([20; RoutingId::LENGTH]);
        let second_material = identity
            .create_conversation_signing_material(second_conversation)
            .unwrap();
        let second_state = ConversationState::new(
            ProtocolVersion::application_v1(),
            second_conversation,
            0,
            vec![Member::new(
                identity.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        fixture
            .store
            .insert_conversation(
                second_routing,
                &second_material,
                &second_state,
                &[second_material.binding().clone()],
            )
            .unwrap();
        fixture
            .store
            .set_adapter_delivery_enabled(fixture.conversation_id, true)
            .unwrap();
        fixture
            .store
            .set_adapter_delivery_enabled(second_conversation, true)
            .unwrap();
        let remote_sender = DeviceId::from_bytes([44; DeviceId::LENGTH]);

        stage_remote_inbox_message(&fixture, 1, 1, remote_sender, 1);
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                1,
                NotificationId::from_bytes([1; NotificationId::LENGTH]),
            )
            .unwrap();
        stage_remote_inbox_message(&fixture, 2, 2, remote_sender, 2);
        fixture
            .store
            .complete_inbox_with_notification(
                fixture.conversation_id,
                2,
                NotificationId::from_bytes([2; NotificationId::LENGTH]),
            )
            .unwrap();
        stage_remote_inbox_for(
            &fixture.store,
            second_conversation,
            second_routing,
            1,
            3,
            remote_sender,
            1,
        );
        fixture
            .store
            .complete_inbox_with_notification(
                second_conversation,
                1,
                NotificationId::from_bytes([3; NotificationId::LENGTH]),
            )
            .unwrap();

        let consumer = AdapterConsumerId::from_bytes([1; AdapterConsumerId::LENGTH]);
        let lease = AdapterLeaseId::from_bytes([1; AdapterLeaseId::LENGTH]);
        fixture
            .store
            .acquire_adapter_consumer(consumer, lease, 1_000, 2_000)
            .unwrap();
        let claimed = fixture
            .store
            .claim_remote_events(consumer, lease, 1_000, 1_500, 3)
            .unwrap();
        assert_eq!(
            claimed
                .iter()
                .map(|event| event.event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 3, 2]
        );
    }

    use KonclaveClientLibrary::RelayClient;
}
