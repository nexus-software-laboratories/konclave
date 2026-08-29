use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveDomainCore::{
    ApplicationContent, CollaborationPolicyDigest, CollaborationPolicyProposalId,
    CollaborationPolicyResponseOutcome, ConversationId, MessageId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{
    MAX_STORED_COLLABORATION_POLICY_BINDINGS, ProfileId, ProfileStore, ProfileStoreError,
    SealedBlob, SecretRecordContext, SecretRecordKind, collaboration_policy_binding_context,
    encode_collaboration_policy_binding, to_sql_integer,
};

const MAX_COLLABORATION_POLICY_OPERATIONS: usize = 2_048;
const COLLABORATION_POLICY_OPERATION_SCHEMA_VERSION: u32 = 17;
const OPERATION_KIND_PROPOSAL: i64 = 1;
const OPERATION_KIND_ACCEPTANCE: i64 = 2;
const OPERATION_KIND_REJECTION: i64 = 3;
const OPERATION_KIND_REVOCATION: i64 = 4;
const OPERATION_RECORD_VERSION: u8 = 1;
const OPERATION_RECORD_BYTES: usize = 150;
const OPERATION_STATE_VERSION: u8 = 1;
const OPERATION_STATE_BYTES: usize = 9;
const MAX_SEALED_OPERATION_RECORD_BYTES: usize = OPERATION_RECORD_BYTES + 64;
const MAX_SEALED_OPERATION_STATE_BYTES: usize = OPERATION_STATE_BYTES + 64;

pub(crate) struct CollaborationPolicyActivationOperation<'a> {
    pub(crate) conversation_id: ConversationId,
    pub(crate) message_id: MessageId,
    pub(crate) proposal_id: CollaborationPolicyProposalId,
    pub(crate) source_proposal_message_id: Option<MessageId>,
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) replaces_policy_digest: Option<CollaborationPolicyDigest>,
    pub(crate) canonical_bundle: &'a [u8],
    pub(crate) activated_at_unix_milliseconds: u64,
    pub(crate) is_acceptance: bool,
}

pub(crate) struct CollaborationPolicyResponseOperation {
    pub(crate) source_proposal_message_id: MessageId,
    pub(crate) binding_changed: bool,
}

pub(crate) struct CollaborationPolicyProposalOperation {
    pub(crate) policy_digest: CollaborationPolicyDigest,
    pub(crate) replaces_policy_digest: Option<CollaborationPolicyDigest>,
    pub(crate) binding_changed: bool,
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
            "CREATE TABLE daemon_collaboration_policy_operation (
                conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 32),
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
                proposal_id BLOB CHECK (
                    proposal_id IS NULL OR length(proposal_id) = 16
                ),
                source_proposal_message_id BLOB CHECK (
                    source_proposal_message_id IS NULL
                    OR length(source_proposal_message_id) = 16
                ),
                policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
                replaces_policy_digest BLOB CHECK (
                    replaces_policy_digest IS NULL
                    OR length(replaces_policy_digest) = 32
                ),
                binding_changed INTEGER NOT NULL CHECK (binding_changed IN (0, 1)),
                sealed_operation BLOB NOT NULL,
                PRIMARY KEY (conversation_id, message_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                CHECK (
                    (kind = 1
                        AND proposal_id IS NOT NULL
                        AND source_proposal_message_id IS NULL)
                    OR
                    (kind = 2
                        AND proposal_id IS NOT NULL
                        AND source_proposal_message_id IS NOT NULL)
                    OR
                    (kind = 3
                        AND proposal_id IS NOT NULL
                        AND source_proposal_message_id IS NOT NULL
                        AND replaces_policy_digest IS NULL
                        AND binding_changed = 0)
                    OR
                    (kind = 4
                        AND proposal_id IS NULL
                        AND source_proposal_message_id IS NULL
                        AND replaces_policy_digest IS NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_collaboration_policy_operation_proposal_idx
                ON daemon_collaboration_policy_operation(
                    conversation_id,
                    proposal_id,
                    kind
                );
             CREATE TABLE daemon_collaboration_policy_operation_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                sealed_state BLOB NOT NULL
             );",
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    let changed = transaction
        .execute(
            "INSERT INTO daemon_collaboration_policy_operation_state (
                singleton_id,
                sealed_state
             ) VALUES (1, ?1)",
            params![sealed_initial_state.as_bytes()],
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    if changed != 1 {
        return Err(ProfileStoreError::Storage);
    }
    if let Some(migrated_device_identity) = migrated_device_identity {
        let changed = transaction
            .execute(
                "UPDATE daemon_profile
                 SET sealed_device_identity = ?1
                 WHERE singleton_id = 1 AND sealed_device_identity IS NOT NULL",
                params![migrated_device_identity.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::CorruptData);
        }
    }
    transaction
        .pragma_update(
            None,
            "user_version",
            COLLABORATION_POLICY_OPERATION_SCHEMA_VERSION,
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    transaction.commit().map_err(|_| ProfileStoreError::Storage)
}

impl ProfileStore {
    pub(super) fn initialize_collaboration_policy_operation_schema(
        &self,
        source_version: u32,
    ) -> Result<(), ProfileStoreError> {
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
        let current_version: u32 = self
            .lock()?
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        if current_version >= COLLABORATION_POLICY_OPERATION_SCHEMA_VERSION {
            return Ok(());
        }
        if current_version != 16 {
            return Err(ProfileStoreError::UnsupportedSchema);
        }
        let migrated_identity = match opened_identity {
            Some((identity, floor)) => {
                if floor > source_version || floor >= COLLABORATION_POLICY_OPERATION_SCHEMA_VERSION
                {
                    return Err(ProfileStoreError::CorruptData);
                }
                Some(
                    identity
                        .seal_with_profile_schema_floor(
                            &self.sealer,
                            self.locked_profile.profile_id.as_bytes(),
                            COLLABORATION_POLICY_OPERATION_SCHEMA_VERSION,
                        )
                        .map_err(|_| ProfileStoreError::Cryptographic)?,
                )
            }
            None => None,
        };
        let sealed_initial_state = self.seal_collaboration_policy_operation_state(0)?;
        let connection = self.lock()?;
        initialize_schema(
            &connection,
            &sealed_initial_state,
            migrated_identity.as_ref(),
        )
    }

    pub(super) fn verify_collaboration_policy_operations(&self) -> Result<(), ProfileStoreError> {
        let metadata = {
            let connection = self.lock()?;
            let sealed_state = self.load_collaboration_policy_operation_state(&connection)?;
            let committed_count = self.open_collaboration_policy_operation_state(sealed_state)?;
            let actual_count = collaboration_policy_operation_count(&connection)?;
            if committed_count != actual_count || actual_count > MAX_COLLABORATION_POLICY_OPERATIONS
            {
                return Err(ProfileStoreError::CorruptData);
            }
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(message_id) = 16 THEN message_id END,
                        kind,
                        typeof(proposal_id),
                        length(proposal_id),
                        CASE
                            WHEN typeof(proposal_id) = 'blob'
                                AND length(proposal_id) = 16
                            THEN proposal_id
                        END,
                        typeof(source_proposal_message_id),
                        length(source_proposal_message_id),
                        CASE
                            WHEN typeof(source_proposal_message_id) = 'blob'
                                AND length(source_proposal_message_id) = 16
                            THEN source_proposal_message_id
                        END,
                        typeof(replaces_policy_digest),
                        length(replaces_policy_digest),
                        CASE
                            WHEN typeof(replaces_policy_digest) = 'blob'
                                AND length(replaces_policy_digest) = 32
                            THEN replaces_policy_digest
                        END,
                        CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                        binding_changed,
                        length(sealed_operation)
                     FROM daemon_collaboration_policy_operation
                     ORDER BY conversation_id, message_id",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], operation_metadata_from_row)
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for metadata in metadata {
            self.verify_collaboration_policy_operation(metadata)?;
        }
        Ok(())
    }

    pub(crate) fn collaboration_policy_response_operation(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        proposal_id: CollaborationPolicyProposalId,
        policy_digest: CollaborationPolicyDigest,
        outcome: CollaborationPolicyResponseOutcome,
    ) -> Result<Option<CollaborationPolicyResponseOperation>, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let connection = self.lock()?;
        let Some(metadata) = load_operation_metadata(&connection, conversation_id, message_id)?
        else {
            return Ok(None);
        };
        let stored = decode_operation_metadata(metadata)?;
        self.verify_collaboration_policy_operation_seal(&connection, &stored)?;
        let expected_kind = match outcome {
            CollaborationPolicyResponseOutcome::Accepted => OPERATION_KIND_ACCEPTANCE,
            CollaborationPolicyResponseOutcome::Rejected => OPERATION_KIND_REJECTION,
        };
        if stored.kind != expected_kind
            || stored.proposal_id != Some(proposal_id)
            || stored.policy_digest != policy_digest
        {
            return Err(ProfileStoreError::CollaborationPolicyProposalConflict);
        }
        Ok(Some(CollaborationPolicyResponseOperation {
            source_proposal_message_id: stored
                .source_proposal_message_id
                .ok_or(ProfileStoreError::CorruptData)?,
            binding_changed: stored.binding_changed,
        }))
    }

    pub(crate) fn collaboration_policy_proposal_operation(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        proposal_id: CollaborationPolicyProposalId,
    ) -> Result<CollaborationPolicyProposalOperation, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let connection = self.lock()?;
        let metadata = load_operation_metadata(&connection, conversation_id, message_id)?
            .ok_or(ProfileStoreError::CollaborationPolicyProposalNotFound)?;
        let stored = decode_operation_metadata(metadata)?;
        self.verify_collaboration_policy_operation_seal(&connection, &stored)?;
        if stored.kind != OPERATION_KIND_PROPOSAL
            || stored.proposal_id != Some(proposal_id)
            || stored.source_proposal_message_id.is_some()
        {
            return Err(ProfileStoreError::CollaborationPolicyProposalConflict);
        }
        Ok(CollaborationPolicyProposalOperation {
            policy_digest: stored.policy_digest,
            replaces_policy_digest: stored.replaces_policy_digest,
            binding_changed: stored.binding_changed,
        })
    }

    pub(super) fn collaboration_policy_operation_reserves_message_id(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<bool, ProfileStoreError> {
        collaboration_policy_operation_exists(connection, conversation_id, message_id)
    }

    pub(super) fn verify_outbound_collaboration_policy_operation(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        message_id: MessageId,
        content: &ApplicationContent,
        reply_to: Option<MessageId>,
    ) -> Result<(), ProfileStoreError> {
        let metadata = load_operation_metadata(connection, conversation_id, message_id)?
            .ok_or(ProfileStoreError::CollaborationPolicyProposalConflict)?;
        let stored = decode_operation_metadata(metadata)?;
        self.verify_collaboration_policy_operation_seal(connection, &stored)?;
        let matches = match (stored.kind, content) {
            (
                OPERATION_KIND_PROPOSAL,
                ApplicationContent::CollaborationPolicyProposal(proposal),
            ) => {
                stored.proposal_id == Some(proposal.proposal_id())
                    && stored.source_proposal_message_id.is_none()
                    && stored.policy_digest == proposal.policy_digest()
                    && stored.replaces_policy_digest == proposal.replaces_policy_digest()
                    && reply_to.is_none()
            }
            (
                OPERATION_KIND_ACCEPTANCE | OPERATION_KIND_REJECTION,
                ApplicationContent::CollaborationPolicyResponse(response),
            ) => {
                let expected_outcome = if stored.kind == OPERATION_KIND_ACCEPTANCE {
                    CollaborationPolicyResponseOutcome::Accepted
                } else {
                    CollaborationPolicyResponseOutcome::Rejected
                };
                stored.proposal_id == Some(response.proposal_id())
                    && stored.policy_digest == response.policy_digest()
                    && response.outcome() == expected_outcome
                    && reply_to == stored.source_proposal_message_id
            }
            (
                OPERATION_KIND_REVOCATION,
                ApplicationContent::CollaborationPolicyRevocation(revocation),
            ) => {
                stored.proposal_id.is_none()
                    && stored.source_proposal_message_id.is_none()
                    && stored.policy_digest == revocation.policy_digest()
                    && stored.replaces_policy_digest.is_none()
                    && reply_to.is_none()
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(ProfileStoreError::CollaborationPolicyProposalConflict)
        }
    }

    pub(crate) fn apply_collaboration_policy_activation_operation(
        &self,
        operation: CollaborationPolicyActivationOperation<'_>,
    ) -> Result<bool, ProfileStoreError> {
        let expected_source_message = if operation.is_acceptance {
            operation.source_proposal_message_id
        } else if operation.source_proposal_message_id.is_none() {
            None
        } else {
            return Err(ProfileStoreError::CorruptData);
        };
        if operation.is_acceptance && expected_source_message.is_none() {
            return Err(ProfileStoreError::CorruptData);
        }
        let stored_digest = self.store_collaboration_policy_bundle(operation.canonical_bundle)?;
        if stored_digest != operation.policy_digest {
            return Err(ProfileStoreError::CorruptData);
        }
        self.conversation_routing_id(operation.conversation_id)?;
        let binding = encode_collaboration_policy_binding(
            operation.conversation_id,
            operation.policy_digest,
            operation.activated_at_unix_milliseconds,
        );
        let sealed_binding = self
            .sealer
            .seal(
                &collaboration_policy_binding_context(
                    &self.locked_profile.profile_id,
                    operation.conversation_id,
                    operation.policy_digest,
                )?,
                &binding,
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let kind = if operation.is_acceptance {
            OPERATION_KIND_ACCEPTANCE
        } else {
            OPERATION_KIND_PROPOSAL
        };
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some(binding_changed) = self.existing_collaboration_policy_operation(
            &transaction,
            operation.conversation_id,
            operation.message_id,
            kind,
            Some(operation.proposal_id),
            expected_source_message,
            operation.policy_digest,
            operation.replaces_policy_digest,
        )? {
            return Ok(binding_changed);
        }
        self.require_collaboration_policy_operation_capacity(&transaction)?;
        let current_digest = current_policy_digest(&transaction, operation.conversation_id)?;
        if current_digest != operation.replaces_policy_digest {
            return Err(ProfileStoreError::CollaborationPolicyReplacementMismatch);
        }
        let binding_changed = if current_digest == Some(operation.policy_digest) {
            false
        } else {
            self.require_collaboration_policy_binding_capacity(
                &transaction,
                operation.conversation_id,
                current_digest.is_some(),
            )?;
            transaction
                .execute(
                    "INSERT INTO daemon_collaboration_policy_binding (
                    conversation_id,
                    policy_digest,
                    activated_at_unix_milliseconds,
                    sealed_binding
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(conversation_id) DO UPDATE
                 SET policy_digest = excluded.policy_digest,
                     activated_at_unix_milliseconds =
                        excluded.activated_at_unix_milliseconds,
                     sealed_binding = excluded.sealed_binding",
                    params![
                        operation.conversation_id.as_bytes().as_slice(),
                        operation.policy_digest.as_bytes().as_slice(),
                        to_sql_integer(operation.activated_at_unix_milliseconds)?,
                        sealed_binding.as_bytes()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            true
        };
        self.insert_collaboration_policy_operation(
            &transaction,
            operation.conversation_id,
            operation.message_id,
            kind,
            Some(operation.proposal_id),
            expected_source_message,
            operation.policy_digest,
            operation.replaces_policy_digest,
            binding_changed,
        )?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(binding_changed)
    }

    pub(crate) fn apply_collaboration_policy_rejection_operation(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        proposal_id: CollaborationPolicyProposalId,
        source_proposal_message_id: MessageId,
        policy_digest: CollaborationPolicyDigest,
    ) -> Result<bool, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some(binding_changed) = self.existing_collaboration_policy_operation(
            &transaction,
            conversation_id,
            message_id,
            OPERATION_KIND_REJECTION,
            Some(proposal_id),
            Some(source_proposal_message_id),
            policy_digest,
            None,
        )? {
            return Ok(binding_changed);
        }
        self.require_collaboration_policy_operation_capacity(&transaction)?;
        self.insert_collaboration_policy_operation(
            &transaction,
            conversation_id,
            message_id,
            OPERATION_KIND_REJECTION,
            Some(proposal_id),
            Some(source_proposal_message_id),
            policy_digest,
            None,
            false,
        )?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(false)
    }

    pub(crate) fn apply_collaboration_policy_revocation_operation(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        policy_digest: CollaborationPolicyDigest,
    ) -> Result<bool, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some(binding_changed) = self.existing_collaboration_policy_operation(
            &transaction,
            conversation_id,
            message_id,
            OPERATION_KIND_REVOCATION,
            None,
            None,
            policy_digest,
            None,
        )? {
            return Ok(binding_changed);
        }
        self.require_collaboration_policy_operation_capacity(&transaction)?;
        let current_digest = current_policy_digest(&transaction, conversation_id)?;
        let binding_changed = match current_digest {
            Some(current) if current == policy_digest => {
                let changed = transaction
                    .execute(
                        "DELETE FROM daemon_collaboration_policy_binding
                         WHERE conversation_id = ?1 AND policy_digest = ?2",
                        params![
                            conversation_id.as_bytes().as_slice(),
                            policy_digest.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if changed != 1 {
                    return Err(ProfileStoreError::CorruptData);
                }
                true
            }
            Some(_) => return Err(ProfileStoreError::CollaborationPolicyReplacementMismatch),
            None => false,
        };
        self.insert_collaboration_policy_operation(
            &transaction,
            conversation_id,
            message_id,
            OPERATION_KIND_REVOCATION,
            None,
            None,
            policy_digest,
            None,
            binding_changed,
        )?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(binding_changed)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "terminal policy-operation identity remains explicit"
    )]
    fn existing_collaboration_policy_operation(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        message_id: MessageId,
        kind: i64,
        proposal_id: Option<CollaborationPolicyProposalId>,
        source_proposal_message_id: Option<MessageId>,
        policy_digest: CollaborationPolicyDigest,
        replaces_policy_digest: Option<CollaborationPolicyDigest>,
    ) -> Result<Option<bool>, ProfileStoreError> {
        let metadata = load_operation_metadata(connection, conversation_id, message_id)?;
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        let stored = decode_operation_metadata(metadata)?;
        self.verify_collaboration_policy_operation_seal(connection, &stored)?;
        if stored.kind != kind
            || stored.proposal_id != proposal_id
            || stored.source_proposal_message_id != source_proposal_message_id
            || stored.policy_digest != policy_digest
            || stored.replaces_policy_digest != replaces_policy_digest
        {
            return Err(ProfileStoreError::CollaborationPolicyProposalConflict);
        }
        Ok(Some(stored.binding_changed))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "terminal policy-operation identity remains explicit"
    )]
    fn insert_collaboration_policy_operation(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        message_id: MessageId,
        kind: i64,
        proposal_id: Option<CollaborationPolicyProposalId>,
        source_proposal_message_id: Option<MessageId>,
        policy_digest: CollaborationPolicyDigest,
        replaces_policy_digest: Option<CollaborationPolicyDigest>,
        binding_changed: bool,
    ) -> Result<(), ProfileStoreError> {
        require_application_message_id_available(connection, conversation_id, message_id)?;
        let operation = DecodedOperation {
            conversation_id,
            message_id,
            kind,
            proposal_id,
            source_proposal_message_id,
            policy_digest,
            replaces_policy_digest,
            binding_changed,
        };
        let encoded = encode_operation_record(&operation)?;
        let sealed_operation = self
            .sealer
            .seal(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    message_id,
                )?,
                &encoded,
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let sealed_state = self.advance_collaboration_policy_operation_state(connection)?;
        let proposal_id = proposal_id.map(|value| value.into_bytes());
        let source_proposal_message_id = source_proposal_message_id.map(|value| value.into_bytes());
        let replaces_policy_digest = replaces_policy_digest.map(|value| value.into_bytes());
        let changed = connection
            .execute(
                "INSERT INTO daemon_collaboration_policy_operation (
                    conversation_id,
                    message_id,
                    kind,
                    proposal_id,
                    source_proposal_message_id,
                    policy_digest,
                    replaces_policy_digest,
                    binding_changed,
                    sealed_operation
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice(),
                    kind,
                    proposal_id.as_ref().map(<[u8; 16]>::as_slice),
                    source_proposal_message_id
                        .as_ref()
                        .map(<[u8; 16]>::as_slice),
                    policy_digest.as_bytes().as_slice(),
                    replaces_policy_digest.as_ref().map(<[u8; 32]>::as_slice),
                    i64::from(binding_changed),
                    sealed_operation.as_bytes()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::Storage);
        }
        let changed = connection
            .execute(
                "UPDATE daemon_collaboration_policy_operation_state
                 SET sealed_state = ?1
                 WHERE singleton_id = 1",
                params![sealed_state.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }

    fn require_collaboration_policy_operation_capacity(
        &self,
        connection: &Connection,
    ) -> Result<(), ProfileStoreError> {
        if collaboration_policy_operation_count(connection)? >= MAX_COLLABORATION_POLICY_OPERATIONS
        {
            Err(ProfileStoreError::CollaborationPolicyCapacityExceeded)
        } else {
            Ok(())
        }
    }

    fn require_collaboration_policy_binding_capacity(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        binding_exists: bool,
    ) -> Result<(), ProfileStoreError> {
        if binding_exists {
            return Ok(());
        }
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM daemon_collaboration_policy_binding",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if count < 0
            || usize::try_from(count)
                .ok()
                .is_none_or(|count| count >= MAX_STORED_COLLABORATION_POLICY_BINDINGS)
        {
            return Err(ProfileStoreError::CollaborationPolicyCapacityExceeded);
        }
        let existing: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM daemon_collaboration_policy_binding
                    WHERE conversation_id = ?1
                 )",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if existing {
            Err(ProfileStoreError::CorruptData)
        } else {
            Ok(())
        }
    }

    fn advance_collaboration_policy_operation_state(
        &self,
        connection: &Connection,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let sealed_state = self.load_collaboration_policy_operation_state(connection)?;
        let committed_count = self.open_collaboration_policy_operation_state(sealed_state)?;
        let actual_count = collaboration_policy_operation_count(connection)?;
        if committed_count != actual_count {
            return Err(ProfileStoreError::CorruptData);
        }
        self.seal_collaboration_policy_operation_state(
            actual_count
                .checked_add(1)
                .ok_or(ProfileStoreError::CollaborationPolicyCapacityExceeded)?,
        )
    }

    fn load_collaboration_policy_operation_state(
        &self,
        connection: &Connection,
    ) -> Result<Vec<u8>, ProfileStoreError> {
        let length: Option<Option<i64>> = connection
            .query_row(
                "SELECT CASE
                    WHEN sealed_state IS NULL THEN NULL
                    ELSE length(sealed_state)
                 END
                 FROM daemon_collaboration_policy_operation_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let length = length
            .ok_or(ProfileStoreError::CorruptData)?
            .ok_or(ProfileStoreError::CorruptData)?;
        validate_sealed_length(length, MAX_SEALED_OPERATION_STATE_BYTES)?;
        let sealed_state: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_collaboration_policy_operation_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(sealed_state)
    }

    fn seal_collaboration_policy_operation_state(
        &self,
        record_count: usize,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let encoded = encode_operation_state(record_count)?;
        self.sealer
            .seal(
                &operation_state_context(&self.locked_profile.profile_id)?,
                &encoded,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_collaboration_policy_operation_state(
        &self,
        sealed_state: Vec<u8>,
    ) -> Result<usize, ProfileStoreError> {
        validate_sealed_bytes(&sealed_state, MAX_SEALED_OPERATION_STATE_BYTES)?;
        let sealed_state =
            SealedBlob::from_bytes(sealed_state).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &operation_state_context(&self.locked_profile.profile_id)?,
                &sealed_state,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        decode_operation_state(&plaintext)
    }

    fn verify_collaboration_policy_operation(
        &self,
        metadata: OperationMetadata,
    ) -> Result<(), ProfileStoreError> {
        let decoded = decode_operation_metadata(metadata)?;
        let connection = self.lock()?;
        self.verify_collaboration_policy_operation_seal(&connection, &decoded)
    }

    fn verify_collaboration_policy_operation_seal(
        &self,
        connection: &Connection,
        operation: &DecodedOperation,
    ) -> Result<(), ProfileStoreError> {
        let length: i64 = connection
            .query_row(
                "SELECT length(sealed_operation)
                 FROM daemon_collaboration_policy_operation
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    operation.conversation_id.as_bytes().as_slice(),
                    operation.message_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let expected_length = validate_sealed_length(length, MAX_SEALED_OPERATION_RECORD_BYTES)?;
        let sealed_operation: Vec<u8> = connection
            .query_row(
                "SELECT sealed_operation
                 FROM daemon_collaboration_policy_operation
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    operation.conversation_id.as_bytes().as_slice(),
                    operation.message_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed_operation.len() != expected_length {
            return Err(ProfileStoreError::CorruptData);
        }
        let sealed_operation =
            SealedBlob::from_bytes(sealed_operation).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    operation.conversation_id,
                    operation.message_id,
                )?,
                &sealed_operation,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let expected = encode_operation_record(operation)?;
        if plaintext.as_slice() == expected.as_slice() {
            Ok(())
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }
}

fn current_policy_digest(
    connection: &Connection,
    conversation_id: ConversationId,
) -> Result<Option<CollaborationPolicyDigest>, ProfileStoreError> {
    let digest: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(policy_digest) = 32 THEN policy_digest END
             FROM daemon_collaboration_policy_binding
             WHERE conversation_id = ?1",
            params![conversation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ProfileStoreError::Storage)?;
    match digest {
        None => Ok(None),
        Some(Some(digest)) => CollaborationPolicyDigest::from_slice(&digest)
            .map(Some)
            .map_err(|_| ProfileStoreError::CorruptData),
        Some(None) => Err(ProfileStoreError::CorruptData),
    }
}

fn load_operation_metadata(
    connection: &Connection,
    conversation_id: ConversationId,
    message_id: MessageId,
) -> Result<Option<OperationMetadata>, ProfileStoreError> {
    connection
        .query_row(
            "SELECT
                CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                CASE WHEN length(message_id) = 16 THEN message_id END,
                kind,
                typeof(proposal_id),
                length(proposal_id),
                CASE
                    WHEN typeof(proposal_id) = 'blob' AND length(proposal_id) = 16
                    THEN proposal_id
                END,
                typeof(source_proposal_message_id),
                length(source_proposal_message_id),
                CASE
                    WHEN typeof(source_proposal_message_id) = 'blob'
                        AND length(source_proposal_message_id) = 16
                    THEN source_proposal_message_id
                END,
                typeof(replaces_policy_digest),
                length(replaces_policy_digest),
                CASE
                    WHEN typeof(replaces_policy_digest) = 'blob'
                        AND length(replaces_policy_digest) = 32
                    THEN replaces_policy_digest
                END,
                CASE WHEN length(policy_digest) = 32 THEN policy_digest END,
                binding_changed,
                length(sealed_operation)
             FROM daemon_collaboration_policy_operation
             WHERE conversation_id = ?1 AND message_id = ?2",
            params![
                conversation_id.as_bytes().as_slice(),
                message_id.as_bytes().as_slice()
            ],
            operation_metadata_from_row,
        )
        .optional()
        .map_err(|_| ProfileStoreError::Storage)
}

fn operation_metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationMetadata> {
    Ok(OperationMetadata {
        conversation_id: row.get(0)?,
        message_id: row.get(1)?,
        kind: row.get(2)?,
        proposal_id_storage_type: row.get(3)?,
        proposal_id_length: row.get(4)?,
        proposal_id: row.get(5)?,
        source_message_storage_type: row.get(6)?,
        source_message_length: row.get(7)?,
        source_proposal_message_id: row.get(8)?,
        replaces_digest_storage_type: row.get(9)?,
        replaces_digest_length: row.get(10)?,
        replaces_policy_digest: row.get(11)?,
        policy_digest: row.get(12)?,
        binding_changed: row.get(13)?,
        sealed_operation_length: row.get(14)?,
    })
}

fn decode_operation_metadata(
    metadata: OperationMetadata,
) -> Result<DecodedOperation, ProfileStoreError> {
    let conversation_id = ConversationId::from_slice(
        &metadata
            .conversation_id
            .ok_or(ProfileStoreError::CorruptData)?,
    )
    .map_err(|_| ProfileStoreError::CorruptData)?;
    let message_id =
        MessageId::from_slice(&metadata.message_id.ok_or(ProfileStoreError::CorruptData)?)
            .map_err(|_| ProfileStoreError::CorruptData)?;
    let proposal_id = decode_optional_fixed(
        &metadata.proposal_id_storage_type,
        metadata.proposal_id_length,
        metadata.proposal_id,
        CollaborationPolicyProposalId::LENGTH,
    )?
    .map(|value| CollaborationPolicyProposalId::from_slice(&value))
    .transpose()
    .map_err(|_| ProfileStoreError::CorruptData)?;
    let source_proposal_message_id = decode_optional_fixed(
        &metadata.source_message_storage_type,
        metadata.source_message_length,
        metadata.source_proposal_message_id,
        MessageId::LENGTH,
    )?
    .map(|value| MessageId::from_slice(&value))
    .transpose()
    .map_err(|_| ProfileStoreError::CorruptData)?;
    let replaces_policy_digest = decode_optional_fixed(
        &metadata.replaces_digest_storage_type,
        metadata.replaces_digest_length,
        metadata.replaces_policy_digest,
        CollaborationPolicyDigest::LENGTH,
    )?
    .map(|value| CollaborationPolicyDigest::from_slice(&value))
    .transpose()
    .map_err(|_| ProfileStoreError::CorruptData)?;
    let policy_digest = CollaborationPolicyDigest::from_slice(
        &metadata
            .policy_digest
            .ok_or(ProfileStoreError::CorruptData)?,
    )
    .map_err(|_| ProfileStoreError::CorruptData)?;
    let binding_changed = match metadata.binding_changed {
        0 => false,
        1 => true,
        _ => return Err(ProfileStoreError::CorruptData),
    };
    validate_sealed_length(
        metadata.sealed_operation_length,
        MAX_SEALED_OPERATION_RECORD_BYTES,
    )?;
    Ok(DecodedOperation {
        conversation_id,
        message_id,
        kind: metadata.kind,
        proposal_id,
        source_proposal_message_id,
        policy_digest,
        replaces_policy_digest,
        binding_changed,
    })
}

fn decode_optional_fixed(
    storage_type: &str,
    length: Option<i64>,
    value: Option<Vec<u8>>,
    expected: usize,
) -> Result<Option<Vec<u8>>, ProfileStoreError> {
    match (storage_type, length, value) {
        ("null", None, None) => Ok(None),
        ("blob", Some(length), Some(value))
            if usize::try_from(length).ok() == Some(expected) && value.len() == expected =>
        {
            Ok(Some(value))
        }
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn require_application_message_id_available(
    connection: &Connection,
    conversation_id: ConversationId,
    message_id: MessageId,
) -> Result<(), ProfileStoreError> {
    let occupied: bool = connection
        .query_row(
            "SELECT
                EXISTS(
                    SELECT 1
                    FROM daemon_message_history
                    WHERE conversation_id = ?1 AND message_id = ?2
                )
                OR EXISTS(
                    SELECT 1
                    FROM daemon_outbox
                    WHERE conversation_id = ?1 AND message_id = ?2
                )",
            params![
                conversation_id.as_bytes().as_slice(),
                message_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    if occupied {
        Err(ProfileStoreError::CollaborationPolicyProposalConflict)
    } else {
        Ok(())
    }
}

fn collaboration_policy_operation_exists(
    connection: &Connection,
    conversation_id: ConversationId,
    message_id: MessageId,
) -> Result<bool, ProfileStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM daemon_collaboration_policy_operation
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

fn collaboration_policy_operation_count(
    connection: &Connection,
) -> Result<usize, ProfileStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM daemon_collaboration_policy_operation",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)
}

fn operation_record_context(
    profile_id: &ProfileId,
    conversation_id: ConversationId,
    message_id: MessageId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::CollaborationPolicyOperation,
        &[
            profile_id.as_bytes(),
            conversation_id.as_bytes(),
            message_id.as_bytes(),
        ],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn operation_state_context(
    profile_id: &ProfileId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::CollaborationPolicyOperationState,
        &[profile_id.as_bytes()],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn encode_operation_record(operation: &DecodedOperation) -> Result<Vec<u8>, ProfileStoreError> {
    let kind = u8::try_from(operation.kind).map_err(|_| ProfileStoreError::CorruptData)?;
    let mut encoded = Vec::with_capacity(OPERATION_RECORD_BYTES);
    encoded.push(OPERATION_RECORD_VERSION);
    encoded.extend_from_slice(operation.conversation_id.as_bytes());
    encoded.extend_from_slice(operation.message_id.as_bytes());
    encoded.push(kind);
    encoded.push(u8::from(operation.proposal_id.is_some()));
    encoded.extend_from_slice(
        operation
            .proposal_id
            .map_or([0; CollaborationPolicyProposalId::LENGTH], |value| {
                value.into_bytes()
            })
            .as_slice(),
    );
    encoded.push(u8::from(operation.source_proposal_message_id.is_some()));
    encoded.extend_from_slice(
        operation
            .source_proposal_message_id
            .map_or([0; MessageId::LENGTH], |value| value.into_bytes())
            .as_slice(),
    );
    encoded.extend_from_slice(operation.policy_digest.as_bytes());
    encoded.push(u8::from(operation.replaces_policy_digest.is_some()));
    encoded.extend_from_slice(
        operation
            .replaces_policy_digest
            .map_or([0; CollaborationPolicyDigest::LENGTH], |value| {
                value.into_bytes()
            })
            .as_slice(),
    );
    encoded.push(u8::from(operation.binding_changed));
    Ok(encoded)
}

fn encode_operation_state(record_count: usize) -> Result<Vec<u8>, ProfileStoreError> {
    let record_count =
        u64::try_from(record_count).map_err(|_| ProfileStoreError::SequenceExhausted)?;
    let mut encoded = Vec::with_capacity(OPERATION_STATE_BYTES);
    encoded.push(OPERATION_STATE_VERSION);
    encoded.extend_from_slice(&record_count.to_be_bytes());
    Ok(encoded)
}

fn decode_operation_state(bytes: &[u8]) -> Result<usize, ProfileStoreError> {
    if bytes.len() != OPERATION_STATE_BYTES || bytes[0] != OPERATION_STATE_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let count = u64::from_be_bytes(
        bytes[1..]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let count = usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)?;
    if count > MAX_COLLABORATION_POLICY_OPERATIONS {
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

fn validate_sealed_bytes(bytes: &[u8], maximum: usize) -> Result<(), ProfileStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(ProfileStoreError::CorruptData)
    } else {
        Ok(())
    }
}

struct OperationMetadata {
    conversation_id: Option<Vec<u8>>,
    message_id: Option<Vec<u8>>,
    kind: i64,
    proposal_id_storage_type: String,
    proposal_id_length: Option<i64>,
    proposal_id: Option<Vec<u8>>,
    source_message_storage_type: String,
    source_message_length: Option<i64>,
    source_proposal_message_id: Option<Vec<u8>>,
    replaces_digest_storage_type: String,
    replaces_digest_length: Option<i64>,
    replaces_policy_digest: Option<Vec<u8>>,
    policy_digest: Option<Vec<u8>>,
    binding_changed: i64,
    sealed_operation_length: i64,
}

struct DecodedOperation {
    conversation_id: ConversationId,
    message_id: MessageId,
    kind: i64,
    proposal_id: Option<CollaborationPolicyProposalId>,
    source_proposal_message_id: Option<MessageId>,
    policy_digest: CollaborationPolicyDigest,
    replaces_policy_digest: Option<CollaborationPolicyDigest>,
    binding_changed: bool,
}
