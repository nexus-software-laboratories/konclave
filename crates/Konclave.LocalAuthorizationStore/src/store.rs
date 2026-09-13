use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceSet, AuthorizationPolicy, AuthorizationPolicyVersion, ClientInstanceId,
    HarnessKind, InstalledIssuerRegistration, IssuerKeyId, IssuerKeyVersion, IssuerRegistration,
    LOCAL_SERVICE_INSTALLATION_FILE, MAX_ADAPTER_REGISTRATIONS, MAX_GRANTS_PER_ISSUER,
    MAX_GRANTS_PER_PROFILE, MAX_POLICY_CLAUSES, MAX_PROFILE_ID_LENGTH, MAX_SESSION_GRANTS,
    ProfileAuthorization, REQUEST_ID_LENGTH, RequestId, SESSION_GRANT_ID_LENGTH, ServiceProfileId,
    SessionCapabilities, SessionGrant, SessionGrantClaims, SessionGrantId,
};
use KonclaveSecretStorage::{
    SecretStorageError, ensure_owner_protected_directory, open_or_create_owner_protected_file,
    open_owner_protected_file,
};
use KonclaveUserPresence::{MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES, UserPresenceCredentialDigest};
use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest as _, Sha256};

use crate::{
    AUTHORIZATION_STORE_BUSY_TIMEOUT_MILLISECONDS, AuthorizationAuditEvent, AuthorizationAuditKind,
    AuthorizationCapacity, AuthorizationGeneration, AuthorizationIssuerRecord,
    AuthorizationMutation, AuthorizationSnapshot, AuthorizationStoreStatus,
    ExistingGrantDisposition, GrantIssuanceKey, GrantIssuanceResult,
    INSTALLATION_FINGERPRINT_LENGTH, InstallationFingerprint, IssuerAvailability,
    LOCAL_AUTHORIZATION_STORE_FILE, LocalAuthorizationStoreError, MAX_AUTHORIZATION_AUDIT_RECORDS,
    MAX_GRANT_IDENTIFIERS, MAX_SUSPENDED_PROFILES, MAX_TERMINAL_GRANT_RECORDS,
    MAX_USER_PRESENCE_CREDENTIAL_IDENTIFIERS, MutationEffect, UserPresenceCredentialRecord,
};

const SCHEMA_VERSION: u32 = 2;
const HARD_MAX_SCHEMA_OBJECT_COUNT: i64 = 32;
const MAX_SCHEMA_IDENTIFIER_BYTES: i64 = 128;
const MAX_SCHEMA_SQL_BYTES: i64 = 8_192;
const _: () = assert!(INSTALLATION_FINGERPRINT_LENGTH == 32);
const _: () = assert!(IssuerKeyId::LENGTH == 16);
const _: () = assert!(Ed25519PublicKey::LENGTH == 32);
const _: () = assert!(SESSION_GRANT_ID_LENGTH == 16);
const _: () = assert!(ClientInstanceId::LENGTH == 16);
const _: () = assert!(REQUEST_ID_LENGTH == 16);
const _: () = assert!(MAX_PROFILE_ID_LENGTH == 32);
const _: () = assert!(MAX_POLICY_CLAUSES == 8);
const _: () = assert!(HarnessKind::A2AGateway.wire_value() == 5);
const _: () = assert!(SessionCapabilities::ALL.bits() == 15);
const CREATE_CORE_SCHEMA_SQL: &str = "
    CREATE TABLE authorization_store_meta (
        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
        schema_version INTEGER NOT NULL CHECK (
            typeof(schema_version) = 'integer' AND schema_version >= 1
        ),
        installation_fingerprint BLOB NOT NULL CHECK (
            typeof(installation_fingerprint) = 'blob'
            AND length(installation_fingerprint) = 32
        ),
        generation INTEGER NOT NULL CHECK (
            typeof(generation) = 'integer' AND generation >= 1
        ),
        policy_version INTEGER NOT NULL CHECK (
            typeof(policy_version) = 'integer' AND policy_version >= 1
        )
    );
    CREATE TABLE authorization_policy_clause (
        ordinal INTEGER PRIMARY KEY CHECK (
            typeof(ordinal) = 'integer' AND ordinal >= 0 AND ordinal < 8
        ),
        evidence_bits INTEGER NOT NULL UNIQUE CHECK (
            typeof(evidence_bits) = 'integer'
            AND evidence_bits >= 1
            AND evidence_bits <= 15
        )
    );
    CREATE TABLE authorization_issuer_identifier (
        issuer_key_id BLOB NOT NULL CHECK (
            typeof(issuer_key_id) = 'blob' AND length(issuer_key_id) = 16
        ),
        issuer_key_version INTEGER NOT NULL CHECK (
            typeof(issuer_key_version) = 'integer'
            AND issuer_key_version >= 1
            AND issuer_key_version <= 4294967295
        ),
        PRIMARY KEY (issuer_key_id, issuer_key_version)
    );
    CREATE TABLE authorization_issuer (
        issuer_key_id BLOB NOT NULL CHECK (
            typeof(issuer_key_id) = 'blob' AND length(issuer_key_id) = 16
        ),
        issuer_key_version INTEGER NOT NULL CHECK (
            typeof(issuer_key_version) = 'integer'
            AND issuer_key_version >= 1
            AND issuer_key_version <= 4294967295
        ),
        public_key BLOB NOT NULL CHECK (
            typeof(public_key) = 'blob' AND length(public_key) = 32
        ),
        harness INTEGER NOT NULL CHECK (
            typeof(harness) = 'integer' AND harness >= 1 AND harness <= 5
        ),
        profile_kind INTEGER NOT NULL CHECK (
            typeof(profile_kind) = 'integer' AND profile_kind >= 1 AND profile_kind <= 3
        ),
        profile_id TEXT NOT NULL CHECK (
            typeof(profile_id) = 'text'
            AND length(CAST(profile_id AS BLOB)) <= 32
            AND (
                (profile_kind IN (1, 2) AND length(CAST(profile_id AS BLOB)) >= 1)
                OR (profile_kind = 3 AND length(profile_id) = 0)
            )
        ),
        enabled INTEGER NOT NULL CHECK (
            typeof(enabled) = 'integer' AND enabled IN (0, 1)
        ),
        existing_grant_disposition INTEGER NOT NULL CHECK (
            typeof(existing_grant_disposition) = 'integer'
            AND existing_grant_disposition IN (1, 2)
        ),
        PRIMARY KEY (issuer_key_id, issuer_key_version),
        FOREIGN KEY (issuer_key_id, issuer_key_version)
            REFERENCES authorization_issuer_identifier(issuer_key_id, issuer_key_version)
    );
    CREATE TABLE authorization_suspended_profile (
        profile_id TEXT PRIMARY KEY CHECK (
            typeof(profile_id) = 'text'
            AND length(CAST(profile_id AS BLOB)) >= 1
            AND length(CAST(profile_id AS BLOB)) <= 32
        )
    );
    CREATE TABLE authorization_grant_identifier (
        grant_id BLOB PRIMARY KEY CHECK (
            typeof(grant_id) = 'blob' AND length(grant_id) = 16
        )
    );
    CREATE TABLE authorization_grant (
        grant_id BLOB PRIMARY KEY CHECK (
            typeof(grant_id) = 'blob' AND length(grant_id) = 16
        ),
        issuer_key_id BLOB NOT NULL CHECK (
            typeof(issuer_key_id) = 'blob' AND length(issuer_key_id) = 16
        ),
        issuer_key_version INTEGER NOT NULL CHECK (
            typeof(issuer_key_version) = 'integer'
            AND issuer_key_version >= 1
            AND issuer_key_version <= 4294967295
        ),
        profile_id TEXT NOT NULL CHECK (
            typeof(profile_id) = 'text'
            AND length(CAST(profile_id AS BLOB)) >= 1
            AND length(CAST(profile_id AS BLOB)) <= 32
        ),
        session_public_key BLOB NOT NULL CHECK (
            typeof(session_public_key) = 'blob' AND length(session_public_key) = 32
        ),
        issuer_client_instance BLOB NOT NULL CHECK (
            typeof(issuer_client_instance) = 'blob'
            AND length(issuer_client_instance) = 16
        ),
        issuance_request_id BLOB NOT NULL CHECK (
            typeof(issuance_request_id) = 'blob'
            AND length(issuance_request_id) = 16
        ),
        harness INTEGER NOT NULL CHECK (
            typeof(harness) = 'integer' AND harness >= 1 AND harness <= 5
        ),
        evidence_bits INTEGER NOT NULL CHECK (
            typeof(evidence_bits) = 'integer'
            AND evidence_bits >= 1
            AND evidence_bits <= 15
        ),
        policy_version INTEGER NOT NULL CHECK (
            typeof(policy_version) = 'integer' AND policy_version >= 1
        ),
        issued_at_unix_milliseconds INTEGER NOT NULL CHECK (
            typeof(issued_at_unix_milliseconds) = 'integer'
            AND issued_at_unix_milliseconds >= 0
        ),
        expires_at_unix_milliseconds INTEGER NOT NULL CHECK (
            typeof(expires_at_unix_milliseconds) = 'integer'
            AND expires_at_unix_milliseconds > issued_at_unix_milliseconds
        ),
        capabilities INTEGER NOT NULL CHECK (
            typeof(capabilities) = 'integer'
            AND capabilities >= 1
            AND capabilities <= 15
        ),
        state INTEGER NOT NULL CHECK (
            typeof(state) = 'integer' AND state >= 1 AND state <= 7
        ),
        terminal_generation INTEGER CHECK (
            terminal_generation IS NULL
            OR (typeof(terminal_generation) = 'integer' AND terminal_generation >= 1)
        ),
        terminal_at_unix_milliseconds INTEGER CHECK (
            terminal_at_unix_milliseconds IS NULL
            OR (
                typeof(terminal_at_unix_milliseconds) = 'integer'
                AND terminal_at_unix_milliseconds >= 0
            )
        ),
        CHECK (
            (state = 1 AND terminal_generation IS NULL AND terminal_at_unix_milliseconds IS NULL)
            OR
            (
                state != 1
                AND terminal_generation IS NOT NULL
                AND terminal_at_unix_milliseconds IS NOT NULL
                AND terminal_at_unix_milliseconds >= issued_at_unix_milliseconds
            )
        ),
        FOREIGN KEY (grant_id)
            REFERENCES authorization_grant_identifier(grant_id),
        FOREIGN KEY (issuer_key_id, issuer_key_version)
            REFERENCES authorization_issuer(issuer_key_id, issuer_key_version),
        UNIQUE (
            issuer_key_id,
            issuer_key_version,
            issuer_client_instance,
            issuance_request_id
        )
    );";

const CREATE_USER_PRESENCE_SCHEMA_SQL: &str = "
    CREATE TABLE authorization_user_presence_credential_identifier (
        credential_digest BLOB PRIMARY KEY CHECK (
            typeof(credential_digest) = 'blob' AND length(credential_digest) = 32
        )
    );
    CREATE TABLE authorization_user_presence_credential (
        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
        provider_id TEXT NOT NULL CHECK (
            typeof(provider_id) = 'text'
            AND length(CAST(provider_id AS BLOB)) >= 1
            AND length(CAST(provider_id AS BLOB)) <= 64
        ),
        credential_id BLOB NOT NULL CHECK (
            typeof(credential_id) = 'blob'
            AND length(credential_id) >= 1
            AND length(credential_id) <= 1024
        ),
        credential_digest BLOB NOT NULL UNIQUE CHECK (
            typeof(credential_digest) = 'blob' AND length(credential_digest) = 32
        ),
        credential_document BLOB NOT NULL CHECK (
            typeof(credential_document) = 'blob'
            AND length(credential_document) >= 1
            AND length(credential_document) <= 65536
        ),
        FOREIGN KEY (credential_digest)
            REFERENCES authorization_user_presence_credential_identifier(credential_digest)
    );";

const CREATE_AUTHORIZATION_AUDIT_V2_SQL: &str = "
    CREATE TABLE authorization_audit (
        generation INTEGER PRIMARY KEY CHECK (
            typeof(generation) = 'integer' AND generation >= 1
        ),
        event_kind INTEGER NOT NULL CHECK (
            typeof(event_kind) = 'integer' AND event_kind >= 1 AND event_kind <= 15
        ),
        occurred_at_unix_milliseconds INTEGER NOT NULL CHECK (
            typeof(occurred_at_unix_milliseconds) = 'integer'
            AND occurred_at_unix_milliseconds >= 0
        )
    );";

const CREATE_AUTHORIZATION_AUDIT_V1_SQL: &str = "
    CREATE TABLE authorization_audit (
        generation INTEGER PRIMARY KEY CHECK (
            typeof(generation) = 'integer' AND generation >= 1
        ),
        event_kind INTEGER NOT NULL CHECK (
            typeof(event_kind) = 'integer' AND event_kind >= 1 AND event_kind <= 11
        ),
        occurred_at_unix_milliseconds INTEGER NOT NULL CHECK (
            typeof(occurred_at_unix_milliseconds) = 'integer'
            AND occurred_at_unix_milliseconds >= 0
        )
    );";

const INSTALLATION_FINGERPRINT_DOMAIN: &[u8] =
    b"konclave:local-authorization-installation-fingerprint:1\0";

/// Derives the opaque binding for one validated immutable installation record.
///
/// # Errors
///
/// Returns a finite encoding failure when the validated installation cannot be
/// serialized canonically.
pub fn installation_fingerprint(
    installation: &KonclaveLocalServiceTransport::LocalServiceInstallation,
) -> Result<InstallationFingerprint, LocalAuthorizationStoreError> {
    let mut encoded = Vec::new();
    installation
        .write_to(&mut encoded)
        .map_err(|_| LocalAuthorizationStoreError::InvalidInput)?;
    let mut digest = Sha256::new();
    digest.update(INSTALLATION_FINGERPRINT_DOMAIN);
    digest.update(encoded);
    Ok(InstallationFingerprint::from_bytes(
        digest.finalize().into(),
    ))
}

/// Synchronous owner-protected SQLite authorization store.
///
/// The type serializes callers sharing this instance. Separate processes and store
/// instances are serialized by SQLite immediate transactions and the bounded busy
/// timeout.
pub struct LocalAuthorizationStore {
    connection: Mutex<Connection>,
    high_water: Mutex<AuthorizationGeneration>,
    installation_fingerprint: InstallationFingerprint,
}

impl LocalAuthorizationStore {
    /// Returns the immutable installation fingerprint this store is bound to.
    #[must_use]
    pub const fn installation_fingerprint(&self) -> InstallationFingerprint {
        self.installation_fingerprint
    }

    /// Explicitly bootstraps the database beside `installation_record_path`.
    ///
    /// Existing valid state is retained without reapplying bootstrap values. This is
    /// the only API that may initialize an empty database and is intended for the
    /// installer, never ordinary service startup. A new installer bootstraps this
    /// store before publishing the immutable installation record. Once that record
    /// exists, a missing or empty database fails closed instead of resetting state.
    ///
    /// # Errors
    ///
    /// Returns a finite path, owner-protection, SQLite, schema, installation-binding,
    /// or bootstrap-validation failure.
    pub fn bootstrap(
        installation_record_path: impl AsRef<Path>,
        installation_fingerprint: InstallationFingerprint,
        bootstrap_policy: &AuthorizationPolicy,
        bootstrap_issuers: &[InstalledIssuerRegistration],
        now_unix_milliseconds: u64,
    ) -> Result<Self, LocalAuthorizationStoreError> {
        Self::open_inner(
            installation_record_path.as_ref(),
            installation_fingerprint,
            Some((bootstrap_policy, bootstrap_issuers, now_unix_milliseconds)),
            None,
        )
    }

    /// Opens an existing nonempty authorization database without initializing it.
    ///
    /// `process_high_water` may carry the largest generation already observed by the
    /// caller's process when replacing a store instance. A lower durable generation
    /// fails closed.
    ///
    /// # Errors
    ///
    /// Returns a finite missing, empty, owner-protection, SQLite, schema,
    /// installation-binding, or rollback failure.
    pub fn open(
        installation_record_path: impl AsRef<Path>,
        installation_fingerprint: InstallationFingerprint,
        process_high_water: Option<AuthorizationGeneration>,
    ) -> Result<Self, LocalAuthorizationStoreError> {
        Self::open_inner(
            installation_record_path.as_ref(),
            installation_fingerprint,
            None,
            process_high_water,
        )
    }

    fn open_inner(
        installation_record_path: &Path,
        installation_fingerprint: InstallationFingerprint,
        bootstrap: Option<(&AuthorizationPolicy, &[InstalledIssuerRegistration], u64)>,
        process_high_water: Option<AuthorizationGeneration>,
    ) -> Result<Self, LocalAuthorizationStoreError> {
        if let Some((bootstrap_policy, bootstrap_issuers, now_unix_milliseconds)) = bootstrap {
            validate_timestamp(now_unix_milliseconds)?;
            validate_bootstrap(bootstrap_policy, bootstrap_issuers)?;
        }
        let database_path = authorization_store_path(installation_record_path)?;
        let installation_exists = match std::fs::symlink_metadata(installation_record_path) {
            Ok(_) => {
                drop(
                    open_owner_protected_file(installation_record_path)
                        .map_err(map_owner_protection_error)?,
                );
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && bootstrap.is_some() => {
                let parent = installation_record_path
                    .parent()
                    .ok_or(LocalAuthorizationStoreError::InvalidInput)?;
                ensure_owner_protected_directory(parent).map_err(map_owner_protection_error)?;
                false
            }
            Err(_) => return Err(LocalAuthorizationStoreError::StorageUnavailable),
        };
        let database_exists = match std::fs::symlink_metadata(&database_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(LocalAuthorizationStoreError::StorageUnavailable),
        };
        if installation_exists && !database_exists {
            return Err(LocalAuthorizationStoreError::StorageUnavailable);
        }
        let database_guard = if database_exists || bootstrap.is_some() {
            open_or_create_owner_protected_file(&database_path)
                .map_err(map_owner_protection_error)?
        } else {
            return Err(LocalAuthorizationStoreError::StorageUnavailable);
        };
        reject_wal_sidecars(&database_path)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection =
            Connection::open_with_flags(&database_path, flags).map_err(map_open_error)?;
        configure_connection(&connection)?;
        match bootstrap.filter(|_| !installation_exists) {
            Some((bootstrap_policy, bootstrap_issuers, now_unix_milliseconds)) => {
                initialize_or_validate(
                    &mut connection,
                    installation_fingerprint,
                    Some((bootstrap_policy, bootstrap_issuers, now_unix_milliseconds)),
                )?;
            }
            None => initialize_or_validate(&mut connection, installation_fingerprint, None)?,
        }
        verify_integrity(&connection)?;
        validate_store(&connection, installation_fingerprint)?;
        drop(database_guard);
        let generation = AuthorizationGeneration::from_validated(load_generation(&connection)?);
        if process_high_water.is_some_and(|high_water| generation < high_water) {
            return Err(LocalAuthorizationStoreError::GenerationRollback);
        }

        Ok(Self {
            connection: Mutex::new(connection),
            high_water: Mutex::new(generation),
            installation_fingerprint,
        })
    }

    /// Loads a complete bounded live-registry snapshot, expiring stale grants first.
    ///
    /// `high_water` is the largest generation observed by this process. A lower
    /// durable value fails closed rather than publishing rolled-back authority.
    ///
    /// # Errors
    ///
    /// Returns a finite storage, validation, rollback, or capacity failure.
    pub fn load_snapshot(
        &self,
        now_unix_milliseconds: u64,
        high_water: Option<AuthorizationGeneration>,
    ) -> Result<AuthorizationSnapshot, LocalAuthorizationStoreError> {
        validate_timestamp(now_unix_milliseconds)?;
        let mut connection = self.lock()?;
        let mut observed_high_water = self.lock_high_water()?;
        let required_high_water = high_water
            .filter(|candidate| candidate > &*observed_high_water)
            .unwrap_or(*observed_high_water);
        let transaction = immediate_transaction(&mut connection)?;
        verify_identity_and_high_water(
            &transaction,
            self.installation_fingerprint,
            Some(required_high_water),
        )?;
        verify_integrity(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        let generation = expire_for_read(&transaction, now_unix_milliseconds)?;
        let snapshot = AuthorizationSnapshot {
            generation,
            policy: load_policy(&transaction)?,
            issuers: load_issuers(&transaction)?,
            suspended_profiles: load_suspended_profiles(&transaction)?,
            active_grants: load_active_grants(&transaction, now_unix_milliseconds)?,
            user_presence_credential: load_user_presence_credential(&transaction)?,
        };
        validate_store(&transaction, self.installation_fingerprint)?;
        transaction.commit().map_err(map_write_error)?;
        *observed_high_water = snapshot.generation;
        Ok(snapshot)
    }

    /// Issues one validated candidate grant without evicting active authority.
    ///
    /// Exact replay of an already-active identical grant is an unchanged success.
    /// Reuse of the identifier with different claims or terminal history conflicts.
    ///
    /// # Errors
    ///
    /// Returns a finite invalid-input, conflict, suspension, issuer, evidence,
    /// capacity, or storage failure.
    pub fn issue_grant(
        &self,
        candidate: &SessionGrant,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        let request_key = GrantIssuanceKey::new(
            ClientInstanceId::from_bytes(*candidate.grant_id().as_bytes()),
            RequestId::from_bytes(*candidate.grant_id().as_bytes()),
        );
        self.issue_grant_for_request(request_key, candidate, now_unix_milliseconds)
            .map(|result| result.mutation())
    }

    /// Issues or replays one grant for an exact authenticated issuer request.
    ///
    /// A retry with the same issuer, client instance, request identifier, profile,
    /// session key, and harness returns the original grant even when the caller
    /// generated a different candidate identifier. Conflicting request reuse fails.
    ///
    /// # Errors
    ///
    /// Returns a finite invalid-input, conflict, suspension, issuer, evidence,
    /// capacity, rollback, or storage failure.
    pub fn issue_grant_for_request(
        &self,
        request_key: GrantIssuanceKey,
        candidate: &SessionGrant,
        now_unix_milliseconds: u64,
    ) -> Result<GrantIssuanceResult, LocalAuthorizationStoreError> {
        if candidate.issued_at_unix_milliseconds() > now_unix_milliseconds
            || candidate.expires_at_unix_milliseconds() <= now_unix_milliseconds
        {
            return Err(LocalAuthorizationStoreError::InvalidInput);
        }
        let mut connection = self.lock()?;
        let mut observed_high_water = self.lock_high_water()?;
        let transaction = immediate_transaction(&mut connection)?;
        verify_identity_and_high_water(
            &transaction,
            self.installation_fingerprint,
            Some(*observed_high_water),
        )?;
        verify_integrity(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        let current_generation = load_generation(&transaction)?;
        *observed_high_water = AuthorizationGeneration::from_validated(current_generation);
        let proposed_generation = next_generation(current_generation).unwrap_or(current_generation);

        if let Some(existing) = load_grant_by_issuance(
            &transaction,
            candidate.issuer_key_id(),
            candidate.issuer_key_version(),
            request_key,
        )? {
            if !same_issuance_request(&existing.grant, candidate) {
                return Err(LocalAuthorizationStoreError::Conflict);
            }
            let expired = expire_grants(&transaction, now_unix_milliseconds, proposed_generation)?;
            let generation = if expired == 0 {
                current_generation
            } else {
                if proposed_generation == current_generation {
                    return Err(LocalAuthorizationStoreError::Capacity);
                }
                commit_generation(
                    &transaction,
                    proposed_generation,
                    AuthorizationAuditKind::GrantsExpired,
                    now_unix_milliseconds,
                )?;
                prune_bounded_history(&transaction)?;
                proposed_generation
            };
            validate_store(&transaction, self.installation_fingerprint)?;
            transaction.commit().map_err(map_write_error)?;
            let generation = AuthorizationGeneration::from_validated(generation);
            *observed_high_water = generation;
            return Ok(GrantIssuanceResult::new(
                AuthorizationMutation {
                    generation,
                    effect: MutationEffect::Unchanged,
                },
                existing.grant,
            ));
        }

        if load_grant_by_id(&transaction, candidate.grant_id())?.is_some()
            || grant_identifier_exists(&transaction, candidate.grant_id())?
        {
            return Err(LocalAuthorizationStoreError::Conflict);
        }
        if count_rows(&transaction, "authorization_grant_identifier")? >= MAX_GRANT_IDENTIFIERS {
            return Err(LocalAuthorizationStoreError::Capacity);
        }
        if is_profile_suspended(&transaction, candidate.profile())? {
            return Err(LocalAuthorizationStoreError::ProfileSuspended);
        }
        let issuer = load_issuer(
            &transaction,
            candidate.issuer_key_id(),
            candidate.issuer_key_version(),
        )?
        .ok_or(LocalAuthorizationStoreError::NotFound)?;
        if issuer.availability == IssuerAvailability::Disabled {
            return Err(LocalAuthorizationStoreError::IssuerDisabled);
        }
        if (issuer.registration.harness() != candidate.harness()
            && issuer.registration.harness() != HarnessKind::Generic)
            || !issuer.registration.profiles().permits(candidate.profile())
        {
            return Err(LocalAuthorizationStoreError::Conflict);
        }
        let policy = load_policy(&transaction)?;
        if candidate.policy_version() != policy.version() {
            return Err(LocalAuthorizationStoreError::Conflict);
        }
        if !policy.accepts(candidate.evidence()) {
            return Err(LocalAuthorizationStoreError::RequiredEvidenceUnavailable);
        }
        enforce_grant_capacity(&transaction, candidate, now_unix_milliseconds)?;
        reserve_grant_identifier(&transaction, candidate.grant_id())?;
        insert_grant(&transaction, request_key, candidate)?;
        expire_grants(&transaction, now_unix_milliseconds, proposed_generation)?;
        if proposed_generation == current_generation {
            return Err(LocalAuthorizationStoreError::Capacity);
        }
        commit_generation(
            &transaction,
            proposed_generation,
            AuthorizationAuditKind::GrantIssued,
            now_unix_milliseconds,
        )?;
        prune_bounded_history(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        transaction.commit().map_err(map_write_error)?;
        let generation = AuthorizationGeneration::from_validated(proposed_generation);
        *observed_high_water = generation;
        Ok(GrantIssuanceResult::new(
            AuthorizationMutation {
                generation,
                effect: MutationEffect::Applied,
            },
            candidate.clone(),
        ))
    }

    /// Loads one active grant previously issued for an exact request key.
    ///
    /// This is the recovery-only half of idempotent issuance: it never creates
    /// authority. Expired grants are terminalized before the lookup.
    ///
    /// # Errors
    ///
    /// Returns a finite storage, validation, rollback, or capacity failure.
    pub fn active_grant_for_request(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        request_key: GrantIssuanceKey,
        now_unix_milliseconds: u64,
    ) -> Result<Option<SessionGrant>, LocalAuthorizationStoreError> {
        validate_timestamp(now_unix_milliseconds)?;
        let mut connection = self.lock()?;
        let mut observed_high_water = self.lock_high_water()?;
        let transaction = immediate_transaction(&mut connection)?;
        verify_identity_and_high_water(
            &transaction,
            self.installation_fingerprint,
            Some(*observed_high_water),
        )?;
        verify_integrity(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        let generation = expire_for_read(&transaction, now_unix_milliseconds)?;
        let grant =
            load_grant_by_issuance(&transaction, issuer_key_id, issuer_key_version, request_key)?
                .filter(|stored| {
                    stored.state == GrantState::Active
                        && stored.grant.expires_at_unix_milliseconds() > now_unix_milliseconds
                })
                .map(|stored| stored.grant);
        validate_store(&transaction, self.installation_fingerprint)?;
        transaction.commit().map_err(map_write_error)?;
        *observed_high_water = generation;
        Ok(grant)
    }

    /// Retires one exact grant without affecting any other grant.
    ///
    /// Repeating the retirement, or observing another terminal condition first, is
    /// an unchanged success while the terminal record remains retained.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, conflict, capacity, or storage failure.
    pub fn retire_grant(
        &self,
        grant_id: SessionGrantId,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::GrantRetired,
            |transaction, generation| {
                terminalize_exact_grant(
                    transaction,
                    grant_id,
                    GrantState::Retired,
                    now_unix_milliseconds,
                    generation,
                )
            },
        )
    }

    /// Revokes one exact grant without affecting any other grant.
    ///
    /// Repeating the revocation, or observing another terminal condition first, is
    /// an unchanged success while the terminal record remains retained.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, conflict, capacity, or storage failure.
    pub fn revoke_grant(
        &self,
        grant_id: SessionGrantId,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::GrantRevoked,
            |transaction, generation| {
                terminalize_exact_grant(
                    transaction,
                    grant_id,
                    GrantState::Revoked,
                    now_unix_milliseconds,
                    generation,
                )
            },
        )
    }

    /// Suspends one exact profile and terminalizes all of its active grants in the
    /// same transaction.
    ///
    /// Repeating an existing suspension is an unchanged success.
    ///
    /// # Errors
    ///
    /// Returns a finite capacity or storage failure.
    pub fn suspend_profile(
        &self,
        profile: &ServiceProfileId,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::ProfileSuspended,
            |transaction, generation| {
                if is_profile_suspended(transaction, profile)? {
                    return Ok(false);
                }
                let count = count_rows(transaction, "authorization_suspended_profile")?;
                if count >= MAX_SUSPENDED_PROFILES {
                    return Err(LocalAuthorizationStoreError::Capacity);
                }
                transaction
                    .execute(
                        "INSERT INTO authorization_suspended_profile (profile_id) VALUES (?1)",
                        params![profile.as_str()],
                    )
                    .map_err(map_write_error)?;
                terminalize_profile_grants(
                    transaction,
                    profile,
                    now_unix_milliseconds,
                    generation,
                )?;
                Ok(true)
            },
        )
    }

    /// Removes one exact profile suspension without restoring terminal grants.
    ///
    /// Repeating a completed resume is an unchanged success.
    ///
    /// # Errors
    ///
    /// Returns a finite capacity or storage failure.
    pub fn resume_profile(
        &self,
        profile: &ServiceProfileId,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::ProfileResumed,
            |transaction, _generation| {
                let removed = transaction
                    .execute(
                        "DELETE FROM authorization_suspended_profile WHERE profile_id = ?1",
                        params![profile.as_str()],
                    )
                    .map_err(map_write_error)?;
                Ok(removed == 1)
            },
        )
    }

    /// Changes one exact issuer key version's availability and existing-grant
    /// disposition.
    ///
    /// Disabling with [`ExistingGrantDisposition::Revoke`] terminalizes every active
    /// grant from that exact key version atomically. Retain mode leaves those grants
    /// active until expiry or another terminal condition.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, capacity, or storage failure.
    pub fn set_issuer_state(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        availability: IssuerAvailability,
        disposition: ExistingGrantDisposition,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::IssuerStateChanged,
            |transaction, generation| {
                let issuer = load_issuer(transaction, issuer_key_id, issuer_key_version)?
                    .ok_or(LocalAuthorizationStoreError::NotFound)?;
                if issuer.availability == availability
                    && issuer.existing_grant_disposition == disposition
                {
                    return Ok(false);
                }
                let changed = transaction
                    .execute(
                        "UPDATE authorization_issuer
                         SET enabled = ?1, existing_grant_disposition = ?2
                         WHERE issuer_key_id = ?3 AND issuer_key_version = ?4",
                        params![
                            availability_code(availability),
                            disposition_code(disposition),
                            issuer_key_id.as_bytes().as_slice(),
                            i64::from(issuer_key_version.get())
                        ],
                    )
                    .map_err(map_write_error)?;
                if changed != 1 {
                    return Err(LocalAuthorizationStoreError::InvalidStorage);
                }
                if availability == IssuerAvailability::Disabled
                    && disposition == ExistingGrantDisposition::Revoke
                {
                    terminalize_issuer_grants(
                        transaction,
                        issuer_key_id,
                        issuer_key_version,
                        now_unix_milliseconds,
                        generation,
                    )?;
                }
                Ok(true)
            },
        )
    }

    /// Replaces the effective policy only when its version is strictly greater.
    ///
    /// Active grants whose recorded evidence no longer satisfies the new policy
    /// become terminal in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns a finite conflict, capacity, invalid-input, or storage failure.
    pub fn replace_policy(
        &self,
        policy: &AuthorizationPolicy,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::PolicyReplaced,
            |transaction, generation| {
                let current = load_policy(transaction)?;
                if policy.version() <= current.version() {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                replace_policy_rows(transaction, policy)?;
                terminalize_policy_invalid_grants(
                    transaction,
                    policy,
                    now_unix_milliseconds,
                    generation,
                )?;
                Ok(true)
            },
        )
    }

    /// Registers one new issuer key version without replacing retained state.
    ///
    /// For an existing issuer identifier, the new version must be strictly greater
    /// than every retained version so rotation activates forward only.
    ///
    /// # Errors
    ///
    /// Returns a finite conflict, capacity, or storage failure.
    pub fn register_issuer(
        &self,
        issuer: &InstalledIssuerRegistration,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::IssuerRegistered,
            |transaction, _generation| {
                if issuer_identifier_exists(
                    transaction,
                    issuer.issuer_key_id(),
                    issuer.issuer_key_version(),
                )? {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                if count_rows(transaction, "authorization_issuer_identifier")?
                    >= MAX_ADAPTER_REGISTRATIONS
                {
                    return Err(LocalAuthorizationStoreError::Capacity);
                }
                let maximum_version: Option<i64> = transaction
                    .query_row(
                        "SELECT max(issuer_key_version)
                         FROM authorization_issuer_identifier
                         WHERE issuer_key_id = ?1",
                        params![issuer.issuer_key_id().as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(map_read_error)?;
                if maximum_version
                    .is_some_and(|maximum| i64::from(issuer.issuer_key_version().get()) <= maximum)
                {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                insert_issuer(transaction, issuer)?;
                Ok(true)
            },
        )
    }

    /// Removes one exact issuer key version without deleting profile data.
    ///
    /// Retain mode refuses removal while active unexpired grants remain. Revoke mode
    /// terminalizes and removes every grant from the issuer before deleting its
    /// registration. The identifier reservation remains so the version can never be
    /// reused. Repeating a completed removal is an unchanged success while the
    /// identifier reservation remains.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, conflict, capacity, or storage failure.
    pub fn remove_issuer(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        disposition: ExistingGrantDisposition,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::IssuerRemoved,
            |transaction, generation| {
                if load_issuer(transaction, issuer_key_id, issuer_key_version)?.is_none() {
                    return if issuer_identifier_exists(
                        transaction,
                        issuer_key_id,
                        issuer_key_version,
                    )? {
                        Ok(false)
                    } else {
                        Err(LocalAuthorizationStoreError::NotFound)
                    };
                }
                let active = count_active_issuer_grants(
                    transaction,
                    issuer_key_id,
                    issuer_key_version,
                    now_unix_milliseconds,
                )?;
                if active > 0 {
                    if disposition == ExistingGrantDisposition::RetainUntilExpiry {
                        return Err(LocalAuthorizationStoreError::Conflict);
                    }
                    terminalize_issuer_grants(
                        transaction,
                        issuer_key_id,
                        issuer_key_version,
                        now_unix_milliseconds,
                        generation,
                    )?;
                }
                transaction
                    .execute(
                        "DELETE FROM authorization_grant
                         WHERE issuer_key_id = ?1 AND issuer_key_version = ?2",
                        params![
                            issuer_key_id.as_bytes().as_slice(),
                            i64::from(issuer_key_version.get())
                        ],
                    )
                    .map_err(map_write_error)?;
                let removed = transaction
                    .execute(
                        "DELETE FROM authorization_issuer
                         WHERE issuer_key_id = ?1 AND issuer_key_version = ?2",
                        params![
                            issuer_key_id.as_bytes().as_slice(),
                            i64::from(issuer_key_version.get())
                        ],
                    )
                    .map_err(map_write_error)?;
                if removed != 1 {
                    return Err(LocalAuthorizationStoreError::InvalidStorage);
                }
                Ok(true)
            },
        )
    }

    /// Enrolls the first active user-presence credential.
    ///
    /// Repeating the exact active credential is unchanged. A different active
    /// credential or reuse of a reserved credential identifier conflicts.
    ///
    /// # Errors
    ///
    /// Returns a finite conflict, capacity, validation, or storage failure.
    pub fn register_user_presence_credential(
        &self,
        credential: &UserPresenceCredentialRecord,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::UserPresenceCredentialRegistered,
            |transaction, _generation| {
                if let Some(existing) = load_user_presence_credential(transaction)? {
                    return if existing == *credential {
                        Ok(false)
                    } else {
                        Err(LocalAuthorizationStoreError::Conflict)
                    };
                }
                reserve_user_presence_credential_identifier(
                    transaction,
                    credential.credential_digest(),
                )?;
                insert_user_presence_credential(transaction, credential)?;
                Ok(true)
            },
        )
    }

    /// Replaces the active user-presence credential after external verification.
    ///
    /// The expected digest binds this mutation to the credential that authorized the
    /// replacement. Identifier reservations remain for the installation lifetime.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, conflict, capacity, validation, or storage failure.
    pub fn replace_user_presence_credential(
        &self,
        expected: UserPresenceCredentialDigest,
        replacement: &UserPresenceCredentialRecord,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::UserPresenceCredentialReplaced,
            |transaction, _generation| {
                let existing = load_user_presence_credential(transaction)?
                    .ok_or(LocalAuthorizationStoreError::NotFound)?;
                if existing.credential_digest() != expected {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                if existing == *replacement {
                    return Ok(false);
                }
                if replacement.credential_digest() == expected {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                reserve_user_presence_credential_identifier(
                    transaction,
                    replacement.credential_digest(),
                )?;
                update_user_presence_credential(transaction, replacement)?;
                Ok(true)
            },
        )
    }

    /// Advances mutable verifier state for the active credential.
    ///
    /// Durable state must exactly match the record used to verify the assertion.
    /// Provider and credential identity must remain exact; only the validated
    /// credential document, such as its WebAuthn counter, may change.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, conflict, validation, or storage failure.
    pub fn update_user_presence_credential(
        &self,
        expected: &UserPresenceCredentialRecord,
        updated: &UserPresenceCredentialRecord,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::UserPresenceCredentialUpdated,
            |transaction, _generation| {
                let existing = load_user_presence_credential(transaction)?
                    .ok_or(LocalAuthorizationStoreError::NotFound)?;
                if existing != *expected
                    || expected.credential_digest() != updated.credential_digest()
                    || expected.provider_id() != updated.provider_id()
                    || expected.credential_id() != updated.credential_id()
                {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                if existing == *updated {
                    return Ok(false);
                }
                update_user_presence_credential(transaction, updated)?;
                Ok(true)
            },
        )
    }

    /// Removes the active user-presence credential after external authorization.
    ///
    /// The identifier reservation remains so a removed credential can never be
    /// silently re-enrolled. Repeating removal for a reserved digest is unchanged.
    ///
    /// # Errors
    ///
    /// Returns a finite not-found, conflict, validation, or storage failure.
    pub fn remove_user_presence_credential(
        &self,
        expected: UserPresenceCredentialDigest,
        now_unix_milliseconds: u64,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        self.mutate(
            now_unix_milliseconds,
            AuthorizationAuditKind::UserPresenceCredentialRemoved,
            |transaction, _generation| {
                let Some(existing) = load_user_presence_credential(transaction)? else {
                    return if user_presence_credential_identifier_exists(transaction, expected)? {
                        Ok(false)
                    } else {
                        Err(LocalAuthorizationStoreError::NotFound)
                    };
                };
                if existing.credential_digest() != expected {
                    return Err(LocalAuthorizationStoreError::Conflict);
                }
                let removed = transaction
                    .execute(
                        "DELETE FROM authorization_user_presence_credential
                         WHERE singleton_id = 1",
                        [],
                    )
                    .map_err(map_write_error)?;
                if removed != 1 {
                    return Err(LocalAuthorizationStoreError::InvalidStorage);
                }
                Ok(true)
            },
        )
    }

    /// Loads bounded diagnostic counts after expiring stale grants.
    ///
    /// Issuer capacity is counted across all retained versions of `issuer_key_id`.
    ///
    /// # Errors
    ///
    /// Returns a finite storage, validation, rollback, or capacity failure.
    pub fn load_status(
        &self,
        now_unix_milliseconds: u64,
        high_water: Option<AuthorizationGeneration>,
        issuer_key_id: IssuerKeyId,
        profile: &ServiceProfileId,
    ) -> Result<AuthorizationStoreStatus, LocalAuthorizationStoreError> {
        validate_timestamp(now_unix_milliseconds)?;
        let mut connection = self.lock()?;
        let mut observed_high_water = self.lock_high_water()?;
        let required_high_water = high_water
            .filter(|candidate| candidate > &*observed_high_water)
            .unwrap_or(*observed_high_water);
        let transaction = immediate_transaction(&mut connection)?;
        verify_identity_and_high_water(
            &transaction,
            self.installation_fingerprint,
            Some(required_high_water),
        )?;
        verify_integrity(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        let generation = expire_for_read(&transaction, now_unix_milliseconds)?;
        let status = load_status_inner(
            &transaction,
            generation,
            now_unix_milliseconds,
            issuer_key_id,
            profile,
        )?;
        validate_store(&transaction, self.installation_fingerprint)?;
        transaction.commit().map_err(map_write_error)?;
        *observed_high_water = status.generation;
        Ok(status)
    }

    /// Loads at most `limit` newest non-sensitive audit events.
    ///
    /// # Errors
    ///
    /// Returns invalid input for zero or a value above the retained audit bound, and
    /// otherwise returns a finite storage, validation, or rollback failure.
    pub fn load_audit_events(
        &self,
        limit: usize,
        high_water: Option<AuthorizationGeneration>,
    ) -> Result<Vec<AuthorizationAuditEvent>, LocalAuthorizationStoreError> {
        if limit == 0 || limit > MAX_AUTHORIZATION_AUDIT_RECORDS {
            return Err(LocalAuthorizationStoreError::InvalidInput);
        }
        let mut connection = self.lock()?;
        let mut observed_high_water = self.lock_high_water()?;
        let required_high_water = high_water
            .filter(|candidate| candidate > &*observed_high_water)
            .unwrap_or(*observed_high_water);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_write_error)?;
        verify_identity_and_high_water(
            &transaction,
            self.installation_fingerprint,
            Some(required_high_water),
        )?;
        verify_integrity(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        let events = load_audit_events_inner(&transaction, limit)?;
        let generation = AuthorizationGeneration::from_validated(load_generation(&transaction)?);
        transaction.commit().map_err(map_write_error)?;
        *observed_high_water = generation;
        Ok(events)
    }

    fn mutate(
        &self,
        now_unix_milliseconds: u64,
        requested_audit_kind: AuthorizationAuditKind,
        operation: impl FnOnce(&Transaction<'_>, u64) -> Result<bool, LocalAuthorizationStoreError>,
    ) -> Result<AuthorizationMutation, LocalAuthorizationStoreError> {
        validate_timestamp(now_unix_milliseconds)?;
        let mut connection = self.lock()?;
        let mut observed_high_water = self.lock_high_water()?;
        let transaction = immediate_transaction(&mut connection)?;
        verify_identity_and_high_water(
            &transaction,
            self.installation_fingerprint,
            Some(*observed_high_water),
        )?;
        verify_integrity(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        let current_generation = load_generation(&transaction)?;
        *observed_high_water = AuthorizationGeneration::from_validated(current_generation);
        let proposed_generation = next_generation(current_generation).unwrap_or(current_generation);
        let requested_change = operation(&transaction, proposed_generation)?;
        let expired = expire_grants(&transaction, now_unix_milliseconds, proposed_generation)?;
        if !requested_change && expired == 0 {
            transaction.commit().map_err(map_write_error)?;
            return Ok(AuthorizationMutation {
                generation: AuthorizationGeneration::from_validated(current_generation),
                effect: MutationEffect::Unchanged,
            });
        }
        if proposed_generation == current_generation {
            return Err(LocalAuthorizationStoreError::Capacity);
        }
        let audit_kind = if requested_change {
            requested_audit_kind
        } else {
            AuthorizationAuditKind::GrantsExpired
        };
        commit_generation(
            &transaction,
            proposed_generation,
            audit_kind,
            now_unix_milliseconds,
        )?;
        prune_bounded_history(&transaction)?;
        validate_store(&transaction, self.installation_fingerprint)?;
        transaction.commit().map_err(map_write_error)?;
        *observed_high_water = AuthorizationGeneration::from_validated(proposed_generation);
        Ok(AuthorizationMutation {
            generation: AuthorizationGeneration::from_validated(proposed_generation),
            effect: if requested_change {
                MutationEffect::Applied
            } else {
                MutationEffect::Unchanged
            },
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, LocalAuthorizationStoreError> {
        self.connection
            .lock()
            .map_err(|_| LocalAuthorizationStoreError::StorageUnavailable)
    }

    fn lock_high_water(
        &self,
    ) -> Result<MutexGuard<'_, AuthorizationGeneration>, LocalAuthorizationStoreError> {
        self.high_water
            .lock()
            .map_err(|_| LocalAuthorizationStoreError::StorageUnavailable)
    }
}

/// Returns the fixed authorization database path beside an immutable installation
/// record.
///
/// # Errors
///
/// Returns [`LocalAuthorizationStoreError::InvalidInput`] unless the input is an
/// absolute path ending in the canonical installation-record file name.
pub fn authorization_store_path(
    installation_record_path: impl AsRef<Path>,
) -> Result<PathBuf, LocalAuthorizationStoreError> {
    let installation_record_path = installation_record_path.as_ref();
    if !installation_record_path.is_absolute()
        || installation_record_path.file_name() != Some(OsStr::new(LOCAL_SERVICE_INSTALLATION_FILE))
    {
        return Err(LocalAuthorizationStoreError::InvalidInput);
    }
    let parent = installation_record_path
        .parent()
        .ok_or(LocalAuthorizationStoreError::InvalidInput)?;
    Ok(parent.join(LOCAL_AUTHORIZATION_STORE_FILE))
}

fn reject_wal_sidecars(database_path: &Path) -> Result<(), LocalAuthorizationStoreError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => return Err(LocalAuthorizationStoreError::InvalidStorage),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(LocalAuthorizationStoreError::StorageUnavailable),
        }
    }
    Ok(())
}

fn immediate_transaction(
    connection: &mut Connection,
) -> Result<Transaction<'_>, LocalAuthorizationStoreError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_write_error)
}

fn configure_connection(connection: &Connection) -> Result<(), LocalAuthorizationStoreError> {
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_WRITABLE_SCHEMA, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    connection
        .busy_timeout(Duration::from_millis(
            AUTHORIZATION_STORE_BUSY_TIMEOUT_MILLISECONDS,
        ))
        .map_err(map_write_error)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(map_write_error)?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(map_write_error)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(map_write_error)?;
    verify_pragmas(connection)
}

fn set_db_config(
    connection: &Connection,
    config: DbConfig,
    enabled: bool,
) -> Result<(), LocalAuthorizationStoreError> {
    let configured = connection
        .set_db_config(config, enabled)
        .map_err(map_write_error)?;
    if configured != enabled {
        return Err(LocalAuthorizationStoreError::StorageUnavailable);
    }
    Ok(())
}

fn verify_pragmas(connection: &Connection) -> Result<(), LocalAuthorizationStoreError> {
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(map_read_error)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(map_read_error)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(map_read_error)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(map_read_error)?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(map_read_error)?;
    if foreign_keys != 1
        || !journal_mode.eq_ignore_ascii_case("delete")
        || synchronous != 2
        || trusted_schema != 0
        || u64_from_sql(busy_timeout)? != AUTHORIZATION_STORE_BUSY_TIMEOUT_MILLISECONDS
    {
        return Err(LocalAuthorizationStoreError::StorageUnavailable);
    }
    Ok(())
}

fn initialize_or_validate(
    connection: &mut Connection,
    installation_fingerprint: InstallationFingerprint,
    bootstrap: Option<(&AuthorizationPolicy, &[InstalledIssuerRegistration], u64)>,
) -> Result<(), LocalAuthorizationStoreError> {
    let expected_schema = expected_schema_objects(SCHEMA_VERSION)?;
    let transaction = immediate_transaction(connection)?;
    let existing_schema = schema_objects(&transaction)?;
    if existing_schema.is_empty() {
        let Some((bootstrap_policy, bootstrap_issuers, now_unix_milliseconds)) = bootstrap else {
            return Err(LocalAuthorizationStoreError::InvalidStorage);
        };
        create_schema_v2(&transaction)?;
        bootstrap_store(
            &transaction,
            installation_fingerprint,
            bootstrap_policy,
            bootstrap_issuers,
            now_unix_milliseconds,
        )?;
    } else {
        if !existing_schema
            .iter()
            .any(|object| object.name == "authorization_store_meta")
        {
            return Err(LocalAuthorizationStoreError::UnsupportedSchema);
        }
        let version: Option<i64> = transaction
            .query_row(
                "SELECT schema_version
                 FROM authorization_store_meta
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_read_error)?;
        match version {
            Some(1) => {
                if existing_schema != expected_schema_objects(1)? {
                    return Err(LocalAuthorizationStoreError::InvalidStorage);
                }
                verify_identity_and_high_water(&transaction, installation_fingerprint, None)?;
                migrate_schema_v1_to_v2(&transaction)?;
            }
            Some(version) if version == i64::from(SCHEMA_VERSION) => {
                if existing_schema != expected_schema {
                    return Err(LocalAuthorizationStoreError::InvalidStorage);
                }
                verify_identity_and_high_water(&transaction, installation_fingerprint, None)?;
            }
            _ => return Err(LocalAuthorizationStoreError::UnsupportedSchema),
        }
    }
    if schema_objects(&transaction)? != expected_schema {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    transaction.commit().map_err(map_write_error)
}

fn bootstrap_store(
    transaction: &Transaction<'_>,
    installation_fingerprint: InstallationFingerprint,
    policy: &AuthorizationPolicy,
    issuers: &[InstalledIssuerRegistration],
    now_unix_milliseconds: u64,
) -> Result<(), LocalAuthorizationStoreError> {
    transaction
        .execute(
            "INSERT INTO authorization_store_meta (
                singleton_id,
                schema_version,
                installation_fingerprint,
                generation,
                policy_version
             ) VALUES (1, ?1, ?2, 1, ?3)",
            params![
                i64::from(SCHEMA_VERSION),
                installation_fingerprint.as_bytes().as_slice(),
                to_sql(policy.version().get())?
            ],
        )
        .map_err(map_write_error)?;
    insert_policy_clauses(transaction, policy)?;

    let mut ordered = issuers.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.issuer_key_id()
            .as_bytes()
            .cmp(right.issuer_key_id().as_bytes())
            .then_with(|| {
                left.issuer_key_version()
                    .get()
                    .cmp(&right.issuer_key_version().get())
            })
    });
    for issuer in ordered {
        insert_issuer(transaction, issuer)?;
    }
    transaction
        .execute(
            "INSERT INTO authorization_audit (
                generation, event_kind, occurred_at_unix_milliseconds
             ) VALUES (1, ?1, ?2)",
            params![
                audit_kind_code(AuthorizationAuditKind::Bootstrap),
                to_sql(now_unix_milliseconds)?
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn validate_bootstrap(
    policy: &AuthorizationPolicy,
    issuers: &[InstalledIssuerRegistration],
) -> Result<(), LocalAuthorizationStoreError> {
    if policy.clauses().is_empty()
        || policy.clauses().len() > MAX_POLICY_CLAUSES
        || issuers.is_empty()
        || issuers.len() > MAX_ADAPTER_REGISTRATIONS
    {
        return Err(LocalAuthorizationStoreError::InvalidInput);
    }
    let mut identities = issuers
        .iter()
        .map(|issuer| {
            (
                *issuer.issuer_key_id().as_bytes(),
                issuer.issuer_key_version().get(),
            )
        })
        .collect::<Vec<_>>();
    identities.sort_unstable();
    if identities.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LocalAuthorizationStoreError::InvalidInput);
    }
    Ok(())
}

fn verify_integrity(connection: &Connection) -> Result<(), LocalAuthorizationStoreError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(map_read_error)?;
    if result != "ok" {
        return Err(LocalAuthorizationStoreError::CorruptStorage);
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

fn create_schema_v2(connection: &Connection) -> Result<(), LocalAuthorizationStoreError> {
    connection
        .execute_batch(CREATE_CORE_SCHEMA_SQL)
        .map_err(map_write_error)?;
    connection
        .execute_batch(CREATE_USER_PRESENCE_SCHEMA_SQL)
        .map_err(map_write_error)?;
    connection
        .execute_batch(CREATE_AUTHORIZATION_AUDIT_V2_SQL)
        .map_err(map_write_error)
}

fn migrate_schema_v1_to_v2(
    transaction: &Transaction<'_>,
) -> Result<(), LocalAuthorizationStoreError> {
    transaction
        .execute_batch(CREATE_USER_PRESENCE_SCHEMA_SQL)
        .map_err(map_write_error)?;
    transaction
        .execute_batch("ALTER TABLE authorization_audit RENAME TO authorization_audit_v1;")
        .map_err(map_write_error)?;
    transaction
        .execute_batch(CREATE_AUTHORIZATION_AUDIT_V2_SQL)
        .map_err(map_write_error)?;
    transaction
        .execute(
            "INSERT INTO authorization_audit (
                generation,
                event_kind,
                occurred_at_unix_milliseconds
             )
             SELECT generation, event_kind, occurred_at_unix_milliseconds
             FROM authorization_audit_v1",
            [],
        )
        .map_err(map_write_error)?;
    transaction
        .execute_batch("DROP TABLE authorization_audit_v1;")
        .map_err(map_write_error)?;
    let updated = transaction
        .execute(
            "UPDATE authorization_store_meta
             SET schema_version = ?1
             WHERE singleton_id = 1 AND schema_version = 1",
            [i64::from(SCHEMA_VERSION)],
        )
        .map_err(map_write_error)?;
    if updated != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

fn expected_schema_objects(
    schema_version: u32,
) -> Result<Vec<SchemaObject>, LocalAuthorizationStoreError> {
    let connection = Connection::open_in_memory().map_err(map_open_error)?;
    connection
        .execute_batch(CREATE_CORE_SCHEMA_SQL)
        .map_err(map_write_error)?;
    match schema_version {
        1 => connection
            .execute_batch(CREATE_AUTHORIZATION_AUDIT_V1_SQL)
            .map_err(map_write_error)?,
        SCHEMA_VERSION => {
            connection
                .execute_batch(CREATE_USER_PRESENCE_SCHEMA_SQL)
                .map_err(map_write_error)?;
            connection
                .execute_batch(CREATE_AUTHORIZATION_AUDIT_V2_SQL)
                .map_err(map_write_error)?;
        }
        _ => return Err(LocalAuthorizationStoreError::UnsupportedSchema),
    }
    schema_objects(&connection)
}

fn schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObject>, LocalAuthorizationStoreError> {
    let metrics: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(MAX(length(CAST(type AS BLOB))), 0),
                    COALESCE(MAX(length(CAST(name AS BLOB))), 0),
                    COALESCE(MAX(length(CAST(tbl_name AS BLOB))), 0),
                    COALESCE(MAX(length(CAST(sql AS BLOB))), 0)
             FROM sqlite_schema",
            [],
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
        .map_err(map_read_error)?;
    if metrics.0 > HARD_MAX_SCHEMA_OBJECT_COUNT
        || metrics.1 > MAX_SCHEMA_IDENTIFIER_BYTES
        || metrics.2 > MAX_SCHEMA_IDENTIFIER_BYTES
        || metrics.3 > MAX_SCHEMA_IDENTIFIER_BYTES
        || metrics.4 > MAX_SCHEMA_SQL_BYTES
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_schema
             ORDER BY type, name
             LIMIT 33",
        )
        .map_err(map_read_error)?;
    statement
        .query_map([], |row| {
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(map_read_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_read_error)
}

fn verify_identity_and_high_water(
    connection: &Connection,
    expected_fingerprint: InstallationFingerprint,
    high_water: Option<AuthorizationGeneration>,
) -> Result<(), LocalAuthorizationStoreError> {
    let lengths: Option<(i64, i64)> = connection
        .query_row(
            "SELECT length(installation_fingerprint), generation
             FROM authorization_store_meta
             WHERE singleton_id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((fingerprint_length, generation)) = lengths else {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    };
    if fingerprint_length != 32 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    let generation = u64_from_positive_sql(generation)?;
    if high_water.is_some_and(|high_water| generation < high_water.get()) {
        return Err(LocalAuthorizationStoreError::GenerationRollback);
    }
    let stored: Vec<u8> = connection
        .query_row(
            "SELECT installation_fingerprint
             FROM authorization_store_meta
             WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    if stored.as_slice() != expected_fingerprint.as_bytes() {
        return Err(LocalAuthorizationStoreError::InstallationMismatch);
    }
    Ok(())
}

fn validate_store(
    connection: &Connection,
    installation_fingerprint: InstallationFingerprint,
) -> Result<(), LocalAuthorizationStoreError> {
    verify_identity_and_high_water(connection, installation_fingerprint, None)?;
    validate_row_bounds(connection)?;
    let generation = load_generation(connection)?;
    let policy = load_policy(connection)?;
    let issuers = load_issuers(connection)?;
    let suspended = load_suspended_profiles(connection)?;
    let grants = load_all_grants(connection)?;
    let user_presence_credential = load_user_presence_credential(connection)?;
    let audit = load_audit_events_inner(connection, MAX_AUTHORIZATION_AUDIT_RECORDS)?;

    let active_grants = grants
        .iter()
        .filter(|grant| grant.state == GrantState::Active)
        .collect::<Vec<_>>();
    if issuers.len() > MAX_ADAPTER_REGISTRATIONS
        || suspended.len() > MAX_SUSPENDED_PROFILES
        || active_grants.len() > MAX_SESSION_GRANTS
        || grants
            .iter()
            .filter(|grant| grant.state != GrantState::Active)
            .count()
            > MAX_TERMINAL_GRANT_RECORDS
        || audit.is_empty()
        || audit.len() > MAX_AUTHORIZATION_AUDIT_RECORDS
        || count_rows(
            connection,
            "authorization_user_presence_credential_identifier",
        )? > MAX_USER_PRESENCE_CREDENTIAL_IDENTIFIERS
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    if let Some(credential) = user_presence_credential
        && !user_presence_credential_identifier_exists(connection, credential.credential_digest())?
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    for grant in &active_grants {
        if active_grants
            .iter()
            .filter(|candidate| candidate.grant.issuer_key_id() == grant.grant.issuer_key_id())
            .count()
            > MAX_GRANTS_PER_ISSUER
            || active_grants
                .iter()
                .filter(|candidate| candidate.grant.profile() == grant.grant.profile())
                .count()
                > MAX_GRANTS_PER_PROFILE
        {
            return Err(LocalAuthorizationStoreError::InvalidStorage);
        }
    }
    if grants.iter().any(|grant| {
        grant
            .terminal_generation
            .is_some_and(|terminal_generation| terminal_generation > generation)
    }) {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    for stored in &grants {
        let issuer = issuers
            .iter()
            .find(|issuer| {
                issuer.issuer_key_id == stored.grant.issuer_key_id()
                    && issuer.issuer_key_version == stored.grant.issuer_key_version()
            })
            .ok_or(LocalAuthorizationStoreError::InvalidStorage)?;
        if (issuer.registration.harness() != stored.grant.harness()
            && issuer.registration.harness() != HarnessKind::Generic)
            || !issuer
                .registration
                .profiles()
                .permits(stored.grant.profile())
            || stored.grant.policy_version() > policy.version()
        {
            return Err(LocalAuthorizationStoreError::InvalidStorage);
        }
        if stored.state == GrantState::Active
            && (suspended
                .iter()
                .any(|profile| profile == stored.grant.profile())
                || !policy.accepts(stored.grant.evidence())
                || (issuer.availability == IssuerAvailability::Disabled
                    && issuer.existing_grant_disposition == ExistingGrantDisposition::Revoke))
        {
            return Err(LocalAuthorizationStoreError::InvalidStorage);
        }
    }
    let foreign_key_violation: Option<i64> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(1))
        .optional()
        .map_err(map_read_error)?;
    if foreign_key_violation.is_some() {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    let expected_audit_count =
        usize::try_from(generation.min(MAX_AUTHORIZATION_AUDIT_RECORDS as u64))
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    if audit.len() != expected_audit_count
        || audit.first().map(|event| event.generation().get()) != Some(generation)
        || audit.last().map(|event| event.generation().get())
            != Some(
                generation
                    .checked_sub(
                        u64::try_from(expected_audit_count - 1)
                            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
                    )
                    .ok_or(LocalAuthorizationStoreError::InvalidStorage)?,
            )
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    if generation <= MAX_AUTHORIZATION_AUDIT_RECORDS as u64
        && audit.last().map(|event| event.kind()) != Some(AuthorizationAuditKind::Bootstrap)
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

fn validate_row_bounds(connection: &Connection) -> Result<(), LocalAuthorizationStoreError> {
    let meta: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(installation_fingerprint)), 0)
             FROM authorization_store_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_read_error)?;
    let policy_count = count_rows(connection, "authorization_policy_clause")?;
    let issuer_identifier_metrics: (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(MAX(length(issuer_key_id)), 0),
                    COALESCE(MAX(issuer_key_version), 0)
             FROM authorization_issuer_identifier",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(map_read_error)?;
    let issuer_metrics: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(MAX(length(issuer_key_id)), 0),
                    COALESCE(MAX(length(public_key)), 0),
                    COALESCE(MAX(length(CAST(profile_id AS BLOB))), 0)
             FROM authorization_issuer",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_read_error)?;
    let suspended_metrics: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(CAST(profile_id AS BLOB))), 0)
             FROM authorization_suspended_profile",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_read_error)?;
    let grant_identifier_metrics: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(grant_id)), 0)
             FROM authorization_grant_identifier",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_read_error)?;
    let grant_metrics: (i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(MAX(length(grant_id)), 0),
                    COALESCE(MAX(length(issuer_key_id)), 0),
                    COALESCE(MAX(length(session_public_key)), 0),
                    COALESCE(MAX(length(issuer_client_instance)), 0),
                    COALESCE(MAX(length(issuance_request_id)), 0),
                    COALESCE(MAX(length(CAST(profile_id AS BLOB))), 0)
             FROM authorization_grant",
            [],
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
        .map_err(map_read_error)?;
    let active_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authorization_grant WHERE state = 1",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let terminal_count = grant_metrics
        .0
        .checked_sub(active_count)
        .ok_or(LocalAuthorizationStoreError::InvalidStorage)?;
    let audit_count = count_rows(connection, "authorization_audit")?;
    let user_presence_identifier_metrics: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(credential_digest)), 0)
             FROM authorization_user_presence_credential_identifier",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_read_error)?;
    let user_presence_metrics: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(MAX(length(CAST(provider_id AS BLOB))), 0),
                    COALESCE(MAX(length(credential_id)), 0),
                    COALESCE(MAX(length(credential_digest)), 0),
                    COALESCE(MAX(length(credential_document)), 0)
             FROM authorization_user_presence_credential",
            [],
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
        .map_err(map_read_error)?;
    let unreserved_issuers: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_issuer AS issuer
             LEFT JOIN authorization_issuer_identifier AS reserved
               ON reserved.issuer_key_id = issuer.issuer_key_id
              AND reserved.issuer_key_version = issuer.issuer_key_version
             WHERE reserved.issuer_key_id IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let unreserved_grants: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant AS grant_record
             LEFT JOIN authorization_grant_identifier AS issued
               ON issued.grant_id = grant_record.grant_id
             WHERE issued.grant_id IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;

    if meta != (1, 32)
        || policy_count == 0
        || policy_count > MAX_POLICY_CLAUSES
        || issuer_identifier_metrics.0
            > i64::try_from(MAX_ADAPTER_REGISTRATIONS).unwrap_or(i64::MAX)
        || (issuer_identifier_metrics.0 > 0
            && (issuer_identifier_metrics.1 != 16
                || issuer_identifier_metrics.2 < 1
                || issuer_identifier_metrics.2 > i64::from(u32::MAX)))
        || issuer_metrics.0 > i64::try_from(MAX_ADAPTER_REGISTRATIONS).unwrap_or(i64::MAX)
        || (issuer_metrics.0 > 0
            && (issuer_metrics.1 != 16 || issuer_metrics.2 != 32 || issuer_metrics.3 > 32))
        || suspended_metrics.0 > i64::try_from(MAX_SUSPENDED_PROFILES).unwrap_or(i64::MAX)
        || suspended_metrics.1 > 32
        || grant_identifier_metrics.0 > i64::try_from(MAX_GRANT_IDENTIFIERS).unwrap_or(i64::MAX)
        || (grant_identifier_metrics.0 > 0 && grant_identifier_metrics.1 != 16)
        || grant_metrics.0
            > i64::try_from(MAX_SESSION_GRANTS + MAX_TERMINAL_GRANT_RECORDS).unwrap_or(i64::MAX)
        || (grant_metrics.0 > 0
            && (grant_metrics.1 != 16
                || grant_metrics.2 != 16
                || grant_metrics.3 != 32
                || grant_metrics.4 != 16
                || grant_metrics.5 != 16
                || grant_metrics.6 > 32))
        || active_count > i64::try_from(MAX_SESSION_GRANTS).unwrap_or(i64::MAX)
        || terminal_count > i64::try_from(MAX_TERMINAL_GRANT_RECORDS).unwrap_or(i64::MAX)
        || audit_count == 0
        || audit_count > MAX_AUTHORIZATION_AUDIT_RECORDS
        || user_presence_identifier_metrics.0
            > i64::try_from(MAX_USER_PRESENCE_CREDENTIAL_IDENTIFIERS).unwrap_or(i64::MAX)
        || (user_presence_identifier_metrics.0 > 0 && user_presence_identifier_metrics.1 != 32)
        || user_presence_metrics.0 > 1
        || (user_presence_metrics.0 > 0
            && (user_presence_metrics.1 < 1
                || user_presence_metrics.1 > 64
                || user_presence_metrics.2 < 1
                || user_presence_metrics.2 > 1024
                || user_presence_metrics.3 != 32
                || user_presence_metrics.4 < 1
                || user_presence_metrics.4
                    > i64::try_from(MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES).unwrap_or(i64::MAX)))
        || unreserved_issuers != 0
        || unreserved_grants != 0
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

fn load_generation(connection: &Connection) -> Result<u64, LocalAuthorizationStoreError> {
    let generation: i64 = connection
        .query_row(
            "SELECT generation
             FROM authorization_store_meta
             WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    u64_from_positive_sql(generation)
}

fn load_policy(
    connection: &Connection,
) -> Result<AuthorizationPolicy, LocalAuthorizationStoreError> {
    let version: i64 = connection
        .query_row(
            "SELECT policy_version
             FROM authorization_store_meta
             WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let version = AuthorizationPolicyVersion::new(u64_from_positive_sql(version)?)
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    let mut statement = connection
        .prepare(
            "SELECT ordinal, evidence_bits
             FROM authorization_policy_clause
             ORDER BY ordinal
             LIMIT 9",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
        .map_err(map_read_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_read_error)?;
    if rows.is_empty() || rows.len() > MAX_POLICY_CLAUSES {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    let mut clauses = Vec::with_capacity(rows.len());
    for (expected_ordinal, (ordinal, bits)) in rows.into_iter().enumerate() {
        if ordinal
            != i64::try_from(expected_ordinal)
                .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?
        {
            return Err(LocalAuthorizationStoreError::InvalidStorage);
        }
        let bits = u8::try_from(bits).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
        clauses.push(
            AuthorizationEvidenceSet::from_bits(bits)
                .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        );
    }
    if clauses.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    AuthorizationPolicy::new(version, clauses)
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)
}

fn insert_policy_clauses(
    transaction: &Transaction<'_>,
    policy: &AuthorizationPolicy,
) -> Result<(), LocalAuthorizationStoreError> {
    for (ordinal, clause) in policy.clauses().iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO authorization_policy_clause (ordinal, evidence_bits)
                 VALUES (?1, ?2)",
                params![
                    i64::try_from(ordinal)
                        .map_err(|_| LocalAuthorizationStoreError::InvalidInput)?,
                    i64::from(clause.bits())
                ],
            )
            .map_err(map_write_error)?;
    }
    Ok(())
}

fn replace_policy_rows(
    transaction: &Transaction<'_>,
    policy: &AuthorizationPolicy,
) -> Result<(), LocalAuthorizationStoreError> {
    if policy.clauses().is_empty() || policy.clauses().len() > MAX_POLICY_CLAUSES {
        return Err(LocalAuthorizationStoreError::InvalidInput);
    }
    transaction
        .execute("DELETE FROM authorization_policy_clause", [])
        .map_err(map_write_error)?;
    insert_policy_clauses(transaction, policy)?;
    let changed = transaction
        .execute(
            "UPDATE authorization_store_meta
             SET policy_version = ?1
             WHERE singleton_id = 1",
            params![to_sql(policy.version().get())?],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

type IssuerRow = (Vec<u8>, i64, Vec<u8>, i64, i64, String, i64, i64);

fn load_issuers(
    connection: &Connection,
) -> Result<Vec<AuthorizationIssuerRecord>, LocalAuthorizationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT issuer_key_id,
                    issuer_key_version,
                    public_key,
                    harness,
                    profile_kind,
                    profile_id,
                    enabled,
                    existing_grant_disposition
             FROM authorization_issuer
             ORDER BY issuer_key_id, issuer_key_version
             LIMIT 257",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map([], |row| {
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
        })
        .map_err(map_read_error)?
        .collect::<Result<Vec<IssuerRow>, _>>()
        .map_err(map_read_error)?;
    if rows.len() > MAX_ADAPTER_REGISTRATIONS {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    rows.into_iter().map(decode_issuer).collect()
}

fn load_issuer(
    connection: &Connection,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
) -> Result<Option<AuthorizationIssuerRecord>, LocalAuthorizationStoreError> {
    let row: Option<IssuerRow> = connection
        .query_row(
            "SELECT issuer_key_id,
                    issuer_key_version,
                    public_key,
                    harness,
                    profile_kind,
                    profile_id,
                    enabled,
                    existing_grant_disposition
             FROM authorization_issuer
             WHERE issuer_key_id = ?1 AND issuer_key_version = ?2",
            params![
                issuer_key_id.as_bytes().as_slice(),
                i64::from(issuer_key_version.get())
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
        .map_err(map_read_error)?;
    row.map(decode_issuer).transpose()
}

fn issuer_identifier_exists(
    connection: &Connection,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
) -> Result<bool, LocalAuthorizationStoreError> {
    connection
        .query_row(
            "SELECT 1
             FROM authorization_issuer_identifier
             WHERE issuer_key_id = ?1 AND issuer_key_version = ?2",
            params![
                issuer_key_id.as_bytes().as_slice(),
                i64::from(issuer_key_version.get())
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(map_read_error)
}

fn decode_issuer(
    row: IssuerRow,
) -> Result<AuthorizationIssuerRecord, LocalAuthorizationStoreError> {
    let issuer_key_id = IssuerKeyId::from_slice(&row.0)
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    let issuer_key_version = IssuerKeyVersion::new(
        u32::try_from(row.1).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
    )
    .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    let public_key = Ed25519PublicKey::from_slice(&row.2)
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    let harness = HarnessKind::from_wire_value(
        u16::try_from(row.3).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
    )
    .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    let profiles = match row.4 {
        1 => ProfileAuthorization::Profile(
            ServiceProfileId::parse(&row.5)
                .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        ),
        2 => ProfileAuthorization::Namespace(
            ServiceProfileId::parse(&row.5)
                .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        ),
        3 if row.5.is_empty() => ProfileAuthorization::All,
        _ => return Err(LocalAuthorizationStoreError::InvalidStorage),
    };
    Ok(AuthorizationIssuerRecord {
        issuer_key_id,
        issuer_key_version,
        registration: IssuerRegistration::new(public_key, harness, profiles),
        availability: availability_from_code(row.6)?,
        existing_grant_disposition: disposition_from_code(row.7)?,
    })
}

fn insert_issuer(
    transaction: &Transaction<'_>,
    issuer: &InstalledIssuerRegistration,
) -> Result<(), LocalAuthorizationStoreError> {
    let (profile_kind, profile_id) = match issuer.registration().profiles() {
        ProfileAuthorization::Profile(profile) => (1_i64, profile.as_str()),
        ProfileAuthorization::Namespace(profile) => (2_i64, profile.as_str()),
        ProfileAuthorization::All => (3_i64, ""),
    };
    let reserved = transaction
        .execute(
            "INSERT INTO authorization_issuer_identifier (
                issuer_key_id,
                issuer_key_version
             ) VALUES (?1, ?2)",
            params![
                issuer.issuer_key_id().as_bytes().as_slice(),
                i64::from(issuer.issuer_key_version().get())
            ],
        )
        .map_err(map_write_error)?;
    if reserved != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    transaction
        .execute(
            "INSERT INTO authorization_issuer (
                issuer_key_id,
                issuer_key_version,
                public_key,
                harness,
                profile_kind,
                profile_id,
                enabled,
                existing_grant_disposition
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1)",
            params![
                issuer.issuer_key_id().as_bytes().as_slice(),
                i64::from(issuer.issuer_key_version().get()),
                issuer.registration().public_key().as_bytes().as_slice(),
                i64::from(issuer.registration().harness().wire_value()),
                profile_kind,
                profile_id
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn load_suspended_profiles(
    connection: &Connection,
) -> Result<Vec<ServiceProfileId>, LocalAuthorizationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT profile_id
             FROM authorization_suspended_profile
             ORDER BY profile_id
             LIMIT 257",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(map_read_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_read_error)?;
    if rows.len() > MAX_SUSPENDED_PROFILES {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    rows.into_iter()
        .map(|profile| {
            ServiceProfileId::parse(&profile)
                .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)
        })
        .collect()
}

fn is_profile_suspended(
    connection: &Connection,
    profile: &ServiceProfileId,
) -> Result<bool, LocalAuthorizationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS (
                SELECT 1
                FROM authorization_suspended_profile
                WHERE profile_id = ?1
             )",
            params![profile.as_str()],
            |row| row.get(0),
        )
        .map_err(map_read_error)
}

type UserPresenceCredentialRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

fn load_user_presence_credential(
    connection: &Connection,
) -> Result<Option<UserPresenceCredentialRecord>, LocalAuthorizationStoreError> {
    let row: Option<UserPresenceCredentialRow> = connection
        .query_row(
            "SELECT provider_id,
                    credential_id,
                    credential_digest,
                    credential_document
             FROM authorization_user_presence_credential
             WHERE singleton_id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((provider_id, credential_id, credential_digest, document)) = row else {
        return Ok(None);
    };
    let record = UserPresenceCredentialRecord::from_document(document)
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    if provider_id != record.provider_id().as_str()
        || credential_id.as_slice() != record.credential_id().as_bytes()
        || credential_digest.as_slice() != record.credential_digest().as_bytes()
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(Some(record))
}

fn user_presence_credential_identifier_exists(
    connection: &Connection,
    digest: UserPresenceCredentialDigest,
) -> Result<bool, LocalAuthorizationStoreError> {
    connection
        .query_row(
            "SELECT 1
             FROM authorization_user_presence_credential_identifier
             WHERE credential_digest = ?1",
            params![digest.as_bytes().as_slice()],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(map_read_error)
}

fn reserve_user_presence_credential_identifier(
    transaction: &Transaction<'_>,
    digest: UserPresenceCredentialDigest,
) -> Result<(), LocalAuthorizationStoreError> {
    if user_presence_credential_identifier_exists(transaction, digest)? {
        return Err(LocalAuthorizationStoreError::Conflict);
    }
    if count_rows(
        transaction,
        "authorization_user_presence_credential_identifier",
    )? >= MAX_USER_PRESENCE_CREDENTIAL_IDENTIFIERS
    {
        return Err(LocalAuthorizationStoreError::Capacity);
    }
    let inserted = transaction
        .execute(
            "INSERT INTO authorization_user_presence_credential_identifier (
                credential_digest
             ) VALUES (?1)",
            params![digest.as_bytes().as_slice()],
        )
        .map_err(map_write_error)?;
    if inserted != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

fn insert_user_presence_credential(
    transaction: &Transaction<'_>,
    credential: &UserPresenceCredentialRecord,
) -> Result<(), LocalAuthorizationStoreError> {
    let inserted = transaction
        .execute(
            "INSERT INTO authorization_user_presence_credential (
                singleton_id,
                provider_id,
                credential_id,
                credential_digest,
                credential_document
             ) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                credential.provider_id().as_str(),
                credential.credential_id().as_bytes(),
                credential.credential_digest().as_bytes().as_slice(),
                credential.document()
            ],
        )
        .map_err(map_write_error)?;
    if inserted != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

fn update_user_presence_credential(
    transaction: &Transaction<'_>,
    credential: &UserPresenceCredentialRecord,
) -> Result<(), LocalAuthorizationStoreError> {
    let updated = transaction
        .execute(
            "UPDATE authorization_user_presence_credential
             SET provider_id = ?1,
                 credential_id = ?2,
                 credential_digest = ?3,
                 credential_document = ?4
             WHERE singleton_id = 1",
            params![
                credential.provider_id().as_str(),
                credential.credential_id().as_bytes(),
                credential.credential_digest().as_bytes().as_slice(),
                credential.document()
            ],
        )
        .map_err(map_write_error)?;
    if updated != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GrantState {
    Active,
    Retired,
    Revoked,
    Expired,
    ProfileSuspended,
    IssuerDisabled,
    PolicyInvalid,
}

struct StoredGrant {
    grant: SessionGrant,
    state: GrantState,
    terminal_generation: Option<u64>,
}

type GrantRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    String,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
);

fn load_all_grants(
    connection: &Connection,
) -> Result<Vec<StoredGrant>, LocalAuthorizationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT grant_id,
                    issuer_key_id,
                    issuer_key_version,
                    profile_id,
                    session_public_key,
                    harness,
                    evidence_bits,
                    policy_version,
                    issued_at_unix_milliseconds,
                    expires_at_unix_milliseconds,
                    capabilities,
                    state,
                    terminal_generation,
                    terminal_at_unix_milliseconds
             FROM authorization_grant
             ORDER BY grant_id
             LIMIT 513",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map([], grant_row)
        .map_err(map_read_error)?
        .collect::<Result<Vec<GrantRow>, _>>()
        .map_err(map_read_error)?;
    if rows.len() > MAX_SESSION_GRANTS + MAX_TERMINAL_GRANT_RECORDS {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    rows.into_iter().map(decode_grant).collect()
}

fn load_active_grants(
    connection: &Connection,
    now_unix_milliseconds: u64,
) -> Result<Vec<SessionGrant>, LocalAuthorizationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT grant_id,
                    issuer_key_id,
                    issuer_key_version,
                    profile_id,
                    session_public_key,
                    harness,
                    evidence_bits,
                    policy_version,
                    issued_at_unix_milliseconds,
                    expires_at_unix_milliseconds,
                    capabilities,
                    state,
                    terminal_generation,
                    terminal_at_unix_milliseconds
             FROM authorization_grant
             WHERE state = 1 AND expires_at_unix_milliseconds > ?1
             ORDER BY grant_id
             LIMIT 257",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map(params![to_sql(now_unix_milliseconds)?], grant_row)
        .map_err(map_read_error)?
        .collect::<Result<Vec<GrantRow>, _>>()
        .map_err(map_read_error)?;
    if rows.len() > MAX_SESSION_GRANTS {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    rows.into_iter()
        .map(decode_grant)
        .map(|stored| {
            stored.and_then(|stored| {
                if stored.state == GrantState::Active {
                    Ok(stored.grant)
                } else {
                    Err(LocalAuthorizationStoreError::InvalidStorage)
                }
            })
        })
        .collect()
}

fn load_grant_by_id(
    connection: &Connection,
    grant_id: SessionGrantId,
) -> Result<Option<StoredGrant>, LocalAuthorizationStoreError> {
    let row = connection
        .query_row(
            "SELECT grant_id,
                    issuer_key_id,
                    issuer_key_version,
                    profile_id,
                    session_public_key,
                    harness,
                    evidence_bits,
                    policy_version,
                    issued_at_unix_milliseconds,
                    expires_at_unix_milliseconds,
                    capabilities,
                    state,
                    terminal_generation,
                    terminal_at_unix_milliseconds
             FROM authorization_grant
             WHERE grant_id = ?1",
            params![grant_id.as_bytes().as_slice()],
            grant_row,
        )
        .optional()
        .map_err(map_read_error)?;
    row.map(decode_grant).transpose()
}

fn load_grant_by_issuance(
    connection: &Connection,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    request_key: GrantIssuanceKey,
) -> Result<Option<StoredGrant>, LocalAuthorizationStoreError> {
    let row = connection
        .query_row(
            "SELECT grant_id,
                    issuer_key_id,
                    issuer_key_version,
                    profile_id,
                    session_public_key,
                    harness,
                    evidence_bits,
                    policy_version,
                    issued_at_unix_milliseconds,
                    expires_at_unix_milliseconds,
                    capabilities,
                    state,
                    terminal_generation,
                    terminal_at_unix_milliseconds
             FROM authorization_grant
             WHERE issuer_key_id = ?1
               AND issuer_key_version = ?2
               AND issuer_client_instance = ?3
               AND issuance_request_id = ?4",
            params![
                issuer_key_id.as_bytes().as_slice(),
                i64::from(issuer_key_version.get()),
                request_key.issuer_client_instance().as_bytes().as_slice(),
                request_key.request_id().as_bytes().as_slice()
            ],
            grant_row,
        )
        .optional()
        .map_err(map_read_error)?;
    row.map(decode_grant).transpose()
}

fn same_issuance_request(existing: &SessionGrant, candidate: &SessionGrant) -> bool {
    existing.issuer_key_id() == candidate.issuer_key_id()
        && existing.issuer_key_version() == candidate.issuer_key_version()
        && existing.profile() == candidate.profile()
        && existing.session_public_key() == candidate.session_public_key()
        && existing.harness() == candidate.harness()
}

fn grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
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
}

fn decode_grant(row: GrantRow) -> Result<StoredGrant, LocalAuthorizationStoreError> {
    let grant = SessionGrant::new(SessionGrantClaims {
        grant_id: SessionGrantId::from_slice(&row.0)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        issuer_key_id: IssuerKeyId::from_slice(&row.1)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        issuer_key_version: IssuerKeyVersion::new(
            u32::try_from(row.2).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        )
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        profile: ServiceProfileId::parse(&row.3)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        session_public_key: Ed25519PublicKey::from_slice(&row.4)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        harness: HarnessKind::from_wire_value(
            u16::try_from(row.5).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        )
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        evidence: AuthorizationEvidenceSet::from_bits(
            u8::try_from(row.6).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        )
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        policy_version: AuthorizationPolicyVersion::new(u64_from_positive_sql(row.7)?)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        issued_at_unix_milliseconds: u64_from_sql(row.8)?,
        expires_at_unix_milliseconds: u64_from_positive_sql(row.9)?,
        capabilities: SessionCapabilities::from_bits(u64_from_positive_sql(row.10)?)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
    })
    .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
    let state = grant_state_from_code(row.11)?;
    let terminal_generation = row.12.map(u64_from_positive_sql).transpose()?;
    let terminal_at = row.13.map(u64_from_sql).transpose()?;
    if (state == GrantState::Active && (terminal_generation.is_some() || terminal_at.is_some()))
        || (state != GrantState::Active && (terminal_generation.is_none() || terminal_at.is_none()))
        || terminal_at.is_some_and(|terminal_at| terminal_at < grant.issued_at_unix_milliseconds())
    {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(StoredGrant {
        grant,
        state,
        terminal_generation,
    })
}

fn grant_identifier_exists(
    connection: &Connection,
    grant_id: SessionGrantId,
) -> Result<bool, LocalAuthorizationStoreError> {
    connection
        .query_row(
            "SELECT 1
             FROM authorization_grant_identifier
             WHERE grant_id = ?1",
            params![grant_id.as_bytes().as_slice()],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(map_read_error)
}

fn reserve_grant_identifier(
    transaction: &Transaction<'_>,
    grant_id: SessionGrantId,
) -> Result<(), LocalAuthorizationStoreError> {
    let changed = transaction
        .execute(
            "INSERT INTO authorization_grant_identifier (grant_id) VALUES (?1)",
            params![grant_id.as_bytes().as_slice()],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(())
}

fn insert_grant(
    transaction: &Transaction<'_>,
    request_key: GrantIssuanceKey,
    grant: &SessionGrant,
) -> Result<(), LocalAuthorizationStoreError> {
    transaction
        .execute(
            "INSERT INTO authorization_grant (
                grant_id,
                issuer_key_id,
                issuer_key_version,
                profile_id,
                session_public_key,
                issuer_client_instance,
                issuance_request_id,
                harness,
                evidence_bits,
                policy_version,
                issued_at_unix_milliseconds,
                expires_at_unix_milliseconds,
                capabilities,
                state,
                terminal_generation,
                terminal_at_unix_milliseconds
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, NULL, NULL
             )",
            params![
                grant.grant_id().as_bytes().as_slice(),
                grant.issuer_key_id().as_bytes().as_slice(),
                i64::from(grant.issuer_key_version().get()),
                grant.profile().as_str(),
                grant.session_public_key().as_bytes().as_slice(),
                request_key.issuer_client_instance().as_bytes().as_slice(),
                request_key.request_id().as_bytes().as_slice(),
                i64::from(grant.harness().wire_value()),
                i64::from(grant.evidence().bits()),
                to_sql(grant.policy_version().get())?,
                to_sql(grant.issued_at_unix_milliseconds())?,
                to_sql(grant.expires_at_unix_milliseconds())?,
                to_sql(grant.capabilities().bits())?
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn enforce_grant_capacity(
    connection: &Connection,
    candidate: &SessionGrant,
    now_unix_milliseconds: u64,
) -> Result<(), LocalAuthorizationStoreError> {
    let now = to_sql(now_unix_milliseconds)?;
    let global: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1 AND expires_at_unix_milliseconds > ?1",
            params![now],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let issuer: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?1
               AND issuer_key_id = ?2",
            params![now, candidate.issuer_key_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let profile: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?1
               AND profile_id = ?2",
            params![now, candidate.profile().as_str()],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    if usize_from_sql(global)? >= MAX_SESSION_GRANTS
        || usize_from_sql(issuer)? >= MAX_GRANTS_PER_ISSUER
        || usize_from_sql(profile)? >= MAX_GRANTS_PER_PROFILE
    {
        return Err(LocalAuthorizationStoreError::Capacity);
    }
    Ok(())
}

fn count_active_issuer_grants(
    connection: &Connection,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    now_unix_milliseconds: u64,
) -> Result<usize, LocalAuthorizationStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?1
               AND issuer_key_id = ?2
               AND issuer_key_version = ?3",
            params![
                to_sql(now_unix_milliseconds)?,
                issuer_key_id.as_bytes().as_slice(),
                i64::from(issuer_key_version.get())
            ],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    usize_from_sql(count)
}

fn terminalize_exact_grant(
    transaction: &Transaction<'_>,
    grant_id: SessionGrantId,
    requested_state: GrantState,
    now_unix_milliseconds: u64,
    generation: u64,
) -> Result<bool, LocalAuthorizationStoreError> {
    let existing =
        load_grant_by_id(transaction, grant_id)?.ok_or(LocalAuthorizationStoreError::NotFound)?;
    if existing.state != GrantState::Active
        || existing.grant.expires_at_unix_milliseconds() <= now_unix_milliseconds
    {
        return Ok(false);
    }
    let changed = transaction
        .execute(
            "UPDATE authorization_grant
             SET state = ?1,
                 terminal_generation = ?2,
                 terminal_at_unix_milliseconds = max(?3, issued_at_unix_milliseconds)
             WHERE grant_id = ?4 AND state = 1",
            params![
                grant_state_code(requested_state),
                to_sql(generation)?,
                to_sql(now_unix_milliseconds)?,
                grant_id.as_bytes().as_slice()
            ],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(LocalAuthorizationStoreError::Conflict);
    }
    Ok(true)
}

fn terminalize_profile_grants(
    transaction: &Transaction<'_>,
    profile: &ServiceProfileId,
    now_unix_milliseconds: u64,
    generation: u64,
) -> Result<usize, LocalAuthorizationStoreError> {
    transaction
        .execute(
            "UPDATE authorization_grant
             SET state = 5,
                 terminal_generation = ?1,
                 terminal_at_unix_milliseconds = max(?2, issued_at_unix_milliseconds)
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?2
               AND profile_id = ?3",
            params![
                to_sql(generation)?,
                to_sql(now_unix_milliseconds)?,
                profile.as_str()
            ],
        )
        .map_err(map_write_error)
}

fn terminalize_issuer_grants(
    transaction: &Transaction<'_>,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    now_unix_milliseconds: u64,
    generation: u64,
) -> Result<usize, LocalAuthorizationStoreError> {
    transaction
        .execute(
            "UPDATE authorization_grant
             SET state = 6,
                 terminal_generation = ?1,
                 terminal_at_unix_milliseconds = max(?2, issued_at_unix_milliseconds)
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?2
               AND issuer_key_id = ?3
               AND issuer_key_version = ?4",
            params![
                to_sql(generation)?,
                to_sql(now_unix_milliseconds)?,
                issuer_key_id.as_bytes().as_slice(),
                i64::from(issuer_key_version.get())
            ],
        )
        .map_err(map_write_error)
}

fn terminalize_policy_invalid_grants(
    transaction: &Transaction<'_>,
    policy: &AuthorizationPolicy,
    now_unix_milliseconds: u64,
    generation: u64,
) -> Result<(), LocalAuthorizationStoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT grant_id, evidence_bits
             FROM authorization_grant
             WHERE state = 1 AND expires_at_unix_milliseconds > ?1
             ORDER BY grant_id
             LIMIT 257",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map(params![to_sql(now_unix_milliseconds)?], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(map_read_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_read_error)?;
    if rows.len() > MAX_SESSION_GRANTS {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    for (grant_id, evidence_bits) in rows {
        let evidence = AuthorizationEvidenceSet::from_bits(
            u8::try_from(evidence_bits)
                .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?,
        )
        .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
        if policy.accepts(evidence) {
            continue;
        }
        let grant_id = SessionGrantId::from_slice(&grant_id)
            .map_err(|_| LocalAuthorizationStoreError::InvalidStorage)?;
        let changed = transaction
            .execute(
                "UPDATE authorization_grant
                 SET state = 7,
                     terminal_generation = ?1,
                     terminal_at_unix_milliseconds = max(?2, issued_at_unix_milliseconds)
                 WHERE grant_id = ?3 AND state = 1",
                params![
                    to_sql(generation)?,
                    to_sql(now_unix_milliseconds)?,
                    grant_id.as_bytes().as_slice()
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(LocalAuthorizationStoreError::InvalidStorage);
        }
    }
    Ok(())
}

fn expire_grants(
    transaction: &Transaction<'_>,
    now_unix_milliseconds: u64,
    generation: u64,
) -> Result<usize, LocalAuthorizationStoreError> {
    transaction
        .execute(
            "UPDATE authorization_grant
             SET state = 4,
                 terminal_generation = ?1,
                 terminal_at_unix_milliseconds = ?2
             WHERE state = 1 AND expires_at_unix_milliseconds <= ?2",
            params![to_sql(generation)?, to_sql(now_unix_milliseconds)?],
        )
        .map_err(map_write_error)
}

fn expire_for_read(
    transaction: &Transaction<'_>,
    now_unix_milliseconds: u64,
) -> Result<AuthorizationGeneration, LocalAuthorizationStoreError> {
    let current_generation = load_generation(transaction)?;
    let proposed_generation = next_generation(current_generation).unwrap_or(current_generation);
    let expired = expire_grants(transaction, now_unix_milliseconds, proposed_generation)?;
    if expired == 0 {
        return Ok(AuthorizationGeneration::from_validated(current_generation));
    }
    if proposed_generation == current_generation {
        return Err(LocalAuthorizationStoreError::Capacity);
    }
    commit_generation(
        transaction,
        proposed_generation,
        AuthorizationAuditKind::GrantsExpired,
        now_unix_milliseconds,
    )?;
    prune_bounded_history(transaction)?;
    Ok(AuthorizationGeneration::from_validated(proposed_generation))
}

fn commit_generation(
    transaction: &Transaction<'_>,
    generation: u64,
    audit_kind: AuthorizationAuditKind,
    now_unix_milliseconds: u64,
) -> Result<(), LocalAuthorizationStoreError> {
    let changed = transaction
        .execute(
            "UPDATE authorization_store_meta
             SET generation = ?1
             WHERE singleton_id = 1",
            params![to_sql(generation)?],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    transaction
        .execute(
            "INSERT INTO authorization_audit (
                generation, event_kind, occurred_at_unix_milliseconds
             ) VALUES (?1, ?2, ?3)",
            params![
                to_sql(generation)?,
                audit_kind_code(audit_kind),
                to_sql(now_unix_milliseconds)?
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn prune_bounded_history(
    transaction: &Transaction<'_>,
) -> Result<(), LocalAuthorizationStoreError> {
    transaction
        .execute(
            "DELETE FROM authorization_grant
             WHERE state != 1
               AND grant_id IN (
                   SELECT grant_id
                   FROM authorization_grant
                   WHERE state != 1
                   ORDER BY terminal_generation DESC, grant_id DESC
                   LIMIT -1 OFFSET ?1
               )",
            params![
                i64::try_from(MAX_TERMINAL_GRANT_RECORDS)
                    .map_err(|_| LocalAuthorizationStoreError::Capacity)?
            ],
        )
        .map_err(map_write_error)?;
    transaction
        .execute(
            "DELETE FROM authorization_audit
             WHERE generation IN (
                 SELECT generation
                 FROM authorization_audit
                 ORDER BY generation DESC
                 LIMIT -1 OFFSET ?1
             )",
            params![
                i64::try_from(MAX_AUTHORIZATION_AUDIT_RECORDS)
                    .map_err(|_| LocalAuthorizationStoreError::Capacity)?
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn load_status_inner(
    connection: &Connection,
    generation: AuthorizationGeneration,
    now_unix_milliseconds: u64,
    issuer_key_id: IssuerKeyId,
    profile: &ServiceProfileId,
) -> Result<AuthorizationStoreStatus, LocalAuthorizationStoreError> {
    let now = to_sql(now_unix_milliseconds)?;
    let policy_version = load_policy(connection)?.version();
    let issuer_records = count_rows(connection, "authorization_issuer")?;
    let issuer_identifiers = count_rows(connection, "authorization_issuer_identifier")?;
    let disabled_issuers: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authorization_issuer WHERE enabled = 0",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let suspended_profiles = count_rows(connection, "authorization_suspended_profile")?;
    let active_grants: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1 AND expires_at_unix_milliseconds > ?1",
            params![now],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let terminal_grants: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authorization_grant WHERE state != 1",
            [],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let grant_identifiers = count_rows(connection, "authorization_grant_identifier")?;
    let audit_records = count_rows(connection, "authorization_audit")?;
    let user_presence_credentials =
        count_rows(connection, "authorization_user_presence_credential")?;
    let user_presence_credential_identifiers = count_rows(
        connection,
        "authorization_user_presence_credential_identifier",
    )?;
    let active_for_issuer: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?1
               AND issuer_key_id = ?2",
            params![now, issuer_key_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    let active_for_profile: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authorization_grant
             WHERE state = 1
               AND expires_at_unix_milliseconds > ?1
               AND profile_id = ?2",
            params![now, profile.as_str()],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    Ok(AuthorizationStoreStatus {
        generation,
        policy_version,
        issuer_records,
        issuer_identifiers,
        disabled_issuers: usize_from_sql(disabled_issuers)?,
        suspended_profiles,
        active_grants: usize_from_sql(active_grants)?,
        terminal_grants: usize_from_sql(terminal_grants)?,
        grant_identifiers,
        audit_records,
        user_presence_credentials,
        user_presence_credential_identifiers,
        capacity: AuthorizationCapacity {
            active_global: usize_from_sql(active_grants)?,
            maximum_global: MAX_SESSION_GRANTS,
            active_for_issuer: usize_from_sql(active_for_issuer)?,
            maximum_for_issuer: MAX_GRANTS_PER_ISSUER,
            active_for_profile: usize_from_sql(active_for_profile)?,
            maximum_for_profile: MAX_GRANTS_PER_PROFILE,
        },
    })
}

fn load_audit_events_inner(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<AuthorizationAuditEvent>, LocalAuthorizationStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT generation, event_kind, occurred_at_unix_milliseconds
             FROM authorization_audit
             ORDER BY generation DESC
             LIMIT ?1",
        )
        .map_err(map_read_error)?;
    let rows = statement
        .query_map(
            params![i64::try_from(limit).map_err(|_| LocalAuthorizationStoreError::InvalidInput)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(map_read_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_read_error)?;
    rows.into_iter()
        .map(|(generation, kind, occurred_at)| {
            Ok(AuthorizationAuditEvent {
                generation: AuthorizationGeneration::from_validated(u64_from_positive_sql(
                    generation,
                )?),
                kind: audit_kind_from_code(kind)?,
                occurred_at_unix_milliseconds: u64_from_sql(occurred_at)?,
            })
        })
        .collect()
}

fn count_rows(
    connection: &Connection,
    table: &'static str,
) -> Result<usize, LocalAuthorizationStoreError> {
    let sql = match table {
        "authorization_policy_clause" => "SELECT COUNT(*) FROM authorization_policy_clause",
        "authorization_issuer_identifier" => "SELECT COUNT(*) FROM authorization_issuer_identifier",
        "authorization_issuer" => "SELECT COUNT(*) FROM authorization_issuer",
        "authorization_suspended_profile" => "SELECT COUNT(*) FROM authorization_suspended_profile",
        "authorization_grant_identifier" => "SELECT COUNT(*) FROM authorization_grant_identifier",
        "authorization_user_presence_credential_identifier" => {
            "SELECT COUNT(*) FROM authorization_user_presence_credential_identifier"
        }
        "authorization_user_presence_credential" => {
            "SELECT COUNT(*) FROM authorization_user_presence_credential"
        }
        "authorization_audit" => "SELECT COUNT(*) FROM authorization_audit",
        _ => return Err(LocalAuthorizationStoreError::InvalidInput),
    };
    let count: i64 = connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(map_read_error)?;
    usize_from_sql(count)
}

const fn availability_code(availability: IssuerAvailability) -> i64 {
    match availability {
        IssuerAvailability::Enabled => 1,
        IssuerAvailability::Disabled => 0,
    }
}

fn availability_from_code(value: i64) -> Result<IssuerAvailability, LocalAuthorizationStoreError> {
    match value {
        1 => Ok(IssuerAvailability::Enabled),
        0 => Ok(IssuerAvailability::Disabled),
        _ => Err(LocalAuthorizationStoreError::InvalidStorage),
    }
}

const fn disposition_code(disposition: ExistingGrantDisposition) -> i64 {
    match disposition {
        ExistingGrantDisposition::RetainUntilExpiry => 1,
        ExistingGrantDisposition::Revoke => 2,
    }
}

fn disposition_from_code(
    value: i64,
) -> Result<ExistingGrantDisposition, LocalAuthorizationStoreError> {
    match value {
        1 => Ok(ExistingGrantDisposition::RetainUntilExpiry),
        2 => Ok(ExistingGrantDisposition::Revoke),
        _ => Err(LocalAuthorizationStoreError::InvalidStorage),
    }
}

const fn grant_state_code(state: GrantState) -> i64 {
    match state {
        GrantState::Active => 1,
        GrantState::Retired => 2,
        GrantState::Revoked => 3,
        GrantState::Expired => 4,
        GrantState::ProfileSuspended => 5,
        GrantState::IssuerDisabled => 6,
        GrantState::PolicyInvalid => 7,
    }
}

fn grant_state_from_code(value: i64) -> Result<GrantState, LocalAuthorizationStoreError> {
    match value {
        1 => Ok(GrantState::Active),
        2 => Ok(GrantState::Retired),
        3 => Ok(GrantState::Revoked),
        4 => Ok(GrantState::Expired),
        5 => Ok(GrantState::ProfileSuspended),
        6 => Ok(GrantState::IssuerDisabled),
        7 => Ok(GrantState::PolicyInvalid),
        _ => Err(LocalAuthorizationStoreError::InvalidStorage),
    }
}

const fn audit_kind_code(kind: AuthorizationAuditKind) -> i64 {
    match kind {
        AuthorizationAuditKind::Bootstrap => 1,
        AuthorizationAuditKind::GrantIssued => 2,
        AuthorizationAuditKind::GrantRetired => 3,
        AuthorizationAuditKind::GrantRevoked => 4,
        AuthorizationAuditKind::ProfileSuspended => 5,
        AuthorizationAuditKind::ProfileResumed => 6,
        AuthorizationAuditKind::IssuerStateChanged => 7,
        AuthorizationAuditKind::PolicyReplaced => 8,
        AuthorizationAuditKind::IssuerRegistered => 9,
        AuthorizationAuditKind::IssuerRemoved => 10,
        AuthorizationAuditKind::GrantsExpired => 11,
        AuthorizationAuditKind::UserPresenceCredentialRegistered => 12,
        AuthorizationAuditKind::UserPresenceCredentialReplaced => 13,
        AuthorizationAuditKind::UserPresenceCredentialRemoved => 14,
        AuthorizationAuditKind::UserPresenceCredentialUpdated => 15,
    }
}

fn audit_kind_from_code(
    value: i64,
) -> Result<AuthorizationAuditKind, LocalAuthorizationStoreError> {
    match value {
        1 => Ok(AuthorizationAuditKind::Bootstrap),
        2 => Ok(AuthorizationAuditKind::GrantIssued),
        3 => Ok(AuthorizationAuditKind::GrantRetired),
        4 => Ok(AuthorizationAuditKind::GrantRevoked),
        5 => Ok(AuthorizationAuditKind::ProfileSuspended),
        6 => Ok(AuthorizationAuditKind::ProfileResumed),
        7 => Ok(AuthorizationAuditKind::IssuerStateChanged),
        8 => Ok(AuthorizationAuditKind::PolicyReplaced),
        9 => Ok(AuthorizationAuditKind::IssuerRegistered),
        10 => Ok(AuthorizationAuditKind::IssuerRemoved),
        11 => Ok(AuthorizationAuditKind::GrantsExpired),
        12 => Ok(AuthorizationAuditKind::UserPresenceCredentialRegistered),
        13 => Ok(AuthorizationAuditKind::UserPresenceCredentialReplaced),
        14 => Ok(AuthorizationAuditKind::UserPresenceCredentialRemoved),
        15 => Ok(AuthorizationAuditKind::UserPresenceCredentialUpdated),
        _ => Err(LocalAuthorizationStoreError::InvalidStorage),
    }
}

fn next_generation(current: u64) -> Option<u64> {
    current
        .checked_add(1)
        .filter(|value| i64::try_from(*value).is_ok())
}

fn validate_timestamp(value: u64) -> Result<(), LocalAuthorizationStoreError> {
    let _ = to_sql(value)?;
    Ok(())
}

fn to_sql(value: u64) -> Result<i64, LocalAuthorizationStoreError> {
    i64::try_from(value).map_err(|_| LocalAuthorizationStoreError::InvalidInput)
}

fn u64_from_sql(value: i64) -> Result<u64, LocalAuthorizationStoreError> {
    u64::try_from(value).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)
}

fn u64_from_positive_sql(value: i64) -> Result<u64, LocalAuthorizationStoreError> {
    let value = u64_from_sql(value)?;
    if value == 0 {
        return Err(LocalAuthorizationStoreError::InvalidStorage);
    }
    Ok(value)
}

fn usize_from_sql(value: i64) -> Result<usize, LocalAuthorizationStoreError> {
    usize::try_from(value).map_err(|_| LocalAuthorizationStoreError::InvalidStorage)
}

fn map_owner_protection_error(error: SecretStorageError) -> LocalAuthorizationStoreError {
    match error {
        SecretStorageError::OwnerProtectedStorageUnsafe => {
            LocalAuthorizationStoreError::UnsafeStorage
        }
        SecretStorageError::OwnerProtectedStorageConflict => {
            LocalAuthorizationStoreError::InvalidStorage
        }
        SecretStorageError::OwnerProtectedStorageUnavailable => {
            LocalAuthorizationStoreError::StorageUnavailable
        }
        _ => LocalAuthorizationStoreError::StorageUnavailable,
    }
}

fn map_open_error(error: rusqlite::Error) -> LocalAuthorizationStoreError {
    if is_corruption(&error) {
        LocalAuthorizationStoreError::CorruptStorage
    } else {
        LocalAuthorizationStoreError::StorageUnavailable
    }
}

fn map_read_error(error: rusqlite::Error) -> LocalAuthorizationStoreError {
    if is_corruption(&error) {
        LocalAuthorizationStoreError::CorruptStorage
    } else if is_operational_failure(&error) {
        LocalAuthorizationStoreError::StorageUnavailable
    } else {
        LocalAuthorizationStoreError::InvalidStorage
    }
}

fn map_write_error(error: rusqlite::Error) -> LocalAuthorizationStoreError {
    if is_corruption(&error) {
        LocalAuthorizationStoreError::CorruptStorage
    } else {
        LocalAuthorizationStoreError::StorageUnavailable
    }
}

fn is_corruption(error: &rusqlite::Error) -> bool {
    sqlite_primary_code(error).is_some_and(|primary_code| {
        primary_code == rusqlite::ffi::SQLITE_CORRUPT
            || primary_code == rusqlite::ffi::SQLITE_NOTADB
    })
}

fn is_operational_failure(error: &rusqlite::Error) -> bool {
    sqlite_primary_code(error).is_some_and(|primary_code| {
        matches!(
            primary_code,
            rusqlite::ffi::SQLITE_BUSY
                | rusqlite::ffi::SQLITE_LOCKED
                | rusqlite::ffi::SQLITE_IOERR
                | rusqlite::ffi::SQLITE_CANTOPEN
                | rusqlite::ffi::SQLITE_READONLY
                | rusqlite::ffi::SQLITE_FULL
                | rusqlite::ffi::SQLITE_INTERRUPT
                | rusqlite::ffi::SQLITE_NOMEM
        )
    })
}

fn sqlite_primary_code(error: &rusqlite::Error) -> Option<i32> {
    let rusqlite::Error::SqliteFailure(failure, _) = error else {
        return None;
    };
    Some(failure.extended_code & 0xff)
}
