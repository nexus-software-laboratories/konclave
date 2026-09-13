use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalAuthorizationStore::{
    AuthorizationAuditKind, ExistingGrantDisposition, GrantIssuanceKey, InstallationFingerprint,
    IssuerAvailability, LOCAL_AUTHORIZATION_STORE_FILE, LocalAuthorizationStore,
    LocalAuthorizationStoreError, MAX_AUTHORIZATION_AUDIT_RECORDS, MAX_TERMINAL_GRANT_RECORDS,
    MutationEffect, UserPresenceCredentialRecord, authorization_store_path,
};
use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    AuthorizationPolicyVersion, ClientInstanceId, HarnessKind, InstalledIssuerRegistration,
    IssuerKeyId, IssuerKeyVersion, IssuerRegistration, LOCAL_SERVICE_INSTALLATION_FILE,
    MAX_GRANTS_PER_ISSUER, MAX_GRANTS_PER_PROFILE, MAX_SESSION_GRANTS, ProfileAuthorization,
    RequestId, ServiceProfileId, SessionCapabilities, SessionGrant, SessionGrantClaims,
    SessionGrantId,
};
use KonclaveSecretStorage::{
    create_or_verify_owner_protected_file, ensure_owner_protected_directory,
    open_or_create_owner_protected_file,
};
use rusqlite::Connection;
use tempfile::TempDir;

const NOW: u64 = 1_000;
const EXPIRY: u64 = 10_000;

struct Fixture {
    _root: TempDir,
    installation_path: PathBuf,
    fingerprint: InstallationFingerprint,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let service_root = root.path().join("service");
        ensure_owner_protected_directory(&service_root).unwrap();
        let installation_path = service_root.join(LOCAL_SERVICE_INSTALLATION_FILE);
        Self {
            _root: root,
            installation_path,
            fingerprint: InstallationFingerprint::from_bytes([9; 32]),
        }
    }

    fn database_path(&self) -> PathBuf {
        authorization_store_path(&self.installation_path).unwrap()
    }

    fn open(&self) -> LocalAuthorizationStore {
        let store = LocalAuthorizationStore::bootstrap(
            &self.installation_path,
            self.fingerprint,
            &account_policy(1),
            &[issuer(1, 1)],
            NOW,
        )
        .unwrap();
        self.publish_installation();
        store
    }

    fn publish_installation(&self) {
        create_or_verify_owner_protected_file(&self.installation_path, b"immutable-installation")
            .unwrap();
    }
}

fn profile(value: &str) -> ServiceProfileId {
    ServiceProfileId::parse(value).unwrap()
}

fn evidence(kind: AuthorizationEvidenceKind) -> AuthorizationEvidenceSet {
    AuthorizationEvidenceSet::new([kind]).unwrap()
}

fn account_policy(version: u64) -> AuthorizationPolicy {
    AuthorizationPolicy::new(
        AuthorizationPolicyVersion::new(version).unwrap(),
        vec![evidence(AuthorizationEvidenceKind::AccountTrusted)],
    )
    .unwrap()
}

fn user_presence_policy(version: u64) -> AuthorizationPolicy {
    AuthorizationPolicy::new(
        AuthorizationPolicyVersion::new(version).unwrap(),
        vec![evidence(AuthorizationEvidenceKind::UserPresence)],
    )
    .unwrap()
}

fn issuer(identifier: u8, version: u32) -> InstalledIssuerRegistration {
    InstalledIssuerRegistration::new(
        IssuerKeyId::from_bytes([identifier; 16]),
        IssuerKeyVersion::new(version).unwrap(),
        IssuerRegistration::new(
            Ed25519PublicKey::from_bytes(
                [identifier.wrapping_add(u8::try_from(version).unwrap_or(u8::MAX)); 32],
            ),
            HarnessKind::Generic,
            ProfileAuthorization::All,
        ),
    )
}

fn grant(
    identifier: u32,
    issuer_identifier: u8,
    issuer_version: u32,
    profile_name: &str,
    evidence_kind: AuthorizationEvidenceKind,
    policy_version: u64,
) -> SessionGrant {
    grant_with_expiry(
        identifier,
        issuer_identifier,
        issuer_version,
        profile_name,
        evidence_kind,
        policy_version,
        EXPIRY,
    )
}

fn grant_with_expiry(
    identifier: u32,
    issuer_identifier: u8,
    issuer_version: u32,
    profile_name: &str,
    evidence_kind: AuthorizationEvidenceKind,
    policy_version: u64,
    expires_at_unix_milliseconds: u64,
) -> SessionGrant {
    grant_with_evidence(
        identifier,
        issuer_identifier,
        issuer_version,
        profile_name,
        evidence(evidence_kind),
        policy_version,
        expires_at_unix_milliseconds,
    )
}

fn grant_with_evidence(
    identifier: u32,
    issuer_identifier: u8,
    issuer_version: u32,
    profile_name: &str,
    evidence: AuthorizationEvidenceSet,
    policy_version: u64,
    expires_at_unix_milliseconds: u64,
) -> SessionGrant {
    let mut grant_id = [0_u8; 16];
    grant_id[..4].copy_from_slice(&identifier.to_be_bytes());
    grant_id[4] = issuer_identifier;
    let mut session_key = [0_u8; 32];
    session_key[..4].copy_from_slice(&identifier.to_be_bytes());
    session_key[4] = issuer_identifier;
    SessionGrant::new(SessionGrantClaims {
        grant_id: SessionGrantId::from_bytes(grant_id),
        issuer_key_id: IssuerKeyId::from_bytes([issuer_identifier; 16]),
        issuer_key_version: IssuerKeyVersion::new(issuer_version).unwrap(),
        profile: profile(profile_name),
        session_public_key: Ed25519PublicKey::from_bytes(session_key),
        harness: HarnessKind::Copilot,
        evidence,
        policy_version: AuthorizationPolicyVersion::new(policy_version).unwrap(),
        issued_at_unix_milliseconds: NOW,
        expires_at_unix_milliseconds,
        capabilities: SessionCapabilities::ALL,
    })
    .unwrap()
}

fn presence_credential(seed: u8) -> UserPresenceCredentialRecord {
    presence_credential_with_counter(seed, 0)
}

fn presence_credential_with_counter(seed: u8, counter: u32) -> UserPresenceCredentialRecord {
    let mut public_key_cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    public_key_cose.extend_from_slice(&[seed; 32]);
    let user_handle = vec![seed; 16];
    let credential_id = vec![seed; 32];
    let aaguid = vec![0; 16];
    let document = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "provider": "windows-native-webauthn-v1",
        "userHandle": user_handle,
        "passkey": {
            "id": credential_id,
            "public_key_cose": public_key_cose,
            "counter": counter,
            "transports": ["internal"],
            "aaguid": aaguid,
        }
    }))
    .unwrap();
    UserPresenceCredentialRecord::from_document(document).unwrap()
}

#[test]
fn bootstrap_is_idempotent_and_reopen_preserves_administrative_state() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let initial = store.load_snapshot(NOW, None).unwrap();
    assert_eq!(initial.generation().get(), 1);
    assert_eq!(initial.policy(), &account_policy(1));
    assert_eq!(initial.issuers().len(), 1);

    let stronger = AuthorizationPolicy::new(
        AuthorizationPolicyVersion::new(2).unwrap(),
        vec![
            evidence(AuthorizationEvidenceKind::AccountTrusted),
            evidence(AuthorizationEvidenceKind::UserPresence),
        ],
    )
    .unwrap();
    store.replace_policy(&stronger, NOW + 1).unwrap();
    store.suspend_profile(&profile("alice"), NOW + 2).unwrap();
    drop(store);

    let reopened = fixture.open();
    let snapshot = reopened.load_snapshot(NOW + 3, None).unwrap();
    assert_eq!(snapshot.generation().get(), 3);
    assert_eq!(snapshot.policy(), &stronger);
    assert_eq!(snapshot.suspended_profiles(), &[profile("alice")]);
}

#[test]
fn user_presence_credentials_are_exact_reserved_and_audited() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first = presence_credential(1);
    let first_updated = presence_credential_with_counter(1, 1);
    let second = presence_credential(2);

    assert!(
        store
            .load_snapshot(NOW, None)
            .unwrap()
            .user_presence_credential()
            .is_none()
    );
    let registered = store
        .register_user_presence_credential(&first, NOW + 1)
        .unwrap();
    assert_eq!(registered.effect(), MutationEffect::Applied);
    assert_eq!(registered.generation().get(), 2);
    assert_eq!(
        store
            .register_user_presence_credential(&first, NOW + 2)
            .unwrap()
            .effect(),
        MutationEffect::Unchanged
    );
    assert_eq!(
        store
            .register_user_presence_credential(&second, NOW + 2)
            .err(),
        Some(LocalAuthorizationStoreError::Conflict)
    );
    assert_eq!(
        store
            .replace_user_presence_credential(second.credential_digest(), &second, NOW + 2,)
            .err(),
        Some(LocalAuthorizationStoreError::Conflict)
    );
    let updated = store
        .update_user_presence_credential(first.credential_digest(), &first_updated, NOW + 2)
        .unwrap();
    assert_eq!(updated.generation().get(), 3);
    assert_eq!(
        store
            .update_user_presence_credential(first.credential_digest(), &first_updated, NOW + 3,)
            .unwrap()
            .effect(),
        MutationEffect::Unchanged
    );

    let replaced = store
        .replace_user_presence_credential(first.credential_digest(), &second, NOW + 3)
        .unwrap();
    assert_eq!(replaced.generation().get(), 4);
    assert_eq!(
        store
            .load_snapshot(NOW + 3, None)
            .unwrap()
            .user_presence_credential(),
        Some(&second)
    );
    assert_eq!(
        store
            .remove_user_presence_credential(first.credential_digest(), NOW + 4)
            .err(),
        Some(LocalAuthorizationStoreError::Conflict)
    );
    let removed = store
        .remove_user_presence_credential(second.credential_digest(), NOW + 4)
        .unwrap();
    assert_eq!(removed.generation().get(), 5);
    assert_eq!(
        store
            .remove_user_presence_credential(second.credential_digest(), NOW + 5)
            .unwrap()
            .effect(),
        MutationEffect::Unchanged
    );
    assert_eq!(
        store
            .register_user_presence_credential(&first, NOW + 5)
            .err(),
        Some(LocalAuthorizationStoreError::Conflict)
    );

    let audit = store.load_audit_events(8, None).unwrap();
    assert_eq!(
        audit.iter().map(|event| event.kind()).collect::<Vec<_>>(),
        vec![
            AuthorizationAuditKind::UserPresenceCredentialRemoved,
            AuthorizationAuditKind::UserPresenceCredentialReplaced,
            AuthorizationAuditKind::UserPresenceCredentialUpdated,
            AuthorizationAuditKind::UserPresenceCredentialRegistered,
            AuthorizationAuditKind::Bootstrap,
        ]
    );
    let status = store
        .load_status(
            NOW + 5,
            None,
            IssuerKeyId::from_bytes([1; 16]),
            &profile("alice"),
        )
        .unwrap();
    assert_eq!(status.user_presence_credentials(), 0);
    assert_eq!(status.user_presence_credential_identifiers(), 2);
}

#[test]
fn malformed_user_presence_credential_fails_closed() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .register_user_presence_credential(&presence_credential(3), NOW + 1)
        .unwrap();
    drop(store);

    let connection = Connection::open(fixture.database_path()).unwrap();
    connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    connection
        .execute(
            "UPDATE authorization_user_presence_credential
             SET credential_document = X'00'",
            [],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None),
        Err(LocalAuthorizationStoreError::InvalidStorage
            | LocalAuthorizationStoreError::CorruptStorage)
    ));
}

#[test]
fn ordinary_open_rejects_missing_and_empty_state() {
    let missing = Fixture::new();
    missing.publish_installation();
    assert!(matches!(
        LocalAuthorizationStore::open(&missing.installation_path, missing.fingerprint, None),
        Err(LocalAuthorizationStoreError::StorageUnavailable)
    ));
    assert!(matches!(
        LocalAuthorizationStore::bootstrap(
            &missing.installation_path,
            missing.fingerprint,
            &account_policy(1),
            &[issuer(1, 1)],
            NOW,
        ),
        Err(LocalAuthorizationStoreError::StorageUnavailable)
    ));

    let empty = Fixture::new();
    empty.publish_installation();
    drop(open_or_create_owner_protected_file(&empty.database_path()).unwrap());
    assert!(matches!(
        LocalAuthorizationStore::open(&empty.installation_path, empty.fingerprint, None),
        Err(LocalAuthorizationStoreError::InvalidStorage)
    ));

    let valid = Fixture::new();
    drop(valid.open());
    LocalAuthorizationStore::open(&valid.installation_path, valid.fingerprint, None).unwrap();
}

#[test]
fn concurrent_bootstrap_converges_on_one_generation() {
    let fixture = Fixture::new();
    let path = fixture.installation_path.clone();
    let fingerprint = fixture.fingerprint;
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            LocalAuthorizationStore::bootstrap(
                path,
                fingerprint,
                &account_policy(1),
                &[issuer(1, 1)],
                NOW,
            )
            .unwrap()
            .load_snapshot(NOW, None)
            .unwrap()
            .generation()
        }));
    }
    barrier.wait();
    for thread in threads {
        assert_eq!(thread.join().unwrap().get(), 1);
    }
}

#[test]
fn fingerprint_mismatch_fails_closed() {
    let fixture = Fixture::new();
    drop(fixture.open());
    assert!(matches!(
        LocalAuthorizationStore::open(
            &fixture.installation_path,
            InstallationFingerprint::from_bytes([8; 32]),
            None,
        ),
        Err(LocalAuthorizationStoreError::InstallationMismatch)
    ));
}

#[test]
fn unknown_schema_and_corrupt_bytes_are_rejected() {
    let unknown = Fixture::new();
    unknown.publish_installation();
    let unknown_path = unknown.database_path();
    drop(open_or_create_owner_protected_file(&unknown_path).unwrap());
    Connection::open(&unknown_path)
        .unwrap()
        .execute("CREATE TABLE unknown_schema (value INTEGER)", [])
        .unwrap();
    assert!(matches!(
        LocalAuthorizationStore::open(&unknown.installation_path, unknown.fingerprint, None,),
        Err(LocalAuthorizationStoreError::UnsupportedSchema)
    ));

    let corrupt = Fixture::new();
    corrupt.publish_installation();
    let corrupt_path = corrupt.database_path();
    let mut file = open_or_create_owner_protected_file(&corrupt_path).unwrap();
    file.write_all(b"not a sqlite database").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(
        LocalAuthorizationStore::open(&corrupt.installation_path, corrupt.fingerprint, None,),
        Err(LocalAuthorizationStoreError::CorruptStorage)
    ));
}

#[test]
fn schema_v1_is_migrated_transactionally_without_losing_authorization_state() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store.suspend_profile(&profile("alice"), NOW + 1).unwrap();
    drop(store);

    let connection = Connection::open(fixture.database_path()).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE authorization_audit RENAME TO authorization_audit_v2;
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
    );
             INSERT INTO authorization_audit (
                generation,
                event_kind,
                occurred_at_unix_milliseconds
             )
             SELECT generation, event_kind, occurred_at_unix_milliseconds
             FROM authorization_audit_v2;
             DROP TABLE authorization_audit_v2;
             DROP TABLE authorization_user_presence_credential;
             DROP TABLE authorization_user_presence_credential_identifier;
             UPDATE authorization_store_meta
             SET schema_version = 1
             WHERE singleton_id = 1;",
        )
        .unwrap();
    drop(connection);

    let migrated =
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None)
            .unwrap();
    let snapshot = migrated.load_snapshot(NOW + 1, None).unwrap();
    assert_eq!(snapshot.generation().get(), 2);
    assert!(snapshot.suspended_profiles().contains(&profile("alice")));
    assert!(snapshot.user_presence_credential().is_none());
    migrated
        .register_user_presence_credential(&presence_credential(7), NOW + 2)
        .unwrap();
    drop(migrated);

    let connection = Connection::open(fixture.database_path()).unwrap();
    let schema_version: i64 = connection
        .query_row(
            "SELECT schema_version
             FROM authorization_store_meta
             WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema_version, 2);
}

#[test]
fn schema_v1_label_on_an_unrecognized_shape_fails_closed() {
    let fixture = Fixture::new();
    drop(fixture.open());
    Connection::open(fixture.database_path())
        .unwrap()
        .execute(
            "UPDATE authorization_store_meta SET schema_version = 1 WHERE singleton_id = 1",
            [],
        )
        .unwrap();
    assert!(matches!(
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None,),
        Err(LocalAuthorizationStoreError::InvalidStorage)
    ));
}

#[test]
fn unknown_schema_version_is_rejected_without_migration() {
    let fixture = Fixture::new();
    drop(fixture.open());
    Connection::open(fixture.database_path())
        .unwrap()
        .execute(
            "UPDATE authorization_store_meta SET schema_version = 3 WHERE singleton_id = 1",
            [],
        )
        .unwrap();
    assert!(matches!(
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None,),
        Err(LocalAuthorizationStoreError::UnsupportedSchema)
    ));
}

#[test]
fn malformed_persisted_enum_is_rejected() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = Connection::open(fixture.database_path()).unwrap();
    connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    connection
        .execute("UPDATE authorization_issuer SET harness = 99", [])
        .unwrap();
    drop(connection);

    let error =
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None).err();
    assert_eq!(error, Some(LocalAuthorizationStoreError::CorruptStorage));
}

#[test]
fn malformed_persisted_identifier_length_is_rejected() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = Connection::open(fixture.database_path()).unwrap();
    connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    connection
        .execute("UPDATE authorization_issuer SET public_key = X'00'", [])
        .unwrap();
    drop(connection);

    let error =
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None).err();
    assert_eq!(error, Some(LocalAuthorizationStoreError::CorruptStorage));
}

#[test]
fn generation_rollback_is_distinguished_from_general_corruption() {
    let fixture = Fixture::new();
    let store = fixture.open();
    drop(store);
    let generation_one = std::fs::read(fixture.database_path()).unwrap();
    let store = fixture.open();
    let issued = store.issue_grant(
        &grant(
            1,
            1,
            1,
            "alice",
            AuthorizationEvidenceKind::AccountTrusted,
            1,
        ),
        NOW,
    );
    let high_water = issued.unwrap().generation();
    drop(store);

    let database_path = fixture.database_path();
    let mut file = open_or_create_owner_protected_file(&database_path).unwrap();
    file.set_len(0).unwrap();
    file.write_all(&generation_one).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(
        LocalAuthorizationStore::open(
            &fixture.installation_path,
            fixture.fingerprint,
            Some(high_water),
        )
        .err()
        .unwrap(),
        LocalAuthorizationStoreError::GenerationRollback
    );
}

#[test]
fn every_mutation_enforces_the_process_high_water_mark() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .issue_grant(
            &grant(
                1,
                1,
                1,
                "alice",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            ),
            NOW,
        )
        .unwrap();
    Connection::open(fixture.database_path())
        .unwrap()
        .execute(
            "UPDATE authorization_store_meta SET generation = 1 WHERE singleton_id = 1",
            [],
        )
        .unwrap();
    assert_eq!(
        store
            .resume_profile(&profile("alice"), NOW + 1)
            .unwrap_err(),
        LocalAuthorizationStoreError::GenerationRollback
    );
}

#[test]
fn exact_grant_issue_replay_and_conflict_are_deterministic() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let candidate = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    let issued = store.issue_grant(&candidate, NOW).unwrap();
    assert_eq!(issued.effect(), MutationEffect::Applied);
    assert_eq!(issued.generation().get(), 2);

    let replay = store.issue_grant(&candidate, NOW + 1).unwrap();
    assert_eq!(replay.effect(), MutationEffect::Unchanged);
    assert_eq!(replay.generation(), issued.generation());

    let conflicting = grant(1, 1, 1, "bob", AuthorizationEvidenceKind::AccountTrusted, 1);
    assert_eq!(
        store.issue_grant(&conflicting, NOW + 1).unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    let snapshot = store.load_snapshot(NOW + 1, None).unwrap();
    assert_eq!(snapshot.active_grants(), &[candidate]);
}

#[test]
fn issuer_request_replay_returns_the_original_durable_grant() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let request_key = GrantIssuanceKey::new(
        ClientInstanceId::from_bytes([7; 16]),
        RequestId::from_bytes([8; 16]),
    );
    let original = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    let issued = store
        .issue_grant_for_request(request_key, &original, NOW)
        .unwrap();
    assert_eq!(issued.mutation().effect(), MutationEffect::Applied);
    assert_eq!(issued.grant(), &original);

    let retry_candidate = SessionGrant::new(SessionGrantClaims {
        grant_id: grant(
            2,
            1,
            1,
            "alice",
            AuthorizationEvidenceKind::AccountTrusted,
            1,
        )
        .grant_id(),
        issuer_key_id: original.issuer_key_id(),
        issuer_key_version: original.issuer_key_version(),
        profile: original.profile().clone(),
        session_public_key: original.session_public_key(),
        harness: original.harness(),
        evidence: original.evidence(),
        policy_version: original.policy_version(),
        issued_at_unix_milliseconds: original.issued_at_unix_milliseconds(),
        expires_at_unix_milliseconds: original.expires_at_unix_milliseconds(),
        capabilities: original.capabilities(),
    })
    .unwrap();
    let replayed = store
        .issue_grant_for_request(request_key, &retry_candidate, NOW + 1)
        .unwrap();
    assert_eq!(replayed.mutation().effect(), MutationEffect::Unchanged);
    assert_eq!(replayed.grant(), &original);
    assert_eq!(
        store
            .active_grant_for_request(
                original.issuer_key_id(),
                original.issuer_key_version(),
                request_key,
                NOW + 1,
            )
            .unwrap(),
        Some(original.clone())
    );

    let conflicting = grant(3, 1, 1, "bob", AuthorizationEvidenceKind::AccountTrusted, 1);
    assert_eq!(
        store
            .issue_grant_for_request(request_key, &conflicting, NOW + 1)
            .unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    assert!(
        store
            .active_grant_for_request(
                original.issuer_key_id(),
                original.issuer_key_version(),
                GrantIssuanceKey::new(
                    ClientInstanceId::from_bytes([9; 16]),
                    RequestId::from_bytes([9; 16]),
                ),
                NOW + 1,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn per_profile_quota_denies_without_eviction() {
    let fixture = Fixture::new();
    let store = fixture.open();
    for identifier in 0..MAX_GRANTS_PER_PROFILE {
        store
            .issue_grant(
                &grant(
                    u32::try_from(identifier).unwrap(),
                    1,
                    1,
                    "alice",
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap();
    }
    let denied = grant(
        10_000,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    assert_eq!(
        store.issue_grant(&denied, NOW).unwrap_err(),
        LocalAuthorizationStoreError::Capacity
    );
    let snapshot = store.load_snapshot(NOW, None).unwrap();
    assert_eq!(snapshot.active_grants().len(), MAX_GRANTS_PER_PROFILE);
    assert!(snapshot.active_grants().iter().any(|stored| {
        stored.grant_id()
            == grant(
                0,
                1,
                1,
                "alice",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            )
            .grant_id()
    }));
    assert!(
        !snapshot
            .active_grants()
            .iter()
            .any(|stored| stored.grant_id() == denied.grant_id())
    );
}

#[test]
fn per_issuer_quota_denies_without_eviction() {
    let fixture = Fixture::new();
    let store = fixture.open();
    for identifier in 0..MAX_GRANTS_PER_ISSUER {
        let profile_name = format!("profile-{}", identifier % 4);
        store
            .issue_grant(
                &grant(
                    u32::try_from(identifier).unwrap(),
                    1,
                    1,
                    &profile_name,
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap();
    }
    assert_eq!(
        store
            .issue_grant(
                &grant(
                    20_000,
                    1,
                    1,
                    "profile-5",
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::Capacity
    );
    let snapshot = store.load_snapshot(NOW, None).unwrap();
    assert_eq!(snapshot.active_grants().len(), MAX_GRANTS_PER_ISSUER);
    assert!(snapshot.active_grants().iter().any(|stored| {
        stored.grant_id()
            == grant(
                0,
                1,
                1,
                "profile-0",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            )
            .grant_id()
    }));
}

#[test]
fn global_quota_denies_without_eviction() {
    let fixture = Fixture::new();
    let store = LocalAuthorizationStore::bootstrap(
        &fixture.installation_path,
        fixture.fingerprint,
        &account_policy(1),
        &[issuer(1, 1), issuer(2, 1), issuer(3, 1)],
        NOW,
    )
    .unwrap();
    for identifier in 0..MAX_SESSION_GRANTS {
        let issuer_identifier = if identifier < MAX_GRANTS_PER_ISSUER {
            1
        } else {
            2
        };
        let profile_name = format!(
            "p{}-{}",
            issuer_identifier,
            identifier % (MAX_GRANTS_PER_ISSUER / MAX_GRANTS_PER_PROFILE)
        );
        store
            .issue_grant(
                &grant(
                    u32::try_from(identifier).unwrap(),
                    issuer_identifier,
                    1,
                    &profile_name,
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap();
    }
    assert_eq!(
        store
            .issue_grant(
                &grant(
                    30_000,
                    3,
                    1,
                    "spare",
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::Capacity
    );
    let snapshot = store.load_snapshot(NOW, None).unwrap();
    assert_eq!(snapshot.active_grants().len(), MAX_SESSION_GRANTS);
    assert!(snapshot.active_grants().iter().any(|stored| {
        stored.grant_id()
            == grant(
                0,
                1,
                1,
                "p1-0",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            )
            .grant_id()
    }));
}

#[test]
fn persisted_per_profile_quota_violation_fails_closed() {
    let fixture = Fixture::new();
    let store = fixture.open();
    for identifier in 0..MAX_GRANTS_PER_PROFILE {
        store
            .issue_grant(
                &grant(
                    u32::try_from(identifier).unwrap(),
                    1,
                    1,
                    "alice",
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap();
    }
    let extra = grant(
        10_000,
        1,
        1,
        "bob",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    store.issue_grant(&extra, NOW).unwrap();
    drop(store);
    Connection::open(fixture.database_path())
        .unwrap()
        .execute(
            "UPDATE authorization_grant SET profile_id = 'alice' WHERE grant_id = ?1",
            rusqlite::params![extra.grant_id().as_bytes().as_slice()],
        )
        .unwrap();
    let error =
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None).err();
    assert_eq!(error, Some(LocalAuthorizationStoreError::InvalidStorage));
}

#[test]
fn persisted_per_issuer_quota_violation_fails_closed() {
    let fixture = Fixture::new();
    let store = LocalAuthorizationStore::bootstrap(
        &fixture.installation_path,
        fixture.fingerprint,
        &account_policy(1),
        &[issuer(1, 1), issuer(2, 1)],
        NOW,
    )
    .unwrap();
    fixture.publish_installation();
    for identifier in 0..MAX_GRANTS_PER_ISSUER {
        store
            .issue_grant(
                &grant(
                    u32::try_from(identifier).unwrap(),
                    1,
                    1,
                    &format!("issuer-{identifier:03}"),
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW,
            )
            .unwrap();
    }
    let extra = grant(
        20_000,
        2,
        1,
        "other",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    store.issue_grant(&extra, NOW).unwrap();
    drop(store);
    let connection = Connection::open(fixture.database_path()).unwrap();
    let changed = connection
        .execute(
            "UPDATE authorization_grant
             SET issuer_key_id = ?1, issuer_key_version = 1
             WHERE grant_id = ?2",
            rusqlite::params![
                IssuerKeyId::from_bytes([1; 16]).as_bytes().as_slice(),
                extra.grant_id().as_bytes().as_slice()
            ],
        )
        .unwrap();
    assert_eq!(changed, 1);
    drop(connection);
    let error =
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None).err();
    assert_eq!(error, Some(LocalAuthorizationStoreError::InvalidStorage));
}

#[test]
fn retire_and_revoke_are_exact_and_idempotent() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let retired = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    let revoked = grant(2, 1, 1, "bob", AuthorizationEvidenceKind::AccountTrusted, 1);
    store.issue_grant(&retired, NOW).unwrap();
    store.issue_grant(&revoked, NOW).unwrap();

    assert_eq!(
        store
            .retire_grant(retired.grant_id(), NOW + 1)
            .unwrap()
            .effect(),
        MutationEffect::Applied
    );
    assert_eq!(
        store
            .retire_grant(retired.grant_id(), NOW + 2)
            .unwrap()
            .effect(),
        MutationEffect::Unchanged
    );
    assert_eq!(
        store
            .revoke_grant(revoked.grant_id(), NOW + 3)
            .unwrap()
            .effect(),
        MutationEffect::Applied
    );
    assert_eq!(
        store
            .revoke_grant(revoked.grant_id(), NOW + 4)
            .unwrap()
            .effect(),
        MutationEffect::Unchanged
    );
    assert!(
        store
            .load_snapshot(NOW + 4, None)
            .unwrap()
            .active_grants()
            .is_empty()
    );
}

#[test]
fn profile_suspension_revokes_existing_and_blocks_new_issuance_until_resume() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    store.issue_grant(&first, NOW).unwrap();
    store.suspend_profile(&profile("alice"), NOW + 1).unwrap();
    assert!(
        store
            .load_snapshot(NOW + 1, None)
            .unwrap()
            .active_grants()
            .is_empty()
    );
    assert_eq!(
        store
            .issue_grant(
                &grant(
                    2,
                    1,
                    1,
                    "alice",
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW + 2,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::ProfileSuspended
    );
    store.resume_profile(&profile("alice"), NOW + 3).unwrap();
    store
        .issue_grant(
            &grant(
                3,
                1,
                1,
                "alice",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            ),
            NOW + 4,
        )
        .unwrap();
}

#[test]
fn issuer_disablement_applies_retain_or_revoke_explicitly() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let retained = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    store.issue_grant(&retained, NOW).unwrap();
    store
        .set_issuer_state(
            IssuerKeyId::from_bytes([1; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            IssuerAvailability::Disabled,
            ExistingGrantDisposition::RetainUntilExpiry,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        store.load_snapshot(NOW + 1, None).unwrap().active_grants(),
        &[retained]
    );
    assert_eq!(
        store
            .issue_grant(
                &grant(2, 1, 1, "bob", AuthorizationEvidenceKind::AccountTrusted, 1,),
                NOW + 2,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::IssuerDisabled
    );
    store
        .set_issuer_state(
            IssuerKeyId::from_bytes([1; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            IssuerAvailability::Enabled,
            ExistingGrantDisposition::RetainUntilExpiry,
            NOW + 3,
        )
        .unwrap();
    store
        .issue_grant(
            &grant(2, 1, 1, "bob", AuthorizationEvidenceKind::AccountTrusted, 1),
            NOW + 4,
        )
        .unwrap();
    store
        .set_issuer_state(
            IssuerKeyId::from_bytes([1; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            IssuerAvailability::Disabled,
            ExistingGrantDisposition::Revoke,
            NOW + 5,
        )
        .unwrap();
    assert!(
        store
            .load_snapshot(NOW + 5, None)
            .unwrap()
            .active_grants()
            .is_empty()
    );
}

#[test]
fn policy_replacement_invalidates_only_unsatisfied_grants() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .issue_grant(
            &grant(
                1,
                1,
                1,
                "alice",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            ),
            NOW,
        )
        .unwrap();
    let retained = grant_with_evidence(
        2,
        1,
        1,
        "bob",
        AuthorizationEvidenceSet::new([
            AuthorizationEvidenceKind::AccountTrusted,
            AuthorizationEvidenceKind::UserPresence,
        ])
        .unwrap(),
        1,
        EXPIRY,
    );
    store.issue_grant(&retained, NOW).unwrap();
    store
        .replace_policy(&user_presence_policy(2), NOW + 1)
        .unwrap();
    assert_eq!(
        store.load_snapshot(NOW + 1, None).unwrap().active_grants(),
        &[retained]
    );
    assert_eq!(
        store
            .issue_grant(
                &grant(
                    3,
                    1,
                    1,
                    "alice",
                    AuthorizationEvidenceKind::AccountTrusted,
                    2,
                ),
                NOW + 2,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::RequiredEvidenceUnavailable
    );
    store
        .issue_grant(
            &grant(4, 1, 1, "alice", AuthorizationEvidenceKind::UserPresence, 2),
            NOW + 2,
        )
        .unwrap();
    assert_eq!(
        store
            .replace_policy(&account_policy(2), NOW + 3)
            .unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
}

#[test]
fn issuer_rotation_requires_strictly_increasing_versions_without_replacement() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store.register_issuer(&issuer(1, 2), NOW + 1).unwrap();
    assert_eq!(
        store.register_issuer(&issuer(1, 2), NOW + 2).unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    assert_eq!(
        store.register_issuer(&issuer(1, 1), NOW + 2).unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    store.register_issuer(&issuer(1, 3), NOW + 3).unwrap();
    let versions = store
        .load_snapshot(NOW + 3, None)
        .unwrap()
        .issuers()
        .iter()
        .map(|record| record.issuer_key_version().get())
        .collect::<Vec<_>>();
    assert_eq!(versions, vec![1, 2, 3]);

    let old_version = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    let new_version = grant(2, 1, 3, "bob", AuthorizationEvidenceKind::AccountTrusted, 1);
    store.issue_grant(&old_version, NOW + 4).unwrap();
    store.issue_grant(&new_version, NOW + 4).unwrap();
    store
        .set_issuer_state(
            IssuerKeyId::from_bytes([1; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            IssuerAvailability::Disabled,
            ExistingGrantDisposition::Revoke,
            NOW + 5,
        )
        .unwrap();
    assert_eq!(
        store.load_snapshot(NOW + 5, None).unwrap().active_grants(),
        &[new_version]
    );
}

#[test]
fn exact_issuer_removal_revokes_or_waits_and_never_reuses_a_version() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let active = grant(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    );
    store.issue_grant(&active, NOW).unwrap();
    assert_eq!(
        store
            .remove_issuer(
                IssuerKeyId::from_bytes([1; 16]),
                IssuerKeyVersion::new(1).unwrap(),
                ExistingGrantDisposition::RetainUntilExpiry,
                NOW + 1,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    store
        .remove_issuer(
            IssuerKeyId::from_bytes([1; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            ExistingGrantDisposition::Revoke,
            NOW + 2,
        )
        .unwrap();
    let snapshot = store.load_snapshot(NOW + 2, None).unwrap();
    assert!(snapshot.issuers().is_empty());
    assert!(snapshot.active_grants().is_empty());
    let status = store
        .load_status(
            NOW + 2,
            None,
            IssuerKeyId::from_bytes([1; 16]),
            &profile("alice"),
        )
        .unwrap();
    assert_eq!(status.issuer_records(), 0);
    assert_eq!(status.issuer_identifiers(), 1);
    assert_eq!(
        store
            .remove_issuer(
                IssuerKeyId::from_bytes([1; 16]),
                IssuerKeyVersion::new(1).unwrap(),
                ExistingGrantDisposition::Revoke,
                NOW + 3,
            )
            .unwrap()
            .effect(),
        MutationEffect::Unchanged
    );
    assert_eq!(
        store.load_audit_events(1, None).unwrap()[0].kind(),
        AuthorizationAuditKind::IssuerRemoved
    );
    assert_eq!(
        store.register_issuer(&issuer(1, 1), NOW + 4).unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    store.register_issuer(&issuer(1, 2), NOW + 4).unwrap();
}

#[test]
fn expiry_advances_generation_once_and_never_reports_grant_issue_success() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let expiring = grant_with_expiry(
        1,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
        NOW + 1,
    );
    let issued = store.issue_grant(&expiring, NOW).unwrap();
    let snapshot = store
        .load_snapshot(NOW + 1, Some(issued.generation()))
        .unwrap();
    assert!(snapshot.active_grants().is_empty());
    assert_eq!(snapshot.generation().get(), issued.generation().get() + 1);
    assert_eq!(
        store.load_audit_events(1, None).unwrap()[0].kind(),
        AuthorizationAuditKind::GrantsExpired
    );
}

#[test]
fn terminal_and_audit_history_are_pruned_deterministically() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first_id = grant(
        0,
        1,
        1,
        "alice",
        AuthorizationEvidenceKind::AccountTrusted,
        1,
    )
    .grant_id();
    let mut last_id = first_id;
    for identifier in 0..=MAX_TERMINAL_GRANT_RECORDS {
        let candidate = grant(
            u32::try_from(identifier).unwrap(),
            1,
            1,
            "alice",
            AuthorizationEvidenceKind::AccountTrusted,
            1,
        );
        last_id = candidate.grant_id();
        store.issue_grant(&candidate, NOW).unwrap();
        store.retire_grant(candidate.grant_id(), NOW + 1).unwrap();
    }
    let status = store
        .load_status(
            NOW + 1,
            None,
            IssuerKeyId::from_bytes([1; 16]),
            &profile("alice"),
        )
        .unwrap();
    assert_eq!(status.terminal_grants(), MAX_TERMINAL_GRANT_RECORDS);
    assert_eq!(status.grant_identifiers(), MAX_TERMINAL_GRANT_RECORDS + 1);
    assert_eq!(status.audit_records(), MAX_AUTHORIZATION_AUDIT_RECORDS);
    assert_eq!(
        store.retire_grant(first_id, NOW + 2).unwrap_err(),
        LocalAuthorizationStoreError::NotFound
    );
    assert_eq!(
        store
            .issue_grant(
                &grant(
                    0,
                    1,
                    1,
                    "alice",
                    AuthorizationEvidenceKind::AccountTrusted,
                    1,
                ),
                NOW + 2,
            )
            .unwrap_err(),
        LocalAuthorizationStoreError::Conflict
    );
    assert_eq!(
        store.retire_grant(last_id, NOW + 2).unwrap().effect(),
        MutationEffect::Unchanged
    );
}

#[test]
fn status_reports_bounded_global_issuer_and_profile_capacity() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .issue_grant(
            &grant(
                1,
                1,
                1,
                "alice",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            ),
            NOW,
        )
        .unwrap();
    let status = store
        .load_status(
            NOW,
            None,
            IssuerKeyId::from_bytes([1; 16]),
            &profile("alice"),
        )
        .unwrap();
    assert_eq!(status.capacity().active_global(), 1);
    assert_eq!(status.capacity().maximum_global(), MAX_SESSION_GRANTS);
    assert_eq!(status.capacity().active_for_issuer(), 1);
    assert_eq!(
        status.capacity().maximum_for_issuer(),
        MAX_GRANTS_PER_ISSUER
    );
    assert_eq!(status.capacity().active_for_profile(), 1);
    assert_eq!(
        status.capacity().maximum_for_profile(),
        MAX_GRANTS_PER_PROFILE
    );
}

#[cfg(any(unix, windows))]
#[test]
fn linked_database_file_is_rejected_as_unsafe() {
    let fixture = Fixture::new();
    fixture.publish_installation();
    let target = fixture
        .installation_path
        .parent()
        .unwrap()
        .join("linked-target.sqlite3");
    drop(open_or_create_owner_protected_file(&target).unwrap());
    std::fs::hard_link(&target, fixture.database_path()).unwrap();
    assert!(matches!(
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None,),
        Err(LocalAuthorizationStoreError::UnsafeStorage)
    ));
}

#[cfg(unix)]
#[test]
fn symbolic_link_database_file_is_rejected_as_unsafe() {
    let fixture = Fixture::new();
    fixture.publish_installation();
    let target = fixture
        .installation_path
        .parent()
        .unwrap()
        .join("symlink-target.sqlite3");
    drop(open_or_create_owner_protected_file(&target).unwrap());
    std::os::unix::fs::symlink(&target, fixture.database_path()).unwrap();
    assert!(matches!(
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None,),
        Err(LocalAuthorizationStoreError::UnsafeStorage)
    ));
}

#[cfg(unix)]
#[test]
fn permissive_database_mode_is_rejected_as_unsafe() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    drop(fixture.open());
    std::fs::set_permissions(
        fixture.database_path(),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(matches!(
        LocalAuthorizationStore::open(&fixture.installation_path, fixture.fingerprint, None,),
        Err(LocalAuthorizationStoreError::UnsafeStorage)
    ));
}

#[test]
fn database_path_is_fixed_beside_the_installation_record() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.database_path().file_name().unwrap(),
        std::ffi::OsStr::new(LOCAL_AUTHORIZATION_STORE_FILE)
    );
    assert_eq!(
        authorization_store_path("relative/konclave-local-service.json").unwrap_err(),
        LocalAuthorizationStoreError::InvalidInput
    );
}

#[test]
fn delete_journal_mode_does_not_leave_wal_or_shared_memory_sidecars() {
    let fixture = Fixture::new();
    let database_path = fixture.database_path();
    let store = fixture.open();
    store
        .issue_grant(
            &grant(
                1,
                1,
                1,
                "alice",
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            ),
            NOW,
        )
        .unwrap();
    drop(store);

    let mut wal = database_path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shared_memory = database_path.as_os_str().to_os_string();
    shared_memory.push("-shm");
    assert!(!PathBuf::from(wal).exists());
    assert!(!PathBuf::from(shared_memory).exists());
}
