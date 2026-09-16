#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use std::collections::BTreeSet;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use std::ffi::OsString;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use std::fs::File;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use std::io::Write as _;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use std::path::{Path, PathBuf};

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use KonclaveClientLibrary::{
    EnrollmentRequestId, HttpRelayEnrollmentTransport, RELAY_INSTALLATION_CONFIG_FILE,
    RelayEndpoint, RelayEnrollmentClient, RelayEnrollmentRequest, RelayEnrollmentSourceConfig,
    RelayEnrollmentTransport, RelayInstallationConfig, RelayPrincipalId,
    relay_enrollment_installation_id,
};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use KonclaveDomainCore::ProtocolVersion;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use KonclaveLocalServiceTransport::{LocalServiceInstallation, LocalServiceProfileCustody};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use KonclaveSecretStorage::{
    ExternalWrappingKeyProvider, NativeEnrollmentCredentialStore, NativeWrappingKeyProvider,
    SecretSealer, ensure_owner_protected_directory, open_or_create_owner_protected_file,
    open_owner_protected_file,
};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use anyhow::{Context as _, bail, ensure};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use fs4::{FileExt, TryLockError};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use rusqlite::{Connection, OptionalExtension as _, params};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use serde::Serialize;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use sha2::{Digest as _, Sha256};

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use crate::persistence::{LockedProfile, ProfileId, ProfileStore};
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
use crate::runtime::{load_installation_credential, read_relay_installation};

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
const RELAY_MIGRATION_JOURNAL_FILE: &str = "relay-endpoint-migration.sqlite3";
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
const RELAY_MIGRATION_LOCK_FILE: &str = "relay-endpoint-migration.lock";
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
const RELAY_MIGRATION_JOURNAL_SCHEMA_VERSION: u32 = 1;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
const MAX_RELAY_MIGRATION_PROFILES: usize = 256;
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
const RELAY_MIGRATION_REQUEST_DOMAIN: &[u8] = b"konclave:relay-migration-request:1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayMigrationState {
    SourceActive,
    RegistrationPrepared,
    DestinationActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayMigrationEvent {
    Apply,
    RegistrationAccepted,
    Abort,
    Finalize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayMigrationAction {
    PrepareRegistration,
    RegisterDestination,
    CommitDestination,
    ClearPreparation,
    RestoreSource,
    Finalize,
    Complete,
    Reject,
}

pub(crate) const fn resolve_relay_migration_action(
    state: RelayMigrationState,
    event: RelayMigrationEvent,
) -> RelayMigrationAction {
    match (state, event) {
        (RelayMigrationState::SourceActive, RelayMigrationEvent::Apply) => {
            RelayMigrationAction::PrepareRegistration
        }
        (RelayMigrationState::RegistrationPrepared, RelayMigrationEvent::Apply) => {
            RelayMigrationAction::RegisterDestination
        }
        (RelayMigrationState::DestinationActive, RelayMigrationEvent::Apply)
        | (RelayMigrationState::SourceActive, RelayMigrationEvent::Abort) => {
            RelayMigrationAction::Complete
        }
        (RelayMigrationState::RegistrationPrepared, RelayMigrationEvent::RegistrationAccepted) => {
            RelayMigrationAction::CommitDestination
        }
        (RelayMigrationState::RegistrationPrepared, RelayMigrationEvent::Abort) => {
            RelayMigrationAction::ClearPreparation
        }
        (RelayMigrationState::DestinationActive, RelayMigrationEvent::Abort) => {
            RelayMigrationAction::RestoreSource
        }
        (RelayMigrationState::DestinationActive, RelayMigrationEvent::Finalize) => {
            RelayMigrationAction::Finalize
        }
        (
            RelayMigrationState::SourceActive | RelayMigrationState::DestinationActive,
            RelayMigrationEvent::RegistrationAccepted,
        )
        | (
            RelayMigrationState::SourceActive | RelayMigrationState::RegistrationPrepared,
            RelayMigrationEvent::Finalize,
        ) => RelayMigrationAction::Reject,
    }
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalProfileState {
    Prepared = 1,
    Committed = 2,
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
impl JournalProfileState {
    fn parse(value: i64) -> anyhow::Result<Self> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Committed),
            _ => bail!("relay migration journal profile state is invalid"),
        }
    }
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
#[derive(Clone)]
struct JournalProfile {
    profile: ProfileId,
    request: RelayEnrollmentRequest,
    state: JournalProfileState,
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
struct RelayMigrationJournal {
    path: PathBuf,
    connection: Connection,
    source: RelayEndpoint,
    destination: RelayEndpoint,
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
impl RelayMigrationJournal {
    fn open(
        root: &Path,
        current_endpoint: &RelayEndpoint,
        requested_destination: &RelayEndpoint,
    ) -> anyhow::Result<Self> {
        let path = root.join(RELAY_MIGRATION_JOURNAL_FILE);
        let existed = path.exists();
        drop(
            open_or_create_owner_protected_file(&path)
                .context("opening owner-protected relay migration journal")?,
        );
        let mut connection =
            Connection::open(&path).context("opening relay migration journal database")?;
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .context("configuring relay migration journal mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("configuring relay migration durability")?;
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context("reading relay migration journal version")?;
        if version == 0 && !existed {
            ensure!(
                current_endpoint.as_str() != requested_destination.as_str(),
                "relay migration source and destination must differ"
            );
            let transaction = connection
                .transaction()
                .context("starting relay migration journal initialization")?;
            transaction
                .execute_batch(
                    "CREATE TABLE relay_migration (
                        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                        source_endpoint TEXT NOT NULL,
                        destination_endpoint TEXT NOT NULL,
                        CHECK (source_endpoint <> destination_endpoint)
                     );
                     CREATE TABLE relay_migration_profile (
                        profile_id TEXT PRIMARY KEY,
                        request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 16),
                        principal_id BLOB NOT NULL UNIQUE CHECK (length(principal_id) = 32),
                        state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 2)
                     ) WITHOUT ROWID;",
                )
                .context("creating relay migration journal schema")?;
            ensure!(
                transaction
                    .execute(
                        "INSERT INTO relay_migration (
                            singleton_id,
                            source_endpoint,
                            destination_endpoint
                         ) VALUES (1, ?1, ?2)",
                        params![current_endpoint.as_str(), requested_destination.as_str(),],
                    )
                    .context("recording relay migration contract")?
                    == 1,
                "relay migration contract was not recorded"
            );
            transaction
                .pragma_update(None, "user_version", RELAY_MIGRATION_JOURNAL_SCHEMA_VERSION)
                .context("versioning relay migration journal")?;
            transaction
                .commit()
                .context("committing relay migration journal")?;
        } else if version != RELAY_MIGRATION_JOURNAL_SCHEMA_VERSION {
            bail!("relay migration journal schema is unsupported");
        }
        let integrity: String = connection
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .context("checking relay migration journal integrity")?;
        ensure!(
            integrity == "ok",
            "relay migration journal integrity check failed"
        );
        let contract: Option<(String, String)> = connection
            .query_row(
                "SELECT source_endpoint, destination_endpoint
                 FROM relay_migration
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("reading relay migration contract")?;
        let (source, destination) =
            contract.context("relay migration journal contract is missing")?;
        let source =
            RelayEndpoint::parse(&source).context("validating relay migration source endpoint")?;
        let destination = RelayEndpoint::parse(&destination)
            .context("validating relay migration destination endpoint")?;
        ensure!(
            source.as_str() != destination.as_str()
                && destination.as_str() == requested_destination.as_str()
                && (current_endpoint.as_str() == source.as_str()
                    || current_endpoint.as_str() == destination.as_str()),
            "relay migration journal conflicts with the requested endpoints"
        );
        let profile_count: i64 = connection
            .query_row("SELECT count(*) FROM relay_migration_profile", [], |row| {
                row.get(0)
            })
            .context("counting relay migration profiles")?;
        ensure!(
            (0..=i64::try_from(MAX_RELAY_MIGRATION_PROFILES).unwrap_or(i64::MAX))
                .contains(&profile_count),
            "relay migration journal exceeds its profile bound"
        );
        Ok(Self {
            path,
            connection,
            source,
            destination,
        })
    }

    fn exists(root: &Path) -> bool {
        root.join(RELAY_MIGRATION_JOURNAL_FILE).is_file()
    }

    fn profile(&self, profile: &ProfileId) -> anyhow::Result<Option<JournalProfile>> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT request_id, principal_id, state
                 FROM relay_migration_profile
                 WHERE profile_id = ?1",
                params![profile.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("reading relay migration profile")?;
        let Some((request_id, principal_id, state)) = row else {
            return Ok(None);
        };
        let request_id = EnrollmentRequestId::from_slice(&request_id)
            .context("validating relay migration request identifier")?;
        let principal_id = RelayPrincipalId::from_slice(&principal_id)
            .context("validating relay migration principal identifier")?;
        Ok(Some(JournalProfile {
            profile: profile.clone(),
            request: RelayEnrollmentRequest::new(
                ProtocolVersion::application_v1(),
                request_id,
                principal_id,
            ),
            state: JournalProfileState::parse(state)?,
        }))
    }

    fn prepare(
        &self,
        profile: &ProfileId,
        principal: RelayPrincipalId,
    ) -> anyhow::Result<JournalProfile> {
        if let Some(existing) = self.profile(profile)? {
            ensure!(
                existing.request.principal_id() == principal,
                "relay migration profile principal conflicts with the journal"
            );
            return Ok(existing);
        }
        let request = RelayEnrollmentRequest::new(
            ProtocolVersion::application_v1(),
            relay_migration_request_id(&self.destination, principal),
            principal,
        );
        ensure!(
            self.connection
                .execute(
                    "INSERT INTO relay_migration_profile (
                        profile_id,
                        request_id,
                        principal_id,
                        state
                     ) VALUES (?1, ?2, ?3, 1)",
                    params![
                        profile.as_str(),
                        request.request_id().as_bytes().as_slice(),
                        principal.as_bytes().as_slice(),
                    ],
                )
                .context("preparing relay migration profile")?
                == 1,
            "relay migration profile was not prepared"
        );
        Ok(JournalProfile {
            profile: profile.clone(),
            request,
            state: JournalProfileState::Prepared,
        })
    }

    fn mark_committed(&self, entry: &JournalProfile) -> anyhow::Result<()> {
        let changed = self
            .connection
            .execute(
                "UPDATE relay_migration_profile
                 SET state = 2
                 WHERE profile_id = ?1
                   AND request_id = ?2
                   AND principal_id = ?3
                   AND state = 1",
                params![
                    entry.profile.as_str(),
                    entry.request.request_id().as_bytes().as_slice(),
                    entry.request.principal_id().as_bytes().as_slice(),
                ],
            )
            .context("committing relay migration profile journal")?;
        if changed == 1 {
            return Ok(());
        }
        let current = self
            .profile(&entry.profile)?
            .context("committed relay migration profile disappeared")?;
        ensure!(
            current.request == entry.request && current.state == JournalProfileState::Committed,
            "relay migration profile commit conflicts with the journal"
        );
        Ok(())
    }

    fn profiles(&self) -> anyhow::Result<Vec<JournalProfile>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT profile_id
                 FROM relay_migration_profile
                 ORDER BY profile_id",
            )
            .context("preparing relay migration profile scan")?;
        let profiles = statement
            .query_map([], |row| row.get::<_, String>(0))
            .context("scanning relay migration profiles")?
            .collect::<Result<Vec<_>, _>>()
            .context("reading relay migration profile identifiers")?;
        profiles
            .into_iter()
            .map(|profile| {
                let profile =
                    ProfileId::parse(profile).context("validating migrated profile identifier")?;
                self.profile(&profile)?
                    .context("relay migration profile disappeared during scan")
            })
            .collect()
    }

    fn committed_profile_count(&self) -> anyhow::Result<usize> {
        let (total, committed): (i64, i64) = self
            .connection
            .query_row(
                "SELECT
                    count(*),
                    coalesce(sum(CASE WHEN state = 2 THEN 1 ELSE 0 END), 0)
                 FROM relay_migration_profile",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("counting committed relay migration profiles")?;
        ensure!(
            total == committed
                && (0..=i64::try_from(MAX_RELAY_MIGRATION_PROFILES).unwrap_or(i64::MAX))
                    .contains(&total)
                && resolve_relay_migration_action(
                    RelayMigrationState::DestinationActive,
                    RelayMigrationEvent::Finalize,
                ) == RelayMigrationAction::Finalize,
            "relay migration has uncommitted profiles"
        );
        usize::try_from(total).context("converting relay migration profile count")
    }

    fn delete(self) -> anyhow::Result<()> {
        let path = self.path.clone();
        drop(self.connection);
        drop(
            open_owner_protected_file(&path)
                .context("validating relay migration journal before deletion")?,
        );
        std::fs::remove_file(&path).context("deleting completed relay migration journal")
    }
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn relay_migration_request_id(
    destination: &RelayEndpoint,
    principal: RelayPrincipalId,
) -> EnrollmentRequestId {
    let mut digest = Sha256::new();
    digest.update(RELAY_MIGRATION_REQUEST_DOMAIN);
    digest.update(destination.as_str().as_bytes());
    digest.update(principal.as_bytes());
    let digest = digest.finalize();
    let mut request_id = [0_u8; EnrollmentRequestId::LENGTH];
    request_id.copy_from_slice(&digest[..EnrollmentRequestId::LENGTH]);
    EnrollmentRequestId::from_bytes(request_id)
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
enum MigrationCustody {
    Native,
    ExternalDirectory(PathBuf),
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
struct RelayMigrationLock {
    _file: File,
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
impl RelayMigrationLock {
    fn acquire(root: &Path) -> anyhow::Result<Self> {
        let file = open_or_create_owner_protected_file(&root.join(RELAY_MIGRATION_LOCK_FILE))
            .context("opening owner-protected relay migration lock")?;
        match FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => bail!("another relay migration is active"),
            Err(TryLockError::Error(error)) => Err(error).context("acquiring relay migration lock"),
        }
    }
}

/// Machine-readable outcome of one relay endpoint migration command.
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayMigrationReport {
    /// Stable completed operation name.
    pub action: &'static str,
    /// Normalized endpoint active before the operation.
    pub source_endpoint: String,
    /// Normalized endpoint requested by the operation.
    pub destination_endpoint: String,
    /// Number of durable profiles inspected.
    pub total_profiles: usize,
    /// Number of profile databases changed by this invocation.
    pub migrated_profiles: usize,
    /// Number already in the requested terminal state.
    pub unchanged_profiles: usize,
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayMigrationMode {
    Apply,
    Abort,
    Finalize,
}

/// Parses and executes one exact relay endpoint migration command.
///
/// Supported arguments are `--config <absolute-path> --relay-endpoint <url>` with an
/// optional final `--abort` or `--finalize`. Apply registers every existing principal
/// on the destination before resealing its credential. Abort restores every
/// journaled profile to the source endpoint without a network operation. Finalize
/// removes the journal only after the restarted service has passed health validation.
///
/// # Errors
///
/// Returns a bounded argument, installation, custody, lock, journal, profile,
/// enrollment, persistence, or finalization error. Failed apply leaves a resumable
/// owner-protected journal; abort removes it only after every profile is restored.
#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
pub async fn run_relay_migration(
    arguments: impl IntoIterator<Item = OsString>,
) -> anyhow::Result<RelayMigrationReport> {
    let (installation_path, destination, mode) =
        parse_relay_migration_arguments(arguments.into_iter())?;
    migrate_relay_endpoint(&installation_path, &destination, mode).await
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn parse_relay_migration_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> anyhow::Result<(PathBuf, String, RelayMigrationMode)> {
    ensure!(
        arguments.next().as_deref() == Some(std::ffi::OsStr::new("--config")),
        "--config and one absolute installation path are required"
    );
    let installation_path = arguments
        .next()
        .map(PathBuf::from)
        .context("--config requires one installation path")?;
    ensure!(
        installation_path.is_absolute(),
        "--config requires an absolute installation path"
    );
    ensure!(
        arguments.next().as_deref() == Some(std::ffi::OsStr::new("--relay-endpoint")),
        "--relay-endpoint and one destination URL are required"
    );
    let destination = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .context("--relay-endpoint requires one Unicode destination URL")?;
    let mode = match arguments.next() {
        None => RelayMigrationMode::Apply,
        Some(value) if value == "--abort" => RelayMigrationMode::Abort,
        Some(value) if value == "--finalize" => RelayMigrationMode::Finalize,
        Some(_) => {
            bail!("the only optional relay migration arguments are --abort and --finalize")
        }
    };
    ensure!(
        arguments.next().is_none(),
        "relay migration received additional arguments"
    );
    Ok((installation_path, destination, mode))
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
async fn migrate_relay_endpoint(
    installation_path: &Path,
    requested_destination: &str,
    mode: RelayMigrationMode,
) -> anyhow::Result<RelayMigrationReport> {
    let destination =
        RelayEndpoint::parse(requested_destination).context("validating destination relay")?;
    let installation_file = open_owner_protected_file(installation_path)
        .context("opening owner-protected local-service installation")?;
    let installation = LocalServiceInstallation::from_reader(installation_file)
        .context("reading local-service installation")?;
    let root = installation.profile_root().to_path_buf();
    ensure_owner_protected_directory(&root).context("validating owner-protected profile root")?;
    let _migration_lock = RelayMigrationLock::acquire(&root)?;
    let custody = match installation.profile_custody() {
        LocalServiceProfileCustody::Native => MigrationCustody::Native,
        LocalServiceProfileCustody::ExternalDirectory(directory) => {
            MigrationCustody::ExternalDirectory(directory.clone())
        }
    };
    let current_installation = read_relay_installation(&root)?
        .context("relay installation configuration is unavailable")?;
    let current_endpoint = current_installation.endpoint().clone();
    if mode == RelayMigrationMode::Abort && !RelayMigrationJournal::exists(&root) {
        return Ok(RelayMigrationReport {
            action: "RelayMigrationNotPending",
            source_endpoint: current_endpoint.as_str().to_string(),
            destination_endpoint: destination.as_str().to_string(),
            total_profiles: 0,
            migrated_profiles: 0,
            unchanged_profiles: 0,
        });
    }
    ensure!(
        mode != RelayMigrationMode::Finalize || RelayMigrationJournal::exists(&root),
        "relay migration has no pending journal to finalize"
    );
    if mode == RelayMigrationMode::Apply
        && !RelayMigrationJournal::exists(&root)
        && current_endpoint.as_str() == destination.as_str()
    {
        let profiles = open_profiles(&root, &custody)?;
        for (_, store) in &profiles {
            let (endpoint, _) = store.relay_migration_identity()?;
            ensure!(
                endpoint.as_str() == destination.as_str(),
                "installation endpoint is active before every profile completed migration"
            );
        }
        return Ok(RelayMigrationReport {
            action: "RelayMigrationUnchanged",
            source_endpoint: current_endpoint.as_str().to_string(),
            destination_endpoint: destination.as_str().to_string(),
            total_profiles: profiles.len(),
            migrated_profiles: 0,
            unchanged_profiles: profiles.len(),
        });
    }
    let journal = RelayMigrationJournal::open(&root, &current_endpoint, &destination)?;
    let source = journal.source.clone();
    let destination = journal.destination.clone();
    if mode == RelayMigrationMode::Finalize {
        ensure!(
            current_installation.endpoint().as_str() == destination.as_str(),
            "relay installation did not reach the migration destination"
        );
        let total_profiles = journal.committed_profile_count()?;
        journal.delete()?;
        return Ok(RelayMigrationReport {
            action: "RelayMigrated",
            source_endpoint: source.as_str().to_string(),
            destination_endpoint: destination.as_str().to_string(),
            total_profiles,
            migrated_profiles: 0,
            unchanged_profiles: total_profiles,
        });
    }
    let profiles = open_profiles(&root, &custody)?;
    ensure_journal_profiles_exist(&journal, &profiles)?;
    if mode == RelayMigrationMode::Abort {
        let (restored, unchanged) = abort_profiles(&profiles, &journal, &source, &destination)?;
        replace_relay_installation(&root, &current_installation, &source)?;
        journal.delete()?;
        return Ok(RelayMigrationReport {
            action: "RelayMigrationAborted",
            source_endpoint: destination.as_str().to_string(),
            destination_endpoint: source.as_str().to_string(),
            total_profiles: profiles.len(),
            migrated_profiles: restored,
            unchanged_profiles: unchanged,
        });
    }
    let credential = load_installation_credential(&current_installation)?;
    let transport = HttpRelayEnrollmentTransport::new(destination.clone(), credential)
        .context("creating destination relay enrollment transport")?;
    let client = RelayEnrollmentClient::new(transport);
    let (migrated, unchanged) =
        apply_profiles(&profiles, &journal, &source, &destination, &client).await?;
    replace_relay_installation(&root, &current_installation, &destination)?;
    Ok(RelayMigrationReport {
        action: "RelayMigrationPendingHealth",
        source_endpoint: source.as_str().to_string(),
        destination_endpoint: destination.as_str().to_string(),
        total_profiles: profiles.len(),
        migrated_profiles: migrated,
        unchanged_profiles: unchanged,
    })
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn open_profiles(
    root: &Path,
    custody: &MigrationCustody,
) -> anyhow::Result<Vec<(ProfileId, ProfileStore)>> {
    let mut profile_ids = Vec::new();
    for entry in std::fs::read_dir(root).context("listing relay migration profiles")? {
        let entry = entry.context("reading relay migration profile directory")?;
        let file_type = entry
            .file_type()
            .context("reading relay migration profile file type")?;
        ensure!(
            !file_type.is_symlink(),
            "relay migration profile entry cannot be a link"
        );
        if !file_type.is_dir() {
            continue;
        }
        let profile = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("relay migration profile name is not Unicode"))
            .and_then(|value| {
                ProfileId::parse(value).context("validating relay migration profile name")
            })?;
        let profile_database = entry.path().join("profile.sqlite");
        let profile_database_type = std::fs::symlink_metadata(&profile_database)
            .context("reading relay migration profile database metadata")?
            .file_type();
        ensure!(
            profile_database_type.is_file() && !profile_database_type.is_symlink(),
            "relay migration profile database is missing or linked"
        );
        profile_ids.push(profile);
    }
    profile_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    ensure!(
        profile_ids.len() <= MAX_RELAY_MIGRATION_PROFILES,
        "relay migration profile count exceeds its bound"
    );
    let mut profiles = Vec::with_capacity(profile_ids.len());
    for profile in profile_ids {
        let locked = LockedProfile::acquire(root, profile.clone())
            .context("acquiring relay migration profile lock")?;
        let sealer = match custody {
            MigrationCustody::Native => {
                let provider = NativeWrappingKeyProvider::new(profile.as_str())
                    .context("configuring native relay migration custody")?;
                SecretSealer::from_provider(provider)
                    .context("loading native relay migration custody")?
            }
            MigrationCustody::ExternalDirectory(directory) => {
                let key_path = directory.join(format!("{}.key", profile.as_str()));
                let key = open_owner_protected_file(&key_path)
                    .context("opening external relay migration wrapping key")?;
                let provider = ExternalWrappingKeyProvider::from_reader(key)
                    .context("reading external relay migration wrapping key")?;
                SecretSealer::from_provider(provider)
                    .context("loading external relay migration custody")?
            }
        };
        let store = locked
            .open_store(sealer)
            .context("opening relay migration profile store")?;
        profiles.push((profile, store));
    }
    Ok(profiles)
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn ensure_journal_profiles_exist(
    journal: &RelayMigrationJournal,
    profiles: &[(ProfileId, ProfileStore)],
) -> anyhow::Result<()> {
    let available: BTreeSet<&str> = profiles
        .iter()
        .map(|(profile, _)| profile.as_str())
        .collect();
    for entry in journal.profiles()? {
        ensure!(
            available.contains(entry.profile.as_str()),
            "relay migration journal references a missing profile"
        );
    }
    Ok(())
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
async fn apply_profiles<T>(
    profiles: &[(ProfileId, ProfileStore)],
    journal: &RelayMigrationJournal,
    source: &RelayEndpoint,
    destination: &RelayEndpoint,
    client: &RelayEnrollmentClient<T>,
) -> anyhow::Result<(usize, usize)>
where
    T: RelayEnrollmentTransport,
{
    let mut migrated = 0;
    let mut unchanged = 0;
    for (profile, store) in profiles {
        loop {
            let (active_endpoint, principal) = store
                .relay_migration_identity()
                .context("reading relay migration profile identity")?;
            let entry = journal.profile(profile)?;
            let state = observed_profile_state(
                &active_endpoint,
                principal,
                entry.as_ref(),
                source,
                destination,
            )?;
            match resolve_relay_migration_action(state, RelayMigrationEvent::Apply) {
                RelayMigrationAction::PrepareRegistration => {
                    journal.prepare(profile, principal)?;
                }
                RelayMigrationAction::RegisterDestination => {
                    let entry = entry.context("prepared relay migration entry is missing")?;
                    let response = client
                        .register(entry.request)
                        .await
                        .context("registering existing principal on destination relay")?;
                    ensure!(
                        resolve_relay_migration_action(
                            state,
                            RelayMigrationEvent::RegistrationAccepted,
                        ) == RelayMigrationAction::CommitDestination
                            && response.request_id() == entry.request.request_id()
                            && response.principal_id() == principal,
                        "destination relay returned a conflicting migration response"
                    );
                    store
                        .migrate_relay_endpoint(source, destination, principal)
                        .context("committing profile relay endpoint migration")?;
                    journal.mark_committed(&entry)?;
                    migrated += 1;
                    break;
                }
                RelayMigrationAction::Complete => {
                    if let Some(entry) = entry
                        && entry.state == JournalProfileState::Prepared
                    {
                        journal.mark_committed(&entry)?;
                    }
                    unchanged += 1;
                    break;
                }
                RelayMigrationAction::CommitDestination
                | RelayMigrationAction::ClearPreparation
                | RelayMigrationAction::RestoreSource
                | RelayMigrationAction::Finalize
                | RelayMigrationAction::Reject => {
                    bail!("relay migration profile apply transition is invalid")
                }
            }
        }
    }
    Ok((migrated, unchanged))
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn observed_profile_state(
    active_endpoint: &RelayEndpoint,
    principal: RelayPrincipalId,
    entry: Option<&JournalProfile>,
    source: &RelayEndpoint,
    destination: &RelayEndpoint,
) -> anyhow::Result<RelayMigrationState> {
    if let Some(entry) = entry {
        ensure!(
            entry.request.principal_id() == principal,
            "relay migration journal principal does not match the profile"
        );
    }
    if active_endpoint.as_str() == source.as_str() {
        return match entry {
            None => Ok(RelayMigrationState::SourceActive),
            Some(entry) if entry.state == JournalProfileState::Prepared => {
                Ok(RelayMigrationState::RegistrationPrepared)
            }
            Some(_) => bail!("committed relay migration profile still uses the source"),
        };
    }
    if active_endpoint.as_str() == destination.as_str() {
        ensure!(
            entry.is_some(),
            "unjournaled profile already uses the migration destination"
        );
        return Ok(RelayMigrationState::DestinationActive);
    }
    bail!("relay migration profile uses an unrelated endpoint")
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn abort_profiles(
    profiles: &[(ProfileId, ProfileStore)],
    journal: &RelayMigrationJournal,
    source: &RelayEndpoint,
    destination: &RelayEndpoint,
) -> anyhow::Result<(usize, usize)> {
    let mut restored = 0;
    let mut unchanged = 0;
    for (profile, store) in profiles {
        let (active_endpoint, principal) = store
            .relay_migration_identity()
            .context("reading relay migration profile identity during abort")?;
        let Some(entry) = journal.profile(profile)? else {
            ensure!(
                resolve_relay_migration_action(
                    observed_profile_state(&active_endpoint, principal, None, source, destination,)?,
                    RelayMigrationEvent::Abort,
                ) == RelayMigrationAction::Complete,
                "unjournaled profile changed during relay migration"
            );
            unchanged += 1;
            continue;
        };
        match resolve_relay_migration_action(
            observed_profile_state(
                &active_endpoint,
                principal,
                Some(&entry),
                source,
                destination,
            )?,
            RelayMigrationEvent::Abort,
        ) {
            RelayMigrationAction::ClearPreparation | RelayMigrationAction::Complete => {
                unchanged += 1;
            }
            RelayMigrationAction::RestoreSource => {
                store
                    .migrate_relay_endpoint(destination, source, principal)
                    .context("restoring profile relay endpoint during abort")?;
                restored += 1;
            }
            RelayMigrationAction::PrepareRegistration
            | RelayMigrationAction::RegisterDestination
            | RelayMigrationAction::CommitDestination
            | RelayMigrationAction::Finalize
            | RelayMigrationAction::Reject => {
                bail!("relay migration profile abort transition is invalid")
            }
        }
    }
    Ok((restored, unchanged))
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
pub(crate) fn relay_migration_allows_profile(
    root: &Path,
    profile: &ProfileId,
) -> anyhow::Result<bool> {
    let path = root.join(RELAY_MIGRATION_JOURNAL_FILE);
    if !path.exists() {
        return Ok(true);
    }
    drop(
        open_owner_protected_file(&path)
            .context("opening relay migration journal for profile admission")?,
    );
    let connection = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("opening relay migration journal for profile admission")?;
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .context("reading relay migration journal admission version")?;
    ensure!(
        version == RELAY_MIGRATION_JOURNAL_SCHEMA_VERSION,
        "relay migration journal admission schema is unsupported"
    );
    let pending: i64 = connection
        .query_row(
            "SELECT count(*) FROM relay_migration_profile WHERE state <> 2",
            [],
            |row| row.get(0),
        )
        .context("counting pending relay migration profiles")?;
    if pending != 0 {
        return Ok(false);
    }
    let state: Option<i64> = connection
        .query_row(
            "SELECT state
             FROM relay_migration_profile
             WHERE profile_id = ?1",
            params![profile.as_str()],
            |row| row.get(0),
        )
        .optional()
        .context("reading relay migration profile admission")?;
    Ok(state == Some(JournalProfileState::Committed as i64))
}

#[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
fn replace_relay_installation(
    root: &Path,
    current: &RelayInstallationConfig,
    destination: &RelayEndpoint,
) -> anyhow::Result<()> {
    if current.endpoint().as_str() == destination.as_str() {
        return Ok(());
    }
    let RelayEnrollmentSourceConfig::Native { .. } = current.source() else {
        bail!("relay endpoint migration currently requires native enrollment custody");
    };
    let credential = load_installation_credential(current)?;
    let installation_id = relay_enrollment_installation_id(&credential, destination);
    let record = credential
        .encode_bound(destination)
        .context("binding enrollment credential to destination relay")?;
    NativeEnrollmentCredentialStore::new(installation_id.clone())
        .context("opening destination enrollment custody")?
        .store(&record)
        .context("storing destination enrollment credential")?;
    let replacement = RelayInstallationConfig::new(
        destination.clone(),
        RelayEnrollmentSourceConfig::Native { installation_id },
    )
    .context("building destination relay installation")?;
    let path = root.join(RELAY_INSTALLATION_CONFIG_FILE);
    let existing = open_owner_protected_file(&path)
        .context("opening relay installation before replacement")?;
    let observed = RelayInstallationConfig::from_reader(existing)
        .context("reading relay installation before replacement")?;
    ensure!(
        observed.endpoint().as_str() == current.endpoint().as_str()
            && observed.source() == current.source(),
        "relay installation changed during migration"
    );
    let bytes = replacement
        .encode()
        .context("encoding destination relay installation")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(root).context("creating relay installation replacement")?;
    temporary
        .write_all(&bytes)
        .context("writing relay installation replacement")?;
    temporary
        .as_file()
        .sync_all()
        .context("syncing relay installation replacement")?;
    temporary
        .persist(&path)
        .map_err(|error| error.error)
        .context("replacing relay installation configuration")?;
    let verified = open_owner_protected_file(&path)
        .context("opening replaced relay installation configuration")?;
    let verified = RelayInstallationConfig::from_reader(verified)
        .context("reading replaced relay installation configuration")?;
    ensure!(
        verified.endpoint().as_str() == destination.as_str()
            && verified.source() == replacement.source(),
        "replaced relay installation configuration did not verify"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    use std::sync::{Arc, Mutex};

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    use KonclaveClientLibrary::{
        KonclaveClientError, RelayAccessCredential, RelayEnrollmentCredential,
        RelayEnrollmentOutcome, RelayEnrollmentResponse,
    };
    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    use KonclaveSecretStorage::{
        ExternalWrappingKeyProvider, SecretSealer, ensure_owner_protected_directory,
    };
    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    use async_trait::async_trait;

    use super::*;
    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    use crate::persistence::{LockedProfile, ProfileId, ProfileStore};
    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    use crate::test_support::TestRelay;

    #[test]
    fn relay_migration_transition_table_is_exhaustive() {
        let cases = [
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::Apply,
                RelayMigrationAction::PrepareRegistration,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::Apply,
                RelayMigrationAction::RegisterDestination,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::Apply,
                RelayMigrationAction::Complete,
            ),
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::RegistrationAccepted,
                RelayMigrationAction::Reject,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::RegistrationAccepted,
                RelayMigrationAction::CommitDestination,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::RegistrationAccepted,
                RelayMigrationAction::Reject,
            ),
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::Abort,
                RelayMigrationAction::Complete,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::Abort,
                RelayMigrationAction::ClearPreparation,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::Abort,
                RelayMigrationAction::RestoreSource,
            ),
            (
                RelayMigrationState::SourceActive,
                RelayMigrationEvent::Finalize,
                RelayMigrationAction::Reject,
            ),
            (
                RelayMigrationState::RegistrationPrepared,
                RelayMigrationEvent::Finalize,
                RelayMigrationAction::Reject,
            ),
            (
                RelayMigrationState::DestinationActive,
                RelayMigrationEvent::Finalize,
                RelayMigrationAction::Finalize,
            ),
        ];

        for (state, event, expected) in cases {
            assert_eq!(resolve_relay_migration_action(state, event), expected);
        }
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    struct FakeEnrollmentTransport {
        requests: Arc<Mutex<Vec<RelayEnrollmentRequest>>>,
        fail_at: Option<usize>,
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    #[async_trait]
    impl RelayEnrollmentTransport for FakeEnrollmentTransport {
        async fn register(
            &self,
            request: RelayEnrollmentRequest,
        ) -> Result<RelayEnrollmentResponse, KonclaveClientError> {
            let mut requests = self.requests.lock().unwrap();
            if self.fail_at == Some(requests.len()) {
                return Err(KonclaveClientError::TransportUnavailable);
            }
            requests.push(request);
            Ok(RelayEnrollmentResponse::new(
                request.version(),
                request.request_id(),
                request.principal_id(),
                RelayEnrollmentOutcome::Registered,
            ))
        }
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    fn endpoint(value: &str) -> RelayEndpoint {
        RelayEndpoint::parse(value).unwrap()
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    fn open_store(root: &Path, profile: &str, credential_byte: u8) -> (ProfileId, ProfileStore) {
        let profile = ProfileId::parse(profile).unwrap();
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([3; 32])).unwrap();
        let store = LockedProfile::acquire(root, profile.clone())
            .unwrap()
            .open_store(sealer)
            .unwrap();
        store
            .configure_relay(
                &endpoint("http://127.0.0.1:43180"),
                &RelayAccessCredential::from_bytes([credential_byte; 32]),
            )
            .unwrap();
        (profile, store)
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    #[test]
    fn relay_migration_arguments_are_exact() {
        let absolute = if cfg!(windows) {
            r"C:\Konclave\service.json"
        } else {
            "/tmp/konclave/service.json"
        };
        assert_eq!(
            parse_relay_migration_arguments(
                [
                    "--config",
                    absolute,
                    "--relay-endpoint",
                    "https://relay.example.com",
                ]
                .into_iter()
                .map(OsString::from),
            )
            .unwrap(),
            (
                PathBuf::from(absolute),
                "https://relay.example.com".to_string(),
                RelayMigrationMode::Apply,
            )
        );
        assert_eq!(
            parse_relay_migration_arguments(
                [
                    "--config",
                    absolute,
                    "--relay-endpoint",
                    "https://relay.example.com",
                    "--abort",
                ]
                .into_iter()
                .map(OsString::from),
            )
            .unwrap()
            .2,
            RelayMigrationMode::Abort
        );
        assert_eq!(
            parse_relay_migration_arguments(
                [
                    "--config",
                    absolute,
                    "--relay-endpoint",
                    "https://relay.example.com",
                    "--finalize",
                ]
                .into_iter()
                .map(OsString::from),
            )
            .unwrap()
            .2,
            RelayMigrationMode::Finalize
        );
        for arguments in [
            Vec::<&str>::new(),
            vec![
                "--config",
                "relative",
                "--relay-endpoint",
                "https://relay.example.com",
            ],
            vec!["--config", absolute, "--other", "https://relay.example.com"],
            vec![
                "--config",
                absolute,
                "--relay-endpoint",
                "https://relay.example.com",
                "--other",
            ],
        ] {
            assert!(
                parse_relay_migration_arguments(arguments.into_iter().map(OsString::from)).is_err()
            );
        }
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    #[test]
    fn relay_migration_request_identity_is_stable_and_destination_bound() {
        let principal = RelayPrincipalId::from_bytes([7; 32]);
        let destination = endpoint("https://relay.example.com");
        assert_eq!(
            relay_migration_request_id(&destination, principal),
            relay_migration_request_id(&destination, principal)
        );
        assert_ne!(
            relay_migration_request_id(&destination, principal),
            relay_migration_request_id(&endpoint("https://other.example.com"), principal)
        );
        assert_ne!(
            relay_migration_request_id(&destination, principal),
            relay_migration_request_id(&destination, RelayPrincipalId::from_bytes([8; 32]))
        );
    }

    #[cfg(all(
        feature = "rust-service-mcp",
        feature = "rust-service-sqlite",
        unix
    ))]
    #[test]
    fn relay_migration_rejects_linked_profile_entries() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        let target = root.path().join("target-profile");
        ensure_owner_protected_directory(&profile_root).unwrap();
        ensure_owner_protected_directory(&target).unwrap();
        symlink(&target, profile_root.join("linked-profile")).unwrap();

        assert!(open_profiles(&profile_root, &MigrationCustody::Native).is_err());
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    #[tokio::test]
    async fn interrupted_profile_migration_resumes_exact_requests() {
        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        ensure_owner_protected_directory(&profile_root).unwrap();
        let source = endpoint("http://127.0.0.1:43180");
        let destination = endpoint("https://relay.example.com");
        let profiles = vec![
            open_store(&profile_root, "profile-a", 7),
            open_store(&profile_root, "profile-b", 8),
        ];
        let journal = RelayMigrationJournal::open(&profile_root, &source, &destination).unwrap();
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let first = RelayEnrollmentClient::new(FakeEnrollmentTransport {
            requests: Arc::clone(&first_requests),
            fail_at: Some(1),
        });

        assert!(
            apply_profiles(&profiles, &journal, &source, &destination, &first)
                .await
                .is_err()
        );
        assert_eq!(first_requests.lock().unwrap().len(), 1);
        assert_eq!(
            profiles[0].1.relay_migration_identity().unwrap().0.as_str(),
            destination.as_str()
        );
        assert_eq!(
            profiles[1].1.relay_migration_identity().unwrap().0.as_str(),
            source.as_str()
        );
        let second_entry = journal.profile(&profiles[1].0).unwrap().unwrap();
        assert_eq!(second_entry.state, JournalProfileState::Prepared);
        assert!(!relay_migration_allows_profile(&profile_root, &profiles[0].0).unwrap());

        let resumed_requests = Arc::new(Mutex::new(Vec::new()));
        let resumed = RelayEnrollmentClient::new(FakeEnrollmentTransport {
            requests: Arc::clone(&resumed_requests),
            fail_at: None,
        });
        assert_eq!(
            apply_profiles(&profiles, &journal, &source, &destination, &resumed)
                .await
                .unwrap(),
            (1, 1)
        );
        assert_eq!(
            resumed_requests.lock().unwrap().as_slice(),
            &[second_entry.request]
        );
        for (profile, store) in &profiles {
            assert_eq!(
                store.relay_migration_identity().unwrap().0.as_str(),
                destination.as_str()
            );
            assert_eq!(
                journal.profile(profile).unwrap().unwrap().state,
                JournalProfileState::Committed
            );
            assert!(relay_migration_allows_profile(&profile_root, profile).unwrap());
        }
        assert_eq!(journal.committed_profile_count().unwrap(), profiles.len());
        assert!(
            !relay_migration_allows_profile(
                &profile_root,
                &ProfileId::parse("new-profile").unwrap()
            )
            .unwrap()
        );
        journal.delete().unwrap();
        assert!(
            relay_migration_allows_profile(
                &profile_root,
                &ProfileId::parse("new-profile").unwrap()
            )
            .unwrap()
        );
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    #[tokio::test]
    async fn interrupted_profile_migration_aborts_without_network() {
        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        ensure_owner_protected_directory(&profile_root).unwrap();
        let source = endpoint("http://127.0.0.1:43180");
        let destination = endpoint("https://relay.example.com");
        let profiles = vec![
            open_store(&profile_root, "profile-a", 9),
            open_store(&profile_root, "profile-b", 10),
        ];
        let journal = RelayMigrationJournal::open(&profile_root, &source, &destination).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let client = RelayEnrollmentClient::new(FakeEnrollmentTransport {
            requests,
            fail_at: Some(1),
        });
        assert!(
            apply_profiles(&profiles, &journal, &source, &destination, &client)
                .await
                .is_err()
        );

        assert_eq!(
            abort_profiles(&profiles, &journal, &source, &destination).unwrap(),
            (1, 1)
        );
        for (_, store) in &profiles {
            assert_eq!(
                store.relay_migration_identity().unwrap().0.as_str(),
                source.as_str()
            );
        }
        journal.delete().unwrap();
    }

    #[cfg(all(feature = "rust-service-mcp", feature = "rust-service-sqlite"))]
    #[tokio::test]
    async fn real_relay_accepts_repeat_migration_to_one_destination() {
        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        ensure_owner_protected_directory(&profile_root).unwrap();
        let source = endpoint("http://127.0.0.1:43180");
        let enrollment = [11; RelayEnrollmentCredential::LENGTH];
        let relay = TestRelay::start_enrollment(enrollment).await;
        let destination = endpoint(&relay.endpoint);
        let profiles = vec![open_store(&profile_root, "profile-a", 12)];
        let first_journal =
            RelayMigrationJournal::open(&profile_root, &source, &destination).unwrap();
        let first = RelayEnrollmentClient::new(
            HttpRelayEnrollmentTransport::new(
                destination.clone(),
                RelayEnrollmentCredential::from_bytes(enrollment),
            )
            .unwrap(),
        );
        assert_eq!(
            apply_profiles(&profiles, &first_journal, &source, &destination, &first,)
                .await
                .unwrap(),
            (1, 0)
        );
        assert_eq!(
            abort_profiles(&profiles, &first_journal, &source, &destination).unwrap(),
            (1, 0)
        );
        first_journal.delete().unwrap();

        let second_journal =
            RelayMigrationJournal::open(&profile_root, &source, &destination).unwrap();
        let second = RelayEnrollmentClient::new(
            HttpRelayEnrollmentTransport::new(
                destination.clone(),
                RelayEnrollmentCredential::from_bytes(enrollment),
            )
            .unwrap(),
        );
        assert_eq!(
            apply_profiles(&profiles, &second_journal, &source, &destination, &second,)
                .await
                .unwrap(),
            (1, 0)
        );
        assert_eq!(
            profiles[0].1.relay_migration_identity().unwrap().0.as_str(),
            destination.as_str()
        );
        second_journal.delete().unwrap();
    }
}
