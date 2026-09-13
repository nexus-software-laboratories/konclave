use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use KonclaveDomainCore::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hex::{decode_lowercase_hex, encode_lowercase_hex};
use crate::{
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    AuthorizationPolicyVersion, HarnessKind, IssuerKeyId, IssuerKeyVersion, IssuerRegistration,
    LocalServiceEndpoint, ProfileAuthorization, ServiceProfileId,
};

/// File name of the service-owned installation record.
pub const LOCAL_SERVICE_INSTALLATION_FILE: &str = "konclave-local-service.json";

/// File name of the installer-owned Copilot and Generic client configuration.
pub const COPILOT_SERVICE_CONFIG_FILE: &str = "konclave.service.json";

const INSTALLATION_SCHEMA_VERSION: u32 = 2;
const MAX_INSTALLATION_BYTES: usize = 64 * 1024;
const MAX_CLIENT_CONFIG_BYTES: usize = 4 * 1024;
const MAX_ISSUER_REGISTRATIONS: usize = 64;
const MAX_PATH_BYTES: usize = 4 * 1024;

/// Stable failures while reading or creating local-service installation records.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalServiceInstallationError {
    /// The bounded document could not be read or written.
    #[error("local service installation I/O failed")]
    Io,
    /// The document exceeded its hard byte bound.
    #[error("local service installation is too large")]
    TooLarge,
    /// The JSON shape or one validated field is invalid.
    #[error("local service installation is invalid")]
    Invalid,
}

/// One validated authorization issuer loaded by the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledIssuerRegistration {
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    registration: IssuerRegistration,
}

impl InstalledIssuerRegistration {
    /// Creates one exact issuer authorization.
    #[must_use]
    pub const fn new(
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        registration: IssuerRegistration,
    ) -> Self {
        Self {
            issuer_key_id,
            issuer_key_version,
            registration,
        }
    }

    /// Returns the registered key identifier.
    #[must_use]
    pub const fn issuer_key_id(&self) -> IssuerKeyId {
        self.issuer_key_id
    }

    /// Returns the registered key version.
    #[must_use]
    pub const fn issuer_key_version(&self) -> IssuerKeyVersion {
        self.issuer_key_version
    }

    /// Returns the public authorization record.
    #[must_use]
    pub const fn registration(&self) -> &IssuerRegistration {
        &self.registration
    }
}

/// Validated service-wide installation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalServiceInstallation {
    endpoint: LocalServiceEndpoint,
    profile_root: PathBuf,
    service_public_key: Ed25519PublicKey,
    service_identity_source: LocalServiceIdentitySource,
    profile_custody: LocalServiceProfileCustody,
    authorization_policy: AuthorizationPolicy,
    issuers: Vec<InstalledIssuerRegistration>,
}

/// Explicit private-key custody selected for the shared service identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalServiceIdentitySource {
    /// The current user's operating-system credential store.
    Native,
    /// One owner-protected external seed file.
    ExternalFile(PathBuf),
}

/// Per-profile wrapping-key custody selected for the shared service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalServiceProfileCustody {
    /// One native credential-store entry per canonical profile identifier.
    Native,
    /// One owner-protected `<profile>.key` file per profile in this directory.
    ExternalDirectory(PathBuf),
}

impl LocalServiceInstallation {
    /// Creates one bounded installation record.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceInstallationError::Invalid`] for a non-absolute or
    /// oversized profile root, an empty issuer set, or too many registrations.
    pub fn new(
        endpoint: LocalServiceEndpoint,
        profile_root: PathBuf,
        service_public_key: Ed25519PublicKey,
        service_identity_source: LocalServiceIdentitySource,
        profile_custody: LocalServiceProfileCustody,
        authorization_policy: AuthorizationPolicy,
        issuers: Vec<InstalledIssuerRegistration>,
    ) -> Result<Self, LocalServiceInstallationError> {
        validate_absolute_path(&profile_root)?;
        if let LocalServiceIdentitySource::ExternalFile(path) = &service_identity_source {
            validate_absolute_path(path)?;
        }
        if let LocalServiceProfileCustody::ExternalDirectory(path) = &profile_custody {
            validate_absolute_path(path)?;
        }
        if issuers.is_empty() || issuers.len() > MAX_ISSUER_REGISTRATIONS {
            return Err(LocalServiceInstallationError::Invalid);
        }
        let unique = issuers
            .iter()
            .map(|issuer| (issuer.issuer_key_id, issuer.issuer_key_version))
            .collect::<HashSet<_>>();
        if unique.len() != issuers.len() {
            return Err(LocalServiceInstallationError::Invalid);
        }
        if issuers
            .iter()
            .any(|issuer| issuer.registration.public_key() == service_public_key)
        {
            return Err(LocalServiceInstallationError::Invalid);
        }
        Ok(Self {
            endpoint,
            profile_root,
            service_public_key,
            service_identity_source,
            profile_custody,
            authorization_policy,
            issuers,
        })
    }

    /// Reads and validates one bounded JSON record.
    ///
    /// # Errors
    ///
    /// Returns a finite I/O, size, or validation error. No path or document content is
    /// carried in the error.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, LocalServiceInstallationError> {
        let mut bytes = Vec::with_capacity(MAX_INSTALLATION_BYTES + 1);
        reader
            .by_ref()
            .take((MAX_INSTALLATION_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| LocalServiceInstallationError::Io)?;
        if bytes.len() > MAX_INSTALLATION_BYTES {
            return Err(LocalServiceInstallationError::TooLarge);
        }
        let document: InstallationDocument =
            serde_json::from_slice(&bytes).map_err(|_| LocalServiceInstallationError::Invalid)?;
        document.try_into()
    }

    /// Writes the canonical JSON representation.
    ///
    /// # Errors
    ///
    /// Returns a finite encoding or output error.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), LocalServiceInstallationError> {
        let document = InstallationDocument::from(self);
        serde_json::to_writer(&mut writer, &document).map_err(|_| LocalServiceInstallationError::Io)
    }

    /// Returns the owner-protected local endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &LocalServiceEndpoint {
        &self.endpoint
    }

    /// Returns the shared profile root.
    #[must_use]
    pub fn profile_root(&self) -> &Path {
        &self.profile_root
    }

    /// Returns the service key clients pin.
    #[must_use]
    pub const fn service_public_key(&self) -> Ed25519PublicKey {
        self.service_public_key
    }

    /// Returns the exact private-key custody selected at installation.
    #[must_use]
    pub const fn service_identity_source(&self) -> &LocalServiceIdentitySource {
        &self.service_identity_source
    }

    /// Returns the exact per-profile wrapping-key custody policy.
    #[must_use]
    pub const fn profile_custody(&self) -> &LocalServiceProfileCustody {
        &self.profile_custody
    }

    /// Returns the effective installation authorization policy.
    #[must_use]
    pub const fn authorization_policy(&self) -> &AuthorizationPolicy {
        &self.authorization_policy
    }

    /// Returns the finite active AccountTrusted issuer registrations.
    #[must_use]
    pub fn issuers(&self) -> &[InstalledIssuerRegistration] {
        &self.issuers
    }
}

/// Validated Copilot and Generic client configuration emitted from an installation.
#[derive(Clone, PartialEq, Eq)]
pub struct CopilotServiceConfig {
    endpoint: LocalServiceEndpoint,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    service_public_key: Ed25519PublicKey,
    signing_key_file: PathBuf,
    user_presence_helper: Option<PathBuf>,
    authorization_policy: AuthorizationPolicy,
}

impl CopilotServiceConfig {
    /// Binds one Copilot AccountTrusted issuer to an installed service.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceInstallationError::Invalid`] when the signing-key path
    /// is not absolute or exceeds the path bound.
    pub fn new(
        endpoint: LocalServiceEndpoint,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        service_public_key: Ed25519PublicKey,
        signing_key_file: PathBuf,
        user_presence_helper: Option<PathBuf>,
        authorization_policy: AuthorizationPolicy,
    ) -> Result<Self, LocalServiceInstallationError> {
        validate_absolute_path(&signing_key_file)?;
        if let Some(user_presence_helper) = user_presence_helper.as_ref() {
            validate_absolute_path(user_presence_helper)?;
        }
        Ok(Self {
            endpoint,
            issuer_key_id,
            issuer_key_version,
            service_public_key,
            signing_key_file,
            user_presence_helper,
            authorization_policy,
        })
    }

    /// Reads one bounded installer-owned client configuration.
    ///
    /// # Errors
    ///
    /// Returns a finite I/O, size, or validation error. Unknown fields, unsupported
    /// schema versions, relative paths, and malformed authorization values are
    /// rejected.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, LocalServiceInstallationError> {
        let mut bytes = Vec::with_capacity(MAX_CLIENT_CONFIG_BYTES + 1);
        reader
            .by_ref()
            .take((MAX_CLIENT_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| LocalServiceInstallationError::Io)?;
        if bytes.len() > MAX_CLIENT_CONFIG_BYTES {
            return Err(LocalServiceInstallationError::TooLarge);
        }
        let document: CopilotDocument =
            serde_json::from_slice(&bytes).map_err(|_| LocalServiceInstallationError::Invalid)?;
        document.try_into()
    }

    /// Writes the exact installer-owned record consumed by thin local clients.
    ///
    /// # Errors
    ///
    /// Returns a finite encoding or output error.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), LocalServiceInstallationError> {
        serde_json::to_writer(&mut writer, &CopilotDocument::try_from(self)?)
            .map_err(|_| LocalServiceInstallationError::Io)
    }

    fn matches_legacy(&self, desired: &Self) -> bool {
        self.endpoint == desired.endpoint
            && self.issuer_key_id == desired.issuer_key_id
            && self.issuer_key_version == desired.issuer_key_version
            && self.service_public_key == desired.service_public_key
            && self.signing_key_file == desired.signing_key_file
            && (self.user_presence_helper.is_none()
                || self.user_presence_helper == desired.user_presence_helper)
            && self.authorization_policy == desired.authorization_policy
    }
}

/// Stable failures while resolving the canonical per-user client configuration path.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientRuntimeConfigPathError {
    /// The platform-required home or data directory is unavailable.
    #[error("client runtime configuration location is unavailable")]
    Unavailable,
    /// The configured platform data directory is relative, oversized, or non-Unicode.
    #[error("client runtime configuration location is invalid")]
    Invalid,
}

/// Resolves the canonical per-user client configuration path for the current platform.
///
/// # Errors
///
/// Returns [`ClientRuntimeConfigPathError::Unavailable`] when a required environment
/// location is absent and [`ClientRuntimeConfigPathError::Invalid`] when a supplied
/// location is unsafe.
pub fn default_client_runtime_config_path() -> Result<PathBuf, ClientRuntimeConfigPathError> {
    #[cfg(windows)]
    {
        return windows_client_runtime_config_path(std::env::var_os("LOCALAPPDATA"));
    }
    #[cfg(target_os = "macos")]
    {
        return macos_client_runtime_config_path(std::env::var_os("HOME"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return unix_client_runtime_config_path(
            std::env::var_os("XDG_DATA_HOME"),
            std::env::var_os("HOME"),
        );
    }
    #[allow(unreachable_code)]
    Err(ClientRuntimeConfigPathError::Unavailable)
}

/// Filesystem action selected for installer-owned client configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRuntimeConfigAction {
    /// No prior configuration exists; create the canonical record.
    CreateCanonical,
    /// The canonical record already contains the requested authority values.
    PreserveCanonical,
    /// Only an equal legacy sidecar exists; copy its authority into the canonical path.
    MigrateLegacy,
}

/// Stable failure while reconciling canonical and legacy client configuration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientRuntimeConfigReconciliationError {
    /// Existing canonical or legacy authority values differ from the requested install.
    #[error("installed client runtime configuration conflicts with the requested installation")]
    Conflict,
}

/// Selects the exact idempotent action for canonical and legacy client configuration.
///
/// Existing records must already have passed bounded parsing and owner-protection
/// checks. Any semantic difference in endpoint, issuer, pinned service key, signing
/// key location, or authorization policy fails closed. A legacy record may omit the
/// optional UserPresence helper added by a newer installer.
///
/// # Errors
///
/// Returns [`ClientRuntimeConfigReconciliationError::Conflict`] when either existing
/// record differs from `desired`.
pub fn reconcile_client_runtime_config(
    desired: &CopilotServiceConfig,
    canonical: Option<&CopilotServiceConfig>,
    legacy: Option<&CopilotServiceConfig>,
) -> Result<ClientRuntimeConfigAction, ClientRuntimeConfigReconciliationError> {
    if canonical.is_some_and(|existing| existing != desired)
        || legacy.is_some_and(|existing| !existing.matches_legacy(desired))
    {
        return Err(ClientRuntimeConfigReconciliationError::Conflict);
    }
    Ok(match (canonical, legacy) {
        (Some(_), _) => ClientRuntimeConfigAction::PreserveCanonical,
        (None, Some(_)) => ClientRuntimeConfigAction::MigrateLegacy,
        (None, None) => ClientRuntimeConfigAction::CreateCanonical,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InstallationDocument {
    schema_version: u32,
    endpoint: String,
    profile_root: String,
    service_public_key: String,
    service_identity: IdentitySourceDocument,
    profile_custody: ProfileCustodyDocument,
    authorization_policy: AuthorizationPolicyDocument,
    issuers: Vec<IssuerDocument>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IdentitySourceDocument {
    Native,
    ExternalFile { path: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProfileCustodyDocument {
    Native,
    ExternalDirectory { path: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IssuerDocument {
    issuer_key_id: String,
    issuer_key_version: u32,
    public_key: String,
    harness: String,
    profile_kind: String,
    profile_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthorizationPolicyDocument {
    version: u64,
    accepted_evidence: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CopilotDocument {
    schema_version: u32,
    endpoint: String,
    issuer_key_id: String,
    issuer_key_version: u32,
    harness: String,
    service_key: String,
    issuer_key_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_presence_helper: Option<String>,
    authorization_policy: AuthorizationPolicyDocument,
}

impl TryFrom<InstallationDocument> for LocalServiceInstallation {
    type Error = LocalServiceInstallationError;

    fn try_from(document: InstallationDocument) -> Result<Self, Self::Error> {
        if document.schema_version != INSTALLATION_SCHEMA_VERSION {
            return Err(LocalServiceInstallationError::Invalid);
        }
        let endpoint = LocalServiceEndpoint::parse(&document.endpoint)
            .map_err(|_| LocalServiceInstallationError::Invalid)?;
        let profile_root = PathBuf::from(document.profile_root);
        let service_public_key =
            Ed25519PublicKey::from_bytes(decode_hex(&document.service_public_key)?);
        let service_identity_source = match document.service_identity {
            IdentitySourceDocument::Native => LocalServiceIdentitySource::Native,
            IdentitySourceDocument::ExternalFile { path } => {
                LocalServiceIdentitySource::ExternalFile(PathBuf::from(path))
            }
        };
        let profile_custody = match document.profile_custody {
            ProfileCustodyDocument::Native => LocalServiceProfileCustody::Native,
            ProfileCustodyDocument::ExternalDirectory { path } => {
                LocalServiceProfileCustody::ExternalDirectory(PathBuf::from(path))
            }
        };
        let authorization_policy = AuthorizationPolicy::try_from(document.authorization_policy)?;
        let issuers = document
            .issuers
            .into_iter()
            .map(InstalledIssuerRegistration::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            endpoint,
            profile_root,
            service_public_key,
            service_identity_source,
            profile_custody,
            authorization_policy,
            issuers,
        )
    }
}

impl TryFrom<CopilotDocument> for CopilotServiceConfig {
    type Error = LocalServiceInstallationError;

    fn try_from(document: CopilotDocument) -> Result<Self, Self::Error> {
        if document.schema_version != INSTALLATION_SCHEMA_VERSION || document.harness != "copilot" {
            return Err(LocalServiceInstallationError::Invalid);
        }
        Self::new(
            LocalServiceEndpoint::parse(&document.endpoint)
                .map_err(|_| LocalServiceInstallationError::Invalid)?,
            IssuerKeyId::from_bytes(decode_hex(&document.issuer_key_id)?),
            IssuerKeyVersion::new(document.issuer_key_version)
                .map_err(|_| LocalServiceInstallationError::Invalid)?,
            Ed25519PublicKey::from_bytes(decode_hex(&document.service_key)?),
            PathBuf::from(document.issuer_key_file),
            document.user_presence_helper.map(PathBuf::from),
            AuthorizationPolicy::try_from(document.authorization_policy)?,
        )
    }
}

impl TryFrom<&CopilotServiceConfig> for CopilotDocument {
    type Error = LocalServiceInstallationError;

    fn try_from(config: &CopilotServiceConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: INSTALLATION_SCHEMA_VERSION,
            endpoint: config.endpoint.as_str().to_string(),
            issuer_key_id: encode_hex(config.issuer_key_id.as_bytes()),
            issuer_key_version: config.issuer_key_version.get(),
            harness: "copilot".to_string(),
            service_key: encode_hex(config.service_public_key.as_bytes()),
            issuer_key_file: config
                .signing_key_file
                .to_str()
                .ok_or(LocalServiceInstallationError::Invalid)?
                .to_string(),
            user_presence_helper: config
                .user_presence_helper
                .as_ref()
                .map(|path| {
                    path.to_str()
                        .map(str::to_string)
                        .ok_or(LocalServiceInstallationError::Invalid)
                })
                .transpose()?,
            authorization_policy: AuthorizationPolicyDocument::from(&config.authorization_policy),
        })
    }
}

impl TryFrom<IssuerDocument> for InstalledIssuerRegistration {
    type Error = LocalServiceInstallationError;

    fn try_from(document: IssuerDocument) -> Result<Self, Self::Error> {
        let harness = match document.harness.as_str() {
            "copilot" => HarnessKind::Copilot,
            "claude-code" => HarnessKind::ClaudeCode,
            "codex" => HarnessKind::Codex,
            "generic" => HarnessKind::Generic,
            "a2a-gateway" => HarnessKind::A2AGateway,
            _ => return Err(LocalServiceInstallationError::Invalid),
        };
        let issuer_key_id = IssuerKeyId::from_bytes(decode_hex(&document.issuer_key_id)?);
        let issuer_key_version = IssuerKeyVersion::new(document.issuer_key_version)
            .map_err(|_| LocalServiceInstallationError::Invalid)?;
        let public_key = Ed25519PublicKey::from_bytes(decode_hex(&document.public_key)?);
        let profiles = match document.profile_kind.as_str() {
            "profile" => ProfileAuthorization::Profile(
                ServiceProfileId::parse(&document.profile_id)
                    .map_err(|_| LocalServiceInstallationError::Invalid)?,
            ),
            "namespace" => ProfileAuthorization::Namespace(
                ServiceProfileId::parse(&document.profile_id)
                    .map_err(|_| LocalServiceInstallationError::Invalid)?,
            ),
            "all" if document.profile_id.is_empty() => ProfileAuthorization::All,
            _ => return Err(LocalServiceInstallationError::Invalid),
        };
        Ok(Self::new(
            issuer_key_id,
            issuer_key_version,
            IssuerRegistration::new(public_key, harness, profiles),
        ))
    }
}

impl From<&LocalServiceInstallation> for InstallationDocument {
    fn from(installation: &LocalServiceInstallation) -> Self {
        Self {
            schema_version: INSTALLATION_SCHEMA_VERSION,
            endpoint: installation.endpoint.as_str().to_string(),
            profile_root: installation.profile_root.to_string_lossy().into_owned(),
            service_public_key: encode_hex(installation.service_public_key.as_bytes()),
            service_identity: match &installation.service_identity_source {
                LocalServiceIdentitySource::Native => IdentitySourceDocument::Native,
                LocalServiceIdentitySource::ExternalFile(path) => {
                    IdentitySourceDocument::ExternalFile {
                        path: path.to_string_lossy().into_owned(),
                    }
                }
            },
            profile_custody: match &installation.profile_custody {
                LocalServiceProfileCustody::Native => ProfileCustodyDocument::Native,
                LocalServiceProfileCustody::ExternalDirectory(path) => {
                    ProfileCustodyDocument::ExternalDirectory {
                        path: path.to_string_lossy().into_owned(),
                    }
                }
            },
            authorization_policy: AuthorizationPolicyDocument::from(
                &installation.authorization_policy,
            ),
            issuers: installation
                .issuers
                .iter()
                .map(|issuer| IssuerDocument {
                    issuer_key_id: encode_hex(issuer.issuer_key_id.as_bytes()),
                    issuer_key_version: issuer.issuer_key_version.get(),
                    public_key: encode_hex(issuer.registration.public_key().as_bytes()),
                    harness: match issuer.registration.harness() {
                        HarnessKind::Copilot => "copilot",
                        HarnessKind::ClaudeCode => "claude-code",
                        HarnessKind::Codex => "codex",
                        HarnessKind::Generic => "generic",
                        HarnessKind::A2AGateway => "a2a-gateway",
                    }
                    .to_string(),
                    profile_kind: match issuer.registration.profiles() {
                        ProfileAuthorization::Profile(_) => "profile",
                        ProfileAuthorization::Namespace(_) => "namespace",
                        ProfileAuthorization::All => "all",
                    }
                    .to_string(),
                    profile_id: match issuer.registration.profiles() {
                        ProfileAuthorization::Profile(profile)
                        | ProfileAuthorization::Namespace(profile) => profile.as_str().to_string(),
                        ProfileAuthorization::All => String::new(),
                    },
                })
                .collect(),
        }
    }
}

impl TryFrom<AuthorizationPolicyDocument> for AuthorizationPolicy {
    type Error = LocalServiceInstallationError;

    fn try_from(document: AuthorizationPolicyDocument) -> Result<Self, Self::Error> {
        let version = AuthorizationPolicyVersion::new(document.version)
            .map_err(|_| LocalServiceInstallationError::Invalid)?;
        let clauses = document
            .accepted_evidence
            .into_iter()
            .map(|clause| {
                AuthorizationEvidenceSet::new(
                    clause
                        .into_iter()
                        .map(|kind| parse_evidence_kind(&kind))
                        .collect::<Result<Vec<_>, _>>()?,
                )
                .map_err(|_| LocalServiceInstallationError::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        AuthorizationPolicy::new(version, clauses)
            .map_err(|_| LocalServiceInstallationError::Invalid)
    }
}

impl From<&AuthorizationPolicy> for AuthorizationPolicyDocument {
    fn from(policy: &AuthorizationPolicy) -> Self {
        Self {
            version: policy.version().get(),
            accepted_evidence: policy
                .clauses()
                .iter()
                .map(|clause| {
                    [
                        AuthorizationEvidenceKind::AccountTrusted,
                        AuthorizationEvidenceKind::UserPresence,
                        AuthorizationEvidenceKind::HarnessAttested,
                        AuthorizationEvidenceKind::WorkloadIdentity,
                    ]
                    .into_iter()
                    .filter(|kind| {
                        AuthorizationEvidenceSet::new([*kind])
                            .is_ok_and(|single| clause.satisfies(single))
                    })
                    .map(|kind| kind.as_str().to_string())
                    .collect()
                })
                .collect(),
        }
    }
}

fn parse_evidence_kind(
    value: &str,
) -> Result<AuthorizationEvidenceKind, LocalServiceInstallationError> {
    match value {
        "account_trusted" => Ok(AuthorizationEvidenceKind::AccountTrusted),
        "user_presence" => Ok(AuthorizationEvidenceKind::UserPresence),
        "harness_attested" => Ok(AuthorizationEvidenceKind::HarnessAttested),
        "workload_identity" => Ok(AuthorizationEvidenceKind::WorkloadIdentity),
        _ => Err(LocalServiceInstallationError::Invalid),
    }
}

#[cfg(any(windows, test))]
fn windows_client_runtime_config_path(
    local_app_data: Option<OsString>,
) -> Result<PathBuf, ClientRuntimeConfigPathError> {
    client_runtime_config_path(
        required_client_config_root(local_app_data)?,
        &["Konclave", "service"],
    )
}

#[cfg(any(target_os = "macos", test))]
fn macos_client_runtime_config_path(
    home: Option<OsString>,
) -> Result<PathBuf, ClientRuntimeConfigPathError> {
    client_runtime_config_path(
        required_client_config_root(home)?,
        &["Library", "Application Support", "Konclave", "service"],
    )
}

fn unix_client_runtime_config_path(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, ClientRuntimeConfigPathError> {
    match optional_client_config_root(xdg_data_home)? {
        Some(root) => client_runtime_config_path(root, &["konclave", "service"]),
        None => client_runtime_config_path(
            required_client_config_root(home)?,
            &[".local", "share", "konclave", "service"],
        ),
    }
}

fn required_client_config_root(
    value: Option<OsString>,
) -> Result<PathBuf, ClientRuntimeConfigPathError> {
    optional_client_config_root(value)?.ok_or(ClientRuntimeConfigPathError::Unavailable)
}

fn optional_client_config_root(
    value: Option<OsString>,
) -> Result<Option<PathBuf>, ClientRuntimeConfigPathError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    validate_client_config_path(&path)?;
    Ok(Some(path))
}

fn client_runtime_config_path(
    root: PathBuf,
    directories: &[&str],
) -> Result<PathBuf, ClientRuntimeConfigPathError> {
    let mut path = root;
    for directory in directories {
        path.push(directory);
    }
    path.push(COPILOT_SERVICE_CONFIG_FILE);
    validate_client_config_path(&path)?;
    Ok(path)
}

fn validate_client_config_path(path: &Path) -> Result<(), ClientRuntimeConfigPathError> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|value| value.is_empty() || value.len() > MAX_PATH_BYTES)
    {
        return Err(ClientRuntimeConfigPathError::Invalid);
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), LocalServiceInstallationError> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|value| value.is_empty() || value.len() > MAX_PATH_BYTES)
    {
        return Err(LocalServiceInstallationError::Invalid);
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], LocalServiceInstallationError> {
    decode_lowercase_hex(value).ok_or(LocalServiceInstallationError::Invalid)
}

fn encode_hex(bytes: &[u8]) -> String {
    encode_lowercase_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installation() -> LocalServiceInstallation {
        LocalServiceInstallation::new(
            LocalServiceEndpoint::parse(if cfg!(windows) {
                r"\\.\pipe\konclave-local-service"
            } else {
                "/tmp/konclave/service.sock"
            })
            .unwrap(),
            if cfg!(windows) {
                PathBuf::from(r"C:\Users\example\AppData\Local\Konclave\profiles")
            } else {
                PathBuf::from("/home/example/.local/share/konclave/profiles")
            },
            Ed25519PublicKey::from_bytes([3_u8; Ed25519PublicKey::LENGTH]),
            LocalServiceIdentitySource::Native,
            LocalServiceProfileCustody::Native,
            AuthorizationPolicy::account_trusted(),
            vec![InstalledIssuerRegistration::new(
                IssuerKeyId::from_bytes([1_u8; IssuerKeyId::LENGTH]),
                IssuerKeyVersion::new(1).unwrap(),
                IssuerRegistration::new(
                    Ed25519PublicKey::from_bytes([2_u8; Ed25519PublicKey::LENGTH]),
                    HarnessKind::Copilot,
                    ProfileAuthorization::Namespace(ServiceProfileId::parse("session").unwrap()),
                ),
            )],
        )
        .unwrap()
    }

    #[test]
    fn installation_and_copilot_documents_round_trip_canonically() {
        let expected = installation();
        let mut encoded = Vec::new();
        expected.write_to(&mut encoded).unwrap();
        assert_eq!(
            LocalServiceInstallation::from_reader(encoded.as_slice()).unwrap(),
            expected
        );

        let signing_key = if cfg!(windows) {
            PathBuf::from(r"C:\Users\example\AppData\Local\Konclave\account-issuer.key")
        } else {
            PathBuf::from("/home/example/.local/share/konclave/account-issuer.key")
        };
        let issuer = &expected.issuers()[0];
        let client = CopilotServiceConfig::new(
            expected.endpoint().clone(),
            issuer.issuer_key_id(),
            issuer.issuer_key_version(),
            expected.service_public_key(),
            signing_key.clone(),
            Some(if cfg!(windows) {
                PathBuf::from(r"C:\Program Files\Konclave\bin\konclave.exe")
            } else {
                PathBuf::from("/opt/konclave/bin/konclave")
            }),
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap();
        let mut client_json = Vec::new();
        client.write_to(&mut client_json).unwrap();
        assert!(CopilotServiceConfig::from_reader(client_json.as_slice()).unwrap() == client);
        let value: serde_json::Value = serde_json::from_slice(&client_json).unwrap();
        assert_eq!(value["schemaVersion"], 2);
        assert_eq!(value["harness"], "copilot");
        assert_eq!(value["issuerKeyId"], "01".repeat(16));
        assert_eq!(value["serviceKey"], "03".repeat(32));
        assert!(
            value["userPresenceHelper"]
                .as_str()
                .unwrap()
                .ends_with(if cfg!(windows) {
                    "konclave.exe"
                } else {
                    "konclave"
                })
        );
        assert_eq!(
            value["authorizationPolicy"]["acceptedEvidence"][0][0],
            "account_trusted"
        );

        let legacy_compatible = CopilotServiceConfig::new(
            expected.endpoint().clone(),
            issuer.issuer_key_id(),
            issuer.issuer_key_version(),
            expected.service_public_key(),
            signing_key,
            None,
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap();
        let mut legacy_json = Vec::new();
        legacy_compatible.write_to(&mut legacy_json).unwrap();
        assert!(
            CopilotServiceConfig::from_reader(legacy_json.as_slice()).unwrap() == legacy_compatible
        );
        let legacy: serde_json::Value = serde_json::from_slice(&legacy_json).unwrap();
        assert!(legacy.get("userPresenceHelper").is_none());
    }

    #[test]
    fn client_configuration_reconciliation_is_finite_and_fail_closed() {
        let desired = client_config(1);
        let mut legacy_without_helper = desired.clone();
        legacy_without_helper.user_presence_helper = None;
        let mut helper_conflict = desired.clone();
        helper_conflict.user_presence_helper = Some(if cfg!(windows) {
            PathBuf::from(r"C:\Other\konclave.exe")
        } else {
            PathBuf::from("/other/konclave")
        });
        let conflict = client_config(2);
        for (canonical, legacy, expected) in [
            (None, None, Ok(ClientRuntimeConfigAction::CreateCanonical)),
            (
                Some(&desired),
                None,
                Ok(ClientRuntimeConfigAction::PreserveCanonical),
            ),
            (
                None,
                Some(&legacy_without_helper),
                Ok(ClientRuntimeConfigAction::MigrateLegacy),
            ),
            (
                Some(&desired),
                Some(&legacy_without_helper),
                Ok(ClientRuntimeConfigAction::PreserveCanonical),
            ),
            (
                Some(&conflict),
                None,
                Err(ClientRuntimeConfigReconciliationError::Conflict),
            ),
            (
                Some(&legacy_without_helper),
                None,
                Err(ClientRuntimeConfigReconciliationError::Conflict),
            ),
            (
                None,
                Some(&conflict),
                Err(ClientRuntimeConfigReconciliationError::Conflict),
            ),
            (
                None,
                Some(&helper_conflict),
                Err(ClientRuntimeConfigReconciliationError::Conflict),
            ),
            (
                Some(&desired),
                Some(&conflict),
                Err(ClientRuntimeConfigReconciliationError::Conflict),
            ),
        ] {
            assert_eq!(
                reconcile_client_runtime_config(&desired, canonical, legacy),
                expected
            );
        }
    }

    #[test]
    fn client_configuration_paths_follow_platform_data_conventions() {
        let base = std::env::temp_dir().join("konclave-client-config-root");
        assert_eq!(
            windows_client_runtime_config_path(Some(base.clone().into_os_string())).unwrap(),
            base.join("Konclave")
                .join("service")
                .join(COPILOT_SERVICE_CONFIG_FILE)
        );
        assert_eq!(
            macos_client_runtime_config_path(Some(base.clone().into_os_string())).unwrap(),
            base.join("Library")
                .join("Application Support")
                .join("Konclave")
                .join("service")
                .join(COPILOT_SERVICE_CONFIG_FILE)
        );
        assert_eq!(
            unix_client_runtime_config_path(Some(base.clone().into_os_string()), None).unwrap(),
            base.join("konclave")
                .join("service")
                .join(COPILOT_SERVICE_CONFIG_FILE)
        );
        assert_eq!(
            unix_client_runtime_config_path(None, Some(base.clone().into_os_string())).unwrap(),
            base.join(".local")
                .join("share")
                .join("konclave")
                .join("service")
                .join(COPILOT_SERVICE_CONFIG_FILE)
        );
        assert_eq!(
            windows_client_runtime_config_path(None),
            Err(ClientRuntimeConfigPathError::Unavailable)
        );
        assert_eq!(
            macos_client_runtime_config_path(Some(OsString::new())),
            Err(ClientRuntimeConfigPathError::Unavailable)
        );
        assert_eq!(
            unix_client_runtime_config_path(Some(OsString::from("relative")), None),
            Err(ClientRuntimeConfigPathError::Invalid)
        );
    }

    #[test]
    fn malformed_or_oversized_client_configuration_fails_closed() {
        let client = client_config(1);
        let mut encoded = Vec::new();
        client.write_to(&mut encoded).unwrap();
        let valid: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let invalid = [
            serde_json::json!({}),
            {
                let mut value = valid.clone();
                value["schemaVersion"] = serde_json::json!(3);
                value
            },
            {
                let mut value = valid.clone();
                value["harness"] = serde_json::json!("generic");
                value
            },
            {
                let mut value = valid;
                value["issuerKeyFile"] = serde_json::json!("relative.key");
                value
            },
        ];
        for value in invalid {
            assert_eq!(
                CopilotServiceConfig::from_reader(value.to_string().as_bytes()).err(),
                Some(LocalServiceInstallationError::Invalid)
            );
        }
        assert_eq!(
            CopilotServiceConfig::from_reader(vec![0_u8; MAX_CLIENT_CONFIG_BYTES + 1].as_slice())
                .err(),
            Some(LocalServiceInstallationError::TooLarge)
        );
    }

    #[test]
    fn service_identity_cannot_be_reused_as_an_issuer_identity() {
        let service_key = Ed25519PublicKey::from_bytes([3_u8; Ed25519PublicKey::LENGTH]);
        assert_eq!(
            LocalServiceInstallation::new(
                LocalServiceEndpoint::parse(if cfg!(windows) {
                    r"\\.\pipe\konclave-local-service"
                } else {
                    "/tmp/konclave/service.sock"
                })
                .unwrap(),
                if cfg!(windows) {
                    PathBuf::from(r"C:\Users\example\AppData\Local\Konclave\profiles")
                } else {
                    PathBuf::from("/home/example/.local/share/konclave/profiles")
                },
                service_key,
                LocalServiceIdentitySource::Native,
                LocalServiceProfileCustody::Native,
                AuthorizationPolicy::account_trusted(),
                vec![InstalledIssuerRegistration::new(
                    IssuerKeyId::from_bytes([1_u8; IssuerKeyId::LENGTH]),
                    IssuerKeyVersion::new(1).unwrap(),
                    IssuerRegistration::new(
                        service_key,
                        HarnessKind::Copilot,
                        ProfileAuthorization::Namespace(
                            ServiceProfileId::parse("session").unwrap(),
                        ),
                    ),
                )],
            )
            .unwrap_err(),
            LocalServiceInstallationError::Invalid
        );
    }

    #[test]
    fn malformed_oversized_or_unbounded_installations_fail_closed() {
        assert_eq!(
            LocalServiceInstallation::from_reader(
                vec![0_u8; MAX_INSTALLATION_BYTES + 1].as_slice()
            )
            .unwrap_err(),
            LocalServiceInstallationError::TooLarge
        );
        for value in [
            serde_json::json!({}),
            serde_json::json!({
                "schemaVersion": 3,
                "endpoint": "/tmp/service.sock",
                "profileRoot": "/tmp/profiles",
                "servicePublicKey": "03".repeat(32),
                "serviceIdentity": {"kind": "native"},
                "profileCustody": {"kind": "native"},
                "authorizationPolicy": {
                    "version": 1,
                    "acceptedEvidence": [["account_trusted"]]
                },
                "issuers": []
            }),
        ] {
            assert_eq!(
                LocalServiceInstallation::from_reader(value.to_string().as_bytes()).unwrap_err(),
                LocalServiceInstallationError::Invalid
            );
        }
    }

    fn client_config(marker: u8) -> CopilotServiceConfig {
        CopilotServiceConfig::new(
            LocalServiceEndpoint::parse(if cfg!(windows) {
                r"\\.\pipe\konclave-local-service"
            } else {
                "/tmp/konclave/service.sock"
            })
            .unwrap(),
            IssuerKeyId::from_bytes([marker; IssuerKeyId::LENGTH]),
            IssuerKeyVersion::new(1).unwrap(),
            Ed25519PublicKey::from_bytes([marker.saturating_add(1); Ed25519PublicKey::LENGTH]),
            if cfg!(windows) {
                PathBuf::from(r"C:\Users\example\AppData\Local\Konclave\account-issuer.key")
            } else {
                PathBuf::from("/home/example/.local/share/konclave/account-issuer.key")
            },
            Some(if cfg!(windows) {
                PathBuf::from(r"C:\Program Files\Konclave\bin\konclave.exe")
            } else {
                PathBuf::from("/opt/konclave/bin/konclave")
            }),
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap()
    }
}
