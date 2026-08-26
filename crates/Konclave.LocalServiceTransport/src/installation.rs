use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use KonclaveDomainCore::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, HarnessKind, LocalServiceEndpoint,
    ProfileAuthorization, ServiceProfileId,
};

/// File name of the service-owned installation record.
pub const LOCAL_SERVICE_INSTALLATION_FILE: &str = "konclave-local-service.json";

/// File name installed beside the Copilot extension.
pub const COPILOT_SERVICE_CONFIG_FILE: &str = "konclave.service.json";

const INSTALLATION_SCHEMA_VERSION: u32 = 1;
const MAX_INSTALLATION_BYTES: usize = 64 * 1024;
const MAX_ADAPTER_REGISTRATIONS: usize = 64;
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

/// One validated adapter authorization loaded by the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledAdapterRegistration {
    adapter_key_id: AdapterKeyId,
    adapter_key_version: AdapterKeyVersion,
    registration: AdapterRegistration,
}

impl InstalledAdapterRegistration {
    /// Creates one exact adapter authorization.
    #[must_use]
    pub const fn new(
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
        registration: AdapterRegistration,
    ) -> Self {
        Self {
            adapter_key_id,
            adapter_key_version,
            registration,
        }
    }

    /// Returns the registered key identifier.
    #[must_use]
    pub const fn adapter_key_id(&self) -> AdapterKeyId {
        self.adapter_key_id
    }

    /// Returns the registered key version.
    #[must_use]
    pub const fn adapter_key_version(&self) -> AdapterKeyVersion {
        self.adapter_key_version
    }

    /// Returns the public authorization record.
    #[must_use]
    pub const fn registration(&self) -> &AdapterRegistration {
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
    adapters: Vec<InstalledAdapterRegistration>,
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
    /// oversized profile root, an empty adapter set, or too many registrations.
    pub fn new(
        endpoint: LocalServiceEndpoint,
        profile_root: PathBuf,
        service_public_key: Ed25519PublicKey,
        service_identity_source: LocalServiceIdentitySource,
        profile_custody: LocalServiceProfileCustody,
        adapters: Vec<InstalledAdapterRegistration>,
    ) -> Result<Self, LocalServiceInstallationError> {
        validate_absolute_path(&profile_root)?;
        if let LocalServiceIdentitySource::ExternalFile(path) = &service_identity_source {
            validate_absolute_path(path)?;
        }
        if let LocalServiceProfileCustody::ExternalDirectory(path) = &profile_custody {
            validate_absolute_path(path)?;
        }
        if adapters.is_empty() || adapters.len() > MAX_ADAPTER_REGISTRATIONS {
            return Err(LocalServiceInstallationError::Invalid);
        }
        let unique = adapters
            .iter()
            .map(|adapter| (adapter.adapter_key_id, adapter.adapter_key_version))
            .collect::<HashSet<_>>();
        if unique.len() != adapters.len() {
            return Err(LocalServiceInstallationError::Invalid);
        }
        if adapters
            .iter()
            .any(|adapter| adapter.registration.public_key() == service_public_key)
        {
            return Err(LocalServiceInstallationError::Invalid);
        }
        Ok(Self {
            endpoint,
            profile_root,
            service_public_key,
            service_identity_source,
            profile_custody,
            adapters,
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

    /// Returns the finite active adapter registrations.
    #[must_use]
    pub fn adapters(&self) -> &[InstalledAdapterRegistration] {
        &self.adapters
    }
}

/// Validated Copilot extension sidecar emitted from an installation.
pub struct CopilotServiceConfig {
    endpoint: LocalServiceEndpoint,
    adapter_key_id: AdapterKeyId,
    adapter_key_version: AdapterKeyVersion,
    service_public_key: Ed25519PublicKey,
    signing_key_file: PathBuf,
}

impl CopilotServiceConfig {
    /// Binds one Copilot adapter to an installed service.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceInstallationError::Invalid`] when the signing-key path
    /// is not absolute or exceeds the path bound.
    pub fn new(
        endpoint: LocalServiceEndpoint,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
        service_public_key: Ed25519PublicKey,
        signing_key_file: PathBuf,
    ) -> Result<Self, LocalServiceInstallationError> {
        validate_absolute_path(&signing_key_file)?;
        Ok(Self {
            endpoint,
            adapter_key_id,
            adapter_key_version,
            service_public_key,
            signing_key_file,
        })
    }

    /// Writes the exact sidecar consumed by the thin Copilot extension.
    ///
    /// # Errors
    ///
    /// Returns a finite encoding or output error.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), LocalServiceInstallationError> {
        serde_json::to_writer(
            &mut writer,
            &CopilotDocument {
                schema_version: INSTALLATION_SCHEMA_VERSION,
                endpoint: self.endpoint.as_str(),
                adapter_key_id: encode_hex(self.adapter_key_id.as_bytes()),
                adapter_key_version: self.adapter_key_version.get(),
                harness: "copilot",
                service_key: encode_hex(self.service_public_key.as_bytes()),
                signing_key_file: self
                    .signing_key_file
                    .to_str()
                    .ok_or(LocalServiceInstallationError::Invalid)?,
            },
        )
        .map_err(|_| LocalServiceInstallationError::Io)
    }
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
    adapters: Vec<AdapterDocument>,
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
struct AdapterDocument {
    adapter_key_id: String,
    adapter_key_version: u32,
    public_key: String,
    harness: String,
    profile_kind: String,
    profile_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CopilotDocument<'a> {
    schema_version: u32,
    endpoint: &'a str,
    adapter_key_id: String,
    adapter_key_version: u32,
    harness: &'static str,
    service_key: String,
    signing_key_file: &'a str,
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
        let adapters = document
            .adapters
            .into_iter()
            .map(InstalledAdapterRegistration::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            endpoint,
            profile_root,
            service_public_key,
            service_identity_source,
            profile_custody,
            adapters,
        )
    }
}

impl TryFrom<AdapterDocument> for InstalledAdapterRegistration {
    type Error = LocalServiceInstallationError;

    fn try_from(document: AdapterDocument) -> Result<Self, Self::Error> {
        let harness = match document.harness.as_str() {
            "copilot" => HarnessKind::Copilot,
            "claude-code" => HarnessKind::ClaudeCode,
            "codex" => HarnessKind::Codex,
            _ => return Err(LocalServiceInstallationError::Invalid),
        };
        let adapter_key_id = AdapterKeyId::from_bytes(decode_hex(&document.adapter_key_id)?);
        let adapter_key_version = AdapterKeyVersion::new(document.adapter_key_version)
            .map_err(|_| LocalServiceInstallationError::Invalid)?;
        let public_key = Ed25519PublicKey::from_bytes(decode_hex(&document.public_key)?);
        let profile = ServiceProfileId::parse(&document.profile_id)
            .map_err(|_| LocalServiceInstallationError::Invalid)?;
        let profiles = match document.profile_kind.as_str() {
            "profile" => ProfileAuthorization::Profile(profile),
            "namespace" => ProfileAuthorization::Namespace(profile),
            _ => return Err(LocalServiceInstallationError::Invalid),
        };
        Ok(Self::new(
            adapter_key_id,
            adapter_key_version,
            AdapterRegistration::new(public_key, harness, profiles),
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
            adapters: installation
                .adapters
                .iter()
                .map(|adapter| AdapterDocument {
                    adapter_key_id: encode_hex(adapter.adapter_key_id.as_bytes()),
                    adapter_key_version: adapter.adapter_key_version.get(),
                    public_key: encode_hex(adapter.registration.public_key().as_bytes()),
                    harness: match adapter.registration.harness() {
                        HarnessKind::Copilot => "copilot",
                        HarnessKind::ClaudeCode => "claude-code",
                        HarnessKind::Codex => "codex",
                    }
                    .to_string(),
                    profile_kind: match adapter.registration.profiles() {
                        ProfileAuthorization::Profile(_) => "profile",
                        ProfileAuthorization::Namespace(_) => "namespace",
                    }
                    .to_string(),
                    profile_id: match adapter.registration.profiles() {
                        ProfileAuthorization::Profile(profile)
                        | ProfileAuthorization::Namespace(profile) => profile.as_str().to_string(),
                    },
                })
                .collect(),
        }
    }
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
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LocalServiceInstallationError::Invalid);
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text =
            core::str::from_utf8(pair).map_err(|_| LocalServiceInstallationError::Invalid)?;
        decoded[index] =
            u8::from_str_radix(text, 16).map_err(|_| LocalServiceInstallationError::Invalid)?;
    }
    Ok(decoded)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
            vec![InstalledAdapterRegistration::new(
                AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH]),
                AdapterKeyVersion::new(1).unwrap(),
                AdapterRegistration::new(
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
            PathBuf::from(r"C:\Users\example\AppData\Local\Konclave\adapter.key")
        } else {
            PathBuf::from("/home/example/.local/share/konclave/adapter.key")
        };
        let adapter = &expected.adapters()[0];
        let client = CopilotServiceConfig::new(
            expected.endpoint().clone(),
            adapter.adapter_key_id(),
            adapter.adapter_key_version(),
            expected.service_public_key(),
            signing_key,
        )
        .unwrap();
        let mut client_json = Vec::new();
        client.write_to(&mut client_json).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&client_json).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["harness"], "copilot");
        assert_eq!(value["adapterKeyId"], "01".repeat(16));
        assert_eq!(value["serviceKey"], "03".repeat(32));
    }

    #[test]
    fn service_identity_cannot_be_reused_as_an_adapter_identity() {
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
                vec![InstalledAdapterRegistration::new(
                    AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH]),
                    AdapterKeyVersion::new(1).unwrap(),
                    AdapterRegistration::new(
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
                "schemaVersion": 2,
                "endpoint": "/tmp/service.sock",
                "profileRoot": "/tmp/profiles",
                "servicePublicKey": "03".repeat(32),
                "serviceIdentity": {"kind": "native"},
                "profileCustody": {"kind": "native"},
                "adapters": []
            }),
        ] {
            assert_eq!(
                LocalServiceInstallation::from_reader(value.to_string().as_bytes()).unwrap_err(),
                LocalServiceInstallationError::Invalid
            );
        }
    }
}
