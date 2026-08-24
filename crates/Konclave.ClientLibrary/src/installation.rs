use std::ffi::OsString;
use std::io::Read;
use std::io::Write as _;
use std::path::PathBuf;

use thiserror::Error;

use crate::{RelayEndpoint, RelayEnrollmentCredential};

/// Default non-secret installation configuration file under the profile root.
pub const RELAY_INSTALLATION_CONFIG_FILE: &str = "relay-installation.conf";

const MAX_INSTALLATION_CONFIG_BYTES: usize = 4 * 1024;
const MAX_INSTALLATION_ID_BYTES: usize = 64;

/// Resolves the platform-default shared profile root.
///
/// # Errors
///
/// Returns an invalid configuration error when the platform's required home or data
/// directory is unavailable.
pub fn default_profile_root() -> Result<PathBuf, RelayInstallationConfigError> {
    #[cfg(windows)]
    {
        return windows_profile_root(std::env::var_os("LOCALAPPDATA"));
    }
    #[cfg(target_os = "macos")]
    {
        return macos_profile_root(std::env::var_os("HOME"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return unix_profile_root(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"));
    }
    #[allow(unreachable_code)]
    Err(RelayInstallationConfigError::Invalid)
}

#[cfg(any(windows, test))]
fn windows_profile_root(
    local_app_data: Option<OsString>,
) -> Result<PathBuf, RelayInstallationConfigError> {
    let root = required_path(local_app_data)?;
    Ok(root.join("Konclave").join("profiles"))
}

#[cfg(any(target_os = "macos", test))]
fn macos_profile_root(home: Option<OsString>) -> Result<PathBuf, RelayInstallationConfigError> {
    let home = required_path(home)?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Konclave")
        .join("profiles"))
}

fn unix_profile_root(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, RelayInstallationConfigError> {
    if let Some(root) = optional_path(xdg_data_home) {
        return Ok(root.join("konclave").join("profiles"));
    }
    let home = required_path(home)?;
    Ok(home
        .join(".local")
        .join("share")
        .join("konclave")
        .join("profiles"))
}

fn required_path(value: Option<OsString>) -> Result<PathBuf, RelayInstallationConfigError> {
    optional_path(value).ok_or(RelayInstallationConfigError::Invalid)
}

fn optional_path(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// Protected enrollment credential source selected once for an installation.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum RelayEnrollmentSourceConfig {
    /// Operating-system credential-store entry.
    Native { installation_id: String },
    /// Explicit headless secret mount containing an endpoint-bound binary record.
    ExternalFile { path: PathBuf },
}

/// Bounded non-secret relay endpoint and enrollment-source configuration.
#[derive(Clone)]
pub struct RelayInstallationConfig {
    endpoint: RelayEndpoint,
    source: RelayEnrollmentSourceConfig,
}

impl RelayInstallationConfig {
    /// Creates one validated installation configuration.
    ///
    /// # Errors
    ///
    /// Returns an invalid configuration error for unsafe credential names or a
    /// relative/empty external source path.
    pub fn new(
        endpoint: RelayEndpoint,
        source: RelayEnrollmentSourceConfig,
    ) -> Result<Self, RelayInstallationConfigError> {
        validate_source(&source)?;
        Ok(Self { endpoint, source })
    }

    /// Reads one strict bounded installation configuration.
    ///
    /// # Errors
    ///
    /// Returns an I/O, size, syntax, endpoint, duplicate-field, or source-validation
    /// error.
    pub fn from_reader(reader: impl Read) -> Result<Self, RelayInstallationConfigError> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_INSTALLATION_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RelayInstallationConfigError::Io)?;
        if bytes.len() > MAX_INSTALLATION_CONFIG_BYTES {
            return Err(RelayInstallationConfigError::TooLarge {
                maximum: MAX_INSTALLATION_CONFIG_BYTES,
            });
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| RelayInstallationConfigError::Invalid)?;
        parse(text)
    }

    /// Returns canonical bounded bytes for durable installation configuration.
    ///
    /// # Errors
    ///
    /// Returns an invalid or oversized configuration error if this value was
    /// constructed through a future incompatible representation.
    pub fn encode(&self) -> Result<Vec<u8>, RelayInstallationConfigError> {
        validate_source(&self.source)?;
        let source = match &self.source {
            RelayEnrollmentSourceConfig::Native { installation_id } => {
                format!(
                    "version=1\nrelay_endpoint={}\nenrollment_source=native\ninstallation_id={installation_id}\n",
                    self.endpoint.as_str()
                )
            }
            RelayEnrollmentSourceConfig::ExternalFile { path } => {
                let path = path.to_str().ok_or(RelayInstallationConfigError::Invalid)?;
                format!(
                    "version=1\nrelay_endpoint={}\nenrollment_source=external_file\ncredential_path={path}\n",
                    self.endpoint.as_str()
                )
            }
        };
        if source.len() > MAX_INSTALLATION_CONFIG_BYTES {
            return Err(RelayInstallationConfigError::TooLarge {
                maximum: MAX_INSTALLATION_CONFIG_BYTES,
            });
        }
        Ok(source.into_bytes())
    }

    /// Loads an external source and verifies its exact endpoint binding.
    ///
    /// # Errors
    ///
    /// Returns an opaque credential-source error for missing, malformed, unbound, or
    /// unreadable external state. Native sources return `None` for composition by a
    /// platform keyring adapter.
    pub fn load_external_credential(
        &self,
    ) -> Result<Option<RelayEnrollmentCredential>, RelayInstallationConfigError> {
        match &self.source {
            RelayEnrollmentSourceConfig::Native { .. } => Ok(None),
            RelayEnrollmentSourceConfig::ExternalFile { path } => {
                let file = open_secure_external(path)?;
                RelayEnrollmentCredential::from_bound_reader(file, &self.endpoint)
                    .map(Some)
                    .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)
            }
        }
    }

    /// Creates one endpoint-bound external credential record without replacement.
    ///
    /// Unix creation uses a no-follow exclusive handle with owner-only permissions.
    /// Platforms without a verifiable owner-only implementation fail closed.
    ///
    /// # Errors
    ///
    /// Returns an opaque credential-source error for an unsupported platform, an
    /// existing path, unsafe file metadata, or write/sync failure.
    pub fn create_external_credential(
        &self,
        credential: &RelayEnrollmentCredential,
    ) -> Result<(), RelayInstallationConfigError> {
        let RelayEnrollmentSourceConfig::ExternalFile { path } = &self.source else {
            return Err(RelayInstallationConfigError::Invalid);
        };
        let record = credential
            .encode_bound(&self.endpoint)
            .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)?;
        create_secure_external(path, &record)
    }

    /// Returns the normalized enrollment and data-plane endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &RelayEndpoint {
        &self.endpoint
    }

    /// Returns the explicitly selected protected credential source.
    #[must_use]
    pub const fn source(&self) -> &RelayEnrollmentSourceConfig {
        &self.source
    }
}

/// Stable failures from non-secret installation configuration handling.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayInstallationConfigError {
    /// The bounded configuration could not be read.
    #[error("relay installation configuration could not be read")]
    Io,
    /// The configuration exceeded its hard byte bound.
    #[error("relay installation configuration exceeds {maximum} bytes")]
    TooLarge { maximum: usize },
    /// The configuration is malformed, ambiguous, or unsafe.
    #[error("relay installation configuration is invalid")]
    Invalid,
    /// The selected protected credential source is unavailable or invalid.
    #[error("relay installation credential is unavailable")]
    CredentialUnavailable,
}

impl RelayInstallationConfigError {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io => "relay_installation_config_io",
            Self::TooLarge { .. } => "relay_installation_config_too_large",
            Self::Invalid => "relay_installation_config_invalid",
            Self::CredentialUnavailable => "relay_installation_credential_unavailable",
        }
    }
}

fn parse(text: &str) -> Result<RelayInstallationConfig, RelayInstallationConfigError> {
    let mut version = None;
    let mut endpoint = None;
    let mut source = None;
    let mut installation_id = None;
    let mut credential_path = None;
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            return Err(RelayInstallationConfigError::Invalid);
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(RelayInstallationConfigError::Invalid)?;
        if value.is_empty() {
            return Err(RelayInstallationConfigError::Invalid);
        }
        let slot = match key {
            "version" => &mut version,
            "relay_endpoint" => &mut endpoint,
            "enrollment_source" => &mut source,
            "installation_id" => &mut installation_id,
            "credential_path" => &mut credential_path,
            _ => return Err(RelayInstallationConfigError::Invalid),
        };
        if slot.replace(value).is_some() {
            return Err(RelayInstallationConfigError::Invalid);
        }
    }
    if version != Some("1") {
        return Err(RelayInstallationConfigError::Invalid);
    }
    let endpoint = RelayEndpoint::parse(endpoint.ok_or(RelayInstallationConfigError::Invalid)?)
        .map_err(|_| RelayInstallationConfigError::Invalid)?;
    let source = match source {
        Some("native") if credential_path.is_none() => RelayEnrollmentSourceConfig::Native {
            installation_id: installation_id
                .ok_or(RelayInstallationConfigError::Invalid)?
                .to_string(),
        },
        Some("external_file") if installation_id.is_none() => {
            RelayEnrollmentSourceConfig::ExternalFile {
                path: PathBuf::from(credential_path.ok_or(RelayInstallationConfigError::Invalid)?),
            }
        }
        _ => return Err(RelayInstallationConfigError::Invalid),
    };
    RelayInstallationConfig::new(endpoint, source)
}

fn validate_source(
    source: &RelayEnrollmentSourceConfig,
) -> Result<(), RelayInstallationConfigError> {
    validate_source_for_platform(source, cfg!(unix))
}

fn validate_source_for_platform(
    source: &RelayEnrollmentSourceConfig,
    supports_external_files: bool,
) -> Result<(), RelayInstallationConfigError> {
    match source {
        RelayEnrollmentSourceConfig::Native { installation_id } => {
            if installation_id.is_empty()
                || installation_id.len() > MAX_INSTALLATION_ID_BYTES
                || !installation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(RelayInstallationConfigError::Invalid);
            }
        }
        RelayEnrollmentSourceConfig::ExternalFile { path } => {
            let Some(path_text) = path.to_str() else {
                return Err(RelayInstallationConfigError::Invalid);
            };
            if !path.is_absolute()
                || path_text.is_empty()
                || path_text
                    .bytes()
                    .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
            {
                return Err(RelayInstallationConfigError::Invalid);
            }
            if !supports_external_files {
                return Err(RelayInstallationConfigError::Invalid);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_secure_external(
    path: &std::path::Path,
) -> Result<std::fs::File, RelayInstallationConfigError> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)?;
    let file = std::fs::File::from(descriptor);
    validate_secure_external(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_secure_external(file: &std::fs::File) -> Result<(), RelayInstallationConfigError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o400 == 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(RelayInstallationConfigError::CredentialUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_secure_external(
    _path: &std::path::Path,
) -> Result<std::fs::File, RelayInstallationConfigError> {
    Err(RelayInstallationConfigError::CredentialUnavailable)
}

#[cfg(unix)]
fn create_secure_external(
    path: &std::path::Path,
    record: &[u8],
) -> Result<(), RelayInstallationConfigError> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)?;
    let mut file = std::fs::File::from(descriptor);
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR)
        .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)?;
    validate_secure_external(&file)?;
    file.write_all(record)
        .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)?;
    file.sync_all()
        .map_err(|_| RelayInstallationConfigError::CredentialUnavailable)
}

#[cfg(not(unix))]
fn create_secure_external(
    _path: &std::path::Path,
    _record: &[u8],
) -> Result<(), RelayInstallationConfigError> {
    Err(RelayInstallationConfigError::CredentialUnavailable)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn platform_profile_roots_follow_native_conventions() {
        let base = PathBuf::from("/user-data");
        assert_eq!(
            windows_profile_root(Some(base.clone().into_os_string())).unwrap(),
            base.join("Konclave").join("profiles")
        );
        assert_eq!(
            macos_profile_root(Some(base.clone().into_os_string())).unwrap(),
            base.join("Library")
                .join("Application Support")
                .join("Konclave")
                .join("profiles")
        );
        assert_eq!(
            unix_profile_root(Some(base.clone().into_os_string()), None).unwrap(),
            base.join("konclave").join("profiles")
        );
        assert_eq!(
            unix_profile_root(None, Some(base.clone().into_os_string())).unwrap(),
            base.join(".local")
                .join("share")
                .join("konclave")
                .join("profiles")
        );
        assert!(windows_profile_root(None).is_err());
        assert!(macos_profile_root(Some(OsString::new())).is_err());
        assert!(unix_profile_root(Some(OsString::new()), None).is_err());
    }

    #[test]
    fn native_config_round_trips_canonically() {
        let config = RelayInstallationConfig::new(
            RelayEndpoint::parse("https://relay.example.com/base").unwrap(),
            RelayEnrollmentSourceConfig::Native {
                installation_id: "installation-a".to_string(),
            },
        )
        .unwrap();
        let encoded = config.encode().unwrap();
        let decoded = RelayInstallationConfig::from_reader(Cursor::new(&encoded)).unwrap();
        assert_eq!(decoded.endpoint().as_str(), config.endpoint().as_str());
        assert!(matches!(
            decoded.source(),
            RelayEnrollmentSourceConfig::Native { installation_id }
                if installation_id == "installation-a"
        ));
    }

    #[test]
    fn external_sources_fail_closed_on_unsupported_platforms() {
        let source = RelayEnrollmentSourceConfig::ExternalFile {
            path: PathBuf::from("/protected/enrollment.credential"),
        };
        assert!(validate_source_for_platform(&source, true).is_ok());
        assert!(validate_source_for_platform(&source, false).is_err());
    }

    #[test]
    fn parser_rejects_ambiguity_relative_paths_and_oversize() {
        for invalid in [
            "version=1\nrelay_endpoint=https://relay.example.com\nenrollment_source=native\n",
            "version=1\nversion=1\nrelay_endpoint=https://relay.example.com\nenrollment_source=native\ninstallation_id=name\n",
            "version=1\nrelay_endpoint=http://relay.example.com\nenrollment_source=native\ninstallation_id=name\n",
            "version=1\nrelay_endpoint=https://relay.example.com\nenrollment_source=external_file\ncredential_path=relative\n",
            "version=2\nrelay_endpoint=https://relay.example.com\nenrollment_source=native\ninstallation_id=name\n",
        ] {
            assert!(RelayInstallationConfig::from_reader(Cursor::new(invalid)).is_err());
        }
        assert!(matches!(
            RelayInstallationConfig::from_reader(Cursor::new(vec![
                b'x';
                MAX_INSTALLATION_CONFIG_BYTES
                    + 1
            ])),
            Err(RelayInstallationConfigError::TooLarge { .. })
        ));

        #[cfg(unix)]
        {
            let external = RelayInstallationConfig::new(
                RelayEndpoint::parse("https://relay.example.com").unwrap(),
                RelayEnrollmentSourceConfig::ExternalFile {
                    path: std::env::temp_dir().join("konclave-enrollment.credential"),
                },
            )
            .unwrap();
            let encoded = external.encode().unwrap();
            assert!(matches!(
                RelayInstallationConfig::from_reader(Cursor::new(encoded))
                    .unwrap()
                    .source(),
                RelayEnrollmentSourceConfig::ExternalFile { .. }
            ));
            assert!(
                RelayInstallationConfig::new(
                    RelayEndpoint::parse("https://relay.example.com").unwrap(),
                    RelayEnrollmentSourceConfig::ExternalFile {
                        path: std::env::temp_dir().join("invalid\npath"),
                    },
                )
                .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn external_credentials_reject_unsafe_files_and_endpoint_rebinding() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("enrollment.credential");
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let config = RelayInstallationConfig::new(
            endpoint,
            RelayEnrollmentSourceConfig::ExternalFile { path: path.clone() },
        )
        .unwrap();
        let credential = RelayEnrollmentCredential::from_bytes([7; 32]);

        config.create_external_credential(&credential).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            config
                .load_external_credential()
                .unwrap()
                .unwrap()
                .authority_id(),
            credential.authority_id()
        );

        let original = std::fs::read(&path).unwrap();
        assert!(config.create_external_credential(&credential).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let rebound = RelayInstallationConfig::new(
            RelayEndpoint::parse("https://other.example.com").unwrap(),
            RelayEnrollmentSourceConfig::ExternalFile { path: path.clone() },
        )
        .unwrap();
        assert!(rebound.load_external_credential().is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(config.load_external_credential().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let hard_link = directory.path().join("enrollment.hard-link");
        std::fs::hard_link(&path, &hard_link).unwrap();
        assert!(config.load_external_credential().is_err());
        std::fs::remove_file(hard_link).unwrap();

        let symbolic_link = directory.path().join("enrollment.symbolic-link");
        symlink(&path, &symbolic_link).unwrap();
        let linked = RelayInstallationConfig::new(
            RelayEndpoint::parse("https://relay.example.com").unwrap(),
            RelayEnrollmentSourceConfig::ExternalFile {
                path: symbolic_link,
            },
        )
        .unwrap();
        assert!(linked.load_external_credential().is_err());
        assert!(linked.create_external_credential(&credential).is_err());
    }
}
