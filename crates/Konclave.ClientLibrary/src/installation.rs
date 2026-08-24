use std::io::Read;
use std::path::PathBuf;

use thiserror::Error;

use crate::RelayEndpoint;

/// Default non-secret installation configuration file under the profile root.
pub const RELAY_INSTALLATION_CONFIG_FILE: &str = "relay-installation.conf";

const MAX_INSTALLATION_CONFIG_BYTES: usize = 4 * 1024;
const MAX_INSTALLATION_ID_BYTES: usize = 64;

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
}

impl RelayInstallationConfigError {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io => "relay_installation_config_io",
            Self::TooLarge { .. } => "relay_installation_config_too_large",
            Self::Invalid => "relay_installation_config_invalid",
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
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

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
