use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use KonclaveClientLibrary::{
    default_profile_root, RelayEnrollmentCredential, RelayEnrollmentSourceConfig,
    RelayInstallationConfig, RELAY_INSTALLATION_CONFIG_FILE,
};
use KonclaveSecretStorage::NativeEnrollmentCredentialStore;

pub(crate) fn resolve_profile_root(root: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let root = root.map_or_else(
        || default_profile_root().context("resolving default profile root"),
        |root| {
            if root.is_absolute() {
                Ok(root)
            } else {
                Ok(std::env::current_dir()?.join(root))
            }
        },
    )?;
    if root.is_absolute() {
        Ok(root)
    } else {
        bail!("profile root must resolve to an absolute path")
    }
}

pub(crate) fn load(root: &Path) -> anyhow::Result<Option<RelayInstallationConfig>> {
    let path = root.join(RELAY_INSTALLATION_CONFIG_FILE);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("opening {}", path.display()));
        }
    };
    RelayInstallationConfig::from_reader(file)
        .with_context(|| format!("reading {}", path.display()))
        .map(Some)
}

pub(crate) fn matches(left: &RelayInstallationConfig, right: &RelayInstallationConfig) -> bool {
    left.endpoint().as_str() == right.endpoint().as_str() && left.source() == right.source()
}

pub(crate) fn require_existing_match(
    existing: &RelayInstallationConfig,
    endpoint: &KonclaveClientLibrary::RelayEndpoint,
    external_source: Option<&Path>,
) -> anyhow::Result<()> {
    if existing.endpoint().as_str() != endpoint.as_str() {
        bail!("relay installation already targets another endpoint");
    }
    match (existing.source(), external_source) {
        (RelayEnrollmentSourceConfig::ExternalFile { path }, Some(requested))
            if path == requested =>
        {
            Ok(())
        }
        (RelayEnrollmentSourceConfig::Native { .. }, None) => Ok(()),
        _ => bail!("relay installation already uses another protected source"),
    }
}

pub(crate) fn load_credential(
    config: &RelayInstallationConfig,
) -> anyhow::Result<RelayEnrollmentCredential> {
    if let Some(credential) = config
        .load_external_credential()
        .context("loading endpoint-bound external enrollment credential")?
    {
        return Ok(credential);
    }
    let RelayEnrollmentSourceConfig::Native { installation_id } = config.source() else {
        bail!("relay enrollment source is unsupported");
    };
    let record = NativeEnrollmentCredentialStore::new(installation_id.clone())
        .context("validating enrollment installation identifier")?
        .load()
        .context("loading native enrollment credential")?;
    RelayEnrollmentCredential::from_bound_reader(record.as_slice(), config.endpoint())
        .context("validating native enrollment credential")
}

pub(crate) fn native_installation_id(
    credential: &RelayEnrollmentCredential,
    endpoint: &KonclaveClientLibrary::RelayEndpoint,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"konclave:relay-enrollment-installation:1\0");
    digest.update(credential.authority_id().as_bytes());
    digest.update(endpoint.as_str().as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

pub(crate) fn write_exact(root: &Path, config: &RelayInstallationConfig) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)
        .with_context(|| format!("creating profile root {}", root.display()))?;
    if let Some(existing) = load(root)? {
        if matches(&existing, config) {
            return Ok(());
        }
        bail!("relay installation configuration already exists with different values");
    }
    let bytes = config
        .encode()
        .context("encoding relay installation configuration")?;
    write_exact_file(
        &root.join(RELAY_INSTALLATION_CONFIG_FILE),
        &bytes,
        "relay installation configuration",
    )
}

pub(crate) fn write_exact_file(
    destination: &Path,
    bytes: &[u8],
    description: &'static str,
) -> anyhow::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{description} path has no parent"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating {description} parent {}", parent.display()))?;
    if existing_file_matches(destination, bytes)? {
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary {description} in {}", parent.display()))?;
    temporary
        .write_all(bytes)
        .with_context(|| format!("writing {description}"))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("syncing {description}"))?;
    match temporary.persist_noclobber(destination) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            if existing_file_matches(destination, bytes)? {
                Ok(())
            } else {
                bail!("{description} already exists with different bytes")
            }
        }
        Err(error) => {
            Err(error.error).with_context(|| format!("persisting {}", destination.display()))
        }
    }
}

fn existing_file_matches(path: &Path, expected: &[u8]) -> anyhow::Result<bool> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
    };
    let maximum = expected
        .len()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("expected file length overflow"))?;
    let mut actual = Vec::with_capacity(maximum);
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64)
        .read_to_end(&mut actual)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(actual == expected)
}

pub(crate) fn source_label(source: &RelayEnrollmentSourceConfig) -> &'static str {
    match source {
        RelayEnrollmentSourceConfig::Native { .. } => "native",
        RelayEnrollmentSourceConfig::ExternalFile { .. } => "external_file",
        _ => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use KonclaveClientLibrary::{RelayEndpoint, RelayEnrollmentSourceConfig};

    use super::*;

    #[test]
    fn exact_write_is_idempotent_and_conflicts_fail() {
        let root = tempfile::tempdir().unwrap();
        let first = RelayInstallationConfig::new(
            RelayEndpoint::parse("https://relay.example.com").unwrap(),
            RelayEnrollmentSourceConfig::Native {
                installation_id: "installation-a".to_string(),
            },
        )
        .unwrap();
        write_exact(root.path(), &first).unwrap();
        write_exact(root.path(), &first).unwrap();
        let second = RelayInstallationConfig::new(
            RelayEndpoint::parse("https://other.example.com").unwrap(),
            RelayEnrollmentSourceConfig::Native {
                installation_id: "installation-a".to_string(),
            },
        )
        .unwrap();
        assert!(write_exact(root.path(), &second).is_err());

        let exact = root.path().join("exact.json");
        write_exact_file(&exact, b"same", "test record").unwrap();
        write_exact_file(&exact, b"same", "test record").unwrap();
        assert!(write_exact_file(&exact, b"different", "test record").is_err());
    }
}
