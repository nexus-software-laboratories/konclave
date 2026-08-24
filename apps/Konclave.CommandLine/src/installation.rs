use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
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
    let mut temporary = tempfile::NamedTempFile::new_in(root)
        .with_context(|| format!("creating temporary config in {}", root.display()))?;
    temporary
        .write_all(&bytes)
        .context("writing relay installation configuration")?;
    temporary
        .as_file()
        .sync_all()
        .context("syncing relay installation configuration")?;
    let destination = root.join(RELAY_INSTALLATION_CONFIG_FILE);
    match temporary.persist_noclobber(&destination) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = load(root)?
                .ok_or_else(|| anyhow::anyhow!("relay installation configuration raced"))?;
            if matches(&existing, config) {
                Ok(())
            } else {
                bail!("relay installation configuration raced with different values")
            }
        }
        Err(error) => {
            Err(error.error).with_context(|| format!("persisting {}", destination.display()))
        }
    }
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
    }
}
