use std::path::{Path, PathBuf};

use anyhow::Context as _;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;
use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, CopilotServiceConfig, HarnessKind,
    InstalledAdapterRegistration, LocalServiceEndpoint, LocalServiceIdentitySource,
    LocalServiceInstallation, LocalServiceProfileCustody, ProfileAuthorization, ServiceProfileId,
    COPILOT_SERVICE_CONFIG_FILE, LOCAL_SERVICE_INSTALLATION_FILE,
};
use KonclaveSecretStorage::{
    create_or_verify_owner_protected_file, ensure_owner_protected_directory,
    open_owner_protected_file, NativeLocalServiceIdentityStore, SecretStorageError,
};

const ADAPTER_KEY_FILE: &str = "copilot-adapter.key";
const SERVICE_DIRECTORY: &str = "service";
const COPILOT_PROFILE_NAMESPACE: &str = "session";

pub(crate) struct InstalledLocalService {
    pub(crate) extension_root: PathBuf,
}

pub(crate) fn install(
    profile_root: &Path,
    extension_root: Option<PathBuf>,
    endpoint_override: Option<&str>,
    service_identity_file: Option<PathBuf>,
    profile_key_directory: Option<PathBuf>,
) -> anyhow::Result<InstalledLocalService> {
    install_with(
        &NativeServiceIdentityStore,
        profile_root,
        extension_root,
        endpoint_override,
        service_identity_file,
        profile_key_directory,
    )
}

trait ServiceIdentityStore {
    fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecretStorageError>;
    fn store(&self, secret: &[u8]) -> Result<(), SecretStorageError>;
}

struct NativeServiceIdentityStore;

impl ServiceIdentityStore for NativeServiceIdentityStore {
    fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
        NativeLocalServiceIdentityStore.load()
    }

    fn store(&self, secret: &[u8]) -> Result<(), SecretStorageError> {
        NativeLocalServiceIdentityStore.store(secret)
    }
}

fn install_with(
    identity_store: &impl ServiceIdentityStore,
    profile_root: &Path,
    extension_root: Option<PathBuf>,
    endpoint_override: Option<&str>,
    service_identity_file: Option<PathBuf>,
    profile_key_directory: Option<PathBuf>,
) -> anyhow::Result<InstalledLocalService> {
    let service_root = profile_root
        .parent()
        .context("profile root has no installation parent")?
        .join(SERVICE_DIRECTORY);
    ensure_owner_protected_directory(&service_root)
        .context("creating owner-protected local-service state")?;

    let (service_seed, service_identity_source) = match service_identity_file {
        Some(path) => {
            let path = absolute_path(path)?;
            let parent = path
                .parent()
                .context("service identity path has no parent")?;
            ensure_owner_protected_directory(parent)
                .context("creating owner-protected service identity parent")?;
            (
                load_or_create_file_seed(&path)?,
                LocalServiceIdentitySource::ExternalFile(path),
            )
        }
        None => (
            load_or_create_service_seed(identity_store)?,
            LocalServiceIdentitySource::Native,
        ),
    };
    let service_identity = LocalServiceIdentity::from_signing_seed(&service_seed)
        .context("loading local-service identity")?;
    let profile_custody = match profile_key_directory {
        Some(path) => {
            let path = absolute_path(path)?;
            ensure_owner_protected_directory(&path)
                .context("creating owner-protected profile key directory")?;
            LocalServiceProfileCustody::ExternalDirectory(path)
        }
        None => LocalServiceProfileCustody::Native,
    };
    let adapter_key_file = service_root.join(ADAPTER_KEY_FILE);
    let adapter_seed = load_or_create_file_seed(&adapter_key_file)?;
    let adapter_identity = LocalServiceIdentity::from_signing_seed(&adapter_seed)
        .context("loading Copilot adapter identity")?;
    let adapter_key_id = adapter_key_id(adapter_identity.public_key());
    let endpoint = match endpoint_override {
        Some(endpoint) => {
            LocalServiceEndpoint::parse(endpoint).context("validating local-service endpoint")?
        }
        None => default_endpoint(&service_root, service_identity.public_key())?,
    };
    let adapter_key_version =
        AdapterKeyVersion::new(1).map_err(|_| anyhow::anyhow!("adapter key version is invalid"))?;
    let installation = LocalServiceInstallation::new(
        endpoint.clone(),
        profile_root.to_path_buf(),
        service_identity.public_key(),
        service_identity_source,
        profile_custody,
        vec![InstalledAdapterRegistration::new(
            adapter_key_id,
            adapter_key_version,
            AdapterRegistration::new(
                adapter_identity.public_key(),
                HarnessKind::Copilot,
                ProfileAuthorization::Namespace(
                    ServiceProfileId::parse(COPILOT_PROFILE_NAMESPACE)
                        .context("validating Copilot profile namespace")?,
                ),
            ),
        )],
    )
    .context("building local-service installation")?;
    let mut service_config = Vec::new();
    installation
        .write_to(&mut service_config)
        .context("encoding local-service installation")?;
    create_or_verify_owner_protected_file(
        &service_root.join(LOCAL_SERVICE_INSTALLATION_FILE),
        &service_config,
    )
    .context("persisting local-service installation")?;

    let extension_root = extension_root.map_or_else(default_extension_root, absolute_path)?;
    ensure_owner_protected_directory(&extension_root)
        .context("creating owner-protected Copilot extension root")?;
    let client = CopilotServiceConfig::new(
        endpoint,
        adapter_key_id,
        adapter_key_version,
        service_identity.public_key(),
        adapter_key_file,
    )
    .context("building Copilot local-service configuration")?;
    let mut client_config = Vec::new();
    client
        .write_to(&mut client_config)
        .context("encoding Copilot local-service configuration")?;
    create_or_verify_owner_protected_file(
        &extension_root.join(COPILOT_SERVICE_CONFIG_FILE),
        &client_config,
    )
    .context("persisting Copilot local-service configuration")?;

    Ok(InstalledLocalService { extension_root })
}

fn load_or_create_service_seed(
    store: &impl ServiceIdentityStore,
) -> anyhow::Result<LocalServiceSigningSeed> {
    match store.load() {
        Ok(seed) => LocalServiceSigningSeed::from_reader(seed.as_slice())
            .context("validating native local-service identity"),
        Err(SecretStorageError::NativeCredentialNotFound) => {
            let seed =
                LocalServiceSigningSeed::generate().context("generating local-service identity")?;
            let mut encoded = Zeroizing::new(Vec::new());
            seed.write_to(&mut *encoded)
                .context("encoding local-service identity")?;
            store
                .store(encoded.as_slice())
                .context("storing native local-service identity")?;
            Ok(seed)
        }
        Err(error) => Err(error).context("loading native local-service identity"),
    }
}

fn load_or_create_file_seed(path: &Path) -> anyhow::Result<LocalServiceSigningSeed> {
    match open_owner_protected_file(path) {
        Ok(file) => LocalServiceSigningSeed::from_reader(file)
            .context("validating Copilot adapter signing key"),
        Err(SecretStorageError::OwnerProtectedStorageUnavailable) if !path.exists() => {
            let candidate = LocalServiceSigningSeed::generate()
                .context("generating Copilot adapter signing key")?;
            let mut encoded = Zeroizing::new(Vec::new());
            candidate
                .write_to(&mut *encoded)
                .context("encoding Copilot adapter signing key")?;
            match create_or_verify_owner_protected_file(path, encoded.as_slice()) {
                Ok(()) => Ok(candidate),
                Err(SecretStorageError::OwnerProtectedStorageConflict) => {
                    let file = open_owner_protected_file(path)
                        .context("opening concurrently created Copilot adapter key")?;
                    LocalServiceSigningSeed::from_reader(file)
                        .context("validating concurrently created Copilot adapter key")
                }
                Err(error) => Err(error).context("creating Copilot adapter signing key"),
            }
        }
        Err(error) => Err(error).context("opening Copilot adapter signing key"),
    }
}

fn adapter_key_id(public_key: Ed25519PublicKey) -> AdapterKeyId {
    let mut digest = Sha256::new();
    digest.update(b"konclave:copilot-adapter-key-id:1\0");
    digest.update(public_key.as_bytes());
    let digest = digest.finalize();
    let mut identifier = [0_u8; AdapterKeyId::LENGTH];
    identifier.copy_from_slice(&digest[..AdapterKeyId::LENGTH]);
    AdapterKeyId::from_bytes(identifier)
}

#[cfg(windows)]
fn default_endpoint(
    _service_root: &Path,
    public_key: Ed25519PublicKey,
) -> anyhow::Result<LocalServiceEndpoint> {
    let suffix = encode_hex(&public_key.as_bytes()[..12]);
    LocalServiceEndpoint::parse(&format!(r"\\.\pipe\konclave-{suffix}"))
        .context("building Windows local-service endpoint")
}

#[cfg(unix)]
fn default_endpoint(
    service_root: &Path,
    _public_key: Ed25519PublicKey,
) -> anyhow::Result<LocalServiceEndpoint> {
    let endpoint = service_root.join("konclave.sock");
    LocalServiceEndpoint::parse(
        endpoint
            .to_str()
            .context("local-service endpoint path is not Unicode")?,
    )
    .context("building Unix local-service endpoint")
}

fn default_extension_root() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|value| !value.is_empty())
        .context("user home is unavailable")?;
    Ok(PathBuf::from(home)
        .join(".copilot")
        .join("extensions")
        .join("konclave"))
}

fn absolute_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(any(windows, test))]
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
    use std::cell::RefCell;

    use KonclaveLocalServiceTransport::LocalServiceInstallation;

    use super::*;

    #[derive(Default)]
    struct MemoryIdentityStore {
        value: RefCell<Option<Vec<u8>>>,
    }

    impl ServiceIdentityStore for MemoryIdentityStore {
        fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
            self.value
                .borrow()
                .clone()
                .map(Zeroizing::new)
                .ok_or(SecretStorageError::NativeCredentialNotFound)
        }

        fn store(&self, secret: &[u8]) -> Result<(), SecretStorageError> {
            let mut value = self.value.borrow_mut();
            match value.as_ref() {
                Some(existing) if existing == secret => Ok(()),
                Some(_) => Err(SecretStorageError::InvalidNativeCredential),
                None => {
                    *value = Some(secret.to_vec());
                    Ok(())
                }
            }
        }
    }

    #[test]
    fn repeated_install_is_exact_and_conflicting_endpoint_fails() {
        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        let extension_root = root.path().join("extension");
        std::fs::create_dir(&profile_root).unwrap();
        let endpoint = root.path().join("service.sock");
        let endpoint = endpoint.to_str().unwrap();
        let profile_keys = root.path().join("profile-keys");
        let store = MemoryIdentityStore::default();

        install_with(
            &store,
            &profile_root,
            Some(extension_root.clone()),
            Some(endpoint),
            None,
            Some(profile_keys.clone()),
        )
        .unwrap();
        let service_path = root
            .path()
            .join(SERVICE_DIRECTORY)
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let first_service = std::fs::read(&service_path).unwrap();
        let first_adapter =
            std::fs::read(root.path().join(SERVICE_DIRECTORY).join(ADAPTER_KEY_FILE)).unwrap();
        install_with(
            &store,
            &profile_root,
            Some(extension_root.clone()),
            Some(endpoint),
            None,
            Some(profile_keys.clone()),
        )
        .unwrap();
        assert_eq!(std::fs::read(&service_path).unwrap(), first_service);
        assert_eq!(
            std::fs::read(root.path().join(SERVICE_DIRECTORY).join(ADAPTER_KEY_FILE)).unwrap(),
            first_adapter
        );

        let installation = LocalServiceInstallation::from_reader(first_service.as_slice()).unwrap();
        assert_eq!(installation.profile_root(), profile_root);
        assert_eq!(installation.adapters().len(), 1);
        assert_eq!(
            installation.profile_custody(),
            &LocalServiceProfileCustody::ExternalDirectory(profile_keys)
        );
        assert!(installation.adapters()[0]
            .registration()
            .profiles()
            .permits(&ServiceProfileId::parse("session-example").unwrap()));
        let client: serde_json::Value = serde_json::from_slice(
            &std::fs::read(extension_root.join(COPILOT_SERVICE_CONFIG_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            client["serviceKey"],
            encode_hex(installation.service_public_key().as_bytes())
        );
        assert_eq!(
            client["signingKeyFile"],
            root.path()
                .join(SERVICE_DIRECTORY)
                .join(ADAPTER_KEY_FILE)
                .to_str()
                .unwrap()
        );

        let conflict = root.path().join("other.sock");
        assert!(install_with(
            &store,
            &profile_root,
            Some(extension_root),
            conflict.to_str(),
            None,
            Some(root.path().join("profile-keys")),
        )
        .is_err());
        assert_eq!(std::fs::read(service_path).unwrap(), first_service);
    }
}
