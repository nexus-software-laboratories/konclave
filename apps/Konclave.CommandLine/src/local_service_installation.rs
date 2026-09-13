use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;
use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalAuthorizationStore::{
    installation_fingerprint, LocalAuthorizationStore, UserPresenceCredentialRecord,
};
use KonclaveLocalServiceTransport::{
    default_client_runtime_config_path, reconcile_client_runtime_config,
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    ClientRuntimeConfigAction, CopilotServiceConfig, HarnessKind, InstalledIssuerRegistration,
    IssuerKeyId, IssuerKeyVersion, IssuerRegistration, LocalServiceEndpoint,
    LocalServiceIdentitySource, LocalServiceInstallation, LocalServiceProfileCustody,
    ProfileAuthorization, COPILOT_SERVICE_CONFIG_FILE, LOCAL_SERVICE_INSTALLATION_FILE,
};
use KonclaveSecretStorage::{
    create_or_verify_owner_protected_file, ensure_owner_protected_directory,
    open_owner_protected_file, NativeLocalServiceIdentityStore, SecretStorageError,
};
use KonclaveUserPresence::{
    perform_native_authentication, perform_native_registration, UserPresenceWebAuthnVerifier,
};

#[cfg(any(windows, test))]
use crate::encoding::encode_hex;
#[cfg(test)]
use KonclaveLocalAuthorizationStore::authorization_store_path;

const ACCOUNT_ISSUER_KEY_FILE: &str = "account-issuer.key";
const SERVICE_DIRECTORY: &str = "service";

pub(crate) struct InstalledLocalService {
    pub(crate) client_config_path: PathBuf,
}

pub(crate) fn install(
    profile_root: &Path,
    legacy_extension_root: Option<PathBuf>,
    client_config_path: Option<PathBuf>,
    endpoint_override: Option<&str>,
    service_identity_file: Option<PathBuf>,
    profile_key_directory: Option<PathBuf>,
    authorization_policy: AuthorizationPolicy,
) -> anyhow::Result<InstalledLocalService> {
    let client_config_path = match client_config_path {
        Some(path) => require_absolute_path(path, "client configuration path")?,
        None => default_client_runtime_config_path()
            .context("resolving canonical client configuration path")?,
    };
    let legacy_extension_root = match legacy_extension_root {
        Some(path) => Some(absolute_path(path)?),
        None => default_legacy_extension_root(),
    };
    install_with(
        &NativeServiceIdentityStore,
        LocalServiceInstallRequest {
            profile_root,
            legacy_extension_root,
            client_config_path,
            endpoint_override,
            service_identity_file,
            profile_key_directory,
        },
        authorization_policy,
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

struct LocalServiceInstallRequest<'a> {
    profile_root: &'a Path,
    legacy_extension_root: Option<PathBuf>,
    client_config_path: PathBuf,
    endpoint_override: Option<&'a str>,
    service_identity_file: Option<PathBuf>,
    profile_key_directory: Option<PathBuf>,
}

fn install_with(
    identity_store: &impl ServiceIdentityStore,
    request: LocalServiceInstallRequest<'_>,
    authorization_policy: AuthorizationPolicy,
) -> anyhow::Result<InstalledLocalService> {
    let LocalServiceInstallRequest {
        profile_root,
        legacy_extension_root,
        client_config_path,
        endpoint_override,
        service_identity_file,
        profile_key_directory,
    } = request;
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
    let issuer_key_file = service_root.join(ACCOUNT_ISSUER_KEY_FILE);
    let issuer_seed = load_or_create_file_seed(&issuer_key_file)?;
    let issuer_identity = LocalServiceIdentity::from_signing_seed(&issuer_seed)
        .context("loading AccountTrusted issuer identity")?;
    let issuer_key_id = account_issuer_key_id(issuer_identity.public_key());
    let endpoint = match endpoint_override {
        Some(endpoint) => {
            LocalServiceEndpoint::parse(endpoint).context("validating local-service endpoint")?
        }
        None => default_endpoint(&service_root, service_identity.public_key())?,
    };
    let issuer_key_version =
        IssuerKeyVersion::new(1).map_err(|_| anyhow::anyhow!("issuer key version is invalid"))?;
    let issuers = vec![InstalledIssuerRegistration::new(
        issuer_key_id,
        issuer_key_version,
        IssuerRegistration::new(
            issuer_identity.public_key(),
            HarnessKind::Generic,
            ProfileAuthorization::All,
        ),
    )];
    let installation = LocalServiceInstallation::new(
        endpoint.clone(),
        profile_root.to_path_buf(),
        service_identity.public_key(),
        service_identity_source,
        profile_custody,
        authorization_policy.clone(),
        issuers.clone(),
    )
    .context("building local-service installation")?;
    let installation_path = service_root.join(LOCAL_SERVICE_INSTALLATION_FILE);
    let fingerprint = installation_fingerprint(&installation)
        .context("binding durable authorization state to the installation")?;
    let user_presence_required = policy_requires_user_presence(&authorization_policy);
    let now_unix_milliseconds = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("reading system time")?
            .as_millis(),
    )
    .context("converting system time")?;
    let authorization = LocalAuthorizationStore::bootstrap(
        &installation_path,
        fingerprint,
        &authorization_policy,
        &issuers,
        now_unix_milliseconds,
    )
    .context("bootstrapping durable local authorization state")?;
    if user_presence_required
        && authorization
            .load_snapshot(now_unix_milliseconds, None)
            .context("loading user-presence enrollment state")?
            .user_presence_credential()
            .is_none()
    {
        let credential = enroll_user_presence(*fingerprint.as_bytes(), now_unix_milliseconds)?;
        authorization
            .register_user_presence_credential(&credential, now_unix_milliseconds)
            .context("persisting user-presence credential")?;
    }
    drop(authorization);
    let mut service_config = Vec::new();
    installation
        .write_to(&mut service_config)
        .context("encoding local-service installation")?;
    create_or_verify_owner_protected_file(&installation_path, &service_config)
        .context("persisting local-service installation")?;

    let client = CopilotServiceConfig::new(
        endpoint,
        issuer_key_id,
        issuer_key_version,
        service_identity.public_key(),
        issuer_key_file,
        if user_presence_required {
            Some(std::env::current_exe().context("resolving native user-presence helper")?)
        } else {
            None
        },
        authorization_policy,
    )
    .context("building Copilot local-service configuration")?;
    let mut client_config = Vec::new();
    client
        .write_to(&mut client_config)
        .context("encoding Copilot local-service configuration")?;
    let client_config_parent = client_config_path
        .parent()
        .context("client configuration path has no parent")?;
    ensure_owner_protected_directory(client_config_parent)
        .context("protecting canonical client configuration root")?;
    let canonical = load_optional_client_config(&client_config_path)?;
    let legacy_client_config_path = legacy_extension_root
        .map(|root| root.join(COPILOT_SERVICE_CONFIG_FILE))
        .filter(|path| path != &client_config_path);
    let legacy = legacy_client_config_path
        .as_deref()
        .map(load_optional_legacy_client_config)
        .transpose()?
        .flatten();
    let action =
        reconcile_client_runtime_config(&client, canonical.as_ref(), legacy.as_ref())
            .context("reconciling installed client configuration")?;
    if matches!(
        action,
        ClientRuntimeConfigAction::CreateCanonical | ClientRuntimeConfigAction::MigrateLegacy
    ) {
        create_or_verify_owner_protected_file(&client_config_path, &client_config)
            .context("persisting canonical client configuration")?;
    }

    Ok(InstalledLocalService { client_config_path })
}

fn policy_requires_user_presence(policy: &AuthorizationPolicy) -> bool {
    let account = AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted]).ok();
    let presence = AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::UserPresence]).ok();
    !account.is_some_and(|account| policy.accepts(account))
        && presence.is_some_and(|presence| policy.accepts(presence))
}

fn enroll_user_presence(
    installation_fingerprint: [u8; 32],
    now_unix_milliseconds: u64,
) -> anyhow::Result<UserPresenceCredentialRecord> {
    eprintln!("Windows will request native user verification to enroll Konclave.");
    let verifier = UserPresenceWebAuthnVerifier::new();
    let (registration, enrollment) = verifier
        .begin_enrollment(installation_fingerprint, None)
        .context("creating user-presence enrollment challenge")?;
    let response =
        perform_native_registration(&registration).context("enrolling native user presence")?;
    let mut credential = verifier
        .finish_enrollment(&response, &enrollment)
        .context("verifying user-presence enrollment")?;
    let (authentication, state) = verifier
        .begin_authentication(&credential)
        .context("creating user-presence confirmation challenge")?;
    let response = perform_native_authentication(&authentication)
        .context("confirming native user presence")?;
    verifier
        .finish_authentication(&response, &state, &mut credential, now_unix_milliseconds)
        .context("verifying user-presence confirmation")?;
    UserPresenceCredentialRecord::from_document(
        credential
            .to_bytes()
            .context("encoding user-presence credential")?,
    )
    .context("validating user-presence credential")
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
            .context("validating AccountTrusted issuer signing key"),
        Err(SecretStorageError::OwnerProtectedStorageUnavailable) if !path.exists() => {
            let candidate = LocalServiceSigningSeed::generate()
                .context("generating AccountTrusted issuer signing key")?;
            let mut encoded = Zeroizing::new(Vec::new());
            candidate
                .write_to(&mut *encoded)
                .context("encoding AccountTrusted issuer signing key")?;
            match create_or_verify_owner_protected_file(path, encoded.as_slice()) {
                Ok(()) => Ok(candidate),
                Err(SecretStorageError::OwnerProtectedStorageConflict) => {
                    let file = open_owner_protected_file(path)
                        .context("opening concurrently created AccountTrusted issuer key")?;
                    LocalServiceSigningSeed::from_reader(file)
                        .context("validating concurrently created AccountTrusted issuer key")
                }
                Err(error) => Err(error).context("creating AccountTrusted issuer signing key"),
            }
        }
        Err(error) => Err(error).context("opening AccountTrusted issuer signing key"),
    }
}

fn account_issuer_key_id(public_key: Ed25519PublicKey) -> IssuerKeyId {
    let mut digest = Sha256::new();
    digest.update(b"konclave:account-issuer-key-id:2\0");
    digest.update(public_key.as_bytes());
    let digest = digest.finalize();
    let mut identifier = [0_u8; IssuerKeyId::LENGTH];
    identifier.copy_from_slice(&digest[..IssuerKeyId::LENGTH]);
    IssuerKeyId::from_bytes(identifier)
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

fn default_legacy_extension_root() -> Option<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|value| !value.is_empty())?;
    Some(
        PathBuf::from(home)
        .join(".copilot")
        .join("extensions")
            .join("konclave"),
    )
}

fn load_optional_legacy_client_config(
    path: &Path,
) -> anyhow::Result<Option<CopilotServiceConfig>> {
    let parent = path
        .parent()
        .context("legacy client configuration path has no parent")?;
    match std::fs::symlink_metadata(parent) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("inspecting legacy client configuration root");
        }
        Ok(_) => {}
    }
    ensure_owner_protected_directory(parent)
        .context("validating legacy client configuration root")?;
    load_optional_client_config(path)
}

fn load_optional_client_config(path: &Path) -> anyhow::Result<Option<CopilotServiceConfig>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("inspecting installed client configuration"),
        Ok(_) => {
            let file = open_owner_protected_file(path)
                .context("opening installed client configuration")?;
            CopilotServiceConfig::from_reader(file)
                .map(Some)
                .context("validating installed client configuration")
        }
    }
}

fn require_absolute_path(path: PathBuf, what: &str) -> anyhow::Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{what} must be absolute");
    }
    Ok(path)
}

fn absolute_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use KonclaveLocalServiceTransport::{LocalServiceInstallation, ServiceProfileId};

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
        let legacy_extension_root = root.path().join("extension");
        let client_config_path = root
            .path()
            .join("client-config")
            .join(COPILOT_SERVICE_CONFIG_FILE);
        std::fs::create_dir(&profile_root).unwrap();
        let endpoint = if cfg!(windows) {
            format!(r"\\.\pipe\konclave-install-test-{}", std::process::id())
        } else {
            root.path()
                .join("service.sock")
                .to_str()
                .unwrap()
                .to_string()
        };
        let profile_keys = root.path().join("profile-keys");
        let store = MemoryIdentityStore::default();

        install_with(
            &store,
            LocalServiceInstallRequest {
                profile_root: &profile_root,
                legacy_extension_root: Some(legacy_extension_root.clone()),
                client_config_path: client_config_path.clone(),
                endpoint_override: Some(&endpoint),
                service_identity_file: None,
                profile_key_directory: Some(profile_keys.clone()),
            },
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap();
        assert!(!legacy_extension_root
            .join(COPILOT_SERVICE_CONFIG_FILE)
            .exists());
        let service_path = root
            .path()
            .join(SERVICE_DIRECTORY)
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let first_service = std::fs::read(&service_path).unwrap();
        assert!(authorization_store_path(&service_path).unwrap().is_file());
        let first_adapter = std::fs::read(
            root.path()
                .join(SERVICE_DIRECTORY)
                .join(ACCOUNT_ISSUER_KEY_FILE),
        )
        .unwrap();
        install_with(
            &store,
            LocalServiceInstallRequest {
                profile_root: &profile_root,
                legacy_extension_root: Some(legacy_extension_root.clone()),
                client_config_path: client_config_path.clone(),
                endpoint_override: Some(&endpoint),
                service_identity_file: None,
                profile_key_directory: Some(profile_keys.clone()),
            },
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&service_path).unwrap(), first_service);
        assert_eq!(
            std::fs::read(
                root.path()
                    .join(SERVICE_DIRECTORY)
                    .join(ACCOUNT_ISSUER_KEY_FILE),
            )
            .unwrap(),
            first_adapter
        );

        let installation = LocalServiceInstallation::from_reader(first_service.as_slice()).unwrap();
        assert_eq!(installation.profile_root(), profile_root);
        assert_eq!(installation.issuers().len(), 1);
        assert_eq!(
            installation.profile_custody(),
            &LocalServiceProfileCustody::ExternalDirectory(profile_keys)
        );
        assert!(installation.issuers()[0]
            .registration()
            .profiles()
            .permits(&ServiceProfileId::parse("session-example").unwrap()));
        let client: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&client_config_path).unwrap(),
        )
        .unwrap();
        assert_eq!(
            client["serviceKey"],
            encode_hex(installation.service_public_key().as_bytes())
        );
        assert_eq!(
            client["issuerKeyFile"],
            root.path()
                .join(SERVICE_DIRECTORY)
                .join(ACCOUNT_ISSUER_KEY_FILE)
                .to_str()
                .unwrap()
        );
        assert!(client.get("userPresenceHelper").is_none());

        let conflict = if cfg!(windows) {
            format!(r"\\.\pipe\konclave-install-conflict-{}", std::process::id())
        } else {
            root.path().join("other.sock").to_str().unwrap().to_string()
        };
        assert!(install_with(
            &store,
            LocalServiceInstallRequest {
                profile_root: &profile_root,
                legacy_extension_root: Some(legacy_extension_root),
                client_config_path,
                endpoint_override: Some(&conflict),
                service_identity_file: None,
                profile_key_directory: Some(root.path().join("profile-keys")),
            },
            AuthorizationPolicy::account_trusted(),
        )
        .is_err());
        assert_eq!(std::fs::read(service_path).unwrap(), first_service);
    }

    #[test]
    fn equal_legacy_configuration_migrates_and_conflicts_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        let legacy_extension_root = root.path().join("legacy-extension");
        let conflicting_extension_root = root.path().join("conflicting-extension");
        let client_config_path = root
            .path()
            .join("client-config")
            .join(COPILOT_SERVICE_CONFIG_FILE);
        std::fs::create_dir(&profile_root).unwrap();
        let endpoint = if cfg!(windows) {
            format!(
                r"\\.\pipe\konclave-migration-test-{}",
                std::process::id()
            )
        } else {
            root.path()
                .join("service.sock")
                .to_str()
                .unwrap()
                .to_string()
        };
        let profile_keys = root.path().join("profile-keys");
        let store = MemoryIdentityStore::default();

        install_with(
            &store,
            LocalServiceInstallRequest {
                profile_root: &profile_root,
                legacy_extension_root: Some(legacy_extension_root.clone()),
                client_config_path: client_config_path.clone(),
                endpoint_override: Some(&endpoint),
                service_identity_file: None,
                profile_key_directory: Some(profile_keys.clone()),
            },
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap();
        let expected = std::fs::read(&client_config_path).unwrap();
        std::fs::remove_file(&client_config_path).unwrap();
        ensure_owner_protected_directory(&legacy_extension_root).unwrap();
        let legacy_path = legacy_extension_root.join(COPILOT_SERVICE_CONFIG_FILE);
        create_or_verify_owner_protected_file(&legacy_path, &expected).unwrap();

        install_with(
            &store,
            LocalServiceInstallRequest {
                profile_root: &profile_root,
                legacy_extension_root: Some(legacy_extension_root),
                client_config_path: client_config_path.clone(),
                endpoint_override: Some(&endpoint),
                service_identity_file: None,
                profile_key_directory: Some(profile_keys.clone()),
            },
            AuthorizationPolicy::account_trusted(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&client_config_path).unwrap(), expected);
        assert_eq!(std::fs::read(legacy_path).unwrap(), expected);

        let mut conflict: serde_json::Value = serde_json::from_slice(&expected).unwrap();
        conflict["endpoint"] = serde_json::json!(if cfg!(windows) {
            format!(
                r"\\.\pipe\konclave-migration-conflict-{}",
                std::process::id()
            )
        } else {
            root.path()
                .join("other.sock")
                .to_str()
                .unwrap()
                .to_string()
        });
        ensure_owner_protected_directory(&conflicting_extension_root).unwrap();
        create_or_verify_owner_protected_file(
            &conflicting_extension_root.join(COPILOT_SERVICE_CONFIG_FILE),
            conflict.to_string().as_bytes(),
        )
        .unwrap();
        assert!(install_with(
            &store,
            LocalServiceInstallRequest {
                profile_root: &profile_root,
                legacy_extension_root: Some(conflicting_extension_root),
                client_config_path,
                endpoint_override: Some(&endpoint),
                service_identity_file: None,
                profile_key_directory: Some(profile_keys),
            },
            AuthorizationPolicy::account_trusted(),
        )
        .is_err());
    }
}
