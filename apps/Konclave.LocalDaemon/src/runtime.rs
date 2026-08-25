use std::future::Future;
use std::io::Read as _;
use std::path::PathBuf;

use KonclaveClientLibrary::{
    HttpRelayEnrollmentTransport, RELAY_INSTALLATION_CONFIG_FILE, RelayAccessCredential,
    RelayClient, RelayEndpoint, RelayEnrollmentClient, RelayEnrollmentCredential,
    RelayEnrollmentRequest, RelayEnrollmentSourceConfig, RelayInstallationConfig,
    default_profile_root,
};
use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveSecretStorage::{
    ExternalWrappingKeyProvider, NativeEnrollmentCredentialStore, NativeWrappingKeyProvider,
    SealedSqliteMlsStorage, SecretSealer,
};
use anyhow::{Context, bail};
use zeroize::Zeroizing;

use crate::adapter::AdapterLaunchConfig;
use crate::application::ApplicationService;
use crate::conversation::ConversationCoordinator;
use crate::pairing_service::PairingService;
use crate::persistence::{LockedProfile, ProfileId, ProfileStore, ProfileStoreError};
use crate::profile_runtime::ProfileRuntime;

pub(crate) async fn run_until<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let _telemetry_guard = crate::observability::init()?;
    let config = ProfileConfig::from_environment()?;
    let adapter_config = read_legacy_adapter_config();
    let profile = initialize_profile(config).await?;
    crate::profile_runtime::run_legacy_until(profile, adapter_config, shutdown).await
}

fn read_legacy_adapter_config() -> Option<AdapterLaunchConfig> {
    match AdapterLaunchConfig::from_environment() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Adapter configuration rejected: {error:#}");
            None
        }
    }
}

struct ProfileConfig {
    root: PathBuf,
    profile_id: ProfileId,
    wrapping_key_file: Option<PathBuf>,
    relay_provisioning: Option<RelayProvisioning>,
    relay_installation: Option<RelayInstallationConfig>,
    allow_mcp_write: bool,
}

struct RelayProvisioning {
    endpoint: RelayEndpoint,
    credential_file: PathBuf,
}

struct OpenedProfile {
    store: ProfileStore,
    mls_storage: SealedSqliteMlsStorage,
    device: DeviceIdentity,
    enrollment: Option<EnrollmentPlan>,
    allow_mcp_write: bool,
    profile_id: String,
}

struct EnrollmentPlan {
    endpoint: RelayEndpoint,
    request: RelayEnrollmentRequest,
    credential: RelayEnrollmentCredential,
}

impl ProfileConfig {
    fn from_environment() -> anyhow::Result<Self> {
        let profile_id = ProfileId::parse(
            std::env::var("KONCLAVE_PROFILE_ID").unwrap_or_else(|_| "default".to_string()),
        )
        .context("validating KONCLAVE_PROFILE_ID")?;
        let root = match std::env::var_os("KONCLAVE_PROFILE_ROOT") {
            Some(root) if !root.is_empty() => PathBuf::from(root),
            Some(_) => bail!("KONCLAVE_PROFILE_ROOT cannot be empty"),
            None => default_profile_root()?,
        };
        let wrapping_key_file = match std::env::var_os("KONCLAVE_WRAPPING_KEY_FILE") {
            Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
            Some(_) => bail!("KONCLAVE_WRAPPING_KEY_FILE cannot be empty"),
            None => None,
        };
        let allow_mcp_write =
            parse_mcp_allow_write(std::env::var_os("KONCLAVE_MCP_ALLOW_WRITE").as_deref())?;
        let relay_installation = read_relay_installation(&root)?;
        let relay_provisioning = Self::parse_relay_provisioning(
            std::env::var_os("KONCLAVE_RELAY_ENDPOINT").as_deref(),
            std::env::var_os("KONCLAVE_RELAY_CREDENTIAL_FILE").as_deref(),
        )?;
        Ok(Self {
            root,
            profile_id,
            wrapping_key_file,
            relay_provisioning,
            relay_installation,
            allow_mcp_write,
        })
    }

    fn parse_relay_provisioning(
        endpoint: Option<&std::ffi::OsStr>,
        credential_file: Option<&std::ffi::OsStr>,
    ) -> anyhow::Result<Option<RelayProvisioning>> {
        match (endpoint, credential_file) {
            (None, None) => Ok(None),
            (Some(endpoint), Some(credential_file))
                if !endpoint.is_empty() && !credential_file.is_empty() =>
            {
                let endpoint = endpoint
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("KONCLAVE_RELAY_ENDPOINT must be Unicode"))?;
                Ok(Some(RelayProvisioning {
                    endpoint: RelayEndpoint::parse(endpoint)
                        .context("validating KONCLAVE_RELAY_ENDPOINT")?,
                    credential_file: PathBuf::from(credential_file),
                }))
            }
            _ => bail!(
                "KONCLAVE_RELAY_ENDPOINT and KONCLAVE_RELAY_CREDENTIAL_FILE must be set together"
            ),
        }
    }
}

fn read_relay_installation(
    root: &std::path::Path,
) -> anyhow::Result<Option<RelayInstallationConfig>> {
    let path = root.join(RELAY_INSTALLATION_CONFIG_FILE);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening relay installation {}", path.display()));
        }
    };
    RelayInstallationConfig::from_reader(file)
        .with_context(|| format!("reading relay installation {}", path.display()))
        .map(Some)
}

fn parse_mcp_allow_write(value: Option<&std::ffi::OsStr>) -> anyhow::Result<bool> {
    match value.and_then(std::ffi::OsStr::to_str) {
        None if value.is_none() => Ok(false),
        Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        Some(_) => bail!("KONCLAVE_MCP_ALLOW_WRITE must be true, false, 1, or 0"),
        None => bail!("KONCLAVE_MCP_ALLOW_WRITE must be Unicode"),
    }
}

async fn initialize_profile(config: ProfileConfig) -> anyhow::Result<ProfileRuntime> {
    let mut opened = tokio::task::spawn_blocking(move || open_profile(config))
        .await
        .context("joining daemon profile open")??;
    if let Some(enrollment) = opened.enrollment.take() {
        let endpoint = enrollment.endpoint;
        let request = enrollment.request;
        let transport = HttpRelayEnrollmentTransport::new(endpoint.clone(), enrollment.credential)
            .context("creating relay enrollment transport")?;
        let response = RelayEnrollmentClient::new(transport)
            .register(request)
            .await
            .context("registering relay principal")?;
        opened = tokio::task::spawn_blocking(move || {
            opened
                .store
                .promote_relay_enrollment(&endpoint, response)
                .context("promoting relay enrollment")?;
            anyhow::Result::<OpenedProfile>::Ok(opened)
        })
        .await
        .context("joining relay enrollment promotion")??;
    }
    tokio::task::spawn_blocking(move || finish_profile(opened))
        .await
        .context("joining daemon profile finalization")?
}

fn open_profile(config: ProfileConfig) -> anyhow::Result<OpenedProfile> {
    let locked = LockedProfile::acquire(&config.root, config.profile_id.clone())
        .context("acquiring daemon profile lock")?;
    let mls_database_path = locked.mls_database_path();
    let sealer = load_sealer(&config)?;
    let mls_sealer = sealer.share();
    let mls_storage = SealedSqliteMlsStorage::open(&mls_database_path, mls_sealer)
        .context("opening sealed MLS store")?;
    let store = locked
        .open_store(sealer)
        .context("opening daemon profile store")?;
    let device = store
        .load_or_create_device()
        .context("loading daemon device identity")?;
    provision_relay_if_needed(&store, config.relay_provisioning.as_ref())?;
    let enrollment = match store.relay_configuration() {
        Ok(_) => None,
        Err(ProfileStoreError::RelayNotConfigured) => match config.relay_installation.as_ref() {
            Some(installation) => Some(prepare_enrollment(&store, installation)?),
            None if store.pending_relay_enrollment()?.is_some() => {
                bail!("pending relay enrollment requires its installation source")
            }
            None => None,
        },
        Err(error) => return Err(error).context("loading relay configuration"),
    };
    Ok(OpenedProfile {
        store,
        mls_storage,
        device,
        enrollment,
        allow_mcp_write: config.allow_mcp_write,
        profile_id: config.profile_id.as_str().to_string(),
    })
}

fn finish_profile(opened: OpenedProfile) -> anyhow::Result<ProfileRuntime> {
    let OpenedProfile {
        store,
        mls_storage,
        device,
        enrollment: _,
        allow_mcp_write,
        profile_id,
    } = opened;
    let relay = match store.relay_configuration() {
        Ok((endpoint, credential)) => {
            let transport = RelayClient::new(endpoint.clone(), credential)
                .context("creating authenticated relay client")?;
            Some((endpoint, transport))
        }
        Err(ProfileStoreError::RelayNotConfigured) => None,
        Err(error) => return Err(error).context("loading relay configuration"),
    };
    let conversations = ConversationCoordinator::new(store, mls_storage, device);
    conversations
        .recover()
        .context("recovering daemon conversations")?;
    let (applications, pairings) = match relay {
        Some((endpoint, transport)) => {
            let applications = ApplicationService::new(conversations.clone(), transport);
            let pairings =
                PairingService::new(conversations.clone(), applications.clone(), endpoint);
            (Some(applications), Some(pairings))
        }
        None => (None, None),
    };
    Ok(ProfileRuntime {
        conversations,
        applications,
        pairings,
        allow_mcp_write,
        profile_id,
    })
}

fn prepare_enrollment(
    store: &ProfileStore,
    installation: &RelayInstallationConfig,
) -> anyhow::Result<EnrollmentPlan> {
    let pending = store
        .reserve_relay_enrollment(installation.endpoint())
        .context("reserving relay enrollment")?;
    let credential = load_installation_credential(installation)?;
    Ok(EnrollmentPlan {
        endpoint: pending.endpoint().clone(),
        request: pending.request(),
        credential,
    })
}

fn load_installation_credential(
    installation: &RelayInstallationConfig,
) -> anyhow::Result<RelayEnrollmentCredential> {
    if let Some(credential) = installation
        .load_external_credential()
        .context("loading endpoint-bound external enrollment credential")?
    {
        return Ok(credential);
    }
    let RelayEnrollmentSourceConfig::Native { installation_id } = installation.source() else {
        bail!("relay enrollment source is unsupported");
    };
    let record = NativeEnrollmentCredentialStore::new(installation_id.clone())
        .context("validating enrollment installation identifier")?
        .load()
        .context("loading native enrollment credential")?;
    RelayEnrollmentCredential::from_bound_reader(record.as_slice(), installation.endpoint())
        .context("validating native enrollment credential")
}

fn provision_relay_if_needed(
    store: &crate::persistence::ProfileStore,
    provisioning: Option<&RelayProvisioning>,
) -> anyhow::Result<()> {
    let Some(provisioning) = provisioning else {
        return Ok(());
    };
    match store.relay_configuration() {
        Ok((endpoint, _credential)) => {
            if endpoint.as_str() != provisioning.endpoint.as_str() {
                bail!("configured relay endpoint does not match KONCLAVE_RELAY_ENDPOINT");
            }
            Ok(())
        }
        Err(ProfileStoreError::RelayNotConfigured) => {
            let credential = read_relay_credential(&provisioning.credential_file)?;
            store
                .configure_relay(&provisioning.endpoint, &credential)
                .context("persisting relay provisioning")
        }
        Err(error) => Err(error).context("loading relay configuration for provisioning"),
    }
}

fn read_relay_credential(path: &std::path::Path) -> anyhow::Result<RelayAccessCredential> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening relay credential file {}", path.display()))?;
    let mut value = Zeroizing::new(String::new());
    file.by_ref()
        .take(129)
        .read_to_string(&mut value)
        .context("reading relay credential file")?;
    if value.is_empty() || value.len() > 128 {
        bail!("relay credential file has an invalid length");
    }
    let trimmed_length = if value.ends_with("\r\n") {
        value.len().checked_sub(2)
    } else if value.ends_with('\n') {
        value.len().checked_sub(1)
    } else {
        None
    };
    if let Some(trimmed_length) = trimmed_length {
        value.truncate(trimmed_length);
    }
    RelayAccessCredential::from_base64(&value).context("parsing relay credential file")
}

fn load_sealer(config: &ProfileConfig) -> anyhow::Result<SecretSealer> {
    match &config.wrapping_key_file {
        Some(path) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("opening wrapping key file {}", path.display()))?;
            let provider =
                ExternalWrappingKeyProvider::from_reader(file).context("reading external key")?;
            SecretSealer::from_provider(provider).context("loading external wrapping key")
        }
        None => {
            let provider = NativeWrappingKeyProvider::new(config.profile_id.as_str())
                .context("configuring native wrapping key")?;
            SecretSealer::from_provider(provider).context("loading native wrapping key")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestRelay;

    #[test]
    fn mcp_write_policy_is_explicit_and_fail_closed() {
        assert!(!parse_mcp_allow_write(None).unwrap());
        assert!(parse_mcp_allow_write(Some(std::ffi::OsStr::new("true"))).unwrap());
        assert!(!parse_mcp_allow_write(Some(std::ffi::OsStr::new("0"))).unwrap());
        assert!(parse_mcp_allow_write(Some(std::ffi::OsStr::new("yes"))).is_err());
    }

    #[tokio::test]
    async fn external_key_profile_initializes_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("wrapping.key");
        let root = directory.path().join("profiles");
        std::fs::write(&key_path, [5_u8; 32]).unwrap();
        let config = || ProfileConfig {
            root: root.clone(),
            profile_id: ProfileId::parse("runtime-test").unwrap(),
            wrapping_key_file: Some(key_path.clone()),
            relay_provisioning: None,
            relay_installation: None,
            allow_mcp_write: false,
        };
        let first = initialize_profile(config()).await.unwrap();
        let first_device = first.conversations.device_id().unwrap();
        assert!(root.join("runtime-test").join("profile.sqlite").is_file());
        assert!(root.join("runtime-test").join("mls.sqlite").is_file());
        drop(first);
        let reopened = initialize_profile(config()).await.unwrap();
        assert_eq!(reopened.conversations.device_id().unwrap(), first_device);
    }

    #[tokio::test]
    async fn distinct_profiles_open_concurrently_in_one_process() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("wrapping.key");
        let root = directory.path().join("profiles");
        std::fs::write(&key_path, [5_u8; 32]).unwrap();
        let config = |profile: &str| ProfileConfig {
            root: root.clone(),
            profile_id: ProfileId::parse(profile).unwrap(),
            wrapping_key_file: Some(key_path.clone()),
            relay_provisioning: None,
            relay_installation: None,
            allow_mcp_write: false,
        };

        let (first, second) = tokio::join!(
            initialize_profile(config("concurrent-a")),
            initialize_profile(config("concurrent-b"))
        );
        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(first.profile_id, "concurrent-a");
        assert_eq!(second.profile_id, "concurrent-b");
        assert_ne!(
            first.conversations.device_id().unwrap(),
            second.conversations.device_id().unwrap()
        );
        assert!(LockedProfile::acquire(&root, ProfileId::parse("concurrent-a").unwrap()).is_err());
        assert!(LockedProfile::acquire(&root, ProfileId::parse("concurrent-b").unwrap()).is_err());
    }

    #[test]
    fn relay_provisioning_requires_endpoint_and_credential_file() {
        let endpoint = std::ffi::OsStr::new("https://relay.example.test");
        let credential = std::ffi::OsStr::new("relay.credential");
        assert!(
            ProfileConfig::parse_relay_provisioning(None, None)
                .unwrap()
                .is_none()
        );
        assert!(ProfileConfig::parse_relay_provisioning(Some(endpoint), None).is_err());
        assert!(ProfileConfig::parse_relay_provisioning(None, Some(credential)).is_err());
        assert!(
            ProfileConfig::parse_relay_provisioning(
                Some(std::ffi::OsStr::new("http://relay.example.test")),
                Some(credential)
            )
            .is_err()
        );
    }

    #[test]
    fn relay_credential_file_is_bounded_and_canonical() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.credential");
        let oversized = directory.path().join("oversized.credential");
        std::fs::write(&valid, "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\r\n").unwrap();
        std::fs::write(&oversized, "a".repeat(129)).unwrap();
        assert!(read_relay_credential(&valid).is_ok());
        assert!(read_relay_credential(&oversized).is_err());
    }

    #[tokio::test]
    async fn relay_provisioning_is_first_run_only_and_endpoint_bound() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("wrapping.key");
        let credential_path = directory.path().join("relay.credential");
        let root = directory.path().join("profiles");
        std::fs::write(&key_path, [5_u8; 32]).unwrap();
        std::fs::write(
            &credential_path,
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\n",
        )
        .unwrap();
        let config = |endpoint: &str| ProfileConfig {
            root: root.clone(),
            profile_id: ProfileId::parse("relay-provisioning").unwrap(),
            wrapping_key_file: Some(key_path.clone()),
            relay_provisioning: Some(RelayProvisioning {
                endpoint: RelayEndpoint::parse(endpoint).unwrap(),
                credential_file: credential_path.clone(),
            }),
            relay_installation: None,
            allow_mcp_write: false,
        };
        let first = initialize_profile(config("https://relay.example.test"))
            .await
            .unwrap();
        assert!(first.applications.is_some());
        assert!(first.pairings.is_some());
        drop(first);
        std::fs::remove_file(&credential_path).unwrap();
        let reopened = initialize_profile(config("https://relay.example.test"))
            .await
            .unwrap();
        assert!(reopened.applications.is_some());
        assert!(reopened.pairings.is_some());
        drop(reopened);
        assert!(
            initialize_profile(config("https://other.example.test"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn installation_source_enrolls_distinct_profiles_automatically() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("profiles");
        let key_path = directory.path().join("wrapping.key");
        let credential_path = directory.path().join("enrollment.credential");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&key_path, [5_u8; 32]).unwrap();
        let enrollment_token = [11_u8; RelayEnrollmentCredential::LENGTH];
        let relay = TestRelay::start_enrollment(enrollment_token).await;
        let endpoint = RelayEndpoint::parse(&relay.endpoint).unwrap();
        let installation = RelayInstallationConfig::new(
            endpoint,
            RelayEnrollmentSourceConfig::ExternalFile {
                path: credential_path.clone(),
            },
        )
        .unwrap();
        installation
            .create_external_credential(&RelayEnrollmentCredential::from_bytes(enrollment_token))
            .unwrap();
        std::fs::write(
            root.join(RELAY_INSTALLATION_CONFIG_FILE),
            installation.encode().unwrap(),
        )
        .unwrap();

        let first = initialize_profile(external_profile_config(&root, &key_path, "automatic-a"))
            .await
            .unwrap();
        let first_principal = first
            .conversations
            .store()
            .relay_configuration()
            .unwrap()
            .1
            .principal_id();
        assert!(first.applications.is_some());
        assert!(first.pairings.is_some());
        drop(first);

        let second = initialize_profile(external_profile_config(&root, &key_path, "automatic-b"))
            .await
            .unwrap();
        let second_principal = second
            .conversations
            .store()
            .relay_configuration()
            .unwrap()
            .1
            .principal_id();
        assert_ne!(first_principal, second_principal);
        drop(second);

        std::fs::remove_file(&credential_path).unwrap();
        let reopened = initialize_profile(external_profile_config(&root, &key_path, "automatic-a"))
            .await
            .unwrap();
        assert!(reopened.applications.is_some());
        relay.stop().await;
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn missing_external_source_fails_closed_and_exact_retry_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("profiles");
        let key_path = directory.path().join("wrapping.key");
        let credential_path = directory.path().join("missing-enrollment.credential");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&key_path, [6_u8; 32]).unwrap();
        let enrollment_token = [12_u8; RelayEnrollmentCredential::LENGTH];
        let relay = TestRelay::start_enrollment(enrollment_token).await;
        let endpoint = RelayEndpoint::parse(&relay.endpoint).unwrap();
        let installation = RelayInstallationConfig::new(
            endpoint.clone(),
            RelayEnrollmentSourceConfig::ExternalFile {
                path: credential_path.clone(),
            },
        )
        .unwrap();
        let installation_bytes = installation.encode().unwrap();
        std::fs::write(
            root.join(RELAY_INSTALLATION_CONFIG_FILE),
            &installation_bytes,
        )
        .unwrap();
        let config = || external_profile_config(&root, &key_path, "missing-source");

        assert!(initialize_profile(config()).await.is_err());
        std::fs::remove_file(root.join(RELAY_INSTALLATION_CONFIG_FILE)).unwrap();
        assert!(initialize_profile(config()).await.is_err());
        std::fs::write(
            root.join(RELAY_INSTALLATION_CONFIG_FILE),
            installation_bytes,
        )
        .unwrap();
        installation
            .create_external_credential(&RelayEnrollmentCredential::from_bytes(enrollment_token))
            .unwrap();
        let recovered = initialize_profile(config()).await.unwrap();
        assert!(recovered.applications.is_some());
        assert!(
            recovered
                .conversations
                .store()
                .pending_relay_enrollment()
                .unwrap()
                .is_none()
        );
        relay.stop().await;
    }

    fn external_profile_config(
        root: &std::path::Path,
        key_path: &std::path::Path,
        profile: &str,
    ) -> ProfileConfig {
        ProfileConfig {
            root: root.to_path_buf(),
            profile_id: ProfileId::parse(profile).unwrap(),
            wrapping_key_file: Some(key_path.to_path_buf()),
            relay_provisioning: None,
            relay_installation: read_relay_installation(root).unwrap(),
            allow_mcp_write: false,
        }
    }
}
