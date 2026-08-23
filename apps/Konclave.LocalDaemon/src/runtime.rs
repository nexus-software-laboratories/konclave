use std::future::Future;
use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use KonclaveClientLibrary::{RelayAccessCredential, RelayClient, RelayEndpoint};
use KonclaveSecretStorage::{
    ExternalWrappingKeyProvider, NativeWrappingKeyProvider, SealedSqliteMlsStorage, SecretSealer,
};
use anyhow::{Context, bail};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::application::ApplicationService;
use crate::conversation::ConversationCoordinator;
use crate::persistence::{LockedProfile, ProfileId, ProfileStoreError};
use crate::service::Service;

pub async fn run_until<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let _telemetry_guard = crate::observability::init()?;
    let config = ProfileConfig::from_environment()?;
    let profile = tokio::task::spawn_blocking(move || initialize_profile(config))
        .await
        .context("joining daemon profile initialization")??;
    run_with_capabilities(profile, shutdown).await
}

async fn run_with_capabilities<F>(profile: RuntimeProfile, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let health = crate::health::DeliveryHealth::default();
    let mcp_server = crate::mcp::StdioServer::new(
        profile.conversations.clone(),
        profile.applications.clone(),
        health.clone(),
        crate::mcp::local_stdio_authorization(profile.allow_mcp_write),
    );
    let service_applications = profile.applications.clone();
    let adapter_store = profile.conversations.store();
    let adapter_health = health.clone();
    let adapter_profile = profile.profile_id.clone();
    let _profile = profile;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let external_shutdown_tx = shutdown_tx.clone();
    let external_shutdown_rx = shutdown_rx.clone();
    let external_shutdown = async move {
        tokio::select! {
            _ = shutdown => {
                let _ = external_shutdown_tx.send(true);
            }
            _ = wait_for_shutdown(external_shutdown_rx) => {}
        }
        anyhow::Result::<()>::Ok(())
    };
    let mcp_shutdown_tx = shutdown_tx.clone();
    let mcp_shutdown_rx = shutdown_rx.clone();
    let mcp_server = async move {
        let result = crate::mcp::run_stdio_server(mcp_server, mcp_shutdown_rx).await;
        let _ = mcp_shutdown_tx.send(true);
        result
    };
    let service_shutdown_tx = shutdown_tx.clone();
    let service_shutdown_rx = shutdown_rx.clone();
    let service = async move {
        let result = Service::new(service_applications, Duration::from_secs(30), health)
            .run_until(wait_for_shutdown(service_shutdown_rx))
            .await;
        let _ = service_shutdown_tx.send(true);
        result
    };

    let adapter_shutdown_rx = shutdown_rx.clone();
    let adapter = async move {
        crate::adapter::run_adapter_channel(
            adapter_store,
            &adapter_profile,
            adapter_health,
            adapter_shutdown_rx,
        )
        .await;
        anyhow::Result::<()>::Ok(())
    };

    tokio::try_join!(service, mcp_server, adapter, external_shutdown)?;

    Ok(())
}

struct RuntimeProfile {
    conversations: ConversationCoordinator,
    applications: Option<ApplicationService<RelayClient>>,
    allow_mcp_write: bool,
    profile_id: String,
}

struct ProfileConfig {
    root: PathBuf,
    profile_id: ProfileId,
    wrapping_key_file: Option<PathBuf>,
    relay_provisioning: Option<RelayProvisioning>,
    allow_mcp_write: bool,
}

struct RelayProvisioning {
    endpoint: RelayEndpoint,
    credential_file: PathBuf,
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
        let relay_provisioning = Self::parse_relay_provisioning(
            std::env::var_os("KONCLAVE_RELAY_ENDPOINT").as_deref(),
            std::env::var_os("KONCLAVE_RELAY_CREDENTIAL_FILE").as_deref(),
        )?;
        Ok(Self {
            root,
            profile_id,
            wrapping_key_file,
            relay_provisioning,
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

fn parse_mcp_allow_write(value: Option<&std::ffi::OsStr>) -> anyhow::Result<bool> {
    match value.and_then(std::ffi::OsStr::to_str) {
        None if value.is_none() => Ok(false),
        Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        Some(_) => bail!("KONCLAVE_MCP_ALLOW_WRITE must be true, false, 1, or 0"),
        None => bail!("KONCLAVE_MCP_ALLOW_WRITE must be Unicode"),
    }
}

fn initialize_profile(config: ProfileConfig) -> anyhow::Result<RuntimeProfile> {
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
    let relay = match store.relay_configuration() {
        Ok((endpoint, credential)) => Some(
            RelayClient::new(endpoint, credential)
                .context("creating authenticated relay client")?,
        ),
        Err(ProfileStoreError::RelayNotConfigured) => None,
        Err(error) => return Err(error).context("loading relay configuration"),
    };
    let conversations = ConversationCoordinator::new(store, mls_storage, device);
    conversations
        .recover()
        .context("recovering daemon conversations")?;
    let applications =
        relay.map(|transport| ApplicationService::new(conversations.clone(), transport));
    Ok(RuntimeProfile {
        conversations,
        applications,
        allow_mcp_write: config.allow_mcp_write,
        profile_id: config.profile_id.as_str().to_string(),
    })
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

fn default_profile_root() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        let root = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is required"))?;
        return Ok(PathBuf::from(root).join("Konclave").join("profiles"));
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("HOME is required"))?;
        return Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Konclave")
            .join("profiles"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(root).join("konclave").join("profiles"));
        }
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("HOME is required"))?;
        return Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("konclave")
            .join("profiles"));
    }
    #[allow(unreachable_code)]
    Err(anyhow::anyhow!("this platform has no default profile root"))
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_write_policy_is_explicit_and_fail_closed() {
        assert!(!parse_mcp_allow_write(None).unwrap());
        assert!(parse_mcp_allow_write(Some(std::ffi::OsStr::new("true"))).unwrap());
        assert!(!parse_mcp_allow_write(Some(std::ffi::OsStr::new("0"))).unwrap());
        assert!(parse_mcp_allow_write(Some(std::ffi::OsStr::new("yes"))).is_err());
    }

    #[test]
    fn external_key_profile_initializes_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("wrapping.key");
        let root = directory.path().join("profiles");
        std::fs::write(&key_path, [5_u8; 32]).unwrap();
        let config = || ProfileConfig {
            root: root.clone(),
            profile_id: ProfileId::parse("runtime-test").unwrap(),
            wrapping_key_file: Some(key_path.clone()),
            relay_provisioning: None,
            allow_mcp_write: false,
        };
        let first = initialize_profile(config()).unwrap();
        let first_device = first.conversations.device_id().unwrap();
        assert!(root.join("runtime-test").join("profile.sqlite").is_file());
        assert!(root.join("runtime-test").join("mls.sqlite").is_file());
        drop(first);
        let reopened = initialize_profile(config()).unwrap();
        assert_eq!(reopened.conversations.device_id().unwrap(), first_device);
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

    #[test]
    fn relay_provisioning_is_first_run_only_and_endpoint_bound() {
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
            allow_mcp_write: false,
        };
        let first = initialize_profile(config("https://relay.example.test")).unwrap();
        assert!(first.applications.is_some());
        drop(first);
        std::fs::remove_file(&credential_path).unwrap();
        let reopened = initialize_profile(config("https://relay.example.test")).unwrap();
        assert!(reopened.applications.is_some());
        drop(reopened);
        assert!(initialize_profile(config("https://other.example.test")).is_err());
    }
}
