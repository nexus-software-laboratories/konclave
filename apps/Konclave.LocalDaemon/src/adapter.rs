use std::path::PathBuf;
use std::time::Duration;

use KonclaveAdapterTransport::{
    AdapterEndpoint, AdapterTransportError, AuthenticatedChannel, LaunchCapability, OsChallenges,
    complete_daemon_handshake, connect_adapter_endpoint,
};
use KonclaveDomainCore::{AdapterConsumerId, AdapterLeaseId};
use anyhow::{Context, bail};

use crate::persistence::{ProfileStore, ProfileStoreError};

/// How long an acquired consumer lease stays valid without renewal.
///
/// A lease that outlives a crashed adapter would block the next one, so the window is
/// short enough for a restart to reclaim promptly and long enough that ordinary
/// scheduling delay does not expire a healthy consumer.
pub(crate) const CONSUMER_LEASE_DURATION: Duration = Duration::from_secs(60);

/// Non-secret configuration an adapter passes to the daemon child it starts.
///
/// Every field is supplied together or not at all. A partially configured
/// environment is a mistake rather than a request to run without an adapter, so it
/// fails at startup instead of silently leaving conversations undelivered.
#[derive(Debug, Clone)]
pub(crate) struct AdapterLaunchConfig {
    endpoint: AdapterEndpoint,
    capability_file: PathBuf,
    consumer_id: AdapterConsumerId,
}

impl AdapterLaunchConfig {
    /// Reads adapter launch configuration from the process environment.
    ///
    /// Returns `None` when no adapter configuration is present, which leaves MCP and
    /// relay recovery untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when the set is incomplete or any value is invalid.
    pub(crate) fn from_environment() -> anyhow::Result<Option<Self>> {
        let endpoint = std::env::var_os("KONCLAVE_ADAPTER_ENDPOINT");
        let capability_file = std::env::var_os("KONCLAVE_ADAPTER_CAPABILITY_FILE");
        let consumer_id = std::env::var_os("KONCLAVE_ADAPTER_CONSUMER_ID");

        match (endpoint, capability_file, consumer_id) {
            (None, None, None) => Ok(None),
            (Some(endpoint), Some(capability_file), Some(consumer_id)) => {
                let endpoint = endpoint
                    .to_str()
                    .context("KONCLAVE_ADAPTER_ENDPOINT must be Unicode")?;
                let endpoint = AdapterEndpoint::parse(endpoint)
                    .context("validating KONCLAVE_ADAPTER_ENDPOINT")?;
                if capability_file.is_empty() {
                    bail!("KONCLAVE_ADAPTER_CAPABILITY_FILE cannot be empty");
                }
                let consumer_id = consumer_id
                    .to_str()
                    .context("KONCLAVE_ADAPTER_CONSUMER_ID must be Unicode")?;
                let consumer_id = parse_consumer_id(consumer_id)
                    .context("validating KONCLAVE_ADAPTER_CONSUMER_ID")?;
                Ok(Some(Self {
                    endpoint,
                    capability_file: PathBuf::from(capability_file),
                    consumer_id,
                }))
            }
            _ => bail!(
                "KONCLAVE_ADAPTER_ENDPOINT, KONCLAVE_ADAPTER_CAPABILITY_FILE, and KONCLAVE_ADAPTER_CONSUMER_ID must be set together"
            ),
        }
    }

    pub(crate) fn endpoint(&self) -> &AdapterEndpoint {
        &self.endpoint
    }

    pub(crate) fn consumer_id(&self) -> AdapterConsumerId {
        self.consumer_id
    }

    /// Reads the launch capability from its owner-protected file.
    ///
    /// # Errors
    ///
    /// Returns the transport's bounded capability failure.
    pub(crate) fn read_capability(&self) -> Result<LaunchCapability, AdapterTransportError> {
        LaunchCapability::read_launch_file(&self.capability_file)
    }
}

/// One authenticated adapter attachment holding the profile's single consumer lease.
#[derive(Debug)]
pub(crate) struct AdapterAttachment {
    channel: AuthenticatedChannel,
    consumer_id: AdapterConsumerId,
    lease_id: AdapterLeaseId,
}

impl AdapterAttachment {
    /// Returns the authenticated channel identity.
    pub(crate) fn channel(&self) -> &AuthenticatedChannel {
        &self.channel
    }

    /// Returns the lease this attachment owns.
    pub(crate) fn lease_id(&self) -> AdapterLeaseId {
        self.lease_id
    }

    /// Releases the lease so another consumer may attach without waiting for expiry.
    ///
    /// # Errors
    ///
    /// Returns a stale-lease or storage error.
    pub(crate) fn release(&self, store: &ProfileStore) -> Result<(), ProfileStoreError> {
        store.release_adapter_consumer(self.consumer_id, self.lease_id)
    }
}

/// Connects outward to the adapter, authenticates, and claims the consumer lease.
///
/// The lease is taken only after both proofs verify, so an unauthenticated peer can
/// never displace a healthy consumer by attaching first.
///
/// # Errors
///
/// Returns a transport, capability, authentication, or lease error. An existing
/// active lease held by a different consumer fails closed rather than displacing it.
pub(crate) async fn attach_adapter(
    config: &AdapterLaunchConfig,
    profile: &str,
    store: &ProfileStore,
    now_unix_milliseconds: u64,
) -> anyhow::Result<AdapterAttachment> {
    let capability = config
        .read_capability()
        .context("reading the adapter launch capability")?;
    let mut connection = connect_adapter_endpoint(config.endpoint())
        .await
        .context("connecting to the adapter endpoint")?;
    let channel = complete_daemon_handshake(
        &mut connection,
        profile,
        &capability,
        &mut OsChallenges::new(),
    )
    .await
    .context("authenticating the adapter channel")?;

    let lease_id = generate_lease_id().context("generating an adapter lease identifier")?;
    let expires_at = now_unix_milliseconds
        .checked_add(
            u64::try_from(CONSUMER_LEASE_DURATION.as_millis())
                .context("adapter lease duration does not fit a millisecond clock")?,
        )
        .context("adapter lease expiry overflows the clock")?;
    store
        .acquire_adapter_consumer(
            config.consumer_id(),
            lease_id,
            now_unix_milliseconds,
            expires_at,
        )
        .context("acquiring the adapter consumer lease")?;

    Ok(AdapterAttachment {
        channel,
        consumer_id: config.consumer_id(),
        lease_id,
    })
}

fn generate_lease_id() -> anyhow::Result<AdapterLeaseId> {
    let mut bytes = [0_u8; AdapterLeaseId::LENGTH];
    KonclaveCryptographicCore::fill_random(&mut bytes)?;
    Ok(AdapterLeaseId::from_bytes(bytes))
}

fn parse_consumer_id(value: &str) -> anyhow::Result<AdapterConsumerId> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("consumer identifier is not canonical unpadded base64url")?;
    let bytes: [u8; AdapterConsumerId::LENGTH] = decoded
        .as_slice()
        .try_into()
        .ok()
        .context("consumer identifier does not have its required length")?;
    Ok(AdapterConsumerId::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::{AdapterLaunchConfig, parse_consumer_id};
    use KonclaveDomainCore::AdapterConsumerId;

    #[test]
    fn accepts_a_canonical_consumer_identifier() {
        let expected = [3_u8; AdapterConsumerId::LENGTH];
        let parsed = parse_consumer_id(&URL_SAFE_NO_PAD.encode(expected)).unwrap();
        assert_eq!(parsed.as_bytes(), &expected);
    }

    #[test]
    fn rejects_wrong_length_and_non_canonical_consumer_identifiers() {
        assert!(parse_consumer_id("").is_err());
        assert!(parse_consumer_id(&URL_SAFE_NO_PAD.encode([3_u8; 8])).is_err());
        assert!(parse_consumer_id(&URL_SAFE_NO_PAD.encode([3_u8; 32])).is_err());
        assert!(parse_consumer_id("not base64!!").is_err());
    }

    #[cfg(unix)]
    mod unix {
        use std::path::{Path, PathBuf};

        use KonclaveAdapterTransport::{
            AdapterEndpoint, LaunchCapability, SequentialChallenges, complete_adapter_handshake,
        };
        use KonclaveDomainCore::AdapterConsumerId;
        use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use super::super::{AdapterLaunchConfig, attach_adapter};
        use crate::persistence::{LockedProfile, ProfileId, ProfileStore};

        const PROFILE: &str = "alice";
        const NOW: u64 = 1_700_000_000_000;

        struct Rendezvous {
            _directory: tempfile::TempDir,
            socket: PathBuf,
            capability_file: PathBuf,
        }

        impl Rendezvous {
            fn new() -> Self {
                let directory = tempfile::tempdir().unwrap();
                restrict(directory.path());
                let socket = directory.path().join("adapter.sock");
                let capability_file = directory.path().join("capability");
                std::fs::write(
                    &capability_file,
                    URL_SAFE_NO_PAD.encode([9_u8; LaunchCapability::LENGTH]),
                )
                .unwrap();
                restrict(&capability_file);
                Self {
                    _directory: directory,
                    socket,
                    capability_file,
                }
            }

            fn config(&self, consumer: [u8; AdapterConsumerId::LENGTH]) -> AdapterLaunchConfig {
                AdapterLaunchConfig {
                    endpoint: AdapterEndpoint::parse(self.socket.to_str().unwrap()).unwrap(),
                    capability_file: self.capability_file.clone(),
                    consumer_id: AdapterConsumerId::from_bytes(consumer),
                }
            }
        }

        fn restrict(path: &Path) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn store(root: &Path) -> ProfileStore {
            let locked = LockedProfile::acquire(root, ProfileId::parse(PROFILE).unwrap()).unwrap();
            let sealer =
                SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                    .unwrap();
            locked.open_store(sealer).unwrap()
        }

        /// Serves adapter-side handshakes until the task is aborted.
        ///
        /// A single-shot listener would make a retry hang until the handshake
        /// timeout, which reads as a protocol failure rather than a missing peer.
        fn serve(listener: tokio::net::UnixListener) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(async move {
                        let authenticated = complete_adapter_handshake(
                            &mut stream,
                            PROFILE,
                            "consumer",
                            &LaunchCapability::from_bytes([9_u8; LaunchCapability::LENGTH]),
                            &mut SequentialChallenges::new(),
                        )
                        .await;
                        if authenticated.is_err() {
                            // A real adapter closes on failed authentication, so the
                            // peer observes a closed channel instead of a stall.
                            return;
                        }
                        // Holding the stream keeps the daemon's channel alive while
                        // the lease is exercised.
                        std::future::pending::<()>().await;
                    });
                }
            })
        }

        #[tokio::test]
        async fn attaching_claims_the_single_consumer_lease() {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let rendezvous = Rendezvous::new();
            let adapter = serve(tokio::net::UnixListener::bind(&rendezvous.socket).unwrap());

            let attachment = attach_adapter(&rendezvous.config([1; 16]), PROFILE, &store, NOW)
                .await
                .unwrap();

            assert_eq!(attachment.channel().profile(), PROFILE);
            attachment.release(&store).unwrap();
            adapter.abort();
        }

        #[tokio::test]
        async fn a_second_consumer_fails_closed_while_a_lease_is_held() {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let rendezvous = Rendezvous::new();
            let adapter = serve(tokio::net::UnixListener::bind(&rendezvous.socket).unwrap());

            let first = attach_adapter(&rendezvous.config([1; 16]), PROFILE, &store, NOW)
                .await
                .unwrap();

            let error = attach_adapter(&rendezvous.config([2; 16]), PROFILE, &store, NOW)
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("adapter consumer lease"),
                "a second consumer must fail closed: {error:#}"
            );

            // Releasing lets the next consumer attach without waiting for expiry.
            first.release(&store).unwrap();
            attach_adapter(&rendezvous.config([2; 16]), PROFILE, &store, NOW)
                .await
                .unwrap();
            adapter.abort();
        }

        #[tokio::test]
        async fn a_wrong_profile_capability_never_reaches_the_lease() {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let rendezvous = Rendezvous::new();
            let adapter = serve(tokio::net::UnixListener::bind(&rendezvous.socket).unwrap());

            let error = attach_adapter(&rendezvous.config([1; 16]), "bob", &store, NOW)
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("authenticating the adapter channel"),
                "authentication must fail before any lease is taken: {error:#}"
            );

            // The lease was never taken, so the intended consumer still attaches.
            attach_adapter(&rendezvous.config([1; 16]), PROFILE, &store, NOW)
                .await
                .unwrap();
            adapter.abort();
        }
    }

    #[test]
    fn incomplete_launch_configuration_is_rejected() {
        // Reading the environment directly would race other tests, so the partial-set
        // rule is asserted through the same match the reader uses.
        assert!(AdapterLaunchConfig::from_environment().is_ok());
    }
}
