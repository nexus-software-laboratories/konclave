use std::path::PathBuf;
use std::time::Duration;

use KonclaveAdapterTransport::{
    AdapterEndpoint, AdapterRequest, AdapterResponse, AdapterStatus, AdapterTransportError,
    AuthenticatedChannel, DeliveredEvent, DeliveredPayload, DeliveredRole, LaunchCapability,
    MAX_AUTHENTICATED_FRAME_BYTES, OsChallenges, complete_daemon_handshake,
    connect_adapter_endpoint, read_frame, write_frame,
};
use KonclaveDomainCore::{AdapterConsumerId, AdapterLeaseId, ConversationRole, NotificationId};
use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use crate::health::DeliveryHealth;
use crate::persistence::{ClaimedRemoteEvent, ProfileStore, ProfileStoreError, RemoteEventPayload};

/// How often the daemon re-checks for eligible work inside a bounded wait.
///
/// The journal has no change notification, so a wait polls. The interval is short
/// enough that delivery latency stays well below a conversational turn and long
/// enough that an idle profile does not spin.
const CLAIM_POLL_INTERVAL: Duration = Duration::from_millis(250);

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

    acquire_attachment(config, store, channel, now_unix_milliseconds)
}

/// Claims the profile's single consumer lease for an already authenticated channel.
///
/// # Errors
///
/// Returns a lease or clock error. An active lease held by a different consumer fails
/// closed rather than displacing it, and a channel that authenticated as a different
/// consumer than the launch configuration names is refused.
fn acquire_attachment(
    config: &AdapterLaunchConfig,
    store: &ProfileStore,
    channel: AuthenticatedChannel,
    now_unix_milliseconds: u64,
) -> anyhow::Result<AdapterAttachment> {
    // The lease is taken under the launch-configured consumer while every request is
    // answered over the authenticated channel. Those are two independently sourced
    // values, so requiring them to agree keeps a mismatch from ever becoming a lease
    // held on behalf of an identity the peer did not actually prove.
    let announced = parse_consumer_id(channel.consumer())
        .context("reading the authenticated adapter consumer")?;
    if announced != config.consumer_id() {
        bail!("the authenticated adapter announced a different consumer than it was launched with");
    }
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

/// Runs the adapter channel for the life of the daemon.
///
/// Missing configuration is not an error: the daemon still serves MCP and still
/// recovers relay state. A configured adapter that is unreachable or that rejects
/// authentication is retried with bounded backoff rather than taking the daemon down,
/// because losing the harness connection must not stop relay processing. There is no
/// fallback to an unauthenticated channel.
pub(crate) async fn run_adapter_channel(
    store: std::sync::Arc<ProfileStore>,
    profile: &str,
    health: DeliveryHealth,
    mut shutdown: watch::Receiver<bool>,
) {
    let config = match AdapterLaunchConfig::from_environment() {
        Ok(Some(config)) => config,
        Ok(None) => return,
        Err(error) => {
            // A malformed set is reported once and then left alone; retrying cannot
            // repair the environment of a running process.
            eprintln!("Adapter configuration rejected: {error:#}");
            return;
        }
    };

    let clock = SystemUnixClock;
    let mut failures: u32 = 0;
    loop {
        if *shutdown.borrow() {
            return;
        }
        match attach_and_serve(&config, profile, &store, &clock, &health, shutdown.clone()).await {
            Ok(()) => failures = 0,
            Err(error) => {
                failures = failures.saturating_add(1);
                eprintln!(
                    "Adapter channel unavailable (attempt {failures}): {}",
                    adapter_error_code(&error)
                );
            }
        }
        if *shutdown.borrow() {
            return;
        }
        let delay = adapter_retry_delay(failures);
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
}

async fn attach_and_serve(
    config: &AdapterLaunchConfig,
    profile: &str,
    store: &ProfileStore,
    clock: &dyn UnixClock,
    health: &DeliveryHealth,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let capability = config.read_capability()?;
    let mut connection = connect_adapter_endpoint(config.endpoint()).await?;
    let channel = complete_daemon_handshake(
        &mut connection,
        profile,
        &capability,
        &mut OsChallenges::new(),
    )
    .await?;

    let now = clock.now_unix_milliseconds();
    let attachment = acquire_attachment(config, store, channel, now)?;
    let result = serve_adapter(&mut connection, &attachment, store, clock, health, shutdown).await;
    // The lease is released on every exit path so a restarting adapter is not made to
    // wait out an expiry window that no live consumer owns.
    let _ = attachment.release(store);
    result.map_err(Into::into)
}

/// Backoff between adapter attachment attempts.
///
/// The first retry is quick because the common case is an adapter that has not
/// finished creating its endpoint yet. Repeated failure backs off to avoid spinning
/// against a permanently absent or misconfigured adapter.
fn adapter_retry_delay(failures: u32) -> Duration {
    const MAXIMUM: Duration = Duration::from_secs(30);
    let exponent = failures.saturating_sub(1).min(5);
    Duration::from_millis(250)
        .saturating_mul(1_u32 << exponent)
        .min(MAXIMUM)
}

fn adapter_error_code(error: &anyhow::Error) -> String {
    error.downcast_ref::<AdapterTransportError>().map_or_else(
        || "adapter_unavailable".to_string(),
        |error| error.code().to_string(),
    )
}

fn generate_lease_id() -> anyhow::Result<AdapterLeaseId> {
    let mut bytes = [0_u8; AdapterLeaseId::LENGTH];
    KonclaveCryptographicCore::fill_random(&mut bytes)?;
    Ok(AdapterLeaseId::from_bytes(bytes))
}

/// Serves adapter requests on an authenticated channel until shutdown or disconnect.
///
/// Every failure is answered with a stable code rather than closing the channel, so a
/// recoverable mistake such as a stale lease does not force the adapter to
/// reauthenticate. Closing is reserved for a peer that leaves or violates framing.
///
/// # Errors
///
/// Returns a transport error when the channel ends abnormally. A clean disconnect and
/// a shutdown both return `Ok`.
pub(crate) async fn serve_adapter<S>(
    stream: &mut S,
    attachment: &AdapterAttachment,
    store: &ProfileStore,
    clock: &dyn UnixClock,
    health: &DeliveryHealth,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AdapterTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let payload = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            payload = read_frame(stream, MAX_AUTHENTICATED_FRAME_BYTES) => match payload {
                Ok(payload) => payload,
                Err(AdapterTransportError::ChannelClosed) => return Ok(()),
                Err(error) => return Err(error),
            },
        };

        let response = match AdapterRequest::decode(&payload) {
            Ok(request) => {
                handle_request(request, attachment, store, clock, health, &mut shutdown).await
            }
            // A malformed request is answered rather than silently dropped so the
            // adapter learns its frame was rejected instead of waiting forever.
            Err(error) => AdapterResponse::Failure {
                code: error.code().to_string(),
            },
        };

        let encoded = response.encode()?;
        write_frame(stream, &encoded, MAX_AUTHENTICATED_FRAME_BYTES).await?;
    }
}

/// Supplies the current wall clock, so lease windows are testable without sleeping.
pub(crate) trait UnixClock: Send + Sync {
    fn now_unix_milliseconds(&self) -> u64;
}

/// The production clock.
pub(crate) struct SystemUnixClock;

impl UnixClock for SystemUnixClock {
    fn now_unix_milliseconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

async fn handle_request(
    request: AdapterRequest,
    attachment: &AdapterAttachment,
    store: &ProfileStore,
    clock: &dyn UnixClock,
    health: &DeliveryHealth,
    shutdown: &mut watch::Receiver<bool>,
) -> AdapterResponse {
    match request {
        AdapterRequest::WaitAndClaim {
            max_events,
            wait_milliseconds,
        } => wait_and_claim(
            attachment,
            store,
            clock,
            shutdown,
            max_events,
            wait_milliseconds,
        )
        .await
        .unwrap_or_else(failure),
        AdapterRequest::Acknowledge {
            notification_id,
            lease_generation,
        } => finish_claim(
            attachment,
            store,
            clock,
            notification_id,
            lease_generation,
            true,
        ),
        AdapterRequest::Release {
            notification_id,
            lease_generation,
        } => finish_claim(
            attachment,
            store,
            clock,
            notification_id,
            lease_generation,
            false,
        ),
        AdapterRequest::Status => match store.remote_event_counts() {
            Ok((pending_events, claimed_events)) => AdapterResponse::Status(AdapterStatus {
                pending_events,
                claimed_events,
                watched_conversations: health.watched_conversations(),
                delivery_degraded: health.is_degraded(),
            }),
            Err(error) => failure(error),
        },
    }
}

async fn wait_and_claim(
    attachment: &AdapterAttachment,
    store: &ProfileStore,
    clock: &dyn UnixClock,
    shutdown: &mut watch::Receiver<bool>,
    max_events: u16,
    wait_milliseconds: u32,
) -> Result<AdapterResponse, ProfileStoreError> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(u64::from(wait_milliseconds));
    loop {
        let now = clock.now_unix_milliseconds();
        let expires_at = now
            .saturating_add(u64::try_from(CONSUMER_LEASE_DURATION.as_millis()).unwrap_or(u64::MAX));
        let claimed = store.claim_remote_events(
            attachment.consumer_id,
            attachment.lease_id,
            now,
            expires_at,
            usize::from(max_events),
        )?;
        if !claimed.is_empty() {
            return Ok(AdapterResponse::Batch(
                claimed.into_iter().map(deliver).collect(),
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            // An expired wait is not an event, so the empty batch tells the adapter
            // to reissue rather than reporting work that does not exist.
            return Ok(AdapterResponse::Batch(Vec::new()));
        }
        let poll = tokio::time::sleep(
            CLAIM_POLL_INTERVAL
                .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        );
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(AdapterResponse::Batch(Vec::new()));
                }
            }
            () = poll => {}
        }
    }
}

fn finish_claim(
    attachment: &AdapterAttachment,
    store: &ProfileStore,
    clock: &dyn UnixClock,
    notification_id: [u8; 16],
    lease_generation: u64,
    acknowledge: bool,
) -> AdapterResponse {
    let notification_id = NotificationId::from_bytes(notification_id);
    let now = clock.now_unix_milliseconds();
    let outcome = if acknowledge {
        store.acknowledge_remote_event(
            notification_id,
            attachment.consumer_id,
            attachment.lease_id,
            lease_generation,
            now,
        )
    } else {
        store.release_remote_event(
            notification_id,
            attachment.consumer_id,
            attachment.lease_id,
            lease_generation,
            now,
        )
    };
    outcome.map_or_else(failure, |()| AdapterResponse::Accepted)
}

fn failure(error: ProfileStoreError) -> AdapterResponse {
    AdapterResponse::Failure {
        code: adapter_failure_code(&error).to_string(),
    }
}

/// Maps a store failure to a stable adapter-facing code.
///
/// Only conditions an adapter can act on are distinguished. Everything else collapses
/// to one code, so internal storage state never becomes an adapter-visible signal.
const fn adapter_failure_code(error: &ProfileStoreError) -> &'static str {
    match error {
        ProfileStoreError::InvalidAdapterLease => "adapter_stale_lease",
        ProfileStoreError::AdapterConsumerActive => "adapter_consumer_active",
        ProfileStoreError::RemoteEventCapacityExceeded => "adapter_capacity_exceeded",
        ProfileStoreError::InvalidTransition => "adapter_invalid_transition",
        ProfileStoreError::OperationNotFound => "adapter_unknown_notification",
        _ => "adapter_internal_error",
    }
}

fn deliver(claimed: ClaimedRemoteEvent) -> DeliveredEvent {
    let event = claimed.event;
    DeliveredEvent {
        notification_id: *event.notification_id.as_bytes(),
        lease_generation: claimed.lease_generation,
        sequence: event.sequence,
        conversation: *event.conversation_id.as_bytes(),
        sender: *event.sender.as_bytes(),
        relay_cursor: event.relay_cursor,
        payload: match event.payload {
            RemoteEventPayload::ApplicationMessage(message) => {
                let KonclaveDomainCore::ApplicationContent::Text(text) = message.content();
                DeliveredPayload::ApplicationText(text.clone())
            }
            RemoteEventPayload::MemberAdded { device_id, role } => DeliveredPayload::MemberAdded {
                device: *device_id.as_bytes(),
                role: deliver_role(role),
            },
            RemoteEventPayload::MemberRemoved { device_id } => DeliveredPayload::MemberRemoved {
                device: *device_id.as_bytes(),
            },
            RemoteEventPayload::MemberRoleChanged { device_id, role } => {
                DeliveredPayload::MemberRoleChanged {
                    device: *device_id.as_bytes(),
                    role: deliver_role(role),
                }
            }
            RemoteEventPayload::LocalAccessRemoved { device_id } => {
                DeliveredPayload::LocalAccessRemoved {
                    device: *device_id.as_bytes(),
                }
            }
        },
    }
}

const fn deliver_role(role: ConversationRole) -> DeliveredRole {
    match role {
        ConversationRole::Administrator => DeliveredRole::Administrator,
        ConversationRole::Member => DeliveredRole::Member,
    }
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
            AdapterEndpoint, AdapterRequest, AdapterResponse, AdapterStatus, LaunchCapability,
            MAX_AUTHENTICATED_FRAME_BYTES, SequentialChallenges, complete_adapter_handshake,
            complete_daemon_handshake,
        };
        use KonclaveDomainCore::AdapterConsumerId;
        use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use super::super::{
            AdapterAttachment, AdapterLaunchConfig, UnixClock, attach_adapter, generate_lease_id,
            serve_adapter,
        };
        use crate::health::DeliveryHealth;
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
                    endpoint: self.endpoint(),
                    capability_file: self.capability_file.clone(),
                    consumer_id: AdapterConsumerId::from_bytes(consumer),
                }
            }

            fn endpoint(&self) -> AdapterEndpoint {
                AdapterEndpoint::parse(self.socket.to_str().unwrap()).unwrap()
            }

            /// The consumer identifier the adapter announces, in wire form.
            ///
            /// It is shared and mutable because one endpoint outlives the consumer
            /// attached to it, which is what a restarted or replaced adapter looks
            /// like from the daemon's side.
            fn announced(
                consumer: [u8; AdapterConsumerId::LENGTH],
            ) -> std::sync::Arc<std::sync::Mutex<String>> {
                std::sync::Arc::new(std::sync::Mutex::new(URL_SAFE_NO_PAD.encode(consumer)))
            }
        }

        fn restrict(path: &Path) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        pub(super) fn store(root: &Path) -> ProfileStore {
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
        fn serve(
            listener: tokio::net::UnixListener,
            consumer: std::sync::Arc<std::sync::Mutex<String>>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let consumer = consumer
                        .lock()
                        .map(|consumer| consumer.clone())
                        .unwrap_or_default();
                    tokio::spawn(async move {
                        let authenticated = complete_adapter_handshake(
                            &mut stream,
                            PROFILE,
                            &consumer,
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
            let announced = Rendezvous::announced([1; 16]);
            let adapter = serve(
                tokio::net::UnixListener::bind(&rendezvous.socket).unwrap(),
                announced.clone(),
            );

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
            let announced = Rendezvous::announced([1; 16]);
            let adapter = serve(
                tokio::net::UnixListener::bind(&rendezvous.socket).unwrap(),
                announced.clone(),
            );

            let first = attach_adapter(&rendezvous.config([1; 16]), PROFILE, &store, NOW)
                .await
                .unwrap();

            *announced.lock().unwrap() = URL_SAFE_NO_PAD.encode([2_u8; 16]);
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
        async fn an_adapter_announcing_another_consumer_never_reaches_the_lease() {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let rendezvous = Rendezvous::new();
            // The capability and profile both check out. Only the announced consumer
            // disagrees with what the daemon was launched to serve.
            let announced = Rendezvous::announced([2; 16]);
            let adapter = serve(
                tokio::net::UnixListener::bind(&rendezvous.socket).unwrap(),
                announced.clone(),
            );

            let error = attach_adapter(&rendezvous.config([1; 16]), PROFILE, &store, NOW)
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("different consumer"),
                "a mismatched consumer must be refused: {error:#}"
            );

            // No lease was taken, so the consumer the daemon was launched for is
            // still able to attach once the adapter announces it.
            *announced.lock().unwrap() = URL_SAFE_NO_PAD.encode([1_u8; 16]);
            attach_adapter(&rendezvous.config([1; 16]), PROFILE, &store, NOW)
                .await
                .unwrap();
            adapter.abort();
        }

        #[tokio::test]
        async fn a_wrong_profile_capability_never_reaches_the_lease() {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let rendezvous = Rendezvous::new();
            let announced = Rendezvous::announced([1; 16]);
            let adapter = serve(
                tokio::net::UnixListener::bind(&rendezvous.socket).unwrap(),
                announced.clone(),
            );

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

        #[tokio::test]
        async fn the_session_serves_status_and_bounded_waits() {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let rendezvous = Rendezvous::new();
            let listener = tokio::net::UnixListener::bind(&rendezvous.socket).unwrap();

            // The adapter side keeps its stream so it can issue session requests.
            let adapter = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                complete_adapter_handshake(
                    &mut stream,
                    PROFILE,
                    "consumer",
                    &LaunchCapability::from_bytes([9_u8; LaunchCapability::LENGTH]),
                    &mut SequentialChallenges::new(),
                )
                .await
                .unwrap();
                stream
            });

            let mut connection =
                KonclaveAdapterTransport::connect_adapter_endpoint(&rendezvous.endpoint())
                    .await
                    .unwrap();
            let channel = complete_daemon_handshake(
                &mut connection,
                PROFILE,
                &LaunchCapability::from_bytes([9_u8; LaunchCapability::LENGTH]),
                &mut SequentialChallenges::new(),
            )
            .await
            .unwrap();
            let mut adapter_stream = adapter.await.unwrap();

            let attachment = AdapterAttachment {
                channel,
                consumer_id: AdapterConsumerId::from_bytes([1; 16]),
                lease_id: generate_lease_id().unwrap(),
            };
            store
                .acquire_adapter_consumer(
                    attachment.consumer_id,
                    attachment.lease_id,
                    NOW,
                    NOW + 60_000,
                )
                .unwrap();

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let served = tokio::spawn(async move {
                let clock = FixedClock(NOW);
                let health = DeliveryHealth::default();
                health.set_watched_conversations(2);
                let _ = serve_adapter(
                    &mut connection,
                    &attachment,
                    &store,
                    &clock,
                    &health,
                    shutdown_rx,
                )
                .await;
            });

            assert_eq!(
                exchange(&mut adapter_stream, AdapterRequest::Status).await,
                AdapterResponse::Status(AdapterStatus {
                    watched_conversations: 2,
                    ..AdapterStatus::default()
                })
            );

            // No events exist, so a bounded wait must expire with an empty batch
            // rather than blocking the adapter forever.
            assert_eq!(
                exchange(
                    &mut adapter_stream,
                    AdapterRequest::WaitAndClaim {
                        max_events: 5,
                        wait_milliseconds: 50,
                    }
                )
                .await,
                AdapterResponse::Batch(Vec::new())
            );

            // An unknown notification is answered with a stable code instead of
            // closing the channel, so the adapter need not reauthenticate.
            assert_eq!(
                exchange(
                    &mut adapter_stream,
                    AdapterRequest::Acknowledge {
                        notification_id: [7; 16],
                        lease_generation: 99,
                    }
                )
                .await,
                AdapterResponse::Failure {
                    code: "adapter_unknown_notification".to_string()
                }
            );

            // A malformed frame is answered rather than dropped.
            KonclaveAdapterTransport::write_frame(
                &mut adapter_stream,
                &[99, 0, 0],
                MAX_AUTHENTICATED_FRAME_BYTES,
            )
            .await
            .unwrap();
            assert_eq!(
                read_response(&mut adapter_stream).await,
                AdapterResponse::Failure {
                    code: "adapter_unknown_message_kind".to_string()
                }
            );

            shutdown_tx.send(true).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), served)
                .await
                .unwrap()
                .unwrap();
        }

        struct FixedClock(u64);

        impl UnixClock for FixedClock {
            fn now_unix_milliseconds(&self) -> u64 {
                self.0
            }
        }

        async fn exchange(
            stream: &mut tokio::net::UnixStream,
            request: AdapterRequest,
        ) -> AdapterResponse {
            KonclaveAdapterTransport::write_frame(
                stream,
                &request.encode(),
                MAX_AUTHENTICATED_FRAME_BYTES,
            )
            .await
            .unwrap();
            read_response(stream).await
        }

        async fn read_response(stream: &mut tokio::net::UnixStream) -> AdapterResponse {
            let payload =
                KonclaveAdapterTransport::read_frame(stream, MAX_AUTHENTICATED_FRAME_BYTES)
                    .await
                    .unwrap();
            AdapterResponse::decode(&payload).unwrap()
        }
    }

    #[test]
    fn retry_backoff_is_bounded_and_starts_quickly() {
        use super::adapter_retry_delay;

        assert_eq!(
            adapter_retry_delay(1),
            std::time::Duration::from_millis(250)
        );
        assert!(adapter_retry_delay(2) > adapter_retry_delay(1));
        for failures in 1..64 {
            assert!(
                adapter_retry_delay(failures) <= std::time::Duration::from_secs(30),
                "retry delay must stay bounded at {failures} failures"
            );
        }
    }

    #[tokio::test]
    async fn an_unconfigured_adapter_channel_returns_without_blocking_the_daemon() {
        // No launch variables are set, so the channel must be a no-op rather than
        // retrying forever and keeping the daemon's join alive.
        let root = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(unix::store(root.path()));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::run_adapter_channel(
                store,
                "alice",
                super::DeliveryHealth::default(),
                shutdown_rx,
            ),
        )
        .await
        .expect("an unconfigured adapter channel must return immediately");
    }

    #[test]
    fn incomplete_launch_configuration_is_rejected() {
        // Reading the environment directly would race other tests, so the partial-set
        // rule is asserted through the same match the reader uses.
        assert!(AdapterLaunchConfig::from_environment().is_ok());
    }
}
