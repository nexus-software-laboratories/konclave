use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use KonclaveClientLibrary::{KonclaveClientError, RelayTransport};
use KonclaveDomainCore::ConversationId;
use anyhow::Context;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{self, MissedTickBehavior, timeout};

use crate::application::{ApplicationService, ApplicationServiceError, WatchConnectionExit};
use crate::conversation::ConversationCoordinatorError;
use crate::health::DeliveryHealth;
use crate::persistence::ProfileStoreError;

const CONVERSATION_PAGE_SIZE: usize = 100;
const MAX_SUPERVISED_CONVERSATIONS: usize = 32;
const MAXIMUM_RETRY_JITTER_MILLISECONDS: u64 = 250;

#[derive(Clone, Copy)]
struct SupervisorConfig {
    discovery_interval: Duration,
    retry_initial: Duration,
    retry_maximum: Duration,
    shutdown_timeout: Duration,
    maximum_conversations: usize,
}

impl SupervisorConfig {
    fn production(discovery_interval: Duration) -> Self {
        Self {
            discovery_interval,
            retry_initial: Duration::from_secs(1),
            retry_maximum: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(5),
            maximum_conversations: MAX_SUPERVISED_CONVERSATIONS,
        }
    }
}

/// Owns bounded relay-watch workers and their coordinated shutdown.
pub(crate) struct Service<T> {
    applications: Option<ApplicationService<T>>,
    config: SupervisorConfig,
    health: DeliveryHealth,
}

impl<T> Service<T>
where
    T: RelayTransport + 'static,
{
    #[must_use]
    pub(crate) fn new(
        applications: Option<ApplicationService<T>>,
        discovery_interval: Duration,
        health: DeliveryHealth,
    ) -> Self {
        Self {
            applications,
            config: SupervisorConfig::production(discovery_interval),
            health,
        }
    }

    /// Runs the watch supervisor until external shutdown or a permanent worker
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns a discovery, worker, shutdown, or join error. Transient relay failures
    /// reconnect inside their owned workers and do not become success-shaped exits.
    pub(crate) async fn run_until<F>(self, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()>,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut worker = tokio::spawn(run_supervisor(
            self.applications,
            self.config,
            self.health.clone(),
            shutdown_rx,
        ));
        tokio::pin!(shutdown);

        tokio::select! {
            result = &mut worker => {
                let _ = shutdown_tx.send(true);
                result.context("joining relay watch supervisor")?
            }
            _ = &mut shutdown => {
                shutdown_tx
                    .send(true)
                    .context("signaling relay watch supervisor shutdown")?;
                match timeout(self.config.shutdown_timeout, &mut worker).await {
                    Ok(result) => result.context("joining relay watch supervisor")?,
                    Err(_) => {
                        worker.abort();
                        let _ = worker.await;
                        Err(anyhow::anyhow!(
                            "relay watch supervisor exceeded its shutdown deadline"
                        ))
                    }
                }
            }
        }
    }
}

async fn run_supervisor<T>(
    applications: Option<ApplicationService<T>>,
    config: SupervisorConfig,
    health: DeliveryHealth,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    T: RelayTransport + 'static,
{
    let Some(applications) = applications else {
        wait_for_shutdown(&mut shutdown).await;
        return Ok(());
    };
    let mut ticker = time::interval(config.discovery_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Rediscovering only on the timer would leave a brand new conversation silent
    // for most of one interval, which is exactly the moment two sessions are waiting
    // on each other. The timer still runs, so a missed signal costs latency only.
    let joined = applications.membership_changed();
    let mut workers = JoinSet::new();
    let mut active = HashSet::new();

    loop {
        let discover = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                false
            }
            result = workers.join_next(), if !workers.is_empty() => {
                let (conversation_id, result) = result
                    .context("relay watch worker set ended unexpectedly")?
                    .context("joining relay watch worker")?;
                active.remove(&conversation_id);
                health.set_watched_conversations(active.len());
                match result? {
                    WatchConnectionExit::Shutdown | WatchConnectionExit::LocalMemberRemoved => {}
                }
                false
            }
            () = joined.notified() => true,
            _ = ticker.tick() => true,
        };

        if discover {
            let conversations =
                discover_watchable_conversations(&applications, config.maximum_conversations)
                    .await?;
            for conversation_id in conversations {
                if active.insert(conversation_id) {
                    let applications = applications.clone();
                    let shutdown = shutdown.clone();
                    let health = health.clone();
                    workers.spawn(async move {
                        (
                            conversation_id,
                            run_watch_worker(
                                applications,
                                conversation_id,
                                config,
                                health,
                                shutdown,
                            )
                            .await,
                        )
                    });
                }
            }
            health.set_watched_conversations(active.len());
        }
    }

    while let Some(result) = workers.join_next().await {
        let (_, worker_result) = result.context("joining relay watch worker during shutdown")?;
        match worker_result? {
            WatchConnectionExit::Shutdown | WatchConnectionExit::LocalMemberRemoved => {}
        }
    }
    Ok(())
}

async fn discover_watchable_conversations<T>(
    applications: &ApplicationService<T>,
    maximum: usize,
) -> Result<Vec<ConversationId>, ApplicationServiceError>
where
    T: RelayTransport + 'static,
{
    let mut after = None;
    let mut watchable = Vec::new();
    loop {
        let page = applications
            .conversation_page(after, CONVERSATION_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            break;
        }
        let page_length = page.len();
        for conversation_id in page {
            after = Some(conversation_id);
            if applications.is_local_member(conversation_id).await? {
                if watchable.len() == maximum {
                    return Err(ApplicationServiceError::WatchCapacityExceeded);
                }
                watchable.push(conversation_id);
            }
        }
        if page_length < CONVERSATION_PAGE_SIZE {
            break;
        }
    }
    Ok(watchable)
}

async fn run_watch_worker<T>(
    applications: ApplicationService<T>,
    conversation_id: ConversationId,
    config: SupervisorConfig,
    health: DeliveryHealth,
    mut shutdown: watch::Receiver<bool>,
) -> Result<WatchConnectionExit, ApplicationServiceError>
where
    T: RelayTransport + 'static,
{
    let mut failures = 0_u32;
    loop {
        if *shutdown.borrow() {
            return Ok(WatchConnectionExit::Shutdown);
        }
        match applications
            .watch_connection_until(conversation_id, shutdown.clone())
            .await
        {
            Ok(exit) => {
                health.set_degraded(false);
                return Ok(exit);
            }
            Err(error) if is_transient_watch_error(&error) => {
                failures = failures.saturating_add(1);
                // Reconnecting or backpressured delivery is reported so an adapter can
                // surface the state instead of appearing idle while work is stalled.
                health.set_degraded(true);
                let delay = retry_delay(conversation_id, failures, config);
                tracing::warn!(
                    error_code = transient_watch_error_code(&error),
                    failure_count = failures,
                    retry_delay_milliseconds = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "relay watch reconnect scheduled"
                );
                tokio::select! {
                    _ = time::sleep(delay) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return Ok(WatchConnectionExit::Shutdown);
                        }
                    }
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn transient_watch_error_code(error: &ApplicationServiceError) -> &str {
    match error {
        ApplicationServiceError::Relay(error) => error.code(),
        ApplicationServiceError::Conversation(ConversationCoordinatorError::Profile(
            ProfileStoreError::RemoteEventCapacityExceeded,
        )) => "remote_event_capacity",
        _ => "watch_retry",
    }
}

fn is_transient_watch_error(error: &ApplicationServiceError) -> bool {
    match error {
        ApplicationServiceError::Relay(
            KonclaveClientError::Timeout
            | KonclaveClientError::TransportUnavailable
            | KonclaveClientError::WatchClosed,
        ) => true,
        ApplicationServiceError::Relay(KonclaveClientError::WatchRejected {
            relay_code, ..
        }) => relay_code == "heartbeat_timeout",
        ApplicationServiceError::Relay(KonclaveClientError::RelayRejected { status, .. }) => {
            *status == 429 || *status >= 500
        }
        ApplicationServiceError::Conversation(ConversationCoordinatorError::Profile(
            ProfileStoreError::RemoteEventCapacityExceeded,
        )) => true,
        _ => false,
    }
}

fn retry_delay(
    conversation_id: ConversationId,
    failures: u32,
    config: SupervisorConfig,
) -> Duration {
    let exponent = failures.saturating_sub(1).min(5);
    let multiplier = 1_u32 << exponent;
    let ceiling = config
        .retry_maximum
        .saturating_sub(Duration::from_millis(MAXIMUM_RETRY_JITTER_MILLISECONDS));
    let base = config
        .retry_initial
        .saturating_mul(multiplier)
        .min(ceiling)
        .min(config.retry_maximum);
    let identifier = conversation_id.as_bytes();
    let jitter_milliseconds = u64::from(u16::from_be_bytes([identifier[0], identifier[1]]))
        % MAXIMUM_RETRY_JITTER_MILLISECONDS;
    base.saturating_add(Duration::from_millis(jitter_milliseconds))
        .min(config.retry_maximum)
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use KonclaveClientLibrary::{KonclaveClientError, RelayTransport, RelayWatchSession};
    use KonclaveDomainCore::{
        AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest, StoredRelayEnvelope,
    };
    use KonclaveSecretStorage::{
        ExternalWrappingKeyProvider, SealedSqliteMlsStorage, SecretSealer,
    };
    use async_trait::async_trait;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::timeout;

    use super::*;
    use crate::conversation::ConversationCoordinator;
    use crate::health::DeliveryHealth;
    use crate::persistence::{LockedProfile, ProfileId};

    struct FailingWatchRelay {
        attempts: mpsc::Sender<()>,
    }

    struct UnauthorizedWatchRelay;

    #[async_trait]
    impl RelayTransport for UnauthorizedWatchRelay {
        async fn submit(
            &self,
            _envelope: &RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            Err(KonclaveClientError::TransportUnavailable)
        }

        async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
            Ok(ReplayPage::new(Vec::new(), request.after_cursor(), false).unwrap())
        }

        async fn acknowledge(
            &self,
            request: AcknowledgeRequest,
        ) -> Result<AcknowledgeRequest, KonclaveClientError> {
            Ok(request)
        }

        async fn connect_watch(
            &self,
            _request: ReplayRequest,
        ) -> Result<RelayWatchSession, KonclaveClientError> {
            Err(KonclaveClientError::WatchRejected {
                close_code: 4403,
                relay_code: "unauthorized".to_string(),
            })
        }
    }

    #[async_trait]
    impl RelayTransport for FailingWatchRelay {
        async fn submit(
            &self,
            _envelope: &RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            Err(KonclaveClientError::TransportUnavailable)
        }

        async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
            Ok(ReplayPage::new(Vec::new(), request.after_cursor(), false).unwrap())
        }

        async fn acknowledge(
            &self,
            request: AcknowledgeRequest,
        ) -> Result<AcknowledgeRequest, KonclaveClientError> {
            Ok(request)
        }

        async fn connect_watch(
            &self,
            _request: ReplayRequest,
        ) -> Result<RelayWatchSession, KonclaveClientError> {
            let _ = self.attempts.try_send(());
            Err(KonclaveClientError::TransportUnavailable)
        }
    }

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
    }

    fn coordinator(root: &Path, profile_name: &str) -> ConversationCoordinator {
        let locked = LockedProfile::acquire(root, ProfileId::parse(profile_name).unwrap()).unwrap();
        let mls_path = locked.mls_database_path();
        let profile_sealer = sealer();
        let mls_storage = SealedSqliteMlsStorage::open(&mls_path, profile_sealer.share()).unwrap();
        let store = locked.open_store(profile_sealer).unwrap();
        let device = store.load_or_create_device().unwrap();
        ConversationCoordinator::new(store, mls_storage, device)
    }

    #[tokio::test]
    async fn idle_service_shuts_down_without_a_relay() {
        let service = Service::<FailingWatchRelay> {
            applications: None,
            config: SupervisorConfig {
                discovery_interval: Duration::from_millis(10),
                retry_initial: Duration::from_millis(10),
                retry_maximum: Duration::from_millis(20),
                shutdown_timeout: Duration::from_secs(1),
                maximum_conversations: 2,
            },
            health: DeliveryHealth::default(),
        };
        service.run_until(async {}).await.unwrap();
    }

    #[tokio::test]
    async fn permanent_discovery_capacity_failure_is_observed() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "watch-capacity");
        coordinator.create().unwrap();
        let (attempt_tx, _attempt_rx) = mpsc::channel(1);
        let service = Service {
            applications: Some(ApplicationService::new(
                coordinator,
                FailingWatchRelay {
                    attempts: attempt_tx,
                },
            )),
            config: SupervisorConfig {
                discovery_interval: Duration::from_millis(10),
                retry_initial: Duration::from_millis(10),
                retry_maximum: Duration::from_millis(20),
                shutdown_timeout: Duration::from_secs(1),
                maximum_conversations: 0,
            },
            health: DeliveryHealth::default(),
        };

        let error = timeout(
            Duration::from_secs(1),
            service.run_until(std::future::pending()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.chain().any(|cause| {
            cause
                .to_string()
                .contains("watchable conversation capacity")
        }));
    }

    #[tokio::test(start_paused = true)]
    async fn transient_watch_failures_retry_and_shutdown_is_observed() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "watch-retry");
        coordinator.create().unwrap();
        let (attempt_tx, mut attempt_rx) = mpsc::channel(4);
        let applications = ApplicationService::new(
            coordinator,
            FailingWatchRelay {
                attempts: attempt_tx,
            },
        );
        let service = Service {
            applications: Some(applications),
            config: SupervisorConfig {
                discovery_interval: Duration::from_millis(10),
                retry_initial: Duration::from_secs(1),
                retry_maximum: Duration::from_secs(2),
                shutdown_timeout: Duration::from_secs(1),
                maximum_conversations: 2,
            },
            health: DeliveryHealth::default(),
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(service.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        attempt_rx.recv().await.unwrap();
        time::advance(Duration::from_secs(2)).await;
        attempt_rx.recv().await.unwrap();
        shutdown_tx.send(()).unwrap();

        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_watch_rejection_stops_the_daemon_without_retrying() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "watch-unauthorized");
        coordinator.create().unwrap();
        let service = Service {
            applications: Some(ApplicationService::new(coordinator, UnauthorizedWatchRelay)),
            config: SupervisorConfig {
                discovery_interval: Duration::from_secs(30),
                retry_initial: Duration::from_secs(1),
                retry_maximum: Duration::from_secs(30),
                shutdown_timeout: Duration::from_secs(5),
                maximum_conversations: 2,
            },
            health: DeliveryHealth::default(),
        };

        let error = timeout(
            Duration::from_secs(1),
            service.run_until(std::future::pending()),
        )
        .await
        .unwrap()
        .unwrap_err();

        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("unauthorized")),
            "permanent rejection must surface instead of retrying: {error:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn discovers_conversations_created_after_startup() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "watch-discovery");
        let (attempt_tx, mut attempt_rx) = mpsc::channel(2);
        let applications = ApplicationService::new(
            coordinator.clone(),
            FailingWatchRelay {
                attempts: attempt_tx,
            },
        );
        let service = Service {
            applications: Some(applications),
            config: SupervisorConfig {
                discovery_interval: Duration::from_secs(1),
                retry_initial: Duration::from_secs(10),
                retry_maximum: Duration::from_secs(10),
                shutdown_timeout: Duration::from_secs(1),
                maximum_conversations: 2,
            },
            health: DeliveryHealth::default(),
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(service.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        tokio::task::yield_now().await;
        assert!(attempt_rx.try_recv().is_err());
        coordinator.create().unwrap();
        time::advance(Duration::from_secs(1)).await;
        attempt_rx.recv().await.unwrap();
        shutdown_tx.send(()).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_conversation_is_watched_without_waiting_for_the_next_sweep() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = coordinator(root.path(), "watch-prompt");
        let (attempt_tx, mut attempt_rx) = mpsc::channel(2);
        let applications = ApplicationService::new(
            coordinator.clone(),
            FailingWatchRelay {
                attempts: attempt_tx,
            },
        );
        let service = Service {
            applications: Some(applications),
            config: SupervisorConfig {
                // Far longer than the test will run, so reaching the relay proves the
                // join signal woke discovery rather than the periodic sweep.
                discovery_interval: Duration::from_secs(3_600),
                retry_initial: Duration::from_secs(10),
                retry_maximum: Duration::from_secs(10),
                shutdown_timeout: Duration::from_secs(1),
                maximum_conversations: 2,
            },
            health: DeliveryHealth::default(),
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(service.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        tokio::task::yield_now().await;
        assert!(attempt_rx.try_recv().is_err());
        coordinator.create().unwrap();
        timeout(Duration::from_secs(5), attempt_rx.recv())
            .await
            .expect("a new conversation must be watched promptly")
            .unwrap();
        shutdown_tx.send(()).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn retry_delay_is_bounded_and_conversation_stable() {
        let conversation_id = ConversationId::from_bytes([7; ConversationId::LENGTH]);
        let config = SupervisorConfig {
            discovery_interval: Duration::from_secs(1),
            retry_initial: Duration::from_secs(1),
            retry_maximum: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(1),
            maximum_conversations: 1,
        };
        assert_eq!(
            retry_delay(conversation_id, 1, config),
            retry_delay(conversation_id, 1, config)
        );
        assert!(retry_delay(conversation_id, 100, config) <= config.retry_maximum);
        assert!(retry_delay(conversation_id, 1, config) >= config.retry_initial);
    }

    #[test]
    fn saturated_retry_delay_keeps_conversations_apart() {
        let config = SupervisorConfig {
            discovery_interval: Duration::from_secs(1),
            retry_initial: Duration::from_secs(1),
            retry_maximum: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(1),
            maximum_conversations: 1,
        };
        let mut delays = Vec::new();
        for identifier in 0..64_u16 {
            let mut bytes = [0_u8; ConversationId::LENGTH];
            bytes[..2].copy_from_slice(&identifier.wrapping_mul(1031).to_be_bytes());
            let delay = retry_delay(ConversationId::from_bytes(bytes), 100, config);
            assert!(delay <= config.retry_maximum);
            assert!(
                delay
                    >= config
                        .retry_maximum
                        .saturating_sub(Duration::from_millis(MAXIMUM_RETRY_JITTER_MILLISECONDS))
            );
            delays.push(delay);
        }
        delays.sort_unstable();
        delays.dedup();
        assert!(
            delays.len() > 1,
            "saturated backoff must not collapse every conversation onto one instant"
        );
    }
}
