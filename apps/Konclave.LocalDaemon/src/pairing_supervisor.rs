use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveClientLibrary::{KonclaveClientError, RelayTransport};
use KonclaveDomainCore::DeviceId;
use tokio::time;

use crate::application::ApplicationServiceError;
use crate::pairing_service::{PairingService, PairingServiceError};
use crate::service::bounded_retry_delay;

#[derive(Clone, Copy)]
struct PairingSupervisorConfig {
    poll_interval: Duration,
    retry_initial: Duration,
    retry_maximum: Duration,
}

impl PairingSupervisorConfig {
    const fn production() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            retry_initial: Duration::from_secs(1),
            retry_maximum: Duration::from_secs(30),
        }
    }
}

/// Owns automatic bounded pairing replay, recovery, and retry.
pub(crate) struct PairingSupervisor<T> {
    pairings: Option<PairingService<T>>,
    stable_retry_seed: DeviceId,
    config: PairingSupervisorConfig,
}

impl<T> PairingSupervisor<T>
where
    T: RelayTransport + 'static,
{
    #[must_use]
    pub(crate) fn new(pairings: Option<PairingService<T>>, stable_retry_seed: DeviceId) -> Self {
        Self {
            pairings,
            stable_retry_seed,
            config: PairingSupervisorConfig::production(),
        }
    }

    /// Runs until shutdown or a permanent pairing failure.
    ///
    /// Transient relay failures back off without ending the daemon. Dropping an
    /// in-flight sweep for shutdown is safe because every external side effect has a
    /// durable exact retry identity.
    ///
    /// # Errors
    ///
    /// Returns a clock or permanent pairing state, authorization, protocol, MLS, or
    /// persistence failure.
    pub(crate) async fn run_until<F>(self, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()>,
    {
        let Some(pairings) = self.pairings else {
            shutdown.await;
            return Ok(());
        };
        tokio::pin!(shutdown);
        let mut delay = Duration::ZERO;
        let mut failures = 0_u32;
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => return Ok(()),
                () = time::sleep(delay) => {}
            }
            let now = current_unix_seconds()?;
            let result = tokio::select! {
                biased;
                _ = &mut shutdown => return Ok(()),
                result = pairings.sync_active_once(now) => result,
            };
            match result {
                Ok(_) => {
                    failures = 0;
                    delay = self.config.poll_interval;
                }
                // The profile stopped admitting operations, which is a coordinated
                // close rather than a pairing failure. Every record stays durable for
                // the next open. The refusal is reported the same way whether the
                // sweep itself was refused or a nested application operation was.
                Err(error) if is_coordinated_profile_stop(&error) => return Ok(()),
                Err(error) if is_transient_pairing_error(&error) => {
                    failures = failures.saturating_add(1);
                    delay = bounded_retry_delay(
                        self.stable_retry_seed.as_bytes(),
                        failures,
                        self.config.retry_initial,
                        self.config.retry_maximum,
                    );
                    tracing::warn!(
                        error_code = transient_pairing_error_code(&error),
                        failure_count = failures,
                        retry_delay_milliseconds =
                            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "pairing retry scheduled"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn current_unix_seconds() -> anyhow::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| anyhow::anyhow!("system time is unavailable"))
}

fn is_transient_pairing_error(error: &PairingServiceError) -> bool {
    match error {
        PairingServiceError::Client(error)
        | PairingServiceError::Application(ApplicationServiceError::Relay(error)) => {
            is_transient_client_error(error)
        }
        _ => false,
    }
}

fn is_transient_client_error(error: &KonclaveClientError) -> bool {
    match error {
        KonclaveClientError::Timeout | KonclaveClientError::TransportUnavailable => true,
        KonclaveClientError::RelayRejected { status, relay_code } => {
            *status == 429 || *status >= 500 || relay_code == "relay_stale_epoch"
        }
        _ => false,
    }
}

/// Reports whether a pairing failure is really this profile closing.
///
/// A sweep can be refused directly, or a nested application operation can be refused
/// inside it and surface wrapped. Both mean the same thing: the profile stopped
/// admitting operations, and every pairing record stays durable for the next open.
fn is_coordinated_profile_stop(error: &PairingServiceError) -> bool {
    matches!(
        error,
        PairingServiceError::ProfileClosing
            | PairingServiceError::Application(ApplicationServiceError::ProfileClosing)
    )
}

fn transient_pairing_error_code(error: &PairingServiceError) -> &str {
    match error {
        PairingServiceError::Client(error)
        | PairingServiceError::Application(ApplicationServiceError::Relay(error)) => error.code(),
        _ => "pairing_retry",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use KonclaveClientLibrary::{RelayEndpoint, RelayWatchSession};
    use KonclaveDomainCore::{
        AcknowledgeRequest, ConversationRole, RelayEnvelope, ReplayPage, ReplayRequest,
        StoredRelayEnvelope,
    };
    use async_trait::async_trait;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::timeout;

    use super::*;
    use crate::activity::ProfileActivity;
    use crate::application::ApplicationService;
    use crate::service::tests::coordinator;

    struct FailingPairingRelay {
        attempts: mpsc::Sender<()>,
        permanent: bool,
        activity: ProfileActivity,
        observed_in_flight: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RelayTransport for FailingPairingRelay {
        async fn submit(
            &self,
            _: &RelayEnvelope,
        ) -> Result<StoredRelayEnvelope, KonclaveClientError> {
            Err(KonclaveClientError::TransportUnavailable)
        }

        async fn replay(&self, _: ReplayRequest) -> Result<ReplayPage, KonclaveClientError> {
            // Recorded from inside the sweep, which is the only moment the profile is
            // genuinely busy with pairing work.
            self.observed_in_flight
                .fetch_max(self.activity.in_flight(), Ordering::SeqCst);
            let _ = self.attempts.try_send(());
            if self.permanent {
                Err(KonclaveClientError::RelayRejected {
                    status: 403,
                    relay_code: "unauthorized".to_string(),
                })
            } else {
                Err(KonclaveClientError::TransportUnavailable)
            }
        }

        async fn acknowledge(
            &self,
            request: AcknowledgeRequest,
        ) -> Result<AcknowledgeRequest, KonclaveClientError> {
            Ok(request)
        }

        async fn connect_watch(
            &self,
            _: ReplayRequest,
        ) -> Result<RelayWatchSession, KonclaveClientError> {
            Err(KonclaveClientError::TransportUnavailable)
        }
    }

    async fn supervisor(
        permanent: bool,
    ) -> (
        tempfile::TempDir,
        PairingSupervisor<FailingPairingRelay>,
        mpsc::Receiver<()>,
        Arc<AtomicUsize>,
    ) {
        let root = tempfile::tempdir().unwrap();
        let conversations = coordinator(root.path(), "pairing-supervisor");
        let device_id = conversations.device_id().unwrap();
        let (attempts, receiver) = mpsc::channel(4);
        let observed_in_flight = Arc::new(AtomicUsize::new(0));
        let applications = ApplicationService::new(
            conversations.clone(),
            FailingPairingRelay {
                attempts,
                permanent,
                activity: conversations.activity().clone(),
                observed_in_flight: Arc::clone(&observed_in_flight),
            },
        );
        let pairings = PairingService::new(
            conversations,
            applications,
            RelayEndpoint::parse("https://relay.example.com").unwrap(),
        );
        let now = current_unix_seconds().unwrap();
        pairings
            .create_capability(ConversationRole::Member, now + 300, now)
            .await
            .unwrap();
        (
            root,
            PairingSupervisor {
                pairings: Some(pairings),
                stable_retry_seed: device_id,
                config: PairingSupervisorConfig {
                    poll_interval: Duration::from_secs(1),
                    retry_initial: Duration::from_secs(1),
                    retry_maximum: Duration::from_secs(2),
                },
            },
            receiver,
            observed_in_flight,
        )
    }

    #[tokio::test]
    async fn supervisor_without_relay_waits_for_shutdown() {
        PairingSupervisor::<FailingPairingRelay>::new(
            None,
            DeviceId::from_bytes([1; DeviceId::LENGTH]),
        )
        .run_until(async {})
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn transient_failures_back_off_and_shutdown_is_observed() {
        let (_root, supervisor, mut attempts, observed_in_flight) = supervisor(false).await;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        attempts.recv().await.unwrap();
        time::advance(Duration::from_secs(2)).await;
        attempts.recv().await.unwrap();
        shutdown_tx.send(()).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // A sweep is one of the operations the shared service must not evict through.
        assert!(
            observed_in_flight.load(Ordering::SeqCst) >= 1,
            "a pairing sweep must mark the profile busy while it runs"
        );
    }

    #[tokio::test]
    async fn permanent_relay_rejection_stops_the_supervisor() {
        let (_root, supervisor, _attempts, _in_flight) = supervisor(true).await;
        let error = timeout(
            Duration::from_secs(1),
            supervisor.run_until(std::future::pending()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("relay rejected"));
    }

    #[test]
    fn a_closing_profile_is_a_coordinated_stop_however_it_surfaces() {
        assert!(is_coordinated_profile_stop(
            &PairingServiceError::ProfileClosing
        ));
        assert!(is_coordinated_profile_stop(
            &PairingServiceError::Application(ApplicationServiceError::ProfileClosing)
        ));
        assert!(!is_coordinated_profile_stop(&PairingServiceError::Expired));
        assert!(!is_coordinated_profile_stop(
            &PairingServiceError::Application(ApplicationServiceError::Task)
        ));
        assert!(!is_coordinated_profile_stop(&PairingServiceError::Client(
            KonclaveClientError::TransportUnavailable
        )));
    }

    #[test]
    fn stale_epoch_is_retryable_but_authorization_rejection_is_permanent() {
        assert!(is_transient_client_error(
            &KonclaveClientError::RelayRejected {
                status: 409,
                relay_code: "relay_stale_epoch".to_string(),
            }
        ));
        assert!(!is_transient_client_error(
            &KonclaveClientError::RelayRejected {
                status: 403,
                relay_code: "unauthorized".to_string(),
            }
        ));
    }
}
