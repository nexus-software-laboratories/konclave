use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use KonclaveClientLibrary::RelayClient;
use anyhow::Context as _;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::activity::ProfileActivity;
use crate::adapter::AdapterLaunchConfig;
use crate::application::ApplicationService;
use crate::conversation::ConversationCoordinator;
use crate::health::DeliveryHealth;
use crate::pairing_service::PairingService;
use crate::service::Service;

/// How often relay watch supervision rediscovers this profile's conversations.
const RELAY_DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// How long the profile task set may take to drain after one component stops.
///
/// Every component already owns a bounded internal stop path, so exceeding this
/// deadline means a component is not observing shutdown at all. Aborting then is
/// preferable to holding the profile lock and its database handles open forever.
const PROFILE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// One fully initialized logical profile hosted by the daemon process.
pub(crate) struct ProfileRuntime {
    pub(crate) conversations: ConversationCoordinator,
    pub(crate) applications: Option<ApplicationService<RelayClient>>,
    pub(crate) pairings: Option<PairingService<RelayClient>>,
    pub(crate) allow_mcp_write: bool,
    pub(crate) profile_id: String,
}

/// The bound per-profile services an attached client is allowed to drive.
///
/// Every handle refers to exactly one profile's store, MLS state, identity, and relay
/// principal. Cloning shares that one profile rather than creating a second owner, so
/// a client holding these handles can never reach another profile's state.
#[derive(Clone)]
pub(crate) struct ProfileServices {
    profile_id: Arc<str>,
    conversations: ConversationCoordinator,
    applications: Option<ApplicationService<RelayClient>>,
    pairings: Option<PairingService<RelayClient>>,
    health: DeliveryHealth,
    allow_mcp_write: bool,
}

impl ProfileServices {
    /// Returns the durable identifier of the bound profile.
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }
    /// Returns the profile's conversation, membership, and pairing state owner.
    pub(crate) fn conversations(&self) -> &ConversationCoordinator {
        &self.conversations
    }

    /// Returns the relay-backed application service, when a relay is configured.
    pub(crate) fn applications(&self) -> Option<&ApplicationService<RelayClient>> {
        self.applications.as_ref()
    }

    /// Returns the relay-backed pairing service, when a relay is configured.
    pub(crate) fn pairings(&self) -> Option<&PairingService<RelayClient>> {
        self.pairings.as_ref()
    }

    /// Returns the profile's delivery health, owned by its watch supervisor.
    pub(crate) fn health(&self) -> &DeliveryHealth {
        &self.health
    }

    /// Returns the profile's in-flight operation signal.
    pub(crate) fn activity(&self) -> &ProfileActivity {
        self.conversations.activity()
    }

    /// Reports whether this profile authorizes state-changing local tool calls.
    pub(crate) fn allow_mcp_write(&self) -> bool {
        self.allow_mcp_write
    }
}

/// Prints only bounded routing state, never the profile's keys or plaintext.
///
/// These handles reach MLS state, sealed storage, and relay credentials. Formatting
/// them into a diagnostic would move secret state to a destination the threat model
/// does not trust.
impl core::fmt::Debug for ProfileServices {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProfileServices")
            .field("profile", &self.profile_id())
            .field("relay_configured", &self.applications.is_some())
            .finish_non_exhaustive()
    }
}

/// One supervised future built from a profile's own services and stop signal.
///
/// The profile task set is identical for every host. A process-specific surface, such
/// as the compatibility stdio host or a later client dispatcher, is expressed as an
/// attachment instead of a second copy of the lifecycle.
pub(crate) type ProfileAttachment = Box<
    dyn FnOnce(
            &ProfileServices,
            watch::Receiver<bool>,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send,
>;

/// Extra supervised work one host adds to the shared profile task set.
#[derive(Default)]
pub(crate) struct ProfileHostOptions {
    attachments: Vec<ProfileAttachment>,
}

impl ProfileHostOptions {
    /// Adds one supervised future to the profile task set.
    #[must_use]
    pub(crate) fn with_attachment(mut self, attachment: ProfileAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

/// Whether one profile's supervised task set is running, stopped, or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileRunState {
    /// The task set is supervising the profile.
    Running,
    /// The task set completed without a failure.
    Stopped,
    /// The task set ended with a failure its owner must observe.
    Failed,
}

/// One running profile: its bound services, its stop signal, and its owned tasks.
///
/// The task set is owned, never detached. Coordinated shutdown drains it and reports
/// its aggregated outcome; an uncoordinated drop, including one during a panic,
/// signals and aborts it instead of leaving supervised tasks and an exclusive profile
/// lock behind with no owner.
pub(crate) struct ProfileHost {
    services: ProfileServices,
    stop: watch::Sender<bool>,
    state: watch::Receiver<ProfileRunState>,
    tasks: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Drop for ProfileHost {
    fn drop(&mut self) {
        if let Some(tasks) = self.tasks.take() {
            let _ = self.stop.send(true);
            tasks.abort();
        }
    }
}

impl ProfileHost {
    /// Starts relay watch supervision, pairing supervision, and every attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile identity that seeds supervision cannot be
    /// read.
    pub(crate) fn start(
        runtime: ProfileRuntime,
        options: ProfileHostOptions,
    ) -> anyhow::Result<Self> {
        let ProfileRuntime {
            conversations,
            applications,
            pairings,
            allow_mcp_write,
            profile_id,
        } = runtime;
        let pairing_retry_seed = conversations
            .device_id()
            .context("loading pairing retry identity")?;
        let services = ProfileServices {
            profile_id: Arc::from(profile_id.as_str()),
            conversations,
            applications,
            pairings,
            health: DeliveryHealth::default(),
            allow_mcp_write,
        };

        let (stop_tx, stop_rx) = watch::channel(false);
        let (state_tx, state_rx) = watch::channel(ProfileRunState::Running);
        let mut tasks = JoinSet::new();

        let relay_applications = services.applications.clone();
        let relay_health = services.health.clone();
        let relay_shutdown = stop_rx.clone();
        tasks.spawn(async move {
            Service::new(relay_applications, RELAY_DISCOVERY_INTERVAL, relay_health)
                .run_until(wait_for_shutdown(relay_shutdown))
                .await
        });

        let pairing_service = services.pairings.clone();
        let pairing_shutdown = stop_rx.clone();
        tasks.spawn(async move {
            crate::pairing_supervisor::PairingSupervisor::new(pairing_service, pairing_retry_seed)
                .run_until(wait_for_shutdown(pairing_shutdown))
                .await
        });

        for attachment in options.attachments {
            tasks.spawn(attachment(&services, stop_rx.clone()));
        }

        let tasks = tokio::spawn(supervise(tasks, stop_tx.clone(), state_tx));
        Ok(Self {
            services,
            stop: stop_tx,
            state: state_rx,
            tasks: Some(tasks),
        })
    }

    /// Returns the bound services this profile exposes to its clients.
    pub(crate) fn services(&self) -> &ProfileServices {
        &self.services
    }

    /// Returns a receiver that observes this profile's supervised state.
    pub(crate) fn watch_run_state(&self) -> watch::Receiver<ProfileRunState> {
        self.state.clone()
    }

    /// Asks the task set to stop without waiting for it.
    ///
    /// Coordinated shutdown signals every profile before draining any of them, so a
    /// slow profile never serializes behind profiles that stop immediately.
    pub(crate) fn request_stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Stops the task set and reports its aggregated outcome exactly once.
    ///
    /// # Errors
    ///
    /// Returns the aggregated component failures, a shutdown-deadline failure, or a
    /// panic observed while joining the task set.
    pub(crate) async fn shutdown(mut self) -> anyhow::Result<()> {
        self.request_stop();
        let tasks = self
            .tasks
            .take()
            .context("the profile task set was already joined")?;
        join_profile_tasks(tasks.await)
    }

    /// Runs until the owning process requests shutdown or the task set ends first.
    ///
    /// # Errors
    ///
    /// Returns the aggregated task-set failure.
    pub(crate) async fn run_until<F>(mut self, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let completed = {
            let tasks = self
                .tasks
                .as_mut()
                .context("the profile task set was already joined")?;
            tokio::select! {
                joined = tasks => Some(joined),
                () = &mut shutdown => None,
            }
        };
        match completed {
            Some(joined) => {
                self.request_stop();
                // The handle is already resolved, so it must not be aborted or joined
                // a second time when this host drops.
                self.tasks = None;
                join_profile_tasks(joined)
            }
            None => self.shutdown().await,
        }
    }
}

/// Runs one profile through the legacy stdio MCP and adapter bindings.
///
/// The profile itself contains no process-global configuration. The compatibility
/// host supplies every binding explicitly, as attachments over the same profile task
/// set the shared-service supervisor uses, so the two hosts cannot drift apart.
pub(crate) async fn run_legacy_until<F>(
    profile: ProfileRuntime,
    adapter_config: Option<AdapterLaunchConfig>,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let options = ProfileHostOptions::default()
        .with_attachment(legacy_mcp_attachment())
        .with_attachment(legacy_adapter_attachment(adapter_config));
    ProfileHost::start(profile, options)?
        .run_until(shutdown)
        .await
}

/// Serves this profile's tools over the stdio transport the harness launched.
fn legacy_mcp_attachment() -> ProfileAttachment {
    Box::new(|services: &ProfileServices, stop| {
        let server = crate::mcp::StdioServer::new(
            services.conversations().clone(),
            services.applications().cloned(),
            services.pairings().cloned(),
            services.health().clone(),
            crate::mcp::local_stdio_authorization(services.allow_mcp_write()),
        );
        Box::pin(crate::mcp::run_stdio_server(server, stop))
    })
}

/// Maintains the outbound delivery channel to the adapter that launched this profile.
fn legacy_adapter_attachment(adapter_config: Option<AdapterLaunchConfig>) -> ProfileAttachment {
    Box::new(move |services: &ProfileServices, stop| {
        let store = services.conversations().store();
        let profile_id = services.profile_id().to_string();
        let health = services.health().clone();
        let idle = stop.clone();
        Box::pin(async move {
            crate::adapter::run_adapter_channel(adapter_config, store, &profile_id, health, stop)
                .await;
            // A session that launched no adapter still serves MCP and still recovers
            // relay state. Completing here would look like a component that finished
            // its work, which stops the whole profile.
            wait_for_shutdown(idle).await;
            Ok(())
        })
    })
}

/// Owns the profile task set until every component has stopped.
///
/// One component finishing means this profile is stopping: the compatibility host
/// ends when its stdio peer disconnects, and a permanent relay or pairing failure
/// must not leave a half-supervised profile behind. Remaining components are asked to
/// stop and are drained within a bounded deadline, so the profile lock and its
/// databases are always released.
async fn supervise(
    mut tasks: JoinSet<anyhow::Result<()>>,
    stop: watch::Sender<bool>,
    state: watch::Sender<ProfileRunState>,
) -> anyhow::Result<()> {
    let mut failures = Vec::new();
    if let Some(joined) = tasks.join_next().await {
        record_failure(joined, &mut failures);
    }
    let _ = stop.send(true);
    let drained = timeout(PROFILE_SHUTDOWN_TIMEOUT, async {
        while let Some(joined) = tasks.join_next().await {
            record_failure(joined, &mut failures);
        }
    })
    .await;
    if drained.is_err() {
        tasks.shutdown().await;
        failures.push(anyhow::anyhow!(
            "profile task set exceeded its shutdown deadline"
        ));
    }

    let outcome = aggregate_failures(failures);
    let _ = state.send(if outcome.is_ok() {
        ProfileRunState::Stopped
    } else {
        ProfileRunState::Failed
    });
    outcome
}

fn record_failure(
    joined: Result<anyhow::Result<()>, JoinError>,
    failures: &mut Vec<anyhow::Error>,
) {
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(error),
        Err(error) => {
            failures.push(anyhow::Error::new(error).context("joining a profile component"));
        }
    }
}

/// Reports every component failure through one error instead of the first one only.
fn aggregate_failures(failures: Vec<anyhow::Error>) -> anyhow::Result<()> {
    let mut failures = failures.into_iter();
    let Some(first) = failures.next() else {
        return Ok(());
    };
    let additional = failures
        .map(|error| format!("{error:#}"))
        .collect::<Vec<_>>();
    if additional.is_empty() {
        return Err(first);
    }
    Err(first.context(format!(
        "additional profile failures: {}",
        additional.join("; ")
    )))
}

fn join_profile_tasks(joined: Result<anyhow::Result<()>, JoinError>) -> anyhow::Result<()> {
    match joined {
        Ok(outcome) => outcome,
        Err(error) => Err(anyhow::Error::new(error).context("joining the profile task set")),
    }
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
    use std::time::Duration;

    use tokio::sync::{oneshot, watch};

    use super::{
        ProfileHost, ProfileHostOptions, ProfileRunState, ProfileServices,
        legacy_adapter_attachment,
    };
    use crate::runtime::initialize_profile;
    use crate::test_support::TestProfileRoot;

    #[tokio::test]
    async fn a_host_exposes_its_bound_profile_services() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("bound")).await.unwrap();
        let expected_device = runtime.conversations.device_id().unwrap();

        let host = ProfileHost::start(runtime, ProfileHostOptions::default()).unwrap();

        assert_eq!(host.services().profile_id(), "bound");
        assert_eq!(
            host.services().conversations().device_id().unwrap(),
            expected_device
        );
        assert!(host.services().applications().is_none());
        assert!(host.services().pairings().is_none());
        assert!(!host.services().allow_mcp_write());
        assert_eq!(*host.watch_run_state().borrow(), ProfileRunState::Running);
        host.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_failing_attachment_stops_the_profile_and_is_reported() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("failing")).await.unwrap();
        let (fail_tx, fail_rx) = oneshot::channel::<()>();
        let options =
            ProfileHostOptions::default().with_attachment(Box::new(|_: &ProfileServices, _| {
                Box::pin(async move {
                    let _ = fail_rx.await;
                    Err(anyhow::anyhow!("attachment failed"))
                })
            }));

        let host = ProfileHost::start(runtime, options).unwrap();
        let mut state = host.watch_run_state();
        fail_tx.send(()).unwrap();
        state
            .wait_for(|state| *state != ProfileRunState::Running)
            .await
            .unwrap();

        assert_eq!(*state.borrow(), ProfileRunState::Failed);
        let error = host.shutdown().await.unwrap_err();
        assert!(format!("{error:#}").contains("attachment failed"));
    }

    #[tokio::test]
    async fn every_component_failure_is_reported_not_only_the_first() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("aggregate")).await.unwrap();
        let options = ProfileHostOptions::default()
            .with_attachment(Box::new(|_: &ProfileServices, _| {
                Box::pin(async move { Err(anyhow::anyhow!("first attachment failed")) })
            }))
            .with_attachment(Box::new(|_: &ProfileServices, _| {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    Err(anyhow::anyhow!("second attachment failed"))
                })
            }));

        let error = ProfileHost::start(runtime, options)
            .unwrap()
            .shutdown()
            .await
            .unwrap_err();

        let reported = format!("{error:#}");
        assert!(reported.contains("first attachment failed"), "{reported}");
        assert!(reported.contains("second attachment failed"), "{reported}");
    }

    #[tokio::test]
    async fn an_unconfigured_adapter_never_ends_the_profile_but_still_stops() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("adapterless"))
            .await
            .unwrap();
        let host = ProfileHost::start(runtime, ProfileHostOptions::default()).unwrap();
        let (stop, stopping) = watch::channel(false);

        let idle = legacy_adapter_attachment(None)(host.services(), stopping.clone());
        assert!(
            tokio::time::timeout(Duration::ZERO, idle).await.is_err(),
            "an absent adapter must not report a finished component"
        );

        let stopping = legacy_adapter_attachment(None)(host.services(), stopping);
        stop.send(true).unwrap();
        stopping.await.unwrap();
        host.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_uncoordinated_drop_stops_the_task_set_instead_of_detaching_it() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("dropped")).await.unwrap();
        let (started, starting) = oneshot::channel::<()>();
        let options =
            ProfileHostOptions::default().with_attachment(Box::new(|_: &ProfileServices, _| {
                Box::pin(async move {
                    let _ = started.send(());
                    // An attachment that ignores the stop signal must still be
                    // stopped when nobody is left to drain it.
                    std::future::pending::<()>().await;
                    Ok(())
                })
            }));
        let host = ProfileHost::start(runtime, options).unwrap();
        let mut state = host.watch_run_state();
        starting.await.unwrap();

        drop(host);

        // A detached supervisor would keep its state channel open forever; an owned
        // one is aborted, which closes it.
        let observed = tokio::time::timeout(Duration::from_secs(5), state.changed()).await;
        assert!(
            matches!(observed, Ok(Err(_))),
            "the supervisor task must end rather than outlive its host: {observed:?}"
        );
        root.wait_until_unlocked("dropped").await;
    }

    #[tokio::test]
    async fn an_external_stop_drains_the_task_set() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("drained")).await.unwrap();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let host = ProfileHost::start(runtime, ProfileHostOptions::default()).unwrap();
        let state = host.watch_run_state();

        stop_tx.send(()).unwrap();
        host.run_until(async move {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();

        assert_eq!(*state.borrow(), ProfileRunState::Stopped);
    }
}
