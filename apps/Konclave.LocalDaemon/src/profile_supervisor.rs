use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use thiserror::Error;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

use crate::activity::{ProfileActivity, ProfileActivityError};
use crate::persistence::{ProfileId, ProfileStoreError};
use crate::profile_runtime::{ProfileHost, ProfileRunState, ProfileServices};
use crate::runtime::{ProfileSource, initialize_profile};

/// How many profiles one service process may host at once.
///
/// The bound covers every profile the registry is holding resources for: hosted
/// profiles, opens in flight, and closes that have not released their lock yet.
/// ADR 0008 requires at least twenty concurrent agent sessions to share one process.
/// The bound is well above that so ordinary workstation use never trips it, while a
/// runaway client still cannot open profiles until the process exhausts descriptors,
/// SQLite handles, or memory.
const DEFAULT_MAX_ACTIVE_PROFILES: usize = 64;

/// How many profile opens may run at once.
///
/// Opening is the expensive path: it acquires a lock, loads custody, opens two
/// databases, and recovers journals. Admission is bounded so a burst of first-connect
/// clients cannot start dozens of simultaneous recoveries; the requests beyond the
/// bound wait for a slot rather than being refused, because a workstation genuinely
/// does start many sessions at once.
const DEFAULT_MAX_PENDING_OPENS: usize = 8;

/// How many clients may hold one profile at once.
const DEFAULT_MAX_CLIENTS_PER_PROFILE: usize = 32;

/// How long a profile with no clients is retained before it may be evicted.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a close waits for already-admitted operations to finish.
///
/// Operations are bounded units of work — one pairing sweep or one received relay
/// page — so exceeding this means an operation is stuck rather than slow. The close
/// then reports an explicit failure instead of dropping stores underneath it.
const DEFAULT_OPERATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How many lifecycle transitions one attach may follow before giving up.
///
/// An attach can legitimately wait for an open, wait for a close, or reap a failed
/// runtime before it leases. Each transition is bounded, so a request that never
/// settles indicates lifecycle churn rather than progress and fails instead of
/// looping forever.
const MAX_ATTACH_STEPS: usize = 8;

/// Bounds and retention policy for one shared local service process.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProfileSupervisorConfig {
    /// Largest number of profiles the registry may hold resources for at once.
    ///
    /// This counts hosted profiles, opens in flight, and closes that have not
    /// released their lock yet, because each of those still holds or reserves a
    /// profile directory, lock, and database handles.
    pub(crate) max_active_profiles: usize,
    /// Largest number of profile opens that may run at once.
    pub(crate) max_pending_opens: usize,
    /// Largest number of clients attached to one profile.
    pub(crate) max_clients_per_profile: usize,
    /// How long a close waits for already-admitted operations to finish.
    pub(crate) operation_drain_timeout: Duration,
    /// How long a client-free profile is retained before eviction.
    pub(crate) idle_timeout: Duration,
}

impl Default for ProfileSupervisorConfig {
    fn default() -> Self {
        Self {
            max_active_profiles: DEFAULT_MAX_ACTIVE_PROFILES,
            max_pending_opens: DEFAULT_MAX_PENDING_OPENS,
            max_clients_per_profile: DEFAULT_MAX_CLIENTS_PER_PROFILE,
            operation_drain_timeout: DEFAULT_OPERATION_DRAIN_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl ProfileSupervisorConfig {
    /// Rejects a configuration that cannot serve any request.
    ///
    /// A zero bound is never a stricter policy: it turns every attach into a
    /// permanent refusal or, for open admission, a permanent wait for a permit that
    /// can never exist. Deliberately small nonzero bounds stay valid.
    ///
    /// # Errors
    ///
    /// Returns the first zero bound found.
    fn validate(&self) -> Result<(), ProfileSupervisorConfigError> {
        if self.max_active_profiles == 0 {
            return Err(ProfileSupervisorConfigError::ActiveProfiles);
        }
        if self.max_pending_opens == 0 {
            return Err(ProfileSupervisorConfigError::ConcurrentOpens);
        }
        if self.max_clients_per_profile == 0 {
            return Err(ProfileSupervisorConfigError::ClientsPerProfile);
        }
        Ok(())
    }
}

/// A configuration this build refuses to run.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ProfileSupervisorConfigError {
    #[error("the active profile limit must be greater than zero")]
    ActiveProfiles,
    #[error("the concurrent profile-open limit must be greater than zero")]
    ConcurrentOpens,
    #[error("the attached client limit must be greater than zero")]
    ClientsPerProfile,
}

/// Why one profile could not be attached.
///
/// Every variant is a refusal the caller can act on. None of them silently substitute
/// a different profile, a different custody source, or an unsupervised runtime. The
/// messages are stable and carry no path, endpoint, or other local detail.
#[non_exhaustive]
#[derive(Clone, Error)]
pub(crate) enum ProfileSupervisorError {
    #[error("profile identifier is invalid")]
    InvalidProfile,
    #[error("the local service is holding its limit of profiles")]
    ActiveProfileLimit,
    #[error("the profile reached its attached client limit")]
    ClientLimit,
    #[error("the local service is shutting down")]
    ShuttingDown,
    #[error("the profile runtime failed and its clients have not detached")]
    FailedRuntime,
    #[error("the profile was closed and this lease no longer grants access")]
    Revoked,
    #[error("the profile is locked by another owner")]
    ProfileLocked,
    #[error("opening the profile failed")]
    Open(Arc<anyhow::Error>),
    #[error("the profile lifecycle did not settle")]
    Unsettled,
}

impl ProfileSupervisorError {
    /// Returns the stable code that identifies this refusal in diagnostics.
    ///
    /// The code is a finite label rather than a message, so a log or metric never
    /// carries a path, endpoint, or other local value out of the service.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidProfile => "invalid_profile",
            Self::ActiveProfileLimit => "active_profile_limit",
            Self::ClientLimit => "client_limit",
            Self::ShuttingDown => "shutting_down",
            Self::FailedRuntime => "failed_runtime",
            Self::Revoked => "revoked",
            Self::ProfileLocked => "profile_locked",
            Self::Open(_) => "open_failed",
            Self::Unsettled => "unsettled",
        }
    }

    /// Returns the retained cause of a failed open.
    ///
    /// The cause names local paths and endpoints, so it is for an operator reading a
    /// returned error, never for a log field or an exported telemetry value.
    pub(crate) fn open_source(&self) -> Option<&anyhow::Error> {
        match self {
            Self::Open(source) => Some(source),
            _ => None,
        }
    }
}

/// Prints only the stable refusal code.
///
/// A derived implementation would format the retained open cause, which names local
/// paths and endpoints. `Debug` reaches assertion messages, panic output, and
/// structured logs, so it must stay as bounded as the message itself;
/// [`ProfileSupervisorError::open_source`] is the one explicit way to see the detail.
impl core::fmt::Debug for ProfileSupervisorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProfileSupervisorError")
            .field("code", &self.code())
            .finish()
    }
}

/// The result one in-flight open publishes to every request that coalesced onto it.
type OpenOutcome = Result<Arc<ActiveProfile>, ProfileSupervisorError>;

/// How one profile close ended, published to everything waiting on that close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseOutcome {
    /// The runtime stopped and the profile lock was released.
    Closed,
    /// The close ran and reported a failure its owner returned.
    Failed,
    /// The owner ended without completing the close, which only a panic can cause.
    Abandoned,
}

impl CloseOutcome {
    /// Returns the stable code that identifies this outcome in diagnostics.
    const fn code(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
        }
    }
}

/// What the registry currently holds for one profile identifier.
enum ProfileSlot {
    /// An open is in flight and later requests for this profile wait on it.
    Pending(watch::Receiver<Option<OpenOutcome>>),
    /// The profile is hosted and can be leased.
    Active(Arc<ActiveProfile>),
    /// A close is in flight and the profile lock is not released yet.
    Closing(watch::Receiver<Option<CloseOutcome>>),
}

#[derive(Default)]
struct SupervisorState {
    shutting_down: bool,
    slots: HashMap<String, ProfileSlot>,
    opens: Vec<JoinHandle<()>>,
}

/// How many clients hold one profile, and since when it has held none.
struct ClientRetention {
    attached: usize,
    idle_since: Option<Instant>,
}

/// One hosted profile plus the retention state that decides when it may close.
struct ActiveProfile {
    profile_id: ProfileId,
    services: Mutex<Option<ProfileServices>>,
    activity: ProfileActivity,
    host: Mutex<Option<ProfileHost>>,
    state: watch::Receiver<ProfileRunState>,
    clients: Mutex<ClientRetention>,
}

impl ActiveProfile {
    fn new(profile_id: ProfileId, host: ProfileHost) -> Self {
        Self {
            profile_id,
            services: Mutex::new(Some(host.services().clone())),
            // Held outside `services` because a close revokes the services first and
            // still has to deny admission and drain afterwards.
            activity: host.services().activity().clone(),
            state: host.watch_run_state(),
            host: Mutex::new(Some(host)),
            clients: Mutex::new(ClientRetention {
                attached: 0,
                idle_since: Some(Instant::now()),
            }),
        }
    }

    fn services(&self) -> Option<ProfileServices> {
        guard(&self.services).clone()
    }

    fn run_state(&self) -> ProfileRunState {
        *self.state.borrow()
    }

    fn attach_client(&self, maximum: usize) -> Result<(), ProfileSupervisorError> {
        let mut clients = guard(&self.clients);
        if clients.attached >= maximum {
            return Err(ProfileSupervisorError::ClientLimit);
        }
        clients.attached += 1;
        clients.idle_since = None;
        Ok(())
    }

    fn release_client(&self) {
        let mut clients = guard(&self.clients);
        clients.attached = clients.attached.saturating_sub(1);
        if clients.attached == 0 {
            clients.idle_since = Some(Instant::now());
        }
    }

    fn attached_clients(&self) -> usize {
        guard(&self.clients).attached
    }

    /// Reports whether this profile has held no client for at least `idle_for`.
    fn is_idle_for(&self, idle_for: Duration) -> bool {
        let clients = guard(&self.clients);
        clients.attached == 0
            && clients
                .idle_since
                .is_some_and(|idle_since| idle_since.elapsed() >= idle_for)
    }

    /// Reports whether the profile is free of supervised operations right now.
    ///
    /// This is only a cheap pre-filter. The decision that actually protects an
    /// operation is [`ProfileActivity::try_begin_closing`], which denies admission and
    /// commits to closing in one transition.
    fn is_operation_free(&self) -> bool {
        !self.activity.is_closing() && self.activity.in_flight() == 0
    }

    /// Denies further operations, but only when none is running.
    ///
    /// Once this returns `true` the profile is committed to closing: no operation can
    /// be admitted afterwards, so nothing can be closed underneath.
    fn try_begin_closing(&self) -> bool {
        self.activity.try_begin_closing()
    }

    /// Denies further operations regardless of what is already running.
    fn begin_closing(&self) {
        self.activity.begin_closing();
    }

    /// Reports whether an adapter still holds claimed delivery work.
    ///
    /// Pending journal entries do not block eviction: they stay durable, and no client
    /// is attached to receive them. A claimed entry is different because a lease is
    /// outstanding against it, and closing the profile underneath that claim would
    /// discard the consumer's in-flight batch.
    async fn has_active_claims(&self) -> anyhow::Result<bool> {
        let Some(services) = self.services() else {
            return Ok(false);
        };
        let store = services.conversations().store();
        let (_, claimed) = tokio::task::spawn_blocking(move || store.remote_event_counts())
            .await
            .context("joining the profile delivery-journal check")?
            .context("reading the profile delivery journal")?;
        Ok(claimed > 0)
    }

    fn request_stop(&self) {
        if let Some(host) = guard(&self.host).as_ref() {
            host.request_stop();
        }
    }

    /// Stops the runtime and releases the profile lock, at most once.
    ///
    /// The close transition happens before anything is awaited: the profile stops
    /// admitting operations and every lease loses access in the same step. Only then
    /// does the close wait for already-admitted operations to drain and for the task
    /// set to stop, so no client can start work against stores that are going away.
    ///
    /// # Errors
    ///
    /// Returns a drain-deadline failure, the aggregated task-set failure, or both.
    /// The profile lock is released on every path, including the failing ones.
    async fn close(&self, drain_timeout: Duration) -> anyhow::Result<bool> {
        let Some(host) = guard(&self.host).take() else {
            return Ok(false);
        };
        self.activity.begin_closing();
        let revoked = guard(&self.services).take();
        host.request_stop();

        let drained = self.activity.wait_drained(drain_timeout).await;
        let stopped = host.shutdown().await;
        // Dropping the last bound services closes both SQLite connections, which
        // checkpoints the write-ahead log and releases the exclusive profile lock.
        drop(revoked);

        match (drained, stopped) {
            (Ok(()), Ok(())) => Ok(true),
            (Ok(()), Err(error)) => Err(error),
            // The drain failure stays the primary error so callers can classify it by
            // type instead of reading a message.
            (Err(drain), Ok(())) => {
                Err(anyhow::Error::new(drain).context("draining profile operations"))
            }
            (Err(drain), Err(error)) => Err(anyhow::Error::new(drain).context(format!(
                "draining profile operations, and the task set also failed: {error:#}"
            ))),
        }
    }
}

/// Reports whether one close failure was an operation drain that timed out.
fn is_operation_drain_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<ProfileActivityError>() == Some(&ProfileActivityError::DrainTimeout)
    })
}

/// One client's hold on exactly one profile.
///
/// The lease keeps the profile open but holds no service handle of its own. Access is
/// resolved from the profile on every use, so coordinated shutdown or eviction can
/// revoke it and release the profile's databases and lock while the lease object
/// still exists.
pub(crate) struct ProfileLease {
    profile: Arc<ActiveProfile>,
}

impl ProfileLease {
    /// Returns the durable identifier of the leased profile.
    pub(crate) fn profile_id(&self) -> &str {
        self.profile.profile_id.as_str()
    }

    /// Returns the bound services for one operation.
    ///
    /// The returned handle keeps the profile's stores alive for as long as it is
    /// held, so it belongs to one operation and must not be cached beyond it.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileSupervisorError::Revoked`] once the profile has been closed.
    pub(crate) fn services(&self) -> Result<ProfileServices, ProfileSupervisorError> {
        self.profile
            .services()
            .ok_or(ProfileSupervisorError::Revoked)
    }

    /// Returns the supervised state of the leased runtime.
    pub(crate) fn run_state(&self) -> ProfileRunState {
        self.profile.run_state()
    }
}

impl Drop for ProfileLease {
    fn drop(&mut self) {
        self.profile.release_client();
    }
}

/// Prints only bounded routing state, never the bound services.
///
/// The lease reaches a profile's keys, plaintext, and relay credentials. Formatting
/// those into a diagnostic would move secret state to a destination the threat model
/// does not trust.
impl core::fmt::Debug for ProfileLease {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProfileLease")
            .field("profile", &self.profile_id())
            .field("run_state", &self.run_state())
            .finish_non_exhaustive()
    }
}

/// The registry that lazily opens, isolates, retains, and closes local profiles.
///
/// One process hosts many profiles, and each of them keeps its own lock, databases,
/// sealer, identity, relay principal, journals, and supervised tasks. Consolidation
/// happens at the process level only: nothing here shares profile state, and one
/// profile's failure is reported to its own clients instead of ending the others.
pub(crate) struct ProfileSupervisor {
    source: Arc<dyn ProfileSource>,
    config: ProfileSupervisorConfig,
    open_permits: Arc<Semaphore>,
    state: Mutex<SupervisorState>,
}

/// What an attach attempt must do before it can lease.
enum AttachStep {
    Leased(Box<ProfileLease>),
    AwaitOpen(watch::Receiver<Option<OpenOutcome>>),
    AwaitClose(watch::Receiver<Option<CloseOutcome>>),
    Reap(ClosingSlot),
}

/// One profile whose close this caller owns.
///
/// Ownership is released through [`Drop`], so a panicking closer publishes an
/// outcome instead of leaving every waiter parked on a close that will never finish.
struct ClosingSlot {
    key: String,
    active: Arc<ActiveProfile>,
    completed: watch::Sender<Option<CloseOutcome>>,
    outcome: Option<CloseOutcome>,
}

impl Drop for ClosingSlot {
    fn drop(&mut self) {
        // The registry lock is deliberately not taken here: this can run while
        // unwinding from a thread that already holds it. A completed slot that is
        // still present is treated as stale by the next request instead.
        let outcome = self.outcome.unwrap_or(CloseOutcome::Abandoned);
        let _ = self.completed.send(Some(outcome));
    }
}

/// An owned view of one registry slot, taken so the registry can be mutated next.
enum SlotView {
    Pending(watch::Receiver<Option<OpenOutcome>>),
    Active(Arc<ActiveProfile>),
    Closing(watch::Receiver<Option<CloseOutcome>>),
}

impl ProfileSupervisor {
    /// Creates a supervisor over one explicit profile source.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for any bound that would refuse or stall every
    /// request.
    pub(crate) fn new(
        source: Arc<dyn ProfileSource>,
        config: ProfileSupervisorConfig,
    ) -> Result<Arc<Self>, ProfileSupervisorConfigError> {
        config.validate()?;
        Ok(Arc::new(Self {
            source,
            config,
            open_permits: Arc::new(Semaphore::new(config.max_pending_opens)),
            state: Mutex::new(SupervisorState::default()),
        }))
    }

    /// Attaches one client to a profile, opening it if this is the first client.
    ///
    /// Concurrent requests for the same profile coalesce onto one open, so a profile
    /// is never opened, locked, or recovered twice.
    ///
    /// # Errors
    ///
    /// Returns a validation, capacity, shutdown, failed-runtime, or open failure.
    pub(crate) async fn attach(
        self: &Arc<Self>,
        profile: &str,
    ) -> Result<ProfileLease, ProfileSupervisorError> {
        let profile_id =
            ProfileId::parse(profile).map_err(|_| ProfileSupervisorError::InvalidProfile)?;
        for _ in 0..MAX_ATTACH_STEPS {
            match self.begin_attach(&profile_id)? {
                AttachStep::Leased(lease) => return Ok(*lease),
                AttachStep::AwaitOpen(pending) => {
                    wait_for_open(pending).await?;
                }
                AttachStep::AwaitClose(closing) => {
                    wait_for_close(closing).await;
                }
                AttachStep::Reap(slot) => {
                    let key = slot.key.clone();
                    if self.close_slot(slot).await.is_err() {
                        tracing::error!(
                            profile = key.as_str(),
                            outcome = "close_failed",
                            "a failed profile runtime did not close cleanly"
                        );
                    }
                }
            }
        }
        Err(ProfileSupervisorError::Unsettled)
    }

    /// Returns how many profiles are currently hosted.
    pub(crate) fn active_profiles(&self) -> usize {
        guard(&self.state)
            .slots
            .values()
            .filter(|slot| matches!(slot, ProfileSlot::Active(_)))
            .count()
    }

    /// Returns the supervised state of one hosted profile.
    pub(crate) fn run_state(&self, profile: &str) -> Option<ProfileRunState> {
        match guard(&self.state).slots.get(profile) {
            Some(ProfileSlot::Active(active)) => Some(active.run_state()),
            _ => None,
        }
    }

    /// Returns a receiver that observes one hosted profile's supervised state.
    pub(crate) fn watch_run_state(
        &self,
        profile: &str,
    ) -> Option<watch::Receiver<ProfileRunState>> {
        match guard(&self.state).slots.get(profile) {
            Some(ProfileSlot::Active(active)) => Some(active.state.clone()),
            _ => None,
        }
    }

    /// Closes every failed runtime that no client still holds.
    ///
    /// A failed profile keeps its lock and databases open until it is closed, so this
    /// is how a supervising loop turns one profile's failure into released resources
    /// and a reported error instead of a silent, half-dead profile.
    pub(crate) async fn reap_failed(self: &Arc<Self>) -> Vec<(String, anyhow::Error)> {
        let slots = {
            let mut state = guard(&self.state);
            let failed = state
                .slots
                .iter()
                .filter_map(|(key, slot)| match slot {
                    ProfileSlot::Active(active)
                        if active.run_state() == ProfileRunState::Failed
                            && active.attached_clients() == 0 =>
                    {
                        Some(key.clone())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            failed
                .into_iter()
                .filter_map(|key| begin_close(&mut state, &key, CloseAdmission::Unconditional))
                .collect::<Vec<_>>()
        };

        let mut failures = Vec::new();
        for slot in slots {
            let key = slot.key.clone();
            if let Err(error) = self.close_slot(slot).await {
                tracing::error!(
                    profile = key.as_str(),
                    outcome = "runtime_failed",
                    "a profile runtime failed and was closed"
                );
                failures.push((key, error));
            }
        }
        failures
    }

    /// Closes every profile that has held no client for at least `idle_for`.
    ///
    /// A profile is evicted only when no client holds it, no supervised pairing or
    /// relay recovery operation is running, and no adapter claim is outstanding.
    /// Eviction is a resource decision, never a data decision: it removes no durable
    /// profile state and no native key, and a later attach reopens the same profile
    /// with the same identity.
    ///
    /// # Errors
    ///
    /// Returns the aggregated failures observed while closing evictable profiles.
    /// A profile whose delivery journal cannot be inspected is retained rather than
    /// closed underneath a claim that may exist.
    pub(crate) async fn evict_idle(self: &Arc<Self>, idle_for: Duration) -> anyhow::Result<usize> {
        let candidates = {
            let state = guard(&self.state);
            if state.shutting_down {
                return Ok(0);
            }
            state
                .slots
                .iter()
                .filter_map(|(key, slot)| match slot {
                    ProfileSlot::Active(active)
                        if active.is_idle_for(idle_for) && active.is_operation_free() =>
                    {
                        Some((key.clone(), Arc::clone(active)))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let mut failures = Vec::new();
        let mut evictable = Vec::new();
        for (key, active) in candidates {
            match active.has_active_claims().await {
                Ok(false) => evictable.push(key),
                Ok(true) => {}
                Err(error) => failures
                    .push(error.context(format!("deciding whether profile {key} can be evicted"))),
            }
        }

        let slots = {
            let mut state = guard(&self.state);
            let mut slots = Vec::new();
            for key in evictable {
                // Retention is decided once, under this lock: a client cannot attach
                // while it is held, and `begin_close` denies operation admission and
                // publishes the closing slot in one transition, so the profile is only
                // committed when nothing can be closed underneath it.
                let still_idle = match state.slots.get(&key) {
                    Some(ProfileSlot::Active(active)) => active.is_idle_for(idle_for),
                    _ => false,
                };
                if still_idle
                    && let Some(slot) = begin_close(&mut state, &key, CloseAdmission::OnlyWhenIdle)
                {
                    slots.push(slot);
                }
            }
            slots
        };

        let mut evicted = 0;
        for slot in slots {
            let key = slot.key.clone();
            match self.close_slot(slot).await {
                // Only a profile that actually released its runtime and lock counts as
                // evicted; a failure is reported instead of inflating the total.
                Ok(true) => evicted += 1,
                Ok(false) => {}
                Err(error) => failures.push(error.context(format!("evicting profile {key}"))),
            }
        }
        report_failures(failures)?;
        Ok(evicted)
    }

    /// Evicts every profile that exceeded the configured idle window.
    ///
    /// # Errors
    ///
    /// Returns the aggregated failures observed while closing evictable profiles.
    pub(crate) async fn sweep_idle(self: &Arc<Self>) -> anyhow::Result<usize> {
        self.evict_idle(self.config.idle_timeout).await
    }

    /// Stops accepting attaches and closes every hosted profile exactly once.
    ///
    /// # Errors
    ///
    /// Returns every failure observed while draining opens and closing runtimes. A
    /// failure closing one profile never skips another profile's close.
    pub(crate) async fn shutdown(self: &Arc<Self>) -> anyhow::Result<usize> {
        let opens = {
            let mut state = guard(&self.state);
            state.shutting_down = true;
            for slot in state.slots.values() {
                if let ProfileSlot::Active(active) = slot {
                    active.request_stop();
                }
            }
            std::mem::take(&mut state.opens)
        };
        // Waiting opens are released immediately: their permit will never be worth
        // waiting for, and shutdown must not block behind admission.
        self.open_permits.close();

        let mut failures = Vec::new();
        // An in-flight open owns a profile lock the moment it succeeds, so shutdown
        // waits for it instead of racing it. A refused open settles immediately.
        for open in opens {
            if let Err(error) = open.await {
                failures.push(anyhow::Error::new(error).context("joining a profile open"));
            }
        }

        let (slots, closing) = {
            let mut state = guard(&self.state);
            let mut active = Vec::new();
            let mut closing = Vec::new();
            for (key, slot) in &state.slots {
                match slot {
                    ProfileSlot::Active(_) => active.push(key.clone()),
                    ProfileSlot::Closing(completed) => {
                        closing.push((key.clone(), completed.clone()));
                    }
                    ProfileSlot::Pending(_) => {}
                }
            }
            let slots = active
                .into_iter()
                .filter_map(|key| begin_close(&mut state, &key, CloseAdmission::Unconditional))
                .collect::<Vec<_>>();
            (slots, closing)
        };

        let mut closed = 0;
        for slot in slots {
            let key = slot.key.clone();
            match self.close_slot(slot).await {
                // The count reports profiles that actually released their runtime and
                // lock, so a failure is aggregated rather than counted as a close.
                Ok(true) => closed += 1,
                Ok(false) => {}
                Err(error) => failures.push(error.context(format!("closing profile {key}"))),
            }
        }
        // A concurrent eviction or reap owns its own close. Shutdown waits for it so
        // every profile lock is released first, counts it only when it actually
        // closed, and reports anything else so a failed or abandoned close never
        // leaves shutdown looking clean.
        for (key, completed) in closing {
            match wait_for_close(completed).await {
                CloseOutcome::Closed => closed += 1,
                outcome => failures.push(anyhow::anyhow!(
                    "concurrent close of profile {key} reported {}",
                    outcome.code()
                )),
            }
        }

        report_failures(failures)?;
        Ok(closed)
    }

    /// Decides, under one lock, what an attach attempt must do next.
    fn begin_attach(
        self: &Arc<Self>,
        profile_id: &ProfileId,
    ) -> Result<AttachStep, ProfileSupervisorError> {
        let key = profile_id.as_str().to_string();
        let mut state = guard(&self.state);
        if state.shutting_down {
            return Err(ProfileSupervisorError::ShuttingDown);
        }
        let existing = match state.slots.get(&key) {
            Some(ProfileSlot::Pending(pending)) => Some(SlotView::Pending(pending.clone())),
            Some(ProfileSlot::Closing(completed)) => Some(SlotView::Closing(completed.clone())),
            Some(ProfileSlot::Active(active)) => Some(SlotView::Active(Arc::clone(active))),
            None => None,
        };
        match existing {
            Some(SlotView::Pending(pending)) => return Ok(AttachStep::AwaitOpen(pending)),
            Some(SlotView::Closing(completed)) => {
                if completed.borrow().is_none() {
                    return Ok(AttachStep::AwaitClose(completed));
                }
                // A completed close removes its own slot, so a slot that is still
                // here belongs to an owner that died. Reclaim it rather than parking
                // every later request on a close nobody will finish.
                tracing::warn!(
                    profile = key.as_str(),
                    outcome = "close_abandoned",
                    "reclaiming a profile slot whose close never finished"
                );
                state.slots.remove(&key);
            }
            Some(SlotView::Active(active)) => {
                if active.run_state() == ProfileRunState::Failed {
                    if active.attached_clients() > 0 {
                        return Err(ProfileSupervisorError::FailedRuntime);
                    }
                    let slot = begin_close(&mut state, &key, CloseAdmission::Unconditional)
                        .ok_or(ProfileSupervisorError::FailedRuntime)?;
                    return Ok(AttachStep::Reap(slot));
                }
                if active.services().is_none() {
                    return Err(ProfileSupervisorError::Revoked);
                }
                active.attach_client(self.config.max_clients_per_profile)?;
                return Ok(AttachStep::Leased(Box::new(ProfileLease {
                    profile: active,
                })));
            }
            None => {}
        }

        if state.slots.len() >= self.config.max_active_profiles {
            return Err(ProfileSupervisorError::ActiveProfileLimit);
        }

        let (sender, receiver) = watch::channel(None);
        state
            .slots
            .insert(key.clone(), ProfileSlot::Pending(receiver.clone()));
        let supervisor = Arc::clone(self);
        let opening = profile_id.clone();
        let open = tokio::spawn(async move {
            let mut guard = PendingOpenGuard {
                supervisor: Arc::clone(&supervisor),
                key,
                sender,
                outcome: None,
            };
            let opened = supervisor.open_profile(&opening).await;
            supervisor.finish_open(&mut guard, opened).await;
        });
        state.opens.retain(|open| !open.is_finished());
        state.opens.push(open);
        Ok(AttachStep::AwaitOpen(receiver))
    }

    /// Opens one profile and starts its supervised task set.
    ///
    /// The expensive work runs under an admission permit, so many simultaneous first
    /// connections queue instead of starting every lock, custody load, database open,
    /// and journal recovery at once.
    async fn open_profile(
        &self,
        profile_id: &ProfileId,
    ) -> Result<Arc<ActiveProfile>, OpenFailure> {
        // The permit set is closed only by shutdown, so a refused permit is a stopping
        // service rather than a failed open.
        let _permit = self
            .open_permits
            .acquire()
            .await
            .map_err(|_| OpenFailure::ShuttingDown)?;
        let source = Arc::clone(&self.source);
        let configuring = profile_id.clone();
        let config = tokio::task::spawn_blocking(move || source.configure(&configuring))
            .await
            .context("joining the profile configuration")
            .map_err(OpenFailure::Failed)?
            .with_context(|| format!("configuring profile {}", profile_id.as_str()))
            .map_err(OpenFailure::Failed)?;
        let runtime = initialize_profile(config)
            .await
            .with_context(|| format!("opening profile {}", profile_id.as_str()))
            .map_err(OpenFailure::Failed)?;
        let host = ProfileHost::start(runtime, self.source.host_options(profile_id))
            .with_context(|| format!("starting profile {}", profile_id.as_str()))
            .map_err(OpenFailure::Failed)?;
        Ok(Arc::new(ActiveProfile::new(profile_id.clone(), host)))
    }

    /// Publishes one completed open, or closes it when the service is stopping.
    async fn finish_open(
        &self,
        open: &mut PendingOpenGuard,
        opened: Result<Arc<ActiveProfile>, OpenFailure>,
    ) {
        let active = match opened {
            Ok(active) => active,
            Err(OpenFailure::ShuttingDown) => {
                open.outcome = Some(Err(ProfileSupervisorError::ShuttingDown));
                return;
            }
            Err(OpenFailure::Failed(error)) => {
                let refusal = classify_open_failure(error);
                tracing::error!(
                    profile = open.key.as_str(),
                    outcome = refusal.code(),
                    "opening a profile failed"
                );
                open.outcome = Some(Err(refusal));
                return;
            }
        };

        let published = {
            let mut state = guard(&self.state);
            if state.shutting_down {
                false
            } else {
                state
                    .slots
                    .insert(open.key.clone(), ProfileSlot::Active(Arc::clone(&active)));
                true
            }
        };
        if published {
            open.outcome = Some(Ok(active));
            return;
        }

        open.outcome = Some(Err(ProfileSupervisorError::ShuttingDown));
        if active
            .close(self.config.operation_drain_timeout)
            .await
            .is_err()
        {
            tracing::error!(
                profile = open.key.as_str(),
                outcome = "close_failed",
                "a profile opened during shutdown did not close cleanly"
            );
        }
    }

    /// Closes one profile this caller owns and removes its slot.
    async fn close_slot(&self, mut slot: ClosingSlot) -> anyhow::Result<bool> {
        let outcome = slot.active.close(self.config.operation_drain_timeout).await;
        slot.outcome = Some(if outcome.is_ok() {
            CloseOutcome::Closed
        } else {
            CloseOutcome::Failed
        });
        {
            let mut state = guard(&self.state);
            if matches!(state.slots.get(&slot.key), Some(ProfileSlot::Closing(_))) {
                state.slots.remove(&slot.key);
            }
        }
        // Dropping the slot publishes the outcome to every waiter.
        drop(slot);
        outcome
    }

    fn abandon_pending(&self, key: &str) {
        let mut state = guard(&self.state);
        if matches!(state.slots.get(key), Some(ProfileSlot::Pending(_))) {
            state.slots.remove(key);
        }
    }
}

/// Why one open did not produce a hosted profile.
enum OpenFailure {
    /// The service began stopping before the open could take a permit.
    ShuttingDown,
    /// The open itself failed, with the local cause retained for classification.
    Failed(anyhow::Error),
}

/// Turns one open failure into a stable refusal.
///
/// A profile lock held by another owner is an expected, well-defined outcome — the
/// duplicate-ownership case ADR 0008 requires to fail closed — so it gets its own
/// stable code instead of an opaque open failure. Neither the code nor the message
/// discloses the profile root, the lock path, or any other local value.
fn classify_open_failure(error: anyhow::Error) -> ProfileSupervisorError {
    if error.chain().any(|cause| {
        cause.downcast_ref::<ProfileStoreError>() == Some(&ProfileStoreError::ProfileLocked)
    }) {
        return ProfileSupervisorError::ProfileLocked;
    }
    ProfileSupervisorError::Open(Arc::new(error))
}

/// Publishes one open outcome to every coalesced request, even after a panic.
///
/// Without this the registry could keep a pending slot no request can ever resolve,
/// which would make one lost open look like a permanently unavailable profile.
struct PendingOpenGuard {
    supervisor: Arc<ProfileSupervisor>,
    key: String,
    sender: watch::Sender<Option<OpenOutcome>>,
    outcome: Option<OpenOutcome>,
}

impl Drop for PendingOpenGuard {
    fn drop(&mut self) {
        let outcome = self.outcome.take().unwrap_or_else(|| {
            tracing::error!(
                profile = self.key.as_str(),
                outcome = "open_abandoned",
                "a profile open ended without an outcome"
            );
            Err(ProfileSupervisorError::Unsettled)
        });
        if outcome.is_err() {
            self.supervisor.abandon_pending(&self.key);
        }
        let _ = self.sender.send(Some(outcome));
    }
}

/// Whether a close may proceed while operations are still admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseAdmission {
    /// Take the profile only when no operation is running, as eviction requires.
    OnlyWhenIdle,
    /// Take the profile regardless, as shutdown and failure reaping require.
    Unconditional,
}

/// Takes ownership of closing one active slot, leaving waiters a signal to follow.
///
/// Closing the profile's operation gate and publishing the `Closing` slot happen
/// together, under the registry lock, so this is the only way a profile can start
/// closing. An eviction therefore cannot observe an idle profile and then commit
/// while an operation slips in behind the check: `OnlyWhenIdle` denies admission and
/// commits in one transition, or refuses and leaves the profile untouched.
fn begin_close(
    state: &mut SupervisorState,
    key: &str,
    admission: CloseAdmission,
) -> Option<ClosingSlot> {
    let ProfileSlot::Active(active) = state.slots.get(key)? else {
        return None;
    };
    let active = Arc::clone(active);
    match admission {
        CloseAdmission::OnlyWhenIdle if !active.try_begin_closing() => return None,
        CloseAdmission::OnlyWhenIdle => {}
        CloseAdmission::Unconditional => active.begin_closing(),
    }
    let (completed, receiver) = watch::channel(None);
    state
        .slots
        .insert(key.to_string(), ProfileSlot::Closing(receiver));
    Some(ClosingSlot {
        key: key.to_string(),
        active,
        completed,
        outcome: None,
    })
}

async fn wait_for_open(
    mut pending: watch::Receiver<Option<OpenOutcome>>,
) -> Result<(), ProfileSupervisorError> {
    let outcome = pending
        .wait_for(Option::is_some)
        .await
        .map(|outcome| outcome.clone())
        .map_err(|_| ProfileSupervisorError::Unsettled)?;
    match outcome {
        Some(Ok(_)) => Ok(()),
        Some(Err(error)) => Err(error),
        None => Err(ProfileSupervisorError::Unsettled),
    }
}

async fn wait_for_close(mut completed: watch::Receiver<Option<CloseOutcome>>) -> CloseOutcome {
    // A dropped sender means the owning close ended without publishing anything,
    // which only an unwinding owner can cause. Waiting further would deadlock.
    match completed.wait_for(Option::is_some).await {
        Ok(outcome) => outcome.unwrap_or(CloseOutcome::Abandoned),
        Err(_) => CloseOutcome::Abandoned,
    }
}

fn report_failures(failures: Vec<anyhow::Error>) -> anyhow::Result<()> {
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
    Err(first.context(format!("additional failures: {}", additional.join("; "))))
}

/// Recovers a poisoned lock instead of propagating it.
///
/// These mutexes guard a client counter, an `Option<ProfileHost>`, and an
/// `Option<ProfileServices>`. A panic while one is held cannot leave a broken
/// invariant behind, and refusing to take the lock afterwards would strand the
/// profile: its lease could never be released and its lock never freed.
fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    use tokio::sync::oneshot;

    use super::*;
    use crate::activity::ProfileActivityError;
    use crate::profile_runtime::ProfileHostOptions;
    use crate::runtime::{ProfileConfig, ProfileCustody, ServiceProfileSettings};
    use crate::test_support::TestProfileRoot;

    /// The number of concurrent profiles ADR 0008 and issue #121 require.
    const REQUIRED_CONCURRENT_PROFILES: usize = 20;

    fn supervisor(root: &TestProfileRoot) -> Arc<ProfileSupervisor> {
        ProfileSupervisor::new(
            Arc::new(root.settings()),
            ProfileSupervisorConfig::default(),
        )
        .unwrap()
    }

    /// Counts how often a profile is configured, which is once per real open.
    struct CountingSource {
        inner: ServiceProfileSettings,
        configured: Arc<AtomicUsize>,
    }

    impl ProfileSource for CountingSource {
        fn configure(&self, profile: &ProfileId) -> anyhow::Result<ProfileConfig> {
            self.configured.fetch_add(1, Ordering::SeqCst);
            self.inner.configure(profile)
        }
    }

    /// Refuses one named profile until its custody source is repaired.
    struct RepairableSource {
        root: std::path::PathBuf,
        key_path: std::path::PathBuf,
        broken_profile: String,
        broken_key: std::path::PathBuf,
    }

    impl ProfileSource for RepairableSource {
        fn configure(&self, profile: &ProfileId) -> anyhow::Result<ProfileConfig> {
            let key = if profile.as_str() == self.broken_profile {
                self.broken_key.clone()
            } else {
                self.key_path.clone()
            };
            ServiceProfileSettings::new(self.root.clone(), ProfileCustody::ExternalFile(key), false)
                .configure(profile)
        }
    }

    /// Blocks every open until the test releases it, and records open concurrency.
    struct GatedSource {
        inner: ServiceProfileSettings,
        entered: tokio::sync::mpsc::UnboundedSender<String>,
        release: Mutex<mpsc::Receiver<()>>,
        concurrent: AtomicUsize,
        peak: AtomicUsize,
    }

    impl ProfileSource for GatedSource {
        fn configure(&self, profile: &ProfileId) -> anyhow::Result<ProfileConfig> {
            let concurrent = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(concurrent, Ordering::SeqCst);
            let _ = self.entered.send(profile.as_str().to_string());
            let _ = guard(&self.release).recv();
            let config = self.inner.configure(profile);
            self.concurrent.fetch_sub(1, Ordering::SeqCst);
            config
        }
    }

    /// Fails one profile's task set the first time that profile is hosted.
    struct FailingRuntimeSource {
        inner: ServiceProfileSettings,
        failing_profile: String,
        trigger: Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl ProfileSource for FailingRuntimeSource {
        fn configure(&self, profile: &ProfileId) -> anyhow::Result<ProfileConfig> {
            self.inner.configure(profile)
        }

        fn host_options(&self, profile: &ProfileId) -> ProfileHostOptions {
            if profile.as_str() != self.failing_profile {
                return ProfileHostOptions::default();
            }
            let Some(trigger) = guard(&self.trigger).take() else {
                return ProfileHostOptions::default();
            };
            ProfileHostOptions::default().with_attachment(Box::new(
                move |_: &ProfileServices, _| {
                    Box::pin(async move {
                        let _ = trigger.await;
                        Err(anyhow::anyhow!("profile runtime failed"))
                    })
                },
            ))
        }
    }

    /// Holds one profile's task set open until the test releases its shutdown.
    struct BlockedShutdownSource {
        inner: ServiceProfileSettings,
        stopping: Mutex<Option<tokio::sync::mpsc::UnboundedSender<()>>>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl ProfileSource for BlockedShutdownSource {
        fn configure(&self, profile: &ProfileId) -> anyhow::Result<ProfileConfig> {
            self.inner.configure(profile)
        }

        fn host_options(&self, _profile: &ProfileId) -> ProfileHostOptions {
            let stopping = guard(&self.stopping).take();
            let release = guard(&self.release).take();
            ProfileHostOptions::default().with_attachment(Box::new(
                move |_: &ProfileServices, mut stop| {
                    Box::pin(async move {
                        while !*stop.borrow_and_update() {
                            if stop.changed().await.is_err() {
                                break;
                            }
                        }
                        if let Some(stopping) = stopping {
                            let _ = stopping.send(());
                        }
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        Ok(())
                    })
                },
            ))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_process_hosts_many_locked_and_isolated_profiles() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);

        let attaching = (0..REQUIRED_CONCURRENT_PROFILES)
            .map(|index| {
                let supervisor = Arc::clone(&supervisor);
                tokio::spawn(async move { supervisor.attach(&format!("session-{index}")).await })
            })
            .collect::<Vec<_>>();
        let mut leases = Vec::new();
        for attach in attaching {
            leases.push(attach.await.unwrap().unwrap());
        }

        assert_eq!(leases.len(), REQUIRED_CONCURRENT_PROFILES);
        assert_eq!(supervisor.active_profiles(), REQUIRED_CONCURRENT_PROFILES);
        let mut devices = std::collections::HashSet::new();
        for lease in &leases {
            assert!(
                devices.insert(
                    lease
                        .services()
                        .unwrap()
                        .conversations()
                        .device_id()
                        .unwrap()
                ),
                "profiles must not share a device identity"
            );
            assert_eq!(lease.run_state(), ProfileRunState::Running);
            // Another owner of the same profile, in this or any other process, is
            // refused for as long as this service hosts it.
            assert!(root.is_locked(lease.profile_id()));
        }

        drop(leases);
        assert_eq!(
            supervisor.shutdown().await.unwrap(),
            REQUIRED_CONCURRENT_PROFILES
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_for_one_profile_open_it_once() {
        let root = TestProfileRoot::new();
        let configured = Arc::new(AtomicUsize::new(0));
        let supervisor = ProfileSupervisor::new(
            Arc::new(CountingSource {
                inner: root.settings(),
                configured: Arc::clone(&configured),
            }),
            ProfileSupervisorConfig::default(),
        )
        .unwrap();

        let attaching = (0..8)
            .map(|_| {
                let supervisor = Arc::clone(&supervisor);
                tokio::spawn(async move { supervisor.attach("shared").await })
            })
            .collect::<Vec<_>>();
        let mut leases = Vec::new();
        for attach in attaching {
            leases.push(attach.await.unwrap().unwrap());
        }

        assert_eq!(configured.load(Ordering::SeqCst), 1);
        assert_eq!(supervisor.active_profiles(), 1);
        let device = leases[0]
            .services()
            .unwrap()
            .conversations()
            .device_id()
            .unwrap();
        for lease in &leases {
            assert_eq!(lease.profile_id(), "shared");
            assert_eq!(
                lease
                    .services()
                    .unwrap()
                    .conversations()
                    .device_id()
                    .unwrap(),
                device
            );
        }

        drop(leases);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_active_profile_limit_fails_closed_and_frees_after_eviction() {
        let root = TestProfileRoot::new();
        let supervisor = ProfileSupervisor::new(
            Arc::new(root.settings()),
            ProfileSupervisorConfig {
                max_active_profiles: 2,
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();

        let first = supervisor.attach("bounded-a").await.unwrap();
        let second = supervisor.attach("bounded-b").await.unwrap();
        let refused = supervisor.attach("bounded-c").await.unwrap_err();

        assert!(
            matches!(refused, ProfileSupervisorError::ActiveProfileLimit),
            "{refused:?}"
        );
        // The refusal is local to the request: both hosted profiles still work.
        assert!(
            first
                .services()
                .unwrap()
                .conversations()
                .device_id()
                .is_ok()
        );
        assert!(
            second
                .services()
                .unwrap()
                .conversations()
                .device_id()
                .is_ok()
        );
        assert!(supervisor.run_state("bounded-c").is_none());

        drop(second);
        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 1);
        let third = supervisor.attach("bounded-c").await.unwrap();

        assert_eq!(third.profile_id(), "bounded-c");
        drop((first, third));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_client_limit_fails_closed_and_frees_when_a_client_detaches() {
        let root = TestProfileRoot::new();
        let supervisor = ProfileSupervisor::new(
            Arc::new(root.settings()),
            ProfileSupervisorConfig {
                max_clients_per_profile: 2,
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();

        let first = supervisor.attach("shared-clients").await.unwrap();
        let second = supervisor.attach("shared-clients").await.unwrap();
        let refused = supervisor.attach("shared-clients").await.unwrap_err();

        assert!(
            matches!(refused, ProfileSupervisorError::ClientLimit),
            "{refused:?}"
        );
        drop(second);
        let reattached = supervisor.attach("shared-clients").await.unwrap();

        assert_eq!(reattached.profile_id(), "shared-clients");
        drop((first, reattached));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_opens_are_admitted_up_to_the_open_limit() {
        let root = TestProfileRoot::new();
        let (entered, mut entering) = tokio::sync::mpsc::unbounded_channel();
        let (release, releasing) = mpsc::channel();
        let source = Arc::new(GatedSource {
            inner: root.settings(),
            entered,
            release: Mutex::new(releasing),
            concurrent: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let supervisor = ProfileSupervisor::new(
            Arc::clone(&source) as Arc<dyn ProfileSource>,
            ProfileSupervisorConfig {
                max_pending_opens: 2,
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();

        let attaching = (0..4)
            .map(|index| {
                let supervisor = Arc::clone(&supervisor);
                tokio::spawn(async move { supervisor.attach(&format!("gated-{index}")).await })
            })
            .collect::<Vec<_>>();
        entering.recv().await.unwrap();
        entering.recv().await.unwrap();

        // Two opens hold the admission permits, so no third open has started.
        assert!(entering.try_recv().is_err());
        for _ in 0..4 {
            release.send(()).unwrap();
        }
        drop(release);
        let mut leases = Vec::new();
        for attach in attaching {
            leases.push(attach.await.unwrap().unwrap());
        }

        assert_eq!(source.peak.load(Ordering::SeqCst), 2);
        assert_eq!(supervisor.active_profiles(), 4);
        drop(leases);
        assert_eq!(supervisor.shutdown().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn a_failed_open_is_reported_to_every_caller_and_an_exact_retry_recovers() {
        let root = TestProfileRoot::new();
        let broken_key = root.path().join("missing.key");
        let supervisor = ProfileSupervisor::new(
            Arc::new(RepairableSource {
                root: root.root().to_path_buf(),
                key_path: root.key_path().to_path_buf(),
                broken_profile: "broken".to_string(),
                broken_key: broken_key.clone(),
            }),
            ProfileSupervisorConfig::default(),
        )
        .unwrap();

        let healthy = supervisor.attach("healthy").await.unwrap();
        let refused = supervisor.attach("broken").await.unwrap_err();

        assert!(
            matches!(refused, ProfileSupervisorError::Open(_)),
            "{refused:?}"
        );
        // The rendered error stays generic; the local cause is retained for an
        // operator reading the returned error, never for a log field.
        let reported = format!("{refused:#}");
        assert_eq!(reported, "opening the profile failed");
        assert!(!reported.contains(&broken_key.display().to_string()));
        assert_eq!(refused.code(), "open_failed");
        // Debug reaches assertion messages, panic output, and structured logs, so it
        // must stay as bounded as the message.
        let debugged = format!("{refused:?}");
        assert_eq!(debugged, "ProfileSupervisorError { code: \"open_failed\" }");
        assert!(!debugged.contains(&broken_key.display().to_string()));
        assert!(
            format!("{:#}", refused.open_source().unwrap()).contains("broken"),
            "the retained cause must still identify the profile"
        );
        // The refused profile leaves nothing behind, and the unrelated profile is
        // untouched by its neighbour's failure.
        assert!(supervisor.run_state("broken").is_none());
        assert_eq!(supervisor.active_profiles(), 1);
        assert!(
            healthy
                .services()
                .unwrap()
                .conversations()
                .device_id()
                .is_ok()
        );
        assert!(!root.is_locked("broken"));

        std::fs::write(&broken_key, [7_u8; 32]).unwrap();
        let repaired = supervisor.attach("broken").await.unwrap();

        assert_eq!(repaired.profile_id(), "broken");
        assert_eq!(supervisor.active_profiles(), 2);
        drop((healthy, repaired));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_failed_runtime_is_reported_without_ending_other_profiles() {
        let root = TestProfileRoot::new();
        let (trigger, triggered) = oneshot::channel();
        let supervisor = ProfileSupervisor::new(
            Arc::new(FailingRuntimeSource {
                inner: root.settings(),
                failing_profile: "failing".to_string(),
                trigger: Mutex::new(Some(triggered)),
            }),
            ProfileSupervisorConfig::default(),
        )
        .unwrap();

        let healthy = supervisor.attach("healthy").await.unwrap();
        let failing = supervisor.attach("failing").await.unwrap();
        let mut state = supervisor.watch_run_state("failing").unwrap();
        trigger.send(()).unwrap();
        state
            .wait_for(|state| *state != ProfileRunState::Running)
            .await
            .unwrap();

        assert_eq!(failing.run_state(), ProfileRunState::Failed);
        assert_eq!(
            supervisor.run_state("healthy"),
            Some(ProfileRunState::Running)
        );
        assert!(
            healthy
                .services()
                .unwrap()
                .conversations()
                .device_id()
                .is_ok()
        );
        // A failed runtime with an attached client is never silently replaced.
        let refused = supervisor.attach("failing").await.unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::FailedRuntime),
            "{refused:?}"
        );

        drop(failing);
        let failures = supervisor.reap_failed().await;

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "failing");
        assert!(format!("{:#}", failures[0].1).contains("profile runtime failed"));
        assert!(!root.is_locked("failing"));
        assert!(root.is_locked("healthy"));

        let recovered = supervisor.attach("failing").await.unwrap();
        assert_eq!(recovered.run_state(), ProfileRunState::Running);
        drop((healthy, recovered));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_attached_profile_is_retained_and_an_idle_one_is_evicted() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let lease = supervisor.attach("retained").await.unwrap();
        let device = lease
            .services()
            .unwrap()
            .conversations()
            .device_id()
            .unwrap();

        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 0);
        assert_eq!(supervisor.active_profiles(), 1);
        assert!(root.is_locked("retained"));

        drop(lease);
        // A recently idle profile is retained until it exceeds the idle window.
        assert_eq!(
            supervisor
                .evict_idle(Duration::from_secs(3_600))
                .await
                .unwrap(),
            0
        );
        assert_eq!(supervisor.active_profiles(), 1);

        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 1);
        assert_eq!(supervisor.active_profiles(), 0);
        assert!(!root.is_locked("retained"));

        // Eviction released resources, not durable state.
        let reopened = supervisor.attach("retained").await.unwrap();
        assert_eq!(
            reopened
                .services()
                .unwrap()
                .conversations()
                .device_id()
                .unwrap(),
            device
        );
        drop(reopened);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_idle_sweep_uses_the_configured_window() {
        let root = TestProfileRoot::new();
        let supervisor = ProfileSupervisor::new(
            Arc::new(root.settings()),
            ProfileSupervisorConfig {
                idle_timeout: Duration::ZERO,
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();
        let lease = supervisor.attach("swept").await.unwrap();

        assert_eq!(supervisor.sweep_idle().await.unwrap(), 0);
        drop(lease);
        assert_eq!(supervisor.sweep_idle().await.unwrap(), 1);
        assert!(!root.is_locked("swept"));
    }

    #[tokio::test]
    async fn shutdown_closes_every_runtime_exactly_once_and_releases_locks() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let leases = vec![
            supervisor.attach("stop-a").await.unwrap(),
            supervisor.attach("stop-b").await.unwrap(),
            supervisor.attach("stop-c").await.unwrap(),
        ];
        drop(leases);

        assert_eq!(supervisor.shutdown().await.unwrap(), 3);
        for profile in ["stop-a", "stop-b", "stop-c"] {
            assert!(!root.is_locked(profile), "{profile} lock must be released");
        }
        assert_eq!(supervisor.active_profiles(), 0);
        assert_eq!(supervisor.shutdown().await.unwrap(), 0);

        let refused = supervisor.attach("stop-a").await.unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::ShuttingDown),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn shutdown_closes_a_profile_that_was_still_attached() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let lease = supervisor.attach("attached").await.unwrap();

        assert_eq!(supervisor.shutdown().await.unwrap(), 1);
        assert_eq!(lease.run_state(), ProfileRunState::Stopped);
        drop(lease);
        assert!(!root.is_locked("attached"));
    }

    #[tokio::test]
    async fn an_admitted_operation_and_a_close_never_overlap() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let lease = supervisor.attach("racing").await.unwrap();
        let services = lease.services().unwrap();
        let activity = services.activity().clone();
        drop(lease);

        // The operation wins the race: it is admitted before eviction decides, so
        // eviction refuses and the stores it is using stay open.
        let operation = activity.try_begin().unwrap();
        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 0);
        assert!(!activity.is_closing());
        assert!(services.conversations().device_id().is_ok());
        assert!(root.is_locked("racing"));

        // The close wins the next race: once it commits, no operation is admitted
        // again, so nothing can start against stores that are going away.
        drop((operation, services));
        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 1);
        assert!(activity.is_closing());
        assert_eq!(
            activity.try_begin().unwrap_err(),
            ProfileActivityError::Closing
        );
        assert!(!root.is_locked("racing"));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_close_waits_for_an_admitted_operation_before_dropping_stores() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let lease = supervisor.attach("draining").await.unwrap();
        let services = lease.services().unwrap();
        let activity = services.activity().clone();
        let operation = activity.try_begin().unwrap();

        // Shutdown closes unconditionally, so it must drain rather than refuse.
        let closing = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.shutdown().await }
        });
        tokio::time::timeout(Duration::from_secs(5), activity.wait_closing())
            .await
            .expect("the close transition must happen before the drain");

        // The close is parked on this operation, and the whole close transition
        // already happened: the retained lease cannot start new work, no further
        // operation is admitted, and the operation in flight still owns live stores.
        let refused = lease.services().unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::Revoked),
            "{refused:?}"
        );
        assert_eq!(
            activity.try_begin().unwrap_err(),
            ProfileActivityError::Closing
        );
        assert!(services.conversations().device_id().is_ok());
        assert!(root.is_locked("draining"));

        drop((operation, services));
        assert_eq!(closing.await.unwrap().unwrap(), 1);
        assert!(!root.is_locked("draining"));
        drop(lease);
    }

    #[tokio::test]
    async fn a_stuck_operation_fails_the_close_instead_of_dropping_stores_silently() {
        let root = TestProfileRoot::new();
        let owner = ProfileSupervisor::new(
            Arc::new(root.settings()),
            ProfileSupervisorConfig {
                operation_drain_timeout: Duration::from_millis(10),
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();
        let lease = owner.attach("stuck").await.unwrap();
        let services = lease.services().unwrap();
        let stuck = services.activity().try_begin().unwrap();
        drop(lease);

        let error = owner.shutdown().await.unwrap_err();

        // Classified by type: the message is a diagnostic, not the contract.
        assert!(is_operation_drain_timeout(&error), "{error:#}");
        assert_eq!(owner.shutdown().await.unwrap(), 0);

        // The stuck operation still holds the lock, so a fresh attach reports the
        // stable locked refusal rather than an opaque open failure.
        let refused = supervisor(&root).attach("stuck").await.unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::ProfileLocked),
            "{refused:?}"
        );

        drop((stuck, services));
        let reopened = supervisor(&root).attach("stuck").await.unwrap();
        assert_eq!(reopened.profile_id(), "stuck");
    }

    #[tokio::test]
    async fn a_profile_owned_by_another_service_fails_closed() {
        let root = TestProfileRoot::new();
        let owner = supervisor(&root);
        let lease = owner.attach("owned").await.unwrap();

        // A second service over the same root is exactly the duplicate-ownership case
        // ADR 0008 requires to fail closed.
        let refused = supervisor(&root).attach("owned").await.unwrap_err();

        assert!(
            matches!(refused, ProfileSupervisorError::ProfileLocked),
            "{refused:?}"
        );
        assert_eq!(refused.code(), "profile_locked");
        assert_eq!(
            format!("{refused}"),
            "the profile is locked by another owner"
        );
        assert!(refused.open_source().is_none());
        drop(lease);
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_refuses_gated_opens_without_reporting_them_as_failures() {
        let root = TestProfileRoot::new();
        let (entered, mut entering) = tokio::sync::mpsc::unbounded_channel();
        let (release, releasing) = mpsc::channel();
        let supervisor = ProfileSupervisor::new(
            Arc::new(GatedSource {
                inner: root.settings(),
                entered,
                release: Mutex::new(releasing),
                concurrent: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }),
            ProfileSupervisorConfig {
                max_pending_opens: 1,
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();

        // One open holds the only admission permit and is parked inside `configure`.
        let holding = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.attach("gate-holder").await.map(|_| ()) }
        });
        assert_eq!(entering.recv().await.unwrap(), "gate-holder");

        // Two more requests coalesce onto one open that is waiting for that permit.
        let waiting = (0..2)
            .map(|_| {
                let supervisor = Arc::clone(&supervisor);
                tokio::spawn(async move { supervisor.attach("gate-waiter").await.map(|_| ()) })
            })
            .collect::<Vec<_>>();
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            matches!(
                guard(&supervisor.state).slots.get("gate-waiter"),
                Some(ProfileSlot::Pending(_))
            ),
            "the second profile must be waiting on the open permit"
        );
        assert!(
            entering.try_recv().is_err(),
            "the waiting open must not have reached configuration"
        );

        let closing = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.shutdown().await }
        });

        // A permit that shutdown revoked is a stopping service, not a failed open.
        for waiter in waiting {
            let refused = waiter.await.unwrap().unwrap_err();
            assert!(
                matches!(refused, ProfileSupervisorError::ShuttingDown),
                "{refused:?}"
            );
        }
        release.send(()).unwrap();
        drop(release);
        let refused = holding.await.unwrap().unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::ShuttingDown),
            "{refused:?}"
        );
        // Nothing was ever published, so nothing was closed, and the profile the open
        // completed into was closed by the open itself.
        assert_eq!(closing.await.unwrap().unwrap(), 0);
        assert!(!root.is_locked("gate-holder"));
    }

    #[tokio::test]
    async fn a_blocked_shutdown_revokes_access_before_it_returns() {
        let root = TestProfileRoot::new();
        let (stopping, mut stopped) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = oneshot::channel();
        let supervisor = ProfileSupervisor::new(
            Arc::new(BlockedShutdownSource {
                inner: root.settings(),
                stopping: Mutex::new(Some(stopping)),
                release: Mutex::new(Some(released)),
            }),
            ProfileSupervisorConfig::default(),
        )
        .unwrap();
        let lease = supervisor.attach("blocked").await.unwrap();
        assert!(lease.services().is_ok());

        let closing = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.shutdown().await }
        });
        // The task set has observed the stop request and is holding shutdown open.
        stopped.recv().await.unwrap();

        // Access is already revoked, so a retained lease cannot start new work at any
        // point during the drain.
        let refused = lease.services().unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::Revoked),
            "{refused:?}"
        );

        release.send(()).unwrap();
        assert_eq!(closing.await.unwrap().unwrap(), 1);
        assert!(!root.is_locked("blocked"));
        drop(lease);
    }

    #[tokio::test]
    async fn shutdown_revokes_a_retained_lease_before_it_returns() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let lease = supervisor.attach("retained").await.unwrap();
        assert!(lease.services().is_ok());

        assert_eq!(supervisor.shutdown().await.unwrap(), 1);

        // The client still holds its lease object. It must no longer reach the
        // profile, and the profile's databases and exclusive lock must already be
        // released rather than waiting for the client to let go.
        assert!(!root.is_locked("retained"));
        let refused = lease.services().unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::Revoked),
            "{refused:?}"
        );
        assert_eq!(refused.code(), "revoked");
        assert_eq!(lease.run_state(), ProfileRunState::Stopped);
        drop(lease);
    }

    #[tokio::test]
    async fn a_running_profile_operation_retains_the_profile() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        let lease = supervisor.attach("operating").await.unwrap();
        let services = lease.services().unwrap();
        // Exactly what a pairing sweep or a received relay page holds while it works.
        let operation = services.activity().try_begin().unwrap();
        drop(services);
        drop(lease);

        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 0);
        assert_eq!(supervisor.active_profiles(), 1);
        assert!(root.is_locked("operating"));

        drop(operation);
        assert_eq!(supervisor.evict_idle(Duration::ZERO).await.unwrap(), 1);
        assert!(!root.is_locked("operating"));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_reports_a_concurrent_close_that_never_finished() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        drop(supervisor.attach("concurrent").await.unwrap());
        // Another caller owns this profile's close and dies without completing it.
        let closing = {
            let mut state = guard(&supervisor.state);
            begin_close(&mut state, "concurrent", CloseAdmission::Unconditional).unwrap()
        };
        drop(closing);

        let error = supervisor.shutdown().await.unwrap_err();

        // Shutdown waited on that close and must not report a clean stop for it.
        let reported = format!("{error:#}");
        assert!(reported.contains("concurrent"), "{reported}");
        assert!(reported.contains("abandoned"), "{reported}");
    }

    #[tokio::test]
    async fn shutdown_counts_a_concurrent_close_that_finished() {
        let root = TestProfileRoot::new();
        let (stopping, mut stopped) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = oneshot::channel();
        let supervisor = ProfileSupervisor::new(
            Arc::new(BlockedShutdownSource {
                inner: root.settings(),
                stopping: Mutex::new(Some(stopping)),
                release: Mutex::new(Some(released)),
            }),
            ProfileSupervisorConfig::default(),
        )
        .unwrap();
        drop(supervisor.attach("shared-close").await.unwrap());

        // An eviction owns this close and parks inside the task-set drain.
        let evicting = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.evict_idle(Duration::ZERO).await }
        });
        stopped.recv().await.unwrap();

        let closing = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.shutdown().await }
        });
        release.send(()).unwrap();

        assert_eq!(evicting.await.unwrap().unwrap(), 1);
        // Shutdown waited on the close it did not own and counts it exactly once.
        assert_eq!(closing.await.unwrap().unwrap(), 1);
        assert!(!root.is_locked("shared-close"));
    }

    #[tokio::test]
    async fn an_open_in_flight_counts_against_the_profile_limit() {
        let root = TestProfileRoot::new();
        let (entered, mut entering) = tokio::sync::mpsc::unbounded_channel();
        let (release, releasing) = mpsc::channel();
        let supervisor = ProfileSupervisor::new(
            Arc::new(GatedSource {
                inner: root.settings(),
                entered,
                release: Mutex::new(releasing),
                concurrent: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }),
            ProfileSupervisorConfig {
                max_active_profiles: 1,
                ..ProfileSupervisorConfig::default()
            },
        )
        .unwrap();

        let opening = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.attach("opening").await.map(|_| ()) }
        });
        assert_eq!(entering.recv().await.unwrap(), "opening");

        // The bound covers what the registry is holding resources for, and an open in
        // flight already owns a directory, a lock, and database handles.
        let refused = supervisor.attach("second").await.unwrap_err();
        assert!(
            matches!(refused, ProfileSupervisorError::ActiveProfileLimit),
            "{refused:?}"
        );

        release.send(()).unwrap();
        drop(release);
        opening.await.unwrap().unwrap();
        assert_eq!(supervisor.active_profiles(), 1);
        assert_eq!(supervisor.shutdown().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_close_abandoned_by_its_owner_does_not_strand_later_requests() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);
        drop(supervisor.attach("stranded").await.unwrap());
        let closing = {
            let mut state = guard(&supervisor.state);
            begin_close(&mut state, "stranded", CloseAdmission::Unconditional).unwrap()
        };
        closing.active.close(Duration::from_secs(5)).await.unwrap();

        // The owner dies before it can remove its slot, exactly as an unwinding task
        // would. Its completion signal must still reach every waiter.
        let mut waiting = match guard(&supervisor.state).slots.get("stranded") {
            Some(ProfileSlot::Closing(completed)) => completed.clone(),
            _ => panic!("the slot must be closing"),
        };
        drop(closing);
        assert_eq!(*waiting.borrow_and_update(), Some(CloseOutcome::Abandoned));

        assert!(!root.is_locked("stranded"));
        let reattached = supervisor.attach("stranded").await.unwrap();
        assert_eq!(reattached.profile_id(), "stranded");
        drop(reattached);
        supervisor.shutdown().await.unwrap();
    }

    #[test]
    fn a_zero_bound_is_refused_with_a_stable_configuration_error() {
        let root = TestProfileRoot::new();
        let refuse = |config| {
            ProfileSupervisor::new(Arc::new(root.settings()), config)
                .err()
                .expect("a zero bound must be refused")
        };

        assert_eq!(
            refuse(ProfileSupervisorConfig {
                max_active_profiles: 0,
                ..ProfileSupervisorConfig::default()
            }),
            ProfileSupervisorConfigError::ActiveProfiles
        );
        assert_eq!(
            refuse(ProfileSupervisorConfig {
                max_pending_opens: 0,
                ..ProfileSupervisorConfig::default()
            }),
            ProfileSupervisorConfigError::ConcurrentOpens
        );
        assert_eq!(
            refuse(ProfileSupervisorConfig {
                max_clients_per_profile: 0,
                ..ProfileSupervisorConfig::default()
            }),
            ProfileSupervisorConfigError::ClientsPerProfile
        );
        // A deliberately small bound remains valid.
        assert!(
            ProfileSupervisor::new(
                Arc::new(root.settings()),
                ProfileSupervisorConfig {
                    max_active_profiles: 1,
                    max_pending_opens: 1,
                    max_clients_per_profile: 1,
                    operation_drain_timeout: Duration::from_millis(1),
                    idle_timeout: Duration::ZERO,
                },
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn an_invalid_profile_identifier_is_refused_before_any_filesystem_work() {
        let root = TestProfileRoot::new();
        let supervisor = supervisor(&root);

        for profile in ["", "../escape", "profile.with.dots", &"a".repeat(64)] {
            let refused = supervisor.attach(profile).await.unwrap_err();
            assert!(
                matches!(refused, ProfileSupervisorError::InvalidProfile),
                "{profile:?} must be refused"
            );
        }
        assert_eq!(supervisor.active_profiles(), 0);
    }
}
