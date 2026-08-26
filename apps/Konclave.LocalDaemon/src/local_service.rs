use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use KonclaveAdapterTransport::{DeliveredEvent, DeliveredPayload, DeliveredRole};
use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveDomainCore::AdapterConsumerId;
use KonclaveLocalServiceTransport::{
    AdapterAuthorizationRegistry, AdapterRegistration, LocalServiceBinding, LocalServiceEndpoint,
    LocalServiceErrorCode, LocalServiceListener, LocalServiceRequest, LocalServiceResponse,
    MAX_RPC_FRAME_BYTES, RequestId, complete_service_handshake, read_request, write_response,
};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::adapter::{DeliveryAttachment, SystemUnixClock, UnixClock};
use crate::mcp::{AuthorizationContext, AuthorizationHook, StdioServer};
use crate::profile_runtime::ProfileServices;
use crate::profile_supervisor::{ProfileSupervisor, ProfileSupervisorConfig};
use crate::runtime::ProfileSource;

const MAX_LEDGER_ENTRIES: usize = 256;
const MAX_LEDGER_BYTES: usize = 64 * 1024 * 1024;
const CLIENT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const AUTHORIZATION_RECHECK_INTERVAL: Duration = Duration::from_secs(1);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(85);
const MAX_DELIVERY_EVENTS: u16 = 16;
const MAX_DELIVERY_WAIT_MILLISECONDS: u32 = 30_000;

/// Validated inputs loaded before the shared service can start.
///
/// Secret custody and adapter registration are injected rather than read from
/// process-global defaults. An absent or invalid installation therefore fails before
/// an endpoint is opened and can never select the legacy per-session host.
pub(crate) struct SharedLocalServiceConfig {
    pub(crate) endpoint: LocalServiceEndpoint,
    pub(crate) service_identity: Arc<LocalServiceIdentity>,
    pub(crate) adapter_registry: Arc<dyn AdapterAuthorizationRegistry>,
    pub(crate) profile_source: Arc<dyn ProfileSource>,
    pub(crate) supervisor: ProfileSupervisorConfig,
}

/// Runs one authenticated per-user local service until shutdown.
///
/// # Errors
///
/// Returns endpoint, profile-supervision, handshake-host, or coordinated-shutdown
/// failures. A failed client is isolated to its connection and never stops another
/// profile.
pub(crate) async fn run_shared_local_service_until<F>(
    config: SharedLocalServiceConfig,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    let supervisor = ProfileSupervisor::new(config.profile_source, config.supervisor)
        .context("validating shared profile supervision")?;
    let mut listener = LocalServiceListener::bind(&config.endpoint)
        .await
        .context("binding the shared local endpoint")?;
    let ledger = Arc::new(Mutex::new(RequestLedger::default()));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut clients = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok(stream) => {
                        let registry = Arc::clone(&config.adapter_registry);
                        let identity = Arc::clone(&config.service_identity);
                        let supervisor = Arc::clone(&supervisor);
                        let ledger = Arc::clone(&ledger);
                        let stop = stop_rx.clone();
                        clients.spawn(async move {
                            serve_client(stream, registry, identity, supervisor, ledger, stop).await
                        });
                    }
                    Err(
                        KonclaveLocalServiceTransport::LocalServiceTransportError::UnauthorizedPeer
                        | KonclaveLocalServiceTransport::LocalServiceTransportError::PeerVerificationUnavailable,
                    ) => {}
                    Err(error) => return Err(error).context("accepting a shared local client"),
                }
            }
            joined = clients.join_next(), if !clients.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(_))) => tracing::warn!(
                        outcome = "client_closed_with_error",
                        "shared local client connection ended"
                    ),
                    Some(Err(error)) => tracing::error!(
                        outcome = "client_task_failed",
                        panic = error.is_panic(),
                        "shared local client task ended unexpectedly"
                    ),
                }
            }
        }
    }

    let _ = stop_tx.send(true);
    let drained = timeout(CLIENT_SHUTDOWN_TIMEOUT, async {
        while clients.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        clients.shutdown().await;
        tracing::warn!(
            outcome = "client_shutdown_timeout",
            "shared local clients exceeded the shutdown deadline"
        );
    }
    supervisor.shutdown().await?;
    Ok(())
}

async fn serve_client(
    mut stream: KonclaveLocalServiceTransport::LocalServiceServerStream,
    registry: Arc<dyn AdapterAuthorizationRegistry>,
    identity: Arc<LocalServiceIdentity>,
    supervisor: Arc<ProfileSupervisor>,
    ledger: Arc<Mutex<RequestLedger>>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let channel = complete_service_handshake(&mut stream, registry.as_ref(), identity.as_ref())
        .await
        .context("authenticating a shared local client")?;
    let registration = channel
        .service_registration()
        .cloned()
        .context("retaining the authenticated adapter registration")?;
    let binding = channel.binding().clone();
    let lease = supervisor
        .attach(binding.profile().as_str())
        .await
        .context("attaching a shared local client profile")?;
    let services = lease.services().context("loading bound profile services")?;
    let handler = operation_handler(&services);
    let store = services.conversations().store();
    let mut state = ClientRequestState {
        ledger,
        registry,
        registration,
        consumer: AdapterConsumerId::from_bytes(*binding.client_instance().as_bytes()),
        binding,
        handler,
        services,
        store,
        delivery: None,
        shutdown: stop.clone(),
    };
    let mut authorization_check = tokio::time::interval(AUTHORIZATION_RECHECK_INTERVAL);
    authorization_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = async {
        loop {
            let request = tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                    continue;
                }
                _ = authorization_check.tick() => {
                    if !state.authorization_is_active() {
                        break;
                    }
                    continue;
                }
                request = read_request(&mut stream) => match request {
                    Ok(request) => request,
                    Err(KonclaveLocalServiceTransport::LocalServiceTransportError::ChannelClosed) => break,
                    Err(error) => return Err(error).context("reading a shared local request"),
                }
            };
            let response = execute_idempotent(&mut state, request).await;
            write_response(&mut stream, &response)
                .await
                .context("writing a shared local response")?;
        }
        Ok(())
    }
    .await;

    if let Some(delivery) = state.delivery {
        let store = Arc::clone(&state.store);
        tokio::task::spawn_blocking(move || delivery.release(&store))
            .await
            .context("joining shared local delivery lease release")?
            .context("releasing a shared local delivery lease")?;
    }
    result
}

fn operation_handler(services: &ProfileServices) -> StdioServer {
    let authorize: AuthorizationHook = Arc::new(|context: AuthorizationContext<'_>| {
        if is_tool_operation(context.method) {
            Ok(())
        } else {
            anyhow::bail!("local service operation is not authorized")
        }
    });
    StdioServer::new(
        services.conversations().clone(),
        services.applications().cloned(),
        services.pairings().cloned(),
        services.health().clone(),
        authorize,
    )
}

struct ClientRequestState {
    ledger: Arc<Mutex<RequestLedger>>,
    registry: Arc<dyn AdapterAuthorizationRegistry>,
    registration: AdapterRegistration,
    consumer: AdapterConsumerId,
    binding: LocalServiceBinding,
    handler: StdioServer,
    services: ProfileServices,
    store: Arc<crate::persistence::ProfileStore>,
    delivery: Option<DeliveryAttachment>,
    shutdown: watch::Receiver<bool>,
}

impl ClientRequestState {
    fn authorization_is_active(&self) -> bool {
        self.registry.active_registration(
            self.binding.adapter_key_id(),
            self.binding.adapter_key_version(),
        ) == Some(self.registration.clone())
    }
}

async fn execute_idempotent(
    state: &mut ClientRequestState,
    request: LocalServiceRequest,
) -> LocalServiceResponse {
    let key = LedgerKey::new(&state.binding, request.request_id());
    match begin_request(&state.ledger, key.clone(), &request) {
        LedgerDecision::Cached(response) => response,
        LedgerDecision::Conflict => {
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Conflict)
        }
        LedgerDecision::Busy => {
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Busy)
        }
        LedgerDecision::Wait(mut outcome) => match outcome
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|response| response.clone())
        {
            Some(response) => response,
            None => {
                LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Internal)
            }
        },
        LedgerDecision::Execute => {
            let mut completion =
                RequestCompletion::new(Arc::clone(&state.ledger), key, request.request_id());
            let response =
                with_operation_deadline(request.request_id(), dispatch_request(state, &request))
                    .await;
            completion.complete(response.clone());
            response
        }
    }
}

async fn with_operation_deadline<F>(request_id: RequestId, operation: F) -> LocalServiceResponse
where
    F: Future<Output = LocalServiceResponse>,
{
    timeout(OPERATION_TIMEOUT, operation)
        .await
        .unwrap_or_else(|_| {
            LocalServiceResponse::failure(request_id, LocalServiceErrorCode::DeadlineExceeded)
        })
}

async fn dispatch_request(
    state: &mut ClientRequestState,
    request: &LocalServiceRequest,
) -> LocalServiceResponse {
    let operation = request.operation().as_str();
    let result = match operation {
        "service.status" => service_status(state.services.clone(), Arc::clone(&state.store)).await,
        "delivery.claim" => {
            delivery_claim(
                &mut state.delivery,
                state.consumer,
                &state.store,
                &mut state.shutdown,
                request.payload(),
            )
            .await
        }
        "delivery.acknowledge" => {
            delivery_finish(&state.delivery, &state.store, request.payload(), true).await
        }
        "delivery.release" => {
            delivery_finish(&state.delivery, &state.store, request.payload(), false).await
        }
        _ if is_tool_operation(operation) => {
            state
                .handler
                .dispatch_json(operation, request.payload())
                .await
        }
        _ => Err("unknown_operation".to_string()),
    };
    response_from_result(request.request_id(), result)
}

fn response_from_result(
    request_id: RequestId,
    result: Result<Vec<u8>, String>,
) -> LocalServiceResponse {
    match result {
        Ok(payload) => LocalServiceResponse::success(request_id, payload).unwrap_or_else(|_| {
            LocalServiceResponse::failure(request_id, LocalServiceErrorCode::PayloadTooLarge)
        }),
        Err(code) => LocalServiceResponse::failure(request_id, operation_error_code(&code)),
    }
}

fn operation_error_code(code: &str) -> LocalServiceErrorCode {
    match code {
        "invalid_request"
        | "invalid_conversation_id"
        | "invalid_pairing_id"
        | "invalid_message_id"
        | "invalid_device_id"
        | "invalid_role"
        | "invalid_page_size"
        | "invalid_text"
        | "invalid_invitation"
        | "invalid_join_proof"
        | "invalid_welcome"
        | "invalid_peer_bindings"
        | "invalid_peer_binding"
        | "invalid_issuer_public_key"
        | "invalid_routing_id" => LocalServiceErrorCode::InvalidRequest,
        "unknown_operation" => LocalServiceErrorCode::UnknownOperation,
        "relay_not_configured" => LocalServiceErrorCode::ProfileUnavailable,
        "local_service_not_authorized" => LocalServiceErrorCode::NotAuthorized,
        "deadline_exceeded" => LocalServiceErrorCode::DeadlineExceeded,
        _ => LocalServiceErrorCode::Internal,
    }
}

fn is_tool_operation(operation: &str) -> bool {
    matches!(
        operation,
        "get_identity"
            | "create_conversation"
            | "list_conversations"
            | "send_message"
            | "read_messages"
            | "sync_messages"
            | "watch_messages"
            | "create_invitation"
            | "create_join_proof"
            | "add_member"
            | "accept_welcome"
            | "remove_member"
            | "change_member_role"
            | "create_pairing_capability"
            | "redeem_pairing_capability"
            | "get_pairing_status"
            | "authorize_pairing_joiner"
            | "authorize_pairing_inviter"
            | "sync_pairing"
            | "cancel_pairing"
            | "set_auto_delivery"
            | "delivery_status"
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceStatusResult {
    profile: String,
    device_id: String,
    relay_configured: bool,
    watched_conversations: u32,
    pending_events: u32,
    claimed_events: u32,
    delivery_degraded: bool,
}

async fn service_status(
    services: ProfileServices,
    store: Arc<crate::persistence::ProfileStore>,
) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || {
        let (pending_events, claimed_events) = store
            .remote_event_counts()
            .map_err(|_| "profile_unavailable".to_string())?;
        serde_json::to_vec(&ServiceStatusResult {
            profile: services.profile_id().to_string(),
            device_id: crate::mcp::encode_hex(
                services
                    .conversations()
                    .device_id()
                    .map_err(|_| "profile_unavailable".to_string())?
                    .as_bytes(),
            ),
            relay_configured: services.applications().is_some(),
            watched_conversations: services.health().watched_conversations(),
            pending_events,
            claimed_events,
            delivery_degraded: services.health().is_degraded(),
        })
        .map_err(|_| "response_encoding_failed".to_string())
    })
    .await
    .map_err(|_| "profile_unavailable".to_string())?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeliveryClaimRequest {
    max_events: u16,
    wait_milliseconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeliveryFinishRequest {
    notification_id: String,
    lease_generation: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryBatchResult {
    events: Vec<DeliveryEventResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryEventResult {
    notification_id: String,
    lease_generation: u64,
    sequence: u64,
    conversation: String,
    sender: String,
    relay_cursor: u64,
    payload: DeliveryPayloadResult,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeliveryPayloadResult {
    ApplicationText { text: String },
    MemberAdded { device: String, role: &'static str },
    MemberRemoved { device: String },
    MemberRoleChanged { device: String, role: &'static str },
    LocalAccessRemoved { device: String },
}

async fn delivery_claim(
    delivery: &mut Option<DeliveryAttachment>,
    consumer: AdapterConsumerId,
    store: &Arc<crate::persistence::ProfileStore>,
    shutdown: &mut watch::Receiver<bool>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let request: DeliveryClaimRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    if request.max_events == 0
        || request.max_events > MAX_DELIVERY_EVENTS
        || request.wait_milliseconds > MAX_DELIVERY_WAIT_MILLISECONDS
    {
        return Err("invalid_request".to_string());
    }
    if delivery.is_none() {
        let store = Arc::clone(store);
        let now = SystemUnixClock.now_unix_milliseconds();
        *delivery = Some(
            tokio::task::spawn_blocking(move || DeliveryAttachment::acquire(consumer, &store, now))
                .await
                .map_err(|_| "profile_unavailable".to_string())?
                .map_err(|_| "profile_unavailable".to_string())?,
        );
    }
    let events = delivery
        .as_ref()
        .ok_or_else(|| "profile_unavailable".to_string())?
        .wait_and_claim(
            store,
            shutdown,
            request.max_events,
            request.wait_milliseconds,
        )
        .await
        .map_err(|_| "profile_unavailable".to_string())?;
    serde_json::to_vec(&DeliveryBatchResult {
        events: events.into_iter().map(delivery_event_result).collect(),
    })
    .map_err(|_| "response_encoding_failed".to_string())
}

async fn delivery_finish(
    delivery: &Option<DeliveryAttachment>,
    store: &Arc<crate::persistence::ProfileStore>,
    payload: &[u8],
    acknowledge: bool,
) -> Result<Vec<u8>, String> {
    let request: DeliveryFinishRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    let notification_id = crate::mcp::decode_hex::<16>(&request.notification_id)
        .map_err(|_| "invalid_request".to_string())?;
    let attachment = delivery
        .as_ref()
        .ok_or_else(|| "profile_unavailable".to_string())?
        .clone();
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || {
        if acknowledge {
            attachment.acknowledge(&store, notification_id, request.lease_generation)
        } else {
            attachment.release_claim(&store, notification_id, request.lease_generation)
        }
    })
    .await
    .map_err(|_| "profile_unavailable".to_string())?
    .map_err(|_| "profile_unavailable".to_string())?;
    Ok(b"{}".to_vec())
}

fn delivery_event_result(event: DeliveredEvent) -> DeliveryEventResult {
    DeliveryEventResult {
        notification_id: crate::mcp::encode_hex(&event.notification_id),
        lease_generation: event.lease_generation,
        sequence: event.sequence,
        conversation: crate::mcp::encode_hex(&event.conversation),
        sender: crate::mcp::encode_hex(&event.sender),
        relay_cursor: event.relay_cursor,
        payload: match event.payload {
            DeliveredPayload::ApplicationText(text) => {
                DeliveryPayloadResult::ApplicationText { text }
            }
            DeliveredPayload::MemberAdded { device, role } => DeliveryPayloadResult::MemberAdded {
                device: crate::mcp::encode_hex(&device),
                role: delivery_role(role),
            },
            DeliveredPayload::MemberRemoved { device } => DeliveryPayloadResult::MemberRemoved {
                device: crate::mcp::encode_hex(&device),
            },
            DeliveredPayload::MemberRoleChanged { device, role } => {
                DeliveryPayloadResult::MemberRoleChanged {
                    device: crate::mcp::encode_hex(&device),
                    role: delivery_role(role),
                }
            }
            DeliveredPayload::LocalAccessRemoved { device } => {
                DeliveryPayloadResult::LocalAccessRemoved {
                    device: crate::mcp::encode_hex(&device),
                }
            }
        },
    }
}

const fn delivery_role(role: DeliveredRole) -> &'static str {
    match role {
        DeliveredRole::Administrator => "administrator",
        DeliveredRole::Member => "member",
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct LedgerKey {
    adapter_key_id: [u8; 16],
    adapter_key_version: u32,
    profile: String,
    request_id: [u8; 16],
}

impl LedgerKey {
    fn new(binding: &LocalServiceBinding, request_id: RequestId) -> Self {
        Self {
            adapter_key_id: *binding.adapter_key_id().as_bytes(),
            adapter_key_version: binding.adapter_key_version().get(),
            profile: binding.profile().as_str().to_string(),
            request_id: *request_id.as_bytes(),
        }
    }
}

struct LedgerEntry {
    operation: String,
    payload: Vec<u8>,
    outcome: watch::Sender<Option<LocalServiceResponse>>,
    stored_bytes: usize,
}

#[derive(Default)]
struct RequestLedger {
    entries: HashMap<LedgerKey, LedgerEntry>,
    order: VecDeque<LedgerKey>,
    stored_bytes: usize,
}

enum LedgerDecision {
    Execute,
    Wait(watch::Receiver<Option<LocalServiceResponse>>),
    Cached(LocalServiceResponse),
    Conflict,
    Busy,
}

fn begin_request(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: LedgerKey,
    request: &LocalServiceRequest,
) -> LedgerDecision {
    let mut ledger = lock(ledger);
    if let Some(entry) = ledger.entries.get(&key) {
        if entry.operation != request.operation().as_str() || entry.payload != request.payload() {
            return LedgerDecision::Conflict;
        }
        return entry.outcome.borrow().clone().map_or_else(
            || LedgerDecision::Wait(entry.outcome.subscribe()),
            LedgerDecision::Cached,
        );
    }
    let request_bytes = request
        .operation()
        .as_str()
        .len()
        .saturating_add(request.payload().len());
    let reservation = request_bytes.saturating_add(MAX_RPC_FRAME_BYTES);
    evict_completed(&mut ledger, 1, reservation);
    if ledger.entries.len() >= MAX_LEDGER_ENTRIES
        || ledger.stored_bytes.saturating_add(reservation) > MAX_LEDGER_BYTES
    {
        return LedgerDecision::Busy;
    }
    let (outcome, _) = watch::channel(None);
    ledger.order.push_back(key.clone());
    ledger.entries.insert(
        key,
        LedgerEntry {
            operation: request.operation().as_str().to_string(),
            payload: request.payload().to_vec(),
            outcome,
            stored_bytes: reservation,
        },
    );
    ledger.stored_bytes = ledger.stored_bytes.saturating_add(reservation);
    LedgerDecision::Execute
}

fn complete_request(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: &LedgerKey,
    response: LocalServiceResponse,
) {
    let mut ledger = lock(ledger);
    let encoded = response.encode().map_or(0, |payload| payload.len());
    let storage_change = if let Some(entry) = ledger.entries.get_mut(key) {
        let actual_bytes = entry
            .operation
            .len()
            .saturating_add(entry.payload.len())
            .saturating_add(encoded);
        let reserved_bytes = entry.stored_bytes;
        entry.stored_bytes = actual_bytes;
        entry.outcome.send_replace(Some(response));
        Some((reserved_bytes, actual_bytes))
    } else {
        None
    };
    if let Some((reserved_bytes, actual_bytes)) = storage_change {
        ledger.stored_bytes = ledger
            .stored_bytes
            .saturating_sub(reserved_bytes)
            .saturating_add(actual_bytes);
    }
    evict_completed(&mut ledger, 0, 0);
}

fn evict_completed(ledger: &mut RequestLedger, required_entries: usize, required_bytes: usize) {
    let mut pending_seen = 0;
    while ledger.entries.len().saturating_add(required_entries) > MAX_LEDGER_ENTRIES
        || ledger.stored_bytes.saturating_add(required_bytes) > MAX_LEDGER_BYTES
    {
        let Some(key) = ledger.order.pop_front() else {
            break;
        };
        let completed = ledger
            .entries
            .get(&key)
            .is_some_and(|entry| entry.outcome.borrow().is_some());
        if !completed {
            ledger.order.push_back(key);
            pending_seen += 1;
            if pending_seen >= ledger.order.len() {
                break;
            }
            continue;
        }
        pending_seen = 0;
        if let Some(entry) = ledger.entries.remove(&key) {
            ledger.stored_bytes = ledger.stored_bytes.saturating_sub(entry.stored_bytes);
        }
    }
}

struct RequestCompletion {
    ledger: Arc<Mutex<RequestLedger>>,
    key: LedgerKey,
    request_id: RequestId,
    completed: bool,
}

impl RequestCompletion {
    fn new(ledger: Arc<Mutex<RequestLedger>>, key: LedgerKey, request_id: RequestId) -> Self {
        Self {
            ledger,
            key,
            request_id,
            completed: false,
        }
    }

    fn complete(&mut self, response: LocalServiceResponse) {
        complete_request(&self.ledger, &self.key, response);
        self.completed = true;
    }
}

impl Drop for RequestCompletion {
    fn drop(&mut self) {
        if !self.completed {
            complete_request(
                &self.ledger,
                &self.key,
                LocalServiceResponse::failure(self.request_id, LocalServiceErrorCode::Internal),
            );
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use KonclaveCryptographicCore::LocalServiceIdentity;
    use KonclaveLocalServiceTransport::{
        AdapterAuthorizationRegistry, AdapterKeyId, AdapterKeyVersion, AdapterRegistration,
        ClientHandshakeRequest, ClientInstanceId, HarnessKind, InMemoryAdapterRegistry,
        LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceBinding, LocalServiceEndpoint,
        LocalServiceErrorCode, LocalServiceRequest, LocalServiceResponse, MAX_RPC_PAYLOAD_BYTES,
        OperationName, ProfileAuthorization, RequestId, ServiceProfileId,
        complete_client_handshake, connect_local_service, read_response, write_request,
    };
    use tokio::sync::oneshot;

    use super::{SharedLocalServiceConfig, run_shared_local_service_until};
    use crate::profile_runtime::{ProfileHost, ProfileHostOptions};
    use crate::profile_supervisor::ProfileSupervisorConfig;
    use crate::runtime::initialize_profile;
    use crate::test_support::TestProfileRoot;

    const TEST_STARTUP_DEADLINE: Duration = Duration::from_secs(5);
    const TEST_REQUEST_DEADLINE: Duration = Duration::from_secs(15);
    const TEST_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

    struct Fixture {
        root: TestProfileRoot,
        endpoint: LocalServiceEndpoint,
        service_identity: Arc<LocalServiceIdentity>,
        client_identity: LocalServiceIdentity,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
    }

    impl Fixture {
        fn new() -> (Self, Arc<InMemoryAdapterRegistry>) {
            let root = TestProfileRoot::new();
            let endpoint = LocalServiceEndpoint::parse(
                root.path()
                    .join("runtime")
                    .join("shared.sock")
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            let service_identity = Arc::new(LocalServiceIdentity::generate().unwrap());
            let client_identity = LocalServiceIdentity::generate().unwrap();
            let adapter_key_id = AdapterKeyId::from_bytes([7_u8; AdapterKeyId::LENGTH]);
            let adapter_key_version = AdapterKeyVersion::new(1).unwrap();
            let mut registry = InMemoryAdapterRegistry::new();
            registry
                .register(
                    adapter_key_id,
                    adapter_key_version,
                    AdapterRegistration::new(
                        client_identity.public_key(),
                        HarnessKind::Copilot,
                        ProfileAuthorization::Namespace(
                            ServiceProfileId::parse("session").unwrap(),
                        ),
                    ),
                )
                .unwrap();
            (
                Self {
                    root,
                    endpoint,
                    service_identity,
                    client_identity,
                    adapter_key_id,
                    adapter_key_version,
                },
                Arc::new(registry),
            )
        }

        fn config(
            &self,
            registry: Arc<dyn AdapterAuthorizationRegistry>,
        ) -> SharedLocalServiceConfig {
            SharedLocalServiceConfig {
                endpoint: self.endpoint.clone(),
                service_identity: Arc::clone(&self.service_identity),
                adapter_registry: registry,
                profile_source: Arc::new(self.root.settings()),
                supervisor: ProfileSupervisorConfig::default(),
            }
        }

        async fn connect(
            &self,
            profile: &str,
            instance_seed: u8,
        ) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
            tokio::time::timeout(TEST_STARTUP_DEADLINE, async {
                let mut stream = loop {
                    match connect_local_service(&self.endpoint).await {
                        Ok(stream) => break stream,
                        Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                };
                complete_client_handshake(
                    &mut stream,
                    &ClientHandshakeRequest {
                        adapter_key_id: self.adapter_key_id,
                        adapter_key_version: self.adapter_key_version,
                        client_instance: ClientInstanceId::from_bytes(
                            [instance_seed; ClientInstanceId::LENGTH],
                        ),
                        harness: HarnessKind::Copilot,
                        profile: ServiceProfileId::parse(profile).unwrap(),
                    },
                    &self.client_identity,
                    self.service_identity.public_key(),
                )
                .await
                .unwrap();
                stream
            })
            .await
            .expect("shared service startup and handshake exceeded the test deadline")
        }
    }

    struct RevocableRegistry {
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
        registration: Mutex<Option<AdapterRegistration>>,
    }

    impl RevocableRegistry {
        fn new(fixture: &Fixture) -> Self {
            Self {
                adapter_key_id: fixture.adapter_key_id,
                adapter_key_version: fixture.adapter_key_version,
                registration: Mutex::new(Some(AdapterRegistration::new(
                    fixture.client_identity.public_key(),
                    HarnessKind::Copilot,
                    ProfileAuthorization::Namespace(ServiceProfileId::parse("session").unwrap()),
                ))),
            }
        }

        fn revoke(&self) {
            *super::lock(&self.registration) = None;
        }
    }

    impl AdapterAuthorizationRegistry for RevocableRegistry {
        fn active_registration(
            &self,
            adapter_key_id: AdapterKeyId,
            adapter_key_version: AdapterKeyVersion,
        ) -> Option<AdapterRegistration> {
            if adapter_key_id != self.adapter_key_id
                || adapter_key_version != self.adapter_key_version
            {
                return None;
            }
            super::lock(&self.registration).clone()
        }
    }

    async fn request(
        stream: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
        seed: u8,
        operation: &str,
        payload: &[u8],
    ) -> LocalServiceResponse {
        tokio::time::timeout(TEST_REQUEST_DEADLINE, async {
            write_request(
                stream,
                &LocalServiceRequest::new(
                    RequestId::from_bytes([seed; 16]),
                    OperationName::parse(operation).unwrap(),
                    payload.to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            read_response(stream).await.unwrap()
        })
        .await
        .unwrap_or_else(|_| {
            panic!("shared service operation '{operation}' exceeded the test deadline")
        })
    }

    fn binding(profile: &str) -> LocalServiceBinding {
        LocalServiceBinding::new(
            LOCAL_SERVICE_PROTOCOL_VERSION,
            AdapterKeyId::from_bytes([7_u8; AdapterKeyId::LENGTH]),
            AdapterKeyVersion::new(1).unwrap(),
            ClientInstanceId::from_bytes([3_u8; ClientInstanceId::LENGTH]),
            HarnessKind::Copilot,
            ServiceProfileId::parse(profile).unwrap(),
        )
        .unwrap()
    }

    fn ledger_request(seed: u8, operation: &str, payload: Vec<u8>) -> LocalServiceRequest {
        LocalServiceRequest::new(
            RequestId::from_bytes([seed; 16]),
            OperationName::parse(operation).unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn the_request_ledger_bounds_pending_payload_and_response_reservations() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-ledger");
        let payload = vec![1_u8; MAX_RPC_PAYLOAD_BYTES];
        let mut admitted = 0_u8;

        for seed in 1..=32 {
            let request = ledger_request(seed, "send_message", payload.clone());
            let key = super::LedgerKey::new(&binding, request.request_id());
            match super::begin_request(&ledger, key, &request) {
                super::LedgerDecision::Execute => admitted = admitted.saturating_add(1),
                super::LedgerDecision::Busy => break,
                _ => panic!("a unique request returned an invalid ledger decision"),
            }
        }

        let state = super::lock(&ledger);
        assert!(admitted > 0);
        assert!(admitted < 32);
        assert!(state.stored_bytes <= super::MAX_LEDGER_BYTES);
        assert_eq!(state.entries.len(), usize::from(admitted));
    }

    #[test]
    fn the_request_ledger_admits_twenty_simultaneous_delivery_waits() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-delivery-capacity");
        for seed in 1..=20 {
            let request = ledger_request(
                seed,
                "delivery.claim",
                br#"{"maxEvents":16,"waitMilliseconds":30000}"#.to_vec(),
            );
            let key = super::LedgerKey::new(&binding, request.request_id());
            assert!(matches!(
                super::begin_request(&ledger, key, &request),
                super::LedgerDecision::Execute
            ));
        }
        let state = super::lock(&ledger);
        assert_eq!(state.entries.len(), 20);
        assert!(state.stored_bytes <= super::MAX_LEDGER_BYTES);
    }

    #[test]
    fn the_request_ledger_rejects_conflicting_reuse_and_caches_completion() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-conflict");
        let request = ledger_request(4, "get_identity", b"{}".to_vec());
        let key = super::LedgerKey::new(&binding, request.request_id());
        assert!(matches!(
            super::begin_request(&ledger, key.clone(), &request),
            super::LedgerDecision::Execute
        ));
        let response =
            LocalServiceResponse::success(request.request_id(), br#"{"device_id":"aa"}"#.to_vec())
                .unwrap();
        super::complete_request(&ledger, &key, response.clone());

        assert!(matches!(
            super::begin_request(&ledger, key.clone(), &request),
            super::LedgerDecision::Cached(cached) if cached == response
        ));
        let conflict = ledger_request(4, "create_conversation", b"{}".to_vec());
        assert!(matches!(
            super::begin_request(&ledger, key, &conflict),
            super::LedgerDecision::Conflict
        ));
    }

    #[test]
    fn an_abandoned_request_publishes_a_finite_internal_outcome() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-abandoned");
        let request = ledger_request(5, "get_identity", b"{}".to_vec());
        let key = super::LedgerKey::new(&binding, request.request_id());
        assert!(matches!(
            super::begin_request(&ledger, key.clone(), &request),
            super::LedgerDecision::Execute
        ));

        drop(super::RequestCompletion::new(
            Arc::clone(&ledger),
            key.clone(),
            request.request_id(),
        ));

        assert!(matches!(
            super::begin_request(&ledger, key, &request),
            super::LedgerDecision::Cached(LocalServiceResponse::Failure {
                code: LocalServiceErrorCode::Internal,
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn an_operation_that_never_finishes_has_a_finite_deadline_outcome() {
        let request_id = RequestId::from_bytes([6_u8; 16]);
        let response = super::with_operation_deadline(
            request_id,
            std::future::pending::<LocalServiceResponse>(),
        )
        .await;
        assert_eq!(
            response,
            LocalServiceResponse::failure(request_id, LocalServiceErrorCode::DeadlineExceeded)
        );
    }

    #[tokio::test]
    async fn the_shared_dispatcher_reuses_conversation_creation() {
        let root = TestProfileRoot::new();
        let runtime = initialize_profile(root.config("session-dispatch"))
            .await
            .unwrap();
        let host = ProfileHost::start(runtime, ProfileHostOptions::default()).unwrap();
        let handler = super::operation_handler(host.services());

        let response = tokio::time::timeout(
            TEST_REQUEST_DEADLINE,
            handler.dispatch_json("create_conversation", b"{}"),
        )
        .await
        .expect("shared dispatcher exceeded the test deadline")
        .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert!(decoded["conversation_id"].as_str().is_some());
        host.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_profiles_share_one_listener_but_not_one_identity() {
        let (fixture, registry) = Fixture::new();
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(registry),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut first = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the first client connected: {result:?}")
            }
            stream = fixture.connect("session-a", 1) => stream,
        };
        let mut second = fixture.connect("session-b", 2).await;

        let first_identity = request(&mut first, 1, "get_identity", b"{}").await;
        let second_identity = request(&mut second, 2, "get_identity", b"{}").await;
        let LocalServiceResponse::Success {
            payload: first_payload,
            ..
        } = first_identity
        else {
            panic!("first identity request failed");
        };
        let LocalServiceResponse::Success {
            payload: second_payload,
            ..
        } = second_identity
        else {
            panic!("second identity request failed");
        };
        assert_ne!(first_payload, second_payload);
        assert!(fixture.root.is_locked("session-a"));
        assert!(fixture.root.is_locked("session-b"));

        drop((first, second));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
        assert!(!fixture.root.is_locked("session-a"));
        assert!(!fixture.root.is_locked("session-b"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_retried_request_id_returns_one_recorded_outcome() {
        let (fixture, registry) = Fixture::new();
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(registry),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut first = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-retry", 3) => stream,
        };
        let initial = request(&mut first, 9, "create_conversation", b"{}").await;
        drop(first);

        let mut reconnected = fixture.connect("session-retry", 4).await;
        let retried = request(&mut reconnected, 9, "create_conversation", b"{}").await;
        assert_eq!(initial, retried);

        drop(reconnected);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revocation_closes_an_already_authenticated_connection() {
        let (fixture, _) = Fixture::new();
        let registry = Arc::new(RevocableRegistry::new(&fixture));
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(registry.clone()),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut client = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-revoked", 8) => stream,
        };
        assert!(matches!(
            request(&mut client, 8, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        registry.revoke();
        let closed = tokio::time::timeout(
            super::AUTHORIZATION_RECHECK_INTERVAL + Duration::from_secs(2),
            read_response(&mut client),
        )
        .await
        .expect("revoked connection was not closed within the authorization deadline");
        assert!(closed.is_err());

        drop(client);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }
}
