use std::collections::{BTreeSet, HashMap, VecDeque, hash_map::Entry};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use KonclaveCryptographicCore::{LocalServiceIdentity, derive_local_service_session_consumer_id};
use KonclaveDomainCore::{
    AdapterConsumerId, ApplicationContent, CollaborationPolicyBundle, CollaborationPolicyCost,
    CollaborationPolicyDecision, CollaborationPolicyEffect, CollaborationPolicyEvaluationContext,
    CollaborationPolicyEvaluationRequest, CollaborationPolicyResponseOutcome,
    CollaborationPolicyTarget, CollaborationPolicyUsage, ConversationId, ConversationRole,
    DeviceId, NotificationId, evaluate_collaboration_policy,
};
use KonclaveLocalServiceTransport::{
    AuthorizationBinding, AuthorizationEvidenceKind, AuthorizationEvidenceSet, HarnessKind,
    LocalServiceEndpoint, LocalServiceErrorCode, LocalServiceListener, LocalServiceRequest,
    LocalServiceResponse, MAX_GRANTS_PER_ISSUER, MAX_GRANTS_PER_PROFILE, MAX_RPC_FRAME_BYTES,
    MAX_SESSION_GRANTS, RequestId, ServiceProfileId, SessionCapabilities, SessionGrant,
    complete_authorization_service_handshake, read_request, write_response,
};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::adapter::{DeliveryAttachment, DeliveryWaitOutcome};
use crate::authorization_runtime::{
    AccountTrustedGrantRequest, AuthorizationRuntimeError, LiveAuthorizationRuntime,
};
use crate::clock::{SystemUnixClock, UnixClock};
use crate::mcp::{AuthorizationContext, AuthorizationHook, StdioServer};
use crate::persistence::{
    ActiveDirectedRequestClaim, ClaimDirectedRequest, ClaimedRemoteEvent,
    CollaborationActionAuthorization, CompleteDirectedRequest, DirectedRequestClaim,
    DirectedRequestClaimOutcome, DirectedRequestCompletionOutcome, RemoteEventPayload,
};
use crate::profile_runtime::ProfileServices;
use crate::profile_supervisor::{ProfileSupervisor, ProfileSupervisorConfig};
use crate::runtime::ProfileSource;

const MAX_LEDGER_ENTRIES: usize = 256;
const MAX_LEDGER_BYTES: usize = 64 * 1024 * 1024;
const CLIENT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_RECONCILIATION_THRESHOLD: Duration = Duration::from_secs(85);
const MAX_DELIVERY_EVENTS: u16 = 16;
const MAX_DELIVERY_WAIT_MILLISECONDS: u32 = 30_000;
const ACCOUNT_TRUSTED_GRANT_TTL: Duration = Duration::from_secs(60 * 60);
const LOCAL_REQUEST_OUTCOME_VERSION: u8 = 1;
const OUTCOME_PERSIST_ATTEMPTS: u8 = 3;
const OUTCOME_PERSIST_RETRY_DELAY: Duration = Duration::from_millis(50);
const COPILOT_HARNESS_CLAIMS: [&str; 4] = [
    "harness.native-permission-intersection",
    "harness.pre-tool-policy-gate",
    "harness.session-identity",
    "harness.single-delivery-consumer",
];
const MAX_COLLABORATION_SEND_AUTHORIZATIONS: usize = 16;
const COLLABORATION_SEND_AUTHORIZATION_TTL: Duration = Duration::from_secs(60);

/// Validated inputs loaded before the shared service can start.
///
/// Secret custody and the validated live authorization runtime are injected rather
/// than read from process-global defaults. Invalid durable authority therefore fails
/// before an endpoint is opened and can never select the legacy per-session host.
pub(crate) struct SharedLocalServiceConfig {
    pub(crate) endpoint: LocalServiceEndpoint,
    pub(crate) service_identity: Arc<LocalServiceIdentity>,
    pub(crate) authorization: Arc<LiveAuthorizationRuntime>,
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
    let mut authorization_reload =
        tokio::spawn(Arc::clone(&config.authorization).run_reload_loop(stop_rx.clone()));
    let mut authorization_reload_finished = false;
    let mut service_error = None;
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            result = &mut authorization_reload => {
                authorization_reload_finished = true;
                service_error = Some(match result {
                    Ok(Ok(())) => anyhow::Error::new(AuthorizationRuntimeError::UnexpectedStop),
                    Ok(Err(error)) => anyhow::Error::new(error),
                    Err(_) => anyhow::Error::new(AuthorizationRuntimeError::BlockingOperationFailed),
                });
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok(stream) => {
                        let authorization = Arc::clone(&config.authorization);
                        let identity = Arc::clone(&config.service_identity);
                        let supervisor = Arc::clone(&supervisor);
                        let ledger = Arc::clone(&ledger);
                        let stop = stop_rx.clone();
                        clients.spawn(async move {
                            serve_client(
                                stream,
                                authorization,
                                identity,
                                supervisor,
                                ledger,
                                stop,
                            )
                            .await
                        });
                    }
                    Err(
                        KonclaveLocalServiceTransport::LocalServiceTransportError::UnauthorizedPeer
                        | KonclaveLocalServiceTransport::LocalServiceTransportError::PeerVerificationUnavailable,
                    ) => {}
                    Err(error) => {
                        service_error = Some(
                            anyhow::Error::new(error).context("accepting a shared local client")
                        );
                        break;
                    }
                }
            }
            joined = clients.join_next(), if !clients.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(_))) => tracing::warn!(
                        outcome = "client_closed_with_error",
                        "shared local client connection ended"
                    ),
                    Some(Err(error)) => {
                        tracing::error!(
                            outcome = "client_task_failed",
                            panic = error.is_panic(),
                            "shared local client task ended unexpectedly"
                        );
                        service_error = Some(anyhow::anyhow!("shared local client task failed"));
                        break;
                    }
                }
            }
        }
    }

    stop_admission_and_cancel_precommit(&ledger, RequestCancellationReason::Shutdown);
    stop_tx.send_replace(true);
    if !authorization_reload_finished {
        match authorization_reload.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if service_error.is_none() => {
                service_error = Some(anyhow::Error::new(error));
            }
            Err(_) if service_error.is_none() => {
                service_error = Some(anyhow::Error::new(
                    AuthorizationRuntimeError::BlockingOperationFailed,
                ));
            }
            Ok(Err(_)) | Err(_) => {}
        }
    }
    let drained = timeout(CLIENT_SHUTDOWN_TIMEOUT, async {
        while clients.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            outcome = "client_shutdown_reconciling",
            "shared local clients crossed the shutdown threshold while reconciling"
        );
        while clients.join_next().await.is_some() {}
    }
    let supervisor_shutdown = supervisor.shutdown().await;
    if let Some(error) = service_error {
        return Err(error);
    }
    supervisor_shutdown?;
    Ok(())
}

async fn serve_client(
    mut stream: KonclaveLocalServiceTransport::LocalServiceServerStream,
    authorization: Arc<LiveAuthorizationRuntime>,
    identity: Arc<LocalServiceIdentity>,
    supervisor: Arc<ProfileSupervisor>,
    ledger: Arc<Mutex<RequestLedger>>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut authorization_status = authorization.subscribe();
    let now = SystemUnixClock.now_unix_milliseconds();
    let mut handshake = Box::pin(complete_authorization_service_handshake(
        &mut stream,
        authorization.as_ref(),
        identity.as_ref(),
        now,
    ));
    let channel = loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            changed = authorization_status.changed() => {
                if changed.is_err()
                    || matches!(
                        *authorization_status.borrow(),
                        crate::authorization_runtime::AuthorizationRuntimeStatus::Failed(_)
                    )
                {
                    return Ok(());
                }
            }
            result = &mut handshake => {
                break result.context("authenticating a shared local client")?;
            }
        }
    };
    drop(handshake);
    match channel.binding().clone() {
        AuthorizationBinding::Issuer {
            issuer_key_id,
            issuer_key_version,
            issuer_public_key,
            client_instance,
            harness,
        } => {
            serve_issuer_client(
                stream,
                authorization,
                ledger,
                IssuerConnection {
                    issuer_key_id,
                    issuer_key_version,
                    issuer_public_key,
                    client_instance,
                    harness,
                },
                stop,
                authorization_status,
            )
            .await
        }
        AuthorizationBinding::Session { grant, .. } => {
            serve_session_client(
                stream,
                authorization,
                supervisor,
                ledger,
                grant,
                stop,
                authorization_status,
            )
            .await
        }
    }
}

async fn serve_session_client(
    stream: KonclaveLocalServiceTransport::LocalServiceServerStream,
    authorization: Arc<LiveAuthorizationRuntime>,
    supervisor: Arc<ProfileSupervisor>,
    ledger: Arc<Mutex<RequestLedger>>,
    grant: SessionGrant,
    mut stop: watch::Receiver<bool>,
    mut authorization_status: watch::Receiver<
        crate::authorization_runtime::AuthorizationRuntimeStatus,
    >,
) -> anyhow::Result<()> {
    if !authorization.grant_is_active(&grant) {
        return Ok(());
    }
    let mut attach = Box::pin(supervisor.attach(grant.profile().as_str()));
    let lease = loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            changed = authorization_status.changed() => {
                if changed.is_err() || !authorization.grant_is_active(&grant) {
                    return Ok(());
                }
            }
            result = &mut attach => {
                break result.context("attaching a shared local client profile")?;
            }
        }
    };
    if *stop.borrow() || !authorization.grant_is_active(&grant) {
        return Ok(());
    }
    let services = lease.services().context("loading bound profile services")?;
    let handler = operation_handler(&services);
    let store = services.conversations().store();
    let consumer = derive_local_service_session_consumer_id(grant.session_public_key());
    let mut state = Some(ClientRequestState {
        ledger,
        authorization: Arc::clone(&authorization),
        consumer,
        grant,
        handler,
        services,
        store,
        delivery: None,
        collaboration_send_authorizations: HashMap::new(),
        shutdown: stop.clone(),
    });
    let mut stream = Some(stream);

    let result = async {
        loop {
            let active_stream = stream
                .as_mut()
                .context("shared local session stream is unavailable")?;
            let request_state = state
                .as_ref()
                .context("shared local session state is unavailable")?;
            let request = tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        None
                    } else {
                        continue;
                    }
                }
                changed = authorization_status.changed() => {
                    if changed.is_err() || !request_state.authorization_is_active() {
                        None
                    } else {
                        continue;
                    }
                }
                request = read_request(active_stream) => match request {
                    Ok(request) => Some(request),
                    Err(KonclaveLocalServiceTransport::LocalServiceTransportError::ChannelClosed) => None,
                    Err(error) => return Err(error).context("reading a shared local request"),
                }
            };
            let Some(request) = request else {
                drop(stream.take());
                break;
            };
            let operation = request.operation().as_str();
            let retirement = operation == "authorization.grant.retire";
            // Retirement is idempotent in the authorization store; the profile
            // request journal intentionally correlates replacement grants by key.
            let direct_dispatch =
                retirement || is_fresh_collaboration_policy_request(operation);
            let uses_ledger = !direct_dispatch;
            let mut request_state = state
                .take()
                .context("shared local session state is unavailable")?;
            let request_key = uses_ledger.then(|| {
                LedgerKey::for_grant(&request_state.grant, request.request_id())
            });
            let cancellation_ledger = Arc::clone(&request_state.ledger);
            let active_grant = request_state.grant.clone();
            let mut execution = tokio::spawn(async move {
                let response = if direct_dispatch {
                    dispatch_request(&mut request_state, &request).await
                } else {
                    execute_session_request(&mut request_state, request).await
                };
                (request_state, response)
            });
            let completed = loop {
                tokio::select! {
                    biased;
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            break Err(RequestCancellationReason::Shutdown);
                        }
                    }
                    changed = authorization_status.changed() => {
                        if changed.is_err()
                            || matches!(
                                *authorization_status.borrow(),
                                crate::authorization_runtime::AuthorizationRuntimeStatus::Failed(_)
                            )
                            || (!retirement && !authorization.grant_is_active(&active_grant))
                        {
                            break Err(RequestCancellationReason::AuthorizationLost);
                        }
                    }
                    result = &mut execution => break Ok(result),
                }
            };
            let (next_state, response) = match completed {
                Ok(result) => result.context("joining a shared local request")?,
                Err(reason) => {
                    if let Some(key) = request_key.as_ref() {
                        cancel_request(&cancellation_ledger, key, reason);
                    }
                    drop(stream.take());
                    let (next_state, response) = execution
                        .await
                        .context("joining a revoked shared local request")?;
                    state = Some(next_state);
                    let _ = response;
                    break;
                }
            };
            state = Some(next_state);
            let request_state = state
                .as_ref()
                .context("shared local session state is unavailable")?;
            if *stop.borrow()
                || matches!(
                    *authorization_status.borrow(),
                    crate::authorization_runtime::AuthorizationRuntimeStatus::Failed(_)
                )
                || (!retirement && !request_state.authorization_is_active())
            {
                drop(stream.take());
                break;
            }
            let active_stream = stream
                .as_mut()
                .context("shared local session stream is unavailable")?;
            write_response(active_stream, &response)
                .await
                .context("writing a shared local response")?;
            if retirement {
                drop(stream.take());
                break;
            }
        }
        Ok(())
    }
    .await;

    if let Some(state) = state.as_mut()
        && let Some(delivery) = state.delivery.take()
    {
        let store = Arc::clone(&state.store);
        tokio::task::spawn_blocking(move || delivery.release(&store))
            .await
            .context("joining shared local delivery lease release")?
            .context("releasing a shared local delivery lease")?;
    }
    result
}

#[derive(Clone)]
struct IssuerConnection {
    issuer_key_id: KonclaveLocalServiceTransport::IssuerKeyId,
    issuer_key_version: KonclaveLocalServiceTransport::IssuerKeyVersion,
    issuer_public_key: KonclaveDomainCore::Ed25519PublicKey,
    client_instance: KonclaveLocalServiceTransport::ClientInstanceId,
    harness: HarnessKind,
}

impl IssuerConnection {
    fn registration_is_present(&self, authorization: &LiveAuthorizationRuntime) -> bool {
        authorization.issuer_is_known(
            self.issuer_key_id,
            self.issuer_key_version,
            self.issuer_public_key,
            self.harness,
        )
    }
}

async fn serve_issuer_client(
    stream: KonclaveLocalServiceTransport::LocalServiceServerStream,
    authorization: Arc<LiveAuthorizationRuntime>,
    ledger: Arc<Mutex<RequestLedger>>,
    issuer: IssuerConnection,
    mut stop: watch::Receiver<bool>,
    mut authorization_status: watch::Receiver<
        crate::authorization_runtime::AuthorizationRuntimeStatus,
    >,
) -> anyhow::Result<()> {
    if !issuer.registration_is_present(&authorization) {
        return Ok(());
    }
    let mut stream = Some(stream);
    loop {
        let active_stream = stream
            .as_mut()
            .context("shared local issuer stream is unavailable")?;
        let request = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
                continue;
            }
            changed = authorization_status.changed() => {
                if changed.is_err() || !issuer.registration_is_present(&authorization) {
                    break;
                }
                continue;
            }
            request = read_request(active_stream) => match request {
                Ok(request) => request,
                Err(KonclaveLocalServiceTransport::LocalServiceTransportError::ChannelClosed) => break,
                Err(error) => return Err(error).context("reading a shared local issuer request"),
            }
        };
        let key = LedgerKey::for_issuer(&issuer, request.request_id());
        let execution_authorization = Arc::clone(&authorization);
        let execution_issuer = issuer.clone();
        let execution_ledger = Arc::clone(&ledger);
        let mut execution = tokio::spawn(async move {
            execute_idempotent(execution_ledger, key, &request, || async {
                dispatch_issuer_request(&execution_authorization, &execution_issuer, &request).await
            })
            .await
        });
        let response = loop {
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        drop(stream.take());
                        execution.await.context("joining a stopped issuer request")?;
                        return Ok(());
                    }
                }
                changed = authorization_status.changed() => {
                    if changed.is_err() || !issuer.registration_is_present(&authorization) {
                        drop(stream.take());
                        execution.await.context("joining a revoked issuer request")?;
                        return Ok(());
                    }
                }
                result = &mut execution => {
                    break result.context("joining a shared local issuer request")?;
                }
            }
        };
        if *stop.borrow() || !issuer.registration_is_present(&authorization) {
            drop(stream.take());
            break;
        }
        let active_stream = stream
            .as_mut()
            .context("shared local issuer stream is unavailable")?;
        write_response(active_stream, &response)
            .await
            .context("writing a shared local issuer response")?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GrantIssueRequest {
    profile: String,
    session_public_key: String,
    harness: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantIssueResult {
    grant_id: String,
    issuer_key_id: String,
    issuer_key_version: u32,
    profile: String,
    session_public_key: String,
    harness: &'static str,
    evidence: u8,
    policy_version: u64,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    capabilities: u64,
}

async fn dispatch_issuer_request(
    authorization: &LiveAuthorizationRuntime,
    issuer: &IssuerConnection,
    request: &LocalServiceRequest,
) -> LocalServiceResponse {
    let result = match request.operation().as_str() {
        "authorization.grant.issue" => {
            issue_account_trusted_grant(
                authorization,
                issuer,
                request.request_id(),
                request.payload(),
            )
            .await
        }
        _ => Err(LocalServiceErrorCode::UnknownOperation),
    };
    match result {
        Ok(payload) => {
            LocalServiceResponse::success(request.request_id(), payload).unwrap_or_else(|_| {
                LocalServiceResponse::failure(
                    request.request_id(),
                    LocalServiceErrorCode::PayloadTooLarge,
                )
            })
        }
        Err(code) => LocalServiceResponse::failure(request.request_id(), code),
    }
}

async fn issue_account_trusted_grant(
    authorization: &LiveAuthorizationRuntime,
    issuer: &IssuerConnection,
    request_id: RequestId,
    payload: &[u8],
) -> Result<Vec<u8>, LocalServiceErrorCode> {
    let request: GrantIssueRequest =
        serde_json::from_slice(payload).map_err(|_| LocalServiceErrorCode::InvalidRequest)?;
    let profile = ServiceProfileId::parse(&request.profile)
        .map_err(|_| LocalServiceErrorCode::InvalidRequest)?;
    let harness = parse_harness(&request.harness).ok_or(LocalServiceErrorCode::InvalidRequest)?;
    let session_public_key = crate::mcp::decode_hex::<32>(&request.session_public_key)
        .map(KonclaveDomainCore::Ed25519PublicKey::from_bytes)
        .map_err(|_| LocalServiceErrorCode::InvalidRequest)?;
    let now = SystemUnixClock.now_unix_milliseconds();
    let ttl = u64::try_from(ACCOUNT_TRUSTED_GRANT_TTL.as_millis())
        .map_err(|_| LocalServiceErrorCode::Internal)?;
    let expires = now
        .checked_add(ttl)
        .ok_or(LocalServiceErrorCode::Internal)?;
    let grant = authorization
        .issue_account_trusted_grant(AccountTrustedGrantRequest {
            issuer_key_id: issuer.issuer_key_id,
            issuer_key_version: issuer.issuer_key_version,
            issuer_client_instance: issuer.client_instance,
            request_id,
            profile,
            session_public_key,
            harness,
            issued_at_unix_milliseconds: now,
            expires_at_unix_milliseconds: expires,
        })
        .await?;
    serde_json::to_vec(&GrantIssueResult {
        grant_id: crate::mcp::encode_hex(grant.grant_id().as_bytes()),
        issuer_key_id: crate::mcp::encode_hex(grant.issuer_key_id().as_bytes()),
        issuer_key_version: grant.issuer_key_version().get(),
        profile: grant.profile().as_str().to_string(),
        session_public_key: crate::mcp::encode_hex(grant.session_public_key().as_bytes()),
        harness: grant.harness().as_str(),
        evidence: grant.evidence().bits(),
        policy_version: grant.policy_version().get(),
        issued_at_unix_milliseconds: grant.issued_at_unix_milliseconds(),
        expires_at_unix_milliseconds: grant.expires_at_unix_milliseconds(),
        capabilities: grant.capabilities().bits(),
    })
    .map_err(|_| LocalServiceErrorCode::Internal)
}

fn parse_harness(value: &str) -> Option<HarnessKind> {
    match value {
        "copilot" => Some(HarnessKind::Copilot),
        "claude-code" => Some(HarnessKind::ClaudeCode),
        "codex" => Some(HarnessKind::Codex),
        "generic" => Some(HarnessKind::Generic),
        "a2a-gateway" => Some(HarnessKind::A2AGateway),
        _ => None,
    }
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
    authorization: Arc<LiveAuthorizationRuntime>,
    consumer: AdapterConsumerId,
    grant: SessionGrant,
    handler: StdioServer,
    services: ProfileServices,
    store: Arc<crate::persistence::ProfileStore>,
    delivery: Option<DeliveryAttachment>,
    collaboration_send_authorizations: HashMap<[u8; 16], CollaborationSendAuthorization>,
    shutdown: watch::Receiver<bool>,
}

impl ClientRequestState {
    fn authorization_is_active(&self) -> bool {
        session_grant_is_active(&self.authorization, &self.grant)
    }
}

fn detached_claim_replay_failure(
    state: &ClientRequestState,
    request: &LocalServiceRequest,
    response: &LocalServiceResponse,
) -> Option<LocalServiceResponse> {
    if state.delivery.is_none()
        && request.operation().as_str() == "delivery.claim"
        && matches!(response, LocalServiceResponse::Success { .. })
    {
        Some(LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::Conflict,
        ))
    } else {
        None
    }
}

async fn execute_session_request(
    state: &mut ClientRequestState,
    request: LocalServiceRequest,
) -> LocalServiceResponse {
    if !state.authorization_is_active() {
        return LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::NotAuthorized,
        );
    }
    let key = LedgerKey::for_grant(&state.grant, request.request_id());
    let ledger = Arc::clone(&state.ledger);
    match begin_request(&ledger, key.clone(), &request) {
        LedgerDecision::Cached(response, durable) => {
            if let Some(failure) = detached_claim_replay_failure(state, &request, &response) {
                failure
            } else if durable {
                response
            } else {
                let reconciliation = reconcile_session_response(state, &request, response).await;
                if reconciliation.durable {
                    mark_request_durable(&ledger, &key);
                }
                reconciliation.client_response
            }
        }
        LedgerDecision::Conflict => {
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Conflict)
        }
        LedgerDecision::Busy => {
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Busy)
        }
        LedgerDecision::ShuttingDown => LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::ProfileUnavailable,
        ),
        LedgerDecision::Wait(mut outcome) => {
            match outcome
                .wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|response| response.clone())
            {
                Some(response) => {
                    if let Some(failure) = detached_claim_replay_failure(state, &request, &response)
                    {
                        failure
                    } else if request_is_durable(&ledger, &key) {
                        response
                    } else {
                        let reconciliation =
                            reconcile_session_response(state, &request, response).await;
                        if reconciliation.durable {
                            mark_request_durable(&ledger, &key);
                        }
                        reconciliation.client_response
                    }
                }
                None => LocalServiceResponse::failure(
                    request.request_id(),
                    LocalServiceErrorCode::Internal,
                ),
            }
        }
        LedgerDecision::Execute => {
            let completion = RequestCompletion::new(Arc::clone(&ledger), key.clone());
            let persisted = match load_persisted_request_outcome(
                Arc::clone(&state.store),
                state.grant.session_public_key(),
                request.request_id(),
            )
            .await
            {
                Ok(persisted) => persisted,
                Err(_) => {
                    tracing::error!(
                        outcome = "request_outcome_read_failed",
                        "shared local request outcome could not be read"
                    );
                    discard_request(&ledger, &key);
                    return LocalServiceResponse::failure(
                        request.request_id(),
                        LocalServiceErrorCode::ProfileUnavailable,
                    );
                }
            };
            if let Some(plaintext) = persisted {
                let (recorded_request, response) = match decode_local_request_outcome(&plaintext) {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        tracing::error!(
                            outcome = "request_outcome_decode_failed",
                            "shared local request outcome could not be decoded"
                        );
                        discard_request(&ledger, &key);
                        return LocalServiceResponse::failure(
                            request.request_id(),
                            LocalServiceErrorCode::ProfileUnavailable,
                        );
                    }
                };
                let expected_request = Zeroizing::new(request.encode());
                if recorded_request != expected_request.as_slice() {
                    discard_request(&ledger, &key);
                    return LocalServiceResponse::failure(
                        request.request_id(),
                        LocalServiceErrorCode::Conflict,
                    );
                }
                if response.request_id() != request.request_id() {
                    tracing::error!(
                        outcome = "request_outcome_mismatch",
                        "shared local request outcome named another request"
                    );
                    discard_request(&ledger, &key);
                    return LocalServiceResponse::failure(
                        request.request_id(),
                        LocalServiceErrorCode::ProfileUnavailable,
                    );
                }
                let client_response = detached_claim_replay_failure(state, &request, &response)
                    .unwrap_or_else(|| response.clone());
                completion.complete(response, true);
                return client_response;
            }

            tokio::task::yield_now().await;
            let response = if let Some(reason) = commit_request(&ledger, &key) {
                LocalServiceResponse::failure(request.request_id(), reason.error_code())
            } else {
                await_operation_outcome(dispatch_request(state, &request)).await
            };
            let reconciliation =
                reconcile_session_response(state, &request, response.clone()).await;
            completion.complete(response, reconciliation.durable);
            reconciliation.client_response
        }
    }
}

async fn execute_idempotent<F, Fut>(
    ledger: Arc<Mutex<RequestLedger>>,
    key: LedgerKey,
    request: &LocalServiceRequest,
    dispatch: F,
) -> LocalServiceResponse
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = LocalServiceResponse>,
{
    match begin_request(&ledger, key.clone(), request) {
        LedgerDecision::Cached(response, _) => response,
        LedgerDecision::Conflict => {
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Conflict)
        }
        LedgerDecision::Busy => {
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Busy)
        }
        LedgerDecision::ShuttingDown => LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::ProfileUnavailable,
        ),
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
            let cancellation = commit_request(&ledger, &key);
            let completion = RequestCompletion::new(ledger, key);
            let response = cancellation.map_or_else(
                || None,
                |reason| {
                    Some(LocalServiceResponse::failure(
                        request.request_id(),
                        reason.error_code(),
                    ))
                },
            );
            let response = match response {
                Some(response) => response,
                None => await_operation_outcome(dispatch()).await,
            };
            completion.complete(response.clone(), true);
            response
        }
    }
}

async fn await_operation_outcome<F>(operation: F) -> LocalServiceResponse
where
    F: Future<Output = LocalServiceResponse>,
{
    tokio::pin!(operation);
    match timeout(OPERATION_RECONCILIATION_THRESHOLD, operation.as_mut()).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                outcome = "operation_reconciling_after_deadline",
                "shared local operation crossed its response deadline"
            );
            operation.await
        }
    }
}

async fn load_persisted_request_outcome(
    store: Arc<crate::persistence::ProfileStore>,
    session_public_key: KonclaveDomainCore::Ed25519PublicKey,
    request_id: RequestId,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    tokio::task::spawn_blocking(move || {
        store.local_request_outcome(session_public_key, request_id.as_bytes())
    })
    .await
    .context("joining local request outcome read")?
    .context("reading local request outcome")
}

async fn persist_request_outcome(
    store: Arc<crate::persistence::ProfileStore>,
    session_public_key: KonclaveDomainCore::Ed25519PublicKey,
    request: &LocalServiceRequest,
    response: &LocalServiceResponse,
) -> anyhow::Result<()> {
    let request_id = request.request_id();
    let plaintext = encode_local_request_outcome(request, response)?;
    let completed_at = SystemUnixClock.now_unix_milliseconds();
    tokio::task::spawn_blocking(move || {
        store.record_local_request_outcome(
            session_public_key,
            request_id.as_bytes(),
            completed_at,
            &plaintext,
        )
    })
    .await
    .context("joining local request outcome write")?
    .context("writing local request outcome")
}

struct SessionReconciliation {
    client_response: LocalServiceResponse,
    durable: bool,
}

async fn reconcile_session_response(
    state: &ClientRequestState,
    request: &LocalServiceRequest,
    response: LocalServiceResponse,
) -> SessionReconciliation {
    for attempt in 1..=OUTCOME_PERSIST_ATTEMPTS {
        if persist_request_outcome(
            Arc::clone(&state.store),
            state.grant.session_public_key(),
            request,
            &response,
        )
        .await
        .is_ok()
        {
            return SessionReconciliation {
                client_response: response,
                durable: true,
            };
        }
        if attempt < OUTCOME_PERSIST_ATTEMPTS {
            tokio::time::sleep(OUTCOME_PERSIST_RETRY_DELAY).await;
        }
    }
    tracing::error!(
        outcome = "request_outcome_reconciliation_pending",
        "shared local request outcome is known but not durably recorded"
    );
    SessionReconciliation {
        client_response: LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::ReconciliationPending,
        ),
        durable: false,
    }
}

fn encode_local_request_outcome(
    request: &LocalServiceRequest,
    response: &LocalServiceResponse,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let request = Zeroizing::new(request.encode());
    let response = Zeroizing::new(
        response
            .encode()
            .context("encoding local request terminal response")?,
    );
    let request_length = u32::try_from(request.len()).context("measuring local request")?;
    let response_length = u32::try_from(response.len()).context("measuring local response")?;
    let capacity = 1_usize
        .checked_add(4)
        .and_then(|value| value.checked_add(request.len()))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(response.len()))
        .context("measuring local request outcome")?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    encoded.push(LOCAL_REQUEST_OUTCOME_VERSION);
    encoded.extend_from_slice(&request_length.to_be_bytes());
    encoded.extend_from_slice(&request);
    encoded.extend_from_slice(&response_length.to_be_bytes());
    encoded.extend_from_slice(&response);
    Ok(encoded)
}

fn decode_local_request_outcome(plaintext: &[u8]) -> anyhow::Result<(&[u8], LocalServiceResponse)> {
    let (version, mut rest) = plaintext
        .split_first()
        .context("local request outcome is empty")?;
    if *version != LOCAL_REQUEST_OUTCOME_VERSION {
        anyhow::bail!("local request outcome version is unsupported");
    }
    let request_length = usize::try_from(u32::from_be_bytes(take_outcome::<4>(&mut rest)?))
        .context("measuring stored local request")?;
    if request_length > MAX_RPC_FRAME_BYTES || rest.len() < request_length {
        anyhow::bail!("stored local request is outside its bound");
    }
    let (request, remaining) = rest.split_at(request_length);
    rest = remaining;
    let response_length = usize::try_from(u32::from_be_bytes(take_outcome::<4>(&mut rest)?))
        .context("measuring stored local response")?;
    if response_length > MAX_RPC_FRAME_BYTES || rest.len() != response_length {
        anyhow::bail!("stored local response is outside its bound");
    }
    let response =
        LocalServiceResponse::decode(rest).context("decoding stored local terminal response")?;
    Ok((request, response))
}

fn take_outcome<const N: usize>(rest: &mut &[u8]) -> anyhow::Result<[u8; N]> {
    if rest.len() < N {
        anyhow::bail!("local request outcome is truncated");
    }
    let (value, remaining) = rest.split_at(N);
    *rest = remaining;
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("local request outcome is malformed"))
}

async fn dispatch_request(
    state: &mut ClientRequestState,
    request: &LocalServiceRequest,
) -> LocalServiceResponse {
    if !state.authorization_is_active() {
        return LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::NotAuthorized,
        );
    }
    let operation = request.operation().as_str();
    let required = required_capability(operation);
    if required.is_none_or(|capability| !state.grant.capabilities().permits(capability)) {
        return LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::NotAuthorized,
        );
    }
    let result = match operation {
        "request.cancel" => cancel_target_request(state, request.payload()),
        "authorization.grant.retire" => {
            match state
                .authorization
                .retire_grant(
                    state.grant.grant_id(),
                    SystemUnixClock.now_unix_milliseconds(),
                )
                .await
            {
                Ok(retired) => serde_json::to_vec(&GrantRetirementResult { retired })
                    .map_err(|_| "response_encoding_failed".to_string()),
                Err(code) => Err(code.as_str().to_string()),
            }
        }
        "service.status" => {
            service_status(
                state.services.clone(),
                Arc::clone(&state.store),
                state.grant.clone(),
                Arc::clone(&state.authorization),
            )
            .await
        }
        "delivery.claim" => {
            delivery_claim(
                &mut state.delivery,
                state.consumer,
                &state.store,
                &mut state.shutdown,
                &state.authorization,
                &state.grant,
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
        "delivery.heartbeat" => {
            let local_device = match state.services.conversations().device_id() {
                Ok(value) => value,
                Err(_) => {
                    return response_from_result(request.request_id(), Err("internal".to_string()));
                }
            };
            delivery_heartbeat(
                &state.delivery,
                &state.store,
                state.consumer,
                local_device,
                request.payload(),
            )
            .await
        }
        "collaboration.turn.authorize" => {
            let store = Arc::clone(&state.store);
            let grant = state.grant.clone();
            let consumer = state.consumer;
            let delivery = state.delivery.clone();
            let local_device = match state.services.conversations().device_id() {
                Ok(value) => value,
                Err(_) => {
                    return response_from_result(request.request_id(), Err("internal".to_string()));
                }
            };
            let payload = request.payload().to_vec();
            run_collaboration_policy_request(move || {
                authorize_collaboration_turn(
                    &store,
                    &grant,
                    consumer,
                    delivery.as_ref(),
                    local_device,
                    &payload,
                )
            })
            .await
        }
        "collaboration.turn.complete" => {
            let store = Arc::clone(&state.store);
            let grant = state.grant.clone();
            let consumer = state.consumer;
            let local_device = match state.services.conversations().device_id() {
                Ok(value) => value,
                Err(_) => {
                    return response_from_result(request.request_id(), Err("internal".to_string()));
                }
            };
            let payload = request.payload().to_vec();
            run_collaboration_policy_request(move || {
                complete_collaboration_turn(&store, &grant, consumer, local_device, &payload)
            })
            .await
        }
        "collaboration.action.evaluate" => {
            let store = Arc::clone(&state.store);
            let grant = state.grant.clone();
            let consumer = state.consumer;
            let local_device = match state.services.conversations().device_id() {
                Ok(value) => value,
                Err(_) => {
                    return response_from_result(request.request_id(), Err("internal".to_string()));
                }
            };
            let payload = request.payload().to_vec();
            match run_collaboration_policy_request(move || {
                evaluate_collaboration_action(&store, &grant, consumer, local_device, &payload)
            })
            .await
            {
                Ok(evaluation) => issue_collaboration_action_evaluation(
                    &mut state.collaboration_send_authorizations,
                    evaluation,
                ),
                Err(error) => Err(error),
            }
        }
        "send_message" => dispatch_send_message(state, request.payload()).await,
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

async fn run_collaboration_policy_request<F, T>(operation: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| "internal".to_string())?
}

async fn dispatch_send_message(
    state: &mut ClientRequestState,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let request: CollaborationAuthorizedSendRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    let Some(authorization) = request.collaboration_authorization.as_deref() else {
        return state.handler.dispatch_json("send_message", payload).await;
    };
    let authorization = consume_collaboration_send_authorization(
        &mut state.collaboration_send_authorizations,
        authorization,
        &request,
        SystemUnixClock.now_unix_milliseconds(),
    )?;
    let store = Arc::clone(&state.store);
    let grant = state.grant.clone();
    let consumer = state.consumer;
    let not_after_unix_milliseconds = authorization.expires_at_unix_milliseconds;
    let candidate = authorization.candidate;
    let send_authorization = CollaborationActionAuthorization {
        policy_digest: candidate.policy_digest,
        consumer_id: candidate.consumer_id,
        not_after_unix_milliseconds,
        directed_request_claim: candidate.directed_request_claim,
    };
    let valid = run_collaboration_policy_request(move || {
        revalidate_collaboration_send(
            &store,
            &grant,
            consumer,
            candidate.directed_request_claim.responder_device_id,
            &candidate,
        )
    })
    .await?;
    if !valid {
        return Err("collaboration_policy_conflict".to_string());
    }
    state
        .handler
        .dispatch_authorized_send_json(payload, send_authorization)
        .await
}

fn consume_collaboration_send_authorization(
    authorizations: &mut HashMap<[u8; 16], CollaborationSendAuthorization>,
    authorization: &str,
    request: &CollaborationAuthorizedSendRequest,
    now_unix_milliseconds: u64,
) -> Result<CollaborationSendAuthorization, String> {
    let token = crate::mcp::decode_hex::<16>(authorization)
        .map_err(|_| "invalid_collaboration_authorization".to_string())?;
    let authorization = authorizations
        .remove(&token)
        .ok_or_else(|| "invalid_collaboration_authorization".to_string())?;
    if authorization.expires_at_unix_milliseconds <= now_unix_milliseconds
        || request.conversation_id
            != crate::mcp::encode_hex(authorization.candidate.conversation_id.as_bytes())
        || request.message_id
            != crate::mcp::encode_hex(authorization.candidate.message_id.as_bytes())
        || request.reply_to_message_id.as_deref()
            != authorization
                .candidate
                .reply_to_message_id
                .map(|value| crate::mcp::encode_hex(value.as_bytes()))
                .as_deref()
        || request.text != authorization.candidate.text.as_str()
    {
        return Err("invalid_collaboration_authorization".to_string());
    }
    Ok(authorization)
}

fn revalidate_collaboration_send(
    store: &crate::persistence::ProfileStore,
    grant: &SessionGrant,
    consumer: AdapterConsumerId,
    local_device: DeviceId,
    candidate: &CollaborationSendCandidate,
) -> Result<bool, String> {
    let request = EvaluateCollaborationActionRequest {
        conversation_id: crate::mcp::encode_hex(candidate.conversation_id.as_bytes()),
        policy_digest: crate::mcp::encode_hex(candidate.policy_digest.as_bytes()),
        action: "conversation.reply".to_string(),
        resource: None,
        message_id: Some(crate::mcp::encode_hex(candidate.message_id.as_bytes())),
        reply_to_message_id: candidate
            .reply_to_message_id
            .map(|value| crate::mcp::encode_hex(value.as_bytes())),
        text: Some(candidate.text.as_str().to_string()),
        request_message_id: crate::mcp::encode_hex(
            candidate
                .directed_request_claim
                .request_message_id
                .as_bytes(),
        ),
        attempt: candidate.directed_request_claim.attempt,
    };
    match evaluate_collaboration_action_request(store, grant, consumer, local_device, request)? {
        CollaborationActionEvaluation::Allow(revalidated) => Ok(revalidated.conversation_id
            == candidate.conversation_id
            && revalidated.policy_digest == candidate.policy_digest
            && revalidated.consumer_id == candidate.consumer_id
            && revalidated.message_id == candidate.message_id
            && revalidated.reply_to_message_id == candidate.reply_to_message_id
            && revalidated.directed_request_claim == candidate.directed_request_claim
            && revalidated.text.as_str() == candidate.text.as_str()),
        CollaborationActionEvaluation::Deny(_) => Ok(false),
    }
}

fn is_fresh_collaboration_policy_request(operation: &str) -> bool {
    matches!(
        operation,
        "collaboration.turn.authorize"
            | "collaboration.turn.complete"
            | "collaboration.action.evaluate"
    )
}

fn required_capability(operation: &str) -> Option<SessionCapabilities> {
    if is_tool_operation(operation) {
        Some(SessionCapabilities::PROFILE_OPERATIONS)
    } else if operation.starts_with("delivery.") || operation.starts_with("collaboration.") {
        Some(SessionCapabilities::DELIVERY)
    } else if operation == "service.status" {
        Some(SessionCapabilities::STATUS)
    } else if matches!(operation, "request.cancel" | "authorization.grant.retire") {
        Some(SessionCapabilities::CONTROL)
    } else {
        None
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthorizeCollaborationTurnRequest {
    conversation_id: String,
    request_message_id: String,
    notification_id: String,
    lease_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvaluateCollaborationActionRequest {
    conversation_id: String,
    policy_digest: String,
    action: String,
    resource: Option<String>,
    message_id: Option<String>,
    reply_to_message_id: Option<String>,
    text: Option<String>,
    request_message_id: String,
    attempt: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CompleteCollaborationTurnRequest {
    conversation_id: String,
    policy_digest: String,
    request_message_id: String,
    attempt: u32,
}

#[derive(Deserialize)]
struct CollaborationAuthorizedSendRequest {
    conversation_id: String,
    message_id: String,
    text: String,
    reply_to_message_id: Option<String>,
    collaboration_authorization: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CollaborationTurnAuthorizationResult {
    outcome: &'static str,
    reason: Option<&'static str>,
    policy_digest: Option<String>,
    policy_name: Option<String>,
    request_message_id: Option<String>,
    attempt: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CollaborationActionEvaluationResult {
    decision: &'static str,
    reason: Option<&'static str>,
    authorization: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompleteCollaborationTurnResult {
    outcome: &'static str,
    changed: bool,
}

struct CollaborationSendCandidate {
    conversation_id: ConversationId,
    policy_digest: KonclaveDomainCore::CollaborationPolicyDigest,
    consumer_id: AdapterConsumerId,
    not_after_unix_milliseconds: u64,
    message_id: KonclaveDomainCore::MessageId,
    reply_to_message_id: Option<KonclaveDomainCore::MessageId>,
    text: Zeroizing<String>,
    directed_request_claim: DirectedRequestClaim,
}

struct CollaborationSendAuthorization {
    candidate: CollaborationSendCandidate,
    expires_at_unix_milliseconds: u64,
}

enum CollaborationActionEvaluation {
    Allow(Box<CollaborationSendCandidate>),
    Deny(&'static str),
}

fn authorize_collaboration_turn(
    store: &crate::persistence::ProfileStore,
    grant: &SessionGrant,
    consumer: AdapterConsumerId,
    delivery: Option<&DeliveryAttachment>,
    local_device: DeviceId,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let request: AuthorizeCollaborationTurnRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    let conversation_id = parse_collaboration_conversation_id(&request.conversation_id)?;
    let request_message_id = parse_collaboration_message_id(&request.request_message_id)?;
    let notification_id = crate::mcp::decode_hex::<16>(&request.notification_id)
        .map(NotificationId::from_bytes)
        .map_err(|_| "invalid_request".to_string())?;
    if grant.harness() != HarnessKind::Copilot || delivery.is_none() {
        return encode_collaboration_turn_authorization(
            "denied",
            Some("copilot_delivery_not_proven"),
            None,
            None,
        );
    }
    let delivery = delivery.ok_or_else(|| "internal".to_string())?;
    let Some(active) = store
        .active_collaboration_policy(conversation_id)
        .map_err(|_| "internal".to_string())?
    else {
        return encode_collaboration_turn_authorization("inactive", None, None, None);
    };
    if active.bundle().limits().turns().is_some() {
        return encode_collaboration_turn_authorization(
            "denied",
            Some("turn_accounting_unavailable"),
            Some(&active),
            None,
        );
    }
    if active.bundle().limits().tokens().is_some() {
        return encode_collaboration_turn_authorization(
            "denied",
            Some("token_accounting_unavailable"),
            Some(&active),
            None,
        );
    }
    let Some(elapsed) = SystemUnixClock
        .now_unix_milliseconds()
        .checked_sub(active.activated_at_unix_milliseconds())
    else {
        return encode_collaboration_turn_authorization(
            "denied",
            Some("clock_regressed"),
            Some(&active),
            None,
        );
    };
    let context = copilot_collaboration_policy_context(active.bundle())?;
    let policy_request = CollaborationPolicyEvaluationRequest::new(
        CollaborationPolicyTarget::new("conversation.reply", None)
            .map_err(|_| "internal".to_string())?,
        CollaborationPolicyCost::new(0, 0, 1),
        false,
    );
    let decision = evaluate_collaboration_policy(
        active.bundle(),
        &context,
        &policy_request,
        CollaborationPolicyUsage::new(elapsed, 0, 0, 0),
    );
    match decision {
        CollaborationPolicyDecision::Allow => {
            let claim = match store.claim_directed_request(ClaimDirectedRequest {
                conversation_id,
                request_message_id,
                responder_device_id: local_device,
                notification_id,
                consumer_id: consumer,
                lease_id: delivery.lease_id(),
                lease_generation: request.lease_generation,
                policy_digest: active.digest(),
                now_unix_milliseconds: SystemUnixClock.now_unix_milliseconds(),
            }) {
                Ok(outcome) => outcome,
                Err(
                    crate::persistence::ProfileStoreError::InvalidTransition
                    | crate::persistence::ProfileStoreError::OperationNotFound,
                ) => {
                    return encode_collaboration_turn_authorization(
                        "denied",
                        Some("directed_request_invalid"),
                        Some(&active),
                        None,
                    );
                }
                Err(crate::persistence::ProfileStoreError::InvalidAdapterLease) => {
                    return encode_collaboration_turn_authorization(
                        "denied",
                        Some("directed_request_claim_inactive"),
                        Some(&active),
                        None,
                    );
                }
                Err(
                    crate::persistence::ProfileStoreError::CollaborationPolicyReplacementMismatch,
                ) => {
                    return encode_collaboration_turn_authorization(
                        "denied",
                        Some("policy_changed"),
                        Some(&active),
                        None,
                    );
                }
                Err(
                    crate::persistence::ProfileStoreError::DirectedRequestHandlingCapacityExceeded,
                ) => {
                    return encode_collaboration_turn_authorization(
                        "denied",
                        Some("directed_request_capacity_exceeded"),
                        Some(&active),
                        None,
                    );
                }
                Err(_) => return Err("internal".to_string()),
            };
            match claim {
                DirectedRequestClaimOutcome::Claimed(claim) => {
                    encode_collaboration_turn_authorization(
                        "authorized",
                        None,
                        Some(&active),
                        Some(claim),
                    )
                }
                DirectedRequestClaimOutcome::Busy => encode_collaboration_turn_authorization(
                    "denied",
                    Some("directed_request_claimed"),
                    Some(&active),
                    None,
                ),
                DirectedRequestClaimOutcome::AttemptsExhausted => {
                    encode_collaboration_turn_authorization(
                        "denied",
                        Some("directed_request_attempts_exhausted"),
                        Some(&active),
                        None,
                    )
                }
                DirectedRequestClaimOutcome::CompletedResponse => {
                    encode_collaboration_turn_authorization(
                        "denied",
                        Some("directed_request_completed_response"),
                        Some(&active),
                        None,
                    )
                }
                DirectedRequestClaimOutcome::CompletedNoResponse => {
                    encode_collaboration_turn_authorization(
                        "denied",
                        Some("directed_request_completed_no_response"),
                        Some(&active),
                        None,
                    )
                }
            }
        }
        CollaborationPolicyDecision::RequireLocalApproval => {
            encode_collaboration_turn_authorization(
                "approval_required",
                Some("local_approval_required"),
                Some(&active),
                None,
            )
        }
        CollaborationPolicyDecision::Deny(reason) => encode_collaboration_turn_authorization(
            "denied",
            Some(reason.code()),
            Some(&active),
            None,
        ),
    }
}

fn complete_collaboration_turn(
    store: &crate::persistence::ProfileStore,
    grant: &SessionGrant,
    consumer: AdapterConsumerId,
    local_device: DeviceId,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let request: CompleteCollaborationTurnRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    if grant.harness() != HarnessKind::Copilot {
        return Err("local_service_not_authorized".to_string());
    }
    let conversation_id = parse_collaboration_conversation_id(&request.conversation_id)?;
    let request_message_id = parse_collaboration_message_id(&request.request_message_id)?;
    let policy_digest = crate::mcp::decode_hex::<32>(&request.policy_digest)
        .map(KonclaveDomainCore::CollaborationPolicyDigest::from_bytes)
        .map_err(|_| "invalid_request".to_string())?;
    let outcome = store
        .complete_directed_request_without_response(CompleteDirectedRequest {
            conversation_id,
            request_message_id,
            responder_device_id: local_device,
            consumer_id: consumer,
            attempt: request.attempt,
            policy_digest,
        })
        .map_err(|error| directed_request_handling_error(&error))?;
    let result = match outcome {
        DirectedRequestCompletionOutcome::CompletedResponse => CompleteCollaborationTurnResult {
            outcome: "completed_response",
            changed: false,
        },
        DirectedRequestCompletionOutcome::CompletedNoResponse { changed } => {
            CompleteCollaborationTurnResult {
                outcome: "completed_no_response",
                changed,
            }
        }
    };
    serde_json::to_vec(&result).map_err(|_| "response_encoding_failed".to_string())
}

fn evaluate_collaboration_action(
    store: &crate::persistence::ProfileStore,
    grant: &SessionGrant,
    consumer: AdapterConsumerId,
    local_device: DeviceId,
    payload: &[u8],
) -> Result<CollaborationActionEvaluation, String> {
    let request: EvaluateCollaborationActionRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    evaluate_collaboration_action_request(store, grant, consumer, local_device, request)
}

fn evaluate_collaboration_action_request(
    store: &crate::persistence::ProfileStore,
    grant: &SessionGrant,
    consumer: AdapterConsumerId,
    local_device: DeviceId,
    request: EvaluateCollaborationActionRequest,
) -> Result<CollaborationActionEvaluation, String> {
    let conversation_id = parse_collaboration_conversation_id(&request.conversation_id)?;
    let request_message_id = parse_collaboration_message_id(&request.request_message_id)?;
    let now_unix_milliseconds = SystemUnixClock.now_unix_milliseconds();
    let lease_expires_at = store
        .active_adapter_consumer_expiry(consumer)
        .map_err(|_| "internal".to_string())?;
    if grant.harness() != HarnessKind::Copilot
        || !lease_expires_at.is_some_and(|expires_at| expires_at > now_unix_milliseconds)
    {
        return Ok(CollaborationActionEvaluation::Deny(
            "copilot_delivery_not_proven",
        ));
    }
    let expected_digest = crate::mcp::decode_hex::<32>(&request.policy_digest)
        .map(KonclaveDomainCore::CollaborationPolicyDigest::from_bytes)
        .map_err(|_| "invalid_request".to_string())?;
    let Some(active) = store
        .active_collaboration_policy(conversation_id)
        .map_err(|_| "internal".to_string())?
    else {
        return Ok(CollaborationActionEvaluation::Deny("policy_inactive"));
    };
    if active.digest() != expected_digest {
        return Ok(CollaborationActionEvaluation::Deny("policy_changed"));
    }
    if active.bundle().limits().turns().is_some() {
        return Ok(CollaborationActionEvaluation::Deny(
            "turn_accounting_unavailable",
        ));
    }
    if active.bundle().limits().tokens().is_some() {
        return Ok(CollaborationActionEvaluation::Deny(
            "token_accounting_unavailable",
        ));
    }
    let Some(elapsed) = now_unix_milliseconds.checked_sub(active.activated_at_unix_milliseconds())
    else {
        return Ok(CollaborationActionEvaluation::Deny("clock_regressed"));
    };
    let policy_expires_at = match active.bundle().limits().duration_milliseconds() {
        Some(duration) => {
            let Some(expires_at) = active
                .activated_at_unix_milliseconds()
                .checked_add(duration)
            else {
                return Ok(CollaborationActionEvaluation::Deny(
                    "limit_arithmetic_overflow",
                ));
            };
            expires_at
        }
        None => u64::MAX,
    };
    let not_after_unix_milliseconds = lease_expires_at.unwrap_or_default().min(policy_expires_at);
    let Some(directed_request_claim) = store
        .active_directed_request_claim(ActiveDirectedRequestClaim {
            conversation_id,
            request_message_id,
            responder_device_id: local_device,
            consumer_id: consumer,
            attempt: request.attempt,
            policy_digest: expected_digest,
            now_unix_milliseconds,
        })
        .map_err(|error| directed_request_handling_error(&error))?
    else {
        return Ok(CollaborationActionEvaluation::Deny(
            "directed_request_claim_inactive",
        ));
    };
    let not_after_unix_milliseconds =
        not_after_unix_milliseconds.min(directed_request_claim.claim_expires_at_unix_milliseconds);
    let context = copilot_collaboration_policy_context(active.bundle())?;
    let target = CollaborationPolicyTarget::new(&request.action, request.resource.clone())
        .map_err(|_| "invalid_request".to_string())?;
    let policy_request = CollaborationPolicyEvaluationRequest::new(
        target,
        CollaborationPolicyCost::default(),
        false,
    );
    let decision = evaluate_collaboration_policy(
        active.bundle(),
        &context,
        &policy_request,
        CollaborationPolicyUsage::new(elapsed, 0, 0, 1),
    );
    match decision {
        CollaborationPolicyDecision::Allow => {
            if request.action != "conversation.reply" || request.resource.is_some() {
                return Ok(CollaborationActionEvaluation::Deny(
                    "harness_control_missing",
                ));
            }
            let message_id = request
                .message_id
                .as_deref()
                .ok_or_else(|| "invalid_request".to_string())
                .and_then(parse_collaboration_message_id)?;
            let reply_to_message_id = request
                .reply_to_message_id
                .as_deref()
                .map(parse_collaboration_message_id)
                .transpose()?;
            if reply_to_message_id != Some(request_message_id) {
                return Ok(CollaborationActionEvaluation::Deny(
                    "directed_request_reply_mismatch",
                ));
            }
            let text = request.text.ok_or_else(|| "invalid_request".to_string())?;
            ApplicationContent::text(text.as_str()).map_err(|_| "invalid_request".to_string())?;
            Ok(CollaborationActionEvaluation::Allow(Box::new(
                CollaborationSendCandidate {
                    conversation_id,
                    policy_digest: expected_digest,
                    consumer_id: consumer,
                    not_after_unix_milliseconds,
                    message_id,
                    reply_to_message_id,
                    text: Zeroizing::new(text),
                    directed_request_claim,
                },
            )))
        }
        CollaborationPolicyDecision::RequireLocalApproval => Ok(
            CollaborationActionEvaluation::Deny("policy_approval_not_composable"),
        ),
        CollaborationPolicyDecision::Deny(reason) => {
            Ok(CollaborationActionEvaluation::Deny(reason.code()))
        }
    }
}

fn parse_collaboration_conversation_id(value: &str) -> Result<ConversationId, String> {
    crate::mcp::decode_hex::<32>(value)
        .map(ConversationId::from_bytes)
        .map_err(|_| "invalid_request".to_string())
}

fn parse_collaboration_message_id(value: &str) -> Result<KonclaveDomainCore::MessageId, String> {
    crate::mcp::decode_hex::<16>(value)
        .map(KonclaveDomainCore::MessageId::from_bytes)
        .map_err(|_| "invalid_request".to_string())
}

fn directed_request_handling_error(error: &crate::persistence::ProfileStoreError) -> String {
    match error {
        crate::persistence::ProfileStoreError::DirectedRequestHandlingCapacityExceeded => {
            "busy".to_string()
        }
        crate::persistence::ProfileStoreError::InvalidAdapterLease => {
            "collaboration_policy_conflict".to_string()
        }
        crate::persistence::ProfileStoreError::InvalidTransition
        | crate::persistence::ProfileStoreError::CollaborationPolicyReplacementMismatch
        | crate::persistence::ProfileStoreError::OperationNotFound => {
            "collaboration_policy_conflict".to_string()
        }
        _ => "internal".to_string(),
    }
}

fn encode_collaboration_turn_authorization(
    outcome: &'static str,
    reason: Option<&'static str>,
    active: Option<&crate::persistence::ActiveCollaborationPolicy>,
    claim: Option<DirectedRequestClaim>,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CollaborationTurnAuthorizationResult {
        outcome,
        reason,
        policy_digest: active.map(|policy| crate::mcp::encode_hex(policy.digest().as_bytes())),
        policy_name: active.map(|policy| policy.bundle().name().to_string()),
        request_message_id: claim
            .map(|value| crate::mcp::encode_hex(value.request_message_id.as_bytes())),
        attempt: claim.map(|value| value.attempt),
    })
    .map_err(|_| "response_encoding_failed".to_string())
}

fn issue_collaboration_action_evaluation(
    authorizations: &mut HashMap<[u8; 16], CollaborationSendAuthorization>,
    evaluation: CollaborationActionEvaluation,
) -> Result<Vec<u8>, String> {
    let now = SystemUnixClock.now_unix_milliseconds();
    authorizations.retain(|_, authorization| authorization.expires_at_unix_milliseconds > now);
    let (decision, reason, authorization) = match evaluation {
        CollaborationActionEvaluation::Deny(reason) => ("deny", Some(reason), None),
        CollaborationActionEvaluation::Allow(candidate) => {
            if authorizations.len() >= MAX_COLLABORATION_SEND_AUTHORIZATIONS {
                return serde_json::to_vec(&CollaborationActionEvaluationResult {
                    decision: "deny",
                    reason: Some("authorization_capacity_exceeded"),
                    authorization: None,
                })
                .map_err(|_| "response_encoding_failed".to_string());
            }
            let ttl_expires_at = now
                .checked_add(
                    u64::try_from(COLLABORATION_SEND_AUTHORIZATION_TTL.as_millis())
                        .map_err(|_| "internal".to_string())?,
                )
                .ok_or_else(|| "internal".to_string())?;
            let expires_at_unix_milliseconds =
                ttl_expires_at.min(candidate.not_after_unix_milliseconds);
            if expires_at_unix_milliseconds <= now {
                return serde_json::to_vec(&CollaborationActionEvaluationResult {
                    decision: "deny",
                    reason: Some("authorization_expired"),
                    authorization: None,
                })
                .map_err(|_| "response_encoding_failed".to_string());
            }
            let mut issued = None;
            for _ in 0..4 {
                let mut token = [0_u8; 16];
                KonclaveCryptographicCore::fill_random(&mut token)
                    .map_err(|_| "internal".to_string())?;
                if let Entry::Vacant(entry) = authorizations.entry(token) {
                    entry.insert(CollaborationSendAuthorization {
                        candidate: *candidate,
                        expires_at_unix_milliseconds,
                    });
                    issued = Some(crate::mcp::encode_hex(&token));
                    break;
                }
            }
            let Some(issued) = issued else {
                return Err("internal".to_string());
            };
            ("allow", None, Some(issued))
        }
    };
    serde_json::to_vec(&CollaborationActionEvaluationResult {
        decision,
        reason,
        authorization,
    })
    .map_err(|_| "response_encoding_failed".to_string())
}

fn copilot_collaboration_policy_context(
    bundle: &CollaborationPolicyBundle,
) -> Result<CollaborationPolicyEvaluationContext, String> {
    let mut local_authority = BTreeSet::new();
    for statement in bundle
        .statements()
        .iter()
        .filter(|statement| statement.effect() != CollaborationPolicyEffect::Deny)
    {
        local_authority.insert((
            statement.action().to_string(),
            statement.resource().map(str::to_string),
        ));
    }
    let local_authority = local_authority
        .into_iter()
        .map(|(action, resource)| CollaborationPolicyTarget::new(action, resource))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "internal".to_string())?;
    let proven_harness_controls = [("conversation.reply", None)]
        .into_iter()
        .map(|(action, resource)| {
            CollaborationPolicyTarget::new(action, resource.map(str::to_string))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "internal".to_string())?;
    CollaborationPolicyEvaluationContext::new(
        local_authority,
        COPILOT_HARNESS_CLAIMS
            .into_iter()
            .map(str::to_string)
            .collect(),
        proven_harness_controls,
        vec![],
        vec![],
    )
    .map_err(|_| "internal".to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequestCancellationRequest {
    request_id: String,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestCancellationResult {
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantRetirementResult {
    retired: bool,
}

fn cancel_target_request(state: &ClientRequestState, payload: &[u8]) -> Result<Vec<u8>, String> {
    let request: RequestCancellationRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    let request_id = crate::mcp::decode_hex::<16>(&request.request_id)
        .map(RequestId::from_bytes)
        .map_err(|_| "invalid_request".to_string())?;
    let reason = match request.reason.as_str() {
        "caller" => RequestCancellationReason::Caller,
        "deadline" => RequestCancellationReason::Deadline,
        _ => return Err("invalid_request".to_string()),
    };
    let key = LedgerKey::for_grant(&state.grant, request_id);
    let cancellation = cancel_request(&state.ledger, &key, reason);
    serde_json::to_vec(&RequestCancellationResult {
        state: cancellation.as_str(),
    })
    .map_err(|_| "response_encoding_failed".to_string())
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
        | "invalid_collaboration_policy_bundle"
        | "invalid_collaboration_policy_source"
        | "invalid_collaboration_policy_digest"
        | "invalid_collaboration_policy_proposal_id"
        | "collaboration_policy_proposal_not_found"
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
        | "invalid_routing_id"
        | "directed_request_unsupported"
        | "directed_request_target_required" => LocalServiceErrorCode::InvalidRequest,
        "unknown_operation" => LocalServiceErrorCode::UnknownOperation,
        "relay_not_configured" => LocalServiceErrorCode::ProfileUnavailable,
        "local_service_not_authorized" | "invalid_collaboration_authorization" => {
            LocalServiceErrorCode::NotAuthorized
        }
        "profile_suspended" => LocalServiceErrorCode::ProfileSuspended,
        "issuer_disabled" => LocalServiceErrorCode::IssuerDisabled,
        "required_evidence_unavailable" => LocalServiceErrorCode::RequiredEvidenceUnavailable,
        "capacity" => LocalServiceErrorCode::Capacity,
        "busy" => LocalServiceErrorCode::Busy,
        "deadline_exceeded" => LocalServiceErrorCode::DeadlineExceeded,
        "collaboration_policy_conflict" => LocalServiceErrorCode::Conflict,
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
            | "send_directed_request"
            | "propose_collaboration_policy"
            | "propose_collaboration_policy_source"
            | "resume_collaboration_policy_proposal"
            | "get_collaboration_policy_status"
            | "inspect_collaboration_policy_proposal"
            | "accept_collaboration_policy"
            | "reject_collaboration_policy"
            | "revoke_collaboration_policy"
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
            | "set_active_conversation"
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
    authorization_policy: &'static str,
    authorization_provider: &'static str,
    authorization_evidence: Vec<&'static str>,
    authorization_generation: u64,
    authorization_policy_version: u64,
    grant_expires_at_unix_milliseconds: u64,
    grant_capabilities: u64,
    active_grants: usize,
    active_grants_for_issuer: usize,
    active_grants_for_profile: usize,
    grant_limit: usize,
    grant_limit_per_issuer: usize,
    grant_limit_per_profile: usize,
}

async fn service_status(
    services: ProfileServices,
    store: Arc<crate::persistence::ProfileStore>,
    grant: SessionGrant,
    authorization: Arc<LiveAuthorizationRuntime>,
) -> Result<Vec<u8>, String> {
    let (authorization_generation, capacity, effective_policy) = authorization
        .status_snapshot(grant.issuer_key_id(), grant.profile())
        .ok_or_else(|| "local_service_not_authorized".to_string())?;
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
            authorization_policy: "AccountTrusted",
            authorization_provider: "AccountTrusted",
            authorization_evidence: evidence_names(grant.evidence()),
            authorization_generation: authorization_generation.get(),
            authorization_policy_version: effective_policy.version().get(),
            grant_expires_at_unix_milliseconds: grant.expires_at_unix_milliseconds(),
            grant_capabilities: grant.capabilities().bits(),
            active_grants: capacity.active_global(),
            active_grants_for_issuer: capacity.active_for_issuer(),
            active_grants_for_profile: capacity.active_for_profile(),
            grant_limit: MAX_SESSION_GRANTS,
            grant_limit_per_issuer: MAX_GRANTS_PER_ISSUER,
            grant_limit_per_profile: MAX_GRANTS_PER_PROFILE,
        })
        .map_err(|_| "response_encoding_failed".to_string())
    })
    .await
    .map_err(|_| "profile_unavailable".to_string())?
}

fn evidence_names(evidence: AuthorizationEvidenceSet) -> Vec<&'static str> {
    [
        AuthorizationEvidenceKind::AccountTrusted,
        AuthorizationEvidenceKind::UserPresence,
        AuthorizationEvidenceKind::HarnessAttested,
        AuthorizationEvidenceKind::WorkloadIdentity,
    ]
    .into_iter()
    .filter(|kind| {
        AuthorizationEvidenceSet::new([*kind]).is_ok_and(|single| evidence.satisfies(single))
    })
    .map(AuthorizationEvidenceKind::as_str)
    .collect()
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryHeartbeatRequest {
    turn: Option<DeliveryHeartbeatTurnRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeliveryHeartbeatTurnRequest {
    conversation_id: String,
    policy_digest: String,
    request_message_id: String,
    attempt: u32,
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
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum DeliveryPayloadResult {
    ApplicationText {
        message_id: String,
        text: String,
    },
    DirectedRequest {
        message_id: String,
        target_device_id: String,
        text: String,
    },
    CollaborationPolicyProposal {
        proposal_id: String,
        policy_digest: String,
        replaces_policy_digest: Option<String>,
    },
    CollaborationPolicyResponse {
        proposal_id: String,
        policy_digest: String,
        outcome: &'static str,
    },
    CollaborationPolicyRevocation {
        policy_digest: String,
    },
    MemberAdded {
        device: String,
        role: &'static str,
    },
    MemberRemoved {
        device: String,
    },
    MemberRoleChanged {
        device: String,
        role: &'static str,
    },
    LocalAccessRemoved {
        device: String,
    },
}

async fn delivery_claim(
    delivery: &mut Option<DeliveryAttachment>,
    consumer: AdapterConsumerId,
    store: &Arc<crate::persistence::ProfileStore>,
    shutdown: &mut watch::Receiver<bool>,
    authorization: &Arc<LiveAuthorizationRuntime>,
    grant: &SessionGrant,
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
    let outcome = delivery
        .as_ref()
        .ok_or_else(|| "profile_unavailable".to_string())?
        .wait_and_claim(
            store,
            shutdown,
            request.max_events,
            request.wait_milliseconds,
            || session_grant_is_active(authorization, grant),
        )
        .await
        .map_err(|_| "profile_unavailable".to_string())?;
    let events = match outcome {
        DeliveryWaitOutcome::Events(events) => events,
        DeliveryWaitOutcome::AuthorizationLost => {
            *delivery = None;
            return Err("local_service_not_authorized".to_string());
        }
    };
    serde_json::to_vec(&DeliveryBatchResult {
        events: events.into_iter().map(delivery_event_result).collect(),
    })
    .map_err(|_| "response_encoding_failed".to_string())
}

fn session_grant_is_active(authorization: &LiveAuthorizationRuntime, grant: &SessionGrant) -> bool {
    authorization.grant_is_active(grant)
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

async fn delivery_heartbeat(
    delivery: &Option<DeliveryAttachment>,
    store: &Arc<crate::persistence::ProfileStore>,
    consumer: AdapterConsumerId,
    local_device: DeviceId,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let request: DeliveryHeartbeatRequest =
        serde_json::from_slice(payload).map_err(|_| "invalid_request".to_string())?;
    let now = SystemUnixClock.now_unix_milliseconds();
    let turn = request
        .turn
        .map(|turn| -> Result<ActiveDirectedRequestClaim, String> {
            Ok(ActiveDirectedRequestClaim {
                conversation_id: parse_collaboration_conversation_id(&turn.conversation_id)?,
                request_message_id: parse_collaboration_message_id(&turn.request_message_id)?,
                responder_device_id: local_device,
                consumer_id: consumer,
                attempt: turn.attempt,
                policy_digest: crate::mcp::decode_hex::<32>(&turn.policy_digest)
                    .map(KonclaveDomainCore::CollaborationPolicyDigest::from_bytes)
                    .map_err(|_| "invalid_request".to_string())?,
                now_unix_milliseconds: now,
            })
        })
        .transpose()?;
    let attachment = delivery
        .as_ref()
        .ok_or_else(|| "profile_unavailable".to_string())?
        .clone();
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || attachment.heartbeat(&store, now, turn))
        .await
        .map_err(|_| "profile_unavailable".to_string())?
        .map_err(|_| "profile_unavailable".to_string())?;
    Ok(b"{}".to_vec())
}

fn delivery_event_result(claimed: ClaimedRemoteEvent) -> DeliveryEventResult {
    let event = claimed.event;
    DeliveryEventResult {
        notification_id: crate::mcp::encode_hex(event.notification_id.as_bytes()),
        lease_generation: claimed.lease_generation,
        sequence: event.sequence,
        conversation: crate::mcp::encode_hex(event.conversation_id.as_bytes()),
        sender: crate::mcp::encode_hex(event.sender.as_bytes()),
        relay_cursor: event.relay_cursor,
        payload: match event.payload {
            RemoteEventPayload::ApplicationMessage(message) => match message.content() {
                ApplicationContent::Text(text) => DeliveryPayloadResult::ApplicationText {
                    message_id: crate::mcp::encode_hex(message.message_id().as_bytes()),
                    text: text.clone(),
                },
                ApplicationContent::DirectedRequest(request) => {
                    DeliveryPayloadResult::DirectedRequest {
                        message_id: crate::mcp::encode_hex(message.message_id().as_bytes()),
                        target_device_id: crate::mcp::encode_hex(
                            request.target_device_id().as_bytes(),
                        ),
                        text: request.body().to_owned(),
                    }
                }
                ApplicationContent::CollaborationPolicyProposal(proposal) => {
                    DeliveryPayloadResult::CollaborationPolicyProposal {
                        proposal_id: crate::mcp::encode_hex(proposal.proposal_id().as_bytes()),
                        policy_digest: crate::mcp::encode_hex(proposal.policy_digest().as_bytes()),
                        replaces_policy_digest: proposal
                            .replaces_policy_digest()
                            .map(|digest| crate::mcp::encode_hex(digest.as_bytes())),
                    }
                }
                ApplicationContent::CollaborationPolicyResponse(response) => {
                    DeliveryPayloadResult::CollaborationPolicyResponse {
                        proposal_id: crate::mcp::encode_hex(response.proposal_id().as_bytes()),
                        policy_digest: crate::mcp::encode_hex(response.policy_digest().as_bytes()),
                        outcome: policy_response_outcome(response.outcome()),
                    }
                }
                ApplicationContent::CollaborationPolicyRevocation(revocation) => {
                    DeliveryPayloadResult::CollaborationPolicyRevocation {
                        policy_digest: crate::mcp::encode_hex(
                            revocation.policy_digest().as_bytes(),
                        ),
                    }
                }
            },
            RemoteEventPayload::MemberAdded { device_id, role } => {
                DeliveryPayloadResult::MemberAdded {
                    device: crate::mcp::encode_hex(device_id.as_bytes()),
                    role: delivery_role(role),
                }
            }
            RemoteEventPayload::MemberRemoved { device_id } => {
                DeliveryPayloadResult::MemberRemoved {
                    device: crate::mcp::encode_hex(device_id.as_bytes()),
                }
            }
            RemoteEventPayload::MemberRoleChanged { device_id, role } => {
                DeliveryPayloadResult::MemberRoleChanged {
                    device: crate::mcp::encode_hex(device_id.as_bytes()),
                    role: delivery_role(role),
                }
            }
            RemoteEventPayload::LocalAccessRemoved { device_id } => {
                DeliveryPayloadResult::LocalAccessRemoved {
                    device: crate::mcp::encode_hex(device_id.as_bytes()),
                }
            }
        },
    }
}

const fn delivery_role(role: ConversationRole) -> &'static str {
    match role {
        ConversationRole::Administrator => "administrator",
        ConversationRole::Member => "member",
    }
}

const fn policy_response_outcome(outcome: CollaborationPolicyResponseOutcome) -> &'static str {
    match outcome {
        CollaborationPolicyResponseOutcome::Accepted => "accepted",
        CollaborationPolicyResponseOutcome::Rejected => "rejected",
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
enum LedgerPrincipal {
    Issuer {
        key_id: [u8; 16],
        key_version: u32,
        client_instance: [u8; 16],
    },
    Session {
        public_key: [u8; 32],
        profile: String,
    },
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct LedgerKey {
    principal: LedgerPrincipal,
    request_id: [u8; 16],
}

impl LedgerKey {
    fn for_grant(grant: &SessionGrant, request_id: RequestId) -> Self {
        Self {
            principal: LedgerPrincipal::Session {
                public_key: *grant.session_public_key().as_bytes(),
                profile: grant.profile().as_str().to_string(),
            },
            request_id: *request_id.as_bytes(),
        }
    }

    fn for_issuer(issuer: &IssuerConnection, request_id: RequestId) -> Self {
        Self {
            principal: LedgerPrincipal::Issuer {
                key_id: *issuer.issuer_key_id.as_bytes(),
                key_version: issuer.issuer_key_version.get(),
                client_instance: *issuer.client_instance.as_bytes(),
            },
            request_id: *request_id.as_bytes(),
        }
    }

    #[cfg(test)]
    fn new(
        binding: &KonclaveLocalServiceTransport::LocalServiceBinding,
        request_id: RequestId,
    ) -> Self {
        Self {
            principal: LedgerPrincipal::Issuer {
                key_id: *binding.adapter_key_id().as_bytes(),
                key_version: binding.adapter_key_version().get(),
                client_instance: *binding.client_instance().as_bytes(),
            },
            request_id: *request_id.as_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestCancellationReason {
    Caller,
    Deadline,
    Shutdown,
    AuthorizationLost,
}

impl RequestCancellationReason {
    const fn error_code(self) -> LocalServiceErrorCode {
        match self {
            Self::Caller => LocalServiceErrorCode::Cancelled,
            Self::Deadline => LocalServiceErrorCode::DeadlineExceeded,
            Self::Shutdown => LocalServiceErrorCode::ProfileUnavailable,
            Self::AuthorizationLost => LocalServiceErrorCode::NotAuthorized,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestPhase {
    PreCommit,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestCancellationState {
    Requested,
    Reconciling,
    Terminal,
}

impl RequestCancellationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "cancellation_requested",
            Self::Reconciling => "reconciling",
            Self::Terminal => "terminal",
        }
    }
}

struct LedgerEntry {
    operation: String,
    payload: Vec<u8>,
    outcome: watch::Sender<Option<LocalServiceResponse>>,
    phase: RequestPhase,
    cancellation: Option<RequestCancellationReason>,
    durable: bool,
    stored_bytes: usize,
}

#[derive(Default)]
struct RequestLedger {
    entries: HashMap<LedgerKey, LedgerEntry>,
    order: VecDeque<LedgerKey>,
    cancellations: HashMap<LedgerKey, RequestCancellationReason>,
    cancellation_order: VecDeque<LedgerKey>,
    stored_bytes: usize,
    stopping: bool,
}

enum LedgerDecision {
    Execute,
    Wait(watch::Receiver<Option<LocalServiceResponse>>),
    Cached(LocalServiceResponse, bool),
    Conflict,
    Busy,
    ShuttingDown,
}

fn begin_request(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: LedgerKey,
    request: &LocalServiceRequest,
) -> LedgerDecision {
    let mut ledger = lock(ledger);
    if ledger.stopping {
        return LedgerDecision::ShuttingDown;
    }
    if let Some(entry) = ledger.entries.get(&key) {
        if entry.operation != request.operation().as_str() || entry.payload != request.payload() {
            return LedgerDecision::Conflict;
        }
        let response = entry.outcome.borrow().clone();
        return response.map_or_else(
            || LedgerDecision::Wait(entry.outcome.subscribe()),
            |response| LedgerDecision::Cached(response, entry.durable),
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
    let cancellation = ledger.cancellations.remove(&key);
    if cancellation.is_some() {
        ledger
            .cancellation_order
            .retain(|candidate| candidate != &key);
    }
    let (outcome, _) = watch::channel(None);
    ledger.order.push_back(key.clone());
    ledger.entries.insert(
        key,
        LedgerEntry {
            operation: request.operation().as_str().to_string(),
            payload: request.payload().to_vec(),
            outcome,
            phase: RequestPhase::PreCommit,
            cancellation,
            durable: false,
            stored_bytes: reservation,
        },
    );
    ledger.stored_bytes = ledger.stored_bytes.saturating_add(reservation);
    LedgerDecision::Execute
}

fn commit_request(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: &LedgerKey,
) -> Option<RequestCancellationReason> {
    let mut ledger = lock(ledger);
    let entry = ledger.entries.get_mut(key)?;
    if entry.outcome.borrow().is_some() {
        return None;
    }
    if entry.cancellation.is_none() {
        entry.phase = RequestPhase::Committed;
    }
    entry.cancellation
}

fn cancel_request(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: &LedgerKey,
    reason: RequestCancellationReason,
) -> RequestCancellationState {
    let mut ledger = lock(ledger);
    let Some(entry) = ledger.entries.get_mut(key) else {
        if !ledger.cancellations.contains_key(key) {
            while ledger.cancellations.len() >= MAX_LEDGER_ENTRIES {
                let Some(oldest) = ledger.cancellation_order.pop_front() else {
                    break;
                };
                ledger.cancellations.remove(&oldest);
            }
            ledger.cancellations.insert(key.clone(), reason);
            ledger.cancellation_order.push_back(key.clone());
        }
        return RequestCancellationState::Requested;
    };
    if entry.outcome.borrow().is_some() {
        return RequestCancellationState::Terminal;
    }
    match entry.phase {
        RequestPhase::PreCommit => {
            entry.cancellation.get_or_insert(reason);
            RequestCancellationState::Requested
        }
        RequestPhase::Committed => RequestCancellationState::Reconciling,
    }
}

fn stop_admission_and_cancel_precommit(
    ledger: &Arc<Mutex<RequestLedger>>,
    reason: RequestCancellationReason,
) {
    let mut ledger = lock(ledger);
    ledger.stopping = true;
    for entry in ledger.entries.values_mut() {
        if entry.phase == RequestPhase::PreCommit && entry.outcome.borrow().is_none() {
            entry.cancellation.get_or_insert(reason);
        }
    }
}

fn discard_request(ledger: &Arc<Mutex<RequestLedger>>, key: &LedgerKey) {
    let mut ledger = lock(ledger);
    if let Some(entry) = ledger.entries.remove(key) {
        ledger.stored_bytes = ledger.stored_bytes.saturating_sub(entry.stored_bytes);
    }
    ledger.order.retain(|candidate| candidate != key);
    ledger.cancellations.remove(key);
    ledger
        .cancellation_order
        .retain(|candidate| candidate != key);
}

fn complete_request(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: &LedgerKey,
    response: LocalServiceResponse,
) {
    complete_request_with_durability(ledger, key, response, true);
}

fn complete_request_with_durability(
    ledger: &Arc<Mutex<RequestLedger>>,
    key: &LedgerKey,
    response: LocalServiceResponse,
    durable: bool,
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
        entry.durable = durable;
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

fn mark_request_durable(ledger: &Arc<Mutex<RequestLedger>>, key: &LedgerKey) {
    let mut ledger = lock(ledger);
    if let Some(entry) = ledger.entries.get_mut(key)
        && entry.outcome.borrow().is_some()
    {
        entry.durable = true;
    }
}

fn request_is_durable(ledger: &Arc<Mutex<RequestLedger>>, key: &LedgerKey) -> bool {
    lock(ledger)
        .entries
        .get(key)
        .is_none_or(|entry| entry.durable)
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
            .is_some_and(|entry| entry.durable && entry.outcome.borrow().is_some());
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
}

impl RequestCompletion {
    fn new(ledger: Arc<Mutex<RequestLedger>>, key: LedgerKey) -> Self {
        Self { ledger, key }
    }

    fn complete(self, response: LocalServiceResponse, durable: bool) {
        complete_request_with_durability(&self.ledger, &self.key, response, durable);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod delivery_contract_tests {
    use KonclaveDomainCore::{
        ApplicationContent, ApplicationMessage, CollaborationPolicyDigest,
        CollaborationPolicyProposal, CollaborationPolicyProposalId, CollaborationPolicyResponse,
        CollaborationPolicyResponseOutcome, CollaborationPolicyRevocation, ConversationId,
        DeviceId, MessageId, NotificationId, ProtocolVersion,
    };
    use KonclaveLocalServiceTransport::LocalServiceErrorCode;
    use serde_json::json;

    use super::{
        delivery_event_result, is_fresh_collaboration_policy_request, is_tool_operation,
        operation_error_code,
    };
    use crate::persistence::{ClaimedRemoteEvent, RemoteEvent, RemoteEventPayload};

    #[test]
    fn policy_delivery_fields_use_the_shared_camel_case_contract() {
        let proposal_id = CollaborationPolicyProposalId::from_bytes([1; 16]);
        let digest = CollaborationPolicyDigest::from_bytes([2; 32]);
        let proposal = serde_json::to_value(delivery_event_result(claimed(
            ApplicationContent::collaboration_policy_proposal(
                CollaborationPolicyProposal::new(proposal_id, digest, vec![3], None).unwrap(),
            ),
        )))
        .unwrap();
        assert_eq!(
            proposal["payload"],
            json!({
                "kind": "collaboration_policy_proposal",
                "proposalId": "01".repeat(16),
                "policyDigest": "02".repeat(32),
                "replacesPolicyDigest": null
            })
        );
        assert!(proposal["payload"].get("canonicalBundle").is_none());

        for (outcome, expected) in [
            (CollaborationPolicyResponseOutcome::Accepted, "accepted"),
            (CollaborationPolicyResponseOutcome::Rejected, "rejected"),
        ] {
            let response =
                serde_json::to_value(delivery_event_result(claimed(
                    ApplicationContent::CollaborationPolicyResponse(
                        CollaborationPolicyResponse::new(proposal_id, digest, outcome),
                    ),
                )))
                .unwrap();
            assert_eq!(response["payload"]["outcome"], expected);
        }

        let revocation = serde_json::to_value(delivery_event_result(claimed(
            ApplicationContent::CollaborationPolicyRevocation(CollaborationPolicyRevocation::new(
                digest,
            )),
        )))
        .unwrap();
        assert_eq!(
            revocation["payload"],
            json!({
                "kind": "collaboration_policy_revocation",
                "policyDigest": "02".repeat(32)
            })
        );
    }

    #[test]
    fn directed_request_delivery_preserves_target_and_body() {
        let payload = serde_json::to_value(delivery_event_result(claimed(
            ApplicationContent::directed_request(DeviceId::from_bytes([9; 32]), "please reply")
                .unwrap(),
        )))
        .unwrap();

        assert_eq!(
            payload["payload"],
            json!({
                "kind": "directed_request",
                "messageId": "04".repeat(16),
                "targetDeviceId": "09".repeat(32),
                "text": "please reply"
            })
        );
    }

    #[test]
    fn policy_operations_use_stable_local_service_capabilities_and_errors() {
        for operation in [
            "propose_collaboration_policy",
            "propose_collaboration_policy_source",
            "resume_collaboration_policy_proposal",
            "get_collaboration_policy_status",
            "inspect_collaboration_policy_proposal",
            "accept_collaboration_policy",
            "reject_collaboration_policy",
            "revoke_collaboration_policy",
        ] {
            assert!(is_tool_operation(operation));
        }
        assert_eq!(
            operation_error_code("invalid_collaboration_policy_bundle"),
            LocalServiceErrorCode::InvalidRequest
        );
        assert_eq!(
            operation_error_code("invalid_collaboration_policy_source"),
            LocalServiceErrorCode::InvalidRequest
        );
        assert_eq!(
            operation_error_code("collaboration_policy_proposal_not_found"),
            LocalServiceErrorCode::InvalidRequest
        );
        assert_eq!(
            operation_error_code("collaboration_policy_conflict"),
            LocalServiceErrorCode::Conflict
        );
        assert_eq!(
            operation_error_code("invalid_collaboration_authorization"),
            LocalServiceErrorCode::NotAuthorized
        );
        assert_eq!(
            operation_error_code("profile_suspended"),
            LocalServiceErrorCode::ProfileSuspended
        );
        assert_eq!(
            operation_error_code("issuer_disabled"),
            LocalServiceErrorCode::IssuerDisabled
        );
        assert_eq!(
            operation_error_code("required_evidence_unavailable"),
            LocalServiceErrorCode::RequiredEvidenceUnavailable
        );
        assert_eq!(
            operation_error_code("capacity"),
            LocalServiceErrorCode::Capacity
        );
        assert_eq!(
            operation_error_code("directed_request_unsupported"),
            LocalServiceErrorCode::InvalidRequest
        );
        assert!(is_fresh_collaboration_policy_request(
            "collaboration.turn.authorize"
        ));
        assert!(is_fresh_collaboration_policy_request(
            "collaboration.turn.complete"
        ));
        assert!(is_fresh_collaboration_policy_request(
            "collaboration.action.evaluate"
        ));
        assert!(!is_fresh_collaboration_policy_request("send_message"));
    }

    fn claimed(content: ApplicationContent) -> ClaimedRemoteEvent {
        let message = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([4; 16]),
            1,
            1_700_000_000_000,
            None,
            content,
        )
        .unwrap();
        ClaimedRemoteEvent {
            event: RemoteEvent {
                sequence: 5,
                notification_id: NotificationId::from_bytes([6; 16]),
                conversation_id: ConversationId::from_bytes([7; 32]),
                relay_cursor: 8,
                sender: DeviceId::from_bytes([9; 32]),
                payload: RemoteEventPayload::ApplicationMessage(message),
            },
            lease_generation: 10,
        }
    }
}

#[cfg(test)]
mod collaboration_policy_tests {
    use std::collections::HashMap;

    use KonclaveDomainCore::{
        AdapterConsumerId, AdapterLeaseId, ApplicationContent, ApplicationMessage,
        CollaborationPolicyBundle, CollaborationPolicyEffect, CollaborationPolicyLimits,
        CollaborationPolicyStatement, DeliveryClass, DeviceId, Ed25519PublicKey, EnvelopeId,
        MessageId, NotificationId, ProtocolVersion, RelayEnvelope, RoutingId, StoredRelayEnvelope,
    };
    use KonclaveLocalServiceTransport::{
        AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicyVersion,
        ClientInstanceId, HarnessKind, IssuerKeyId, IssuerKeyVersion, RequestId, ServiceProfileId,
        SessionCapabilities, SessionGrant, SessionGrantClaims, SessionGrantId,
    };
    use KonclaveProtocolContracts::v1::encode_collaboration_policy_bundle;
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::{
        CollaborationAuthorizedSendRequest, CollaborationSendAuthorization,
        CollaborationSendCandidate, SystemUnixClock, UnixClock, authorize_collaboration_turn,
        complete_collaboration_turn, consume_collaboration_send_authorization,
        evaluate_collaboration_action, issue_collaboration_action_evaluation,
    };
    use crate::adapter::DeliveryAttachment;
    use crate::conversation::tests::open_coordinator;
    use crate::persistence::DirectedRequestClaim;

    fn grant(harness: HarnessKind) -> SessionGrant {
        grant_with_identity(harness, [1; 16], [3; 32])
    }

    fn grant_with_identity(
        harness: HarnessKind,
        grant_id: [u8; 16],
        session_public_key: [u8; 32],
    ) -> SessionGrant {
        SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes(grant_id),
            issuer_key_id: IssuerKeyId::from_bytes([2; 16]),
            issuer_key_version: IssuerKeyVersion::new(1).unwrap(),
            profile: ServiceProfileId::parse("policy-eval").unwrap(),
            session_public_key: Ed25519PublicKey::from_bytes(session_public_key),
            harness,
            evidence: AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
                .unwrap(),
            policy_version: AuthorizationPolicyVersion::new(1).unwrap(),
            issued_at_unix_milliseconds: 1,
            expires_at_unix_milliseconds: u64::MAX,
            capabilities: SessionCapabilities::ALL,
        })
        .unwrap()
    }

    #[test]
    fn refreshed_grants_preserve_the_session_request_ledger_principal() {
        let request_id = RequestId::from_bytes([7; 16]);
        let first = grant_with_identity(HarnessKind::A2AGateway, [1; 16], [3; 32]);
        let refreshed = grant_with_identity(HarnessKind::A2AGateway, [9; 16], [3; 32]);
        let another_session = grant_with_identity(HarnessKind::A2AGateway, [10; 16], [4; 32]);

        assert!(
            super::LedgerKey::for_grant(&first, request_id)
                == super::LedgerKey::for_grant(&refreshed, request_id)
        );
        assert!(
            super::LedgerKey::for_grant(&first, request_id)
                != super::LedgerKey::for_grant(&another_session, request_id)
        );
    }

    #[test]
    fn issuer_request_ledger_principal_includes_the_client_instance() {
        let request_id = RequestId::from_bytes([7; 16]);
        let first = super::IssuerConnection {
            issuer_key_id: IssuerKeyId::from_bytes([2; 16]),
            issuer_key_version: IssuerKeyVersion::new(1).unwrap(),
            issuer_public_key: Ed25519PublicKey::from_bytes([3; 32]),
            client_instance: ClientInstanceId::from_bytes([4; 16]),
            harness: HarnessKind::Generic,
        };
        let second = super::IssuerConnection {
            client_instance: ClientInstanceId::from_bytes([5; 16]),
            ..first.clone()
        };

        assert!(
            super::LedgerKey::for_issuer(&first, request_id)
                != super::LedgerKey::for_issuer(&second, request_id)
        );
        assert!(
            super::LedgerKey::for_issuer(&first, request_id)
                == super::LedgerKey::for_issuer(&first, request_id)
        );
    }

    fn bundle(limits: CollaborationPolicyLimits) -> Vec<u8> {
        encode_collaboration_policy_bundle(
            &CollaborationPolicyBundle::new(
                ProtocolVersion::application_v1(),
                "copilot-policy",
                Some("Align the contract and report the result.".to_string()),
                vec![
                    CollaborationPolicyStatement::new(
                        "reply",
                        CollaborationPolicyEffect::Allow,
                        "conversation.reply",
                        None,
                    )
                    .unwrap(),
                ],
                vec!["harness.session-identity".to_string()],
                limits,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn consumer() -> AdapterConsumerId {
        AdapterConsumerId::from_bytes([9; AdapterConsumerId::LENGTH])
    }

    fn attach_delivery(store: &crate::persistence::ProfileStore) -> u64 {
        let now = SystemUnixClock.now_unix_milliseconds();
        let expires_at = now + 60_000;
        store
            .acquire_adapter_consumer(
                consumer(),
                AdapterLeaseId::from_bytes([10; AdapterLeaseId::LENGTH]),
                now,
                expires_at,
            )
            .unwrap();
        expires_at
    }

    fn directed_request_delivery(
        store: &std::sync::Arc<crate::persistence::ProfileStore>,
        conversation_id: KonclaveDomainCore::ConversationId,
        routing_id: RoutingId,
        local_device: DeviceId,
    ) -> (DeliveryAttachment, MessageId, NotificationId, u64) {
        store
            .set_adapter_delivery_enabled(conversation_id, true)
            .unwrap();
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            routing_id,
            EnvelopeId::from_bytes([41; EnvelopeId::LENGTH]),
            DeliveryClass::GroupApplication,
            None,
            1_900_000_000,
            vec![41],
        )
        .unwrap();
        store
            .record_inbox_envelope(&StoredRelayEnvelope::new(envelope, 1).unwrap())
            .unwrap();
        let request_message_id = MessageId::from_bytes([42; MessageId::LENGTH]);
        let request = ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            request_message_id,
            1,
            1_700_000_000_000,
            None,
            ApplicationContent::directed_request(local_device, "review the contract").unwrap(),
        )
        .unwrap();
        store
            .save_inbox_message(
                conversation_id,
                1,
                DeviceId::from_bytes([43; DeviceId::LENGTH]),
                0,
                &request,
            )
            .unwrap();
        let notification_id = NotificationId::from_bytes([44; NotificationId::LENGTH]);
        store
            .complete_inbox_with_notification(conversation_id, 1, notification_id)
            .unwrap();
        let now = SystemUnixClock.now_unix_milliseconds();
        let delivery = DeliveryAttachment::acquire(consumer(), store, now).unwrap();
        let claimed = store
            .claim_remote_events(consumer(), delivery.lease_id(), now, now + 60_000, 1)
            .unwrap();
        assert_eq!(claimed.len(), 1);
        (
            delivery,
            request_message_id,
            notification_id,
            claimed[0].lease_generation,
        )
    }

    #[test]
    fn copilot_turn_authorization_and_action_evaluation_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = open_coordinator(root.path(), "policy-eval");
        let conversation = coordinator.create().unwrap();
        let store = coordinator.store();
        let digest = store
            .store_collaboration_policy_bundle(&bundle(
                CollaborationPolicyLimits::new(None, None, None, Some(1)).unwrap(),
            ))
            .unwrap();
        store
            .activate_collaboration_policy(conversation.conversation_id, digest, 0)
            .unwrap();
        let local_device = coordinator.device_id().unwrap();
        let (delivery, request_message_id, notification_id, lease_generation) =
            directed_request_delivery(
                &store,
                conversation.conversation_id,
                conversation.routing_id,
                local_device,
            );
        let conversation_id = crate::mcp::encode_hex(conversation.conversation_id.as_bytes());
        let authorize_payload = serde_json::to_vec(&json!({
            "conversationId": conversation_id,
            "requestMessageId": crate::mcp::encode_hex(request_message_id.as_bytes()),
            "notificationId": crate::mcp::encode_hex(notification_id.as_bytes()),
            "leaseGeneration": lease_generation
        }))
        .unwrap();

        let authorized: serde_json::Value = serde_json::from_slice(
            &authorize_collaboration_turn(
                &store,
                &grant(HarnessKind::Copilot),
                consumer(),
                Some(&delivery),
                local_device,
                &authorize_payload,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authorized["outcome"], "authorized");
        assert!(authorized.get("guidance").is_none());
        assert_eq!(
            authorized["requestMessageId"],
            crate::mcp::encode_hex(request_message_id.as_bytes())
        );
        assert_eq!(authorized["attempt"], 1);

        let action_payload = serde_json::to_vec(&json!({
            "conversationId": conversation_id,
            "policyDigest": crate::mcp::encode_hex(digest.as_bytes()),
            "action": "conversation.reply",
            "resource": null,
            "messageId": "11".repeat(16),
            "replyToMessageId": crate::mcp::encode_hex(request_message_id.as_bytes()),
            "text": "aligned",
            "requestMessageId": crate::mcp::encode_hex(request_message_id.as_bytes()),
            "attempt": 1
        }))
        .unwrap();
        let mut authorizations = HashMap::new();
        let action: serde_json::Value = serde_json::from_slice(
            &issue_collaboration_action_evaluation(
                &mut authorizations,
                evaluate_collaboration_action(
                    &store,
                    &grant(HarnessKind::Copilot),
                    consumer(),
                    local_device,
                    &action_payload,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(action["decision"], "allow");
        let authorization = action["authorization"].as_str().unwrap();
        assert_eq!(authorization.len(), 32);
        assert_eq!(authorizations.len(), 1);
        let send = CollaborationAuthorizedSendRequest {
            conversation_id: conversation_id.clone(),
            message_id: "11".repeat(16),
            text: "aligned".to_string(),
            reply_to_message_id: Some(crate::mcp::encode_hex(request_message_id.as_bytes())),
            collaboration_authorization: Some(authorization.to_string()),
        };
        consume_collaboration_send_authorization(
            &mut authorizations,
            authorization,
            &send,
            SystemUnixClock.now_unix_milliseconds(),
        )
        .unwrap();
        assert!(authorizations.is_empty());
        assert!(
            consume_collaboration_send_authorization(
                &mut authorizations,
                authorization,
                &send,
                SystemUnixClock.now_unix_milliseconds(),
            )
            .is_err()
        );
        let complete_payload = serde_json::to_vec(&json!({
            "conversationId": conversation_id,
            "policyDigest": crate::mcp::encode_hex(digest.as_bytes()),
            "requestMessageId": crate::mcp::encode_hex(request_message_id.as_bytes()),
            "attempt": 1
        }))
        .unwrap();
        let completed: serde_json::Value = serde_json::from_slice(
            &complete_collaboration_turn(
                &store,
                &grant(HarnessKind::Copilot),
                consumer(),
                local_device,
                &complete_payload,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(completed["outcome"], "completed_no_response");
        assert_eq!(completed["changed"], true);
        let repeated: serde_json::Value = serde_json::from_slice(
            &complete_collaboration_turn(
                &store,
                &grant(HarnessKind::Copilot),
                consumer(),
                local_device,
                &complete_payload,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated["changed"], false);
        let after_completion: serde_json::Value = serde_json::from_slice(
            &issue_collaboration_action_evaluation(
                &mut authorizations,
                evaluate_collaboration_action(
                    &store,
                    &grant(HarnessKind::Copilot),
                    consumer(),
                    local_device,
                    &action_payload,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(after_completion["decision"], "deny");
        assert_eq!(
            after_completion["reason"],
            "directed_request_claim_inactive"
        );

        let generic: serde_json::Value = serde_json::from_slice(
            &authorize_collaboration_turn(
                &store,
                &grant(HarnessKind::Generic),
                consumer(),
                Some(&delivery),
                local_device,
                &authorize_payload,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(generic["outcome"], "denied");
        let generic_action: serde_json::Value = serde_json::from_slice(
            &issue_collaboration_action_evaluation(
                &mut authorizations,
                evaluate_collaboration_action(
                    &store,
                    &grant(HarnessKind::Generic),
                    consumer(),
                    local_device,
                    &action_payload,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(generic_action["decision"], "deny");
        assert_eq!(generic_action["reason"], "copilot_delivery_not_proven");
        assert!(authorizations.is_empty());

        let detached: serde_json::Value = serde_json::from_slice(
            &authorize_collaboration_turn(
                &store,
                &grant(HarnessKind::Copilot),
                AdapterConsumerId::from_bytes([8; AdapterConsumerId::LENGTH]),
                None,
                local_device,
                &authorize_payload,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(detached["outcome"], "denied");

        let unsupported_digest_payload = serde_json::to_vec(&json!({
            "conversationId": conversation_id,
            "policyDigest": "ff".repeat(32),
            "action": "conversation.reply",
            "resource": null,
            "messageId": "12".repeat(16),
            "replyToMessageId": crate::mcp::encode_hex(request_message_id.as_bytes()),
            "text": "aligned",
            "requestMessageId": crate::mcp::encode_hex(request_message_id.as_bytes()),
            "attempt": 1
        }))
        .unwrap();
        let changed: serde_json::Value = serde_json::from_slice(
            &issue_collaboration_action_evaluation(
                &mut authorizations,
                evaluate_collaboration_action(
                    &store,
                    &grant(HarnessKind::Copilot),
                    consumer(),
                    local_device,
                    &unsupported_digest_payload,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(changed["decision"], "deny");
        assert_eq!(changed["reason"], "policy_changed");
    }

    #[test]
    fn finite_turn_or_token_limits_disable_unproven_autonomy() {
        for (profile, limits, reason) in [
            (
                "finite-turns",
                CollaborationPolicyLimits::new(None, Some(1), None, Some(1)).unwrap(),
                "turn_accounting_unavailable",
            ),
            (
                "finite-tokens",
                CollaborationPolicyLimits::new(None, None, Some(1), Some(1)).unwrap(),
                "token_accounting_unavailable",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let coordinator = open_coordinator(root.path(), profile);
            let conversation = coordinator.create().unwrap();
            let store = coordinator.store();
            let now = SystemUnixClock.now_unix_milliseconds();
            let delivery = DeliveryAttachment::acquire(consumer(), &store, now).unwrap();
            let digest = store
                .store_collaboration_policy_bundle(&bundle(limits))
                .unwrap();
            store
                .activate_collaboration_policy(conversation.conversation_id, digest, 0)
                .unwrap();
            let payload = serde_json::to_vec(&json!({
                "conversationId": crate::mcp::encode_hex(conversation.conversation_id.as_bytes()),
                "requestMessageId": "11".repeat(16),
                "notificationId": "12".repeat(16),
                "leaseGeneration": 1
            }))
            .unwrap();
            let result: serde_json::Value = serde_json::from_slice(
                &authorize_collaboration_turn(
                    &store,
                    &grant(HarnessKind::Copilot),
                    consumer(),
                    Some(&delivery),
                    coordinator.device_id().unwrap(),
                    &payload,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(result["outcome"], "denied");
            assert_eq!(result["reason"], reason);
        }
    }

    #[test]
    fn collaboration_send_authorizations_are_one_use_and_exactly_bound() {
        let now = SystemUnixClock.now_unix_milliseconds();
        let conversation_id = KonclaveDomainCore::ConversationId::from_bytes([1; 32]);
        let policy_digest = KonclaveDomainCore::CollaborationPolicyDigest::from_bytes([2; 32]);
        let message_id = KonclaveDomainCore::MessageId::from_bytes([3; 16]);
        let reply_to_message_id = KonclaveDomainCore::MessageId::from_bytes([4; 16]);
        let token = [5; 16];
        let token_text = crate::mcp::encode_hex(&token);
        let candidate = || CollaborationSendCandidate {
            conversation_id,
            policy_digest,
            consumer_id: consumer(),
            not_after_unix_milliseconds: now + 2_000,
            message_id,
            reply_to_message_id: Some(reply_to_message_id),
            text: Zeroizing::new("aligned".to_string()),
            directed_request_claim: DirectedRequestClaim {
                conversation_id,
                request_message_id: reply_to_message_id,
                responder_device_id: DeviceId::from_bytes([6; DeviceId::LENGTH]),
                notification_id: NotificationId::from_bytes([7; NotificationId::LENGTH]),
                consumer_id: consumer(),
                lease_id: AdapterLeaseId::from_bytes([8; AdapterLeaseId::LENGTH]),
                lease_generation: 1,
                claim_expires_at_unix_milliseconds: now + 2_000,
                attempt: 1,
                policy_digest,
            },
        };
        let request = |conversation_id: String,
                       message_id: String,
                       reply_to_message_id: Option<String>,
                       text: &str| CollaborationAuthorizedSendRequest {
            conversation_id,
            message_id,
            text: text.to_string(),
            reply_to_message_id,
            collaboration_authorization: Some(token_text.clone()),
        };
        let expected_conversation = crate::mcp::encode_hex(conversation_id.as_bytes());
        let expected_message = crate::mcp::encode_hex(message_id.as_bytes());
        let expected_reply = Some(crate::mcp::encode_hex(reply_to_message_id.as_bytes()));
        let valid = request(
            expected_conversation.clone(),
            expected_message.clone(),
            expected_reply.clone(),
            "aligned",
        );
        let altered = [
            request(
                crate::mcp::encode_hex([6; 32].as_slice()),
                expected_message.clone(),
                expected_reply.clone(),
                "aligned",
            ),
            request(
                expected_conversation.clone(),
                crate::mcp::encode_hex([7; 16].as_slice()),
                expected_reply.clone(),
                "aligned",
            ),
            request(
                expected_conversation.clone(),
                expected_message.clone(),
                Some(crate::mcp::encode_hex([8; 16].as_slice())),
                "aligned",
            ),
            request(
                expected_conversation.clone(),
                expected_message.clone(),
                expected_reply.clone(),
                "changed",
            ),
        ];
        let mut authorizations = HashMap::new();
        for changed in altered {
            authorizations.insert(
                token,
                CollaborationSendAuthorization {
                    candidate: candidate(),
                    expires_at_unix_milliseconds: now + 1_000,
                },
            );
            assert!(
                consume_collaboration_send_authorization(
                    &mut authorizations,
                    &token_text,
                    &changed,
                    now,
                )
                .is_err()
            );
            assert!(authorizations.is_empty());
        }
        authorizations.insert(
            token,
            CollaborationSendAuthorization {
                candidate: candidate(),
                expires_at_unix_milliseconds: now,
            },
        );
        assert!(
            consume_collaboration_send_authorization(
                &mut authorizations,
                &token_text,
                &valid,
                now,
            )
            .is_err()
        );
        authorizations.insert(
            token,
            CollaborationSendAuthorization {
                candidate: candidate(),
                expires_at_unix_milliseconds: now + 1_000,
            },
        );
        consume_collaboration_send_authorization(&mut authorizations, &token_text, &valid, now)
            .unwrap();
        assert!(
            consume_collaboration_send_authorization(
                &mut authorizations,
                &token_text,
                &valid,
                now,
            )
            .is_err()
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
    use KonclaveLocalAuthorizationStore::{
        AuthorizationGeneration, AuthorizationMutation, ExistingGrantDisposition,
        InstallationFingerprint, IssuerAvailability, LocalAuthorizationStore,
        LocalAuthorizationStoreError,
    };
    use KonclaveLocalServiceTransport::{
        AdapterKeyId, AdapterKeyVersion, AdapterRegistration, AuthorizationEvidenceKind,
        AuthorizationEvidenceSet, AuthorizationPolicy, AuthorizationPolicyVersion,
        ClientInstanceId, HarnessKind, InstalledIssuerRegistration, IssuerHandshakeRequest,
        LOCAL_SERVICE_INSTALLATION_FILE, LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceBinding,
        LocalServiceEndpoint, LocalServiceErrorCode, LocalServiceRequest, LocalServiceResponse,
        MAX_RPC_PAYLOAD_BYTES, OperationName, ProfileAuthorization, RequestId, ServiceProfileId,
        SessionCapabilities, SessionGrant, SessionGrantClaims, SessionGrantId,
        complete_issuer_client_handshake, complete_session_client_handshake, connect_local_service,
        read_response, write_request,
    };
    use KonclaveSecretStorage::{
        create_or_verify_owner_protected_file, ensure_owner_protected_directory,
    };
    use tokio::sync::oneshot;

    use super::{SharedLocalServiceConfig, run_shared_local_service_until};
    use crate::authorization_runtime::{
        AUTHORIZATION_OBSERVATION_BOUND, AuthorizationRuntimeStatus, LiveAuthorizationRuntime,
    };
    use crate::clock::{SystemUnixClock, UnixClock};
    use crate::profile_runtime::{ProfileHost, ProfileHostOptions};
    use crate::profile_supervisor::ProfileSupervisorConfig;
    use crate::runtime::{ProfileSource, initialize_profile};
    use crate::test_support::{TestProfileRoot, TestProfileSettings};

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
        authorization: Arc<LiveAuthorizationRuntime>,
        installation_path: PathBuf,
        installation_fingerprint: InstallationFingerprint,
    }

    struct BlockingProfileSource {
        inner: TestProfileSettings,
        started: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl ProfileSource for BlockingProfileSource {
        fn configure(
            &self,
            profile: &crate::persistence::ProfileId,
        ) -> anyhow::Result<crate::runtime::ProfileConfig> {
            self.started
                .send(())
                .map_err(|_| anyhow::anyhow!("profile-open observer was dropped"))?;
            self.release
                .lock()
                .map_err(|_| anyhow::anyhow!("profile-open release was poisoned"))?
                .recv()
                .map_err(|_| anyhow::anyhow!("profile-open release was dropped"))?;
            self.inner.configure(profile)
        }

        fn host_options(&self, profile: &crate::persistence::ProfileId) -> ProfileHostOptions {
            self.inner.host_options(profile)
        }
    }

    struct ProfileOpenRelease(Option<mpsc::Sender<()>>);

    impl ProfileOpenRelease {
        fn new(release: mpsc::Sender<()>) -> Self {
            Self(Some(release))
        }

        fn release(&mut self) {
            if let Some(release) = self.0.take() {
                let _ = release.send(());
            }
        }
    }

    impl Drop for ProfileOpenRelease {
        fn drop(&mut self) {
            self.release();
        }
    }

    impl Fixture {
        async fn new() -> Self {
            Self::new_with_policy(AuthorizationPolicy::account_trusted()).await
        }

        async fn new_with_policy(policy: AuthorizationPolicy) -> Self {
            let root = TestProfileRoot::new();
            let endpoint = LocalServiceEndpoint::parse(
                root.path()
                    .join("runtime")
                    .join("shared.sock")
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            let service_seed = LocalServiceSigningSeed::from_reader([5_u8; 32].as_slice()).unwrap();
            let service_identity =
                Arc::new(LocalServiceIdentity::from_signing_seed(&service_seed).unwrap());
            let client_seed = LocalServiceSigningSeed::from_reader([6_u8; 32].as_slice()).unwrap();
            let client_identity = LocalServiceIdentity::from_signing_seed(&client_seed).unwrap();
            let adapter_key_id = AdapterKeyId::from_bytes([7_u8; AdapterKeyId::LENGTH]);
            let adapter_key_version = AdapterKeyVersion::new(1).unwrap();
            let issuer = InstalledIssuerRegistration::new(
                adapter_key_id,
                adapter_key_version,
                AdapterRegistration::new(
                    client_identity.public_key(),
                    HarnessKind::Copilot,
                    ProfileAuthorization::Namespace(ServiceProfileId::parse("session").unwrap()),
                ),
            );
            let installation_path = root
                .path()
                .join("service")
                .join(LOCAL_SERVICE_INSTALLATION_FILE);
            let installation_fingerprint = InstallationFingerprint::from_bytes([9; 32]);
            let setup_path = installation_path.clone();
            let setup_issuer = issuer.clone();
            let setup_policy = policy.clone();
            tokio::task::spawn_blocking(move || {
                ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
                drop(
                    LocalAuthorizationStore::bootstrap(
                        &setup_path,
                        installation_fingerprint,
                        &setup_policy,
                        &[setup_issuer],
                        1,
                    )
                    .unwrap(),
                );
                create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
            })
            .await
            .unwrap();
            let authorization =
                LiveAuthorizationRuntime::open(&installation_path, installation_fingerprint)
                    .await
                    .unwrap();
            Self {
                root,
                endpoint,
                service_identity,
                client_identity,
                adapter_key_id,
                adapter_key_version,
                authorization,
                installation_path,
                installation_fingerprint,
            }
        }

        fn config(&self) -> SharedLocalServiceConfig {
            self.config_with(Arc::clone(&self.authorization))
        }

        fn config_with(
            &self,
            authorization: Arc<LiveAuthorizationRuntime>,
        ) -> SharedLocalServiceConfig {
            self.config_with_profile_source(authorization, Arc::new(self.root.settings()))
        }

        fn config_with_profile_source(
            &self,
            authorization: Arc<LiveAuthorizationRuntime>,
            profile_source: Arc<dyn ProfileSource>,
        ) -> SharedLocalServiceConfig {
            SharedLocalServiceConfig {
                endpoint: self.endpoint.clone(),
                service_identity: Arc::clone(&self.service_identity),
                authorization,
                profile_source,
                supervisor: ProfileSupervisorConfig::default(),
            }
        }

        fn grant(&self, profile: &str, instance_seed: u8) -> SessionGrant {
            self.grant_with_evidence(
                profile,
                instance_seed,
                AuthorizationEvidenceKind::AccountTrusted,
                1,
            )
        }

        fn grant_with_evidence(
            &self,
            profile: &str,
            instance_seed: u8,
            evidence: AuthorizationEvidenceKind,
            policy_version: u64,
        ) -> SessionGrant {
            SessionGrant::new(SessionGrantClaims {
                grant_id: SessionGrantId::from_bytes([instance_seed; 16]),
                issuer_key_id: self.adapter_key_id,
                issuer_key_version: self.adapter_key_version,
                profile: ServiceProfileId::parse(profile).unwrap(),
                session_public_key: self.client_identity.public_key(),
                harness: HarnessKind::Copilot,
                evidence: AuthorizationEvidenceSet::new([evidence]).unwrap(),
                policy_version: AuthorizationPolicyVersion::new(policy_version).unwrap(),
                issued_at_unix_milliseconds: 1,
                expires_at_unix_milliseconds: i64::MAX as u64,
                capabilities: SessionCapabilities::ALL,
            })
            .unwrap()
        }

        async fn persist_grant(&self, grant: SessionGrant) {
            if !self.authorization.grant_is_active(&grant) {
                self.authorization
                    .persist_grant_for_test(grant, SystemUnixClock.now_unix_milliseconds())
                    .await
                    .unwrap();
            }
        }

        async fn mutate_authorization<F>(&self, mutation: F) -> AuthorizationMutation
        where
            F: FnOnce(
                    &LocalAuthorizationStore,
                    u64,
                )
                    -> Result<AuthorizationMutation, LocalAuthorizationStoreError>
                + Send
                + 'static,
        {
            let installation_path = self.installation_path.clone();
            let installation_fingerprint = self.installation_fingerprint;
            let mutation = tokio::task::spawn_blocking(move || {
                let store = LocalAuthorizationStore::open(
                    installation_path,
                    installation_fingerprint,
                    None,
                )?;
                mutation(&store, SystemUnixClock.now_unix_milliseconds())
            })
            .await
            .unwrap()
            .unwrap();
            self.authorization.request_reload();
            self.wait_for_generation(mutation.generation()).await;
            mutation
        }

        async fn wait_for_generation(&self, expected: AuthorizationGeneration) {
            let mut status = self.authorization.subscribe();
            tokio::time::timeout(TEST_REQUEST_DEADLINE, async {
                loop {
                    match *status.borrow_and_update() {
                        AuthorizationRuntimeStatus::Active(generation)
                            if generation >= expected =>
                        {
                            break;
                        }
                        AuthorizationRuntimeStatus::Failed(_) => {
                            panic!("authorization runtime failed before publishing generation")
                        }
                        AuthorizationRuntimeStatus::Active(_) => {}
                    }
                    status.changed().await.unwrap();
                }
            })
            .await
            .expect("authorization generation was not published");
        }

        async fn connect_issuer(
            &self,
            instance_seed: u8,
        ) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
            tokio::time::timeout(TEST_STARTUP_DEADLINE, async {
                let mut stream = loop {
                    match connect_local_service(&self.endpoint).await {
                        Ok(stream) => break stream,
                        Err(_) => tokio::task::yield_now().await,
                    }
                };
                complete_issuer_client_handshake(
                    &mut stream,
                    &IssuerHandshakeRequest {
                        issuer_key_id: self.adapter_key_id,
                        issuer_key_version: self.adapter_key_version,
                        client_instance: ClientInstanceId::from_bytes(
                            [instance_seed; ClientInstanceId::LENGTH],
                        ),
                        harness: HarnessKind::Copilot,
                    },
                    &self.client_identity,
                    self.service_identity.public_key(),
                )
                .await
                .unwrap();
                stream
            })
            .await
            .expect("shared service issuer handshake exceeded the test deadline")
        }

        async fn connect_grant(
            &self,
            grant: SessionGrant,
            instance_seed: u8,
        ) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
            self.try_connect_grant(grant, instance_seed).await.unwrap()
        }

        async fn try_connect_grant(
            &self,
            grant: SessionGrant,
            instance_seed: u8,
        ) -> Result<
            KonclaveLocalServiceTransport::LocalServiceClientStream,
            KonclaveLocalServiceTransport::LocalServiceTransportError,
        > {
            tokio::time::timeout(TEST_STARTUP_DEADLINE, async {
                let mut stream = loop {
                    match connect_local_service(&self.endpoint).await {
                        Ok(stream) => break stream,
                        Err(_) => tokio::task::yield_now().await,
                    }
                };
                complete_session_client_handshake(
                    &mut stream,
                    &KonclaveLocalServiceTransport::SessionHandshakeRequest {
                        grant,
                        client_instance: ClientInstanceId::from_bytes(
                            [instance_seed; ClientInstanceId::LENGTH],
                        ),
                    },
                    &self.client_identity,
                    self.service_identity.public_key(),
                )
                .await?;
                Ok(stream)
            })
            .await
            .expect("shared service startup and handshake exceeded the test deadline")
        }

        async fn connect(
            &self,
            profile: &str,
            instance_seed: u8,
        ) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
            let grant = self.grant(profile, instance_seed);
            self.persist_grant(grant.clone()).await;
            self.connect_grant(grant, instance_seed).await
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

    async fn issue_grant(
        fixture: &Fixture,
        issuer: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
        seed: u8,
        profile: &str,
    ) -> Result<SessionGrant, LocalServiceErrorCode> {
        let payload = serde_json::to_vec(&serde_json::json!({
            "profile": profile,
            "sessionPublicKey": crate::mcp::encode_hex(
                fixture.client_identity.public_key().as_bytes()
            ),
            "harness": "copilot"
        }))
        .unwrap();
        match request(issuer, seed, "authorization.grant.issue", &payload).await {
            LocalServiceResponse::Success { payload, .. } => {
                let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                let grant_id =
                    crate::mcp::decode_hex::<16>(value["grantId"].as_str().unwrap()).unwrap();
                let issuer_key_id =
                    crate::mcp::decode_hex::<16>(value["issuerKeyId"].as_str().unwrap()).unwrap();
                let session_public_key =
                    crate::mcp::decode_hex::<32>(value["sessionPublicKey"].as_str().unwrap())
                        .unwrap();
                Ok(SessionGrant::new(SessionGrantClaims {
                    grant_id: SessionGrantId::from_bytes(grant_id),
                    issuer_key_id: AdapterKeyId::from_bytes(issuer_key_id),
                    issuer_key_version: AdapterKeyVersion::new(
                        u32::try_from(value["issuerKeyVersion"].as_u64().unwrap()).unwrap(),
                    )
                    .unwrap(),
                    profile: ServiceProfileId::parse(value["profile"].as_str().unwrap()).unwrap(),
                    session_public_key: KonclaveDomainCore::Ed25519PublicKey::from_bytes(
                        session_public_key,
                    ),
                    harness: super::parse_harness(value["harness"].as_str().unwrap()).unwrap(),
                    evidence: AuthorizationEvidenceSet::from_bits(
                        u8::try_from(value["evidence"].as_u64().unwrap()).unwrap(),
                    )
                    .unwrap(),
                    policy_version: AuthorizationPolicyVersion::new(
                        value["policyVersion"].as_u64().unwrap(),
                    )
                    .unwrap(),
                    issued_at_unix_milliseconds: value["issuedAtUnixMilliseconds"]
                        .as_u64()
                        .unwrap(),
                    expires_at_unix_milliseconds: value["expiresAtUnixMilliseconds"]
                        .as_u64()
                        .unwrap(),
                    capabilities: SessionCapabilities::from_bits(
                        value["capabilities"].as_u64().unwrap(),
                    )
                    .unwrap(),
                })
                .unwrap())
            }
            LocalServiceResponse::Failure { code, .. } => Err(code),
        }
    }

    async fn wait_for_active_delivery(root: &TestProfileRoot, profile: &str) {
        let database = root.root().join(profile).join("profile.sqlite");
        tokio::time::timeout(TEST_REQUEST_DEADLINE, async {
            loop {
                let candidate = database.clone();
                let active = tokio::task::spawn_blocking(move || {
                    if !candidate.is_file() {
                        return false;
                    }
                    rusqlite::Connection::open_with_flags(
                        candidate,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                    )
                    .ok()
                    .and_then(|connection| {
                        connection
                            .query_row("SELECT count(*) FROM daemon_adapter_consumer", [], |row| {
                                row.get::<_, i64>(0)
                            })
                            .ok()
                    }) == Some(1)
                })
                .await
                .unwrap();
                if active {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("delivery claim did not acquire its consumer lease");
    }

    async fn wait_for_outcome_database(
        root: &TestProfileRoot,
        profile: &str,
    ) -> std::path::PathBuf {
        let database = root.root().join(profile).join("profile.sqlite");
        tokio::time::timeout(TEST_REQUEST_DEADLINE, async {
            loop {
                let candidate = database.clone();
                let ready = tokio::task::spawn_blocking(move || {
                    if !candidate.is_file() {
                        return false;
                    }
                    rusqlite::Connection::open_with_flags(
                        candidate,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                    )
                    .unwrap()
                    .query_row(
                        "SELECT count(*) FROM sqlite_schema
                         WHERE type = 'table'
                           AND name = 'daemon_local_request_outcome'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap()
                        == 1
                })
                .await
                .unwrap();
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("local request outcome table was not created");
        database
    }

    async fn wait_for_recorded_outcome_count(root: &TestProfileRoot, profile: &str, expected: i64) {
        let outcome_database = wait_for_outcome_database(root, profile).await;
        tokio::time::timeout(TEST_REQUEST_DEADLINE, async {
            loop {
                let database = outcome_database.clone();
                let recorded = tokio::task::spawn_blocking(move || {
                    rusqlite::Connection::open_with_flags(
                        database,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                    )
                    .unwrap()
                    .query_row(
                        "SELECT count(*) FROM daemon_local_request_outcome",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap()
                })
                .await
                .unwrap();
                if recorded == expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal request outcomes were not persisted");
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
            super::LedgerDecision::Cached(cached, true) if cached == response
        ));
        let conflict = ledger_request(4, "create_conversation", b"{}".to_vec());
        assert!(matches!(
            super::begin_request(&ledger, key, &conflict),
            super::LedgerDecision::Conflict
        ));
    }

    #[test]
    fn cancellation_is_terminal_only_before_commit() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-cancellation");
        let request = ledger_request(12, "send_message", b"{}".to_vec());
        let key = super::LedgerKey::new(&binding, request.request_id());
        assert!(matches!(
            super::begin_request(&ledger, key.clone(), &request),
            super::LedgerDecision::Execute
        ));
        assert_eq!(
            super::cancel_request(&ledger, &key, super::RequestCancellationReason::Caller),
            super::RequestCancellationState::Requested
        );
        assert_eq!(
            super::commit_request(&ledger, &key),
            Some(super::RequestCancellationReason::Caller)
        );
        let cancelled =
            LocalServiceResponse::failure(request.request_id(), LocalServiceErrorCode::Cancelled);
        super::complete_request(&ledger, &key, cancelled);
        assert_eq!(
            super::cancel_request(&ledger, &key, super::RequestCancellationReason::Deadline),
            super::RequestCancellationState::Terminal
        );

        let committed = ledger_request(13, "send_message", b"{}".to_vec());
        let committed_key = super::LedgerKey::new(&binding, committed.request_id());
        assert!(matches!(
            super::begin_request(&ledger, committed_key.clone(), &committed),
            super::LedgerDecision::Execute
        ));
        assert_eq!(super::commit_request(&ledger, &committed_key), None);
        assert_eq!(
            super::cancel_request(
                &ledger,
                &committed_key,
                super::RequestCancellationReason::Deadline
            ),
            super::RequestCancellationState::Reconciling
        );

        let raced = ledger_request(14, "send_message", b"{}".to_vec());
        let raced_key = super::LedgerKey::new(&binding, raced.request_id());
        assert_eq!(
            super::cancel_request(
                &ledger,
                &raced_key,
                super::RequestCancellationReason::Deadline
            ),
            super::RequestCancellationState::Requested
        );
        assert!(matches!(
            super::begin_request(&ledger, raced_key.clone(), &raced),
            super::LedgerDecision::Execute
        ));
        assert_eq!(
            super::commit_request(&ledger, &raced_key),
            Some(super::RequestCancellationReason::Deadline)
        );
    }

    #[test]
    fn admission_pressure_never_discards_a_racing_cancellation() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-cancellation-pressure");
        let payload = vec![1_u8; MAX_RPC_PAYLOAD_BYTES];
        let mut first = None;
        for seed in 1..=64 {
            let request = ledger_request(seed, "send_message", payload.clone());
            let key = super::LedgerKey::new(&binding, request.request_id());
            match super::begin_request(&ledger, key.clone(), &request) {
                super::LedgerDecision::Execute => {
                    if first.is_none() {
                        first = Some((key, request));
                    }
                }
                super::LedgerDecision::Busy => break,
                _ => panic!("a unique request returned an invalid ledger decision"),
            };
        }
        let target = ledger_request(200, "send_message", payload);
        let target_key = super::LedgerKey::new(&binding, target.request_id());
        assert_eq!(
            super::cancel_request(
                &ledger,
                &target_key,
                super::RequestCancellationReason::Deadline
            ),
            super::RequestCancellationState::Requested
        );
        assert!(matches!(
            super::begin_request(&ledger, target_key.clone(), &target),
            super::LedgerDecision::Busy
        ));

        let (first_key, first_request) = first.unwrap();
        super::complete_request(
            &ledger,
            &first_key,
            LocalServiceResponse::failure(
                first_request.request_id(),
                LocalServiceErrorCode::Internal,
            ),
        );
        assert!(matches!(
            super::begin_request(&ledger, target_key.clone(), &target),
            super::LedgerDecision::Execute
        ));
        assert_eq!(
            super::commit_request(&ledger, &target_key),
            Some(super::RequestCancellationReason::Deadline)
        );
    }

    #[test]
    fn shutdown_atomically_cancels_precommit_work_and_stops_admission() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-shutdown-admission");
        let admitted = ledger_request(23, "get_identity", b"{}".to_vec());
        let admitted_key = super::LedgerKey::new(&binding, admitted.request_id());
        assert!(matches!(
            super::begin_request(&ledger, admitted_key.clone(), &admitted),
            super::LedgerDecision::Execute
        ));

        super::stop_admission_and_cancel_precommit(
            &ledger,
            super::RequestCancellationReason::Shutdown,
        );

        assert_eq!(
            super::commit_request(&ledger, &admitted_key),
            Some(super::RequestCancellationReason::Shutdown)
        );
        let later = ledger_request(24, "get_identity", b"{}".to_vec());
        assert!(matches!(
            super::begin_request(
                &ledger,
                super::LedgerKey::new(&binding, later.request_id()),
                &later
            ),
            super::LedgerDecision::ShuttingDown
        ));
    }

    #[test]
    fn an_abandoned_request_never_publishes_a_false_terminal_outcome() {
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
        ));

        assert!(matches!(
            super::begin_request(&ledger, key, &request),
            super::LedgerDecision::Wait(_)
        ));
    }

    #[test]
    fn an_unpersisted_actual_outcome_remains_reconcilable_without_leaking_the_slot() {
        let ledger = Arc::new(std::sync::Mutex::new(super::RequestLedger::default()));
        let binding = binding("session-reconciliation-pending");
        let request = ledger_request(22, "get_identity", b"{}".to_vec());
        let key = super::LedgerKey::new(&binding, request.request_id());
        assert!(matches!(
            super::begin_request(&ledger, key.clone(), &request),
            super::LedgerDecision::Execute
        ));
        assert_eq!(super::commit_request(&ledger, &key), None);
        let actual =
            LocalServiceResponse::success(request.request_id(), br#"{"device_id":"aa"}"#.to_vec())
                .unwrap();
        super::RequestCompletion::new(Arc::clone(&ledger), key.clone())
            .complete(actual.clone(), false);
        let caller_outcome = LocalServiceResponse::failure(
            request.request_id(),
            LocalServiceErrorCode::ReconciliationPending,
        );
        assert!(matches!(
            caller_outcome,
            LocalServiceResponse::Failure {
                code: LocalServiceErrorCode::ReconciliationPending,
                ..
            }
        ));
        for seed in 30..=64 {
            let pressure = ledger_request(seed, "send_message", vec![1_u8; MAX_RPC_PAYLOAD_BYTES]);
            let pressure_key = super::LedgerKey::new(&binding, pressure.request_id());
            if matches!(
                super::begin_request(&ledger, pressure_key, &pressure),
                super::LedgerDecision::Busy
            ) {
                break;
            }
        }
        assert!(matches!(
            super::begin_request(&ledger, key, &request),
            super::LedgerDecision::Cached(cached, false) if cached == actual
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn an_operation_crossing_the_deadline_records_its_actual_outcome() {
        let request_id = RequestId::from_bytes([6_u8; 16]);
        let expected = LocalServiceResponse::success(request_id, b"settled".to_vec()).unwrap();
        let response = super::await_operation_outcome(async {
            tokio::time::sleep(super::OPERATION_RECONCILIATION_THRESHOLD + Duration::from_secs(1))
                .await;
            expected.clone()
        })
        .await;
        assert_eq!(response, expected);
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
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
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
        let status = request(&mut first, 21, "service.status", b"{}").await;
        let LocalServiceResponse::Success { payload, .. } = status else {
            panic!("service status request failed");
        };
        let status: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(status["authorizationProvider"], "AccountTrusted");
        assert_eq!(status["authorizationEvidence"][0], "account_trusted");
        assert_eq!(status["activeGrants"], 2);
        assert_eq!(status["grantLimit"], super::MAX_SESSION_GRANTS);
        assert_eq!(status["grantLimitPerIssuer"], super::MAX_GRANTS_PER_ISSUER);
        assert_eq!(
            status["grantLimitPerProfile"],
            super::MAX_GRANTS_PER_PROFILE
        );
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
    async fn a_reconnected_claim_requires_a_fresh_request_id() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut first = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-claim-retry", 4) => stream,
        };
        let claim_payload = br#"{"maxEvents":1,"waitMilliseconds":0}"#;
        let initial = ledger_request(11, "delivery.claim", claim_payload.to_vec());
        write_request(&mut first, &initial).await.unwrap();
        wait_for_recorded_outcome_count(&fixture.root, "session-claim-retry", 1).await;
        drop(first);

        let mut reconnected = fixture.connect("session-claim-retry", 4).await;
        assert!(matches!(
            request(&mut reconnected, 11, "delivery.claim", claim_payload).await,
            LocalServiceResponse::Failure {
                code: LocalServiceErrorCode::Conflict,
                ..
            }
        ));

        let fresh_payload = tokio::time::timeout(TEST_REQUEST_DEADLINE, async {
            for seed in 12..=32 {
                match request(&mut reconnected, seed, "delivery.claim", claim_payload).await {
                    LocalServiceResponse::Success { payload, .. } => return payload,
                    LocalServiceResponse::Failure {
                        code: LocalServiceErrorCode::ProfileUnavailable,
                        ..
                    } => tokio::task::yield_now().await,
                    response => panic!("fresh claim returned an unexpected response: {response:?}"),
                }
            }
            panic!("replacement connection did not acquire the delivery lease");
        })
        .await
        .expect("replacement delivery claim exceeded the test deadline");
        let fresh: serde_json::Value = serde_json::from_slice(&fresh_payload).unwrap();
        assert!(fresh["events"].as_array().unwrap().is_empty());

        drop(reconnected);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_retried_request_id_returns_one_recorded_outcome() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
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
        let initial = ledger_request(9, "create_conversation", b"{}".to_vec());
        write_request(&mut first, &initial).await.unwrap();
        wait_for_recorded_outcome_count(&fixture.root, "session-retry", 1).await;
        drop(first);

        let mut reconnected = fixture.connect("session-retry", 3).await;
        let retried = request(&mut reconnected, 9, "create_conversation", b"{}").await;
        assert!(matches!(retried, LocalServiceResponse::Success { .. }));
        let conversations = request(&mut reconnected, 10, "list_conversations", b"{}").await;
        let LocalServiceResponse::Success { payload, .. } = conversations else {
            panic!("conversation listing failed");
        };
        let conversations: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            conversations["conversation_ids"].as_array().unwrap().len(),
            1
        );

        drop(reconnected);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn outcome_read_failure_discards_admission_without_wedging_retry() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut client = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-storage-failure", 25) => stream,
        };
        crate::persistence::inject_local_request_outcome_read_failures(
            "session-storage-failure",
            2,
        );

        for _ in 0..2 {
            assert!(matches!(
                request(&mut client, 25, "get_identity", b"{}").await,
                LocalServiceResponse::Failure {
                    code: LocalServiceErrorCode::ProfileUnavailable,
                    ..
                }
            ));
        }

        drop(client);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn outcome_write_failure_returns_nonterminal_and_exact_retry_recovers() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut client = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-write-failure", 26) => stream,
        };
        crate::persistence::inject_local_request_outcome_write_failures(
            "session-write-failure",
            usize::from(super::OUTCOME_PERSIST_ATTEMPTS),
        );

        assert!(matches!(
            request(&mut client, 26, "get_identity", b"{}").await,
            LocalServiceResponse::Failure {
                code: LocalServiceErrorCode::ReconciliationPending,
                ..
            }
        ));
        assert!(matches!(
            request(&mut client, 26, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        drop(client);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authenticated_cancellation_survives_a_replacement_grant_race() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut control = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the control client connected: {result:?}")
            }
            stream = fixture.connect("session-cancel-race", 15) => stream,
        };
        let cancellation = request(
            &mut control,
            15,
            "request.cancel",
            br#"{"requestId":"10101010101010101010101010101010","reason":"deadline"}"#,
        )
        .await;
        let LocalServiceResponse::Success { payload, .. } = cancellation else {
            panic!("cancellation request failed");
        };
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["state"], "cancellation_requested");

        let mut replacement = fixture.connect("session-cancel-race", 16).await;
        assert!(matches!(
            request(&mut replacement, 16, "get_identity", b"{}").await,
            LocalServiceResponse::Failure {
                code: LocalServiceErrorCode::DeadlineExceeded,
                ..
            }
        ));

        drop((control, replacement));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_durable_grant_survives_service_restart_and_reconnect() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut issuer = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the issuer connected: {result:?}")
            }
            stream = fixture.connect_issuer(31) => stream,
        };
        let grant = issue_grant(&fixture, &mut issuer, 31, "session-durable")
            .await
            .unwrap();
        let mut session = fixture.connect_grant(grant.clone(), 32).await;
        assert!(matches!(
            request(&mut session, 31, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        drop((issuer, session));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("first shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();

        let reopened = LiveAuthorizationRuntime::open(
            &fixture.installation_path,
            fixture.installation_fingerprint,
        )
        .await
        .unwrap();
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut restarted = tokio::spawn(run_shared_local_service_until(
            fixture.config_with(reopened),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut reconnected = tokio::select! {
            result = &mut restarted => {
                panic!("restarted service exited before reconnect: {result:?}")
            }
            stream = fixture.connect_grant(grant, 33) => stream,
        };
        assert!(matches!(
            request(&mut reconnected, 32, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        drop(reconnected);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, restarted)
            .await
            .expect("restarted shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_lost_grant_response_replays_the_same_durable_grant_after_restart() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut issuer = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the issuer connected: {result:?}")
            }
            stream = fixture.connect_issuer(34) => stream,
        };
        let payload = serde_json::to_vec(&serde_json::json!({
            "profile": "session-issuance-replay",
            "sessionPublicKey": crate::mcp::encode_hex(
                fixture.client_identity.public_key().as_bytes()
            ),
            "harness": "copilot"
        }))
        .unwrap();
        write_request(
            &mut issuer,
            &LocalServiceRequest::new(
                RequestId::from_bytes([34; 16]),
                OperationName::parse("authorization.grant.issue").unwrap(),
                payload.clone(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        fixture
            .wait_for_generation(AuthorizationGeneration::new(2).unwrap())
            .await;
        drop(issuer);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("first shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();

        let reopened = LiveAuthorizationRuntime::open(
            &fixture.installation_path,
            fixture.installation_fingerprint,
        )
        .await
        .unwrap();
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut restarted = tokio::spawn(run_shared_local_service_until(
            fixture.config_with(reopened),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut retrying_issuer = tokio::select! {
            result = &mut restarted => {
                panic!("restarted service exited before issuer reconnect: {result:?}")
            }
            stream = fixture.connect_issuer(34) => stream,
        };
        let replayed = issue_grant(
            &fixture,
            &mut retrying_issuer,
            34,
            "session-issuance-replay",
        )
        .await
        .unwrap();
        let installation_path = fixture.installation_path.clone();
        let fingerprint = fixture.installation_fingerprint;
        let active_grants = tokio::task::spawn_blocking(move || {
            LocalAuthorizationStore::open(installation_path, fingerprint, None)
                .unwrap()
                .load_snapshot(SystemUnixClock.now_unix_milliseconds(), None)
                .unwrap()
                .active_grants()
                .to_vec()
        })
        .await
        .unwrap();
        assert_eq!(active_grants, vec![replayed]);

        drop(retrying_issuer);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, restarted)
            .await
            .expect("restarted shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exact_revocation_closes_only_matching_active_connections() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut revoked = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-revocation-exact", 8) => stream,
        };
        let mut retained = fixture.connect("session-revocation-exact", 9).await;
        assert!(matches!(
            request(&mut revoked, 8, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));
        assert!(matches!(
            request(&mut retained, 9, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        fixture
            .mutate_authorization(move |store, now| {
                store.revoke_grant(SessionGrantId::from_bytes([8; 16]), now)
            })
            .await;
        let closed =
            tokio::time::timeout(AUTHORIZATION_OBSERVATION_BOUND, read_response(&mut revoked))
                .await
                .expect("revoked connection was not closed within the authorization deadline");
        assert!(closed.is_err());
        assert!(
            fixture
                .try_connect_grant(fixture.grant("session-revocation-exact", 8), 10)
                .await
                .is_err()
        );
        assert!(matches!(
            request(&mut retained, 11, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        drop((revoked, retained));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn profile_suspension_closes_all_matching_grants_and_blocks_issuance() {
        let fixture = Fixture::new().await;
        let (open_started_tx, open_started_rx) = mpsc::sync_channel(1);
        let (open_release_tx, open_release_rx) = mpsc::channel();
        let profile_source = Arc::new(BlockingProfileSource {
            inner: fixture.root.settings(),
            started: open_started_tx,
            release: Mutex::new(open_release_rx),
        });
        let config =
            fixture.config_with_profile_source(Arc::clone(&fixture.authorization), profile_source);
        let mut release = ProfileOpenRelease::new(open_release_tx);
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(config, async move {
            let _ = stop_rx.await;
        }));
        let mut first = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the first session connected: {result:?}")
            }
            stream = fixture.connect("session-suspended", 41) => stream,
        };
        let mut second = fixture.connect("session-suspended", 42).await;
        let mut issuer = fixture.connect_issuer(43).await;
        tokio::task::spawn_blocking(move || open_started_rx.recv_timeout(TEST_STARTUP_DEADLINE))
            .await
            .unwrap()
            .expect("profile open did not reach the configured barrier");

        fixture
            .mutate_authorization(|store, now| {
                store.suspend_profile(&ServiceProfileId::parse("session-suspended").unwrap(), now)
            })
            .await;

        let (first_closed, second_closed) = tokio::join!(
            tokio::time::timeout(AUTHORIZATION_OBSERVATION_BOUND, read_response(&mut first)),
            tokio::time::timeout(AUTHORIZATION_OBSERVATION_BOUND, read_response(&mut second)),
        );
        assert!(first_closed.unwrap().is_err());
        assert!(second_closed.unwrap().is_err());
        release.release();
        assert_eq!(
            issue_grant(&fixture, &mut issuer, 43, "session-suspended").await,
            Err(LocalServiceErrorCode::ProfileSuspended)
        );

        drop((first, second, issuer));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn disabled_issuer_denies_new_grants_and_applies_retain_then_revoke() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut issuer = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the issuer connected: {result:?}")
            }
            stream = fixture.connect_issuer(51) => stream,
        };
        let grant = issue_grant(&fixture, &mut issuer, 51, "session-disabled")
            .await
            .unwrap();
        let mut session = fixture.connect_grant(grant, 52).await;

        let issuer_key_id = fixture.adapter_key_id;
        let issuer_key_version = fixture.adapter_key_version;
        fixture
            .mutate_authorization(move |store, now| {
                store.set_issuer_state(
                    issuer_key_id,
                    issuer_key_version,
                    IssuerAvailability::Disabled,
                    ExistingGrantDisposition::RetainUntilExpiry,
                    now,
                )
            })
            .await;
        assert_eq!(
            issue_grant(&fixture, &mut issuer, 52, "session-disabled-new").await,
            Err(LocalServiceErrorCode::IssuerDisabled)
        );
        assert!(matches!(
            request(&mut session, 53, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));

        let issuer_key_id = fixture.adapter_key_id;
        let issuer_key_version = fixture.adapter_key_version;
        fixture
            .mutate_authorization(move |store, now| {
                store.set_issuer_state(
                    issuer_key_id,
                    issuer_key_version,
                    IssuerAvailability::Disabled,
                    ExistingGrantDisposition::Revoke,
                    now,
                )
            })
            .await;
        let closed =
            tokio::time::timeout(AUTHORIZATION_OBSERVATION_BOUND, read_response(&mut session))
                .await
                .expect("revoke-on-disable connection was not closed");
        assert!(closed.is_err());
        let mut disabled_reconnect = fixture.connect_issuer(54).await;
        assert_eq!(
            issue_grant(
                &fixture,
                &mut disabled_reconnect,
                54,
                "session-disabled-new",
            )
            .await,
            Err(LocalServiceErrorCode::IssuerDisabled)
        );

        drop((issuer, disabled_reconnect, session));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn policy_replacement_invalidates_only_unsatisfied_grants() {
        let account =
            AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted]).unwrap();
        let presence =
            AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::UserPresence]).unwrap();
        let initial = AuthorizationPolicy::new(
            AuthorizationPolicyVersion::new(1).unwrap(),
            vec![account, presence],
        )
        .unwrap();
        let fixture = Fixture::new_with_policy(initial).await;
        let account_grant = fixture.grant_with_evidence(
            "session-policy",
            61,
            AuthorizationEvidenceKind::AccountTrusted,
            1,
        );
        let presence_grant = fixture.grant_with_evidence(
            "session-policy",
            62,
            AuthorizationEvidenceKind::UserPresence,
            1,
        );
        fixture.persist_grant(account_grant.clone()).await;
        fixture.persist_grant(presence_grant.clone()).await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut account_session = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the policy session connected: {result:?}")
            }
            stream = fixture.connect_grant(account_grant, 61) => stream,
        };
        let mut presence_session = fixture.connect_grant(presence_grant, 62).await;
        let mut issuer = fixture.connect_issuer(63).await;
        let replacement =
            AuthorizationPolicy::new(AuthorizationPolicyVersion::new(2).unwrap(), vec![presence])
                .unwrap();
        fixture
            .mutate_authorization(move |store, now| store.replace_policy(&replacement, now))
            .await;

        let closed = tokio::time::timeout(
            AUTHORIZATION_OBSERVATION_BOUND,
            read_response(&mut account_session),
        )
        .await
        .expect("policy-invalid connection was not closed");
        assert!(closed.is_err());
        assert!(matches!(
            request(&mut presence_session, 63, "get_identity", b"{}").await,
            LocalServiceResponse::Success { .. }
        ));
        assert_eq!(
            issue_grant(&fixture, &mut issuer, 64, "session-policy-new").await,
            Err(LocalServiceErrorCode::RequiredEvidenceUnavailable)
        );

        drop((account_session, presence_session, issuer));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn grant_retirement_persists_and_prevents_reconnect() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut issuer = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the issuer connected: {result:?}")
            }
            stream = fixture.connect_issuer(71) => stream,
        };
        let grant = issue_grant(&fixture, &mut issuer, 71, "session-retired")
            .await
            .unwrap();
        let mut session = fixture.connect_grant(grant.clone(), 72).await;
        let retirement = request(&mut session, 72, "authorization.grant.retire", b"{}").await;
        let LocalServiceResponse::Success { payload, .. } = retirement else {
            panic!("grant retirement failed");
        };
        let result: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(result["retired"], true);
        assert!(fixture.try_connect_grant(grant, 73).await.is_err());

        drop((issuer, session));
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reload_failure_stops_the_service_and_closes_clients() {
        let fixture = Fixture::new().await;
        let (_hold_shutdown, stop_rx) = oneshot::channel::<()>();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut client = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the client connected: {result:?}")
            }
            stream = fixture.connect("session-reload-failure", 81) => stream,
        };
        fixture.authorization.fail_next_reload_for_test();
        fixture.authorization.request_reload();

        let result = tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, &mut service)
            .await
            .expect("authorization reload failure did not stop the service")
            .unwrap();
        let error = result.expect_err("authorization reload failure returned success");
        assert!(
            error
                .to_string()
                .contains("local authorization storage is unavailable")
        );
        assert!(
            tokio::time::timeout(TEST_REQUEST_DEADLINE, read_response(&mut client))
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn long_delivery_claim_observes_live_revocation() {
        let fixture = Fixture::new().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut service = tokio::spawn(run_shared_local_service_until(
            fixture.config(),
            async move {
                let _ = stop_rx.await;
            },
        ));
        let mut client = tokio::select! {
            result = &mut service => {
                panic!("shared service exited before the delivery client connected: {result:?}")
            }
            stream = fixture.connect("session-long-claim", 91) => stream,
        };
        write_request(
            &mut client,
            &LocalServiceRequest::new(
                RequestId::from_bytes([91; 16]),
                OperationName::parse("delivery.claim").unwrap(),
                br#"{"maxEvents":1,"waitMilliseconds":30000}"#.to_vec(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        wait_for_active_delivery(&fixture.root, "session-long-claim").await;

        fixture
            .mutate_authorization(move |store, now| {
                store.revoke_grant(SessionGrantId::from_bytes([91; 16]), now)
            })
            .await;
        assert!(
            tokio::time::timeout(AUTHORIZATION_OBSERVATION_BOUND, read_response(&mut client))
                .await
                .expect("long delivery claim did not observe revocation")
                .is_err()
        );

        drop(client);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(TEST_SHUTDOWN_DEADLINE, service)
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap()
            .unwrap();
    }
}
