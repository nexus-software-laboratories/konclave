use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

#[cfg(test)]
use std::sync::{Condvar, Mutex as StdMutex};

use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalAuthorizationStore::{
    AuthorizationGeneration, AuthorizationIssuerRecord, AuthorizationMutation,
    AuthorizationSnapshot, GrantIssuanceKey, InstallationFingerprint, IssuerAvailability,
    LocalAuthorizationStore, LocalAuthorizationStoreError, MutationEffect,
    UserPresenceCredentialRecord,
};
use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    AuthorizationPolicyVersion, ClientInstanceId, HarnessKind,
    InMemorySessionAuthorizationRegistry, InstalledIssuerRegistration, IssuerKeyId,
    IssuerKeyVersion, LocalServiceErrorCode, LocalServiceTransportError, RequestId,
    ServiceProfileId, SessionAuthorizationRegistry, SessionCapabilities, SessionGrant,
    SessionGrantCapacity, SessionGrantClaims, SessionGrantId,
};
use KonclaveUserPresence::NativeWebAuthnCredential;
use thiserror::Error;
use tokio::sync::{Mutex, Notify, watch};

use crate::authorization_reload::{
    AuthorizationReloadEvent, AuthorizationReloadState, AuthorizationReloadTransition,
    resolve_authorization_reload_transition,
};
use crate::clock::{SystemUnixClock, UnixClock};

pub(crate) const AUTHORIZATION_RELOAD_INTERVAL: Duration = Duration::from_millis(500);
const AUTHORIZATION_RELOAD_DEADLINE: Duration = Duration::from_millis(500);
const AUTHORIZATION_RELOAD_COMPLETION_DEADLINE: Duration = Duration::from_secs(30);
#[cfg(test)]
pub(crate) const AUTHORIZATION_OBSERVATION_BOUND: Duration = Duration::from_secs(1);
const GRANT_IDENTIFIER_ATTEMPTS: usize = 4;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum AuthorizationRuntimeError {
    #[error("{0}")]
    Store(LocalAuthorizationStoreError),
    #[error("local authorization projection is invalid")]
    InvalidProjection,
    #[error("local authorization observation exceeded its deadline")]
    ObservationDeadlineExceeded,
    #[error("local authorization blocking operation failed")]
    BlockingOperationFailed,
    #[error("local authorization runtime stopped unexpectedly")]
    UnexpectedStop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationRuntimeStatus {
    Active(AuthorizationGeneration),
    Failed(AuthorizationRuntimeError),
}

struct AuthorizationProjection {
    generation: AuthorizationGeneration,
    policy: AuthorizationPolicy,
    issuers: Vec<AuthorizationIssuerRecord>,
    suspended_profiles: Vec<ServiceProfileId>,
    user_presence_credential: Option<UserPresenceCredentialRecord>,
    failure: Option<AuthorizationRuntimeError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GrantIssuanceContext {
    generation: AuthorizationGeneration,
    policy_version: AuthorizationPolicyVersion,
}

pub(crate) struct AccountTrustedGrantRequest {
    pub(crate) issuer_key_id: IssuerKeyId,
    pub(crate) issuer_key_version: IssuerKeyVersion,
    pub(crate) issuer_client_instance: ClientInstanceId,
    pub(crate) request_id: RequestId,
    pub(crate) profile: ServiceProfileId,
    pub(crate) session_public_key: Ed25519PublicKey,
    pub(crate) harness: HarnessKind,
    pub(crate) issued_at_unix_milliseconds: u64,
    pub(crate) expires_at_unix_milliseconds: u64,
}

pub(crate) struct UserPresenceGrantRequest {
    pub(crate) issuer_key_id: IssuerKeyId,
    pub(crate) issuer_key_version: IssuerKeyVersion,
    pub(crate) request_key: GrantIssuanceKey,
    pub(crate) grant_id: SessionGrantId,
    pub(crate) profile: ServiceProfileId,
    pub(crate) session_public_key: Ed25519PublicKey,
    pub(crate) harness: HarnessKind,
    pub(crate) policy_version: AuthorizationPolicyVersion,
    pub(crate) evidence: AuthorizationEvidenceSet,
    pub(crate) capabilities: SessionCapabilities,
    pub(crate) expected_credential: UserPresenceCredentialRecord,
    pub(crate) updated_credential: NativeWebAuthnCredential,
    pub(crate) issued_at_unix_milliseconds: u64,
    pub(crate) expires_at_unix_milliseconds: u64,
}

struct GrantRequest {
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    request_key: GrantIssuanceKey,
    grant_id: Option<SessionGrantId>,
    profile: ServiceProfileId,
    session_public_key: Ed25519PublicKey,
    harness: HarnessKind,
    evidence: AuthorizationEvidenceSet,
    policy_version: Option<AuthorizationPolicyVersion>,
    capabilities: SessionCapabilities,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

#[cfg(test)]
pub(crate) struct AuthorizationReloadTestGate {
    entered: Notify,
    released: StdMutex<bool>,
    release: Condvar,
}

#[cfg(test)]
impl AuthorizationReloadTestGate {
    fn new() -> Self {
        Self {
            entered: Notify::new(),
            released: StdMutex::new(false),
            release: Condvar::new(),
        }
    }

    fn block(&self) {
        self.entered.notify_one();
        let mut released = self.released.lock().unwrap_or_else(PoisonError::into_inner);
        while !*released {
            released = self
                .release
                .wait(released)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    pub(crate) async fn wait_until_entered(&self) {
        self.entered.notified().await;
    }

    pub(crate) fn release(&self) {
        *self.released.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.release.notify_all();
    }
}

pub(crate) struct LiveAuthorizationRuntime {
    store: Arc<LocalAuthorizationStore>,
    registry: InMemorySessionAuthorizationRegistry,
    projection: RwLock<AuthorizationProjection>,
    installation_fingerprint: InstallationFingerprint,
    operations: Mutex<()>,
    status: watch::Sender<AuthorizationRuntimeStatus>,
    reload_requested: Notify,
    #[cfg(test)]
    fail_next_reload: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    block_next_reload: StdMutex<Option<Arc<AuthorizationReloadTestGate>>>,
}

impl LiveAuthorizationRuntime {
    pub(crate) async fn open(
        installation_path: &Path,
        installation_fingerprint: InstallationFingerprint,
    ) -> Result<Arc<Self>, AuthorizationRuntimeError> {
        let installation_path = PathBuf::from(installation_path);
        let now_unix_milliseconds = SystemUnixClock.now_unix_milliseconds();
        let opened = tokio::task::spawn_blocking(move || {
            let store =
                LocalAuthorizationStore::open(installation_path, installation_fingerprint, None)?;
            let snapshot = store.load_snapshot(now_unix_milliseconds, None)?;
            Ok::<_, LocalAuthorizationStoreError>((store, snapshot))
        })
        .await
        .map_err(|_| AuthorizationRuntimeError::BlockingOperationFailed)?
        .map_err(AuthorizationRuntimeError::Store)?;
        Self::from_snapshot(opened.0, opened.1, now_unix_milliseconds)
    }

    fn from_snapshot(
        store: LocalAuthorizationStore,
        snapshot: AuthorizationSnapshot,
        now_unix_milliseconds: u64,
    ) -> Result<Arc<Self>, AuthorizationRuntimeError> {
        let installation_fingerprint = store.installation_fingerprint();
        let registry = InMemorySessionAuthorizationRegistry::new();
        replace_registry(&registry, &snapshot, now_unix_milliseconds)?;
        let generation = snapshot.generation();
        let (status, _) = watch::channel(AuthorizationRuntimeStatus::Active(generation));
        Ok(Arc::new(Self {
            store: Arc::new(store),
            registry,
            projection: RwLock::new(AuthorizationProjection {
                generation,
                policy: snapshot.policy().clone(),
                issuers: snapshot.issuers().to_vec(),
                suspended_profiles: snapshot.suspended_profiles().to_vec(),
                user_presence_credential: snapshot.user_presence_credential().cloned(),
                failure: None,
            }),
            installation_fingerprint,
            operations: Mutex::new(()),
            status,
            reload_requested: Notify::new(),
            #[cfg(test)]
            fail_next_reload: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            block_next_reload: StdMutex::new(None),
        }))
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<AuthorizationRuntimeStatus> {
        self.status.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn request_reload(&self) {
        self.reload_requested.notify_one();
    }

    pub(crate) async fn run_reload_loop(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), AuthorizationRuntimeError> {
        let start = tokio::time::Instant::now() + AUTHORIZATION_RELOAD_INTERVAL;
        let mut interval = tokio::time::interval_at(start, AUTHORIZATION_RELOAD_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let reload = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return match resolve_authorization_reload_transition(
                            self.reload_state(),
                            AuthorizationReloadEvent::Shutdown,
                        ) {
                            AuthorizationReloadTransition::StopCleanly => Ok(()),
                            AuthorizationReloadTransition::Publish { .. }
                            | AuthorizationReloadTransition::FailClosed { .. }
                            | AuthorizationReloadTransition::StopService => unreachable!(),
                        };
                    }
                    false
                }
                () = self.reload_requested.notified() => {
                    true
                }
                _ = interval.tick() => {
                    true
                }
            };
            if !reload {
                continue;
            }
            if let Some(error) = self.current_failure()
                && matches!(
                    resolve_authorization_reload_transition(
                        self.reload_state(),
                        authorization_reload_event(error),
                    ),
                    AuthorizationReloadTransition::StopService
                )
            {
                return Err(error);
            }
            if let Err(error) = self.reload_once().await {
                match resolve_authorization_reload_transition(
                    self.reload_state(),
                    authorization_reload_event(error),
                ) {
                    AuthorizationReloadTransition::FailClosed { .. } => {
                        self.fail_closed(error);
                    }
                    AuthorizationReloadTransition::StopService => return Err(error),
                    AuthorizationReloadTransition::Publish { .. }
                    | AuthorizationReloadTransition::StopCleanly => unreachable!(),
                }
            }
        }
    }

    pub(crate) fn issuer_is_known(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        issuer_public_key: Ed25519PublicKey,
        harness: HarnessKind,
    ) -> bool {
        self.active_issuer(issuer_key_id, issuer_key_version)
            .is_some_and(|registration| {
                registration.public_key() == issuer_public_key
                    && (registration.harness() == harness
                        || registration.harness() == HarnessKind::Generic)
            })
    }

    pub(crate) fn grant_is_active(&self, grant: &SessionGrant) -> bool {
        self.active_grant(grant.grant_id(), SystemUnixClock.now_unix_milliseconds())
            .is_some_and(|active| &active == grant)
    }

    pub(crate) fn status_snapshot(
        &self,
        issuer_key_id: IssuerKeyId,
        profile: &ServiceProfileId,
    ) -> Option<(
        AuthorizationGeneration,
        SessionGrantCapacity,
        AuthorizationPolicy,
    )> {
        let projection = read(&self.projection);
        projection.failure.is_none().then(|| {
            (
                projection.generation,
                self.registry.grant_capacity(
                    issuer_key_id,
                    profile,
                    SystemUnixClock.now_unix_milliseconds(),
                ),
                projection.policy.clone(),
            )
        })
    }

    pub(crate) async fn issue_account_trusted_grant(
        &self,
        request: AccountTrustedGrantRequest,
    ) -> Result<SessionGrant, LocalServiceErrorCode> {
        let _operation = self.operations.lock().await;
        let AccountTrustedGrantRequest {
            issuer_key_id,
            issuer_key_version,
            issuer_client_instance,
            request_id,
            profile,
            session_public_key,
            harness,
            issued_at_unix_milliseconds,
            expires_at_unix_milliseconds,
        } = request;
        let evidence = AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
            .map_err(|_| LocalServiceErrorCode::Internal)?;
        self.issue_grant_locked(GrantRequest {
            issuer_key_id,
            issuer_key_version,
            request_key: GrantIssuanceKey::new(issuer_client_instance, request_id),
            grant_id: None,
            profile,
            session_public_key,
            harness,
            evidence,
            policy_version: None,
            capabilities: SessionCapabilities::ALL,
            issued_at_unix_milliseconds,
            expires_at_unix_milliseconds,
        })
        .await
    }

    pub(crate) fn user_presence_context(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        profile: &ServiceProfileId,
        harness: HarnessKind,
    ) -> Result<
        (
            InstallationFingerprint,
            AuthorizationPolicyVersion,
            AuthorizationEvidenceSet,
            UserPresenceCredentialRecord,
        ),
        LocalServiceErrorCode,
    > {
        let presence = AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::UserPresence])
            .map_err(|_| LocalServiceErrorCode::Internal)?;
        let (context, evidence) = match self.issuance_context(
            issuer_key_id,
            issuer_key_version,
            profile,
            harness,
            presence,
        ) {
            Ok(context) => (context, presence),
            Err(LocalServiceErrorCode::RequiredEvidenceUnavailable) => {
                let combined = AuthorizationEvidenceSet::new([
                    AuthorizationEvidenceKind::AccountTrusted,
                    AuthorizationEvidenceKind::UserPresence,
                ])
                .map_err(|_| LocalServiceErrorCode::Internal)?;
                (
                    self.issuance_context(
                        issuer_key_id,
                        issuer_key_version,
                        profile,
                        harness,
                        combined,
                    )?,
                    combined,
                )
            }
            Err(error) => return Err(error),
        };
        let projection = read(&self.projection);
        let credential = projection
            .user_presence_credential
            .clone()
            .ok_or(LocalServiceErrorCode::RequiredEvidenceUnavailable)?;
        Ok((
            self.installation_fingerprint,
            context.policy_version,
            evidence,
            credential,
        ))
    }

    pub(crate) async fn issue_user_presence_grant(
        &self,
        request: UserPresenceGrantRequest,
    ) -> Result<SessionGrant, LocalServiceErrorCode> {
        let _operation = self.operations.lock().await;
        let UserPresenceGrantRequest {
            issuer_key_id,
            issuer_key_version,
            request_key,
            grant_id,
            profile,
            session_public_key,
            harness,
            policy_version,
            evidence,
            capabilities,
            expected_credential,
            updated_credential,
            issued_at_unix_milliseconds,
            expires_at_unix_milliseconds,
        } = request;
        let updated_record = UserPresenceCredentialRecord::from_document(
            updated_credential
                .to_bytes()
                .map_err(|_| LocalServiceErrorCode::Internal)?,
        )
        .map_err(|_| LocalServiceErrorCode::Internal)?;
        let candidate = SessionGrant::new(SessionGrantClaims {
            grant_id,
            issuer_key_id,
            issuer_key_version,
            profile: profile.clone(),
            session_public_key,
            harness,
            evidence,
            policy_version,
            issued_at_unix_milliseconds,
            expires_at_unix_milliseconds,
            capabilities,
        })
        .map_err(|_| LocalServiceErrorCode::Internal)?;
        let store = Arc::clone(&self.store);
        let mutation = tokio::task::spawn_blocking(move || {
            store.update_user_presence_credential_for_grant(
                &expected_credential,
                &updated_record,
                &candidate,
                issued_at_unix_milliseconds,
            )
        })
        .await
        .map_err(|_| {
            self.fail_closed(AuthorizationRuntimeError::BlockingOperationFailed);
            LocalServiceErrorCode::Internal
        })?
        .map_err(|error| self.map_mutation_error(error))?;
        self.refresh_after_mutation(mutation, issued_at_unix_milliseconds)
            .await
            .map_err(|_| LocalServiceErrorCode::Internal)?;
        self.issue_grant_locked(GrantRequest {
            issuer_key_id,
            issuer_key_version,
            request_key,
            grant_id: Some(grant_id),
            profile,
            session_public_key,
            harness,
            evidence,
            policy_version: Some(policy_version),
            capabilities,
            issued_at_unix_milliseconds,
            expires_at_unix_milliseconds,
        })
        .await
    }

    pub(crate) async fn recover_user_presence_grant(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        request_key: GrantIssuanceKey,
        now_unix_milliseconds: u64,
    ) -> Result<Option<SessionGrant>, LocalServiceErrorCode> {
        let _operation = self.operations.lock().await;
        let store = Arc::clone(&self.store);
        let grant = tokio::task::spawn_blocking(move || {
            store.active_grant_for_request(
                issuer_key_id,
                issuer_key_version,
                request_key,
                now_unix_milliseconds,
            )
        })
        .await
        .map_err(|_| {
            self.fail_closed(AuthorizationRuntimeError::BlockingOperationFailed);
            LocalServiceErrorCode::Internal
        })?
        .map_err(|error| self.map_mutation_error(error))?;
        let high_water = self
            .current_generation()
            .ok_or(LocalServiceErrorCode::Internal)?;
        self.refresh_locked(now_unix_milliseconds, high_water)
            .await
            .map_err(|_| LocalServiceErrorCode::Internal)?;
        Ok(grant)
    }

    async fn issue_grant_locked(
        &self,
        request: GrantRequest,
    ) -> Result<SessionGrant, LocalServiceErrorCode> {
        let GrantRequest {
            issuer_key_id,
            issuer_key_version,
            request_key,
            grant_id,
            profile,
            session_public_key,
            harness,
            evidence,
            policy_version,
            capabilities,
            issued_at_unix_milliseconds,
            expires_at_unix_milliseconds,
        } = request;
        let mut context = self.issuance_context(
            issuer_key_id,
            issuer_key_version,
            &profile,
            harness,
            evidence,
        )?;
        if policy_version.is_some_and(|expected| expected != context.policy_version) {
            return Err(LocalServiceErrorCode::Conflict);
        }
        let attempts = if grant_id.is_some() {
            1
        } else {
            GRANT_IDENTIFIER_ATTEMPTS
        };
        for _ in 0..attempts {
            let grant_id = match grant_id {
                Some(grant_id) => grant_id,
                None => {
                    let mut identifier = [0_u8; 16];
                    KonclaveCryptographicCore::fill_random(&mut identifier)
                        .map_err(|_| LocalServiceErrorCode::Internal)?;
                    SessionGrantId::from_bytes(identifier)
                }
            };
            let grant = SessionGrant::new(SessionGrantClaims {
                grant_id,
                issuer_key_id,
                issuer_key_version,
                profile: profile.clone(),
                session_public_key,
                harness,
                evidence,
                policy_version: context.policy_version,
                issued_at_unix_milliseconds,
                expires_at_unix_milliseconds,
                capabilities,
            })
            .map_err(|_| LocalServiceErrorCode::Internal)?;
            let store = Arc::clone(&self.store);
            let candidate = grant.clone();
            let result = tokio::task::spawn_blocking(move || {
                store.issue_grant_for_request(request_key, &candidate, issued_at_unix_milliseconds)
            })
            .await
            .map_err(|_| {
                self.fail_closed(AuthorizationRuntimeError::BlockingOperationFailed);
                LocalServiceErrorCode::Internal
            })?;
            match result {
                Ok(issuance) => {
                    self.refresh_after_mutation(issuance.mutation(), issued_at_unix_milliseconds)
                        .await
                        .map_err(|_| LocalServiceErrorCode::Internal)?;
                    return Ok(issuance.into_grant());
                }
                Err(LocalAuthorizationStoreError::Conflict) => {
                    let prior_generation = context.generation;
                    self.refresh_locked(issued_at_unix_milliseconds, prior_generation)
                        .await
                        .map_err(|_| LocalServiceErrorCode::Internal)?;
                    context = self.issuance_context(
                        issuer_key_id,
                        issuer_key_version,
                        &profile,
                        harness,
                        evidence,
                    )?;
                    if policy_version.is_some_and(|expected| expected != context.policy_version) {
                        return Err(LocalServiceErrorCode::Conflict);
                    }
                }
                Err(error) => {
                    if should_refresh_after_mutation_error(error) {
                        let high_water = context.generation;
                        self.refresh_locked(issued_at_unix_milliseconds, high_water)
                            .await
                            .map_err(|_| LocalServiceErrorCode::Internal)?;
                    }
                    return Err(self.map_mutation_error(error));
                }
            }
        }
        Err(LocalServiceErrorCode::Conflict)
    }

    pub(crate) async fn retire_grant(
        &self,
        grant_id: SessionGrantId,
        now_unix_milliseconds: u64,
    ) -> Result<bool, LocalServiceErrorCode> {
        let _operation = self.operations.lock().await;
        let store = Arc::clone(&self.store);
        let result = tokio::task::spawn_blocking(move || {
            store.retire_grant(grant_id, now_unix_milliseconds)
        })
        .await
        .map_err(|_| {
            self.fail_closed(AuthorizationRuntimeError::BlockingOperationFailed);
            LocalServiceErrorCode::Internal
        })?;
        match result {
            Ok(mutation) => {
                self.refresh_after_mutation(mutation, now_unix_milliseconds)
                    .await
                    .map_err(|_| LocalServiceErrorCode::Internal)?;
                Ok(mutation.effect() == MutationEffect::Applied)
            }
            Err(LocalAuthorizationStoreError::NotFound) => {
                let high_water = self
                    .current_generation()
                    .ok_or(LocalServiceErrorCode::Internal)?;
                self.refresh_locked(now_unix_milliseconds, high_water)
                    .await
                    .map_err(|_| LocalServiceErrorCode::Internal)?;
                Ok(false)
            }
            Err(error) => Err(self.map_mutation_error(error)),
        }
    }

    async fn reload_once(&self) -> Result<(), AuthorizationRuntimeError> {
        #[cfg(test)]
        if self
            .fail_next_reload
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let error =
                AuthorizationRuntimeError::Store(LocalAuthorizationStoreError::StorageUnavailable);
            self.fail_closed(error);
            return Err(error);
        }
        let high_water = self.reload_generation();
        self.refresh_locked(SystemUnixClock.now_unix_milliseconds(), high_water)
            .await
    }

    async fn refresh_after_mutation(
        &self,
        mutation: AuthorizationMutation,
        now_unix_milliseconds: u64,
    ) -> Result<(), AuthorizationRuntimeError> {
        self.refresh_locked(now_unix_milliseconds, mutation.generation())
            .await
    }

    async fn refresh_locked(
        &self,
        now_unix_milliseconds: u64,
        high_water: AuthorizationGeneration,
    ) -> Result<(), AuthorizationRuntimeError> {
        let store = Arc::clone(&self.store);
        #[cfg(test)]
        let reload_gate = self
            .block_next_reload
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let mut snapshot_task = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(gate) = reload_gate {
                gate.block();
            }
            store.load_snapshot(now_unix_milliseconds, Some(high_water))
        });
        let snapshot =
            match tokio::time::timeout(AUTHORIZATION_RELOAD_DEADLINE, &mut snapshot_task).await {
                Ok(result) => result
                    .map_err(|_| AuthorizationRuntimeError::BlockingOperationFailed)?
                    .map_err(AuthorizationRuntimeError::Store),
                Err(_) => {
                    let error = AuthorizationRuntimeError::ObservationDeadlineExceeded;
                    self.fail_closed(error);
                    match tokio::time::timeout(
                        AUTHORIZATION_RELOAD_COMPLETION_DEADLINE,
                        &mut snapshot_task,
                    )
                    .await
                    {
                        Ok(Ok(_)) => return Err(error),
                        Ok(Err(_)) | Err(_) => {
                            let worker_error = AuthorizationRuntimeError::BlockingOperationFailed;
                            self.fail_closed(worker_error);
                            return Err(worker_error);
                        }
                    }
                }
            };
        match snapshot {
            Ok(snapshot) => self.publish(snapshot, now_unix_milliseconds),
            Err(error) => {
                self.fail_closed(error);
                Err(error)
            }
        }
    }

    fn publish(
        &self,
        snapshot: AuthorizationSnapshot,
        now_unix_milliseconds: u64,
    ) -> Result<(), AuthorizationRuntimeError> {
        if !matches!(
            resolve_authorization_reload_transition(
                self.reload_state(),
                AuthorizationReloadEvent::SnapshotVerified,
            ),
            AuthorizationReloadTransition::Publish {
                next: AuthorizationReloadState::Active
            }
        ) {
            unreachable!();
        }
        let mut projection = write(&self.projection);
        if snapshot.generation() < projection.generation {
            return Ok(());
        }
        if replace_registry(&self.registry, &snapshot, now_unix_milliseconds).is_err() {
            let error = AuthorizationRuntimeError::InvalidProjection;
            self.fail_closed_locked(&mut projection, error);
            return Err(error);
        }
        projection.generation = snapshot.generation();
        projection.policy = snapshot.policy().clone();
        projection.issuers = snapshot.issuers().to_vec();
        projection.suspended_profiles = snapshot.suspended_profiles().to_vec();
        projection.user_presence_credential = snapshot.user_presence_credential().cloned();
        projection.failure = None;
        let generation = projection.generation;
        drop(projection);
        self.status
            .send_replace(AuthorizationRuntimeStatus::Active(generation));
        Ok(())
    }

    fn issuance_context(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        profile: &ServiceProfileId,
        harness: HarnessKind,
        evidence: AuthorizationEvidenceSet,
    ) -> Result<GrantIssuanceContext, LocalServiceErrorCode> {
        let projection = read(&self.projection);
        if projection.failure.is_some() {
            return Err(LocalServiceErrorCode::Internal);
        }
        if projection
            .suspended_profiles
            .iter()
            .any(|candidate| candidate == profile)
        {
            return Err(LocalServiceErrorCode::ProfileSuspended);
        }
        let issuer = projection
            .issuers
            .iter()
            .find(|issuer| {
                issuer.issuer_key_id() == issuer_key_id
                    && issuer.issuer_key_version() == issuer_key_version
            })
            .ok_or(LocalServiceErrorCode::NotAuthorized)?;
        if issuer.availability() == IssuerAvailability::Disabled {
            return Err(LocalServiceErrorCode::IssuerDisabled);
        }
        if !issuer.registration().profiles().permits(profile)
            || (issuer.registration().harness() != harness
                && issuer.registration().harness() != HarnessKind::Generic)
        {
            return Err(LocalServiceErrorCode::NotAuthorized);
        }
        if !projection.policy.accepts(evidence) {
            return Err(LocalServiceErrorCode::RequiredEvidenceUnavailable);
        }
        Ok(GrantIssuanceContext {
            generation: projection.generation,
            policy_version: projection.policy.version(),
        })
    }

    fn current_generation(&self) -> Option<AuthorizationGeneration> {
        let projection = read(&self.projection);
        projection
            .failure
            .is_none()
            .then_some(projection.generation)
    }

    fn reload_generation(&self) -> AuthorizationGeneration {
        read(&self.projection).generation
    }

    fn reload_state(&self) -> AuthorizationReloadState {
        if self.current_failure().is_some() {
            AuthorizationReloadState::FailedClosed
        } else {
            AuthorizationReloadState::Active
        }
    }

    fn current_failure(&self) -> Option<AuthorizationRuntimeError> {
        read(&self.projection).failure
    }

    fn map_mutation_error(&self, error: LocalAuthorizationStoreError) -> LocalServiceErrorCode {
        match error {
            LocalAuthorizationStoreError::ProfileSuspended => {
                LocalServiceErrorCode::ProfileSuspended
            }
            LocalAuthorizationStoreError::IssuerDisabled => LocalServiceErrorCode::IssuerDisabled,
            LocalAuthorizationStoreError::RequiredEvidenceUnavailable => {
                LocalServiceErrorCode::RequiredEvidenceUnavailable
            }
            LocalAuthorizationStoreError::Capacity => LocalServiceErrorCode::Capacity,
            LocalAuthorizationStoreError::Conflict => LocalServiceErrorCode::Conflict,
            LocalAuthorizationStoreError::NotFound => LocalServiceErrorCode::NotAuthorized,
            LocalAuthorizationStoreError::InvalidInput => LocalServiceErrorCode::Internal,
            LocalAuthorizationStoreError::StorageUnavailable
            | LocalAuthorizationStoreError::InvalidStorage
            | LocalAuthorizationStoreError::CorruptStorage
            | LocalAuthorizationStoreError::UnsafeStorage
            | LocalAuthorizationStoreError::UnsupportedSchema
            | LocalAuthorizationStoreError::InstallationMismatch
            | LocalAuthorizationStoreError::GenerationRollback => {
                self.fail_closed(AuthorizationRuntimeError::Store(error));
                LocalServiceErrorCode::Internal
            }
        }
    }

    fn fail_closed(&self, error: AuthorizationRuntimeError) {
        let mut projection = write(&self.projection);
        self.fail_closed_locked(&mut projection, error);
    }

    fn fail_closed_locked(
        &self,
        projection: &mut AuthorizationProjection,
        error: AuthorizationRuntimeError,
    ) {
        if projection.failure == Some(error) {
            return;
        }
        projection.failure = Some(error);
        self.status
            .send_replace(AuthorizationRuntimeStatus::Failed(error));
    }

    #[cfg(test)]
    pub(crate) async fn persist_grant_for_test(
        &self,
        grant: SessionGrant,
        now_unix_milliseconds: u64,
    ) -> Result<(), AuthorizationRuntimeError> {
        let _operation = self.operations.lock().await;
        let store = Arc::clone(&self.store);
        let mutation =
            tokio::task::spawn_blocking(move || store.issue_grant(&grant, now_unix_milliseconds))
                .await
                .map_err(|_| AuthorizationRuntimeError::BlockingOperationFailed)?
                .map_err(AuthorizationRuntimeError::Store)?;
        self.refresh_after_mutation(mutation, now_unix_milliseconds)
            .await
    }

    #[cfg(test)]
    pub(crate) fn fail_next_reload_for_test(&self) {
        self.fail_next_reload
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn block_next_reload_for_test(&self) -> Arc<AuthorizationReloadTestGate> {
        let gate = Arc::new(AuthorizationReloadTestGate::new());
        *self
            .block_next_reload
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&gate));
        gate
    }
}

impl SessionAuthorizationRegistry for LiveAuthorizationRuntime {
    fn active_issuer(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
    ) -> Option<KonclaveLocalServiceTransport::IssuerRegistration> {
        let projection = read(&self.projection);
        if projection.failure.is_some() {
            return None;
        }
        self.registry
            .active_issuer(issuer_key_id, issuer_key_version)
    }

    fn active_grant(
        &self,
        grant_id: SessionGrantId,
        now_unix_milliseconds: u64,
    ) -> Option<SessionGrant> {
        let projection = read(&self.projection);
        if projection.failure.is_some() {
            return None;
        }
        self.registry.active_grant(grant_id, now_unix_milliseconds)
    }
}

fn replace_registry(
    registry: &InMemorySessionAuthorizationRegistry,
    snapshot: &AuthorizationSnapshot,
    now_unix_milliseconds: u64,
) -> Result<(), AuthorizationRuntimeError> {
    let issuers = snapshot
        .issuers()
        .iter()
        .map(|issuer| {
            InstalledIssuerRegistration::new(
                issuer.issuer_key_id(),
                issuer.issuer_key_version(),
                issuer.registration().clone(),
            )
        })
        .collect();
    registry
        .replace(
            issuers,
            snapshot.active_grants().to_vec(),
            now_unix_milliseconds,
        )
        .map_err(|_error: LocalServiceTransportError| AuthorizationRuntimeError::InvalidProjection)
}

const fn authorization_reload_event(error: AuthorizationRuntimeError) -> AuthorizationReloadEvent {
    match error {
        AuthorizationRuntimeError::Store(_)
        | AuthorizationRuntimeError::InvalidProjection
        | AuthorizationRuntimeError::ObservationDeadlineExceeded => {
            AuthorizationReloadEvent::ObservationFailed
        }
        AuthorizationRuntimeError::BlockingOperationFailed
        | AuthorizationRuntimeError::UnexpectedStop => AuthorizationReloadEvent::WorkerFailed,
    }
}

const fn should_refresh_after_mutation_error(error: LocalAuthorizationStoreError) -> bool {
    matches!(
        error,
        LocalAuthorizationStoreError::ProfileSuspended
            | LocalAuthorizationStoreError::IssuerDisabled
            | LocalAuthorizationStoreError::RequiredEvidenceUnavailable
            | LocalAuthorizationStoreError::Capacity
            | LocalAuthorizationStoreError::NotFound
    )
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use KonclaveDomainCore::Ed25519PublicKey;
    use KonclaveLocalAuthorizationStore::{
        LocalAuthorizationStore, LocalAuthorizationStoreError, authorization_store_path,
    };
    use KonclaveLocalServiceTransport::{
        AuthorizationPolicy, ClientInstanceId, HarnessKind, InstalledIssuerRegistration,
        IssuerKeyId, IssuerKeyVersion, IssuerRegistration, LOCAL_SERVICE_INSTALLATION_FILE,
        LocalServiceErrorCode, ProfileAuthorization, RequestId, ServiceProfileId,
    };
    use KonclaveSecretStorage::{
        create_or_verify_owner_protected_file, ensure_owner_protected_directory,
        open_or_create_owner_protected_file,
    };
    use rusqlite::Connection;
    use tokio::sync::watch;

    use super::{
        AUTHORIZATION_RELOAD_DEADLINE, AUTHORIZATION_RELOAD_INTERVAL, AccountTrustedGrantRequest,
        AuthorizationRuntimeError, AuthorizationRuntimeStatus, InstallationFingerprint,
        LiveAuthorizationRuntime, authorization_reload_event,
    };
    use crate::authorization_reload::AuthorizationReloadEvent;
    use crate::clock::{SystemUnixClock, UnixClock};

    fn issuer() -> InstalledIssuerRegistration {
        InstalledIssuerRegistration::new(
            IssuerKeyId::from_bytes([7; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            IssuerRegistration::new(
                Ed25519PublicKey::from_bytes([8; 32]),
                HarnessKind::Copilot,
                ProfileAuthorization::All,
            ),
        )
    }

    #[tokio::test]
    async fn startup_rejects_missing_empty_and_corrupt_authorization_state() {
        for (kind, expected) in [
            ("missing", LocalAuthorizationStoreError::StorageUnavailable),
            ("empty", LocalAuthorizationStoreError::InvalidStorage),
            ("corrupt", LocalAuthorizationStoreError::CorruptStorage),
        ] {
            let root = tempfile::tempdir().unwrap();
            let installation_path = root.path().join(kind).join(LOCAL_SERVICE_INSTALLATION_FILE);
            let setup_path = installation_path.clone();
            tokio::task::spawn_blocking(move || {
                ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
                create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
                if kind == "empty" {
                    drop(
                        open_or_create_owner_protected_file(
                            &authorization_store_path(&setup_path).unwrap(),
                        )
                        .unwrap(),
                    );
                } else if kind == "corrupt" {
                    let mut file = open_or_create_owner_protected_file(
                        &authorization_store_path(&setup_path).unwrap(),
                    )
                    .unwrap();
                    file.write_all(b"not a sqlite database").unwrap();
                    file.sync_all().unwrap();
                }
            })
            .await
            .unwrap();

            assert!(matches!(
                LiveAuthorizationRuntime::open(
                    &installation_path,
                    InstallationFingerprint::from_bytes([9; 32]),
                )
                .await,
                Err(AuthorizationRuntimeError::Store(error)) if error == expected
            ));
        }
    }

    #[tokio::test]
    async fn conflicting_issuer_request_reuse_returns_conflict() {
        let root = tempfile::tempdir().unwrap();
        let installation_path = root
            .path()
            .join("service")
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let fingerprint = InstallationFingerprint::from_bytes([11; 32]);
        let setup_path = installation_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
            drop(
                LocalAuthorizationStore::bootstrap(
                    &setup_path,
                    fingerprint,
                    &AuthorizationPolicy::account_trusted(),
                    &[issuer()],
                    1,
                )
                .unwrap(),
            );
            create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
        })
        .await
        .unwrap();
        let runtime = LiveAuthorizationRuntime::open(&installation_path, fingerprint)
            .await
            .unwrap();
        let now = SystemUnixClock.now_unix_milliseconds();
        let issuer_client_instance = ClientInstanceId::from_bytes([12; 16]);
        let request_id = RequestId::from_bytes([13; 16]);
        runtime
            .issue_account_trusted_grant(AccountTrustedGrantRequest {
                issuer_key_id: IssuerKeyId::from_bytes([7; 16]),
                issuer_key_version: IssuerKeyVersion::new(1).unwrap(),
                issuer_client_instance,
                request_id,
                profile: ServiceProfileId::parse("session-first").unwrap(),
                session_public_key: Ed25519PublicKey::from_bytes([14; 32]),
                harness: HarnessKind::Copilot,
                issued_at_unix_milliseconds: now,
                expires_at_unix_milliseconds: now + 1_000,
            })
            .await
            .unwrap();

        assert_eq!(
            runtime
                .issue_account_trusted_grant(AccountTrustedGrantRequest {
                    issuer_key_id: IssuerKeyId::from_bytes([7; 16]),
                    issuer_key_version: IssuerKeyVersion::new(1).unwrap(),
                    issuer_client_instance,
                    request_id,
                    profile: ServiceProfileId::parse("session-conflict").unwrap(),
                    session_public_key: Ed25519PublicKey::from_bytes([14; 32]),
                    harness: HarnessKind::Copilot,
                    issued_at_unix_milliseconds: now,
                    expires_at_unix_milliseconds: now + 1_000,
                })
                .await,
            Err(LocalServiceErrorCode::Conflict)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_reload_fails_closed_until_a_fresh_snapshot_recovers() {
        let root = tempfile::tempdir().unwrap();
        let installation_path = root
            .path()
            .join("service")
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let fingerprint = InstallationFingerprint::from_bytes([12; 32]);
        let setup_path = installation_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
            drop(
                LocalAuthorizationStore::bootstrap(
                    &setup_path,
                    fingerprint,
                    &AuthorizationPolicy::account_trusted(),
                    &[issuer()],
                    1,
                )
                .unwrap(),
            );
            create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
        })
        .await
        .unwrap();
        let runtime = LiveAuthorizationRuntime::open(&installation_path, fingerprint)
            .await
            .unwrap();
        let mut status = runtime.subscribe();
        let gate = runtime.block_next_reload_for_test();
        let delayed_runtime = Arc::clone(&runtime);
        let delayed = tokio::spawn(async move { delayed_runtime.reload_once().await });

        gate.wait_until_entered().await;
        tokio::time::advance(AUTHORIZATION_RELOAD_DEADLINE).await;
        status.changed().await.unwrap();
        assert_eq!(
            *status.borrow_and_update(),
            AuthorizationRuntimeStatus::Failed(
                AuthorizationRuntimeError::ObservationDeadlineExceeded
            )
        );
        assert!(!runtime.issuer_is_known(
            IssuerKeyId::from_bytes([7; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            Ed25519PublicKey::from_bytes([8; 32]),
            HarnessKind::Copilot,
        ));

        gate.release();
        assert_eq!(
            delayed.await.unwrap(),
            Err(AuthorizationRuntimeError::ObservationDeadlineExceeded)
        );
        assert!(matches!(
            *status.borrow(),
            AuthorizationRuntimeStatus::Failed(
                AuthorizationRuntimeError::ObservationDeadlineExceeded
            )
        ));

        runtime.reload_once().await.unwrap();
        status.changed().await.unwrap();
        assert!(matches!(
            *status.borrow_and_update(),
            AuthorizationRuntimeStatus::Active(_)
        ));
        assert!(runtime.issuer_is_known(
            IssuerKeyId::from_bytes([7; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            Ed25519PublicKey::from_bytes([8; 32]),
            HarnessKind::Copilot,
        ));
    }

    #[tokio::test]
    async fn exclusive_sqlite_lock_fails_closed_without_stopping_recovery() {
        let root = tempfile::tempdir().unwrap();
        let installation_path = root
            .path()
            .join("service")
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let fingerprint = InstallationFingerprint::from_bytes([13; 32]);
        let setup_path = installation_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
            drop(
                LocalAuthorizationStore::bootstrap(
                    &setup_path,
                    fingerprint,
                    &AuthorizationPolicy::account_trusted(),
                    &[issuer()],
                    1,
                )
                .unwrap(),
            );
            create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
        })
        .await
        .unwrap();
        let runtime = LiveAuthorizationRuntime::open(&installation_path, fingerprint)
            .await
            .unwrap();
        let database_path = authorization_store_path(&installation_path).unwrap();
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let database_lock = tokio::task::spawn_blocking(move || {
            let connection = Connection::open(database_path).unwrap();
            connection
                .execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE;")
                .unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            connection.execute_batch("ROLLBACK;").unwrap();
        });
        locked_rx.await.unwrap();

        let mut status = runtime.subscribe();
        let delayed_runtime = Arc::clone(&runtime);
        let delayed = tokio::spawn(async move { delayed_runtime.reload_once().await });
        tokio::time::timeout(Duration::from_secs(2), status.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *status.borrow_and_update(),
            AuthorizationRuntimeStatus::Failed(
                AuthorizationRuntimeError::ObservationDeadlineExceeded
            )
        );
        assert!(!delayed.is_finished());
        assert!(!runtime.issuer_is_known(
            IssuerKeyId::from_bytes([7; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            Ed25519PublicKey::from_bytes([8; 32]),
            HarnessKind::Copilot,
        ));

        release_tx.send(()).unwrap();
        database_lock.await.unwrap();
        assert_eq!(
            delayed.await.unwrap(),
            Err(AuthorizationRuntimeError::ObservationDeadlineExceeded)
        );
        runtime.reload_once().await.unwrap();
        status.changed().await.unwrap();
        assert!(matches!(
            *status.borrow_and_update(),
            AuthorizationRuntimeStatus::Active(_)
        ));
        assert!(runtime.issuer_is_known(
            IssuerKeyId::from_bytes([7; 16]),
            IssuerKeyVersion::new(1).unwrap(),
            Ed25519PublicKey::from_bytes([8; 32]),
            HarnessKind::Copilot,
        ));
    }

    #[test]
    fn reload_error_classification_is_exhaustive() {
        let cases = [
            (
                AuthorizationRuntimeError::Store(LocalAuthorizationStoreError::StorageUnavailable),
                AuthorizationReloadEvent::ObservationFailed,
            ),
            (
                AuthorizationRuntimeError::InvalidProjection,
                AuthorizationReloadEvent::ObservationFailed,
            ),
            (
                AuthorizationRuntimeError::ObservationDeadlineExceeded,
                AuthorizationReloadEvent::ObservationFailed,
            ),
            (
                AuthorizationRuntimeError::BlockingOperationFailed,
                AuthorizationReloadEvent::WorkerFailed,
            ),
            (
                AuthorizationRuntimeError::UnexpectedStop,
                AuthorizationReloadEvent::WorkerFailed,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(authorization_reload_event(error), expected);
        }
    }

    #[tokio::test]
    async fn worker_failure_remains_fatal_to_the_reload_loop() {
        let root = tempfile::tempdir().unwrap();
        let installation_path = root
            .path()
            .join("service")
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let fingerprint = InstallationFingerprint::from_bytes([14; 32]);
        let setup_path = installation_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
            drop(
                LocalAuthorizationStore::bootstrap(
                    &setup_path,
                    fingerprint,
                    &AuthorizationPolicy::account_trusted(),
                    &[issuer()],
                    1,
                )
                .unwrap(),
            );
            create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
        })
        .await
        .unwrap();
        let runtime = LiveAuthorizationRuntime::open(&installation_path, fingerprint)
            .await
            .unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        runtime.fail_closed(AuthorizationRuntimeError::BlockingOperationFailed);
        runtime.request_reload();

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                Arc::clone(&runtime).run_reload_loop(shutdown_rx),
            )
            .await
            .unwrap(),
            Err(AuthorizationRuntimeError::BlockingOperationFailed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn polling_publishes_a_durable_generation_without_a_wall_clock_sleep() {
        let root = tempfile::tempdir().unwrap();
        let installation_path = root
            .path()
            .join("service")
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let fingerprint = InstallationFingerprint::from_bytes([9; 32]);
        let setup_path = installation_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
            drop(
                LocalAuthorizationStore::bootstrap(
                    &setup_path,
                    fingerprint,
                    &AuthorizationPolicy::account_trusted(),
                    &[issuer()],
                    1,
                )
                .unwrap(),
            );
            create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
        })
        .await
        .unwrap();
        let runtime = LiveAuthorizationRuntime::open(&installation_path, fingerprint)
            .await
            .unwrap();
        let mut status = runtime.subscribe();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reload = tokio::spawn(Arc::clone(&runtime).run_reload_loop(shutdown_rx));
        tokio::task::yield_now().await;

        let mutation_path = installation_path.clone();
        let mutation = tokio::task::spawn_blocking(move || {
            LocalAuthorizationStore::open(mutation_path, fingerprint, None)
                .unwrap()
                .suspend_profile(
                    &ServiceProfileId::parse("session-poll").unwrap(),
                    SystemUnixClock.now_unix_milliseconds(),
                )
                .unwrap()
        })
        .await
        .unwrap();
        tokio::time::advance(AUTHORIZATION_RELOAD_INTERVAL).await;
        loop {
            match *status.borrow_and_update() {
                AuthorizationRuntimeStatus::Active(generation)
                    if generation >= mutation.generation() =>
                {
                    break;
                }
                AuthorizationRuntimeStatus::Failed(error) => {
                    panic!("authorization reload failed: {error}")
                }
                AuthorizationRuntimeStatus::Active(_) => {}
            }
            status.changed().await.unwrap();
        }

        let now = SystemUnixClock.now_unix_milliseconds();
        assert_eq!(
            runtime
                .issue_account_trusted_grant(AccountTrustedGrantRequest {
                    issuer_key_id: IssuerKeyId::from_bytes([7; 16]),
                    issuer_key_version: IssuerKeyVersion::new(1).unwrap(),
                    issuer_client_instance: ClientInstanceId::from_bytes([9; 16]),
                    request_id: RequestId::from_bytes([10; 16]),
                    profile: ServiceProfileId::parse("session-poll").unwrap(),
                    session_public_key: Ed25519PublicKey::from_bytes([10; 32]),
                    harness: HarnessKind::Copilot,
                    issued_at_unix_milliseconds: now,
                    expires_at_unix_milliseconds: now + 1_000,
                })
                .await,
            Err(LocalServiceErrorCode::ProfileSuspended)
        );

        shutdown_tx.send_replace(true);
        reload.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reload_observes_external_revocation_while_a_local_mutation_is_queued() {
        let root = tempfile::tempdir().unwrap();
        let installation_path = root
            .path()
            .join("service")
            .join(LOCAL_SERVICE_INSTALLATION_FILE);
        let fingerprint = InstallationFingerprint::from_bytes([10; 32]);
        let setup_path = installation_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_owner_protected_directory(setup_path.parent().unwrap()).unwrap();
            drop(
                LocalAuthorizationStore::bootstrap(
                    &setup_path,
                    fingerprint,
                    &AuthorizationPolicy::account_trusted(),
                    &[issuer()],
                    1,
                )
                .unwrap(),
            );
            create_or_verify_owner_protected_file(&setup_path, b"test-installation").unwrap();
        })
        .await
        .unwrap();
        let runtime = LiveAuthorizationRuntime::open(&installation_path, fingerprint)
            .await
            .unwrap();
        let mut status = runtime.subscribe();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reload = tokio::spawn(Arc::clone(&runtime).run_reload_loop(shutdown_rx));
        let mutation_guard = runtime.operations.lock().await;

        let mutation_path = installation_path.clone();
        let mutation = tokio::task::spawn_blocking(move || {
            LocalAuthorizationStore::open(mutation_path, fingerprint, None)
                .unwrap()
                .suspend_profile(
                    &ServiceProfileId::parse("session-blocked-mutation").unwrap(),
                    SystemUnixClock.now_unix_milliseconds(),
                )
                .unwrap()
        })
        .await
        .unwrap();
        runtime.request_reload();
        loop {
            match *status.borrow_and_update() {
                AuthorizationRuntimeStatus::Active(generation)
                    if generation >= mutation.generation() =>
                {
                    break;
                }
                AuthorizationRuntimeStatus::Failed(error) => {
                    panic!("authorization reload failed: {error}")
                }
                AuthorizationRuntimeStatus::Active(_) => {}
            }
            status.changed().await.unwrap();
        }

        drop(mutation_guard);
        shutdown_tx.send_replace(true);
        reload.await.unwrap().unwrap();
    }
}
