use core::fmt;

use KonclaveLocalServiceTransport::{
    AuthorizationPolicy, AuthorizationPolicyVersion, ClientInstanceId, IssuerKeyId,
    IssuerKeyVersion, IssuerRegistration, RequestId, ServiceProfileId, SessionGrant,
};
use KonclaveUserPresence::{
    NativeWebAuthnCredential, UserPresenceCredentialDigest, UserPresenceCredentialId,
    UserPresenceProviderId,
};

use crate::LocalAuthorizationStoreError;

/// File name of the mutable authorization database beside the installation record.
pub const LOCAL_AUTHORIZATION_STORE_FILE: &str = "konclave-local-authorization.sqlite3";

/// Byte length of the caller-supplied immutable installation fingerprint.
pub const INSTALLATION_FINGERPRINT_LENGTH: usize = 32;

/// Maximum retained terminal grants used for bounded idempotency and audit history.
pub const MAX_TERMINAL_GRANT_RECORDS: usize = 256;

/// Maximum grant identifiers issued during one installation lifetime.
pub const MAX_GRANT_IDENTIFIERS: usize = 1_048_576;

/// Maximum retained mutation audit events.
pub const MAX_AUTHORIZATION_AUDIT_RECORDS: usize = 256;

/// Maximum exact profiles that may be suspended concurrently.
pub const MAX_SUSPENDED_PROFILES: usize = 256;

/// Maximum credential identifiers reserved during one installation lifetime.
pub const MAX_USER_PRESENCE_CREDENTIAL_IDENTIFIERS: usize = 256;

/// SQLite busy timeout used by every store connection.
pub const AUTHORIZATION_STORE_BUSY_TIMEOUT_MILLISECONDS: u64 = 5_000;

/// Opaque digest that binds one database to one immutable service installation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstallationFingerprint([u8; INSTALLATION_FINGERPRINT_LENGTH]);

impl InstallationFingerprint {
    /// Wraps exactly one opaque installation fingerprint.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; INSTALLATION_FINGERPRINT_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the exact opaque fingerprint bytes for persistence comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; INSTALLATION_FINGERPRINT_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for InstallationFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationFingerprint")
            .finish_non_exhaustive()
    }
}

/// Monotonic generation of one authorization database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationGeneration(u64);

impl AuthorizationGeneration {
    /// Creates a nonzero process high-water mark.
    ///
    /// # Errors
    ///
    /// Returns [`LocalAuthorizationStoreError::InvalidInput`] for zero.
    pub const fn new(value: u64) -> Result<Self, LocalAuthorizationStoreError> {
        if value == 0 {
            return Err(LocalAuthorizationStoreError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the durable generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn from_validated(value: u64) -> Self {
        Self(value)
    }
}

/// Whether one exact issuer key version accepts new grant issuance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuerAvailability {
    /// The issuer may create new grants.
    Enabled,
    /// The issuer remains registered but cannot create new grants.
    Disabled,
}

/// How issuer disablement applies to grants that already exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingGrantDisposition {
    /// Existing grants remain usable until another terminal condition or expiry.
    RetainUntilExpiry,
    /// Existing grants become terminal in the same transaction as disablement.
    Revoke,
}

/// One validated durable issuer key version in a live-registry snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationIssuerRecord {
    pub(crate) issuer_key_id: IssuerKeyId,
    pub(crate) issuer_key_version: IssuerKeyVersion,
    pub(crate) registration: IssuerRegistration,
    pub(crate) availability: IssuerAvailability,
    pub(crate) existing_grant_disposition: ExistingGrantDisposition,
}

impl AuthorizationIssuerRecord {
    /// Returns the exact issuer key identifier.
    #[must_use]
    pub const fn issuer_key_id(&self) -> IssuerKeyId {
        self.issuer_key_id
    }

    /// Returns the exact issuer key version.
    #[must_use]
    pub const fn issuer_key_version(&self) -> IssuerKeyVersion {
        self.issuer_key_version
    }

    /// Returns the validated public issuer registration.
    #[must_use]
    pub const fn registration(&self) -> &IssuerRegistration {
        &self.registration
    }

    /// Returns whether this key version accepts new issuance.
    #[must_use]
    pub const fn availability(&self) -> IssuerAvailability {
        self.availability
    }

    /// Returns the configured treatment of grants during disablement.
    #[must_use]
    pub const fn existing_grant_disposition(&self) -> ExistingGrantDisposition {
        self.existing_grant_disposition
    }
}

impl fmt::Debug for AuthorizationIssuerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationIssuerRecord")
            .field("availability", &self.availability)
            .field(
                "existing_grant_disposition",
                &self.existing_grant_disposition,
            )
            .finish_non_exhaustive()
    }
}

/// Complete bounded state used to replace an in-memory live authorization registry.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationSnapshot {
    pub(crate) generation: AuthorizationGeneration,
    pub(crate) policy: AuthorizationPolicy,
    pub(crate) issuers: Vec<AuthorizationIssuerRecord>,
    pub(crate) suspended_profiles: Vec<ServiceProfileId>,
    pub(crate) active_grants: Vec<SessionGrant>,
    pub(crate) user_presence_credential: Option<UserPresenceCredentialRecord>,
}

impl AuthorizationSnapshot {
    /// Returns the monotonic durable generation represented by this snapshot.
    #[must_use]
    pub const fn generation(&self) -> AuthorizationGeneration {
        self.generation
    }

    /// Returns the effective evidence policy.
    #[must_use]
    pub const fn policy(&self) -> &AuthorizationPolicy {
        &self.policy
    }

    /// Returns every finite issuer key version in deterministic order.
    #[must_use]
    pub fn issuers(&self) -> &[AuthorizationIssuerRecord] {
        &self.issuers
    }

    /// Returns every exact suspended profile in deterministic order.
    #[must_use]
    pub fn suspended_profiles(&self) -> &[ServiceProfileId] {
        &self.suspended_profiles
    }

    /// Returns active unexpired grants in deterministic identifier order.
    #[must_use]
    pub fn active_grants(&self) -> &[SessionGrant] {
        &self.active_grants
    }

    /// Returns the active user-presence credential, when one is enrolled.
    #[must_use]
    pub const fn user_presence_credential(&self) -> Option<&UserPresenceCredentialRecord> {
        self.user_presence_credential.as_ref()
    }
}

impl fmt::Debug for AuthorizationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationSnapshot")
            .field("generation", &self.generation)
            .field("policy_version", &self.policy.version())
            .field("issuer_count", &self.issuers.len())
            .field("suspended_profile_count", &self.suspended_profiles.len())
            .field("active_grant_count", &self.active_grants.len())
            .field(
                "user_presence_credential",
                &self.user_presence_credential.is_some(),
            )
            .finish()
    }
}

/// One validated active native WebAuthn credential retained as public verifier state.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPresenceCredentialRecord {
    provider_id: UserPresenceProviderId,
    credential_id: UserPresenceCredentialId,
    credential_digest: UserPresenceCredentialDigest,
    document: Vec<u8>,
}

impl UserPresenceCredentialRecord {
    /// Decodes and validates one bounded native WebAuthn credential document.
    ///
    /// # Errors
    ///
    /// Returns [`LocalAuthorizationStoreError::InvalidInput`] when the document is
    /// malformed, unsupported, or inconsistent with its embedded credential.
    pub fn from_document(document: Vec<u8>) -> Result<Self, LocalAuthorizationStoreError> {
        let credential = NativeWebAuthnCredential::from_bytes(&document)
            .map_err(|_| LocalAuthorizationStoreError::InvalidInput)?;
        let provider_id = credential.provider_id().clone();
        let credential_id = credential.credential_id().clone();
        let credential_digest = credential_id.digest();
        Ok(Self {
            provider_id,
            credential_id,
            credential_digest,
            document,
        })
    }

    /// Returns the exact provider identifier.
    #[must_use]
    pub const fn provider_id(&self) -> &UserPresenceProviderId {
        &self.provider_id
    }

    /// Returns the opaque credential identifier.
    #[must_use]
    pub const fn credential_id(&self) -> &UserPresenceCredentialId {
        &self.credential_id
    }

    /// Returns the fixed credential digest used for replacement checks.
    #[must_use]
    pub const fn credential_digest(&self) -> UserPresenceCredentialDigest {
        self.credential_digest
    }

    /// Returns the validated public credential document.
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
    }
}

impl fmt::Debug for UserPresenceCredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserPresenceCredentialRecord")
            .field("provider_id", &self.provider_id)
            .field("credential_id_length", &self.credential_id.as_bytes().len())
            .field("document_length", &self.document.len())
            .finish_non_exhaustive()
    }
}

/// Whether an idempotent operation changed durable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationEffect {
    /// The requested transition was committed.
    Applied,
    /// Durable state already represented the requested exact outcome.
    Unchanged,
}

/// Generation and effect returned by one synchronous transactional operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationMutation {
    pub(crate) generation: AuthorizationGeneration,
    pub(crate) effect: MutationEffect,
}

impl AuthorizationMutation {
    /// Returns the generation visible after the operation.
    #[must_use]
    pub const fn generation(self) -> AuthorizationGeneration {
        self.generation
    }

    /// Returns whether the operation changed durable state.
    #[must_use]
    pub const fn effect(self) -> MutationEffect {
        self.effect
    }
}

/// Durable identity of one issuer-side grant request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrantIssuanceKey {
    issuer_client_instance: ClientInstanceId,
    request_id: RequestId,
}

impl GrantIssuanceKey {
    /// Creates one exact issuer request key.
    #[must_use]
    pub const fn new(issuer_client_instance: ClientInstanceId, request_id: RequestId) -> Self {
        Self {
            issuer_client_instance,
            request_id,
        }
    }

    /// Returns the issuer connection instance.
    #[must_use]
    pub const fn issuer_client_instance(self) -> ClientInstanceId {
        self.issuer_client_instance
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }
}

/// Exact grant and mutation metadata returned by durable issuance.
#[derive(Clone, PartialEq, Eq)]
pub struct GrantIssuanceResult {
    mutation: AuthorizationMutation,
    grant: SessionGrant,
}

impl GrantIssuanceResult {
    pub(crate) const fn new(mutation: AuthorizationMutation, grant: SessionGrant) -> Self {
        Self { mutation, grant }
    }

    /// Returns the durable mutation outcome.
    #[must_use]
    pub const fn mutation(&self) -> AuthorizationMutation {
        self.mutation
    }

    /// Returns the exact issued or replayed grant.
    #[must_use]
    pub const fn grant(&self) -> &SessionGrant {
        &self.grant
    }

    /// Consumes the result and returns the exact issued or replayed grant.
    #[must_use]
    pub fn into_grant(self) -> SessionGrant {
        self.grant
    }
}

impl fmt::Debug for GrantIssuanceResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrantIssuanceResult")
            .field("mutation", &self.mutation)
            .finish_non_exhaustive()
    }
}

/// Stable bounded categories retained by the authorization audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationAuditKind {
    /// The database was created from immutable installation state.
    Bootstrap,
    /// One candidate session grant was issued.
    GrantIssued,
    /// One exact grant was cleanly retired.
    GrantRetired,
    /// One exact grant was administratively revoked.
    GrantRevoked,
    /// One exact profile was suspended.
    ProfileSuspended,
    /// One exact profile suspension was removed.
    ProfileResumed,
    /// One exact issuer key version changed enabled state or disposition.
    IssuerStateChanged,
    /// The effective evidence policy advanced.
    PolicyReplaced,
    /// One higher issuer key version was registered.
    IssuerRegistered,
    /// One exact issuer key version was removed from active installation state.
    IssuerRemoved,
    /// Expired active grants were moved to bounded terminal history.
    GrantsExpired,
    /// One user-presence credential was enrolled.
    UserPresenceCredentialRegistered,
    /// The active user-presence credential was replaced.
    UserPresenceCredentialReplaced,
    /// The active user-presence credential was removed.
    UserPresenceCredentialRemoved,
    /// Mutable WebAuthn counter state advanced for the active credential.
    UserPresenceCredentialUpdated,
}

/// One non-sensitive retained authorization mutation event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationAuditEvent {
    pub(crate) generation: AuthorizationGeneration,
    pub(crate) kind: AuthorizationAuditKind,
    pub(crate) occurred_at_unix_milliseconds: u64,
}

impl AuthorizationAuditEvent {
    /// Returns the generation committed by this event.
    #[must_use]
    pub const fn generation(self) -> AuthorizationGeneration {
        self.generation
    }

    /// Returns the stable mutation category.
    #[must_use]
    pub const fn kind(self) -> AuthorizationAuditKind {
        self.kind
    }

    /// Returns the caller-supplied event timestamp.
    #[must_use]
    pub const fn occurred_at_unix_milliseconds(self) -> u64 {
        self.occurred_at_unix_milliseconds
    }
}

/// Bounded grant usage for one global, issuer, and exact-profile capacity query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationCapacity {
    pub(crate) active_global: usize,
    pub(crate) maximum_global: usize,
    pub(crate) active_for_issuer: usize,
    pub(crate) maximum_for_issuer: usize,
    pub(crate) active_for_profile: usize,
    pub(crate) maximum_for_profile: usize,
}

impl AuthorizationCapacity {
    /// Returns active grants across the installation.
    #[must_use]
    pub const fn active_global(self) -> usize {
        self.active_global
    }

    /// Returns the global active-grant quota.
    #[must_use]
    pub const fn maximum_global(self) -> usize {
        self.maximum_global
    }

    /// Returns active grants for the queried issuer identifier across key versions.
    #[must_use]
    pub const fn active_for_issuer(self) -> usize {
        self.active_for_issuer
    }

    /// Returns the per-issuer active-grant quota.
    #[must_use]
    pub const fn maximum_for_issuer(self) -> usize {
        self.maximum_for_issuer
    }

    /// Returns active grants for the queried exact profile.
    #[must_use]
    pub const fn active_for_profile(self) -> usize {
        self.active_for_profile
    }

    /// Returns the per-profile active-grant quota.
    #[must_use]
    pub const fn maximum_for_profile(self) -> usize {
        self.maximum_for_profile
    }
}

/// Bounded diagnostic counts and effective policy metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationStoreStatus {
    pub(crate) generation: AuthorizationGeneration,
    pub(crate) policy_version: AuthorizationPolicyVersion,
    pub(crate) issuer_records: usize,
    pub(crate) issuer_identifiers: usize,
    pub(crate) disabled_issuers: usize,
    pub(crate) suspended_profiles: usize,
    pub(crate) active_grants: usize,
    pub(crate) terminal_grants: usize,
    pub(crate) grant_identifiers: usize,
    pub(crate) audit_records: usize,
    pub(crate) user_presence_credentials: usize,
    pub(crate) user_presence_credential_identifiers: usize,
    pub(crate) capacity: AuthorizationCapacity,
}

impl AuthorizationStoreStatus {
    /// Returns the durable generation represented by these counts.
    #[must_use]
    pub const fn generation(self) -> AuthorizationGeneration {
        self.generation
    }

    /// Returns the effective policy version.
    #[must_use]
    pub const fn policy_version(self) -> AuthorizationPolicyVersion {
        self.policy_version
    }

    /// Returns the number of retained issuer key versions.
    #[must_use]
    pub const fn issuer_records(self) -> usize {
        self.issuer_records
    }

    /// Returns retained issuer key-version identifiers, including removed versions.
    #[must_use]
    pub const fn issuer_identifiers(self) -> usize {
        self.issuer_identifiers
    }

    /// Returns the installation-lifetime issuer identifier bound.
    #[must_use]
    pub const fn maximum_issuer_identifiers(self) -> usize {
        KonclaveLocalServiceTransport::MAX_ADAPTER_REGISTRATIONS
    }

    /// Returns the number of disabled issuer key versions.
    #[must_use]
    pub const fn disabled_issuers(self) -> usize {
        self.disabled_issuers
    }

    /// Returns the number of exact suspended profiles.
    #[must_use]
    pub const fn suspended_profiles(self) -> usize {
        self.suspended_profiles
    }

    /// Returns the number of active unexpired grants.
    #[must_use]
    pub const fn active_grants(self) -> usize {
        self.active_grants
    }

    /// Returns the number of retained terminal grant records.
    #[must_use]
    pub const fn terminal_grants(self) -> usize {
        self.terminal_grants
    }

    /// Returns grant identifiers reserved during the installation lifetime.
    #[must_use]
    pub const fn grant_identifiers(self) -> usize {
        self.grant_identifiers
    }

    /// Returns the installation-lifetime grant identifier bound.
    #[must_use]
    pub const fn maximum_grant_identifiers(self) -> usize {
        MAX_GRANT_IDENTIFIERS
    }

    /// Returns the number of retained bounded audit events.
    #[must_use]
    pub const fn audit_records(self) -> usize {
        self.audit_records
    }

    /// Returns zero or one active user-presence credentials.
    #[must_use]
    pub const fn user_presence_credentials(self) -> usize {
        self.user_presence_credentials
    }

    /// Returns identifiers reserved for the installation lifetime.
    #[must_use]
    pub const fn user_presence_credential_identifiers(self) -> usize {
        self.user_presence_credential_identifiers
    }

    /// Returns global and queried-scope active grant usage.
    #[must_use]
    pub const fn capacity(self) -> AuthorizationCapacity {
        self.capacity
    }
}
