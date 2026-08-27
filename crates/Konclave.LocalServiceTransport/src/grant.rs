use std::sync::{Mutex, MutexGuard, PoisonError};

use KonclaveDomainCore::Ed25519PublicKey;

use crate::{
    HarnessKind, IssuerKeyId, IssuerKeyVersion, LocalServiceTransportError, ServiceProfileId,
};

/// Local-service protocol version that requires evidence-bound session grants.
pub const SESSION_GRANT_PROTOCOL_VERSION: u16 = 2;

/// Largest number of policy clauses one profile may accept.
pub const MAX_POLICY_CLAUSES: usize = 8;

/// Largest number of active session grants held by one service process.
pub const MAX_SESSION_GRANTS: usize = 256;

/// Largest number of active grants one issuer may hold.
pub const MAX_GRANTS_PER_ISSUER: usize = 128;

/// Largest number of active grants one profile may hold.
pub const MAX_GRANTS_PER_PROFILE: usize = 32;

/// Fixed byte length of one random session-grant identifier.
pub const SESSION_GRANT_ID_LENGTH: usize = 16;

/// Bounded active-grant usage visible to status diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionGrantCapacity {
    active_global: usize,
    active_for_issuer: usize,
    active_for_profile: usize,
}

impl SessionGrantCapacity {
    /// Returns all active grants in this service process.
    #[must_use]
    pub const fn active_global(self) -> usize {
        self.active_global
    }

    /// Returns active grants from the selected issuer.
    #[must_use]
    pub const fn active_for_issuer(self) -> usize {
        self.active_for_issuer
    }

    /// Returns active grants for the selected exact profile.
    #[must_use]
    pub const fn active_for_profile(self) -> usize {
        self.active_for_profile
    }
}

/// Random identifier for one finite exact-profile authorization grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionGrantId([u8; SESSION_GRANT_ID_LENGTH]);

impl SessionGrantId {
    /// Wraps one exact grant identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_GRANT_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Parses one exact grant identifier.
    ///
    /// # Errors
    ///
    /// Returns an invalid-identifier error unless `bytes` has the exact wire length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LocalServiceTransportError> {
        Ok(Self(bytes.try_into().map_err(|_| {
            LocalServiceTransportError::InvalidIdentifier {
                field: "session_grant",
            }
        })?))
    }

    /// Returns the canonical identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_GRANT_ID_LENGTH] {
        &self.0
    }
}

/// Closed evidence claims the service can verify before issuing a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorizationEvidenceKind {
    /// Every process under the configured operating-system account is trusted.
    AccountTrusted,
    /// A platform ceremony proved interactive human presence.
    UserPresence,
    /// A supported harness issued a signed session assertion.
    HarnessAttested,
    /// An isolated platform workload proved its identity.
    WorkloadIdentity,
}

impl AuthorizationEvidenceKind {
    const fn bit(self) -> u8 {
        match self {
            Self::AccountTrusted => 1,
            Self::UserPresence => 2,
            Self::HarnessAttested => 4,
            Self::WorkloadIdentity => 8,
        }
    }

    /// Returns the stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountTrusted => "account_trusted",
            Self::UserPresence => "user_presence",
            Self::HarnessAttested => "harness_attested",
            Self::WorkloadIdentity => "workload_identity",
        }
    }
}

/// One canonical nonempty set of verified evidence kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationEvidenceSet(u8);

impl AuthorizationEvidenceSet {
    const KNOWN_BITS: u8 = 1 | 2 | 4 | 8;

    /// Creates a nonempty canonical evidence set.
    ///
    /// # Errors
    ///
    /// Returns an invalid-evidence error when the input is empty or repeats a kind.
    pub fn new(
        evidence: impl IntoIterator<Item = AuthorizationEvidenceKind>,
    ) -> Result<Self, LocalServiceTransportError> {
        let mut bits = 0_u8;
        for kind in evidence {
            let bit = kind.bit();
            if bits & bit != 0 {
                return Err(LocalServiceTransportError::InvalidEvidence);
            }
            bits |= bit;
        }
        Self::from_bits(bits)
    }

    /// Parses a canonical wire bitset.
    ///
    /// # Errors
    ///
    /// Returns an invalid-evidence error for an empty set or unknown bits.
    pub const fn from_bits(bits: u8) -> Result<Self, LocalServiceTransportError> {
        if bits == 0 || bits & !Self::KNOWN_BITS != 0 {
            return Err(LocalServiceTransportError::InvalidEvidence);
        }
        Ok(Self(bits))
    }

    /// Returns the canonical wire bitset.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Reports whether this verified set satisfies every kind in `required`.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// Monotonic authorization-policy generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationPolicyVersion(u64);

impl AuthorizationPolicyVersion {
    /// Creates one nonzero policy version.
    ///
    /// # Errors
    ///
    /// Returns an invalid-identifier error for zero.
    pub const fn new(value: u64) -> Result<Self, LocalServiceTransportError> {
        if value == 0 {
            return Err(LocalServiceTransportError::InvalidIdentifier {
                field: "authorization_policy_version",
            });
        }
        Ok(Self(value))
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Constrained any-of/all-of evidence policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationPolicy {
    version: AuthorizationPolicyVersion,
    clauses: Vec<AuthorizationEvidenceSet>,
}

impl AuthorizationPolicy {
    /// Creates one canonical nonempty policy.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence for an empty, oversized, or duplicate clause list.
    pub fn new(
        version: AuthorizationPolicyVersion,
        mut clauses: Vec<AuthorizationEvidenceSet>,
    ) -> Result<Self, LocalServiceTransportError> {
        clauses.sort_unstable();
        if clauses.is_empty()
            || clauses.len() > MAX_POLICY_CLAUSES
            || clauses.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(LocalServiceTransportError::InvalidEvidence);
        }
        Ok(Self { version, clauses })
    }

    /// Returns the initial explicit AccountTrusted policy.
    #[must_use]
    pub fn account_trusted() -> Self {
        Self {
            version: AuthorizationPolicyVersion(1),
            clauses: vec![AuthorizationEvidenceSet(
                AuthorizationEvidenceKind::AccountTrusted.bit(),
            )],
        }
    }

    /// Returns the policy generation.
    #[must_use]
    pub const fn version(&self) -> AuthorizationPolicyVersion {
        self.version
    }

    /// Returns the canonical accepted clauses.
    #[must_use]
    pub fn clauses(&self) -> &[AuthorizationEvidenceSet] {
        &self.clauses
    }

    /// Reports whether `evidence` satisfies any complete clause.
    #[must_use]
    pub fn accepts(&self, evidence: AuthorizationEvidenceSet) -> bool {
        self.clauses
            .iter()
            .any(|required| evidence.satisfies(*required))
    }
}

/// Closed capabilities one operational session grant carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionCapabilities(u64);

impl SessionCapabilities {
    /// Profile tools, deterministic commands, and membership operations.
    pub const PROFILE_OPERATIONS: Self = Self(1);
    /// Automatic-delivery claim, acknowledgment, and release operations.
    pub const DELIVERY: Self = Self(2);
    /// Bounded profile and service status operations.
    pub const STATUS: Self = Self(4);
    /// Request cancellation and clean grant-retirement operations.
    pub const CONTROL: Self = Self(8);
    /// Complete initial operational capability set.
    pub const ALL: Self =
        Self(Self::PROFILE_OPERATIONS.0 | Self::DELIVERY.0 | Self::STATUS.0 | Self::CONTROL.0);
    const KNOWN_BITS: u64 = Self::ALL.0;

    /// Parses one canonical capability bitset.
    ///
    /// # Errors
    ///
    /// Returns invalid capabilities for zero or unknown bits.
    pub const fn from_bits(bits: u64) -> Result<Self, LocalServiceTransportError> {
        if bits == 0 || bits & !Self::KNOWN_BITS != 0 {
            return Err(LocalServiceTransportError::InvalidCapabilities);
        }
        Ok(Self(bits))
    }

    /// Returns the wire bitset.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Reports whether this grant includes `required`.
    #[must_use]
    pub const fn permits(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// Finite exact-profile authorization issued to one ephemeral session key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    grant_id: SessionGrantId,
    issuer_key_id: IssuerKeyId,
    issuer_key_version: IssuerKeyVersion,
    profile: ServiceProfileId,
    session_public_key: Ed25519PublicKey,
    harness: HarnessKind,
    evidence: AuthorizationEvidenceSet,
    policy_version: AuthorizationPolicyVersion,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    capabilities: SessionCapabilities,
}

/// Complete claims used to construct one validated session grant.
pub struct SessionGrantClaims {
    /// Random identifier that is never reused.
    pub grant_id: SessionGrantId,
    /// Exact issuer that evaluated the evidence.
    pub issuer_key_id: IssuerKeyId,
    /// Exact active issuer-key version.
    pub issuer_key_version: IssuerKeyVersion,
    /// Canonical profile this grant alone may operate.
    pub profile: ServiceProfileId,
    /// Ephemeral key whose private half the client must prove.
    pub session_public_key: Ed25519PublicKey,
    /// Bounded integration metadata presented at issuance.
    pub harness: HarnessKind,
    /// Exact evidence set verified by the issuer.
    pub evidence: AuthorizationEvidenceSet,
    /// Policy generation used to authorize the evidence.
    pub policy_version: AuthorizationPolicyVersion,
    /// Inclusive issuance timestamp.
    pub issued_at_unix_milliseconds: u64,
    /// Exclusive expiry timestamp.
    pub expires_at_unix_milliseconds: u64,
    /// Closed operational authority carried by this grant.
    pub capabilities: SessionCapabilities,
}

impl SessionGrant {
    /// Creates one validated finite grant.
    ///
    /// # Errors
    ///
    /// Returns an invalid-grant error when expiry is not strictly after issuance.
    pub fn new(claims: SessionGrantClaims) -> Result<Self, LocalServiceTransportError> {
        if claims.expires_at_unix_milliseconds <= claims.issued_at_unix_milliseconds {
            return Err(LocalServiceTransportError::InvalidGrant);
        }
        Ok(Self {
            grant_id: claims.grant_id,
            issuer_key_id: claims.issuer_key_id,
            issuer_key_version: claims.issuer_key_version,
            profile: claims.profile,
            session_public_key: claims.session_public_key,
            harness: claims.harness,
            evidence: claims.evidence,
            policy_version: claims.policy_version,
            issued_at_unix_milliseconds: claims.issued_at_unix_milliseconds,
            expires_at_unix_milliseconds: claims.expires_at_unix_milliseconds,
            capabilities: claims.capabilities,
        })
    }

    /// Returns the grant identifier.
    #[must_use]
    pub const fn grant_id(&self) -> SessionGrantId {
        self.grant_id
    }

    /// Returns the issuing account credential identifier.
    #[must_use]
    pub const fn issuer_key_id(&self) -> IssuerKeyId {
        self.issuer_key_id
    }

    /// Returns the issuing account credential version.
    #[must_use]
    pub const fn issuer_key_version(&self) -> IssuerKeyVersion {
        self.issuer_key_version
    }

    /// Returns the exact profile.
    #[must_use]
    pub const fn profile(&self) -> &ServiceProfileId {
        &self.profile
    }

    /// Returns the ephemeral verification key.
    #[must_use]
    pub const fn session_public_key(&self) -> Ed25519PublicKey {
        self.session_public_key
    }

    /// Returns the integration kind.
    #[must_use]
    pub const fn harness(&self) -> HarnessKind {
        self.harness
    }

    /// Returns the exact evidence verified at issuance.
    #[must_use]
    pub const fn evidence(&self) -> AuthorizationEvidenceSet {
        self.evidence
    }

    /// Returns the policy generation used at issuance.
    #[must_use]
    pub const fn policy_version(&self) -> AuthorizationPolicyVersion {
        self.policy_version
    }

    /// Returns the issuance time.
    #[must_use]
    pub const fn issued_at_unix_milliseconds(&self) -> u64 {
        self.issued_at_unix_milliseconds
    }

    /// Returns the expiry time.
    #[must_use]
    pub const fn expires_at_unix_milliseconds(&self) -> u64 {
        self.expires_at_unix_milliseconds
    }

    /// Returns the allowed operation capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> SessionCapabilities {
        self.capabilities
    }
}

/// Resolves issuer registrations and active grants during a v2 handshake.
pub trait SessionAuthorizationRegistry: Send + Sync {
    /// Resolves one exact active issuer key version.
    fn active_issuer(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
    ) -> Option<crate::IssuerRegistration>;

    /// Resolves one exact active, unexpired grant.
    fn active_grant(
        &self,
        grant_id: SessionGrantId,
        now_unix_milliseconds: u64,
    ) -> Option<SessionGrant>;
}

#[derive(Debug, Default)]
struct GrantState {
    issuers: Vec<(IssuerKeyId, IssuerKeyVersion, crate::IssuerRegistration)>,
    grants: Vec<SessionGrant>,
}

/// Bounded mutable service-lifetime issuer and session-grant registry.
#[derive(Debug, Default)]
pub struct InMemorySessionAuthorizationRegistry {
    state: Mutex<GrantState>,
}

impl InMemorySessionAuthorizationRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(GrantState {
                issuers: Vec::new(),
                grants: Vec::new(),
            }),
        }
    }

    /// Registers one exact active account issuer.
    ///
    /// # Errors
    ///
    /// Returns duplicate or capacity failures without replacing another record.
    pub fn register_issuer(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        registration: crate::IssuerRegistration,
    ) -> Result<(), LocalServiceTransportError> {
        let mut state = lock(&self.state);
        if state
            .issuers
            .iter()
            .any(|(id, version, _)| *id == issuer_key_id && *version == issuer_key_version)
        {
            return Err(LocalServiceTransportError::DuplicateRegistration);
        }
        if state.issuers.len() == crate::MAX_ADAPTER_REGISTRATIONS {
            return Err(LocalServiceTransportError::RegistrationLimitReached);
        }
        state
            .issuers
            .push((issuer_key_id, issuer_key_version, registration));
        Ok(())
    }

    /// Issues one active grant without evicting any existing grant.
    ///
    /// # Errors
    ///
    /// Returns duplicate or quota failures. Expired grants are reclaimed first.
    pub fn issue_grant(
        &self,
        grant: SessionGrant,
        now_unix_milliseconds: u64,
    ) -> Result<(), LocalServiceTransportError> {
        let mut state = lock(&self.state);
        state
            .grants
            .retain(|existing| existing.expires_at_unix_milliseconds > now_unix_milliseconds);
        if state
            .grants
            .iter()
            .any(|existing| existing.grant_id == grant.grant_id)
        {
            return Err(LocalServiceTransportError::DuplicateGrant);
        }
        if state.grants.len() >= MAX_SESSION_GRANTS
            || state
                .grants
                .iter()
                .filter(|existing| existing.issuer_key_id == grant.issuer_key_id)
                .count()
                >= MAX_GRANTS_PER_ISSUER
            || state
                .grants
                .iter()
                .filter(|existing| existing.profile == grant.profile)
                .count()
                >= MAX_GRANTS_PER_PROFILE
        {
            return Err(LocalServiceTransportError::GrantLimitReached);
        }
        state.grants.push(grant);
        Ok(())
    }

    /// Revokes one exact grant.
    ///
    /// Returns whether an active record was removed.
    pub fn revoke_grant(&self, grant_id: SessionGrantId) -> bool {
        let mut state = lock(&self.state);
        let before = state.grants.len();
        state.grants.retain(|grant| grant.grant_id != grant_id);
        before != state.grants.len()
    }

    /// Reports active grant usage after reclaiming expired records.
    #[must_use]
    pub fn grant_capacity(
        &self,
        issuer_key_id: IssuerKeyId,
        profile: &ServiceProfileId,
        now_unix_milliseconds: u64,
    ) -> SessionGrantCapacity {
        let mut state = lock(&self.state);
        state
            .grants
            .retain(|grant| grant.expires_at_unix_milliseconds > now_unix_milliseconds);
        SessionGrantCapacity {
            active_global: state.grants.len(),
            active_for_issuer: state
                .grants
                .iter()
                .filter(|grant| grant.issuer_key_id == issuer_key_id)
                .count(),
            active_for_profile: state
                .grants
                .iter()
                .filter(|grant| grant.profile == *profile)
                .count(),
        }
    }
}

impl SessionAuthorizationRegistry for InMemorySessionAuthorizationRegistry {
    fn active_issuer(
        &self,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
    ) -> Option<crate::IssuerRegistration> {
        lock(&self.state)
            .issuers
            .iter()
            .find(|(id, version, _)| *id == issuer_key_id && *version == issuer_key_version)
            .map(|(_, _, registration)| registration.clone())
    }

    fn active_grant(
        &self,
        grant_id: SessionGrantId,
        now_unix_milliseconds: u64,
    ) -> Option<SessionGrant> {
        lock(&self.state)
            .grants
            .iter()
            .find(|grant| {
                grant.grant_id == grant_id
                    && grant.expires_at_unix_milliseconds > now_unix_milliseconds
            })
            .cloned()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::Ed25519PublicKey;

    use super::*;
    use crate::{IssuerRegistration, ProfileAuthorization};

    fn profile(value: &str) -> ServiceProfileId {
        ServiceProfileId::parse(value).unwrap()
    }

    fn evidence(kind: AuthorizationEvidenceKind) -> AuthorizationEvidenceSet {
        AuthorizationEvidenceSet::new([kind]).unwrap()
    }

    fn grant(id: u16, profile_name: &str, issuer: u8) -> SessionGrant {
        grant_with_version(id, profile_name, issuer, 1)
    }

    fn grant_with_version(
        id: u16,
        profile_name: &str,
        issuer: u8,
        issuer_version: u32,
    ) -> SessionGrant {
        let mut grant_id = [0_u8; SESSION_GRANT_ID_LENGTH];
        if let Ok(byte) = u8::try_from(id) {
            grant_id.fill(byte);
        } else {
            grant_id[..2].copy_from_slice(&id.to_be_bytes());
        }
        SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes(grant_id),
            issuer_key_id: IssuerKeyId::from_bytes([issuer; IssuerKeyId::LENGTH]),
            issuer_key_version: IssuerKeyVersion::new(issuer_version).unwrap(),
            profile: profile(profile_name),
            session_public_key: Ed25519PublicKey::from_bytes(
                [u8::try_from(id % 256).unwrap(); Ed25519PublicKey::LENGTH],
            ),
            harness: HarnessKind::Copilot,
            evidence: evidence(AuthorizationEvidenceKind::AccountTrusted),
            policy_version: AuthorizationPolicyVersion::new(1).unwrap(),
            issued_at_unix_milliseconds: 10,
            expires_at_unix_milliseconds: 20,
            capabilities: SessionCapabilities::ALL,
        })
        .unwrap()
    }

    #[test]
    fn any_of_all_of_policy_is_canonical_and_deterministic() {
        let account = evidence(AuthorizationEvidenceKind::AccountTrusted);
        let strong = AuthorizationEvidenceSet::new([
            AuthorizationEvidenceKind::HarnessAttested,
            AuthorizationEvidenceKind::UserPresence,
        ])
        .unwrap();
        let policy = AuthorizationPolicy::new(
            AuthorizationPolicyVersion::new(2).unwrap(),
            vec![strong, account],
        )
        .unwrap();
        assert!(policy.accepts(account));
        assert!(policy.accepts(strong));
        assert!(!policy.accepts(evidence(AuthorizationEvidenceKind::HarnessAttested)));
        assert!(
            AuthorizationPolicy::new(AuthorizationPolicyVersion::new(1).unwrap(), Vec::new())
                .is_err()
        );
    }

    #[test]
    fn grants_are_exact_bounded_and_expire_without_eviction() {
        let registry = InMemorySessionAuthorizationRegistry::new();
        registry.issue_grant(grant(1, "alice", 1), 10).unwrap();
        assert!(
            registry
                .active_grant(SessionGrantId::from_bytes([1; 16]), 19)
                .is_some()
        );
        assert!(
            registry
                .active_grant(SessionGrantId::from_bytes([1; 16]), 20)
                .is_none()
        );
        registry.issue_grant(grant(2, "bob", 1), 10).unwrap();
        let capacity =
            registry.grant_capacity(IssuerKeyId::from_bytes([1; 16]), &profile("bob"), 10);
        assert_eq!(capacity.active_global(), 2);
        assert_eq!(capacity.active_for_issuer(), 2);
        assert_eq!(capacity.active_for_profile(), 1);
        assert!(
            registry
                .active_grant(SessionGrantId::from_bytes([2; 16]), 10)
                .is_some()
        );
        assert!(registry.revoke_grant(SessionGrantId::from_bytes([2; 16])));
        assert!(
            registry
                .active_grant(SessionGrantId::from_bytes([2; 16]), 20)
                .is_none()
        );
    }

    #[test]
    fn every_grant_quota_denies_without_evicting_active_grants() {
        let issuer_registry = InMemorySessionAuthorizationRegistry::new();
        for id in 0..u16::try_from(MAX_GRANTS_PER_ISSUER).unwrap() {
            issuer_registry
                .issue_grant(
                    grant_with_version(id, &format!("issuer-{id:03}"), 1, 1 + u32::from(id % 2)),
                    10,
                )
                .unwrap();
        }
        assert_eq!(
            issuer_registry.issue_grant(grant(200, "issuer-overflow", 1), 10),
            Err(LocalServiceTransportError::GrantLimitReached)
        );
        assert!(
            issuer_registry
                .active_grant(SessionGrantId::from_bytes([0; 16]), 10)
                .is_some()
        );

        let profile_registry = InMemorySessionAuthorizationRegistry::new();
        for id in 0..u16::try_from(MAX_GRANTS_PER_PROFILE).unwrap() {
            profile_registry
                .issue_grant(
                    grant(id, "shared-profile", u8::try_from(id + 1).unwrap()),
                    10,
                )
                .unwrap();
        }
        assert_eq!(
            profile_registry.issue_grant(grant(201, "shared-profile", 99), 10),
            Err(LocalServiceTransportError::GrantLimitReached)
        );

        let global_registry = InMemorySessionAuthorizationRegistry::new();
        for id in 0..u16::try_from(MAX_SESSION_GRANTS).unwrap() {
            let issuer = if usize::from(id) < MAX_GRANTS_PER_ISSUER {
                1
            } else {
                2
            };
            global_registry
                .issue_grant(grant(id, &format!("global-{id:03}"), issuer), 10)
                .unwrap();
        }
        assert_eq!(
            global_registry.issue_grant(grant(300, "global-overflow", 3), 10),
            Err(LocalServiceTransportError::GrantLimitReached)
        );
    }

    #[test]
    fn an_issuer_registration_is_exact() {
        let registry = InMemorySessionAuthorizationRegistry::new();
        let registration = IssuerRegistration::new(
            Ed25519PublicKey::from_bytes([7; 32]),
            HarnessKind::Generic,
            ProfileAuthorization::Namespace(profile("session")),
        );
        registry
            .register_issuer(
                IssuerKeyId::from_bytes([8; 16]),
                IssuerKeyVersion::new(1).unwrap(),
                registration.clone(),
            )
            .unwrap();
        assert_eq!(
            registry.active_issuer(
                IssuerKeyId::from_bytes([8; 16]),
                IssuerKeyVersion::new(1).unwrap()
            ),
            Some(registration)
        );
    }
}
