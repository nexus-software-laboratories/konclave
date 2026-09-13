#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Pure request binding and lifecycle decisions for challenge-bound user presence.
//!
//! Platform authenticators, WebAuthn parsing, durable storage, transport, and grant
//! issuance remain outside this crate. Callers provide already validated transport
//! identifiers and provider-verification results, while this crate keeps the exact
//! request, expiry, replay, and recovery decisions deterministic.

use core::fmt;

use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceSet, AuthorizationPolicyVersion, ClientInstanceId, HarnessKind,
    IssuerKeyId, IssuerKeyVersion, RequestId, ServiceProfileId, SessionCapabilities,
    SessionGrantId,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod webauthn;

pub use webauthn::{
    MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES, NativeWebAuthnAuthentication, NativeWebAuthnCredential,
    NativeWebAuthnEnrollment, NativeWebAuthnRequest, UserPresenceWebAuthnError,
    UserPresenceWebAuthnVerifier, native_user_presence_supported, perform_native_authentication,
    perform_native_authentication_json, perform_native_registration,
    perform_native_registration_json,
};

const BINDING_DOMAIN: &[u8] = b"konclave.user-presence.binding.v1\0";

/// Current canonical user-presence binding version.
pub const USER_PRESENCE_BINDING_VERSION: u16 = 1;

/// Required byte length of one fresh WebAuthn challenge.
pub const USER_PRESENCE_CHALLENGE_LENGTH: usize = 32;

/// Required byte length of one issuer-connection identifier.
pub const USER_PRESENCE_CONNECTION_ID_LENGTH: usize = 16;

/// Required byte length of binding, credential, and assertion digests.
pub const USER_PRESENCE_DIGEST_LENGTH: usize = 32;

/// Largest accepted provider identifier.
pub const MAX_USER_PRESENCE_PROVIDER_ID_LENGTH: usize = 64;

/// Largest accepted WebAuthn credential identifier.
pub const MAX_USER_PRESENCE_CREDENTIAL_ID_LENGTH: usize = 1024;

/// Longest service challenge lifetime.
pub const MAX_USER_PRESENCE_CHALLENGE_MILLISECONDS: u64 = 120_000;

/// Longest grant lifetime one presence ceremony may authorize.
pub const MAX_USER_PRESENCE_GRANT_MILLISECONDS: u64 = 3_600_000;

/// Longest period in which an exact ambiguous completion may recover its grant.
pub const MAX_USER_PRESENCE_RECOVERY_MILLISECONDS: u64 = 600_000;

/// Stable failures from user-presence request validation and lifecycle decisions.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum UserPresenceError {
    /// A provider identifier is empty, oversized, or noncanonical.
    #[error("user-presence provider identifier is invalid")]
    InvalidProviderId,
    /// A credential identifier is empty or oversized.
    #[error("user-presence credential identifier is invalid")]
    InvalidCredentialId,
    /// Challenge, grant, or recovery timestamps violate their finite bounds.
    #[error("user-presence time window is invalid")]
    InvalidTimeWindow,
    /// A request or verification timestamp precedes its issuance.
    #[error("user-presence request is not yet valid")]
    NotYetValid,
    /// The pending challenge reached its exclusive expiry.
    #[error("user-presence challenge expired")]
    ChallengeExpired,
    /// Completion arrived on another connection before durable commit.
    #[error("user-presence connection does not match")]
    ConnectionMismatch,
    /// Completion names another exact request binding.
    #[error("user-presence binding does not match")]
    BindingMismatch,
    /// Completion names another WebAuthn challenge.
    #[error("user-presence challenge does not match")]
    ChallengeMismatch,
    /// Verified evidence came from another provider.
    #[error("user-presence provider does not match")]
    ProviderMismatch,
    /// Verified evidence came from another enrolled credential.
    #[error("user-presence credential does not match")]
    CredentialMismatch,
    /// Verified evidence does not match the presented assertion.
    #[error("user-presence assertion does not match")]
    AssertionMismatch,
    /// The request was explicitly cancelled.
    #[error("user-presence request was cancelled")]
    Cancelled,
    /// Policy, issuer, provider, or another authority change invalidated the request.
    #[error("user-presence request was invalidated")]
    Invalidated,
    /// A consumed proof was presented with changed context.
    #[error("user-presence proof replay does not match the committed request")]
    Replay,
    /// The exact terminal result aged out of its recovery window.
    #[error("user-presence recovery window expired")]
    RecoveryExpired,
    /// The requested lifecycle event is not valid from the current state.
    #[error("user-presence lifecycle transition is invalid")]
    InvalidTransition,
    /// A canonical variable-length field exceeds its wire encoding.
    #[error("user-presence binding cannot be encoded")]
    InvalidEncoding,
}

/// Random identifier for the authenticated issuer connection that owns a challenge.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserPresenceConnectionId([u8; USER_PRESENCE_CONNECTION_ID_LENGTH]);

impl UserPresenceConnectionId {
    /// Wraps one exact connection identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; USER_PRESENCE_CONNECTION_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; USER_PRESENCE_CONNECTION_ID_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for UserPresenceConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserPresenceConnectionId")
            .finish_non_exhaustive()
    }
}

/// Fresh random WebAuthn challenge generated by the trusted verifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserPresenceChallenge([u8; USER_PRESENCE_CHALLENGE_LENGTH]);

impl UserPresenceChallenge {
    /// Wraps one exact challenge.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; USER_PRESENCE_CHALLENGE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the challenge bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; USER_PRESENCE_CHALLENGE_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for UserPresenceChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserPresenceChallenge")
            .finish_non_exhaustive()
    }
}

macro_rules! define_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; USER_PRESENCE_DIGEST_LENGTH]);

        impl $name {
            /// Wraps one exact SHA-256 digest.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; USER_PRESENCE_DIGEST_LENGTH]) -> Self {
                Self(bytes)
            }

            /// Returns the digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; USER_PRESENCE_DIGEST_LENGTH] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .finish_non_exhaustive()
            }
        }
    };
}

define_digest!(
    /// SHA-256 digest of one complete canonical presence binding.
    UserPresenceBindingDigest
);

define_digest!(
    /// SHA-256 digest of one enrolled WebAuthn credential identifier.
    UserPresenceCredentialDigest
);

define_digest!(
    /// SHA-256 digest of one complete opaque authenticator assertion.
    UserPresenceAssertionDigest
);

impl UserPresenceAssertionDigest {
    /// Hashes one complete assertion carrier for exact retry identity.
    #[must_use]
    pub fn sha256(assertion: &[u8]) -> Self {
        Self::from_bytes(Sha256::digest(assertion).into())
    }
}

/// Canonical identifier of one installed user-presence provider.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserPresenceProviderId(String);

impl UserPresenceProviderId {
    /// Parses one bounded lowercase provider identifier.
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceError::InvalidProviderId`] unless the value begins with
    /// a lowercase ASCII letter or digit and contains only lowercase ASCII letters,
    /// digits, `.`, `_`, or `-`.
    pub fn parse(value: &str) -> Result<Self, UserPresenceError> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_USER_PRESENCE_PROVIDER_ID_LENGTH
            || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(UserPresenceError::InvalidProviderId);
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque WebAuthn credential identifier retained only by trusted local state.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserPresenceCredentialId(Vec<u8>);

impl UserPresenceCredentialId {
    /// Creates one bounded nonempty credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceError::InvalidCredentialId`] for an empty or oversized
    /// value.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, UserPresenceError> {
        if bytes.is_empty() || bytes.len() > MAX_USER_PRESENCE_CREDENTIAL_ID_LENGTH {
            return Err(UserPresenceError::InvalidCredentialId);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque credential identifier.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the fixed digest used in canonical request bindings.
    #[must_use]
    pub fn digest(&self) -> UserPresenceCredentialDigest {
        UserPresenceCredentialDigest::from_bytes(Sha256::digest(&self.0).into())
    }
}

impl fmt::Debug for UserPresenceCredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserPresenceCredentialId")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Complete validated claims whose digest is proved by the ephemeral session key.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPresenceBindingClaims {
    /// Exact live issuer connection that receives the pending challenge.
    pub connection_id: UserPresenceConnectionId,
    /// Random WebAuthn challenge generated for this request.
    pub challenge: UserPresenceChallenge,
    /// Installation fingerprint that owns provider enrollment.
    pub installation_fingerprint: [u8; USER_PRESENCE_DIGEST_LENGTH],
    /// Pinned local-service identity.
    pub service_public_key: Ed25519PublicKey,
    /// Installed issuer requesting the grant.
    pub issuer_key_id: IssuerKeyId,
    /// Exact active issuer key version.
    pub issuer_key_version: IssuerKeyVersion,
    /// Stable issuer instance retained across an ambiguous exact retry.
    pub issuer_client_instance: ClientInstanceId,
    /// Stable operation identifier retained across an ambiguous exact retry.
    pub request_id: RequestId,
    /// Effective policy version the ceremony authorizes.
    pub policy_version: AuthorizationPolicyVersion,
    /// Exact canonical profile the grant may operate.
    pub profile: ServiceProfileId,
    /// Ephemeral session key whose private half proves the binding.
    pub session_public_key: Ed25519PublicKey,
    /// Exact harness metadata recorded in the grant.
    pub harness: HarnessKind,
    /// Exact verified evidence set recorded in the grant.
    pub evidence: AuthorizationEvidenceSet,
    /// Exact capability bitset recorded in the grant.
    pub capabilities: SessionCapabilities,
    /// Installed provider selected by the service.
    pub provider_id: UserPresenceProviderId,
    /// Digest of the exact enrolled credential selected by the service.
    pub credential_digest: UserPresenceCredentialDigest,
    /// Inclusive service issuance timestamp.
    pub issued_at_unix_milliseconds: u64,
    /// Exclusive pending-challenge expiry.
    pub challenge_expires_at_unix_milliseconds: u64,
    /// Exclusive expiry of the resulting grant.
    pub grant_expires_at_unix_milliseconds: u64,
}

/// Canonical immutable binding for one exact user-presence request.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPresenceBinding {
    claims: UserPresenceBindingClaims,
    canonical: Vec<u8>,
    digest: UserPresenceBindingDigest,
}

impl UserPresenceBinding {
    /// Validates all finite windows and freezes canonical binding bytes.
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceError::InvalidTimeWindow`] when a challenge or grant is
    /// empty, reversed, or longer than its hard bound. Returns
    /// [`UserPresenceError::InvalidEncoding`] when a variable field cannot use the
    /// canonical two-byte length.
    pub fn new(claims: UserPresenceBindingClaims) -> Result<Self, UserPresenceError> {
        validate_time_window(&claims)?;
        let canonical = encode_binding(&claims)?;
        let digest = UserPresenceBindingDigest::from_bytes(Sha256::digest(&canonical).into());
        Ok(Self {
            claims,
            canonical,
            digest,
        })
    }

    /// Returns the complete validated claims.
    #[must_use]
    pub const fn claims(&self) -> &UserPresenceBindingClaims {
        &self.claims
    }

    /// Returns the immutable canonical bytes signed by the ephemeral session key.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the fixed digest that identifies this exact request.
    #[must_use]
    pub const fn digest(&self) -> UserPresenceBindingDigest {
        self.digest
    }
}

/// One pending connection-bound user-presence request.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingUserPresenceRequest {
    binding: UserPresenceBinding,
}

impl PendingUserPresenceRequest {
    /// Creates a pending request from one validated immutable binding.
    #[must_use]
    pub fn new(binding: UserPresenceBinding) -> Self {
        Self { binding }
    }

    /// Returns the exact request binding.
    #[must_use]
    pub const fn binding(&self) -> &UserPresenceBinding {
        &self.binding
    }
}

/// Metadata produced only after the platform verifier accepts an assertion.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedUserPresenceAssertion {
    challenge: UserPresenceChallenge,
    provider_id: UserPresenceProviderId,
    credential_digest: UserPresenceCredentialDigest,
    assertion_digest: UserPresenceAssertionDigest,
    verified_at_unix_milliseconds: u64,
}

impl VerifiedUserPresenceAssertion {
    /// Records the exact output of a trusted provider verifier.
    ///
    /// This constructor does not verify cryptography. The platform verifier that owns
    /// WebAuthn parsing and signature validation is the only production caller.
    #[must_use]
    pub fn new(
        challenge: UserPresenceChallenge,
        provider_id: UserPresenceProviderId,
        credential_digest: UserPresenceCredentialDigest,
        assertion_digest: UserPresenceAssertionDigest,
        verified_at_unix_milliseconds: u64,
    ) -> Self {
        Self {
            challenge,
            provider_id,
            credential_digest,
            assertion_digest,
            verified_at_unix_milliseconds,
        }
    }
}

/// Untrusted completion metadata presented to the lifecycle classifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserPresencePresentation {
    connection_id: UserPresenceConnectionId,
    binding_digest: UserPresenceBindingDigest,
    challenge: UserPresenceChallenge,
    assertion_digest: UserPresenceAssertionDigest,
}

impl UserPresencePresentation {
    /// Creates one exact completion presentation.
    #[must_use]
    pub const fn new(
        connection_id: UserPresenceConnectionId,
        binding_digest: UserPresenceBindingDigest,
        challenge: UserPresenceChallenge,
        assertion_digest: UserPresenceAssertionDigest,
    ) -> Self {
        Self {
            connection_id,
            binding_digest,
            challenge,
            assertion_digest,
        }
    }
}

/// Durable terminal metadata that can recover one already issued grant.
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedUserPresenceRequest {
    binding_digest: UserPresenceBindingDigest,
    challenge: UserPresenceChallenge,
    assertion_digest: UserPresenceAssertionDigest,
    grant_id: SessionGrantId,
    recovery_expires_at_unix_milliseconds: u64,
}

impl CommittedUserPresenceRequest {
    /// Returns the issued grant identifier.
    #[must_use]
    pub const fn grant_id(&self) -> SessionGrantId {
        self.grant_id
    }

    /// Returns the exclusive exact-result recovery expiry.
    #[must_use]
    pub const fn recovery_expires_at_unix_milliseconds(&self) -> u64 {
        self.recovery_expires_at_unix_milliseconds
    }
}

/// Persisted request states relevant to completion and exact retry.
#[derive(Clone, PartialEq, Eq)]
pub enum UserPresenceRequestRecord {
    /// The provider assertion has not been verified or consumed.
    Pending(Box<PendingUserPresenceRequest>),
    /// The exact assertion already issued one durable grant.
    Committed(CommittedUserPresenceRequest),
    /// The owner or client cancelled the pending request.
    Cancelled,
    /// The pending challenge expired before commit.
    Expired,
    /// An authority change invalidated the pending request.
    Invalidated,
}

/// Safe next action selected from one request record and presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPresenceCompletionDecision {
    /// The connection and request match; invoke the platform verifier once.
    VerifyProvider,
    /// Return the already committed grant without issuing another.
    RecoverGrant(SessionGrantId),
}

/// Classifies a first completion or an exact terminal retry.
///
/// # Errors
///
/// Returns a finite mismatch, expiry, terminal, or replay failure. A pending request
/// is connection-bound. A committed exact result can be recovered on a replacement
/// authenticated connection until its recovery deadline.
pub fn classify_completion(
    record: &UserPresenceRequestRecord,
    presentation: UserPresencePresentation,
    now_unix_milliseconds: u64,
) -> Result<UserPresenceCompletionDecision, UserPresenceError> {
    match record {
        UserPresenceRequestRecord::Pending(pending) => {
            classify_pending(pending, presentation, now_unix_milliseconds)?;
            Ok(UserPresenceCompletionDecision::VerifyProvider)
        }
        UserPresenceRequestRecord::Committed(committed) => {
            if now_unix_milliseconds >= committed.recovery_expires_at_unix_milliseconds {
                return Err(UserPresenceError::RecoveryExpired);
            }
            if presentation.binding_digest != committed.binding_digest
                || presentation.challenge != committed.challenge
                || presentation.assertion_digest != committed.assertion_digest
            {
                return Err(UserPresenceError::Replay);
            }
            Ok(UserPresenceCompletionDecision::RecoverGrant(
                committed.grant_id,
            ))
        }
        UserPresenceRequestRecord::Cancelled => Err(UserPresenceError::Cancelled),
        UserPresenceRequestRecord::Expired => Err(UserPresenceError::ChallengeExpired),
        UserPresenceRequestRecord::Invalidated => Err(UserPresenceError::Invalidated),
    }
}

/// Consumes one verified assertion into exact terminal recovery metadata.
///
/// # Errors
///
/// Returns a finite mismatch or time-window error unless the presentation, verified
/// provider output, pending binding, grant, and recovery window all agree exactly.
pub fn commit_verified_assertion(
    pending: PendingUserPresenceRequest,
    presentation: UserPresencePresentation,
    verified: VerifiedUserPresenceAssertion,
    grant_id: SessionGrantId,
    now_unix_milliseconds: u64,
    recovery_expires_at_unix_milliseconds: u64,
) -> Result<CommittedUserPresenceRequest, UserPresenceError> {
    classify_pending(&pending, presentation, now_unix_milliseconds)?;
    let claims = pending.binding.claims();
    if verified.challenge != claims.challenge {
        return Err(UserPresenceError::ChallengeMismatch);
    }
    if verified.provider_id != claims.provider_id {
        return Err(UserPresenceError::ProviderMismatch);
    }
    if verified.credential_digest != claims.credential_digest {
        return Err(UserPresenceError::CredentialMismatch);
    }
    if verified.assertion_digest != presentation.assertion_digest {
        return Err(UserPresenceError::AssertionMismatch);
    }
    if verified.verified_at_unix_milliseconds < claims.issued_at_unix_milliseconds
        || verified.verified_at_unix_milliseconds > now_unix_milliseconds
    {
        return Err(UserPresenceError::NotYetValid);
    }
    if verified.verified_at_unix_milliseconds >= claims.challenge_expires_at_unix_milliseconds {
        return Err(UserPresenceError::ChallengeExpired);
    }
    let maximum_recovery = now_unix_milliseconds
        .checked_add(MAX_USER_PRESENCE_RECOVERY_MILLISECONDS)
        .ok_or(UserPresenceError::InvalidTimeWindow)?;
    if recovery_expires_at_unix_milliseconds <= now_unix_milliseconds
        || recovery_expires_at_unix_milliseconds > maximum_recovery
        || recovery_expires_at_unix_milliseconds > claims.grant_expires_at_unix_milliseconds
    {
        return Err(UserPresenceError::InvalidTimeWindow);
    }
    Ok(CommittedUserPresenceRequest {
        binding_digest: pending.binding.digest(),
        challenge: claims.challenge,
        assertion_digest: verified.assertion_digest,
        grant_id,
        recovery_expires_at_unix_milliseconds,
    })
}

/// Finite lifecycle states used by durable and in-memory implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPresenceLifecycleState {
    /// Awaiting a provider assertion.
    Pending,
    /// Provider verification succeeded but grant commit has not completed.
    Verified,
    /// One exact grant and terminal recovery result were committed.
    Committed,
    /// The request was explicitly cancelled.
    Cancelled,
    /// The challenge expired before commit.
    Expired,
    /// A policy, issuer, credential, or provider change invalidated the request.
    Invalidated,
}

/// Closed events that move one user-presence request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPresenceLifecycleEvent {
    /// The platform verifier accepted the exact assertion.
    ProviderVerified,
    /// Grant issuance and terminal recovery metadata committed atomically.
    GrantCommitted,
    /// The owner or client cancelled the request.
    Cancel,
    /// The challenge deadline elapsed.
    DeadlineElapsed,
    /// An authorization authority changed.
    AuthorityChanged,
}

/// Applies one pure user-presence lifecycle transition.
///
/// # Errors
///
/// Returns [`UserPresenceError::InvalidTransition`] for every transition not listed
/// by the closed state machine.
pub const fn transition(
    state: UserPresenceLifecycleState,
    event: UserPresenceLifecycleEvent,
) -> Result<UserPresenceLifecycleState, UserPresenceError> {
    use UserPresenceLifecycleEvent::{
        AuthorityChanged, Cancel, DeadlineElapsed, GrantCommitted, ProviderVerified,
    };
    use UserPresenceLifecycleState::{
        Cancelled, Committed, Expired, Invalidated, Pending, Verified,
    };

    match (state, event) {
        (Pending, ProviderVerified) => Ok(Verified),
        (Verified, GrantCommitted) => Ok(Committed),
        (Pending | Verified, Cancel) => Ok(Cancelled),
        (Pending | Verified, DeadlineElapsed) => Ok(Expired),
        (Pending | Verified, AuthorityChanged) => Ok(Invalidated),
        _ => Err(UserPresenceError::InvalidTransition),
    }
}

fn validate_time_window(claims: &UserPresenceBindingClaims) -> Result<(), UserPresenceError> {
    let maximum_challenge = claims
        .issued_at_unix_milliseconds
        .checked_add(MAX_USER_PRESENCE_CHALLENGE_MILLISECONDS)
        .ok_or(UserPresenceError::InvalidTimeWindow)?;
    let maximum_grant = claims
        .issued_at_unix_milliseconds
        .checked_add(MAX_USER_PRESENCE_GRANT_MILLISECONDS)
        .ok_or(UserPresenceError::InvalidTimeWindow)?;
    if claims.challenge_expires_at_unix_milliseconds <= claims.issued_at_unix_milliseconds
        || claims.challenge_expires_at_unix_milliseconds > maximum_challenge
        || claims.grant_expires_at_unix_milliseconds <= claims.issued_at_unix_milliseconds
        || claims.grant_expires_at_unix_milliseconds > maximum_grant
        || claims.challenge_expires_at_unix_milliseconds > claims.grant_expires_at_unix_milliseconds
    {
        return Err(UserPresenceError::InvalidTimeWindow);
    }
    Ok(())
}

fn encode_binding(claims: &UserPresenceBindingClaims) -> Result<Vec<u8>, UserPresenceError> {
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(BINDING_DOMAIN);
    bytes.extend_from_slice(&USER_PRESENCE_BINDING_VERSION.to_be_bytes());
    bytes.extend_from_slice(claims.connection_id.as_bytes());
    bytes.extend_from_slice(claims.challenge.as_bytes());
    bytes.extend_from_slice(&claims.installation_fingerprint);
    bytes.extend_from_slice(claims.service_public_key.as_bytes());
    bytes.extend_from_slice(claims.issuer_key_id.as_bytes());
    bytes.extend_from_slice(&claims.issuer_key_version.get().to_be_bytes());
    bytes.extend_from_slice(claims.issuer_client_instance.as_bytes());
    bytes.extend_from_slice(claims.request_id.as_bytes());
    bytes.extend_from_slice(&claims.policy_version.get().to_be_bytes());
    append_length_prefixed(&mut bytes, claims.profile.as_str().as_bytes())?;
    bytes.extend_from_slice(claims.session_public_key.as_bytes());
    bytes.extend_from_slice(&claims.harness.wire_value().to_be_bytes());
    bytes.push(claims.evidence.bits());
    bytes.extend_from_slice(&claims.capabilities.bits().to_be_bytes());
    append_length_prefixed(&mut bytes, claims.provider_id.as_str().as_bytes())?;
    bytes.extend_from_slice(claims.credential_digest.as_bytes());
    bytes.extend_from_slice(&claims.issued_at_unix_milliseconds.to_be_bytes());
    bytes.extend_from_slice(&claims.challenge_expires_at_unix_milliseconds.to_be_bytes());
    bytes.extend_from_slice(&claims.grant_expires_at_unix_milliseconds.to_be_bytes());
    Ok(bytes)
}

fn append_length_prefixed(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), UserPresenceError> {
    let length = u16::try_from(value.len()).map_err(|_| UserPresenceError::InvalidEncoding)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn classify_pending(
    pending: &PendingUserPresenceRequest,
    presentation: UserPresencePresentation,
    now_unix_milliseconds: u64,
) -> Result<(), UserPresenceError> {
    let claims = pending.binding.claims();
    if now_unix_milliseconds < claims.issued_at_unix_milliseconds {
        return Err(UserPresenceError::NotYetValid);
    }
    if now_unix_milliseconds >= claims.challenge_expires_at_unix_milliseconds {
        return Err(UserPresenceError::ChallengeExpired);
    }
    if presentation.connection_id != claims.connection_id {
        return Err(UserPresenceError::ConnectionMismatch);
    }
    if presentation.binding_digest != pending.binding.digest() {
        return Err(UserPresenceError::BindingMismatch);
    }
    if presentation.challenge != claims.challenge {
        return Err(UserPresenceError::ChallengeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUED_AT: u64 = 1_700_000_000_000;

    fn credential() -> UserPresenceCredentialId {
        UserPresenceCredentialId::from_bytes(vec![0x09; 32]).unwrap()
    }

    fn claims() -> UserPresenceBindingClaims {
        UserPresenceBindingClaims {
            connection_id: UserPresenceConnectionId::from_bytes([0x01; 16]),
            challenge: UserPresenceChallenge::from_bytes([0x02; 32]),
            installation_fingerprint: [0x03; 32],
            service_public_key: Ed25519PublicKey::from_bytes([0x04; 32]),
            issuer_key_id: IssuerKeyId::from_bytes([0x05; 16]),
            issuer_key_version: IssuerKeyVersion::new(7).unwrap(),
            issuer_client_instance: ClientInstanceId::from_bytes([0x06; 16]),
            request_id: RequestId::from_bytes([0x07; 16]),
            policy_version: AuthorizationPolicyVersion::new(8).unwrap(),
            profile: ServiceProfileId::parse("session-test").unwrap(),
            session_public_key: Ed25519PublicKey::from_bytes([0x08; 32]),
            harness: HarnessKind::Copilot,
            evidence: AuthorizationEvidenceSet::new([
                KonclaveLocalServiceTransport::AuthorizationEvidenceKind::UserPresence,
            ])
            .unwrap(),
            capabilities: SessionCapabilities::ALL,
            provider_id: UserPresenceProviderId::parse("windows-native-webauthn-v1").unwrap(),
            credential_digest: credential().digest(),
            issued_at_unix_milliseconds: ISSUED_AT,
            challenge_expires_at_unix_milliseconds: ISSUED_AT + 60_000,
            grant_expires_at_unix_milliseconds: ISSUED_AT + 3_600_000,
        }
    }

    fn pending() -> PendingUserPresenceRequest {
        PendingUserPresenceRequest::new(UserPresenceBinding::new(claims()).unwrap())
    }

    fn assertion_digest(byte: u8) -> UserPresenceAssertionDigest {
        UserPresenceAssertionDigest::from_bytes([byte; 32])
    }

    fn presentation(pending: &PendingUserPresenceRequest) -> UserPresencePresentation {
        UserPresencePresentation::new(
            pending.binding().claims().connection_id,
            pending.binding().digest(),
            pending.binding().claims().challenge,
            assertion_digest(0x0a),
        )
    }

    #[test]
    fn provider_and_credential_identifiers_are_bounded() {
        let provider_cases = [
            ("windows-native-webauthn-v1", true),
            ("a", true),
            ("", false),
            ("Windows", false),
            ("-windows", false),
            ("windows/native", false),
        ];
        for (value, valid) in provider_cases {
            assert_eq!(
                UserPresenceProviderId::parse(value).is_ok(),
                valid,
                "{value}"
            );
        }
        assert!(
            UserPresenceProviderId::parse(&"a".repeat(MAX_USER_PRESENCE_PROVIDER_ID_LENGTH))
                .is_ok()
        );
        assert!(
            UserPresenceProviderId::parse(&"a".repeat(MAX_USER_PRESENCE_PROVIDER_ID_LENGTH + 1))
                .is_err()
        );

        let credential_cases = [
            (Vec::new(), false),
            (vec![1], true),
            (vec![1; MAX_USER_PRESENCE_CREDENTIAL_ID_LENGTH], true),
            (vec![1; MAX_USER_PRESENCE_CREDENTIAL_ID_LENGTH + 1], false),
        ];
        for (value, valid) in credential_cases {
            assert_eq!(UserPresenceCredentialId::from_bytes(value).is_ok(), valid);
        }
    }

    #[test]
    fn binding_time_windows_are_finite_and_ordered() {
        let cases = [
            (ISSUED_AT, ISSUED_AT + 1, false),
            (
                ISSUED_AT + MAX_USER_PRESENCE_CHALLENGE_MILLISECONDS + 1,
                ISSUED_AT + MAX_USER_PRESENCE_GRANT_MILLISECONDS,
                false,
            ),
            (ISSUED_AT + 2, ISSUED_AT + 1, false),
            (
                ISSUED_AT + 1,
                ISSUED_AT + MAX_USER_PRESENCE_GRANT_MILLISECONDS + 1,
                false,
            ),
            (
                ISSUED_AT + MAX_USER_PRESENCE_CHALLENGE_MILLISECONDS,
                ISSUED_AT + MAX_USER_PRESENCE_GRANT_MILLISECONDS,
                true,
            ),
        ];
        for (challenge_expiry, grant_expiry, valid) in cases {
            let mut candidate = claims();
            candidate.challenge_expires_at_unix_milliseconds = challenge_expiry;
            candidate.grant_expires_at_unix_milliseconds = grant_expiry;
            assert_eq!(UserPresenceBinding::new(candidate).is_ok(), valid);
        }

        let mut overflow = claims();
        overflow.issued_at_unix_milliseconds = u64::MAX;
        overflow.challenge_expires_at_unix_milliseconds = u64::MAX;
        overflow.grant_expires_at_unix_milliseconds = u64::MAX;
        assert_eq!(
            UserPresenceBinding::new(overflow).err(),
            Some(UserPresenceError::InvalidTimeWindow)
        );
    }

    #[test]
    fn canonical_binding_vector_is_stable() {
        let binding = UserPresenceBinding::new(claims()).unwrap();
        assert_eq!(binding.canonical_bytes().len(), 349);
        assert_eq!(
            binding.digest().as_bytes(),
            &[
                0x83, 0x6f, 0x5d, 0x2f, 0xe8, 0x8d, 0xbb, 0x3c, 0x1b, 0xea, 0x0e, 0x08, 0x5d, 0xb7,
                0xaa, 0x0a, 0x20, 0xbe, 0x8e, 0x47, 0x9b, 0x0c, 0x8e, 0xc3, 0xa5, 0xf5, 0x4d, 0xdd,
                0xa1, 0x5b, 0x44, 0xf2,
            ]
        );
    }

    #[test]
    fn pending_completion_requires_exact_live_binding() {
        let pending = pending();
        let exact = presentation(&pending);
        assert_eq!(
            classify_completion(
                &UserPresenceRequestRecord::Pending(Box::new(pending.clone())),
                exact,
                ISSUED_AT + 1,
            ),
            Ok(UserPresenceCompletionDecision::VerifyProvider)
        );

        let cases = [
            (
                UserPresencePresentation::new(
                    UserPresenceConnectionId::from_bytes([0x11; 16]),
                    pending.binding().digest(),
                    pending.binding().claims().challenge,
                    exact.assertion_digest,
                ),
                ISSUED_AT + 1,
                UserPresenceError::ConnectionMismatch,
            ),
            (
                UserPresencePresentation::new(
                    exact.connection_id,
                    UserPresenceBindingDigest::from_bytes([0x12; 32]),
                    exact.challenge,
                    exact.assertion_digest,
                ),
                ISSUED_AT + 1,
                UserPresenceError::BindingMismatch,
            ),
            (
                UserPresencePresentation::new(
                    exact.connection_id,
                    exact.binding_digest,
                    UserPresenceChallenge::from_bytes([0x13; 32]),
                    exact.assertion_digest,
                ),
                ISSUED_AT + 1,
                UserPresenceError::ChallengeMismatch,
            ),
            (exact, ISSUED_AT - 1, UserPresenceError::NotYetValid),
            (
                exact,
                ISSUED_AT + 60_000,
                UserPresenceError::ChallengeExpired,
            ),
        ];
        for (candidate, now, expected) in cases {
            assert_eq!(
                classify_completion(
                    &UserPresenceRequestRecord::Pending(Box::new(pending.clone())),
                    candidate,
                    now,
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn verified_completion_commits_once_and_recovers_exactly() {
        let pending = pending();
        let presentation = presentation(&pending);
        let verified = VerifiedUserPresenceAssertion::new(
            pending.binding().claims().challenge,
            pending.binding().claims().provider_id.clone(),
            pending.binding().claims().credential_digest,
            presentation.assertion_digest,
            ISSUED_AT + 2,
        );
        let grant_id = SessionGrantId::from_bytes([0x0b; 16]);
        let committed = commit_verified_assertion(
            pending,
            presentation,
            verified,
            grant_id,
            ISSUED_AT + 3,
            ISSUED_AT + 30_000,
        )
        .unwrap();
        let record = UserPresenceRequestRecord::Committed(committed);
        assert_eq!(
            classify_completion(&record, presentation, ISSUED_AT + 4),
            Ok(UserPresenceCompletionDecision::RecoverGrant(grant_id))
        );
        let replacement_connection = UserPresencePresentation::new(
            UserPresenceConnectionId::from_bytes([0xfe; 16]),
            presentation.binding_digest,
            presentation.challenge,
            presentation.assertion_digest,
        );
        assert_eq!(
            classify_completion(&record, replacement_connection, ISSUED_AT + 4),
            Ok(UserPresenceCompletionDecision::RecoverGrant(grant_id))
        );

        let replay = UserPresencePresentation::new(
            UserPresenceConnectionId::from_bytes([0xff; 16]),
            presentation.binding_digest,
            presentation.challenge,
            assertion_digest(0xff),
        );
        assert_eq!(
            classify_completion(&record, replay, ISSUED_AT + 4),
            Err(UserPresenceError::Replay)
        );
        assert_eq!(
            classify_completion(&record, presentation, ISSUED_AT + 30_000),
            Err(UserPresenceError::RecoveryExpired)
        );
    }

    #[test]
    fn commit_rejects_provider_substitution_and_invalid_recovery() {
        enum Mutation {
            Challenge,
            Provider,
            Credential,
            Assertion,
            VerifiedBeforeIssuance,
            VerifiedAfterNow,
            VerifiedAfterChallenge,
        }
        let cases = [
            (Mutation::Challenge, UserPresenceError::ChallengeMismatch),
            (Mutation::Provider, UserPresenceError::ProviderMismatch),
            (Mutation::Credential, UserPresenceError::CredentialMismatch),
            (Mutation::Assertion, UserPresenceError::AssertionMismatch),
            (
                Mutation::VerifiedBeforeIssuance,
                UserPresenceError::NotYetValid,
            ),
            (Mutation::VerifiedAfterNow, UserPresenceError::NotYetValid),
            (
                Mutation::VerifiedAfterChallenge,
                UserPresenceError::NotYetValid,
            ),
        ];
        for (mutation, expected) in cases {
            let pending = pending();
            let presentation = presentation(&pending);
            let claims = pending.binding().claims();
            let mut verified = VerifiedUserPresenceAssertion::new(
                claims.challenge,
                claims.provider_id.clone(),
                claims.credential_digest,
                presentation.assertion_digest,
                ISSUED_AT + 2,
            );
            match mutation {
                Mutation::Challenge => {
                    verified.challenge = UserPresenceChallenge::from_bytes([0x21; 32]);
                }
                Mutation::Provider => {
                    verified.provider_id = UserPresenceProviderId::parse("other").unwrap();
                }
                Mutation::Credential => {
                    verified.credential_digest =
                        UserPresenceCredentialDigest::from_bytes([0x22; 32]);
                }
                Mutation::Assertion => {
                    verified.assertion_digest = assertion_digest(0x23);
                }
                Mutation::VerifiedBeforeIssuance => {
                    verified.verified_at_unix_milliseconds = ISSUED_AT - 1;
                }
                Mutation::VerifiedAfterNow => {
                    verified.verified_at_unix_milliseconds = ISSUED_AT + 5;
                }
                Mutation::VerifiedAfterChallenge => {
                    verified.verified_at_unix_milliseconds = ISSUED_AT + 60_000;
                }
            }
            assert!(matches!(
                commit_verified_assertion(
                    pending,
                    presentation,
                    verified,
                    SessionGrantId::from_bytes([0x24; 16]),
                    ISSUED_AT + 4,
                    ISSUED_AT + 30_000,
                ),
                Err(actual) if actual == expected
            ));
        }

        let pending = pending();
        let presentation = presentation(&pending);
        let verified = VerifiedUserPresenceAssertion::new(
            pending.binding().claims().challenge,
            pending.binding().claims().provider_id.clone(),
            pending.binding().claims().credential_digest,
            presentation.assertion_digest,
            ISSUED_AT + 2,
        );
        assert!(matches!(
            commit_verified_assertion(
                pending,
                presentation,
                verified,
                SessionGrantId::from_bytes([0x25; 16]),
                ISSUED_AT + 4,
                ISSUED_AT + 4,
            ),
            Err(UserPresenceError::InvalidTimeWindow)
        ));
    }

    #[test]
    fn terminal_states_fail_closed() {
        let presentation = presentation(&pending());
        let cases = [
            (
                UserPresenceRequestRecord::Cancelled,
                UserPresenceError::Cancelled,
            ),
            (
                UserPresenceRequestRecord::Expired,
                UserPresenceError::ChallengeExpired,
            ),
            (
                UserPresenceRequestRecord::Invalidated,
                UserPresenceError::Invalidated,
            ),
        ];
        for (record, expected) in cases {
            assert_eq!(
                classify_completion(&record, presentation, ISSUED_AT + 1),
                Err(expected)
            );
        }
    }

    #[test]
    fn lifecycle_transitions_are_closed_and_table_driven() {
        use UserPresenceLifecycleEvent::{
            AuthorityChanged, Cancel, DeadlineElapsed, GrantCommitted, ProviderVerified,
        };
        use UserPresenceLifecycleState::{
            Cancelled, Committed, Expired, Invalidated, Pending, Verified,
        };

        let valid = [
            (Pending, ProviderVerified, Verified),
            (Verified, GrantCommitted, Committed),
            (Pending, Cancel, Cancelled),
            (Verified, Cancel, Cancelled),
            (Pending, DeadlineElapsed, Expired),
            (Verified, DeadlineElapsed, Expired),
            (Pending, AuthorityChanged, Invalidated),
            (Verified, AuthorityChanged, Invalidated),
        ];
        for (state, event, expected) in valid {
            assert_eq!(transition(state, event), Ok(expected));
        }

        let states = [
            Pending,
            Verified,
            Committed,
            Cancelled,
            Expired,
            Invalidated,
        ];
        let events = [
            ProviderVerified,
            GrantCommitted,
            Cancel,
            DeadlineElapsed,
            AuthorityChanged,
        ];
        for state in states {
            for event in events {
                let is_valid = valid.iter().any(|(candidate_state, candidate_event, _)| {
                    *candidate_state == state && *candidate_event == event
                });
                if !is_valid {
                    assert_eq!(
                        transition(state, event),
                        Err(UserPresenceError::InvalidTransition)
                    );
                }
            }
        }
    }

    #[test]
    fn sensitive_identifiers_do_not_render_their_bytes() {
        let credential = credential();
        assert_eq!(
            format!("{credential:?}"),
            "UserPresenceCredentialId { length: 32, .. }"
        );
        assert_eq!(
            format!("{:?}", UserPresenceChallenge::from_bytes([0xaa; 32])),
            "UserPresenceChallenge { .. }"
        );
        assert!(!format!("{credential:?}").contains("0909"));
    }
}
