use std::collections::BTreeSet;

use KonclaveA2AContracts::InitialA2AAgentSecurityKind;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::A2AGatewayError;

const BEARER_PRINCIPAL_DOMAIN: &[u8] = b"konclave-a2a-http-bearer-principal-v1\0";
const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 512;
const MAX_STATIC_BEARER_CREDENTIALS: usize = 64;

/// Protected A2A HTTP operation presented to deployment authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum A2AHttpAction {
    /// Create or reconcile one task.
    SendMessage,
    /// Read one exact task.
    GetTask,
    /// Read the configured authenticated extended card.
    GetExtendedAgentCard,
    /// Reach a standard operation excluded from the advertised profile.
    UnsupportedOperation,
}

/// Opaque authenticated HTTP principal identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct A2AHttpPrincipalId([u8; 32]);

impl A2AHttpPrincipalId {
    /// Creates one deployment-selected opaque principal identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque principal bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Explicit deployment authorization result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum A2AHttpAuthorizationDecision {
    /// Permit the operation.
    Allow,
    /// Deny the operation.
    Deny,
    /// Authorization cannot currently make a reliable decision.
    Unavailable,
}

/// HTTP authentication and authorization boundary.
///
/// Custom mutual-TLS implementations may read certificate identity placed in request
/// extensions by trusted TLS middleware. Raw identity or credentials do not enter
/// gateway application state.
pub trait A2AHttpAccess: Send + Sync {
    /// Returns the authentication mechanism represented by this access boundary.
    fn authentication_kind(&self) -> Option<InitialA2AAgentSecurityKind>;

    /// Authenticates one HTTP request before its body is read.
    ///
    /// # Errors
    ///
    /// Returns an opaque unauthenticated error without credential details.
    fn authenticate(&self, request: &Parts) -> Result<A2AHttpPrincipalId, A2AGatewayError>;

    /// Authorizes one authenticated principal for an exact protected operation.
    fn authorize(
        &self,
        principal: A2AHttpPrincipalId,
        action: A2AHttpAction,
    ) -> A2AHttpAuthorizationDecision;
}

/// Secret Bearer credential consumed while building static access.
pub struct A2ABearerCredential(Zeroizing<String>);

impl A2ABearerCredential {
    /// Parses one bounded visible-ASCII Bearer token.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for short, oversized, whitespace-containing, or
    /// non-visible token values.
    pub fn parse(value: impl Into<String>) -> Result<Self, A2AGatewayError> {
        let value = Zeroizing::new(value.into());
        if value.len() < MIN_BEARER_TOKEN_BYTES
            || value.len() > MAX_BEARER_TOKEN_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        Ok(Self(value))
    }

    pub(crate) fn into_secret(self) -> Zeroizing<String> {
        self.0
    }
}

/// Startup-loaded static Bearer authentication that stores only token-derived
/// principals.
pub struct StaticBearerAccess {
    principals: BTreeSet<A2AHttpPrincipalId>,
}

impl StaticBearerAccess {
    /// Builds static access from one or more unique high-entropy Bearer credentials.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for an empty, oversized, or duplicate set.
    pub fn new(
        credentials: impl IntoIterator<Item = A2ABearerCredential>,
    ) -> Result<Self, A2AGatewayError> {
        let mut principals = BTreeSet::new();
        for credential in credentials {
            if principals.len() == MAX_STATIC_BEARER_CREDENTIALS
                || !principals.insert(principal_from_token(credential.0.as_bytes()))
            {
                return Err(A2AGatewayError::InvalidConfiguration);
            }
        }
        if principals.is_empty() {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        Ok(Self { principals })
    }
}

impl A2AHttpAccess for StaticBearerAccess {
    fn authentication_kind(&self) -> Option<InitialA2AAgentSecurityKind> {
        Some(InitialA2AAgentSecurityKind::Bearer)
    }

    fn authenticate(&self, request: &Parts) -> Result<A2AHttpPrincipalId, A2AGatewayError> {
        let mut values = request.headers.get_all(AUTHORIZATION).iter();
        let value = values.next().ok_or(A2AGatewayError::Unauthenticated)?;
        if values.next().is_some() {
            return Err(A2AGatewayError::Unauthenticated);
        }
        let value = value
            .to_str()
            .map_err(|_| A2AGatewayError::Unauthenticated)?;
        let (scheme, token) = value
            .split_once(' ')
            .ok_or(A2AGatewayError::Unauthenticated)?;
        if !scheme.eq_ignore_ascii_case("Bearer")
            || token.len() < MIN_BEARER_TOKEN_BYTES
            || token.len() > MAX_BEARER_TOKEN_BYTES
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        {
            return Err(A2AGatewayError::Unauthenticated);
        }
        let principal = principal_from_token(token.as_bytes());
        if self.principals.contains(&principal) {
            Ok(principal)
        } else {
            Err(A2AGatewayError::Unauthenticated)
        }
    }

    fn authorize(
        &self,
        _principal: A2AHttpPrincipalId,
        _action: A2AHttpAction,
    ) -> A2AHttpAuthorizationDecision {
        A2AHttpAuthorizationDecision::Allow
    }
}

fn principal_from_token(token: &[u8]) -> A2AHttpPrincipalId {
    let mut digest = Sha256::new();
    digest.update(BEARER_PRINCIPAL_DOMAIN);
    digest.update(token);
    A2AHttpPrincipalId(digest.finalize().into())
}
