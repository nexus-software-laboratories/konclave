use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use KonclaveDomainCore::RoutingId;
use KonclaveRelayCore::{RelayAuthorizer, RelayError, RelayPermission, RelayPrincipalId};
use anyhow::{Context, ensure};
use async_trait::async_trait;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use zeroize::Zeroizing;

const ACCESS_DOCUMENT_VERSION: u32 = 1;
const MAX_ACCESS_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_PRINCIPALS: usize = 1_024;
const MAX_GRANTS_PER_PRINCIPAL: usize = 1_024;
const MAX_TOTAL_GRANTS: usize = 8_192;

/// Bounded, startup-loaded bearer authentication and route authorization.
#[derive(Clone)]
pub struct StaticRelayAccess {
    grants: Arc<BTreeMap<RelayPrincipalId, BTreeSet<Grant>>>,
}

impl StaticRelayAccess {
    /// Loads a versioned access document without retaining any bearer token.
    ///
    /// This is a blocking startup operation. Async callers must place it on a
    /// blocking executor.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read within its hard size bound or
    /// contains unsupported, malformed, duplicate, or empty authorization data.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("opening relay access file {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take((MAX_ACCESS_DOCUMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading relay access file {}", path.display()))?;
        ensure!(
            bytes.len() <= MAX_ACCESS_DOCUMENT_BYTES,
            "relay access document exceeds {MAX_ACCESS_DOCUMENT_BYTES} bytes"
        );
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() <= MAX_ACCESS_DOCUMENT_BYTES,
            "relay access document exceeds {MAX_ACCESS_DOCUMENT_BYTES} bytes"
        );
        let document: AccessDocument =
            serde_json::from_slice(bytes).context("parsing relay access document")?;
        ensure!(
            document.version == ACCESS_DOCUMENT_VERSION,
            "unsupported relay access document version"
        );
        ensure!(
            !document.principals.is_empty() && document.principals.len() <= MAX_PRINCIPALS,
            "relay access principal count is outside the supported range"
        );

        let mut grants_by_principal = BTreeMap::new();
        let mut total_grants = 0_usize;
        for principal in document.principals {
            ensure!(
                !principal.grants.is_empty() && principal.grants.len() <= MAX_GRANTS_PER_PRINCIPAL,
                "relay access grant count is outside the supported range"
            );
            let principal_id = decode_principal_id(&principal.principal)?;
            let mut grants = BTreeSet::new();
            for grant in principal.grants {
                ensure!(
                    !grant.permissions.is_empty() && grant.permissions.len() <= 3,
                    "relay access permission count is outside the supported range"
                );
                let route = decode_route(&grant.route)?;
                for permission in grant.permissions {
                    ensure!(
                        grants.insert(Grant {
                            route,
                            permission: permission.into(),
                        }),
                        "relay access document contains a duplicate grant"
                    );
                    total_grants = total_grants
                        .checked_add(1)
                        .context("relay access grant count overflow")?;
                    ensure!(
                        total_grants <= MAX_TOTAL_GRANTS,
                        "relay access document contains too many grants"
                    );
                }
            }
            ensure!(
                grants_by_principal.insert(principal_id, grants).is_none(),
                "relay access document contains a duplicate principal"
            );
        }
        Ok(Self {
            grants: Arc::new(grants_by_principal),
        })
    }

    /// Authenticates exactly one standard bearer header.
    ///
    /// # Errors
    ///
    /// Returns an opaque authentication error for missing, duplicated, malformed,
    /// incorrectly sized, or unconfigured credentials.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<RelayPrincipalId, RelayAuthenticationError> {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let value = values.next().ok_or(RelayAuthenticationError)?;
        if values.next().is_some() {
            return Err(RelayAuthenticationError);
        }
        let value = value.to_str().map_err(|_| RelayAuthenticationError)?;
        let (scheme, encoded_token) = value.split_once(' ').ok_or(RelayAuthenticationError)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || encoded_token.len() != 43
            || encoded_token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(RelayAuthenticationError);
        }
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded_token)
                .map_err(|_| RelayAuthenticationError)?,
        );
        let token = Zeroizing::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| RelayAuthenticationError)?,
        );
        let principal = RelayPrincipalId::from_access_token(&token);
        if self.grants.contains_key(&principal) {
            Ok(principal)
        } else {
            Err(RelayAuthenticationError)
        }
    }
}

#[async_trait]
impl RelayAuthorizer for StaticRelayAccess {
    async fn authorize(
        &self,
        principal: RelayPrincipalId,
        routing_id: RoutingId,
        permission: RelayPermission,
    ) -> Result<(), RelayError> {
        let authorized = self.grants.get(&principal).is_some_and(|grants| {
            grants.contains(&Grant {
                route: RouteGrant::Any,
                permission,
            }) || grants.contains(&Grant {
                route: RouteGrant::Exact(routing_id),
                permission,
            })
        });
        if authorized {
            Ok(())
        } else {
            Err(RelayError::Unauthorized)
        }
    }
}

/// Opaque bearer-authentication failure that never formats credential material.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("relay authentication failed")]
pub struct RelayAuthenticationError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Grant {
    route: RouteGrant,
    permission: RelayPermission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RouteGrant {
    Any,
    Exact(RoutingId),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessDocument {
    version: u32,
    principals: Vec<PrincipalDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalDocument {
    principal: String,
    grants: Vec<GrantDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantDocument {
    route: String,
    permissions: Vec<PermissionDocument>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PermissionDocument {
    Send,
    Replay,
    Acknowledge,
}

impl From<PermissionDocument> for RelayPermission {
    fn from(value: PermissionDocument) -> Self {
        match value {
            PermissionDocument::Send => Self::Send,
            PermissionDocument::Replay => Self::Replay,
            PermissionDocument::Acknowledge => Self::Acknowledge,
        }
    }
}

fn decode_principal_id(value: &str) -> anyhow::Result<RelayPrincipalId> {
    let bytes = decode_fixed(value, RelayPrincipalId::LENGTH, "relay principal")?;
    RelayPrincipalId::from_slice(&bytes).context("validating relay principal")
}

fn decode_route(value: &str) -> anyhow::Result<RouteGrant> {
    if value == "*" {
        return Ok(RouteGrant::Any);
    }
    let bytes = decode_fixed(value, RoutingId::LENGTH, "relay route")?;
    Ok(RouteGrant::Exact(
        RoutingId::from_slice(&bytes).context("validating relay route")?,
    ))
}

fn decode_fixed(value: &str, expected: usize, field: &'static str) -> anyhow::Result<Vec<u8>> {
    let expected_encoded_length = (expected * 8).div_ceil(6);
    ensure!(
        value.len() == expected_encoded_length,
        "{field} has an invalid encoded length"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("decoding {field}"))?;
    ensure!(bytes.len() == expected, "{field} has an invalid length");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use KonclaveRelayCore::RelayAuthorizer;
    use axum::http::HeaderValue;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    use super::*;

    fn access(token: &[u8; RelayPrincipalId::LENGTH], route: &str) -> StaticRelayAccess {
        let principal = RelayPrincipalId::from_access_token(token);
        StaticRelayAccess::from_bytes(
            serde_json::to_vec(&json!({
                "version": 1,
                "principals": [{
                    "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                    "grants": [{
                        "route": route,
                        "permissions": ["send", "replay", "acknowledge"]
                    }]
                }]
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap()
    }

    fn bearer(token: &[u8; RelayPrincipalId::LENGTH]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", URL_SAFE_NO_PAD.encode(token))).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn authenticates_configured_tokens_and_enforces_route_grants() {
        let token = [7; RelayPrincipalId::LENGTH];
        let route = RoutingId::from_bytes([8; RoutingId::LENGTH]);
        let access = access(&token, &URL_SAFE_NO_PAD.encode(route.as_bytes()));
        let principal = access.authenticate(&bearer(&token)).unwrap();
        assert_eq!(principal, RelayPrincipalId::from_access_token(&token));
        assert!(
            access
                .authorize(principal, route, RelayPermission::Send)
                .await
                .is_ok()
        );
        assert_eq!(
            access
                .authorize(
                    principal,
                    RoutingId::from_bytes([9; RoutingId::LENGTH]),
                    RelayPermission::Send,
                )
                .await,
            Err(RelayError::Unauthorized)
        );
    }

    #[test]
    fn rejects_unconfigured_malformed_and_duplicated_credentials() {
        let token = [3; RelayPrincipalId::LENGTH];
        let access = access(&token, "*");
        assert!(access.authenticate(&HeaderMap::new()).is_err());
        assert!(
            access
                .authenticate(&bearer(&[4; RelayPrincipalId::LENGTH]))
                .is_err()
        );

        let mut malformed = HeaderMap::new();
        malformed.insert(AUTHORIZATION, HeaderValue::from_static("Basic ignored"));
        assert!(access.authenticate(&malformed).is_err());
        malformed.insert(AUTHORIZATION, HeaderValue::from_static("Bearer YWJj"));
        assert!(access.authenticate(&malformed).is_err());

        let mut duplicated = bearer(&token);
        duplicated.append(AUTHORIZATION, HeaderValue::from_static("Bearer duplicated"));
        assert!(access.authenticate(&duplicated).is_err());
    }

    #[test]
    fn rejects_unknown_versions_fields_and_duplicate_grants() {
        for document in [
            json!({"version": 2, "principals": []}),
            json!({"version": 1, "unexpected": true, "principals": []}),
        ] {
            assert!(
                StaticRelayAccess::from_bytes(&serde_json::to_vec(&document).unwrap()).is_err()
            );
        }

        let token = [5; RelayPrincipalId::LENGTH];
        let principal = RelayPrincipalId::from_access_token(&token);
        let duplicate = json!({
            "version": 1,
            "principals": [{
                "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                "grants": [
                    {"route": "*", "permissions": ["send"]},
                    {"route": "*", "permissions": ["send"]}
                ]
            }]
        });
        assert!(StaticRelayAccess::from_bytes(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    }

    #[tokio::test]
    async fn wildcard_grants_still_require_a_configured_principal() {
        let token = [6; RelayPrincipalId::LENGTH];
        let access = access(&token, "*");
        let principal = access.authenticate(&bearer(&token)).unwrap();
        assert!(
            access
                .authorize(
                    principal,
                    RoutingId::from_bytes([1; RoutingId::LENGTH]),
                    RelayPermission::Replay,
                )
                .await
                .is_ok()
        );
    }

    #[test]
    fn file_loading_rejects_documents_over_the_byte_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.json");
        std::fs::write(&path, vec![b' '; MAX_ACCESS_DOCUMENT_BYTES + 1]).unwrap();
        assert!(StaticRelayAccess::load(&path).is_err());
    }
}
