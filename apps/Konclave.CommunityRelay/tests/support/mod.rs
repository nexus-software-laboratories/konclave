use std::path::{Path, PathBuf};

use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveDomainCore::RoutingId;
use KonclaveRelayAuthentication::RelayEnrollmentAuthorityId;
use KonclaveRelayCore::RelayPrincipalId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use tempfile::TempDir;

pub struct TestRelay {
    _directory: TempDir,
    pub access: StaticRelayAccess,
    pub application: RelayApplication,
    #[allow(dead_code)]
    pub database_path: PathBuf,
    #[allow(dead_code)]
    pub route: RoutingId,
    pub token: [u8; RelayPrincipalId::LENGTH],
    #[allow(dead_code)]
    pub enrollment_token: Option<[u8; RelayEnrollmentAuthorityId::LENGTH]>,
}

impl TestRelay {
    pub async fn new(wildcard: bool) -> Self {
        Self::build(wildcard, None).await
    }

    #[allow(dead_code)]
    pub async fn with_enrollment(wildcard: bool) -> Self {
        Self::build(wildcard, Some([6; RelayEnrollmentAuthorityId::LENGTH])).await
    }

    async fn build(
        wildcard: bool,
        enrollment_token: Option<[u8; RelayEnrollmentAuthorityId::LENGTH]>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("relay.sqlite");
        let access_path = directory.path().join("access.json");
        let route = RoutingId::from_bytes([8; RoutingId::LENGTH]);
        let token = [7; RelayPrincipalId::LENGTH];
        let route_grant = if wildcard {
            "*".to_string()
        } else {
            URL_SAFE_NO_PAD.encode(route.as_bytes())
        };
        write_access_file(
            &access_path,
            &token,
            &route_grant,
            enrollment_token.as_ref(),
        );
        let access = StaticRelayAccess::load(&access_path).unwrap();
        let application = RelayApplication::connect(&database_path, access.clone())
            .await
            .unwrap();
        Self {
            _directory: directory,
            access,
            application,
            database_path,
            route,
            token,
            enrollment_token,
        }
    }
}

fn write_access_file(
    path: &Path,
    token: &[u8; RelayPrincipalId::LENGTH],
    route: &str,
    enrollment_token: Option<&[u8; RelayEnrollmentAuthorityId::LENGTH]>,
) {
    let principal = RelayPrincipalId::from_access_token(token);
    let enrollment = enrollment_token.map(|token| {
        let authority = RelayEnrollmentAuthorityId::from_enrollment_token(token);
        json!({
            "authority": URL_SAFE_NO_PAD.encode(authority.as_bytes())
        })
    });
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "version": if enrollment.is_some() { 2 } else { 1 },
            "principals": [{
                "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                "grants": [{
                    "route": route,
                    "permissions": ["send", "replay", "acknowledge"]
                }]
            }],
            "enrollment": enrollment
        }))
        .unwrap(),
    )
    .unwrap();
}
