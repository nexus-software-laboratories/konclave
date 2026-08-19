use std::path::{Path, PathBuf};

use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveDomainCore::RoutingId;
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
}

impl TestRelay {
    pub async fn new(wildcard: bool) -> Self {
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
        write_access_file(&access_path, &token, &route_grant);
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
        }
    }
}

fn write_access_file(path: &Path, token: &[u8; RelayPrincipalId::LENGTH], route: &str) {
    let principal = RelayPrincipalId::from_access_token(token);
    std::fs::write(
        path,
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
        .unwrap(),
    )
    .unwrap();
}
