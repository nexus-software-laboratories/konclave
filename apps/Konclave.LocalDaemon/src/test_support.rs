use KonclaveClientLibrary::RelayEnrollmentAuthorityId;
use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveRelayCore::RelayPrincipalId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

pub(crate) struct TestRelay {
    _directory: tempfile::TempDir,
    pub(crate) endpoint: String,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<()>,
}

impl TestRelay {
    pub(crate) async fn start_static(token: [u8; RelayPrincipalId::LENGTH]) -> Self {
        let principal = RelayPrincipalId::from_access_token(&token);
        Self::start(json!({
            "version": 1,
            "principals": [{
                "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                "grants": [{
                    "route": "*",
                    "permissions": ["send", "replay", "acknowledge"]
                }]
            }]
        }))
        .await
    }

    pub(crate) async fn start_enrollment(token: [u8; RelayEnrollmentAuthorityId::LENGTH]) -> Self {
        let authority = RelayEnrollmentAuthorityId::from_enrollment_token(&token);
        Self::start(json!({
            "version": 2,
            "principals": [],
            "enrollment": {
                "authority": URL_SAFE_NO_PAD.encode(authority.as_bytes())
            }
        }))
        .await
    }

    async fn start(access_document: serde_json::Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let access_path = directory.path().join("access.json");
        std::fs::write(&access_path, serde_json::to_vec(&access_document).unwrap()).unwrap();
        let access = StaticRelayAccess::load(&access_path).unwrap();
        let application =
            RelayApplication::connect(&directory.path().join("relay.sqlite"), access.clone())
                .await
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(
                    HttpState::new("local-daemon-test", application),
                    access,
                    shutdown_rx.clone(),
                ),
            )
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        });
        Self {
            _directory: directory,
            endpoint: format!("http://{address}"),
            shutdown,
            server,
        }
    }

    pub(crate) async fn stop(self) {
        self.shutdown.send(true).unwrap();
        timeout(Duration::from_secs(2), self.server)
            .await
            .unwrap()
            .unwrap();
    }
}
