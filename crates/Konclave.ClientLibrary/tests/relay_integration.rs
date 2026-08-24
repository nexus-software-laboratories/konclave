use std::net::SocketAddr;
use std::time::Duration;

use KonclaveClientLibrary::{
    EnrollmentRequestId, HttpRelayEnrollmentTransport, KonclaveClientError, RelayAccessCredential,
    RelayClient, RelayEndpoint, RelayEnrollmentClient, RelayEnrollmentCredential,
    RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayTransport,
};
use KonclaveCommunityRelay::access::StaticRelayAccess;
use KonclaveCommunityRelay::application::RelayApplication;
use KonclaveCommunityRelay::http::{HttpState, router};
use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, EnvelopeId, ProtocolVersion, RelayEnvelope, ReplayRequest,
    RoutingId,
};
use KonclaveRelayCore::RelayPrincipalId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

struct TestServer {
    _directory: TempDir,
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<()>,
    route: RoutingId,
    token: [u8; RelayPrincipalId::LENGTH],
    enrollment_token: Option<Zeroizing<[u8; RelayEnrollmentCredential::LENGTH]>>,
}

impl TestServer {
    async fn start(wildcard: bool) -> Self {
        let route = RoutingId::from_bytes([8; RoutingId::LENGTH]);
        let token = [7; RelayPrincipalId::LENGTH];
        let principal = RelayPrincipalId::from_access_token(&token);
        let route_grant = if wildcard {
            "*".to_string()
        } else {
            URL_SAFE_NO_PAD.encode(route.as_bytes())
        };
        let access_document = json!({
            "version": 1,
            "principals": [{
                "principal": URL_SAFE_NO_PAD.encode(principal.as_bytes()),
                "grants": [{
                    "route": route_grant,
                    "permissions": ["send", "replay", "acknowledge"]
                }]
            }]
        });
        Self::start_with_access(access_document, None).await
    }

    async fn start_enrollment() -> Self {
        let enrollment_token = Zeroizing::new([12; RelayEnrollmentCredential::LENGTH]);
        let authority =
            KonclaveRelayAuthentication::RelayEnrollmentAuthorityId::from_enrollment_token(
                &enrollment_token,
            );
        let access_document = json!({
            "version": 2,
            "principals": [],
            "enrollment": {
                "authority": URL_SAFE_NO_PAD.encode(authority.as_bytes())
            }
        });
        Self::start_with_access(access_document, Some(enrollment_token)).await
    }

    async fn start_with_access(
        access_document: serde_json::Value,
        enrollment_token: Option<Zeroizing<[u8; RelayEnrollmentCredential::LENGTH]>>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("relay.sqlite");
        let access_path = directory.path().join("access.json");
        let route = RoutingId::from_bytes([8; RoutingId::LENGTH]);
        let token = [7; RelayPrincipalId::LENGTH];
        std::fs::write(&access_path, serde_json::to_vec(&access_document).unwrap()).unwrap();
        let access = StaticRelayAccess::load(&access_path).unwrap();
        let application = RelayApplication::connect(&database_path, access.clone())
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(
                    HttpState::new("relay-client-test", application),
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
            address,
            shutdown,
            server,
            route,
            token,
            enrollment_token,
        }
    }

    fn client(&self) -> RelayClient {
        RelayClient::new(
            RelayEndpoint::parse(&format!("http://{}", self.address)).unwrap(),
            RelayAccessCredential::from_bytes(self.token),
        )
        .unwrap()
    }

    fn enrollment_client(&self) -> RelayEnrollmentClient<HttpRelayEnrollmentTransport> {
        RelayEnrollmentClient::new(
            HttpRelayEnrollmentTransport::new(
                RelayEndpoint::parse(&format!("http://{}", self.address)).unwrap(),
                RelayEnrollmentCredential::from_bytes(**self.enrollment_token.as_ref().unwrap()),
            )
            .unwrap(),
        )
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        timeout(Duration::from_secs(1), self.server)
            .await
            .unwrap()
            .unwrap();
    }
}

fn envelope(route: RoutingId, id: u8, payload: u8) -> RelayEnvelope {
    RelayEnvelope::new(
        ProtocolVersion::application_v1(),
        route,
        EnvelopeId::from_bytes([id; EnvelopeId::LENGTH]),
        DeliveryClass::GroupApplication,
        None,
        u64::MAX / 2,
        vec![payload],
    )
    .unwrap()
}

#[tokio::test]
async fn client_submits_replays_and_acknowledges_idempotently() {
    let server = TestServer::start(true).await;
    let client = server.client();
    let envelope = envelope(server.route, 1, 10);
    assert_eq!(client.submit(&envelope).await.unwrap().cursor(), 1);
    assert_eq!(client.submit(&envelope).await.unwrap().cursor(), 1);

    let replay = client
        .replay(ReplayRequest::new(server.route, 0, 100).unwrap())
        .await
        .unwrap();
    assert_eq!(replay.envelopes().len(), 1);
    assert_eq!(replay.next_cursor(), 1);
    assert_eq!(
        client
            .acknowledge(AcknowledgeRequest::new(server.route, 1).unwrap())
            .await
            .unwrap()
            .cursor(),
        1
    );
    server.stop().await;
}

#[tokio::test]
async fn client_enrolls_and_activates_one_independent_data_plane_principal() {
    let server = TestServer::start_enrollment().await;
    let request = RelayEnrollmentRequest::new(
        ProtocolVersion::application_v1(),
        EnrollmentRequestId::from_bytes([4; EnrollmentRequestId::LENGTH]),
        RelayPrincipalId::from_access_token(&server.token),
    );
    let enrollment = server.enrollment_client();
    let wrong_enrollment = RelayEnrollmentClient::new(
        HttpRelayEnrollmentTransport::new(
            RelayEndpoint::parse(&format!("http://{}", server.address)).unwrap(),
            RelayEnrollmentCredential::from_bytes([13; RelayEnrollmentCredential::LENGTH]),
        )
        .unwrap(),
    );

    assert!(matches!(
        wrong_enrollment.register(request).await.unwrap_err(),
        KonclaveClientError::RelayRejected {
            status: 401,
            ref relay_code
        } if relay_code == "relay_authentication_failed"
    ));
    assert_eq!(
        enrollment.register(request).await.unwrap().outcome(),
        RelayEnrollmentOutcome::Registered
    );
    assert_eq!(
        enrollment.register(request).await.unwrap().outcome(),
        RelayEnrollmentOutcome::AlreadyRegistered
    );
    assert_eq!(
        server
            .client()
            .submit(&envelope(server.route, 5, 50))
            .await
            .unwrap()
            .cursor(),
        1
    );

    server.stop().await;
}

#[tokio::test]
async fn client_watch_receives_live_and_reconnected_replay() {
    let server = TestServer::start(true).await;
    let client = server.client();
    let mut watch = client
        .connect_watch(ReplayRequest::new(server.route, 0, 100).unwrap())
        .await
        .unwrap();
    assert!(watch.next_page().await.unwrap().envelopes().is_empty());

    client.submit(&envelope(server.route, 2, 20)).await.unwrap();
    let live = watch.next_page().await.unwrap();
    assert_eq!(live.next_cursor(), 1);
    assert_eq!(live.envelopes()[0].envelope().payload(), &[20]);
    watch.close().await.unwrap();

    client.submit(&envelope(server.route, 3, 30)).await.unwrap();
    let mut reconnected = client
        .connect_watch(ReplayRequest::new(server.route, 1, 100).unwrap())
        .await
        .unwrap();
    let missed = reconnected.next_page().await.unwrap();
    assert_eq!(missed.next_cursor(), 2);
    assert_eq!(missed.envelopes()[0].envelope().payload(), &[30]);
    reconnected.close().await.unwrap();
    server.stop().await;
}

#[tokio::test]
async fn client_surfaces_stable_route_denial_without_response_text() {
    let server = TestServer::start(false).await;
    let client = server.client();
    let error = client
        .submit(&envelope(
            RoutingId::from_bytes([4; RoutingId::LENGTH]),
            4,
            40,
        ))
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        KonclaveClientError::RelayRejected {
            status: 403,
            ref relay_code
        } if relay_code == "relay_unauthorized"
    ));
    server.stop().await;
}

#[tokio::test]
async fn client_watch_surfaces_stable_route_denial() {
    let server = TestServer::start(false).await;
    let client = server.client();
    let mut watch = client
        .connect_watch(
            ReplayRequest::new(RoutingId::from_bytes([4; RoutingId::LENGTH]), 0, 100).unwrap(),
        )
        .await
        .unwrap();
    let error = watch.next_page().await.err().unwrap();
    assert!(matches!(
        error,
        KonclaveClientError::WatchRejected {
            close_code: 1008,
            ref relay_code
        } if relay_code == "relay_unauthorized"
    ));
    server.stop().await;
}
