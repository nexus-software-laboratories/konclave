//! Proves the handshake over a real local endpoint rather than an in-memory pipe.
//!
//! ADR 0005 requires the adapter to own the endpoint and the daemon to connect
//! outward, so the daemon never opens a listener. Running the exchange over an actual
//! socket is what demonstrates that direction.

#![cfg(unix)]

use std::path::PathBuf;

use KonclaveAdapterTransport::{
    AdapterEndpoint, AdapterTransportError, LaunchCapability, SequentialChallenges,
    complete_adapter_handshake, complete_daemon_handshake, connect_adapter_endpoint,
};

const PROFILE: &str = "alice";
const CONSUMER: &str = "01HQ8Z3K";

fn capability(seed: u8) -> LaunchCapability {
    LaunchCapability::from_bytes([seed; LaunchCapability::LENGTH])
}

struct AdapterRendezvous {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl AdapterRendezvous {
    /// Creates the owner-only private directory and socket path an adapter owns.
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        restrict_to_owner(directory.path());
        let path = directory.path().join("adapter.sock");
        Self {
            _directory: directory,
            path,
        }
    }

    fn endpoint(&self) -> AdapterEndpoint {
        AdapterEndpoint::parse(self.path.to_str().unwrap()).unwrap()
    }
}

fn restrict_to_owner(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn the_daemon_connects_outward_and_both_sides_authenticate() {
    let rendezvous = AdapterRendezvous::new();
    let listener = tokio::net::UnixListener::bind(&rendezvous.path).unwrap();
    restrict_to_owner(&rendezvous.path);

    let adapter = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        complete_adapter_handshake(
            &mut stream,
            PROFILE,
            CONSUMER,
            &capability(9),
            &mut SequentialChallenges::new(),
        )
        .await
    });

    let mut connection = connect_adapter_endpoint(&rendezvous.endpoint())
        .await
        .unwrap();
    let daemon = complete_daemon_handshake(
        &mut connection,
        PROFILE,
        &capability(9),
        &mut SequentialChallenges::new(),
    )
    .await
    .unwrap();

    let adapter = adapter.await.unwrap().unwrap();
    assert_eq!(daemon.profile(), PROFILE);
    assert_eq!(daemon.consumer(), CONSUMER);
    assert_eq!(adapter.consumer(), CONSUMER);
}

#[tokio::test]
async fn a_wrong_capability_fails_over_a_real_endpoint() {
    let rendezvous = AdapterRendezvous::new();
    let listener = tokio::net::UnixListener::bind(&rendezvous.path).unwrap();
    restrict_to_owner(&rendezvous.path);

    let adapter = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        complete_adapter_handshake(
            &mut stream,
            PROFILE,
            CONSUMER,
            &capability(8),
            &mut SequentialChallenges::new(),
        )
        .await
    });

    let mut connection = connect_adapter_endpoint(&rendezvous.endpoint())
        .await
        .unwrap();
    let daemon = complete_daemon_handshake(
        &mut connection,
        PROFILE,
        &capability(9),
        &mut SequentialChallenges::new(),
    )
    .await;

    assert_eq!(
        adapter.await.unwrap().unwrap_err(),
        AdapterTransportError::UnauthenticPeer
    );
    assert!(daemon.is_err());
}

#[tokio::test]
async fn a_stale_endpoint_fails_without_disclosing_its_path() {
    let rendezvous = AdapterRendezvous::new();
    // The adapter exited without cleaning up, so the path exists but nothing listens.
    std::fs::write(&rendezvous.path, b"").unwrap();

    let error = connect_adapter_endpoint(&rendezvous.endpoint())
        .await
        .unwrap_err();

    assert_eq!(error, AdapterTransportError::EndpointUnavailable);
    let rendered = format!("{error}");
    assert!(
        !rendered.contains(rendezvous.path.to_str().unwrap()),
        "endpoint failure must not disclose the adapter-private path: {rendered}"
    );
}

#[tokio::test]
async fn an_absent_endpoint_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint =
        AdapterEndpoint::parse(directory.path().join("absent.sock").to_str().unwrap()).unwrap();

    assert_eq!(
        connect_adapter_endpoint(&endpoint).await.unwrap_err(),
        AdapterTransportError::EndpointUnavailable
    );
}
