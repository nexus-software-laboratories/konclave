//! Proves the Unix endpoint contract over real sockets rather than in-memory pipes.
//!
//! ADR 0008 requires an owner-restricted local endpoint with no TCP listener of any
//! kind. Owner-only directory creation, link rejection, stale-socket replacement, live
//! endpoint protection, and kernel peer credentials are all filesystem behaviors, so
//! they are exercised against an actual socket in a temporary directory.

#![cfg(unix)]

mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use KonclaveLocalServiceTransport::{
    LocalServiceEndpoint, LocalServiceListener, LocalServiceTransportError, connect_local_service,
};
use support::AttachFixture;

struct Rendezvous {
    _root: tempfile::TempDir,
    directory: PathBuf,
}

impl Rendezvous {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("runtime");
        Self {
            _root: root,
            directory,
        }
    }

    fn endpoint(&self) -> LocalServiceEndpoint {
        LocalServiceEndpoint::parse(self.directory.join("service.sock").to_str().unwrap()).unwrap()
    }

    fn path(&self) -> PathBuf {
        self.directory.join("service.sock")
    }

    fn create_directory(&self, mode: u32) {
        std::fs::create_dir_all(&self.directory).unwrap();
        std::fs::set_permissions(&self.directory, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[tokio::test]
async fn binding_creates_an_owner_only_directory_and_socket() {
    let rendezvous = Rendezvous::new();
    let listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();

    assert_eq!(listener.endpoint(), &rendezvous.endpoint());
    assert_eq!(mode_of(&rendezvous.directory), 0o700);
    assert_eq!(mode_of(&rendezvous.path()), 0o600);
    assert_eq!(
        std::fs::symlink_metadata(rendezvous.path()).unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
}

#[tokio::test]
async fn an_authorized_client_attaches_over_a_real_socket() {
    let rendezvous = Rendezvous::new();
    let fixture = AttachFixture::for_profiles(&["alice"]);
    let mut listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();

    let service = async {
        let mut accepted = listener.accept().await.unwrap();
        fixture.attach_service(&mut accepted).await
    };
    let client = async {
        let mut connection = connect_local_service(&rendezvous.endpoint()).await.unwrap();
        fixture.attach_client(&mut connection, 0).await
    };

    let (service, client) = tokio::join!(service, client);
    assert_eq!(service.unwrap().binding(), client.unwrap().binding());
}

#[tokio::test]
async fn two_clients_attach_at_the_same_time_and_keep_separate_bindings() {
    let rendezvous = Rendezvous::new();
    let fixture = AttachFixture::for_profiles(&["alice", "bob"]);
    let mut listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();

    let service = async {
        let mut bindings = Vec::new();
        for _ in 0..2 {
            let mut accepted = listener.accept().await.unwrap();
            bindings.push(
                fixture
                    .attach_service(&mut accepted)
                    .await
                    .unwrap()
                    .binding()
                    .clone(),
            );
        }
        bindings
    };
    let clients = async {
        let mut first = connect_local_service(&rendezvous.endpoint()).await.unwrap();
        let mut second = connect_local_service(&rendezvous.endpoint()).await.unwrap();
        let first = fixture.attach_client(&mut first, 0).await.unwrap();
        let second = fixture.attach_client(&mut second, 1).await.unwrap();
        (first, second)
    };

    let (mut bindings, (first, second)) = tokio::join!(service, clients);
    bindings.sort_by(|left, right| left.profile().as_str().cmp(right.profile().as_str()));
    assert_eq!(bindings[0].profile().as_str(), "alice");
    assert_eq!(bindings[1].profile().as_str(), "bob");
    assert_eq!(first.binding().profile().as_str(), "alice");
    assert_eq!(second.binding().profile().as_str(), "bob");
    assert_ne!(first.binding(), second.binding());
}

#[tokio::test]
async fn a_directory_reachable_by_another_account_is_refused() {
    let rendezvous = Rendezvous::new();
    rendezvous.create_directory(0o750);

    assert_eq!(
        LocalServiceListener::bind(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointNotOwnerProtected
    );
}

#[tokio::test]
async fn a_symbolic_link_in_place_of_the_endpoint_is_refused() {
    let rendezvous = Rendezvous::new();
    rendezvous.create_directory(0o700);
    let target = rendezvous.directory.join("elsewhere.sock");
    std::os::unix::fs::symlink(&target, rendezvous.path()).unwrap();

    assert_eq!(
        LocalServiceListener::bind(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointNotOwnerProtected
    );
    assert!(
        std::fs::symlink_metadata(rendezvous.path())
            .unwrap()
            .file_type()
            .is_symlink(),
        "an unsafe endpoint must never be removed"
    );
}

#[tokio::test]
async fn a_symbolic_link_in_place_of_the_endpoint_directory_is_refused() {
    let rendezvous = Rendezvous::new();
    let real = rendezvous._root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, &rendezvous.directory).unwrap();

    assert_eq!(
        LocalServiceListener::bind(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointNotOwnerProtected
    );
}

#[tokio::test]
async fn an_ordinary_file_in_place_of_the_endpoint_is_refused_and_kept() {
    let rendezvous = Rendezvous::new();
    rendezvous.create_directory(0o700);
    std::fs::write(rendezvous.path(), b"not a socket").unwrap();

    assert_eq!(
        LocalServiceListener::bind(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointNotOwnerProtected
    );
    assert_eq!(
        std::fs::read(rendezvous.path()).unwrap(),
        b"not a socket".to_vec()
    );
}

#[tokio::test]
async fn a_live_endpoint_is_never_taken_over_by_a_second_service() {
    let rendezvous = Rendezvous::new();
    let _listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();

    assert_eq!(
        LocalServiceListener::bind(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointInUse
    );
}

#[tokio::test]
async fn a_clean_shutdown_removes_the_socket_by_exact_path() {
    let rendezvous = Rendezvous::new();
    let listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();
    assert!(std::fs::symlink_metadata(rendezvous.path()).is_ok());

    drop(listener);
    assert!(
        std::fs::symlink_metadata(rendezvous.path()).is_err(),
        "a clean shutdown must not leave an endpoint that looks live"
    );
    assert!(
        std::fs::symlink_metadata(&rendezvous.directory).is_ok(),
        "only the socket is removed, not the runtime directory"
    );
}

#[tokio::test]
async fn a_stale_socket_from_a_crashed_service_is_replaced() {
    let rendezvous = Rendezvous::new();
    rendezvous.create_directory(0o700);

    // A crashed service leaves its socket behind, because neither the standard
    // library nor tokio unlinks a bound path when the process disappears.
    let crashed = tokio::net::UnixListener::bind(rendezvous.path()).unwrap();
    drop(crashed);
    assert!(std::fs::symlink_metadata(rendezvous.path()).is_ok());

    let listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();
    assert_eq!(mode_of(&rendezvous.path()), 0o600);
    drop(listener);
}

#[tokio::test]
async fn connecting_refuses_an_endpoint_that_is_not_an_owned_socket() {
    let rendezvous = Rendezvous::new();
    rendezvous.create_directory(0o700);

    assert_eq!(
        connect_local_service(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointUnavailable
    );

    std::fs::write(rendezvous.path(), b"not a socket").unwrap();
    assert_eq!(
        connect_local_service(&rendezvous.endpoint())
            .await
            .unwrap_err(),
        LocalServiceTransportError::EndpointNotOwnerProtected
    );

    std::fs::remove_file(rendezvous.path()).unwrap();
    let real = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();
    let link = rendezvous.directory.join("link.sock");
    std::os::unix::fs::symlink(rendezvous.path(), &link).unwrap();
    let linked = LocalServiceEndpoint::parse(link.to_str().unwrap()).unwrap();
    assert_eq!(
        connect_local_service(&linked).await.unwrap_err(),
        LocalServiceTransportError::EndpointNotOwnerProtected
    );
    drop(real);
}

#[tokio::test]
async fn a_failure_never_discloses_the_endpoint_path() {
    let rendezvous = Rendezvous::new();
    let error = connect_local_service(&rendezvous.endpoint())
        .await
        .unwrap_err();

    let rendered = format!("{error}");
    assert!(
        !rendered.contains(rendezvous.path().to_str().unwrap()),
        "endpoint failure must not disclose a private path: {rendered}"
    );
    assert_eq!(error.code(), "local_service_endpoint_unavailable");
}

#[tokio::test]
async fn peer_ownership_is_enforced_for_every_accepted_connection() {
    let rendezvous = Rendezvous::new();
    let mut listener = LocalServiceListener::bind(&rendezvous.endpoint())
        .await
        .unwrap();

    let service = async { listener.accept().await };
    let client = async { connect_local_service(&rendezvous.endpoint()).await };
    let (accepted, connected) = tokio::join!(service, client);

    accepted.unwrap();
    connected.unwrap();
}
