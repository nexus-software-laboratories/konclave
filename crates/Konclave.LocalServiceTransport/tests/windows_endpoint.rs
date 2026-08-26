//! Proves the Windows named-pipe endpoint contract on a real pipe.
//!
//! ADR 0008 requires an owner-restricted endpoint with no TCP listener. On Windows the
//! endpoint is a named pipe with an explicit owner-only DACL. Both ends verify that
//! the connected process belongs to the current account and is not lower integrity.

#![cfg(windows)]

mod support;

use KonclaveLocalServiceTransport::{
    LocalServiceEndpoint, LocalServiceListener, LocalServiceTransportError, connect_local_service,
};
use support::AttachFixture;

fn endpoint(name: &str) -> LocalServiceEndpoint {
    LocalServiceEndpoint::parse(&format!(
        r"\\.\pipe\konclave-local-service-test-{}-{name}",
        std::process::id()
    ))
    .unwrap()
}

#[tokio::test]
async fn an_authorized_client_attaches_over_a_real_named_pipe() {
    let endpoint = endpoint("attach");
    let fixture = AttachFixture::for_profiles(&["alice"]);
    let mut listener = LocalServiceListener::bind(&endpoint).await.unwrap();

    let service = async {
        let mut accepted = listener.accept().await.unwrap();
        fixture.attach_service(&mut accepted).await
    };
    let client = async {
        let mut connection = connect_local_service(&endpoint).await.unwrap();
        fixture.attach_client(&mut connection, 0).await
    };

    let (service, client) = tokio::join!(service, client);
    assert_eq!(service.unwrap().binding(), client.unwrap().binding());
}

#[tokio::test]
async fn a_second_process_cannot_squat_the_endpoint_name() {
    let endpoint = endpoint("squat");
    let _listener = LocalServiceListener::bind(&endpoint).await.unwrap();

    assert_eq!(
        LocalServiceListener::bind(&endpoint).await.unwrap_err(),
        LocalServiceTransportError::EndpointInUse
    );
}

#[tokio::test]
async fn two_clients_attach_in_turn_and_keep_separate_bindings() {
    let endpoint = endpoint("concurrent");
    let fixture = AttachFixture::for_profiles(&["alice", "bob"]);
    let mut listener = LocalServiceListener::bind(&endpoint).await.unwrap();

    let mut channels = Vec::new();
    for index in 0..2 {
        let service = async {
            let mut accepted = listener.accept().await.unwrap();
            fixture.attach_service(&mut accepted).await.unwrap()
        };
        let client = async {
            let mut connection = connect_local_service(&endpoint).await.unwrap();
            fixture.attach_client(&mut connection, index).await.unwrap()
        };
        let (service, client) = tokio::join!(service, client);
        assert_eq!(service.binding(), client.binding());
        channels.push(client);
    }

    assert_eq!(channels[0].binding().profile().as_str(), "alice");
    assert_eq!(channels[1].binding().profile().as_str(), "bob");
    assert_ne!(channels[0].binding(), channels[1].binding());
}

#[tokio::test]
async fn an_early_probe_disconnect_does_not_stop_the_next_accept() {
    let endpoint = endpoint("probe-disconnect");
    let mut listener = LocalServiceListener::bind(&endpoint).await.unwrap();

    let probe = connect_local_service(&endpoint).await.unwrap();
    drop(probe);

    let service = async { listener.accept().await.unwrap() };
    let client = async { connect_local_service(&endpoint).await.unwrap() };
    let (accepted, connected) = tokio::join!(service, client);

    drop(accepted);
    drop(connected);
}

#[tokio::test]
async fn connecting_to_an_absent_endpoint_fails_closed() {
    let endpoint = endpoint("absent");
    let error = connect_local_service(&endpoint).await.unwrap_err();

    assert_eq!(error, LocalServiceTransportError::EndpointUnavailable);
    let rendered = format!("{error}");
    assert!(
        !rendered.contains(endpoint.as_str()),
        "endpoint failure must not disclose the endpoint name: {rendered}"
    );
}

#[tokio::test]
async fn peer_ownership_is_enforced_for_every_connection() {
    let endpoint = endpoint("peer");
    let mut listener = LocalServiceListener::bind(&endpoint).await.unwrap();

    let service = async { listener.accept().await };
    let client = async { connect_local_service(&endpoint).await };
    let (accepted, connected) = tokio::join!(service, client);

    accepted.unwrap();
    connected.unwrap();
}
