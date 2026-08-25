//! Proves the bounded request and response contract over an authenticated channel.
//!
//! The transport carries opaque payloads for a finite set of operations it does not
//! interpret. These tests exercise a full attach followed by request traffic, so the
//! bounds and the stable failure codes are proved on the same channel a client uses
//! rather than on an encoder in isolation.

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, ClientHandshakeRequest, ClientInstanceId,
    HarnessKind, InMemoryAdapterRegistry, LocalServiceErrorCode, LocalServiceRequest,
    LocalServiceResponse, LocalServiceTransportError, MAX_RPC_PAYLOAD_BYTES, OperationName,
    ProfileAuthorization, RequestId, ServiceProfileId, complete_client_handshake,
    complete_service_handshake, read_request, read_response, write_request, write_response,
};
use tokio::io::DuplexStream;

fn request_id(seed: u8) -> RequestId {
    RequestId::from_bytes([seed; KonclaveLocalServiceTransport::REQUEST_ID_LENGTH])
}

fn operation(name: &str) -> OperationName {
    OperationName::parse(name).unwrap()
}

/// Attaches one authorized client and returns both live halves of the channel.
async fn attached_channel() -> (DuplexStream, DuplexStream) {
    let service_identity = LocalServiceIdentity::generate().unwrap();
    let client_identity = LocalServiceIdentity::generate().unwrap();
    let adapter_key_id = AdapterKeyId::from_bytes([3_u8; AdapterKeyId::LENGTH]);
    let adapter_key_version = AdapterKeyVersion::new(1).unwrap();
    let mut registry = InMemoryAdapterRegistry::new();
    registry
        .register(
            adapter_key_id,
            adapter_key_version,
            AdapterRegistration::new(
                client_identity.public_key(),
                HarnessKind::Copilot,
                ProfileAuthorization::Profile(ServiceProfileId::parse("alice").unwrap()),
            ),
        )
        .unwrap();

    let (mut client_stream, mut service_stream) = tokio::io::duplex(2 * MAX_RPC_PAYLOAD_BYTES);
    let request = ClientHandshakeRequest {
        adapter_key_id,
        adapter_key_version,
        client_instance: ClientInstanceId::from_bytes([4_u8; ClientInstanceId::LENGTH]),
        harness: HarnessKind::Copilot,
        profile: ServiceProfileId::parse("alice").unwrap(),
    };

    let service = complete_service_handshake(&mut service_stream, &registry, &service_identity);
    let client = complete_client_handshake(
        &mut client_stream,
        &request,
        &client_identity,
        service_identity.public_key(),
    );
    let (client, service) = tokio::join!(client, service);
    let client = client.unwrap();
    let service = service.unwrap();
    assert_eq!(client.binding(), service.binding());

    (client_stream, service_stream)
}

#[tokio::test]
async fn a_request_and_its_response_round_trip_over_the_authenticated_channel() {
    let (mut client, mut service) = attached_channel().await;

    let sent = LocalServiceRequest::new(
        request_id(1),
        operation("delivery.wait"),
        b"bounded payload".to_vec(),
    )
    .unwrap();
    write_request(&mut client, &sent).await.unwrap();

    let received = read_request(&mut service).await.unwrap();
    assert_eq!(received, sent);
    assert_eq!(received.request_id(), request_id(1));
    assert_eq!(received.operation().as_str(), "delivery.wait");
    assert_eq!(received.payload(), b"bounded payload");

    let answer = LocalServiceResponse::success(received.request_id(), b"result".to_vec()).unwrap();
    write_response(&mut service, &answer).await.unwrap();
    assert_eq!(read_response(&mut client).await.unwrap(), answer);
}

#[tokio::test]
async fn a_failure_answers_with_a_stable_code_and_no_payload() {
    let (mut client, mut service) = attached_channel().await;

    let sent =
        LocalServiceRequest::new(request_id(2), operation("profile.status"), Vec::new()).unwrap();
    write_request(&mut client, &sent).await.unwrap();
    let received = read_request(&mut service).await.unwrap();

    let answer = LocalServiceResponse::failure(
        received.request_id(),
        LocalServiceErrorCode::ProfileUnavailable,
    );
    write_response(&mut service, &answer).await.unwrap();

    let response = read_response(&mut client).await.unwrap();
    assert_eq!(response, answer);
    assert_eq!(response.request_id(), request_id(2));
    match response {
        LocalServiceResponse::Failure { code, .. } => {
            assert_eq!(code, LocalServiceErrorCode::ProfileUnavailable);
            assert_eq!(code.as_str(), "profile_unavailable");
        }
        LocalServiceResponse::Success { .. } => panic!("expected a failure response"),
    }
}

#[tokio::test]
async fn one_channel_carries_many_requests_and_each_response_names_its_request() {
    let (mut client, mut service) = attached_channel().await;

    for index in 0..8_u8 {
        let sent = LocalServiceRequest::new(
            request_id(index),
            operation("delivery.acknowledge"),
            vec![index; 32],
        )
        .unwrap();
        write_request(&mut client, &sent).await.unwrap();
        let received = read_request(&mut service).await.unwrap();
        assert_eq!(received.request_id(), request_id(index));

        let answer = LocalServiceResponse::success(received.request_id(), vec![index; 8]).unwrap();
        write_response(&mut service, &answer).await.unwrap();
        assert_eq!(
            read_response(&mut client).await.unwrap().request_id(),
            request_id(index)
        );
    }
}

#[tokio::test]
async fn a_retry_carries_the_same_request_identifier_so_the_service_can_deduplicate() {
    let (mut client, mut service) = attached_channel().await;

    let sent =
        LocalServiceRequest::new(request_id(9), operation("pairing.redeem"), b"once".to_vec())
            .unwrap();
    write_request(&mut client, &sent).await.unwrap();
    write_request(&mut client, &sent).await.unwrap();

    let first = read_request(&mut service).await.unwrap();
    let second = read_request(&mut service).await.unwrap();
    assert_eq!(first.request_id(), second.request_id());
    assert_eq!(first, second);
}

#[tokio::test]
async fn a_maximal_payload_still_crosses_the_channel() {
    let (client, mut service) = attached_channel().await;

    let sent = LocalServiceRequest::new(
        request_id(10),
        operation("tool.invoke"),
        vec![7_u8; MAX_RPC_PAYLOAD_BYTES],
    )
    .unwrap();
    let writer = async {
        let mut client = client;
        write_request(&mut client, &sent).await.unwrap();
        client
    };
    let reader = async { read_request(&mut service).await.unwrap() };
    let (_client, received) = tokio::join!(writer, reader);
    assert_eq!(received.payload().len(), MAX_RPC_PAYLOAD_BYTES);
}

#[tokio::test]
async fn a_frame_beyond_the_request_bound_is_refused_before_any_buffer_is_reserved() {
    use tokio::io::AsyncWriteExt;

    let (mut client, mut service) = attached_channel().await;
    let declared = u32::try_from(KonclaveLocalServiceTransport::MAX_RPC_FRAME_BYTES + 1).unwrap();
    client.write_all(&declared.to_be_bytes()).await.unwrap();
    client.flush().await.unwrap();

    assert_eq!(
        read_request(&mut service).await.unwrap_err(),
        LocalServiceTransportError::FrameTooLarge
    );
}

#[tokio::test]
async fn a_response_read_as_a_request_is_refused() {
    let (mut client, mut service) = attached_channel().await;

    let answer = LocalServiceResponse::success(request_id(11), b"result".to_vec()).unwrap();
    write_response(&mut service, &answer).await.unwrap();
    assert_eq!(
        read_request(&mut client).await.unwrap_err(),
        LocalServiceTransportError::UnknownMessageKind
    );
}

#[tokio::test]
async fn a_closed_channel_is_reported_rather_than_hanging() {
    let (client, mut service) = attached_channel().await;
    drop(client);

    assert_eq!(
        read_request(&mut service).await.unwrap_err(),
        LocalServiceTransportError::ChannelClosed
    );
}
