//! Exercises the mutual handshake and every way it must fail closed.
//!
//! ADR 0008 requires a replay-resistant signature handshake that binds one connection
//! to exactly one authorized profile. These tests drive both roles over an in-memory
//! duplex so the contract is proved without a platform endpoint, and every rejection
//! path is asserted by its stable error rather than by a generic failure.

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, AuthenticatedLocalChannel,
    CHALLENGE_LENGTH, ClientHandshakeRequest, ClientInstanceId, HandshakeMessage, HarnessKind,
    InMemoryAdapterRegistry, LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceBinding,
    LocalServiceChallenge, LocalServiceTranscript, LocalServiceTransportError,
    MAX_HANDSHAKE_FRAME_BYTES, ProfileAuthorization, ServiceProfileId, complete_client_handshake,
    complete_service_handshake,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

const CLIENT_KEY_VERSION: u32 = 4;

struct Fixture {
    service_identity: LocalServiceIdentity,
    client_identity: LocalServiceIdentity,
    registry: InMemoryAdapterRegistry,
}

impl Fixture {
    fn new(harness: HarnessKind, profiles: ProfileAuthorization) -> Self {
        let service_identity = LocalServiceIdentity::generate().unwrap();
        let client_identity = LocalServiceIdentity::generate().unwrap();
        let mut registry = InMemoryAdapterRegistry::new();
        registry
            .register(
                adapter_key(),
                key_version(CLIENT_KEY_VERSION),
                AdapterRegistration::new(client_identity.public_key(), harness, profiles),
            )
            .unwrap();
        Self {
            service_identity,
            client_identity,
            registry,
        }
    }

    fn authorized() -> Self {
        Self::new(
            HarnessKind::Copilot,
            ProfileAuthorization::Profile(profile("alice")),
        )
    }

    /// Runs both roles concurrently and returns both outcomes.
    ///
    /// Each half is moved into its own future, so a role that fails early drops its
    /// stream and the peer observes a closed channel instead of waiting for the
    /// handshake bound to expire.
    async fn attach(
        &self,
        request: &ClientHandshakeRequest,
        pinned_service_key: Ed25519PublicKey,
    ) -> HandshakeOutcome {
        let (client_stream, service_stream) = tokio::io::duplex(4_096);
        let service = async {
            let mut service_stream = service_stream;
            complete_service_handshake(&mut service_stream, &self.registry, &self.service_identity)
                .await
        };
        let client = async {
            let mut client_stream = client_stream;
            complete_client_handshake(
                &mut client_stream,
                request,
                &self.client_identity,
                pinned_service_key,
            )
            .await
        };
        tokio::join!(client, service)
    }
}

type HandshakeOutcome = (
    Result<AuthenticatedLocalChannel, LocalServiceTransportError>,
    Result<AuthenticatedLocalChannel, LocalServiceTransportError>,
);

fn adapter_key() -> AdapterKeyId {
    AdapterKeyId::from_bytes([9_u8; AdapterKeyId::LENGTH])
}

fn key_version(value: u32) -> AdapterKeyVersion {
    AdapterKeyVersion::new(value).unwrap()
}

fn profile(value: &str) -> ServiceProfileId {
    ServiceProfileId::parse(value).unwrap()
}

fn client_instance() -> ClientInstanceId {
    ClientInstanceId::from_bytes([5_u8; ClientInstanceId::LENGTH])
}

fn request() -> ClientHandshakeRequest {
    ClientHandshakeRequest {
        adapter_key_id: adapter_key(),
        adapter_key_version: key_version(CLIENT_KEY_VERSION),
        client_instance: client_instance(),
        harness: HarnessKind::Copilot,
        profile: profile("alice"),
    }
}

async fn read_frame<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    KonclaveLocalFraming::read_frame(stream, MAX_HANDSHAKE_FRAME_BYTES)
        .await
        .unwrap()
}

async fn write_frame<S>(stream: &mut S, payload: &[u8])
where
    S: AsyncWrite + Unpin,
{
    KonclaveLocalFraming::write_frame(stream, payload, MAX_HANDSHAKE_FRAME_BYTES)
        .await
        .unwrap();
}

async fn read_message(stream: &mut DuplexStream) -> HandshakeMessage {
    HandshakeMessage::decode(&read_frame(stream).await).unwrap()
}

#[tokio::test]
async fn an_authorized_client_and_the_service_agree_on_one_immutable_binding() {
    let fixture = Fixture::authorized();
    let (client, service) = fixture
        .attach(&request(), fixture.service_identity.public_key())
        .await;

    let client = client.unwrap();
    let service = service.unwrap();
    assert_eq!(client.binding(), service.binding());

    let binding = client.binding();
    assert_eq!(binding.version(), LOCAL_SERVICE_PROTOCOL_VERSION);
    assert_eq!(binding.adapter_key_id(), adapter_key());
    assert_eq!(
        binding.adapter_key_version(),
        key_version(CLIENT_KEY_VERSION)
    );
    assert_eq!(binding.client_instance(), client_instance());
    assert_eq!(binding.harness(), HarnessKind::Copilot);
    assert_eq!(binding.profile().as_str(), "alice");
}

#[tokio::test]
async fn an_unregistered_adapter_key_fails_closed() {
    let fixture = Fixture::authorized();
    let unregistered = ClientHandshakeRequest {
        adapter_key_id: AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH]),
        ..request()
    };
    let (client, service) = fixture
        .attach(&unregistered, fixture.service_identity.public_key())
        .await;

    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::UnknownAdapterRegistration
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn a_wrong_key_version_never_falls_back_to_an_active_one() {
    let fixture = Fixture::authorized();
    for version in [CLIENT_KEY_VERSION - 1, CLIENT_KEY_VERSION + 1] {
        let wrong_version = ClientHandshakeRequest {
            adapter_key_version: key_version(version),
            ..request()
        };
        let (client, service) = fixture
            .attach(&wrong_version, fixture.service_identity.public_key())
            .await;

        assert_eq!(
            service.unwrap_err(),
            LocalServiceTransportError::UnknownAdapterRegistration,
            "version {version} must not resolve"
        );
        assert!(client.is_err());
    }
}

#[tokio::test]
async fn a_revoked_registration_stops_new_attaches() {
    let mut fixture = Fixture::authorized();
    assert_eq!(fixture.registry.revoke(adapter_key()), 1);
    let (client, service) = fixture
        .attach(&request(), fixture.service_identity.public_key())
        .await;

    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::UnknownAdapterRegistration
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn another_private_key_under_a_registered_identifier_fails_closed() {
    let mut fixture = Fixture::authorized();
    fixture.client_identity = LocalServiceIdentity::generate().unwrap();
    let (client, service) = fixture
        .attach(&request(), fixture.service_identity.public_key())
        .await;

    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::UnauthenticClient
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn a_harness_outside_the_registration_fails_closed() {
    let fixture = Fixture::authorized();
    let wrong_harness = ClientHandshakeRequest {
        harness: HarnessKind::Codex,
        ..request()
    };
    let (client, service) = fixture
        .attach(&wrong_harness, fixture.service_identity.public_key())
        .await;

    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::HarnessNotAuthorized
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn a_profile_outside_the_registration_fails_closed() {
    let fixture = Fixture::authorized();
    let wrong_profile = ClientHandshakeRequest {
        profile: profile("bob"),
        ..request()
    };
    let (client, service) = fixture
        .attach(&wrong_profile, fixture.service_identity.public_key())
        .await;

    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::ProfileNotAuthorized
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn a_namespace_registration_binds_only_its_own_profiles() {
    let fixture = Fixture::new(
        HarnessKind::Copilot,
        ProfileAuthorization::Namespace(profile("team")),
    );

    for allowed in ["team", "team-alice"] {
        let permitted = ClientHandshakeRequest {
            profile: profile(allowed),
            ..request()
        };
        let (client, service) = fixture
            .attach(&permitted, fixture.service_identity.public_key())
            .await;
        assert_eq!(client.unwrap().binding().profile().as_str(), allowed);
        assert_eq!(service.unwrap().binding().profile().as_str(), allowed);
    }

    for refused in ["teamalice", "other-team"] {
        let denied = ClientHandshakeRequest {
            profile: profile(refused),
            ..request()
        };
        let (client, service) = fixture
            .attach(&denied, fixture.service_identity.public_key())
            .await;
        assert_eq!(
            service.unwrap_err(),
            LocalServiceTransportError::ProfileNotAuthorized,
            "{refused} must not be authorized"
        );
        assert!(client.is_err());
    }
}

#[tokio::test]
async fn a_client_refuses_a_service_identity_it_did_not_pin() {
    let fixture = Fixture::authorized();
    let (client, _service) = fixture
        .attach(
            &request(),
            Ed25519PublicKey::from_bytes([2_u8; Ed25519PublicKey::LENGTH]),
        )
        .await;

    assert_eq!(
        client.unwrap_err(),
        LocalServiceTransportError::ServiceKeyMismatch
    );
}

#[tokio::test]
async fn a_client_refuses_an_acceptance_signed_by_another_key() {
    let fixture = Fixture::authorized();
    let impostor = LocalServiceIdentity::generate().unwrap();
    let pinned = fixture.service_identity.public_key();
    let (client_stream, service_stream) = tokio::io::duplex(4_096);

    // The impostor presents the pinned public key it does not hold, so only the
    // acceptance signature can expose it.
    let service = async {
        let mut service_stream = service_stream;
        let HandshakeMessage::ClientHello {
            version,
            adapter_key_id,
            adapter_key_version,
            client_instance,
            harness,
            profile,
            challenge: client_challenge,
        } = read_message(&mut service_stream).await
        else {
            panic!("expected a client hello");
        };
        let service_challenge = LocalServiceChallenge::from_bytes([7_u8; CHALLENGE_LENGTH]);
        write_frame(
            &mut service_stream,
            &HandshakeMessage::ServiceChallenge {
                service_public_key: pinned,
                challenge: service_challenge,
            }
            .encode(),
        )
        .await;
        let _client_auth = read_message(&mut service_stream).await;
        let transcript = LocalServiceTranscript::new(
            LocalServiceBinding::new(
                version,
                adapter_key_id,
                adapter_key_version,
                client_instance,
                harness,
                profile,
            )
            .unwrap(),
            client_challenge,
            service_challenge,
            pinned,
        );
        write_frame(
            &mut service_stream,
            &HandshakeMessage::ServiceAccept {
                signature: transcript.sign_as_service(&impostor).unwrap(),
            }
            .encode(),
        )
        .await;
    };

    let client = async {
        let mut client_stream = client_stream;
        complete_client_handshake(
            &mut client_stream,
            &request(),
            &fixture.client_identity,
            pinned,
        )
        .await
    };

    let (client, ()) = tokio::join!(client, service);
    assert_eq!(
        client.unwrap_err(),
        LocalServiceTransportError::UnauthenticService
    );
}

#[tokio::test]
async fn a_captured_client_proof_does_not_authenticate_a_second_connection() {
    let fixture = Fixture::authorized();

    // One authentic attach proves the registration before the replay attempt.
    let (accepted, _) = fixture
        .attach(&request(), fixture.service_identity.public_key())
        .await;
    accepted.unwrap();

    let recorded_challenge = LocalServiceChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]);
    let transcript = LocalServiceTranscript::new(
        LocalServiceBinding::new(
            LOCAL_SERVICE_PROTOCOL_VERSION,
            adapter_key(),
            key_version(CLIENT_KEY_VERSION),
            client_instance(),
            HarnessKind::Copilot,
            profile("alice"),
        )
        .unwrap(),
        recorded_challenge,
        recorded_challenge,
        fixture.service_identity.public_key(),
    );
    let recorded_hello = HandshakeMessage::ClientHello {
        version: LOCAL_SERVICE_PROTOCOL_VERSION,
        adapter_key_id: adapter_key(),
        adapter_key_version: key_version(CLIENT_KEY_VERSION),
        client_instance: client_instance(),
        harness: HarnessKind::Copilot,
        profile: profile("alice"),
        challenge: recorded_challenge,
    }
    .encode();
    let recorded_auth = HandshakeMessage::ClientAuth {
        signature: transcript.sign_as_client(&fixture.client_identity).unwrap(),
    }
    .encode();

    // Replay those exact frames against a service that contributes a fresh challenge.
    let (replay_stream, service_stream) = tokio::io::duplex(4_096);
    let service = async {
        let mut service_stream = service_stream;
        complete_service_handshake(
            &mut service_stream,
            &fixture.registry,
            &fixture.service_identity,
        )
        .await
    };
    let attacker = async {
        let mut replay_stream = replay_stream;
        write_frame(&mut replay_stream, &recorded_hello).await;
        let _service_challenge = read_frame(&mut replay_stream).await;
        write_frame(&mut replay_stream, &recorded_auth).await;
    };

    let (service, ()) = tokio::join!(service, attacker);
    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::UnauthenticClient
    );
}

#[tokio::test]
async fn an_oversized_or_malformed_first_frame_never_reaches_authorization() {
    let fixture = Fixture::authorized();

    for payload in [
        vec![0_u8; MAX_HANDSHAKE_FRAME_BYTES + 1],
        vec![99_u8, 0, 0],
        Vec::new(),
    ] {
        let (client_stream, service_stream) = tokio::io::duplex(8_192);
        let service = async {
            let mut service_stream = service_stream;
            complete_service_handshake(
                &mut service_stream,
                &fixture.registry,
                &fixture.service_identity,
            )
            .await
        };
        let attacker = async {
            let mut client_stream = client_stream;
            let declared = u32::try_from(payload.len()).unwrap().to_be_bytes();
            let mut frame = declared.to_vec();
            frame.extend_from_slice(&payload);
            use tokio::io::AsyncWriteExt;
            let _ = client_stream.write_all(&frame).await;
            let _ = client_stream.flush().await;
        };

        let (service, ()) = tokio::join!(service, attacker);
        let error = service.unwrap_err();
        assert!(
            matches!(
                error,
                LocalServiceTransportError::FrameTooLarge
                    | LocalServiceTransportError::MalformedFrame
                    | LocalServiceTransportError::UnknownMessageKind
            ),
            "unexpected failure for a {} byte payload: {error}",
            payload.len()
        );
    }
}

#[tokio::test]
async fn a_service_never_answers_a_message_that_arrives_out_of_order() {
    let fixture = Fixture::authorized();
    let (client_stream, service_stream) = tokio::io::duplex(4_096);
    let service = async {
        let mut service_stream = service_stream;
        complete_service_handshake(
            &mut service_stream,
            &fixture.registry,
            &fixture.service_identity,
        )
        .await
    };
    let attacker = async {
        let mut client_stream = client_stream;
        write_frame(
            &mut client_stream,
            &HandshakeMessage::ClientAuth {
                signature: KonclaveDomainCore::Ed25519Signature::from_bytes(
                    [0_u8; KonclaveDomainCore::Ed25519Signature::LENGTH],
                ),
            }
            .encode(),
        )
        .await;
    };

    let (service, ()) = tokio::join!(service, attacker);
    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::UnexpectedMessage
    );
}
