//! Adversarial proof for protocol-v2 issuer and exact-profile session handshakes.

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveLocalServiceTransport::{
    AUTHORIZATION_HANDSHAKE_TIMEOUT, AdapterKeyId, AdapterKeyVersion, AdapterRegistration,
    AuthorizationBinding, AuthorizationEvidenceKind, AuthorizationEvidenceSet,
    AuthorizationPolicyVersion, ClientInstanceId, HarnessKind,
    InMemorySessionAuthorizationRegistry, IssuerHandshakeRequest, LocalServiceTransportError,
    ProfileAuthorization, ServiceProfileId, SessionAuthorizationRegistry, SessionCapabilities,
    SessionGrant, SessionGrantClaims, SessionGrantId, SessionHandshakeRequest,
    complete_authorization_service_handshake,
    complete_authorization_service_handshake_with_authorizer, complete_issuer_client_handshake,
    complete_session_client_handshake,
};
use tokio::io::AsyncReadExt as _;

struct Fixture {
    service: LocalServiceIdentity,
    issuer: LocalServiceIdentity,
    registry: InMemorySessionAuthorizationRegistry,
}

impl Fixture {
    fn issuer_request() -> IssuerHandshakeRequest {
        IssuerHandshakeRequest {
            issuer_key_id: AdapterKeyId::from_bytes([1; 16]),
            issuer_key_version: AdapterKeyVersion::new(1).unwrap(),
            client_instance: ClientInstanceId::from_bytes([2; 16]),
            harness: HarnessKind::Copilot,
        }
    }

    fn new() -> Self {
        let service = LocalServiceIdentity::generate().unwrap();
        let issuer = LocalServiceIdentity::generate().unwrap();
        let registry = InMemorySessionAuthorizationRegistry::new();
        registry
            .register_issuer(
                AdapterKeyId::from_bytes([1; 16]),
                AdapterKeyVersion::new(1).unwrap(),
                AdapterRegistration::new(
                    issuer.public_key(),
                    HarnessKind::Generic,
                    ProfileAuthorization::All,
                ),
            )
            .unwrap();
        Self {
            service,
            issuer,
            registry,
        }
    }

    fn grant(&self, identity: &LocalServiceIdentity, id: u8) -> SessionGrant {
        SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes([id; 16]),
            issuer_key_id: AdapterKeyId::from_bytes([1; 16]),
            issuer_key_version: AdapterKeyVersion::new(1).unwrap(),
            profile: ServiceProfileId::parse("session-a").unwrap(),
            session_public_key: identity.public_key(),
            harness: HarnessKind::Copilot,
            evidence: AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
                .unwrap(),
            policy_version: AuthorizationPolicyVersion::new(1).unwrap(),
            issued_at_unix_milliseconds: 1,
            expires_at_unix_milliseconds: u64::MAX,
            capabilities: SessionCapabilities::ALL,
        })
        .unwrap()
    }
}

#[tokio::test]
async fn issuer_and_session_roles_authenticate_independently() {
    let fixture = Fixture::new();
    let (mut issuer_client, mut issuer_server) = tokio::io::duplex(4_096);
    let issuer_request = Fixture::issuer_request();
    let (client, service) = tokio::join!(
        complete_issuer_client_handshake(
            &mut issuer_client,
            &issuer_request,
            &fixture.issuer,
            fixture.service.public_key(),
        ),
        complete_authorization_service_handshake(
            &mut issuer_server,
            &fixture.registry,
            &fixture.service,
            1,
        )
    );
    assert_eq!(client.unwrap().binding(), service.unwrap().binding());

    let session_identity = LocalServiceIdentity::generate().unwrap();
    let grant = fixture.grant(&session_identity, 3);
    fixture.registry.issue_grant(grant.clone(), 1).unwrap();
    let (mut session_client, mut session_server) = tokio::io::duplex(4_096);
    let session_request = SessionHandshakeRequest {
        grant: grant.clone(),
        client_instance: ClientInstanceId::from_bytes([4; 16]),
    };
    let (client, service) = tokio::join!(
        complete_session_client_handshake(
            &mut session_client,
            &session_request,
            &session_identity,
            fixture.service.public_key(),
        ),
        complete_authorization_service_handshake(
            &mut session_server,
            &fixture.registry,
            &fixture.service,
            1,
        )
    );
    assert_eq!(client.unwrap().binding(), service.unwrap().binding());
}

#[tokio::test]
async fn an_unknown_grant_fails_after_proof_with_one_uniform_error() {
    let fixture = Fixture::new();
    let session_identity = LocalServiceIdentity::generate().unwrap();
    let unknown = fixture.grant(&session_identity, 9);
    let (mut client_stream, mut service_stream) = tokio::io::duplex(4_096);
    let session_request = SessionHandshakeRequest {
        grant: unknown,
        client_instance: ClientInstanceId::from_bytes([5; 16]),
    };
    let (client, service) = tokio::join!(
        complete_session_client_handshake(
            &mut client_stream,
            &session_request,
            &session_identity,
            fixture.service.public_key(),
        ),
        complete_authorization_service_handshake(
            &mut service_stream,
            &fixture.registry,
            &fixture.service,
            1,
        )
    );
    assert_eq!(
        service.unwrap_err(),
        KonclaveLocalServiceTransport::LocalServiceTransportError::UnauthenticClient
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn revoked_and_expired_grants_cannot_reconnect() {
    let fixture = Fixture::new();
    let session_identity = LocalServiceIdentity::generate().unwrap();
    let grant = fixture.grant(&session_identity, 7);
    fixture.registry.issue_grant(grant.clone(), 1).unwrap();
    assert!(fixture.registry.revoke_grant(grant.grant_id()));

    for now in [1, u64::MAX] {
        let (mut client_stream, mut service_stream) = tokio::io::duplex(4_096);
        let session_request = SessionHandshakeRequest {
            grant: grant.clone(),
            client_instance: ClientInstanceId::from_bytes([8; 16]),
        };
        let (_, service) = tokio::join!(
            complete_session_client_handshake(
                &mut client_stream,
                &session_request,
                &session_identity,
                fixture.service.public_key(),
            ),
            complete_authorization_service_handshake(
                &mut service_stream,
                &fixture.registry,
                &fixture.service,
                now,
            )
        );
        assert_eq!(
            service.unwrap_err(),
            KonclaveLocalServiceTransport::LocalServiceTransportError::UnauthenticClient
        );
    }
}

#[tokio::test]
async fn a_v2_client_classifies_a_reachable_legacy_service() {
    let fixture = Fixture::new();
    let (mut client, mut legacy_service) = tokio::io::duplex(512);
    let legacy = tokio::spawn(async move {
        let mut header = [0_u8; 4];
        legacy_service.read_exact(&mut header).await.unwrap();
        let length = usize::try_from(u32::from_be_bytes(header)).unwrap();
        let mut hello = vec![0_u8; length];
        legacy_service.read_exact(&mut hello).await.unwrap();
    });

    let error = complete_issuer_client_handshake(
        &mut client,
        &IssuerHandshakeRequest {
            issuer_key_id: AdapterKeyId::from_bytes([1; 16]),
            issuer_key_version: AdapterKeyVersion::new(1).unwrap(),
            client_instance: ClientInstanceId::from_bytes([2; 16]),
            harness: HarnessKind::Copilot,
        },
        &fixture.issuer,
        fixture.service.public_key(),
    )
    .await
    .unwrap_err();

    assert_eq!(error, LocalServiceTransportError::ServiceUpgradeRequired);
    legacy.await.unwrap();
}

#[test]
fn issuer_binding_checks_every_registration_claim() {
    let fixture = Fixture::new();
    let unknown = LocalServiceIdentity::generate().unwrap();
    for (key_id, version, public_key, authorized) in [
        (1, 1, fixture.issuer.public_key(), true),
        (9, 1, fixture.issuer.public_key(), false),
        (1, 2, fixture.issuer.public_key(), false),
        (1, 1, unknown.public_key(), false),
    ] {
        let binding = AuthorizationBinding::Issuer {
            issuer_key_id: AdapterKeyId::from_bytes([key_id; 16]),
            issuer_key_version: AdapterKeyVersion::new(version).unwrap(),
            issuer_public_key: public_key,
            client_instance: ClientInstanceId::from_bytes([2; 16]),
            harness: HarnessKind::Copilot,
        };
        assert_eq!(fixture.registry.authorizes_binding(&binding, 1), authorized);
    }
}

#[test]
fn binding_authorization_preserves_harness_and_grant_boundaries() {
    let fixture = Fixture::new();
    let restricted = InMemorySessionAuthorizationRegistry::new();
    restricted
        .register_issuer(
            AdapterKeyId::from_bytes([1; 16]),
            AdapterKeyVersion::new(1).unwrap(),
            AdapterRegistration::new(
                fixture.issuer.public_key(),
                HarnessKind::Copilot,
                ProfileAuthorization::All,
            ),
        )
        .unwrap();
    for (harness, authorized) in [(HarnessKind::Copilot, true), (HarnessKind::Generic, false)] {
        let binding = AuthorizationBinding::Issuer {
            issuer_key_id: AdapterKeyId::from_bytes([1; 16]),
            issuer_key_version: AdapterKeyVersion::new(1).unwrap(),
            issuer_public_key: fixture.issuer.public_key(),
            client_instance: ClientInstanceId::from_bytes([2; 16]),
            harness,
        };
        assert_eq!(restricted.authorizes_binding(&binding, 1), authorized);
    }
    let session_identity = LocalServiceIdentity::generate().unwrap();
    let grant = fixture.grant(&session_identity, 7);
    fixture.registry.issue_grant(grant.clone(), 1).unwrap();
    let binding = AuthorizationBinding::Session {
        grant: grant.clone(),
        client_instance: ClientInstanceId::from_bytes([8; 16]),
    };
    for (now, authorized) in [(1, true), (u64::MAX, false)] {
        assert_eq!(
            fixture.registry.authorizes_binding(&binding, now),
            authorized
        );
    }
    assert!(fixture.registry.revoke_grant(grant.grant_id()));
    assert!(!fixture.registry.authorizes_binding(&binding, 1));
}

#[tokio::test(start_paused = true)]
async fn pending_authorization_waits_for_a_fresh_allow_or_uniform_denial() {
    for remains_registered in [true, false] {
        let fixture = Fixture::new();
        let request = Fixture::issuer_request();
        let (mut client_stream, mut service_stream) = tokio::io::duplex(4_096);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let registry = &fixture.registry;
        let client = complete_issuer_client_handshake(
            &mut client_stream,
            &request,
            &fixture.issuer,
            fixture.service.public_key(),
        );
        let service = complete_authorization_service_handshake_with_authorizer(
            &mut service_stream,
            &fixture.service,
            move |binding| async move {
                entered_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok(registry.authorizes_binding(&binding, 1))
            },
        );
        tokio::pin!(client, service);
        tokio::select! {
            biased;
            result = &mut client => panic!("client completed before observation: {result:?}"),
            () = async { entered_rx.await.unwrap() } => {}
            result = &mut service => panic!("service completed before observation: {result:?}"),
        }
        tokio::time::advance(std::time::Duration::from_millis(1500)).await;
        tokio::select! {
            biased;
            result = &mut client => panic!("client accepted an unobserved registry: {result:?}"),
            () = std::future::ready(()) => {}
        }
        if !remains_registered {
            fixture.registry.replace(Vec::new(), Vec::new(), 1).unwrap();
        }
        release_tx.send(()).unwrap();
        let (client, service) = tokio::join!(client, service);
        if remains_registered {
            assert_eq!(client.unwrap().binding(), service.unwrap().binding());
        } else {
            assert_eq!(
                client.unwrap_err(),
                LocalServiceTransportError::UnauthenticClient
            );
            assert_eq!(
                service.unwrap_err(),
                LocalServiceTransportError::UnauthenticClient
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn pending_authorization_cannot_extend_the_handshake_deadline() {
    let fixture = Fixture::new();
    let request = Fixture::issuer_request();
    let (mut client_stream, mut service_stream) = tokio::io::duplex(4_096);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let client = complete_issuer_client_handshake(
        &mut client_stream,
        &request,
        &fixture.issuer,
        fixture.service.public_key(),
    );
    let service = complete_authorization_service_handshake_with_authorizer(
        &mut service_stream,
        &fixture.service,
        move |_| async move {
            entered_tx.send(()).unwrap();
            std::future::pending().await
        },
    );
    tokio::pin!(client, service);
    tokio::select! {
        biased;
        result = &mut client => panic!("client completed before observation: {result:?}"),
        () = async { entered_rx.await.unwrap() } => {}
        result = &mut service => panic!("service completed before observation: {result:?}"),
    }
    tokio::time::advance(AUTHORIZATION_HANDSHAKE_TIMEOUT).await;
    let (client, service) = tokio::join!(client, service);
    assert_eq!(
        client.unwrap_err(),
        LocalServiceTransportError::HandshakeTimeout
    );
    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::HandshakeTimeout
    );
}

#[tokio::test]
async fn an_authorizer_failure_is_not_a_signed_denial_or_legacy_service() {
    let fixture = Fixture::new();
    let request = Fixture::issuer_request();
    let (mut client_stream, mut service_stream) = tokio::io::duplex(4_096);
    let service_identity = &fixture.service;
    let service = async move {
        complete_authorization_service_handshake_with_authorizer(
            &mut service_stream,
            service_identity,
            |_| async { Err(LocalServiceTransportError::EndpointUnavailable) },
        )
        .await
    };
    let (client, service) = tokio::join!(
        complete_issuer_client_handshake(
            &mut client_stream,
            &request,
            &fixture.issuer,
            fixture.service.public_key(),
        ),
        service,
    );
    assert_eq!(
        service.unwrap_err(),
        LocalServiceTransportError::EndpointUnavailable
    );
    assert_eq!(
        client.unwrap_err(),
        LocalServiceTransportError::ChannelClosed
    );
}
