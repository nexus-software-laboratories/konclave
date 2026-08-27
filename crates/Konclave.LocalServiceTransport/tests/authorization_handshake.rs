//! Adversarial proof for protocol-v2 issuer and exact-profile session handshakes.

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, AuthorizationEvidenceKind,
    AuthorizationEvidenceSet, AuthorizationPolicyVersion, ClientInstanceId, HarnessKind,
    InMemorySessionAuthorizationRegistry, IssuerHandshakeRequest, LocalServiceTransportError,
    ProfileAuthorization, ServiceProfileId, SessionCapabilities, SessionGrant, SessionGrantClaims,
    SessionGrantId, SessionHandshakeRequest, complete_authorization_service_handshake,
    complete_issuer_client_handshake, complete_session_client_handshake,
};
use tokio::io::AsyncReadExt as _;

struct Fixture {
    service: LocalServiceIdentity,
    issuer: LocalServiceIdentity,
    registry: InMemorySessionAuthorizationRegistry,
}

impl Fixture {
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
    let issuer_request = IssuerHandshakeRequest {
        issuer_key_id: AdapterKeyId::from_bytes([1; 16]),
        issuer_key_version: AdapterKeyVersion::new(1).unwrap(),
        client_instance: ClientInstanceId::from_bytes([2; 16]),
        harness: HarnessKind::Copilot,
    };
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
