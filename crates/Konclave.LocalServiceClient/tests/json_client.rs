//! End-to-end proof for the reconnecting authenticated JSON client.

use std::time::Duration;

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveDomainCore::Ed25519PublicKey;
use KonclaveLocalServiceClient::{
    LocalServiceIssuerCredential, LocalServiceJsonClient, LocalServiceJsonClientConfig,
};
use KonclaveLocalServiceTransport::{
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicyVersion, HarnessKind,
    InMemorySessionAuthorizationRegistry, IssuerKeyId, IssuerKeyVersion, IssuerRegistration,
    LocalServiceEndpoint, LocalServiceListener, LocalServiceResponse, ProfileAuthorization,
    RequestId, ServiceProfileId, SessionCapabilities, SessionGrant, SessionGrantClaims,
    SessionGrantId, complete_authorization_service_handshake, decode_lowercase_hex,
    encode_lowercase_hex, read_request, write_response,
};
use serde::Deserialize;
use serde_json::json;

#[tokio::test]
async fn client_issues_a_grant_and_retries_an_ambiguous_session_request_exactly() {
    let (endpoint, _endpoint_root) = endpoint("json-client-retry");
    let mut listener = LocalServiceListener::bind(&endpoint).await.unwrap();
    let service_identity = LocalServiceIdentity::generate().unwrap();
    let service_public_key = service_identity.public_key();
    let issuer_identity = LocalServiceIdentity::generate().unwrap();
    let issuer_public_key = issuer_identity.public_key();
    let issuer_key_id = IssuerKeyId::from_bytes([1; 16]);
    let issuer_key_version = IssuerKeyVersion::new(1).unwrap();
    let registry = InMemorySessionAuthorizationRegistry::new();
    registry
        .register_issuer(
            issuer_key_id,
            issuer_key_version,
            IssuerRegistration::new(
                issuer_public_key,
                HarnessKind::Generic,
                ProfileAuthorization::All,
            ),
        )
        .unwrap();

    let service = async move {
        let mut issuer_stream = listener.accept().await.unwrap();
        complete_authorization_service_handshake(
            &mut issuer_stream,
            &registry,
            &service_identity,
            1,
        )
        .await
        .unwrap();
        let issue_request = read_request(&mut issuer_stream).await.unwrap();
        assert_eq!(
            issue_request.operation().as_str(),
            "authorization.grant.issue"
        );
        let requested: GrantRequest = serde_json::from_slice(issue_request.payload()).unwrap();
        assert_eq!(requested.profile, "a2a-gateway");
        assert_eq!(requested.harness, "a2a-gateway");
        let session_public_key = Ed25519PublicKey::from_bytes(
            decode_lowercase_hex::<32>(&requested.session_public_key).unwrap(),
        );
        let grant = SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes([2; 16]),
            issuer_key_id,
            issuer_key_version,
            profile: ServiceProfileId::parse(&requested.profile).unwrap(),
            session_public_key,
            harness: HarnessKind::A2AGateway,
            evidence: AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
                .unwrap(),
            policy_version: AuthorizationPolicyVersion::new(1).unwrap(),
            issued_at_unix_milliseconds: 1,
            expires_at_unix_milliseconds: u64::MAX,
            capabilities: SessionCapabilities::ALL,
        })
        .unwrap();
        registry.issue_grant(grant.clone(), 1).unwrap();
        let issue_payload = serde_json::to_vec(&json!({
            "grantId": encode_lowercase_hex(grant.grant_id().as_bytes()),
            "issuerKeyId": encode_lowercase_hex(grant.issuer_key_id().as_bytes()),
            "issuerKeyVersion": grant.issuer_key_version().get(),
            "profile": grant.profile().as_str(),
            "sessionPublicKey": encode_lowercase_hex(grant.session_public_key().as_bytes()),
            "harness": grant.harness().as_str(),
            "evidence": grant.evidence().bits(),
            "policyVersion": grant.policy_version().get(),
            "issuedAtUnixMilliseconds": grant.issued_at_unix_milliseconds(),
            "expiresAtUnixMilliseconds": grant.expires_at_unix_milliseconds(),
            "capabilities": grant.capabilities().bits()
        }))
        .unwrap();
        write_response(
            &mut issuer_stream,
            &LocalServiceResponse::success(issue_request.request_id(), issue_payload).unwrap(),
        )
        .await
        .unwrap();

        let mut first_session = listener.accept().await.unwrap();
        complete_authorization_service_handshake(
            &mut first_session,
            &registry,
            &service_identity,
            2,
        )
        .await
        .unwrap();
        let first_request = read_request(&mut first_session).await.unwrap();
        drop(first_session);

        let mut second_session = listener.accept().await.unwrap();
        complete_authorization_service_handshake(
            &mut second_session,
            &registry,
            &service_identity,
            3,
        )
        .await
        .unwrap();
        let second_request = read_request(&mut second_session).await.unwrap();
        assert_eq!(first_request, second_request);
        write_response(
            &mut second_session,
            &LocalServiceResponse::success(
                second_request.request_id(),
                br#"{"device_id":"01"}"#.to_vec(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    };

    let client = async move {
        let config = LocalServiceJsonClientConfig::new(
            endpoint,
            LocalServiceIssuerCredential::new(issuer_key_id, issuer_key_version, issuer_identity),
            service_public_key,
            ServiceProfileId::parse("a2a-gateway").unwrap(),
            HarnessKind::A2AGateway,
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .unwrap();
        let client = LocalServiceJsonClient::connect(config).await.unwrap();
        let request_id = RequestId::from_bytes([9; 16]);
        let response = client
            .request(request_id, "get_identity", br#"{}"#.to_vec())
            .await
            .unwrap();
        assert_eq!(response, br#"{"device_id":"01"}"#);
    };

    let ((), ()) = tokio::join!(service, client);
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantRequest {
    profile: String,
    session_public_key: String,
    harness: String,
}

#[cfg(windows)]
fn endpoint(name: &str) -> (LocalServiceEndpoint, Option<tempfile::TempDir>) {
    (
        LocalServiceEndpoint::parse(&format!(
            r"\\.\pipe\konclave-local-service-test-{}-{name}",
            std::process::id()
        ))
        .unwrap(),
        None,
    )
}

#[cfg(unix)]
fn endpoint(name: &str) -> (LocalServiceEndpoint, Option<tempfile::TempDir>) {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint =
        LocalServiceEndpoint::parse(root.path().join(format!("{name}.sock")).to_str().unwrap())
            .unwrap();
    (endpoint, Some(root))
}
