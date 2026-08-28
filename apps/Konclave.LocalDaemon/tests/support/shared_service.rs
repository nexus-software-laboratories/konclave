use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AuthorizationEvidenceSet, AuthorizationPolicyVersion,
    ClientInstanceId, HarnessKind, IssuerHandshakeRequest, LocalServiceEndpoint,
    LocalServiceRequest, LocalServiceResponse, OperationName, RequestId, ServiceProfileId,
    SessionCapabilities, SessionGrant, SessionGrantClaims, SessionGrantId, SessionHandshakeRequest,
    complete_issuer_client_handshake, complete_session_client_handshake, connect_local_service,
    read_response, write_request,
};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use zeroize::Zeroizing;

const STARTUP_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub struct SharedServiceProcess {
    child: Option<Child>,
}

pub struct SessionConnectionRequest<'a> {
    pub endpoint: &'a LocalServiceEndpoint,
    pub service_key: KonclaveDomainCore::Ed25519PublicKey,
    pub issuer_identity: &'a LocalServiceIdentity,
    pub issuer_key_id: AdapterKeyId,
    pub issuer_key_version: AdapterKeyVersion,
    pub profile: &'a str,
    pub instance: u8,
    pub session_identity: &'a LocalServiceIdentity,
}

impl SharedServiceProcess {
    pub fn start(binary: &Path, config: &Path) -> Self {
        Self::start_with_stderr(binary, config, Stdio::null())
    }

    pub fn start_with_inherited_stderr(binary: &Path, config: &Path) -> Self {
        Self::start_with_stderr(binary, config, Stdio::inherit())
    }

    fn start_with_stderr(binary: &Path, config: &Path, stderr: Stdio) -> Self {
        let child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self { child: Some(child) }
    }

    pub fn id(&self) -> u32 {
        self.child.as_ref().and_then(Child::id).unwrap()
    }

    pub async fn shutdown(mut self) {
        let process_id = self.id();
        let process_id = i32::try_from(process_id).expect("process identifier exceeds Unix pid_t");
        // SAFETY: this fixture spawned `process_id`, still owns its live Child handle,
        // and sends only SIGTERM so the service exercises coordinated shutdown.
        assert_eq!(unsafe { libc::kill(process_id, libc::SIGTERM) }, 0);
        let status = timeout(SHUTDOWN_DEADLINE, self.child.as_mut().unwrap().wait())
            .await
            .expect("shared service shutdown exceeded the test deadline")
            .unwrap();
        assert!(status.success(), "shared service exited with {status}");
        self.child = None;
    }
}

pub async fn connect(
    endpoint: &LocalServiceEndpoint,
    service_key: KonclaveDomainCore::Ed25519PublicKey,
    adapter_identity: &LocalServiceIdentity,
    adapter_key_id: AdapterKeyId,
    adapter_key_version: AdapterKeyVersion,
    profile: &str,
    instance: u8,
) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
    let session_identity = LocalServiceIdentity::generate().unwrap();
    connect_with_session_identity(SessionConnectionRequest {
        endpoint,
        service_key,
        issuer_identity: adapter_identity,
        issuer_key_id: adapter_key_id,
        issuer_key_version: adapter_key_version,
        profile,
        instance,
        session_identity: &session_identity,
    })
    .await
}

pub async fn connect_with_session_identity(
    request: SessionConnectionRequest<'_>,
) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
    let SessionConnectionRequest {
        endpoint,
        service_key,
        issuer_identity,
        issuer_key_id,
        issuer_key_version,
        profile,
        instance,
        session_identity,
    } = request;
    timeout(STARTUP_DEADLINE, async {
        let mut issuer_stream = loop {
            match connect_local_service(endpoint).await {
                Ok(stream) => break stream,
                Err(
                    KonclaveLocalServiceTransport::LocalServiceTransportError::EndpointUnavailable,
                ) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => panic!("shared service connection failed: {}", error.code()),
            }
        };
        complete_issuer_client_handshake(
            &mut issuer_stream,
            &IssuerHandshakeRequest {
                issuer_key_id,
                issuer_key_version,
                client_instance: ClientInstanceId::from_bytes([instance; ClientInstanceId::LENGTH]),
                harness: HarnessKind::Copilot,
            },
            issuer_identity,
            service_key,
        )
        .await
        .unwrap();
        let issued = rpc(
            &mut issuer_stream,
            "authorization.grant.issue",
            serde_json::json!({
                "profile": profile,
                "sessionPublicKey": encode_hex(session_identity.public_key().as_bytes()),
                "harness": "copilot"
            }),
        )
        .await;
        drop(issuer_stream);
        let grant = decode_grant(&issued);
        let mut stream = connect_local_service(endpoint).await.unwrap();
        complete_session_client_handshake(
            &mut stream,
            &SessionHandshakeRequest {
                grant,
                client_instance: ClientInstanceId::from_bytes([instance; ClientInstanceId::LENGTH]),
            },
            session_identity,
            service_key,
        )
        .await
        .unwrap();
        stream
    })
    .await
    .expect("shared service startup and handshake exceeded the test deadline")
}

fn decode_grant(value: &serde_json::Value) -> SessionGrant {
    SessionGrant::new(SessionGrantClaims {
        grant_id: SessionGrantId::from_bytes(decode_hex(value["grantId"].as_str().unwrap())),
        issuer_key_id: AdapterKeyId::from_bytes(decode_hex(value["issuerKeyId"].as_str().unwrap())),
        issuer_key_version: AdapterKeyVersion::new(
            u32::try_from(value["issuerKeyVersion"].as_u64().unwrap()).unwrap(),
        )
        .unwrap(),
        profile: ServiceProfileId::parse(value["profile"].as_str().unwrap()).unwrap(),
        session_public_key: KonclaveDomainCore::Ed25519PublicKey::from_bytes(decode_hex(
            value["sessionPublicKey"].as_str().unwrap(),
        )),
        harness: HarnessKind::Copilot,
        evidence: AuthorizationEvidenceSet::from_bits(
            u8::try_from(value["evidence"].as_u64().unwrap()).unwrap(),
        )
        .unwrap(),
        policy_version: AuthorizationPolicyVersion::new(value["policyVersion"].as_u64().unwrap())
            .unwrap(),
        issued_at_unix_milliseconds: value["issuedAtUnixMilliseconds"].as_u64().unwrap(),
        expires_at_unix_milliseconds: value["expiresAtUnixMilliseconds"].as_u64().unwrap(),
        capabilities: SessionCapabilities::from_bits(value["capabilities"].as_u64().unwrap())
            .unwrap(),
    })
    .unwrap()
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        let pair = &value.as_bytes()[offset..offset + 2];
        *output = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    decoded
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub async fn rpc(
    stream: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    operation: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    let counter = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let mut request_id = [0_u8; 16];
    request_id[..8].copy_from_slice(&counter.to_be_bytes());
    rpc_with_request_id(stream, request_id, operation, payload).await
}

pub async fn rpc_with_request_id(
    stream: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    request_id: [u8; 16],
    operation: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    timeout(REQUEST_DEADLINE, async {
        let request = LocalServiceRequest::new(
            RequestId::from_bytes(request_id),
            OperationName::parse(operation).unwrap(),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        write_request(stream, &request).await.unwrap();
        match read_response(stream).await.unwrap() {
            LocalServiceResponse::Success { payload, .. } => {
                serde_json::from_slice(&payload).unwrap()
            }
            LocalServiceResponse::Failure { code, .. } => {
                panic!("shared service operation failed: {}", code.as_str())
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("shared service operation '{operation}' exceeded its deadline"))
}

pub async fn identity(
    stream: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
) -> String {
    let value = rpc(stream, "get_identity", serde_json::json!({})).await;
    value["device_id"].as_str().unwrap().to_string()
}

pub async fn complete_pairing(
    first: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    second: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
) -> (String, String) {
    timeout(Duration::from_secs(30), async {
        let created = rpc(
            first,
            "create_pairing_capability",
            serde_json::json!({"requested_role": "member"}),
        )
        .await;
        let capability = Zeroizing::new(created["capability"].as_str().unwrap().to_string());
        let pairing_id = created["pairing"]["pairing_id"]
            .as_str()
            .unwrap()
            .to_string();
        let redeemed = rpc(
            second,
            "redeem_pairing_capability",
            serde_json::json!({"capability": capability.as_str()}),
        )
        .await;
        assert_eq!(redeemed["pairing_id"], pairing_id);
        let conversation = rpc(second, "create_conversation", serde_json::json!({})).await;
        let conversation_id = conversation["conversation_id"]
            .as_str()
            .unwrap()
            .to_string();
        rpc(
            second,
            "authorize_pairing_joiner",
            serde_json::json!({
                "pairing_id": pairing_id,
                "conversation_id": conversation_id,
                "granted_role": "member"
            }),
        )
        .await;

        let mut inviter_authorized = false;
        for _ in 0..16 {
            let mut first_status = rpc(
                first,
                "sync_pairing",
                serde_json::json!({"pairing_id": pairing_id}),
            )
            .await;
            if !inviter_authorized
                && first_status["pairing"]["phase"] == "joiner_awaiting_inviter_authorization"
            {
                let pairing = &first_status["pairing"];
                first_status = rpc(
                    first,
                    "authorize_pairing_inviter",
                    serde_json::json!({
                        "pairing_id": pairing_id,
                        "inviter_device_id": pairing["inviter_device_id"],
                        "conversation_id": pairing["conversation_id"],
                        "granted_role": pairing["granted_role"]
                    }),
                )
                .await;
                inviter_authorized = true;
            }
            let second_status = rpc(
                second,
                "sync_pairing",
                serde_json::json!({"pairing_id": pairing_id}),
            )
            .await;
            if first_status["pairing"]["phase"] == "completed"
                && second_status["pairing"]["phase"] == "completed"
            {
                return (pairing_id, conversation_id);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("shared-service pairing did not complete");
    })
    .await
    .expect("shared-service pairing exceeded its deadline")
}
