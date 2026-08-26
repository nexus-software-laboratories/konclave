use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, ClientHandshakeRequest, ClientInstanceId, HarnessKind,
    LocalServiceEndpoint, LocalServiceRequest, LocalServiceResponse, OperationName, RequestId,
    ServiceProfileId, complete_client_handshake, connect_local_service, read_response,
    write_request,
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

impl SharedServiceProcess {
    pub fn start(binary: &Path, config: &Path) -> Self {
        let child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        assert!(status.success());
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
    timeout(STARTUP_DEADLINE, async {
        let mut stream = loop {
            match connect_local_service(endpoint).await {
                Ok(stream) => break stream,
                Err(
                    KonclaveLocalServiceTransport::LocalServiceTransportError::EndpointUnavailable,
                ) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => panic!("shared service connection failed: {}", error.code()),
            }
        };
        complete_client_handshake(
            &mut stream,
            &ClientHandshakeRequest {
                adapter_key_id,
                adapter_key_version,
                client_instance: ClientInstanceId::from_bytes([instance; ClientInstanceId::LENGTH]),
                harness: HarnessKind::Copilot,
                profile: ServiceProfileId::parse(profile).unwrap(),
            },
            adapter_identity,
            service_key,
        )
        .await
        .unwrap();
        stream
    })
    .await
    .expect("shared service startup and handshake exceeded the test deadline")
}

pub async fn rpc(
    stream: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    operation: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    timeout(REQUEST_DEADLINE, async {
        let counter = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let mut request_id = [0_u8; 16];
        request_id[..8].copy_from_slice(&counter.to_be_bytes());
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
