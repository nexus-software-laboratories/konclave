//! Exercises extracted client artifacts through the shared local-service boundary.
//!
//! Real Copilot OAuth and cloud inference remain outside this deterministic test. The
//! packaged CLI, thin plugin, shared service, relay, A2A gateway, pairing, messaging,
//! restart, and profile recovery paths are real.

#![cfg(unix)]

mod support;

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use KonclaveA2AContracts::wire::{
    Message as A2AMessage, Part as A2APart, Role as A2ARole, SendMessageConfiguration,
    SendMessageRequest, TaskState as A2ATaskState, part as a2a_part,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, InitialA2AInterfaceEnvironment, MAX_A2A_ENCODED_RESPONSE_BYTES,
    validate_initial_send_message_request,
};
use KonclaveA2ADomain::A2ATaskId;
use KonclaveA2AGateway::{
    A2AAgentCardFetchOutcome, A2ABearerCredential, A2AHttpClientConfig, A2AHttpJsonClient,
    fetch_public_agent_card,
};
use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, LocalServiceInstallation, LocalServiceProfileCustody,
    encode_lowercase_hex,
};
use KonclaveSecretStorage::{create_or_verify_owner_protected_file, open_owner_protected_file};
use sha2::{Digest as _, Sha256};
use tokio::process::{Child, Command as TokioCommand};
use tokio::time::timeout;
use zeroize::Zeroizing;

use support::shared_service::{
    SessionConnectionRequest, SharedServiceProcess, complete_pairing, connect,
    connect_with_session_identity, identity, rpc,
};

const A2A_CONTEXT_ID: &str = "packaged-a2a-context";
const A2A_REQUEST_TEXT: &str = "packaged A2A contract request";
const A2A_RESPONSE_TEXT: &str = "packaged A2A contract response";
const A2A_BEARER_TOKEN: &str = "packaged-a2a-bearer-0123456789abcdef";

struct AcceptancePaths {
    cli: PathBuf,
    service: PathBuf,
    second_service: PathBuf,
    client_module: PathBuf,
    generic_module: PathBuf,
    generic_skill: PathBuf,
    install_root: PathBuf,
    relay_endpoint: String,
    enrollment_source: PathBuf,
    profile_root: PathBuf,
    profile_keys: PathBuf,
    service_identity: PathBuf,
    extension_root: PathBuf,
    relay_state: PathBuf,
    relay_database: PathBuf,
    gateway: PathBuf,
    gateway_address: String,
    gateway_container: bool,
    gateway_container_name: Option<String>,
    gateway_image: Option<String>,
    container_run_id: Option<String>,
}

impl AcceptancePaths {
    fn from_environment() -> Self {
        Self {
            cli: required_path("KONCLAVE_ACCEPTANCE_CLI"),
            service: required_path("KONCLAVE_ACCEPTANCE_SERVICE"),
            second_service: required_path("KONCLAVE_ACCEPTANCE_SECOND_SERVICE"),
            client_module: required_path("KONCLAVE_ACCEPTANCE_CLIENT_MODULE"),
            generic_module: required_path("KONCLAVE_ACCEPTANCE_GENERIC_MODULE"),
            generic_skill: required_path("KONCLAVE_ACCEPTANCE_GENERIC_SKILL"),
            install_root: required_path("KONCLAVE_ACCEPTANCE_INSTALL_ROOT"),
            relay_endpoint: required("KONCLAVE_ACCEPTANCE_RELAY_ENDPOINT"),
            enrollment_source: required_path("KONCLAVE_ACCEPTANCE_ENROLLMENT_SOURCE"),
            profile_root: required_path("KONCLAVE_ACCEPTANCE_PROFILE_ROOT"),
            profile_keys: required_path("KONCLAVE_ACCEPTANCE_PROFILE_KEYS"),
            service_identity: required_path("KONCLAVE_ACCEPTANCE_SERVICE_IDENTITY"),
            extension_root: required_path("KONCLAVE_ACCEPTANCE_EXTENSION_ROOT"),
            relay_state: required_path("KONCLAVE_ACCEPTANCE_RELAY_STATE"),
            relay_database: required_path("KONCLAVE_ACCEPTANCE_RELAY_DATABASE"),
            gateway: required_path("KONCLAVE_ACCEPTANCE_GATEWAY"),
            gateway_address: required("KONCLAVE_ACCEPTANCE_GATEWAY_ADDRESS"),
            gateway_container: required_bool("KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER"),
            gateway_container_name: optional("KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER_NAME"),
            gateway_image: optional("KONCLAVE_ACCEPTANCE_GATEWAY_IMAGE"),
            container_run_id: optional("KONCLAVE_ACCEPTANCE_CONTAINER_RUN_ID"),
        }
    }
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(required(name));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn required_bool(name: &str) -> bool {
    match required(name).as_str() {
        "true" => true,
        "false" => false,
        _ => panic!("{name} must be true or false"),
    }
}

struct GatewayFixture {
    runtime_config_path: PathBuf,
    config_root: PathBuf,
    credential_root: PathBuf,
    socket_root: PathBuf,
    task_root: PathBuf,
    object_root: PathBuf,
    endpoint: String,
}

struct GatewayAcceptanceRoute<'a> {
    conversation_id: &'a str,
    target_device_id: &'a str,
    policy_digest: &'a str,
}

struct GatewayProcess {
    child: Option<Child>,
    container_name: Option<String>,
}

impl GatewayProcess {
    fn start(paths: &AcceptancePaths, fixture: &GatewayFixture, attempt: u8) -> Self {
        let mut command = if paths.gateway_container {
            let mut command = TokioCommand::new("bash");
            command.arg(&paths.gateway);
            command
        } else {
            TokioCommand::new(&paths.gateway)
        };
        command
            .env(
                "KONCLAVE_A2A_GATEWAY_CONFIG_FILE",
                &fixture.runtime_config_path,
            )
            .env(
                "KONCLAVE_ACCEPTANCE_GATEWAY_CONFIG_ROOT",
                &fixture.config_root,
            )
            .env(
                "KONCLAVE_ACCEPTANCE_GATEWAY_CREDENTIAL_ROOT",
                &fixture.credential_root,
            )
            .env(
                "KONCLAVE_ACCEPTANCE_GATEWAY_SOCKET_ROOT",
                &fixture.socket_root,
            )
            .env("KONCLAVE_ACCEPTANCE_GATEWAY_TASK_ROOT", &fixture.task_root)
            .env(
                "KONCLAVE_ACCEPTANCE_GATEWAY_OBJECT_ROOT",
                &fixture.object_root,
            )
            .env(
                "KONCLAVE_ACCEPTANCE_GATEWAY_HEALTH_ADDRESS",
                &paths.gateway_address,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let container_name = if paths.gateway_container {
            let container_name = paths
                .gateway_container_name
                .as_deref()
                .expect("gateway container name is required");
            let container_name = format!("{container_name}-{attempt}");
            command
                .env(
                    "KONCLAVE_ACCEPTANCE_GATEWAY_IMAGE",
                    paths
                        .gateway_image
                        .as_deref()
                        .expect("gateway container image is required"),
                )
                .env(
                    "KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER_NAME",
                    &container_name,
                )
                .env(
                    "KONCLAVE_ACCEPTANCE_CONTAINER_RUN_ID",
                    paths
                        .container_run_id
                        .as_deref()
                        .expect("container run identity is required"),
                );
            Some(container_name)
        } else {
            None
        };
        let child = command.spawn().expect("packaged A2A gateway must start");
        Self {
            child: Some(child),
            container_name,
        }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().and_then(Child::id).unwrap()
    }

    async fn shutdown(mut self) {
        if let Some(container_name) = &self.container_name {
            let status = TokioCommand::new("docker")
                .args(["stop", "--time", "90"])
                .arg(container_name)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .await
                .expect("gateway container stop must execute");
            assert!(status.success(), "gateway container stop failed");
        } else {
            let process_id =
                i32::try_from(self.id()).expect("gateway process identifier exceeds Unix pid_t");
            // SAFETY: this fixture spawned `process_id`, still owns its live Child
            // handle, and sends SIGTERM to exercise coordinated shutdown.
            assert_eq!(unsafe { libc::kill(process_id, libc::SIGTERM) }, 0);
        }
        let status = timeout(
            Duration::from_secs(100),
            self.child.as_mut().unwrap().wait(),
        )
        .await
        .expect("A2A gateway shutdown exceeded its deadline")
        .expect("waiting for packaged A2A gateway failed");
        assert!(status.success(), "A2A gateway exited with {status}");
        self.child = None;
    }
}

fn ensure_owner_directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn copy_owner_file(source: &Path, destination: &Path) {
    let bytes = std::fs::read(source).unwrap();
    create_or_verify_owner_protected_file(destination, &bytes).unwrap();
}

fn prepare_gateway_fixture(
    paths: &AcceptancePaths,
    installation: &LocalServiceInstallation,
    installation_file: &Path,
    issuer_key_file: &Path,
    conversation_id: &str,
    target_device_id: &str,
) -> GatewayFixture {
    let root = paths.profile_root.parent().unwrap().join("gateway");
    let config_root = root.join("config");
    let credential_root = root.join("credentials");
    let task_root = root.join("tasks");
    let object_root = root.join("objects");
    for directory in [
        &root,
        &config_root,
        &credential_root,
        &task_root,
        &object_root,
    ] {
        ensure_owner_directory(directory);
    }
    let installed_service =
        credential_root.join(KonclaveLocalServiceTransport::LOCAL_SERVICE_INSTALLATION_FILE);
    let installed_issuer = credential_root.join("account-issuer.key");
    let bearer_file = credential_root.join("a2a-bearer");
    copy_owner_file(installation_file, &installed_service);
    copy_owner_file(issuer_key_file, &installed_issuer);
    create_or_verify_owner_protected_file(&bearer_file, A2A_BEARER_TOKEN.as_bytes()).unwrap();

    let (runtime_config_root, runtime_credential_root, runtime_task_root, runtime_object_root) =
        if paths.gateway_container {
            (
                PathBuf::from("/etc/konclave/a2a"),
                PathBuf::from("/run/konclave/credentials"),
                PathBuf::from("/var/lib/konclave/a2a/tasks"),
                PathBuf::from("/var/lib/konclave/a2a/objects"),
            )
        } else {
            (
                config_root.clone(),
                credential_root.clone(),
                task_root.clone(),
                object_root.clone(),
            )
        };
    let endpoint = format!("http://{}", paths.gateway_address);
    let publication_file = config_root.join("agent-publication.json");
    let runtime_publication_file = runtime_config_root.join("agent-publication.json");
    let publication = serde_json::to_vec(&serde_json::json!({
        "apiVersion": "konclave.dev/v1",
        "kind": "A2AAgentPublication",
        "metadata": { "name": "packaged-agent" },
        "spec": {
            "publicWellKnown": true,
            "name": "Packaged agent",
            "description": "Exercises one packaged A2A request.",
            "version": "1.0.0",
            "interfaces": [{ "url": format!("{endpoint}/") }],
            "authentication": {
                "type": "bearer",
                "name": "bearer",
                "bearerFormat": "opaque"
            },
            "skills": [{
                "id": "contract-review",
                "name": "Contract review",
                "description": "Returns one deterministic response.",
                "tags": ["contracts", "text"]
            }]
        }
    }))
    .unwrap();
    create_or_verify_owner_protected_file(&publication_file, &publication).unwrap();

    let config_path = config_root.join("gateway.json");
    let config = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "interfaceEnvironment": "loopback_development",
        "listener": {
            "address": paths.gateway_address.as_str(),
            "tlsTerminated": false
        },
        "publicationFile": runtime_publication_file,
        "taskDatabaseFile": runtime_task_root.join("tasks.sqlite"),
        "artifactObjectDirectory": runtime_object_root,
        "route": {
            "contextId": A2A_CONTEXT_ID,
            "conversationId": conversation_id,
            "targetDeviceId": target_device_id
        },
        "localService": {
            "installationFile": runtime_credential_root.join(
                KonclaveLocalServiceTransport::LOCAL_SERVICE_INSTALLATION_FILE
            ),
            "issuerKeyFile": runtime_credential_root.join("account-issuer.key"),
            "profile": "session-packaged-a"
        },
        "bearerTokenFiles": [runtime_credential_root.join("a2a-bearer")]
    }))
    .unwrap();
    create_or_verify_owner_protected_file(&config_path, &config).unwrap();

    let endpoint_path = installation.endpoint().as_path();
    GatewayFixture {
        runtime_config_path: if paths.gateway_container {
            runtime_config_root.join("gateway.json")
        } else {
            config_path
        },
        config_root,
        credential_root,
        socket_root: endpoint_path.parent().unwrap().to_path_buf(),
        task_root,
        object_root,
        endpoint,
    }
}

fn run_cli(paths: &AcceptancePaths, arguments: &[OsString], expect_success: bool) -> String {
    let output = Command::new(&paths.cli)
        .args(arguments)
        .output()
        .expect("packaged CLI must start");
    assert_eq!(
        output.status.success(),
        expect_success,
        "packaged CLI status was unexpected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("packaged CLI output must be UTF-8")
}

struct GenericInvocation<'a> {
    profile: &'a str,
    profile_mode: &'a str,
    integration_label: &'a str,
    operation: &'a str,
    request_id: Option<&'a str>,
    payload: serde_json::Value,
}

fn run_generic(
    module: &Path,
    invocation: GenericInvocation<'_>,
    expect_success: bool,
) -> serde_json::Value {
    let mut command = Command::new("node");
    command
        .arg(module)
        .args([
            "--profile",
            invocation.profile,
            "--profile-mode",
            invocation.profile_mode,
            "--integration-label",
            invocation.integration_label,
            "--operation",
            invocation.operation,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(request_id) = invocation.request_id {
        command.args(["--request-id", request_id]);
    }
    let mut child = command.spawn().expect("packaged generic client must start");
    let payload = serde_json::to_vec(&invocation.payload).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&payload).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.success(),
        expect_success,
        "packaged generic client status was unexpected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(if expect_success {
        &output.stdout
    } else {
        &output.stderr
    })
    .unwrap();
    if !expect_success {
        return document;
    }
    assert_eq!(document["integration"]["kind"], "generic");
    assert_eq!(
        document["integration"]["label"],
        invocation.integration_label
    );
    assert_eq!(document["profile"]["alias"], invocation.profile);
    assert_eq!(document["profile"]["mode"], invocation.profile_mode);
    document["result"].clone()
}

fn assert_process_has_no_secret_input(process_id: u32, sentinels: &[&[u8]]) {
    let environment = std::fs::read(format!("/proc/{process_id}/environ")).unwrap();
    let command_line = std::fs::read(format!("/proc/{process_id}/cmdline")).unwrap();
    for sentinel in sentinels {
        assert!(!contains(&environment, sentinel));
        assert!(!contains(&command_line, sentinel));
    }
}

fn assert_relay_opaque(root: &Path, sentinels: &[&[u8]]) {
    for entry in walkdir(root) {
        let metadata = std::fs::metadata(&entry).unwrap();
        if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
            continue;
        }
        let bytes = std::fs::read(&entry).unwrap();
        for sentinel in sentinels {
            assert!(
                !contains(&bytes, sentinel),
                "relay state {} contains a protected sentinel",
                entry.display()
            );
        }
    }
}

fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

async fn finish_delivery_event(
    delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    event: &serde_json::Value,
) {
    rpc(
        delivery,
        "delivery.acknowledge",
        serde_json::json!({
            "notificationId": event["notificationId"],
            "leaseGeneration": event["leaseGeneration"]
        }),
    )
    .await;
}

async fn drain_delivery(delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream) {
    for _ in 0..8 {
        let claimed = rpc(
            delivery,
            "delivery.claim",
            serde_json::json!({"maxEvents": 16, "waitMilliseconds": 0}),
        )
        .await;
        let events = claimed["events"].as_array().unwrap();
        if events.is_empty() {
            return;
        }
        for event in events {
            finish_delivery_event(delivery, event).await;
        }
    }
    panic!("packaged delivery backlog did not drain within its bound");
}

async fn claim_application_text(
    delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    expected_text: &str,
) -> serde_json::Value {
    timeout(Duration::from_secs(10), async {
        loop {
            let claimed = rpc(
                delivery,
                "delivery.claim",
                serde_json::json!({"maxEvents": 16, "waitMilliseconds": 1_000}),
            )
            .await;
            for event in claimed["events"].as_array().unwrap() {
                if event["payload"]["kind"].as_str() == Some("application_text")
                    && event["payload"]["text"].as_str() == Some(expected_text)
                {
                    return event.clone();
                }
                finish_delivery_event(delivery, event).await;
            }
        }
    })
    .await
    .expect("expected application delivery was not claimed")
}

async fn claim_directed_request(
    delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    expected_text: &str,
) -> serde_json::Value {
    timeout(Duration::from_secs(10), async {
        loop {
            let claimed = rpc(
                delivery,
                "delivery.claim",
                serde_json::json!({"maxEvents": 16, "waitMilliseconds": 1_000}),
            )
            .await;
            for event in claimed["events"].as_array().unwrap() {
                if event["payload"]["kind"].as_str() == Some("directed_request")
                    && event["payload"]["text"].as_str() == Some(expected_text)
                {
                    return event.clone();
                }
                finish_delivery_event(delivery, event).await;
            }
        }
    })
    .await
    .expect("expected directed request was not claimed")
}

async fn connect_gateway_client(fixture: &GatewayFixture) -> A2AHttpJsonClient {
    let config =
        A2AHttpClientConfig::new(Duration::from_secs(5), MAX_A2A_ENCODED_RESPONSE_BYTES).unwrap();
    let discovery_url = format!("{}/.well-known/agent-card.json", fixture.endpoint);
    for _ in 0..200 {
        if let Ok(A2AAgentCardFetchOutcome::Modified { card, .. }) = fetch_public_agent_card(
            &discovery_url,
            InitialA2AInterfaceEnvironment::LoopbackDevelopment,
            None,
            None,
            config,
        )
        .await
        {
            return A2AHttpJsonClient::new(
                &card,
                Some(A2ABearerCredential::parse(A2A_BEARER_TOKEN).unwrap()),
                config,
            )
            .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("packaged A2A gateway never became ready");
}

fn packaged_a2a_request() -> KonclaveA2AContracts::InitialSendMessageRequest {
    validate_initial_send_message_request(
        SendMessageRequest {
            tenant: String::new(),
            message: Some(A2AMessage {
                message_id: "packaged-a2a-request".to_owned(),
                context_id: A2A_CONTEXT_ID.to_owned(),
                task_id: String::new(),
                role: A2ARole::User as i32,
                parts: vec![A2APart {
                    content: Some(a2a_part::Content::Text(A2A_REQUEST_TEXT.to_owned())),
                    metadata: None,
                    filename: String::new(),
                    media_type: A2A_TEXT_MEDIA_TYPE.to_owned(),
                }],
                metadata: None,
                extensions: vec![],
                reference_task_ids: vec![],
            }),
            configuration: Some(SendMessageConfiguration {
                accepted_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_owned()],
                task_push_notification_config: None,
                history_length: Some(1),
                return_immediately: true,
            }),
            metadata: None,
        },
        None,
    )
    .unwrap()
}

fn task_contains_agent_text(
    task: &KonclaveA2AContracts::InitialA2ATaskResponse,
    expected: &str,
) -> bool {
    task.as_wire().history.iter().any(|message| {
        message.role == A2ARole::Agent as i32
            && message.parts.iter().any(|part| {
                matches!(
                    &part.content,
                    Some(a2a_part::Content::Text(text)) if text == expected
                )
            })
    })
}

fn assert_ciphertext_endpoint(fixture: &GatewayFixture, object_id: &str, expected: &[u8]) {
    let url = format!("{}/objects/sha256/{object_id}", fixture.endpoint);
    let output = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--max-time", "5"])
        .arg(&url)
        .output()
        .expect("ciphertext retrieval must execute");
    assert!(
        output.status.success(),
        "ciphertext retrieval failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected);

    let range = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--header",
            "Range: bytes=0-1",
        ])
        .arg(&url)
        .output()
        .expect("ciphertext range rejection must execute");
    assert!(range.status.success());
    assert_eq!(range.stdout, b"416");
}

fn assert_gateway_anonymous_rejected(fixture: &GatewayFixture) {
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--header",
            "Accept: application/a2a+json",
            "--header",
            "A2A-Version: 1.0",
        ])
        .arg(format!("{}/tasks", fixture.endpoint))
        .output()
        .expect("anonymous gateway request must execute");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"401");
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn assert_terminal_text_not_authorized(
    delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    conversation_id: &str,
    policy_digest: &str,
    event: &serde_json::Value,
) {
    let turn = rpc(
        delivery,
        "collaboration.turn.authorize",
        serde_json::json!({
            "conversationId": conversation_id,
            "requestMessageId": event["payload"]["messageId"],
            "notificationId": event["notificationId"],
            "leaseGeneration": event["leaseGeneration"]
        }),
    )
    .await;
    assert_eq!(turn["outcome"].as_str(), Some("denied"));
    assert_eq!(turn["reason"].as_str(), Some("directed_request_invalid"));
    assert_eq!(turn["policyDigest"].as_str(), Some(policy_digest));
}

async fn connect_session_lane(
    installation: &LocalServiceInstallation,
    issuer_identity: &LocalServiceIdentity,
    issuer_key_id: AdapterKeyId,
    issuer_key_version: AdapterKeyVersion,
    profile: &str,
    instance: u8,
    session_identity: &LocalServiceIdentity,
) -> KonclaveLocalServiceTransport::LocalServiceClientStream {
    connect_with_session_identity(SessionConnectionRequest {
        endpoint: installation.endpoint(),
        service_key: installation.service_public_key(),
        issuer_identity,
        issuer_key_id,
        issuer_key_version,
        profile,
        instance,
        session_identity,
    })
    .await
}

async fn exercise_packaged_gateway(
    paths: &AcceptancePaths,
    installation: &LocalServiceInstallation,
    installation_file: &Path,
    issuer_key_file: &Path,
    route: GatewayAcceptanceRoute<'_>,
    target_delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
) {
    let fixture = prepare_gateway_fixture(
        paths,
        installation,
        installation_file,
        issuer_key_file,
        route.conversation_id,
        route.target_device_id,
    );
    let ciphertext = b"packaged-encrypted-object-ciphertext";
    let object_id = sha256_hex(ciphertext);
    create_or_verify_owner_protected_file(&fixture.object_root.join(&object_id), ciphertext)
        .unwrap();

    let gateway = GatewayProcess::start(paths, &fixture, 1);
    let client = connect_gateway_client(&fixture).await;
    assert_gateway_anonymous_rejected(&fixture);
    let submitted = client.send_message(packaged_a2a_request()).await.unwrap();
    assert!(matches!(
        submitted.state(),
        A2ATaskState::Submitted | A2ATaskState::Working
    ));
    assert_eq!(submitted.context_id(), A2A_CONTEXT_ID);
    let task_id = A2ATaskId::parse(submitted.task_id().to_owned()).unwrap();

    let request_event = claim_directed_request(target_delivery, A2A_REQUEST_TEXT).await;
    assert_eq!(
        request_event["payload"]["targetDeviceId"].as_str(),
        Some(route.target_device_id)
    );
    let request_message_id = request_event["payload"]["messageId"].as_str().unwrap();
    let turn = rpc(
        target_delivery,
        "collaboration.turn.authorize",
        serde_json::json!({
            "conversationId": route.conversation_id,
            "requestMessageId": request_message_id,
            "notificationId": request_event["notificationId"],
            "leaseGeneration": request_event["leaseGeneration"]
        }),
    )
    .await;
    assert_eq!(turn["outcome"].as_str(), Some("authorized"));
    assert_eq!(turn["policyDigest"].as_str(), Some(route.policy_digest));
    let attempt = turn["attempt"].as_u64().unwrap();
    let response_message_id = "61".repeat(16);
    let action = rpc(
        target_delivery,
        "collaboration.action.evaluate",
        serde_json::json!({
            "conversationId": route.conversation_id,
            "policyDigest": route.policy_digest,
            "action": "conversation.reply",
            "resource": null,
            "messageId": response_message_id,
            "replyToMessageId": request_message_id,
            "text": A2A_RESPONSE_TEXT,
            "requestMessageId": request_message_id,
            "attempt": attempt
        }),
    )
    .await;
    assert_eq!(action["decision"].as_str(), Some("allow"));
    let collaboration_authorization = action["authorization"].as_str().unwrap();
    rpc(
        target_delivery,
        "send_message",
        serde_json::json!({
            "conversation_id": route.conversation_id,
            "message_id": response_message_id,
            "reply_to_message_id": request_message_id,
            "text": A2A_RESPONSE_TEXT,
            "collaboration_authorization": collaboration_authorization
        }),
    )
    .await;
    finish_delivery_event(target_delivery, &request_event).await;

    let completed = timeout(Duration::from_secs(15), async {
        loop {
            let task = client.get_task(&task_id, Some(1)).await.unwrap();
            if task.state() == A2ATaskState::Completed {
                break task;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("packaged A2A task did not complete");
    assert!(task_contains_agent_text(&completed, A2A_RESPONSE_TEXT));
    let listed = client.list_tasks(Some(10), None).await.unwrap();
    assert!(
        listed
            .as_wire()
            .tasks
            .iter()
            .any(|task| task.id.as_str() == task_id.as_str())
    );
    assert_ciphertext_endpoint(&fixture, &object_id, ciphertext);
    assert_process_has_no_secret_input(
        gateway.id(),
        &[
            A2A_BEARER_TOKEN.as_bytes(),
            A2A_REQUEST_TEXT.as_bytes(),
            A2A_RESPONSE_TEXT.as_bytes(),
        ],
    );
    assert_relay_opaque(
        &paths.relay_state,
        &[A2A_REQUEST_TEXT.as_bytes(), A2A_RESPONSE_TEXT.as_bytes()],
    );
    gateway.shutdown().await;

    let restarted = GatewayProcess::start(paths, &fixture, 2);
    let restarted_client = connect_gateway_client(&fixture).await;
    let recovered = restarted_client.get_task(&task_id, Some(1)).await.unwrap();
    assert!(recovered.state() == A2ATaskState::Completed);
    assert!(task_contains_agent_text(&recovered, A2A_RESPONSE_TEXT));
    let listed = restarted_client.list_tasks(Some(10), None).await.unwrap();
    assert!(
        listed
            .as_wire()
            .tasks
            .iter()
            .any(|task| task.id.as_str() == task_id.as_str())
    );
    assert_ciphertext_endpoint(&fixture, &object_id, ciphertext);
    restarted.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires extracted release artifacts, packaged relays, and packaged A2A gateways"]
async fn packaged_shared_service_pairs_replays_restarts_enforces_policy_and_remains_opaque() {
    let paths = AcceptancePaths::from_environment();
    for binary in [
        &paths.cli,
        &paths.service,
        &paths.second_service,
        &paths.gateway,
    ] {
        assert!(binary.is_file(), "packaged binary is missing");
    }
    assert!(paths.client_module.is_file());
    assert!(paths.generic_module.is_file());
    assert!(paths.generic_skill.is_file());
    assert!(
        !paths
            .client_module
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("bin")
            .join("KonclaveLocalDaemon")
            .exists()
    );

    let init_output = run_cli(
        &paths,
        &[
            OsString::from("init"),
            OsString::from("--relay-endpoint"),
            OsString::from(&paths.relay_endpoint),
            OsString::from("--authorization-policy"),
            OsString::from("account-trusted"),
            OsString::from("--profile-root"),
            paths.profile_root.clone().into_os_string(),
            OsString::from("--external-source"),
            paths.enrollment_source.clone().into_os_string(),
            OsString::from("--copilot-extension-root"),
            paths.extension_root.clone().into_os_string(),
            OsString::from("--local-service-identity-file"),
            paths.service_identity.clone().into_os_string(),
            OsString::from("--local-service-profile-key-directory"),
            paths.profile_keys.clone().into_os_string(),
        ],
        true,
    );
    assert!(init_output.contains("shared local service"));
    let installed_generic = paths.extension_root.join("generic.mjs");
    std::fs::copy(&paths.generic_module, &installed_generic).unwrap();
    for (profile, value) in [
        ("session-packaged-a", 31_u8),
        ("session-packaged-b", 32_u8),
        ("generic-packaged", 33_u8),
    ] {
        create_or_verify_owner_protected_file(
            &paths.profile_keys.join(format!("{profile}.key")),
            &[value; 32],
        )
        .unwrap();
    }

    let config_path = paths
        .profile_root
        .parent()
        .unwrap()
        .join("service")
        .join(KonclaveLocalServiceTransport::LOCAL_SERVICE_INSTALLATION_FILE);
    let installation =
        LocalServiceInstallation::from_reader(open_owner_protected_file(&config_path).unwrap())
            .unwrap();
    assert_eq!(
        installation.profile_custody(),
        &LocalServiceProfileCustody::ExternalDirectory(paths.profile_keys.clone())
    );
    let issuer = &installation.issuers()[0];
    let issuer_seed_path = paths
        .profile_root
        .parent()
        .unwrap()
        .join("service")
        .join("account-issuer.key");
    let issuer_seed =
        LocalServiceSigningSeed::from_reader(open_owner_protected_file(&issuer_seed_path).unwrap())
            .unwrap();
    let issuer_identity = LocalServiceIdentity::from_signing_seed(&issuer_seed).unwrap();

    let service = SharedServiceProcess::start_with_inherited_stderr(&paths.service, &config_path);
    let generic_identity = run_generic(
        &installed_generic,
        GenericInvocation {
            profile: "generic-packaged",
            profile_mode: "durable",
            integration_label: "package-unknown-harness",
            operation: "get_identity",
            request_id: None,
            payload: serde_json::json!({}),
        },
        true,
    );
    assert!(generic_identity["device_id"].as_str().is_some());
    let mut first = connect(
        installation.endpoint(),
        installation.service_public_key(),
        &issuer_identity,
        issuer.issuer_key_id(),
        issuer.issuer_key_version(),
        "session-packaged-a",
        1,
    )
    .await;
    let mut second = connect(
        installation.endpoint(),
        installation.service_public_key(),
        &issuer_identity,
        issuer.issuer_key_id(),
        issuer.issuer_key_version(),
        "session-packaged-b",
        2,
    )
    .await;
    let first_identity = identity(&mut first).await;
    let second_identity = identity(&mut second).await;
    assert_ne!(first_identity, second_identity);
    let (_pairing_id, conversation_id) = complete_pairing(&mut first, &mut second).await;

    let generic_pairing = run_generic(
        &installed_generic,
        GenericInvocation {
            profile: "generic-packaged",
            profile_mode: "durable",
            integration_label: "package-unknown-harness",
            operation: "create_pairing_capability",
            request_id: Some("71".repeat(16).as_str()),
            payload: serde_json::json!({"requested_role": "member"}),
        },
        true,
    );
    let generic_pairing_id = generic_pairing["pairing"]["pairing_id"]
        .as_str()
        .unwrap()
        .to_string();
    let generic_capability =
        Zeroizing::new(generic_pairing["capability"].as_str().unwrap().to_string());
    drop(generic_pairing);
    let redeemed = rpc(
        &mut first,
        "redeem_pairing_capability",
        serde_json::json!({"capability": generic_capability.as_str()}),
    )
    .await;
    assert_eq!(redeemed["pairing_id"], generic_pairing_id);
    let generic_conversation = rpc(&mut first, "create_conversation", serde_json::json!({})).await;
    let generic_conversation_id = generic_conversation["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    rpc(
        &mut first,
        "authorize_pairing_joiner",
        serde_json::json!({
            "pairing_id": generic_pairing_id,
            "conversation_id": generic_conversation_id,
            "granted_role": "member"
        }),
    )
    .await;
    let mut generic_inviter_authorized = false;
    let mut generic_pairing_completed = false;
    for attempt in 0_u8..16 {
        let sync_request_id = format!("{:02x}", 80 + attempt).repeat(16);
        let mut generic_status = run_generic(
            &installed_generic,
            GenericInvocation {
                profile: "generic-packaged",
                profile_mode: "durable",
                integration_label: "package-unknown-harness",
                operation: "sync_pairing",
                request_id: Some(&sync_request_id),
                payload: serde_json::json!({"pairing_id": generic_pairing_id}),
            },
            true,
        );
        if !generic_inviter_authorized
            && generic_status["pairing"]["phase"] == "joiner_awaiting_inviter_authorization"
        {
            let authorize_request_id = format!("{:02x}", 96 + attempt).repeat(16);
            let pairing = &generic_status["pairing"];
            generic_status = run_generic(
                &installed_generic,
                GenericInvocation {
                    profile: "generic-packaged",
                    profile_mode: "durable",
                    integration_label: "package-unknown-harness",
                    operation: "authorize_pairing_inviter",
                    request_id: Some(&authorize_request_id),
                    payload: serde_json::json!({
                        "pairing_id": generic_pairing_id,
                        "inviter_device_id": pairing["inviter_device_id"],
                        "conversation_id": pairing["conversation_id"],
                        "granted_role": pairing["granted_role"]
                    }),
                },
                true,
            );
            generic_inviter_authorized = true;
        }
        let paved_status = rpc(
            &mut first,
            "sync_pairing",
            serde_json::json!({"pairing_id": generic_pairing_id}),
        )
        .await;
        if generic_status["pairing"]["phase"] == "completed"
            && paved_status["pairing"]["phase"] == "completed"
        {
            generic_pairing_completed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        generic_pairing_completed,
        "packaged Generic-to-paved pairing did not complete"
    );

    let generic_text = "packaged generic client message";
    run_generic(
        &installed_generic,
        GenericInvocation {
            profile: "generic-packaged",
            profile_mode: "durable",
            integration_label: "package-unknown-harness",
            operation: "send_message",
            request_id: Some("b1".repeat(16).as_str()),
            payload: serde_json::json!({
                "conversation_id": generic_conversation_id,
                "message_id": "61".repeat(16),
                "text": generic_text
            }),
        },
        true,
    );
    timeout(Duration::from_secs(10), async {
        loop {
            rpc(
                &mut first,
                "sync_messages",
                serde_json::json!({"conversation_id": generic_conversation_id}),
            )
            .await;
            let history = rpc(
                &mut first,
                "read_messages",
                serde_json::json!({"conversation_id": generic_conversation_id, "limit": 100}),
            )
            .await;
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == generic_text)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("packaged generic client message was not delivered");
    let generic_reply = "packaged paved-session reply";
    rpc(
        &mut first,
        "send_message",
        serde_json::json!({
            "conversation_id": generic_conversation_id,
            "message_id": "62".repeat(16),
            "reply_to_message_id": "61".repeat(16),
            "text": generic_reply
        }),
    )
    .await;
    timeout(Duration::from_secs(10), async {
        for attempt in 0_u8..16 {
            let sync_request_id = format!("{:02x}", 128 + attempt).repeat(16);
            run_generic(
                &installed_generic,
                GenericInvocation {
                    profile: "generic-packaged",
                    profile_mode: "durable",
                    integration_label: "package-unknown-harness",
                    operation: "sync_messages",
                    request_id: Some(&sync_request_id),
                    payload: serde_json::json!({"conversation_id": generic_conversation_id}),
                },
                true,
            );
            let history = run_generic(
                &installed_generic,
                GenericInvocation {
                    profile: "generic-packaged",
                    profile_mode: "durable",
                    integration_label: "package-unknown-harness",
                    operation: "read_messages",
                    request_id: None,
                    payload: serde_json::json!({
                        "conversation_id": generic_conversation_id,
                        "limit": 100
                    }),
                },
                true,
            );
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == generic_reply)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("generic client did not observe the paved-session reply");
    })
    .await
    .expect("packaged paved-session reply was not delivered to the generic client");

    drop(second);
    let first_text = "packaged shared-service offline message";
    rpc(
        &mut first,
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": "31".repeat(16),
            "text": first_text
        }),
    )
    .await;
    let mut second = connect(
        installation.endpoint(),
        installation.service_public_key(),
        &issuer_identity,
        issuer.issuer_key_id(),
        issuer.issuer_key_version(),
        "session-packaged-b",
        3,
    )
    .await;
    timeout(Duration::from_secs(10), async {
        loop {
            rpc(
                &mut second,
                "sync_messages",
                serde_json::json!({"conversation_id": conversation_id}),
            )
            .await;
            let history = rpc(
                &mut second,
                "read_messages",
                serde_json::json!({"conversation_id": conversation_id, "limit": 100}),
            )
            .await;
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == first_text)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("packaged offline message was not replayed");
    let reply_text = "packaged shared-service reply";
    rpc(
        &mut second,
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": "32".repeat(16),
            "reply_to_message_id": "31".repeat(16),
            "text": reply_text
        }),
    )
    .await;
    timeout(Duration::from_secs(10), async {
        loop {
            rpc(
                &mut first,
                "sync_messages",
                serde_json::json!({"conversation_id": conversation_id}),
            )
            .await;
            let history = rpc(
                &mut first,
                "read_messages",
                serde_json::json!({"conversation_id": conversation_id, "limit": 100}),
            )
            .await;
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == reply_text)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("packaged reply was not delivered");

    let policy_source = r#"{
  "apiVersion": "konclave.dev/v2",
  "kind": "CollaborationPolicy",
  "metadata": { "name": "packaged-request-reply" },
  "spec": {
    "statements": [
      {
        "id": "conversation-reply",
        "effect": "allow",
        "action": "conversation.reply"
      }
    ],
    "requiredHarnessClaims": [
      "harness.native-permission-intersection",
      "harness.pre-tool-policy-gate",
      "harness.session-identity",
      "harness.single-delivery-consumer"
    ],
    "limits": {
      "durationMilliseconds": null,
      "turns": null,
      "tokens": null,
      "concurrentRequests": 1
    }
  }
}"#;
    let proposal_id = "41".repeat(16);
    let proposed = rpc(
        &mut first,
        "propose_collaboration_policy_source",
        serde_json::json!({
            "conversation_id": conversation_id,
            "proposal_id": proposal_id,
            "source": policy_source
        }),
    )
    .await;
    let policy_digest = proposed["policy_digest"].as_str().unwrap().to_string();
    rpc(
        &mut second,
        "sync_messages",
        serde_json::json!({"conversation_id": conversation_id}),
    )
    .await;
    let inspected = rpc(
        &mut second,
        "inspect_collaboration_policy_proposal",
        serde_json::json!({
            "conversation_id": conversation_id,
            "proposal_id": proposal_id
        }),
    )
    .await;
    assert_eq!(
        inspected["policy_digest"].as_str(),
        Some(policy_digest.as_str())
    );
    assert!(inspected["untrusted_guidance"].is_null());
    assert_eq!(inspected["statements"].as_array().unwrap().len(), 1);
    assert_eq!(
        inspected["required_harness_claims"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    rpc(
        &mut second,
        "accept_collaboration_policy",
        serde_json::json!({
            "conversation_id": conversation_id,
            "proposal_id": proposal_id,
            "policy_digest": policy_digest
        }),
    )
    .await;
    for client in [&mut first, &mut second] {
        let status = rpc(
            client,
            "get_collaboration_policy_status",
            serde_json::json!({"conversation_id": conversation_id}),
        )
        .await;
        assert_eq!(
            status["active_policy"]["policy_digest"].as_str(),
            Some(policy_digest.as_str())
        );
    }

    let doctor_output = run_cli(
        &paths,
        &[
            OsString::from("doctor"),
            OsString::from("--profile-root"),
            paths.profile_root.clone().into_os_string(),
            OsString::from("--install-root"),
            paths.install_root.clone().into_os_string(),
        ],
        true,
    );
    for expected in [
        "PASS local_service_binary:",
        "PASS copilot_plugin:",
        "PASS local_service_config:",
        "PASS local_service_running:",
    ] {
        assert!(doctor_output.contains(expected));
    }
    let protected_source = std::fs::read(&paths.enrollment_source).unwrap();
    let sentinels = [
        first_text.as_bytes(),
        reply_text.as_bytes(),
        generic_text.as_bytes(),
        generic_reply.as_bytes(),
        generic_capability.as_bytes(),
        policy_source.as_bytes(),
        protected_source.as_slice(),
    ];
    assert_process_has_no_secret_input(service.id(), &sentinels);
    assert_relay_opaque(&paths.relay_state, &sentinels);

    drop((first, second));
    service.shutdown().await;
    let restarted =
        SharedServiceProcess::start_with_inherited_stderr(&paths.second_service, &config_path);
    let first_session = LocalServiceIdentity::generate().unwrap();
    let second_session = LocalServiceIdentity::generate().unwrap();
    let issuer_key_id = issuer.issuer_key_id();
    let issuer_key_version = issuer.issuer_key_version();
    let mut first = connect_session_lane(
        &installation,
        &issuer_identity,
        issuer_key_id,
        issuer_key_version,
        "session-packaged-a",
        4,
        &first_session,
    )
    .await;
    let mut first_delivery = connect_session_lane(
        &installation,
        &issuer_identity,
        issuer_key_id,
        issuer_key_version,
        "session-packaged-a",
        5,
        &first_session,
    )
    .await;
    let mut second = connect_session_lane(
        &installation,
        &issuer_identity,
        issuer_key_id,
        issuer_key_version,
        "session-packaged-b",
        6,
        &second_session,
    )
    .await;
    let mut second_delivery = connect_session_lane(
        &installation,
        &issuer_identity,
        issuer_key_id,
        issuer_key_version,
        "session-packaged-b",
        7,
        &second_session,
    )
    .await;
    assert_eq!(identity(&mut first).await, first_identity);
    assert_eq!(identity(&mut second).await, second_identity);
    for client in [&mut first, &mut second] {
        let status = rpc(
            client,
            "get_collaboration_policy_status",
            serde_json::json!({"conversation_id": conversation_id}),
        )
        .await;
        assert_eq!(
            status["active_policy"]["policy_digest"].as_str(),
            Some(policy_digest.as_str())
        );
    }
    drain_delivery(&mut first_delivery).await;
    drain_delivery(&mut second_delivery).await;
    exercise_packaged_gateway(
        &paths,
        &installation,
        &config_path,
        &issuer_seed_path,
        GatewayAcceptanceRoute {
            conversation_id: &conversation_id,
            target_device_id: &second_identity,
            policy_digest: &policy_digest,
        },
        &mut second_delivery,
    )
    .await;
    let unrelated_session = LocalServiceIdentity::generate().unwrap();
    let mut unrelated = connect_session_lane(
        &installation,
        &issuer_identity,
        issuer_key_id,
        issuer_key_version,
        "session-packaged-b",
        8,
        &unrelated_session,
    )
    .await;
    let unrelated_decision = rpc(
        &mut unrelated,
        "collaboration.action.evaluate",
        serde_json::json!({
            "conversationId": conversation_id,
            "policyDigest": policy_digest,
            "action": "conversation.reply",
            "resource": null,
            "messageId": "50".repeat(16),
            "replyToMessageId": null,
            "text": "unrelated session must not inherit the delivery lease",
            "requestMessageId": "49".repeat(16),
            "attempt": 1
        }),
    )
    .await;
    assert_eq!(unrelated_decision["decision"].as_str(), Some("deny"));
    assert_eq!(
        unrelated_decision["reason"].as_str(),
        Some("copilot_delivery_not_proven")
    );
    drop(unrelated);

    let policy_request = "packaged policy-authorized request";
    let policy_reply = "packaged explicit terminal reply";
    let policy_request_id = "51".repeat(16);
    let policy_reply_id = "52".repeat(16);
    rpc(
        &mut first,
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": policy_request_id,
            "text": policy_request
        }),
    )
    .await;
    let request_event = claim_application_text(&mut second_delivery, policy_request).await;
    assert_terminal_text_not_authorized(
        &mut second_delivery,
        &conversation_id,
        &policy_digest,
        &request_event,
    )
    .await;
    rpc(
        &mut second,
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": policy_reply_id,
            "reply_to_message_id": policy_request_id,
            "text": policy_reply
        }),
    )
    .await;
    finish_delivery_event(&mut second_delivery, &request_event).await;

    let reply_event = claim_application_text(&mut first_delivery, policy_reply).await;
    assert_terminal_text_not_authorized(
        &mut first_delivery,
        &conversation_id,
        &policy_digest,
        &reply_event,
    )
    .await;
    finish_delivery_event(&mut first_delivery, &reply_event).await;

    for client in [&mut first, &mut second] {
        let history = rpc(
            client,
            "read_messages",
            serde_json::json!({"conversation_id": conversation_id, "limit": 100}),
        )
        .await;
        let message = history["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["message_id"].as_str() == Some(policy_reply_id.as_str()))
            .unwrap();
        assert_eq!(
            message["reply_to_message_id"].as_str(),
            Some(policy_request_id.as_str())
        );
    }
    assert_process_has_no_secret_input(
        restarted.id(),
        &[policy_request.as_bytes(), policy_reply.as_bytes()],
    );
    assert_relay_opaque(
        &paths.relay_state,
        &[policy_request.as_bytes(), policy_reply.as_bytes()],
    );

    let authorization_before = rpc(&mut first, "service.status", serde_json::json!({})).await;
    let generation_before = authorization_before["authorizationGeneration"]
        .as_u64()
        .unwrap();
    let issuer_key_id = encode_lowercase_hex(issuer.issuer_key_id().as_bytes());
    let issuer_key_version = issuer.issuer_key_version().get().to_string();
    let disable_output = run_cli(
        &paths,
        &[
            OsString::from("authorization"),
            OsString::from("disable-issuer"),
            OsString::from("--profile-root"),
            paths.profile_root.clone().into_os_string(),
            OsString::from("--issuer-key-id"),
            OsString::from(issuer_key_id),
            OsString::from("--issuer-key-version"),
            OsString::from(issuer_key_version),
            OsString::from("--existing-grants"),
            OsString::from("retain"),
        ],
        true,
    );
    assert!(disable_output.contains("issuer disablement: applied"));
    timeout(Duration::from_secs(5), async {
        loop {
            let status = rpc(&mut first, "service.status", serde_json::json!({})).await;
            if status["authorizationGeneration"]
                .as_u64()
                .is_some_and(|generation| generation > generation_before)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shared service did not publish issuer disablement");
    let disabled = run_generic(
        &installed_generic,
        GenericInvocation {
            profile: "generic-packaged",
            profile_mode: "durable",
            integration_label: "package-unknown-harness",
            operation: "get_identity",
            request_id: None,
            payload: serde_json::json!({}),
        },
        false,
    );
    assert_eq!(disabled["error"], "issuer_disabled");
    assert_eq!(disabled["operation"], "authorization.grant.issue");

    drop((first, first_delivery, second, second_delivery));
    restarted.shutdown().await;

    let relay_database = rusqlite::Connection::open_with_flags(
        &paths.relay_database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let active_principals: i64 = relay_database
        .query_row(
            "SELECT count(*) FROM relay_dynamic_principal WHERE status = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_principals, 3);
}
