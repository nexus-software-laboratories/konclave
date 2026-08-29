//! Exercises extracted client artifacts through the shared local-service boundary.
//!
//! Real Copilot OAuth and cloud inference remain outside this deterministic test. The
//! packaged CLI, thin plugin, shared service, relay, pairing, messaging, restart, and
//! profile recovery paths are real.

#![cfg(unix)]

mod support;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, LocalServiceInstallation, LocalServiceProfileCustody,
};
use KonclaveSecretStorage::{create_or_verify_owner_protected_file, open_owner_protected_file};
use tokio::time::timeout;

use support::shared_service::{
    SessionConnectionRequest, SharedServiceProcess, complete_pairing, connect,
    connect_with_session_identity, identity, rpc,
};

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

async fn send_policy_authorized_reply(
    interactive: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    delivery: &mut KonclaveLocalServiceTransport::LocalServiceClientStream,
    conversation_id: &str,
    policy_digest: &str,
    message_id: &str,
    reply_to_message_id: &str,
    text: &str,
) {
    let turn = rpc(
        delivery,
        "collaboration.turn.authorize",
        serde_json::json!({"conversationId": conversation_id}),
    )
    .await;
    assert_eq!(turn["outcome"].as_str(), Some("authorized"));
    assert_eq!(turn["policyDigest"].as_str(), Some(policy_digest));
    let decision = rpc(
        interactive,
        "collaboration.action.evaluate",
        serde_json::json!({
            "conversationId": conversation_id,
            "policyDigest": policy_digest,
            "action": "conversation.reply",
            "resource": null,
            "messageId": message_id,
            "replyToMessageId": reply_to_message_id,
            "text": text
        }),
    )
    .await;
    assert_eq!(decision["decision"].as_str(), Some("allow"));
    let authorization = decision["authorization"].as_str().unwrap();
    let sent = rpc(
        interactive,
        "send_message",
        serde_json::json!({
            "conversation_id": conversation_id,
            "message_id": message_id,
            "reply_to_message_id": reply_to_message_id,
            "text": text,
            "collaboration_authorization": authorization
        }),
    )
    .await;
    assert_eq!(sent["conversation_id"].as_str(), Some(conversation_id));
    assert_eq!(sent["message_id"].as_str(), Some(message_id));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires extracted release artifacts and a packaged relay"]
async fn packaged_shared_service_pairs_replays_restarts_enforces_policy_and_remains_opaque() {
    let paths = AcceptancePaths::from_environment();
    for binary in [&paths.cli, &paths.service, &paths.second_service] {
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
    let generic_output = Command::new("node")
        .arg(&installed_generic)
        .args([
            "--profile",
            "generic-packaged",
            "--operation",
            "get_identity",
        ])
        .output()
        .expect("packaged generic client must start");
    assert!(
        generic_output.status.success(),
        "packaged generic client failed: {}",
        String::from_utf8_lossy(&generic_output.stderr)
    );
    let generic_identity: serde_json::Value =
        serde_json::from_slice(&generic_output.stdout).unwrap();
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
            "text": "unrelated session must not inherit the delivery lease"
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
    let policy_reply = "packaged policy-authorized reply";
    let policy_follow_up = "packaged policy-authorized follow-up";
    let policy_request_id = "51".repeat(16);
    let policy_reply_id = "52".repeat(16);
    let policy_follow_up_id = "53".repeat(16);
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
    send_policy_authorized_reply(
        &mut second,
        &mut second_delivery,
        &conversation_id,
        &policy_digest,
        &policy_reply_id,
        &policy_request_id,
        policy_reply,
    )
    .await;
    finish_delivery_event(&mut second_delivery, &request_event).await;

    let reply_event = claim_application_text(&mut first_delivery, policy_reply).await;
    send_policy_authorized_reply(
        &mut first,
        &mut first_delivery,
        &conversation_id,
        &policy_digest,
        &policy_follow_up_id,
        &policy_reply_id,
        policy_follow_up,
    )
    .await;
    finish_delivery_event(&mut first_delivery, &reply_event).await;

    let follow_up_event = claim_application_text(&mut second_delivery, policy_follow_up).await;
    finish_delivery_event(&mut second_delivery, &follow_up_event).await;
    for (client, message_id, reply_to) in [
        (
            &mut first,
            policy_reply_id.as_str(),
            policy_request_id.as_str(),
        ),
        (
            &mut second,
            policy_follow_up_id.as_str(),
            policy_reply_id.as_str(),
        ),
    ] {
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
            .find(|message| message["message_id"].as_str() == Some(message_id))
            .unwrap();
        assert_eq!(message["reply_to_message_id"].as_str(), Some(reply_to));
    }
    assert_process_has_no_secret_input(
        restarted.id(),
        &[
            policy_request.as_bytes(),
            policy_reply.as_bytes(),
            policy_follow_up.as_bytes(),
        ],
    );
    assert_relay_opaque(
        &paths.relay_state,
        &[
            policy_request.as_bytes(),
            policy_reply.as_bytes(),
            policy_follow_up.as_bytes(),
        ],
    );
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
