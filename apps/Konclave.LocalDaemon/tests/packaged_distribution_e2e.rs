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
use KonclaveLocalServiceTransport::{LocalServiceInstallation, LocalServiceProfileCustody};
use KonclaveSecretStorage::{create_or_verify_owner_protected_file, open_owner_protected_file};
use tokio::time::timeout;

use support::shared_service::{SharedServiceProcess, complete_pairing, connect, identity, rpc};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires extracted release artifacts and a packaged relay"]
async fn packaged_shared_service_pairs_replays_restarts_and_remains_opaque() {
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

    let service = SharedServiceProcess::start(&paths.service, &config_path);
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
        protected_source.as_slice(),
    ];
    assert_process_has_no_secret_input(service.id(), &sentinels);
    assert_relay_opaque(&paths.relay_state, &sentinels);

    drop((first, second));
    service.shutdown().await;
    let restarted = SharedServiceProcess::start(&paths.second_service, &config_path);
    let mut recovered = connect(
        installation.endpoint(),
        installation.service_public_key(),
        &issuer_identity,
        issuer.issuer_key_id(),
        issuer.issuer_key_version(),
        "session-packaged-a",
        4,
    )
    .await;
    assert_eq!(identity(&mut recovered).await, first_identity);
    drop(recovered);
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
