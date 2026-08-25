//! Exercises installed artifacts through a simulated Copilot host boundary.
//!
//! Real Copilot OAuth and cloud inference are intentionally outside this deterministic
//! test. The packaged plugin's bundled daemon, MCP tools, authenticated adapter
//! channel, enrollment, pairing, delivery, and recovery paths are all real.

#![cfg(unix)]

mod support;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use KonclaveAdapterTransport::{AdapterRequest, AdapterResponse, DeliveredPayload};
use serde_json::{Value, json};
use support::{AdapterHost, connect_daemon, pair_with_capability, text_of};
use zeroize::Zeroizing;

const CLAIM_WAIT_MILLISECONDS: u32 = 15_000;

struct AcceptancePaths {
    cli: PathBuf,
    daemon: PathBuf,
    second_daemon: PathBuf,
    install_root: PathBuf,
    relay_endpoint: String,
    access_document: PathBuf,
    enrollment_source: PathBuf,
    profile_root: PathBuf,
    wrapping_key: PathBuf,
    relay_state: PathBuf,
    relay_database: PathBuf,
}

impl AcceptancePaths {
    fn from_environment() -> Self {
        Self {
            cli: required_path("KONCLAVE_ACCEPTANCE_CLI"),
            daemon: required_path("KONCLAVE_ACCEPTANCE_DAEMON"),
            second_daemon: required_path("KONCLAVE_ACCEPTANCE_SECOND_DAEMON"),
            install_root: required_path("KONCLAVE_ACCEPTANCE_INSTALL_ROOT"),
            relay_endpoint: required("KONCLAVE_ACCEPTANCE_RELAY_ENDPOINT"),
            access_document: required_path("KONCLAVE_ACCEPTANCE_ACCESS_DOCUMENT"),
            enrollment_source: required_path("KONCLAVE_ACCEPTANCE_ENROLLMENT_SOURCE"),
            profile_root: required_path("KONCLAVE_ACCEPTANCE_PROFILE_ROOT"),
            wrapping_key: required_path("KONCLAVE_ACCEPTANCE_WRAPPING_KEY"),
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

fn run_cli(paths: &AcceptancePaths, arguments: &[OsString]) -> String {
    let output = Command::new(&paths.cli)
        .args(arguments)
        .output()
        .expect("packaged CLI must start");
    assert!(
        output.status.success(),
        "packaged CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful packaged CLI command wrote diagnostics: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("packaged CLI output must be UTF-8")
}

fn profile_environment() -> Vec<(OsString, OsString)> {
    Vec::new()
}

fn assert_process_has_no_relay_secret_input(process_id: u32, sentinels: &[&[u8]]) {
    let environment = std::fs::read(format!("/proc/{process_id}/environ"))
        .expect("daemon environment must be readable on the hosted runner");
    let command_line = std::fs::read(format!("/proc/{process_id}/cmdline"))
        .expect("daemon command line must be readable on the hosted runner");
    for forbidden in [
        &b"KONCLAVE_RELAY_ENDPOINT"[..],
        &b"KONCLAVE_RELAY_CREDENTIAL_FILE"[..],
    ] {
        assert!(!contains(&environment, forbidden));
    }
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

#[tokio::test]
#[ignore = "requires extracted release artifacts and a packaged relay"]
async fn packaged_sessions_pair_deliver_restart_cancel_and_remain_opaque() {
    let paths = AcceptancePaths::from_environment();
    for binary in [&paths.cli, &paths.daemon, &paths.second_daemon] {
        assert!(
            binary.is_file(),
            "packaged binary is missing: {}",
            binary.display()
        );
    }

    let bootstrap_output = run_cli(
        &paths,
        &[
            OsString::from("relay-bootstrap"),
            OsString::from("--relay-endpoint"),
            OsString::from(&paths.relay_endpoint),
            OsString::from("--access-document"),
            paths.access_document.clone().into_os_string(),
            OsString::from("--external-source"),
            paths.enrollment_source.clone().into_os_string(),
        ],
    );
    assert!(bootstrap_output.contains("external_file custody"));
    let init_output = run_cli(
        &paths,
        &[
            OsString::from("init"),
            OsString::from("--relay-endpoint"),
            OsString::from(&paths.relay_endpoint),
            OsString::from("--profile-root"),
            paths.profile_root.clone().into_os_string(),
            OsString::from("--external-source"),
            paths.enrollment_source.clone().into_os_string(),
        ],
    );
    assert!(init_output.contains("external_file custody"));
    let doctor_output = run_cli(
        &paths,
        &[
            OsString::from("doctor"),
            OsString::from("--profile-root"),
            paths.profile_root.clone().into_os_string(),
            OsString::from("--install-root"),
            paths.install_root.clone().into_os_string(),
        ],
    );
    for expected in [
        "PASS daemon_binary:",
        "PASS copilot_plugin:",
        "PASS installation_config:",
        "PASS enrollment_source:",
        "PASS relay_reachable:",
    ] {
        assert!(
            doctor_output.contains(expected),
            "doctor omitted {expected}"
        );
    }

    let alice_host = AdapterHost::new("alice", 81, 81);
    let bob_host = AdapterHost::new("bob", 82, 82);
    let alice = connect_daemon(
        &paths.daemon,
        &paths.profile_root,
        "alice",
        &paths.wrapping_key,
        profile_environment(),
        Some(&alice_host),
    )
    .await;
    let bob = connect_daemon(
        &paths.daemon,
        &paths.profile_root,
        "bob",
        &paths.wrapping_key,
        profile_environment(),
        Some(&bob_host),
    )
    .await;
    let mut alice_session = alice_host.accept().await;
    let mut bob_session = bob_host.accept().await;
    let (conversation_id, capability) = pair_with_capability(&alice, &bob).await;

    let first_text = b"packaged contract change survives restart";
    alice
        .send(
            &conversation_id,
            "81818181818181818181818181818181",
            std::str::from_utf8(first_text).unwrap(),
        )
        .await;
    let claimed = bob_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let original = claimed
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("packaged receiving session must get automatic delivery")
        .clone();
    assert_eq!(text_of(&original.payload).as_bytes(), first_text);

    bob.kill().await;
    bob_session.abandon();
    let restarted = connect_daemon(
        &paths.second_daemon,
        &paths.profile_root,
        "bob",
        &paths.wrapping_key,
        profile_environment(),
        Some(&bob_host),
    )
    .await;
    let mut recovered = bob_host.accept().await;
    let redelivered = recovered.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let repeated = redelivered
        .iter()
        .find(|event| event.notification_id == original.notification_id)
        .expect("restart through the second extraction must redeliver the stable notification");
    assert_eq!(
        recovered
            .request(&AdapterRequest::Acknowledge {
                notification_id: repeated.notification_id,
                lease_generation: repeated.lease_generation,
            })
            .await,
        AdapterResponse::Accepted
    );

    let second_text = b"packaged reply reached the original session";
    restarted
        .send(
            &conversation_id,
            "82828282828282828282828282828282",
            std::str::from_utf8(second_text).unwrap(),
        )
        .await;
    let replied = alice_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let reply = replied
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("packaged reply must reach the originating session automatically");
    assert_eq!(text_of(&reply.payload).as_bytes(), second_text);

    let cancelled = restarted
        .require(
            "create_pairing_capability",
            json!({"requested_role": "member"}),
        )
        .await;
    let cancelled_capability =
        Zeroizing::new(cancelled["capability"].as_str().unwrap().to_string());
    let cancelled_status = restarted
        .require(
            "cancel_pairing",
            json!({"pairing_id": cancelled["pairing"]["pairing_id"]}),
        )
        .await;
    assert_eq!(
        cancelled_status["phase"],
        Value::String("cancelled".to_string())
    );

    let protected_source = std::fs::read(&paths.enrollment_source).unwrap();
    let sentinels = [
        capability.as_bytes(),
        cancelled_capability.as_bytes(),
        first_text.as_slice(),
        second_text.as_slice(),
        protected_source.as_slice(),
    ];
    assert_process_has_no_relay_secret_input(alice.process_id(), &sentinels);
    assert_process_has_no_relay_secret_input(restarted.process_id(), &sentinels);
    assert!(!alice.diagnostics().contains(capability.as_str()));
    assert!(!restarted.diagnostics().contains(capability.as_str()));
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
    assert_eq!(
        active_principals, 2,
        "two packaged sessions must enroll independent relay principals"
    );
    assert_relay_opaque(&paths.relay_state, &sentinels);

    restarted.close().await;
    alice.close().await;
}
