use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use KonclaveClientLibrary::RelayEndpoint;

#[test]
fn version_subcommand_prints_version() {
    let mut cmd = Command::cargo_bin("KonclaveCommandLine").unwrap();
    cmd.arg("version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn missing_subcommand_fails() {
    let mut cmd = Command::cargo_bin("KonclaveCommandLine").unwrap();
    cmd.assert().failure();
}

#[test]
#[cfg(unix)]
fn external_init_is_idempotent_and_conflicts_fail() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("profiles");
    let source = directory.path().join("enrollment.credential");
    let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
    let encoded_credential = URL_SAFE_NO_PAD.encode([7; 32]);

    for attempt in 0..2 {
        let mut command = Command::cargo_bin("KonclaveCommandLine").unwrap();
        command
            .args([
                "init",
                "--relay-endpoint",
                endpoint.as_str(),
                "--profile-root",
            ])
            .arg(&root)
            .arg("--external-source")
            .arg(&source);
        if attempt == 0 {
            command.write_stdin(format!("{encoded_credential}\n"));
        }
        command
            .assert()
            .success()
            .stdout(contains("external_file custody"))
            .stdout(predicates::str::contains("BwcHB").not());
    }
    assert!(source.is_file());
    assert!(!std::fs::read(root.join("relay-installation.conf"))
        .unwrap()
        .windows(encoded_credential.len())
        .any(|window| window == encoded_credential.as_bytes()));

    let mut conflict = Command::cargo_bin("KonclaveCommandLine").unwrap();
    conflict
        .args([
            "init",
            "--relay-endpoint",
            "https://other.example.com",
            "--profile-root",
        ])
        .arg(&root)
        .arg("--external-source")
        .arg(&source)
        .assert()
        .failure();
}

#[test]
#[cfg(unix)]
fn doctor_checks_installation_source_layout_and_relay() {
    use std::io::{Read as _, Write as _};

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("profiles");
    let install = directory.path().join("install");
    let source = directory.path().join("enrollment.credential");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint =
        RelayEndpoint::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let daemon = if cfg!(windows) {
        "KonclaveLocalDaemon.exe"
    } else {
        "KonclaveLocalDaemon"
    };
    std::fs::create_dir_all(install.join("bin")).unwrap();
    std::fs::write(install.join("bin").join(daemon), b"test").unwrap();
    let plugin = install.join("share").join("konclave").join("plugin");
    std::fs::create_dir_all(&plugin).unwrap();
    std::fs::write(plugin.join("plugin.json"), br#"{"name":"konclave"}"#).unwrap();

    let mut init = Command::cargo_bin("KonclaveCommandLine").unwrap();
    init.args([
        "init",
        "--relay-endpoint",
        endpoint.as_str(),
        "--profile-root",
    ])
    .arg(&root)
    .arg("--external-source")
    .arg(&source)
    .write_stdin(format!("{}\n", URL_SAFE_NO_PAD.encode([8; 32])))
    .assert()
    .success();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}",
            )
            .unwrap();
    });
    let mut doctor = Command::cargo_bin("KonclaveCommandLine").unwrap();
    doctor
        .arg("doctor")
        .arg("--profile-root")
        .arg(&root)
        .arg("--install-root")
        .arg(&install)
        .assert()
        .success()
        .stdout(contains("PASS installation_config"))
        .stdout(contains("PASS enrollment_source"))
        .stdout(contains("PASS relay_reachable"))
        .stdout(contains("PASS daemon_binary"))
        .stdout(contains("PASS copilot_plugin"))
        .stdout(contains("WARN profiles"));
    server.join().unwrap();
}
