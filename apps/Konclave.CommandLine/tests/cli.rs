use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use KonclaveClientLibrary::{RelayEndpoint, RelayEnrollmentCredential};

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
    let extension = directory.path().join("extension");
    let service_identity = directory.path().join("service").join("identity.key");
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
            .arg(&source)
            .arg("--copilot-extension-root")
            .arg(&extension)
            .arg("--local-service-identity-file")
            .arg(&service_identity);
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
        .arg("--copilot-extension-root")
        .arg(&extension)
        .arg("--local-service-identity-file")
        .arg(&service_identity)
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
    let extension = directory.path().join("extension");
    let service_identity = directory.path().join("service").join("identity.key");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint =
        RelayEndpoint::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let service = if cfg!(windows) {
        "KonclaveLocalService.exe"
    } else {
        "KonclaveLocalService"
    };
    std::fs::create_dir_all(install.join("bin")).unwrap();
    std::fs::write(install.join("bin").join(service), b"test").unwrap();
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
    .arg("--copilot-extension-root")
    .arg(&extension)
    .arg("--local-service-identity-file")
    .arg(&service_identity)
    .write_stdin(format!("{}\n", URL_SAFE_NO_PAD.encode([8; 32])))
    .assert()
    .success();

    let service_config = std::fs::File::open(
        directory
            .path()
            .join("service")
            .join(KonclaveLocalServiceTransport::LOCAL_SERVICE_INSTALLATION_FILE),
    )
    .unwrap();
    let service_installation =
        KonclaveLocalServiceTransport::LocalServiceInstallation::from_reader(service_config)
            .unwrap();
    let local_listener =
        std::os::unix::net::UnixListener::bind(service_installation.endpoint().as_path()).unwrap();
    let local_service = std::thread::spawn(move || {
        let _ = local_listener.accept().unwrap();
    });

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
        .stdout(contains("PASS local_service_binary"))
        .stdout(contains("PASS copilot_plugin"))
        .stdout(contains("PASS local_service_config"))
        .stdout(contains("PASS local_service_running"))
        .stdout(contains("WARN profiles"));
    server.join().unwrap();
    local_service.join().unwrap();
}

#[test]
#[cfg(unix)]
fn relay_bootstrap_creates_idempotent_access_and_protected_source() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("profiles");
    let source = directory.path().join("enrollment.credential");
    let access = directory.path().join("relay-access.json");
    let extension = directory.path().join("extension");
    let service_identity = directory.path().join("service").join("identity.key");
    let endpoint = RelayEndpoint::parse("http://127.0.0.1:43123").unwrap();

    for _ in 0..2 {
        let mut bootstrap = Command::cargo_bin("KonclaveCommandLine").unwrap();
        bootstrap
            .arg("relay-bootstrap")
            .arg("--relay-endpoint")
            .arg(endpoint.as_str())
            .arg("--access-document")
            .arg(&access)
            .arg("--external-source")
            .arg(&source)
            .assert()
            .success()
            .stdout(contains("external_file custody"));
    }

    let access_document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&access).unwrap()).unwrap();
    let authority = access_document["enrollment"]["authority"].as_str().unwrap();
    let credential = RelayEnrollmentCredential::from_bound_reader(
        std::fs::File::open(&source).unwrap(),
        &endpoint,
    )
    .unwrap();
    assert_eq!(
        authority,
        URL_SAFE_NO_PAD.encode(credential.authority_id().as_bytes())
    );

    let mut init = Command::cargo_bin("KonclaveCommandLine").unwrap();
    init.arg("init")
        .arg("--relay-endpoint")
        .arg(endpoint.as_str())
        .arg("--profile-root")
        .arg(&root)
        .arg("--external-source")
        .arg(&source)
        .arg("--copilot-extension-root")
        .arg(&extension)
        .arg("--local-service-identity-file")
        .arg(&service_identity)
        .assert()
        .success();

    let mut conflict = Command::cargo_bin("KonclaveCommandLine").unwrap();
    conflict
        .arg("relay-bootstrap")
        .arg("--relay-endpoint")
        .arg("http://127.0.0.1:43124")
        .arg("--access-document")
        .arg(&access)
        .arg("--external-source")
        .arg(&source)
        .assert()
        .failure();
}
