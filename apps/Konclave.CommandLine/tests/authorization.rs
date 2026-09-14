#![cfg(unix)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use predicates::str::contains;
use KonclaveLocalServiceTransport::{
    encode_lowercase_hex, LocalServiceInstallation, LOCAL_SERVICE_INSTALLATION_FILE,
};
use KonclaveSecretStorage::open_owner_protected_file;

struct Installation {
    _root: tempfile::TempDir,
    profile_root: PathBuf,
    issuer_key_id: String,
    issuer_key_version: u32,
}

impl Installation {
    fn create() -> Self {
        let root = tempfile::tempdir().unwrap();
        let profile_root = root.path().join("profiles");
        let enrollment_source = root.path().join("enrollment.credential");
        let extension_root = root.path().join("extension");
        let client_config = root.path().join("service").join("konclave.service.json");
        let service_identity = root.path().join("service").join("identity.key");
        let mut init = Command::cargo_bin("KonclaveCommandLine").unwrap();
        init.args([
            "init",
            "--relay-endpoint",
            "https://relay.example.com",
            "--authorization-policy",
            "account-trusted",
            "--profile-root",
        ])
        .arg(&profile_root)
        .arg("--external-source")
        .arg(&enrollment_source)
        .arg("--copilot-extension-root")
        .arg(&extension_root)
        .arg("--local-service-client-config")
        .arg(&client_config)
        .arg("--local-service-identity-file")
        .arg(&service_identity)
        .write_stdin(format!("{}\n", URL_SAFE_NO_PAD.encode([8; 32])))
        .assert()
        .success();

        let installation_path = authorization_installation_path(&profile_root);
        let installation = LocalServiceInstallation::from_reader(
            open_owner_protected_file(&installation_path).unwrap(),
        )
        .unwrap();
        let issuer = &installation.issuers()[0];
        Self {
            _root: root,
            profile_root,
            issuer_key_id: encode_lowercase_hex(issuer.issuer_key_id().as_bytes()),
            issuer_key_version: issuer.issuer_key_version().get(),
        }
    }

    fn command(&self, subcommand: &str) -> Command {
        let mut command = Command::cargo_bin("KonclaveCommandLine").unwrap();
        command
            .arg("authorization")
            .arg(subcommand)
            .arg("--profile-root")
            .arg(&self.profile_root);
        command
    }
}

fn authorization_installation_path(profile_root: &Path) -> PathBuf {
    profile_root
        .parent()
        .unwrap()
        .join("service")
        .join(LOCAL_SERVICE_INSTALLATION_FILE)
}

#[test]
fn authorization_commands_apply_exact_bounded_transitions() {
    let installation = Installation::create();

    installation
        .command("status")
        .assert()
        .success()
        .stdout(contains("generation: 1"))
        .stdout(contains("active grants: 0/"));

    installation
        .command("suspend-profile")
        .args(["--profile", "generic-example"])
        .assert()
        .success()
        .stdout(contains("profile suspension: applied"));
    installation
        .command("resume-profile")
        .args(["--profile", "generic-example"])
        .assert()
        .success()
        .stdout(contains("profile resume: applied"));

    let next_version = (installation.issuer_key_version + 1).to_string();
    let current_version = installation.issuer_key_version.to_string();
    let public_key = "11".repeat(32);
    installation
        .command("register-issuer")
        .args([
            "--issuer-key-id",
            installation.issuer_key_id.as_str(),
            "--issuer-key-version",
            next_version.as_str(),
            "--public-key",
            public_key.as_str(),
            "--harness",
            "generic",
            "--profile-scope",
            "all",
        ])
        .assert()
        .success()
        .stdout(contains("issuer registration: applied"));
    installation
        .command("disable-issuer")
        .args([
            "--issuer-key-id",
            installation.issuer_key_id.as_str(),
            "--issuer-key-version",
            current_version.as_str(),
            "--existing-grants",
            "retain",
        ])
        .assert()
        .success()
        .stdout(contains("issuer disablement: applied"));
    installation
        .command("remove-issuer")
        .args([
            "--issuer-key-id",
            installation.issuer_key_id.as_str(),
            "--issuer-key-version",
            current_version.as_str(),
            "--existing-grants",
            "revoke",
        ])
        .assert()
        .success()
        .stdout(contains("issuer removal: applied"));

    installation
        .command("replace-policy")
        .args(["--clause", "user_presence"])
        .assert()
        .failure()
        .stderr(contains("cannot remove the AccountTrusted"));
    installation
        .command("replace-policy")
        .args(["--clause", "account_trusted", "--clause", "user_presence"])
        .assert()
        .success()
        .stdout(contains("authorization policy: applied; version 2"));
}
