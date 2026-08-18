use assert_cmd::Command;
use predicates::str::contains;

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
    // clap exits non-zero when the required subcommand is missing.
    let mut cmd = Command::cargo_bin("KonclaveCommandLine").unwrap();
    cmd.assert().failure();
}
