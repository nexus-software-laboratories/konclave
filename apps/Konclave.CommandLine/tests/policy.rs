use assert_cmd::Command;
use predicates::str::contains;

fn write_policy(path: &std::path::Path, name: &str, guidance: &str) {
    std::fs::write(
        path,
        format!(
            r#"{{
  "apiVersion": "konclave.dev/v1",
  "kind": "CollaborationPolicy",
  "metadata": {{ "name": "{name}" }},
  "spec": {{
    "guidance": "{guidance}",
    "statements": [
      {{
        "id": "reply",
        "effect": "allow",
        "action": "conversation.reply"
      }}
    ],
    "limits": {{}}
  }}
}}"#
        ),
    )
    .unwrap();
}

#[test]
fn policy_create_validate_inspect_and_compile_are_explicit() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("policy.json");
    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args([
            "policy",
            "create",
            "--name",
            "contract-alignment",
            "--output",
        ])
        .arg(&source)
        .assert()
        .success()
        .stdout(contains("created policy source: contract-alignment"));
    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args([
            "policy",
            "create",
            "--name",
            "contract-alignment",
            "--output",
        ])
        .arg(&source)
        .assert()
        .failure();

    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "validate", "--source"])
        .arg(&source)
        .assert()
        .success()
        .stdout(contains("valid policy: contract-alignment sha256:"));

    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "inspect", "--source"])
        .arg(&source)
        .args(["--default-turns", "20"])
        .assert()
        .success()
        .stdout(contains("name: contract-alignment"))
        .stdout(contains("turns: unlimited"));

    let bundle = root.path().join("policy.bin");
    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "compile", "--source"])
        .arg(&source)
        .arg("--output")
        .arg(&bundle)
        .assert()
        .success()
        .stdout(contains("compiled policy: contract-alignment sha256:"));
    assert!(bundle.is_file());
}

#[test]
fn policy_diff_reports_exact_and_different_definitions() {
    let root = tempfile::tempdir().unwrap();
    let left = root.path().join("left.json");
    let right = root.path().join("right.json");
    write_policy(&left, "contract-alignment", "First.");
    write_policy(&right, "contract-alignment", "First.");

    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "diff", "--left"])
        .arg(&left)
        .arg("--right")
        .arg(&right)
        .assert()
        .success()
        .stdout(contains("definition match: exact"));

    write_policy(&right, "contract-alignment", "Second.");
    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "diff", "--left"])
        .arg(&left)
        .arg("--right")
        .arg(&right)
        .assert()
        .success()
        .stdout(contains("definition match: different"));
}

#[test]
fn policy_catalog_lists_and_validates_declared_entries() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("contract.json");
    write_policy(&source, "contract-alignment", "Align.");
    let catalog = root.path().join("catalog.json");
    std::fs::write(
        &catalog,
        r#"{
  "schemaVersion": 1,
  "entries": [
    { "name": "contract-alignment", "source": "contract.json" }
  ]
}"#,
    )
    .unwrap();

    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "list", "--catalog"])
        .arg(&catalog)
        .assert()
        .success()
        .stdout(contains("contract-alignment"));
    Command::cargo_bin("KonclaveCommandLine")
        .unwrap()
        .args(["policy", "validate-catalog", "--catalog"])
        .arg(&catalog)
        .assert()
        .success()
        .stdout(contains("valid policy: contract-alignment sha256:"));
}
