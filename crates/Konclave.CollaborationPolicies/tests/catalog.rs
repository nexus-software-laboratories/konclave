use KonclaveCollaborationPolicies::{
    CollaborationPolicySourceError, FileCollaborationPolicyCatalog,
};
use KonclaveDomainCore::CollaborationPolicyLimits;

fn write_policy(path: &std::path::Path, name: &str) {
    std::fs::write(
        path,
        format!(
            r#"{{
  "apiVersion": "konclave.dev/v2",
  "kind": "CollaborationPolicy",
  "metadata": {{ "name": "{name}" }},
  "spec": {{ "limits": {{}} }}
}}"#
        ),
    )
    .unwrap();
}

#[test]
fn explicit_catalog_lists_and_compiles_only_declared_sources() {
    let root = tempfile::tempdir().unwrap();
    write_policy(&root.path().join("beta.json"), "beta");
    write_policy(&root.path().join("alpha.json"), "alpha");
    write_policy(&root.path().join("unlisted.json"), "unlisted");
    let catalog_path = root.path().join("catalog.json");
    std::fs::write(
        &catalog_path,
        r#"{
  "schemaVersion": 1,
  "entries": [
    { "name": "beta", "source": "beta.json" },
    { "name": "alpha", "source": "alpha.json" }
  ]
}"#,
    )
    .unwrap();

    let catalog = FileCollaborationPolicyCatalog::open(&catalog_path).unwrap();
    assert_eq!(catalog.names().collect::<Vec<_>>(), vec!["alpha", "beta"]);
    assert_eq!(
        catalog
            .compile("alpha", CollaborationPolicyLimits::default())
            .unwrap()
            .bundle()
            .name(),
        "alpha"
    );
    assert_eq!(
        catalog
            .compile("unlisted", CollaborationPolicyLimits::default())
            .err(),
        Some(CollaborationPolicySourceError::PolicyNotFound)
    );
}

#[test]
fn catalog_rejects_duplicates_unsafe_paths_and_name_mismatch() {
    let root = tempfile::tempdir().unwrap();
    write_policy(&root.path().join("alpha.json"), "different");

    for (name, descriptor, expected) in [
        (
            "duplicate-name.json",
            r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"alpha.json"},{"name":"alpha","source":"other.json"}]}"#,
            CollaborationPolicySourceError::DuplicateCatalogEntry { field: "name" },
        ),
        (
            "duplicate-source.json",
            r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"alpha.json"},{"name":"beta","source":"alpha.json"}]}"#,
            CollaborationPolicySourceError::DuplicateCatalogEntry { field: "source" },
        ),
        (
            "unsafe.json",
            r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"../alpha.json"}]}"#,
            CollaborationPolicySourceError::UnsafeCatalogPath,
        ),
        (
            "backslash.json",
            r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"nested\\alpha.json"}]}"#,
            CollaborationPolicySourceError::UnsafeCatalogPath,
        ),
        (
            "trailing-period.json",
            r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"nested./alpha.json"}]}"#,
            CollaborationPolicySourceError::UnsafeCatalogPath,
        ),
    ] {
        if descriptor.contains("other.json") {
            write_policy(&root.path().join("other.json"), "alpha");
        }
        let path = root.path().join(name);
        std::fs::write(&path, descriptor).unwrap();
        assert_eq!(
            FileCollaborationPolicyCatalog::open(&path).err(),
            Some(expected)
        );
    }

    let mismatch_path = root.path().join("mismatch.json");
    std::fs::write(
        &mismatch_path,
        r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"alpha.json"}]}"#,
    )
    .unwrap();
    let catalog = FileCollaborationPolicyCatalog::open(&mismatch_path).unwrap();
    assert_eq!(
        catalog
            .compile("alpha", CollaborationPolicyLimits::default())
            .err(),
        Some(CollaborationPolicySourceError::CatalogNameMismatch)
    );
}

#[test]
fn catalog_rejects_unknown_version_and_unavailable_files() {
    let root = tempfile::tempdir().unwrap();
    let version = root.path().join("version.json");
    std::fs::write(&version, r#"{"schemaVersion":2,"entries":[]}"#).unwrap();
    assert_eq!(
        FileCollaborationPolicyCatalog::open(&version).err(),
        Some(CollaborationPolicySourceError::UnsupportedCatalogVersion)
    );

    let missing = root.path().join("missing.json");
    std::fs::write(
        &missing,
        r#"{"schemaVersion":1,"entries":[{"name":"missing","source":"absent.json"}]}"#,
    )
    .unwrap();
    assert_eq!(
        FileCollaborationPolicyCatalog::open(&missing).err(),
        Some(CollaborationPolicySourceError::UnsafeCatalogPath)
    );
}

#[test]
fn repository_examples_compile_through_the_explicit_catalog() {
    let catalog_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy/examples/catalog.json");
    let catalog = FileCollaborationPolicyCatalog::open(&catalog_path).unwrap();
    let compiled = catalog
        .compile("request-reply", CollaborationPolicyLimits::default())
        .unwrap();
    assert_eq!(compiled.bundle().name(), "request-reply");
    assert_eq!(compiled.bundle().statements().len(), 1);
    assert_eq!(compiled.bundle().required_harness_claims().len(), 3);
}

#[test]
#[cfg(unix)]
fn catalog_rejects_a_linked_source_even_when_its_target_is_inside_the_root() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    write_policy(&root.path().join("target.json"), "alpha");
    symlink(
        root.path().join("target.json"),
        root.path().join("linked.json"),
    )
    .unwrap();
    let catalog_path = root.path().join("catalog.json");
    std::fs::write(
        &catalog_path,
        r#"{"schemaVersion":1,"entries":[{"name":"alpha","source":"linked.json"}]}"#,
    )
    .unwrap();

    assert_eq!(
        FileCollaborationPolicyCatalog::open(&catalog_path).err(),
        Some(CollaborationPolicySourceError::UnsafeCatalogPath)
    );
}
