use KonclaveBoundedDocuments::{
    BoundedDocumentError, BoundedVec, JsonFileCatalogRoot, deserialize_strict,
    read_bounded_regular_file,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    values: BoundedVec<String, 2>,
}

#[test]
fn strict_json_and_bounded_sequences_fail_closed() {
    let document: Document = deserialize_strict(br#"{"values":["a","b"]}"#, 128).unwrap();
    assert_eq!(document.values.as_slice(), ["a", "b"]);
    assert_eq!(
        deserialize_strict::<Document>(br#"{"values":["a","b","c"]}"#, 128).err(),
        Some(BoundedDocumentError::InvalidJson)
    );
    assert_eq!(
        deserialize_strict::<Document>(br#"{"values":[],"unknown":true}"#, 128).err(),
        Some(BoundedDocumentError::InvalidJson)
    );
    assert_eq!(
        deserialize_strict::<Document>(br#"{"values":[]}{}"#, 128).err(),
        Some(BoundedDocumentError::InvalidJson)
    );
    assert_eq!(
        deserialize_strict::<serde_json::Value>(br#"{"outer":{"key":1,"key":2}}"#, 128).err(),
        Some(BoundedDocumentError::InvalidJson)
    );
    assert_eq!(
        deserialize_strict::<serde_json::Value>(br#"{"value":1}"#, 4).err(),
        Some(BoundedDocumentError::DocumentTooLarge { maximum: 4 })
    );
}

#[test]
fn bounded_regular_file_rejects_growth_and_non_files() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("source.json");
    std::fs::write(&file, b"1234").unwrap();
    assert_eq!(read_bounded_regular_file(&file, 4).unwrap(), b"1234");
    assert_eq!(
        read_bounded_regular_file(&file, 3).err(),
        Some(BoundedDocumentError::DocumentTooLarge { maximum: 3 })
    );
    assert_eq!(
        read_bounded_regular_file(root.path(), 4).err(),
        Some(BoundedDocumentError::FileUnavailable)
    );
}

#[test]
fn catalog_root_accepts_only_confined_portable_json_sources() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("agents");
    std::fs::create_dir(&nested).unwrap();
    let source = nested.join("agent-a.json");
    std::fs::write(&source, b"{}").unwrap();
    let descriptor = root.path().join("catalog.json");
    std::fs::write(&descriptor, b"{}").unwrap();
    let catalog = JsonFileCatalogRoot::from_descriptor(&descriptor).unwrap();
    assert_eq!(catalog.read("agents/agent-a.json", 16).unwrap(), b"{}");
    for unsafe_source in [
        "../agent-a.json",
        "/agent-a.json",
        r"agents\agent-a.json",
        ".hidden.json",
        "agents/agent-a.txt",
    ] {
        assert_eq!(
            catalog.read(unsafe_source, 16).err(),
            Some(BoundedDocumentError::UnsafeCatalogPath)
        );
    }
}

#[test]
#[cfg(unix)]
fn catalog_root_rejects_linked_sources() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.json");
    let linked = root.path().join("linked.json");
    std::fs::write(&target, b"{}").unwrap();
    symlink(&target, &linked).unwrap();
    let descriptor = root.path().join("catalog.json");
    std::fs::write(&descriptor, b"{}").unwrap();
    let catalog = JsonFileCatalogRoot::from_descriptor(&descriptor).unwrap();
    assert_eq!(
        catalog.read("linked.json", 16).err(),
        Some(BoundedDocumentError::UnsafeCatalogPath)
    );
}

#[test]
#[cfg(unix)]
fn catalog_root_rejects_intermediate_symlink_escape() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.json"), b"{}").unwrap();
    symlink(outside.path(), root.path().join("agents")).unwrap();
    let descriptor = root.path().join("catalog.json");
    std::fs::write(&descriptor, b"{}").unwrap();
    let catalog = JsonFileCatalogRoot::from_descriptor(&descriptor).unwrap();
    assert_eq!(
        catalog.read("agents/outside.json", 16).err(),
        Some(BoundedDocumentError::UnsafeCatalogPath)
    );
}
