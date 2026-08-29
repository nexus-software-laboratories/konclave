use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const A2A_SCHEMA_BYTES: usize = 35_844;
const A2A_SCHEMA_SHA256: &str = "e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016";
const OPTION_STUBS: [(&str, usize, &str); 3] = [
    (
        "google/api/annotations.proto",
        445,
        "c29a8babaaeec1572f3fae74ebf5168de7ac2f83b28fa8744c03c39e26ab02df",
    ),
    (
        "google/api/client.proto",
        280,
        "da5f31475cc03a0cf2f6294d7ee0dca129aa6fde86f9610ffc0141b024e42cc0",
    ),
    (
        "google/api/field_behavior.proto",
        363,
        "e44d489fdf0477df072faa13aa1fd86237fa2ebec55ff70d2e249dcf7dca1e93",
    ),
];

fn main() -> Result<(), Box<dyn Error>> {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/a2a/v1.0.1");
    let schema = source_root.join("a2a.proto");
    let descriptor = PathBuf::from(std::env::var("OUT_DIR")?).join("a2a-descriptor.bin");

    println!("cargo:rerun-if-changed={}", schema.display());
    verify_pinned_file(
        &schema,
        A2A_SCHEMA_BYTES,
        A2A_SCHEMA_SHA256,
        "A2A v1.0.1 schema",
    )?;
    for (relative_path, bytes, sha256) in OPTION_STUBS {
        let stub = source_root.join(relative_path);
        println!("cargo:rerun-if-changed={}", stub.display());
        verify_pinned_file(&stub, bytes, sha256, "A2A generation option stub")?;
    }

    let mut config = prost_build::Config::new();
    config
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .file_descriptor_set_path(&descriptor)
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types")
        .bytes([".lf.a2a.v1"])
        .skip_debug([".lf.a2a.v1"])
        .compile_protos(&[schema], &[source_root])?;

    let descriptor = fs::read(descriptor)?;
    let mut json = pbjson_build::Builder::new();
    json.register_descriptors(&descriptor)?;
    json.build(&[".lf.a2a.v1"])?;
    Ok(())
}

fn verify_pinned_file(
    path: &Path,
    expected_bytes: usize,
    expected_sha256: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if bytes.len() != expected_bytes || digest != expected_sha256 {
        return Err(format!("{label} does not match its pinned digest").into());
    }
    Ok(())
}
