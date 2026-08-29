use std::error::Error;
use std::fs;
use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

const A2A_SCHEMA_BYTES: usize = 35_844;
const A2A_SCHEMA_SHA256: &str = "e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016";

fn main() -> Result<(), Box<dyn Error>> {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/a2a/v1.0.1");
    let schema = source_root.join("a2a.proto");
    let option_stubs = [
        source_root.join("google/api/annotations.proto"),
        source_root.join("google/api/client.proto"),
        source_root.join("google/api/field_behavior.proto"),
    ];
    let descriptor = PathBuf::from(std::env::var("OUT_DIR")?).join("a2a-descriptor.bin");

    println!("cargo:rerun-if-changed={}", schema.display());
    for stub in &option_stubs {
        println!("cargo:rerun-if-changed={}", stub.display());
    }
    let schema_bytes = fs::read(&schema)?;
    let schema_digest = format!("{:x}", Sha256::digest(&schema_bytes));
    if schema_bytes.len() != A2A_SCHEMA_BYTES || schema_digest != A2A_SCHEMA_SHA256 {
        return Err("vendored A2A v1.0.1 schema does not match its pinned digest".into());
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
