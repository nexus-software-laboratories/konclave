use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let protocol_root = proto_root.join("konclave/protocol/v1");
    let protos = [
        protocol_root.join("common.proto"),
        protocol_root.join("identity.proto"),
        protocol_root.join("pairing.proto"),
        protocol_root.join("membership.proto"),
        protocol_root.join("application.proto"),
        protocol_root.join("relay.proto"),
    ];

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let mut config = prost_build::Config::new();
    config
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .bytes([".konclave.protocol.v1"])
        .skip_debug([".konclave.protocol.v1"])
        .compile_protos(&protos, &[proto_root])?;

    Ok(())
}
