use std::collections::HashMap;

use KonclaveA2AContracts::wire::{Artifact, Part, part};
use KonclaveA2AContracts::{
    A2A_ARTIFACT_OBJECT_AAD_DOMAIN, A2AContractError, InitialA2AArtifactReferenceDescriptor,
    MAX_A2A_ARTIFACT_INLINE_BYTES, decode_initial_artifact_json,
    decode_initial_artifact_protobuf, parse_initial_encrypted_artifact_reference,
    validate_initial_artifact,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message as _;

fn encrypted_reference() -> String {
    format!(
        "https://objects.example.com/a2a/sha256/{}#konclave-aes256gcm-v1.{}.{}.64",
        "ab".repeat(32),
        URL_SAFE_NO_PAD.encode([1_u8; 32]),
        URL_SAFE_NO_PAD.encode([2_u8; 12]),
    )
}

fn artifact() -> Artifact {
    Artifact {
        artifact_id: "artifact-1".to_owned(),
        name: "Contract output".to_owned(),
        description: "Bounded mixed artifact".to_owned(),
        parts: vec![
            Part {
                content: Some(part::Content::Text("response".to_owned())),
                metadata: None,
                filename: "response.txt".to_owned(),
                media_type: String::new(),
            },
            Part {
                content: Some(part::Content::Data(
                    serde_json::from_str(r#"{"z":1,"a":{"second":2,"first":1}}"#).unwrap(),
                )),
                metadata: None,
                filename: "response.json".to_owned(),
                media_type: String::new(),
            },
            Part {
                content: Some(part::Content::Raw(vec![1, 2, 3].into())),
                metadata: None,
                filename: "response.bin".to_owned(),
                media_type: "application/octet-stream".to_owned(),
            },
            Part {
                content: Some(part::Content::Url(encrypted_reference())),
                metadata: None,
                filename: "large.bin".to_owned(),
                media_type: "application/octet-stream".to_owned(),
            },
        ],
        metadata: None,
        extensions: vec![],
    }
}

#[test]
fn artifact_forms_round_trip_to_deterministic_canonical_json() {
    let validated = validate_initial_artifact(artifact()).unwrap();
    assert_eq!(validated.artifact_id(), "artifact-1");
    assert_eq!(validated.as_wire().parts[0].media_type, "text/plain");
    assert_eq!(validated.as_wire().parts[1].media_type, "application/json");
    let json = validated.canonical_json().to_vec();
    assert_eq!(
        decode_initial_artifact_json(&json)
            .unwrap()
            .canonical_json(),
        json
    );
    let protobuf = validated.as_wire().encode_to_vec();
    assert_eq!(
        decode_initial_artifact_protobuf(&protobuf)
            .unwrap()
            .canonical_json(),
        json
    );
    let text = std::str::from_utf8(&json).unwrap();
    assert!(text.find("\"a\"").unwrap() < text.find("\"z\"").unwrap());
    assert!(text.find("\"first\"").unwrap() < text.find("\"second\"").unwrap());

    let mut empty_metadata = artifact();
    empty_metadata.metadata = Some(pbjson_types::Struct {
        fields: HashMap::new(),
    });
    empty_metadata.parts[0].metadata = Some(pbjson_types::Struct {
        fields: HashMap::new(),
    });
    assert_eq!(
        validate_initial_artifact(empty_metadata)
            .unwrap()
            .canonical_json(),
        json
    );
}

#[test]
fn encrypted_reference_parser_strips_secret_fragment_and_builds_bound_aad() {
    let reference = parse_initial_encrypted_artifact_reference(&encrypted_reference()).unwrap();
    assert_eq!(
        reference.request_url(),
        format!(
            "https://objects.example.com/a2a/sha256/{}",
            "ab".repeat(32)
        )
    );
    assert_eq!(reference.ciphertext_digest(), &[0xab; 32]);
    assert_eq!(reference.key(), &[1; 32]);
    assert_eq!(reference.nonce(), &[2; 12]);
    assert_eq!(reference.plaintext_bytes(), 64);

    let descriptor = InitialA2AArtifactReferenceDescriptor::new(
        "artifact-1",
        3,
        "application/octet-stream",
        "large.bin",
        64,
    )
    .unwrap();
    let aad = descriptor.associated_data().unwrap();
    assert!(aad.starts_with(A2A_ARTIFACT_OBJECT_AAD_DOMAIN));
    assert!(aad.ends_with(&64_u64.to_be_bytes()));
    assert_eq!(descriptor.artifact_id(), "artifact-1");
    assert_eq!(descriptor.part_index(), 3);
}

#[test]
fn artifact_rejects_unsafe_media_filename_metadata_and_urls() {
    let mut uppercase_media = artifact();
    uppercase_media.parts[2].media_type = "Application/Octet-Stream".to_owned();
    assert!(matches!(
        validate_initial_artifact(uppercase_media),
        Err(A2AContractError::InvalidText {
            field: "artifact.part.media_type"
        })
    ));

    let mut unsafe_filename = artifact();
    unsafe_filename.parts[0].filename = "../response.txt".to_owned();
    assert!(matches!(
        validate_initial_artifact(unsafe_filename),
        Err(A2AContractError::InvalidText {
            field: "artifact.part.filename"
        })
    ));

    let mut arbitrary_url = artifact();
    arbitrary_url.parts[3].content =
        Some(part::Content::Url("https://example.com/file".to_owned()));
    assert_eq!(
        validate_initial_artifact(arbitrary_url).err(),
        Some(A2AContractError::InvalidInterfaceUrl)
    );

    let mut metadata = artifact();
    metadata.metadata = Some(pbjson_types::Struct {
        fields: HashMap::from([(
            "unbounded".to_owned(),
            pbjson_types::Value {
                kind: Some(pbjson_types::value::Kind::StringValue("value".to_owned())),
            },
        )]),
    });
    assert!(matches!(
        validate_initial_artifact(metadata),
        Err(A2AContractError::UnsupportedField {
            field: "artifact.metadata"
        })
    ));
}

#[test]
fn artifact_rejects_inline_and_structured_data_bounds() {
    let mut oversized = artifact();
    oversized.parts = vec![Part {
        content: Some(part::Content::Raw(
            vec![0_u8; MAX_A2A_ARTIFACT_INLINE_BYTES + 1].into(),
        )),
        metadata: None,
        filename: "large.bin".to_owned(),
        media_type: "application/octet-stream".to_owned(),
    }];
    assert!(matches!(
        validate_initial_artifact(oversized),
        Err(A2AContractError::OutOfRange {
            field: "artifact.inline_bytes"
        })
    ));

    let mut nested = serde_json::Value::Null;
    for _ in 0..34 {
        nested = serde_json::json!([nested]);
    }
    let mut deep = artifact();
    deep.parts = vec![Part {
        content: Some(part::Content::Data(serde_json::from_value(nested).unwrap())),
        metadata: None,
        filename: "deep.json".to_owned(),
        media_type: "application/json".to_owned(),
    }];
    assert!(matches!(
        validate_initial_artifact(deep),
        Err(A2AContractError::OutOfRange {
            field: "artifact.part.data"
        })
    ));
}
