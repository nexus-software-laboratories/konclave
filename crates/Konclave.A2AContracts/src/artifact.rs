use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message as _;
use url::Url;

use crate::A2AContractError;
use crate::initial_profile::{
    A2A_TEXT_MEDIA_TYPE, decode_json_bounded, require_empty_struct, require_encoded_bound,
    validate_identifier,
};
use crate::wire::{Artifact, Part, part};

/// Maximum UTF-8 byte length of an artifact name.
pub const MAX_A2A_ARTIFACT_NAME_BYTES: usize = 128;
/// Maximum UTF-8 byte length of an artifact description.
pub const MAX_A2A_ARTIFACT_DESCRIPTION_BYTES: usize = 1_024;
/// Maximum UTF-8 byte length of one artifact filename.
pub const MAX_A2A_ARTIFACT_FILENAME_BYTES: usize = 255;
/// Maximum byte length of one canonical media type.
pub const MAX_A2A_ARTIFACT_MEDIA_TYPE_BYTES: usize = 127;
/// Maximum number of Parts in one artifact.
pub const MAX_A2A_ARTIFACT_PARTS: usize = 8;
/// Maximum artifacts projected in one bounded Task.
pub const MAX_A2A_ARTIFACTS_PER_TASK: usize = 8;
/// Maximum aggregate decoded inline content in one artifact.
pub const MAX_A2A_ARTIFACT_INLINE_BYTES: usize = 64 * 1_024;
/// Maximum deterministic ProtoJSON bytes stored for one artifact.
pub const MAX_A2A_CANONICAL_ARTIFACT_BYTES: usize = 192 * 1_024;
/// Maximum plaintext represented by one encrypted object reference.
pub const MAX_A2A_ARTIFACT_REFERENCE_PLAINTEXT_BYTES: u64 = 64 * 1_024 * 1_024;

const MAX_A2A_ARTIFACT_JSON_DEPTH: usize = 32;
const MAX_A2A_ARTIFACT_JSON_VALUES: usize = 1_024;
const ENCRYPTED_REFERENCE_PREFIX: &str = "konclave-aes256gcm-v1";
const ENCRYPTED_REFERENCE_KEY_BYTES: usize = 32;
const ENCRYPTED_REFERENCE_NONCE_BYTES: usize = 12;

/// Validated canonical Artifact admitted by Konclave's A2A profile.
///
/// The wrapper intentionally does not implement `Clone` or `Debug` because an
/// encrypted reference contains decryption key material in its URL fragment.
pub struct InitialA2AArtifact {
    wire: Artifact,
    canonical_json: Vec<u8>,
}

impl InitialA2AArtifact {
    /// Returns the canonical task-scoped artifact identifier.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.wire.artifact_id
    }

    /// Returns the validated generated wire DTO.
    #[must_use]
    pub const fn as_wire(&self) -> &Artifact {
        &self.wire
    }

    /// Returns the generated wire DTO and consumes the validated wrapper.
    #[must_use]
    pub fn into_wire(self) -> Artifact {
        self.wire
    }

    /// Returns deterministic compact ProtoJSON used by the portable task store.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    /// Returns deterministic compact ProtoJSON and consumes the wrapper.
    #[must_use]
    pub fn into_canonical_json(self) -> Vec<u8> {
        self.canonical_json
    }
}

/// Decodes and validates one bounded protobuf Artifact.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, unsupported, or
/// noncanonical artifact content.
pub fn decode_initial_artifact_protobuf(
    bytes: &[u8],
) -> Result<InitialA2AArtifact, A2AContractError> {
    require_encoded_bound(bytes, MAX_A2A_CANONICAL_ARTIFACT_BYTES)?;
    let artifact = Artifact::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_artifact(artifact)
}

/// Decodes and validates one bounded ProtoJSON Artifact.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, unsupported, or
/// noncanonical artifact content.
pub fn decode_initial_artifact_json(bytes: &[u8]) -> Result<InitialA2AArtifact, A2AContractError> {
    let artifact = decode_json_bounded(bytes, MAX_A2A_CANONICAL_ARTIFACT_BYTES)?;
    validate_initial_artifact(artifact)
}

/// Narrows one generated Artifact to the bounded output profile.
///
/// # Errors
///
/// Returns a stable contract error for invalid identity, content, media type,
/// filename, metadata, inline bounds, structured-data bounds, or URL references.
pub fn validate_initial_artifact(
    mut artifact: Artifact,
) -> Result<InitialA2AArtifact, A2AContractError> {
    validate_identifier(artifact.artifact_id.clone(), "artifact.artifact_id")?;
    validate_optional_display(&artifact.name, MAX_A2A_ARTIFACT_NAME_BYTES, "artifact.name")?;
    validate_optional_display(
        &artifact.description,
        MAX_A2A_ARTIFACT_DESCRIPTION_BYTES,
        "artifact.description",
    )?;
    if artifact.parts.is_empty() {
        return Err(A2AContractError::MissingField {
            field: "artifact.parts",
        });
    }
    if artifact.parts.len() > MAX_A2A_ARTIFACT_PARTS {
        return Err(A2AContractError::OutOfRange {
            field: "artifact.parts",
        });
    }
    require_empty_struct(artifact.metadata.clone(), "artifact.metadata")?;
    artifact.metadata = None;
    if !artifact.extensions.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "artifact.extensions",
        });
    }

    let mut inline_bytes = 0_usize;
    for part in &mut artifact.parts {
        validate_part(part, &mut inline_bytes)?;
    }
    let canonical_value =
        serde_json::to_value(&artifact).map_err(|_| A2AContractError::MalformedEncoding)?;
    let canonical_value = sort_json(canonical_value);
    let canonical_json =
        serde_json::to_vec(&canonical_value).map_err(|_| A2AContractError::MalformedEncoding)?;
    require_encoded_bound(&canonical_json, MAX_A2A_CANONICAL_ARTIFACT_BYTES)?;
    let wire =
        serde_json::from_slice(&canonical_json).map_err(|_| A2AContractError::MalformedEncoding)?;
    Ok(InitialA2AArtifact {
        wire,
        canonical_json,
    })
}

fn validate_part(part: &mut Part, inline_bytes: &mut usize) -> Result<(), A2AContractError> {
    require_empty_struct(part.metadata.clone(), "artifact.part.metadata")?;
    part.metadata = None;
    validate_filename(&part.filename)?;
    match part.content.as_mut() {
        Some(part::Content::Text(text)) => {
            if text.is_empty() {
                return Err(A2AContractError::InvalidText {
                    field: "artifact.part.text",
                });
            }
            add_inline_bytes(inline_bytes, text.len())?;
            if part.media_type.is_empty() {
                part.media_type = A2A_TEXT_MEDIA_TYPE.to_owned();
            } else {
                validate_media_type(&part.media_type, "artifact.part.media_type")?;
                if !part.media_type.starts_with("text/") {
                    return Err(A2AContractError::UnsupportedField {
                        field: "artifact.part.media_type",
                    });
                }
            }
        }
        Some(part::Content::Raw(bytes)) => {
            if bytes.is_empty() || part.media_type.is_empty() {
                return Err(A2AContractError::MissingField {
                    field: "artifact.part.raw",
                });
            }
            validate_media_type(&part.media_type, "artifact.part.media_type")?;
            add_inline_bytes(inline_bytes, bytes.len())?;
        }
        Some(part::Content::Data(data)) => {
            if !part.media_type.is_empty() && part.media_type != "application/json" {
                return Err(A2AContractError::UnsupportedField {
                    field: "artifact.part.media_type",
                });
            }
            part.media_type = "application/json".to_owned();
            let value =
                serde_json::to_value(&*data).map_err(|_| A2AContractError::MalformedEncoding)?;
            let mut count = 0;
            let value = canonicalize_json(value, 0, &mut count)?;
            let bytes =
                serde_json::to_vec(&value).map_err(|_| A2AContractError::MalformedEncoding)?;
            add_inline_bytes(inline_bytes, bytes.len())?;
            *data =
                serde_json::from_value(value).map_err(|_| A2AContractError::MalformedEncoding)?;
        }
        Some(part::Content::Url(url)) => {
            if part.media_type.is_empty() {
                return Err(A2AContractError::MissingField {
                    field: "artifact.part.media_type",
                });
            }
            validate_media_type(&part.media_type, "artifact.part.media_type")?;
            validate_encrypted_reference(url)?;
        }
        None => {
            return Err(A2AContractError::MissingField {
                field: "artifact.part.content",
            });
        }
    }
    Ok(())
}

fn add_inline_bytes(total: &mut usize, additional: usize) -> Result<(), A2AContractError> {
    *total = total
        .checked_add(additional)
        .ok_or(A2AContractError::OutOfRange {
            field: "artifact.inline_bytes",
        })?;
    if *total > MAX_A2A_ARTIFACT_INLINE_BYTES {
        return Err(A2AContractError::OutOfRange {
            field: "artifact.inline_bytes",
        });
    }
    Ok(())
}

fn validate_optional_display(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), A2AContractError> {
    if value.len() > maximum
        || (!value.is_empty() && value.trim() != value)
        || value.chars().any(char::is_control)
    {
        return Err(A2AContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_filename(value: &str) -> Result<(), A2AContractError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > MAX_A2A_ARTIFACT_FILENAME_BYTES
        || value == "."
        || value == ".."
        || value.trim() != value
        || value.ends_with('.')
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
    {
        return Err(A2AContractError::InvalidText {
            field: "artifact.part.filename",
        });
    }
    Ok(())
}

fn validate_media_type(value: &str, field: &'static str) -> Result<(), A2AContractError> {
    if value.is_empty()
        || value.len() > MAX_A2A_ARTIFACT_MEDIA_TYPE_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(A2AContractError::InvalidText { field });
    }
    let mut segments = value.split('/');
    let Some(r#type) = segments.next() else {
        return Err(A2AContractError::InvalidText { field });
    };
    let Some(subtype) = segments.next() else {
        return Err(A2AContractError::InvalidText { field });
    };
    if segments.next().is_some()
        || r#type.is_empty()
        || subtype.is_empty()
        || r#type == "*"
        || subtype == "*"
        || !r#type.bytes().all(media_type_token)
        || !subtype.bytes().all(media_type_token)
    {
        return Err(A2AContractError::InvalidText { field });
    }
    Ok(())
}

fn media_type_token(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
        )
}

fn validate_encrypted_reference(value: &str) -> Result<(), A2AContractError> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    let url = Url::parse(value).map_err(|_| A2AContractError::InvalidInterfaceUrl)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.as_str() != value
    {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    let mut path = url
        .path_segments()
        .ok_or(A2AContractError::InvalidInterfaceUrl)?
        .rev();
    let digest = path.next().ok_or(A2AContractError::InvalidInterfaceUrl)?;
    if path.next() != Some("sha256")
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    let fragment = url
        .fragment()
        .ok_or(A2AContractError::InvalidInterfaceUrl)?;
    let mut fields = fragment.split('.');
    if fields.next() != Some(ENCRYPTED_REFERENCE_PREFIX) {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    validate_base64url(
        fields.next().ok_or(A2AContractError::InvalidInterfaceUrl)?,
        ENCRYPTED_REFERENCE_KEY_BYTES,
    )?;
    validate_base64url(
        fields.next().ok_or(A2AContractError::InvalidInterfaceUrl)?,
        ENCRYPTED_REFERENCE_NONCE_BYTES,
    )?;
    let size = fields.next().ok_or(A2AContractError::InvalidInterfaceUrl)?;
    if fields.next().is_some()
        || size.starts_with('0')
        || size
            .parse::<u64>()
            .ok()
            .filter(|size| (1..=MAX_A2A_ARTIFACT_REFERENCE_PLAINTEXT_BYTES).contains(size))
            .is_none()
    {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    Ok(())
}

fn validate_base64url(value: &str, expected_bytes: usize) -> Result<(), A2AContractError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| A2AContractError::InvalidInterfaceUrl)?;
    if decoded.len() != expected_bytes || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    Ok(())
}

fn canonicalize_json(
    value: serde_json::Value,
    depth: usize,
    count: &mut usize,
) -> Result<serde_json::Value, A2AContractError> {
    if depth > MAX_A2A_ARTIFACT_JSON_DEPTH {
        return Err(A2AContractError::OutOfRange {
            field: "artifact.part.data",
        });
    }

    *count = count.checked_add(1).ok_or(A2AContractError::OutOfRange {
        field: "artifact.part.data",
    })?;
    if *count > MAX_A2A_ARTIFACT_JSON_VALUES {
        return Err(A2AContractError::OutOfRange {
            field: "artifact.part.data",
        });
    }
    match value {
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(|value| canonicalize_json(value, depth + 1, count))
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        serde_json::Value::Object(values) => {
            let sorted = values.into_iter().collect::<BTreeMap<_, _>>();
            let mut object = serde_json::Map::new();
            for (key, value) in sorted {
                object.insert(key, canonicalize_json(value, depth + 1, count)?);
            }
            Ok(serde_json::Value::Object(object))
        }
        value => Ok(value),
    }
}

fn sort_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sort_json).collect())
        }
        serde_json::Value::Object(values) => {
            let sorted = values.into_iter().collect::<BTreeMap<_, _>>();
            serde_json::Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, value)| (key, sort_json(value)))
                    .collect(),
            )
        }
        value => value,
    }
}
