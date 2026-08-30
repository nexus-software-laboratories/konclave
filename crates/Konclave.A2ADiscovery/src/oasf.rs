use KonclaveA2AContracts::{A2A_PROTOCOL_VERSION, InitialA2AAgentCard};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::A2ADiscoveryError;

/// OASF schema version used by the initial generated projection.
pub const OASF_SCHEMA_VERSION: &str = "1.1.0";
/// Exact OASF release commit that defines the projection shape.
pub const OASF_RELEASE_COMMIT: &str = "f510be0d4b5878ac8f86c64ffd6cd7132733c03e";
/// Only OASF taxonomy skill currently accepted by the bounded projection.
pub const OASF_LANGUAGE_GENERATION_SKILL: &str = "language_generation";
const OASF_A2A_MODULE_NAME: &str = "a2a";
const OASF_AGENT_CARD_MEDIA_TYPE: &str = "application/json";

/// Deterministic compact OASF record generated from one validated A2A publication.
pub struct OasfAgentRecord {
    bytes: Vec<u8>,
    agent_card_digest: [u8; 32],
    agent_card_size: usize,
}

impl OasfAgentRecord {
    /// Returns deterministic compact OASF record JSON bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 digest of the embedded deterministic Agent Card JSON.
    #[must_use]
    pub const fn agent_card_digest(&self) -> &[u8; 32] {
        &self.agent_card_digest
    }

    /// Returns the byte length of the embedded deterministic Agent Card JSON.
    #[must_use]
    pub const fn agent_card_size(&self) -> usize {
        self.agent_card_size
    }
}

pub(crate) struct OasfProjectionInput {
    pub(crate) authors: Vec<String>,
    pub(crate) created_at: String,
    pub(crate) skills: Vec<String>,
}

pub(crate) fn project_oasf_record(
    card: &InitialA2AAgentCard,
    input: OasfProjectionInput,
) -> Result<OasfAgentRecord, A2ADiscoveryError> {
    let card_bytes = card
        .deterministic_json()
        .map_err(|_| A2ADiscoveryError::InvalidAgentCard)?;
    let agent_card_digest: [u8; 32] = Sha256::digest(&card_bytes).into();
    let card_json: Value =
        serde_json::from_slice(&card_bytes).map_err(|_| A2ADiscoveryError::InvalidAgentCard)?;
    let digest = format!("sha256:{}", lowercase_hex(agent_card_digest));
    let record = OasfRecord {
        name: card.name(),
        version: card.version(),
        schema_version: OASF_SCHEMA_VERSION,
        description: card.description(),
        authors: &input.authors,
        created_at: &input.created_at,
        skills: input.skills.iter().map(|name| OasfSkill { name }).collect(),
        modules: [OasfModule {
            name: OASF_A2A_MODULE_NAME,
            data: OasfA2AData {
                card_schema_version: A2A_PROTOCOL_VERSION,
            },
            artifact: OasfArtifact {
                media_type: OASF_AGENT_CARD_MEDIA_TYPE,
                size: u64::try_from(card_bytes.len())
                    .map_err(|_| A2ADiscoveryError::InvalidOasfProjection)?,
                digest: &digest,
                json: &card_json,
            },
        }],
    };
    let bytes =
        serde_json::to_vec(&record).map_err(|_| A2ADiscoveryError::InvalidOasfProjection)?;
    Ok(OasfAgentRecord {
        bytes,
        agent_card_digest,
        agent_card_size: card_bytes.len(),
    })
}

#[derive(Serialize)]
struct OasfRecord<'a> {
    name: &'a str,
    version: &'a str,
    schema_version: &'static str,
    description: &'a str,
    authors: &'a [String],
    created_at: &'a str,
    skills: Vec<OasfSkill<'a>>,
    modules: [OasfModule<'a>; 1],
}

#[derive(Serialize)]
struct OasfSkill<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct OasfModule<'a> {
    name: &'static str,
    data: OasfA2AData,
    artifact: OasfArtifact<'a>,
}

#[derive(Serialize)]
struct OasfA2AData {
    card_schema_version: &'static str,
}

#[derive(Serialize)]
struct OasfArtifact<'a> {
    media_type: &'static str,
    size: u64,
    digest: &'a str,
    json: &'a Value,
}

fn lowercase_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
