use std::borrow::Borrow;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use KonclaveA2AContracts::wire::{
    AgentCapabilities, AgentCard, AgentInterface, AgentSkill, HttpAuthSecurityScheme,
    MutualTlsSecurityScheme, SecurityRequirement, SecurityScheme, StringList, security_scheme,
};
use KonclaveA2AContracts::{
    A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_TEXT_MEDIA_TYPE,
    InitialA2AInterfaceEnvironment, MAX_A2A_AGENT_CARD_INTERFACES, MAX_A2A_AGENT_CARD_SKILLS,
    MAX_A2A_AGENT_SKILL_TAGS, validate_initial_agent_card,
};
use KonclaveA2ADomain::A2AAgentId;
use KonclaveBoundedDocuments::{
    BoundedDocumentError, BoundedVec, deserialize_strict, read_bounded_regular_file,
};
use serde::Deserialize;
use url::{Host, Url};

use crate::oasf::{OASF_LANGUAGE_GENERATION_SKILL, OasfProjectionInput, project_oasf_record};
use crate::{A2ADiscoveryError, CompiledA2AAgentPublication};

/// Maximum byte length of one strict publication source.
pub const MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES: usize = 256 * 1024;
/// Maximum number of OASF author declarations.
pub const MAX_OASF_AUTHORS: usize = 8;
/// Maximum number of OASF taxonomy mappings for one publication.
pub const MAX_OASF_SKILLS: usize = 8;
/// Maximum UTF-8 byte length of one OASF author declaration.
pub const MAX_OASF_AUTHOR_BYTES: usize = 256;
const SOURCE_API_VERSION: &str = "konclave.dev/v1";
const SOURCE_KIND: &str = "A2AAgentPublication";

/// Compiles one bounded strict-JSON A2A publication source.
///
/// # Errors
///
/// Returns a typed document, version, identity, authentication, Agent Card, or OASF
/// validation error.
pub fn compile_a2a_agent_publication_source(
    bytes: &[u8],
    environment: InitialA2AInterfaceEnvironment,
) -> Result<CompiledA2AAgentPublication, A2ADiscoveryError> {
    if bytes.len() > MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES {
        return Err(A2ADiscoveryError::DocumentTooLarge {
            document: "publication",
            maximum: MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES,
        });
    }
    let source: AgentPublicationSource =
        deserialize_strict(bytes, MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES)
            .map_err(|error| map_document_error(error, "publication"))?;
    if source.api_version != SOURCE_API_VERSION {
        return Err(A2ADiscoveryError::UnsupportedApiVersion);
    }
    if source.kind != SOURCE_KIND {
        return Err(A2ADiscoveryError::UnsupportedKind);
    }
    compile_source(source, environment)
}

/// Reads and compiles one explicitly selected regular publication source.
///
/// # Errors
///
/// Returns a typed file, source, identity, authentication, Agent Card, or OASF
/// validation error.
pub fn compile_a2a_agent_publication_file(
    path: &Path,
    environment: InitialA2AInterfaceEnvironment,
) -> Result<CompiledA2AAgentPublication, A2ADiscoveryError> {
    let bytes = read_bounded_regular_file(path, MAX_A2A_AGENT_PUBLICATION_SOURCE_BYTES)
        .map_err(|error| map_document_error(error, "publication"))?;
    compile_a2a_agent_publication_source(&bytes, environment)
}

fn compile_source(
    source: AgentPublicationSource,
    environment: InitialA2AInterfaceEnvironment,
) -> Result<CompiledA2AAgentPublication, A2ADiscoveryError> {
    let AgentPublicationSource { metadata, spec, .. } = source;
    let PublicationSpec {
        public_well_known,
        name,
        description,
        version,
        interfaces,
        authentication,
        skills,
        extended_skills,
        oasf,
    } = spec;
    let id = A2AAgentId::parse(metadata.name).map_err(|_| A2ADiscoveryError::InvalidAgentId)?;
    let interfaces = interfaces.into_inner();
    if authentication.is_none() {
        if environment != InitialA2AInterfaceEnvironment::LoopbackDevelopment {
            return Err(A2ADiscoveryError::AuthenticationRequired);
        }
        if interfaces
            .iter()
            .any(|interface| !is_loopback_url(&interface.url))
        {
            return Err(A2ADiscoveryError::UnauthenticatedInterface);
        }
    }
    let public_skills = skills.into_inner();
    let extended_skills = extended_skills.into_inner();
    let mut skill_ids = BTreeSet::new();
    for skill in public_skills.iter().chain(&extended_skills) {
        if !skill_ids.insert(skill.id.as_str()) {
            return Err(A2ADiscoveryError::InvalidAgentCard);
        }
    }
    let expected_tenant = interfaces
        .first()
        .and_then(|interface| interface.tenant.as_deref());
    let has_extended_card = !extended_skills.is_empty();
    let public_wire = build_card(
        &name,
        &description,
        &version,
        &interfaces,
        authentication.as_ref(),
        &public_skills,
        has_extended_card,
    );
    let card = validate_initial_agent_card(public_wire, environment, expected_tenant)
        .map_err(|_| A2ADiscoveryError::InvalidAgentCard)?;
    let extended_card = if has_extended_card {
        let all_skills = public_skills
            .iter()
            .chain(&extended_skills)
            .collect::<Vec<_>>();
        let wire = build_card(
            &name,
            &description,
            &version,
            &interfaces,
            authentication.as_ref(),
            &all_skills,
            true,
        );
        Some(
            validate_initial_agent_card(wire, environment, expected_tenant)
                .map_err(|_| A2ADiscoveryError::InvalidAgentCard)?,
        )
    } else {
        None
    };
    let oasf_record = oasf
        .map(validate_oasf_input)
        .transpose()?
        .map(|input| project_oasf_record(extended_card.as_ref().unwrap_or(&card), input))
        .transpose()?;
    Ok(CompiledA2AAgentPublication {
        id,
        publicly_discoverable: public_well_known,
        card,
        extended_card,
        oasf_record,
    })
}

fn build_card<S: Borrow<SkillSource>>(
    name: &str,
    description: &str,
    version: &str,
    interfaces: &[InterfaceSource],
    authentication: Option<&AuthenticationSource>,
    skills: &[S],
    extended_agent_card: bool,
) -> AgentCard {
    let (security_schemes, security_requirements) = build_security(authentication);
    AgentCard {
        name: name.to_owned(),
        description: description.to_owned(),
        supported_interfaces: interfaces
            .iter()
            .map(|interface| AgentInterface {
                url: interface.url.clone(),
                protocol_binding: A2A_HTTP_JSON_BINDING.to_owned(),
                tenant: interface.tenant.clone().unwrap_or_default(),
                protocol_version: A2A_PROTOCOL_VERSION.to_owned(),
            })
            .collect(),
        provider: None,
        version: version.to_owned(),
        documentation_url: None,
        capabilities: Some(AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extensions: vec![],
            extended_agent_card: Some(extended_agent_card),
        }),
        security_schemes,
        security_requirements,
        default_input_modes: vec![A2A_TEXT_MEDIA_TYPE.to_owned()],
        default_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_owned()],
        skills: skills
            .iter()
            .map(|skill| {
                let skill = skill.borrow();
                AgentSkill {
                    id: skill.id.clone(),
                    name: skill.name.clone(),
                    description: skill.description.clone(),
                    tags: skill.tags.as_slice().to_vec(),
                    examples: vec![],
                    input_modes: vec![],
                    output_modes: vec![],
                    security_requirements: vec![],
                }
            })
            .collect(),
        signatures: vec![],
        icon_url: None,
    }
}

fn build_security(
    authentication: Option<&AuthenticationSource>,
) -> (HashMap<String, SecurityScheme>, Vec<SecurityRequirement>) {
    let Some(authentication) = authentication else {
        return (HashMap::new(), vec![]);
    };
    let (name, scheme) = match authentication {
        AuthenticationSource::Bearer {
            name,
            bearer_format,
        } => (
            name.clone(),
            security_scheme::Scheme::HttpAuthSecurityScheme(HttpAuthSecurityScheme {
                description: String::new(),
                scheme: "Bearer".to_owned(),
                bearer_format: bearer_format.clone().unwrap_or_default(),
            }),
        ),
        AuthenticationSource::MutualTls { name } => (
            name.clone(),
            security_scheme::Scheme::MtlsSecurityScheme(MutualTlsSecurityScheme {
                description: String::new(),
            }),
        ),
    };
    (
        HashMap::from([(
            name.clone(),
            SecurityScheme {
                scheme: Some(scheme),
            },
        )]),
        vec![SecurityRequirement {
            schemes: HashMap::from([(name, StringList { list: vec![] })]),
        }],
    )
}

fn validate_oasf_input(source: OasfSource) -> Result<OasfProjectionInput, A2ADiscoveryError> {
    let authors = source.authors.into_inner();
    if authors.is_empty() || authors.iter().any(|author| !valid_author(author)) {
        return Err(A2ADiscoveryError::InvalidOasfProjection);
    }
    if !valid_utc_timestamp(&source.created_at) {
        return Err(A2ADiscoveryError::InvalidOasfProjection);
    }
    let skills = source.skills.into_inner();
    if skills.is_empty()
        || skills
            .iter()
            .any(|skill| skill != OASF_LANGUAGE_GENERATION_SKILL)
        || skills.iter().collect::<BTreeSet<_>>().len() != skills.len()
    {
        return Err(A2ADiscoveryError::InvalidOasfProjection);
    }
    Ok(OasfProjectionInput {
        authors,
        created_at: source.created_at,
        skills,
    })
}

fn valid_author(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_OASF_AUTHOR_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value.ends_with('>')
    {
        return false;
    }
    let Some((name, email)) = value[..value.len() - 1].rsplit_once(" <") else {
        return false;
    };
    !name.is_empty()
        && email.is_ascii()
        && !email.contains(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        bytes[start..end]
            .iter()
            .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year != 0 && day != 0 && day <= maximum_day && hour < 24 && minute < 60 && second < 60
}

fn is_loopback_url(value: &str) -> bool {
    Url::parse(value).ok().is_some_and(|url| {
        url.host().is_some_and(|host| match host {
            Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
        })
    })
}

pub(crate) fn map_document_error(
    error: BoundedDocumentError,
    document: &'static str,
) -> A2ADiscoveryError {
    match error {
        BoundedDocumentError::FileUnavailable => {
            A2ADiscoveryError::DocumentUnavailable { document }
        }
        BoundedDocumentError::DocumentTooLarge { maximum } => {
            A2ADiscoveryError::DocumentTooLarge { document, maximum }
        }
        BoundedDocumentError::InvalidJson => A2ADiscoveryError::InvalidJson { document },
        BoundedDocumentError::UnsafeCatalogPath => A2ADiscoveryError::UnsafeCatalogPath,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentPublicationSource {
    api_version: String,
    kind: String,
    metadata: PublicationMetadata,
    spec: PublicationSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationMetadata {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationSpec {
    #[serde(default)]
    public_well_known: bool,
    name: String,
    description: String,
    version: String,
    interfaces: BoundedVec<InterfaceSource, MAX_A2A_AGENT_CARD_INTERFACES>,
    authentication: Option<AuthenticationSource>,
    skills: BoundedVec<SkillSource, MAX_A2A_AGENT_CARD_SKILLS>,
    #[serde(default)]
    extended_skills: BoundedVec<SkillSource, MAX_A2A_AGENT_CARD_SKILLS>,
    oasf: Option<OasfSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceSource {
    url: String,
    tenant: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
enum AuthenticationSource {
    Bearer {
        name: String,
        #[serde(rename = "bearerFormat")]
        bearer_format: Option<String>,
    },
    MutualTls {
        name: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillSource {
    id: String,
    name: String,
    description: String,
    tags: BoundedVec<String, MAX_A2A_AGENT_SKILL_TAGS>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OasfSource {
    authors: BoundedVec<String, MAX_OASF_AUTHORS>,
    created_at: String,
    skills: BoundedVec<String, MAX_OASF_SKILLS>,
}
