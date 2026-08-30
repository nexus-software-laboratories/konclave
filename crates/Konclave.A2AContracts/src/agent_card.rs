use std::collections::BTreeSet;

use prost::Message as _;

use crate::A2AContractError;
use crate::initial_profile::{
    A2A_TEXT_MEDIA_TYPE, InitialA2AInterfaceEnvironment, InitialA2AValidatedInterface,
    decode_json_bounded, require_encoded_bound, validate_identifier,
    validate_initial_agent_interface,
};
use crate::wire::{AgentCard, SecurityRequirement, security_scheme};

/// Maximum encoded protobuf or ProtoJSON Agent Card accepted before decoding.
pub const MAX_A2A_ENCODED_AGENT_CARD_BYTES: usize = 256 * 1024;
/// Maximum number of interfaces advertised by one initial-profile card.
pub const MAX_A2A_AGENT_CARD_INTERFACES: usize = 4;
/// Maximum number of skills advertised by one initial-profile card.
pub const MAX_A2A_AGENT_CARD_SKILLS: usize = 32;
/// Maximum number of tags attached to one initial-profile skill.
pub const MAX_A2A_AGENT_SKILL_TAGS: usize = 16;
/// Maximum UTF-8 byte length of an agent or skill display name.
pub const MAX_A2A_AGENT_NAME_BYTES: usize = 256;
/// Maximum UTF-8 byte length of an agent or skill description.
pub const MAX_A2A_AGENT_DESCRIPTION_BYTES: usize = 4 * 1024;
/// Maximum ASCII byte length of an advertised agent version.
pub const MAX_A2A_AGENT_VERSION_BYTES: usize = 64;
/// Maximum UTF-8 byte length of one skill tag.
pub const MAX_A2A_AGENT_SKILL_TAG_BYTES: usize = 64;
/// Maximum ASCII byte length of a Bearer token format hint.
pub const MAX_A2A_BEARER_FORMAT_BYTES: usize = 64;
const MAX_A2A_SECURITY_DESCRIPTION_BYTES: usize = 512;

/// Web authentication mechanism advertised by an initial-profile Agent Card.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InitialA2AAgentSecurityKind {
    /// RFC 7235 Bearer authentication in the `Authorization` header.
    Bearer,
    /// Mutual TLS authentication.
    MutualTls,
}

/// Validated single-scheme web authentication declaration.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialA2AAgentSecurity {
    name: String,
    kind: InitialA2AAgentSecurityKind,
    bearer_format: Option<String>,
}

impl InitialA2AAgentSecurity {
    /// Returns the card-local security scheme identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the supported web authentication mechanism.
    #[must_use]
    pub const fn kind(&self) -> InitialA2AAgentSecurityKind {
        self.kind
    }

    /// Returns the optional bounded Bearer token format hint.
    #[must_use]
    pub fn bearer_format(&self) -> Option<&str> {
        self.bearer_format.as_deref()
    }
}

/// Validated public metadata for one initial-profile A2A skill.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialA2AAgentSkill {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
}

impl InitialA2AAgentSkill {
    /// Returns the unique card-local skill identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the bounded display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the bounded skill description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns unique bounded tags in advertised order.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
}

/// Fully validated Agent Card within Konclave's initial A2A profile.
#[derive(Clone)]
pub struct InitialA2AAgentCard {
    wire: AgentCard,
    interfaces: Vec<InitialA2AValidatedInterface>,
    security: Option<InitialA2AAgentSecurity>,
    skills: Vec<InitialA2AAgentSkill>,
    extended_agent_card: bool,
}

impl InitialA2AAgentCard {
    /// Returns the bounded agent display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.wire.name
    }

    /// Returns the bounded agent description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.wire.description
    }

    /// Returns the bounded advertised agent version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.wire.version
    }

    /// Returns the validated ordered interfaces.
    #[must_use]
    pub fn interfaces(&self) -> &[InitialA2AValidatedInterface] {
        &self.interfaces
    }

    /// Returns the optional single supported web-authentication scheme.
    #[must_use]
    pub const fn security(&self) -> Option<&InitialA2AAgentSecurity> {
        self.security.as_ref()
    }

    /// Returns the validated advertised skills.
    #[must_use]
    pub fn skills(&self) -> &[InitialA2AAgentSkill] {
        &self.skills
    }

    /// Returns whether authenticated extended-card retrieval is advertised.
    #[must_use]
    pub const fn extended_agent_card(&self) -> bool {
        self.extended_agent_card
    }

    /// Returns the generated wire DTO after all initial-profile checks.
    #[must_use]
    pub const fn as_wire(&self) -> &AgentCard {
        &self.wire
    }

    /// Returns the generated wire DTO and consumes the validated wrapper.
    #[must_use]
    pub fn into_wire(self) -> AgentCard {
        self.wire
    }

    /// Produces deterministic compact ProtoJSON bytes for publication or projection.
    ///
    /// The output is deterministic for this profile because it admits at most one
    /// security-map entry and rejects arbitrary metadata maps.
    ///
    /// # Errors
    ///
    /// Returns a contract error if generated ProtoJSON unexpectedly cannot be
    /// represented or exceeds the validated encoded-card bound.
    pub fn deterministic_json(&self) -> Result<Vec<u8>, A2AContractError> {
        let value =
            serde_json::to_value(&self.wire).map_err(|_| A2AContractError::MalformedEncoding)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| A2AContractError::MalformedEncoding)?;
        require_encoded_bound(&bytes, MAX_A2A_ENCODED_AGENT_CARD_BYTES)?;
        Ok(bytes)
    }
}

/// Decodes and validates one bounded initial-profile protobuf Agent Card.
///
/// # Errors
///
/// Returns a stable contract error for oversized, malformed, unsupported, insecure,
/// duplicate, or deployment-mismatched card content.
pub fn decode_initial_agent_card_protobuf(
    bytes: &[u8],
    environment: InitialA2AInterfaceEnvironment,
    expected_tenant: Option<&str>,
) -> Result<InitialA2AAgentCard, A2AContractError> {
    require_encoded_bound(bytes, MAX_A2A_ENCODED_AGENT_CARD_BYTES)?;
    let card = AgentCard::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_agent_card(card, environment, expected_tenant)
}

/// Decodes and validates one bounded initial-profile ProtoJSON Agent Card.
///
/// # Errors
///
/// Returns a stable contract error for oversized, malformed, unsupported, insecure,
/// duplicate, or deployment-mismatched card content.
pub fn decode_initial_agent_card_json(
    bytes: &[u8],
    environment: InitialA2AInterfaceEnvironment,
    expected_tenant: Option<&str>,
) -> Result<InitialA2AAgentCard, A2AContractError> {
    let card = decode_json_bounded(bytes, MAX_A2A_ENCODED_AGENT_CARD_BYTES)?;
    validate_initial_agent_card(card, environment, expected_tenant)
}

/// Narrows one generated Agent Card to Konclave's initial A2A profile.
///
/// # Errors
///
/// Returns a stable contract error when required metadata is absent, a value exceeds
/// its bound, an unsupported capability is advertised, or an interface tenant differs
/// from deployment configuration.
pub fn validate_initial_agent_card(
    card: AgentCard,
    environment: InitialA2AInterfaceEnvironment,
    expected_tenant: Option<&str>,
) -> Result<InitialA2AAgentCard, A2AContractError> {
    validate_display_text(&card.name, MAX_A2A_AGENT_NAME_BYTES, "agent_card.name")?;
    validate_display_text(
        &card.description,
        MAX_A2A_AGENT_DESCRIPTION_BYTES,
        "agent_card.description",
    )?;
    validate_version(&card.version)?;
    if card.provider.is_some() {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.provider",
        });
    }
    if card.documentation_url.is_some() {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.documentation_url",
        });
    }
    if card.icon_url.is_some() {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.icon_url",
        });
    }
    if !card.signatures.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.signatures",
        });
    }
    validate_modes(&card.default_input_modes, "agent_card.default_input_modes")?;
    validate_modes(
        &card.default_output_modes,
        "agent_card.default_output_modes",
    )?;

    let capabilities = card
        .capabilities
        .as_ref()
        .ok_or(A2AContractError::MissingField {
            field: "agent_card.capabilities",
        })?;
    if capabilities.streaming.unwrap_or(false) {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.capabilities.streaming",
        });
    }
    if capabilities.push_notifications.unwrap_or(false) {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.capabilities.push_notifications",
        });
    }
    if !capabilities.extensions.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.capabilities.extensions",
        });
    }
    let extended_agent_card = capabilities.extended_agent_card.unwrap_or(false);

    if card.supported_interfaces.is_empty() {
        return Err(A2AContractError::MissingField {
            field: "agent_card.supported_interfaces",
        });
    }
    if card.supported_interfaces.len() > MAX_A2A_AGENT_CARD_INTERFACES {
        return Err(A2AContractError::OutOfRange {
            field: "agent_card.supported_interfaces",
        });
    }
    let expected_tenant = expected_tenant
        .map(|value| validate_identifier(value.to_owned(), "expected_tenant"))
        .transpose()?;
    let mut interfaces = Vec::with_capacity(card.supported_interfaces.len());
    let mut interface_keys = BTreeSet::new();
    for interface in card.supported_interfaces.iter().cloned() {
        let interface = validate_initial_agent_interface(interface, environment)?;
        if interface.tenant() != expected_tenant.as_deref() {
            return Err(A2AContractError::TenantMismatch);
        }
        if !interface_keys.insert((
            interface.url().to_owned(),
            interface.tenant().map(str::to_owned),
        )) {
            return Err(A2AContractError::DuplicateValue {
                field: "agent_card.supported_interfaces",
            });
        }
        interfaces.push(interface);
    }

    let security = validate_security(&card)?;
    let skills = validate_skills(&card)?;
    Ok(InitialA2AAgentCard {
        wire: card,
        interfaces,
        security,
        skills,
        extended_agent_card,
    })
}

fn validate_security(
    card: &AgentCard,
) -> Result<Option<InitialA2AAgentSecurity>, A2AContractError> {
    if card.security_schemes.len() > 1 {
        return Err(A2AContractError::OutOfRange {
            field: "agent_card.security_schemes",
        });
    }
    let security = card
        .security_schemes
        .iter()
        .next()
        .map(|(name, scheme)| {
            let name = validate_identifier(name.clone(), "agent_card.security_scheme.name")?;
            let scheme = scheme
                .scheme
                .as_ref()
                .ok_or(A2AContractError::MissingField {
                    field: "agent_card.security_scheme",
                })?;
            let (kind, bearer_format) = match scheme {
                security_scheme::Scheme::HttpAuthSecurityScheme(scheme) => {
                    validate_optional_display_text(
                        &scheme.description,
                        MAX_A2A_SECURITY_DESCRIPTION_BYTES,
                        "agent_card.security_scheme.description",
                    )?;
                    if scheme.scheme != "Bearer" {
                        return Err(A2AContractError::UnsupportedField {
                            field: "agent_card.security_scheme.http.scheme",
                        });
                    }
                    let bearer_format = if scheme.bearer_format.is_empty() {
                        None
                    } else {
                        validate_ascii_text(
                            &scheme.bearer_format,
                            MAX_A2A_BEARER_FORMAT_BYTES,
                            "agent_card.security_scheme.http.bearer_format",
                        )?;
                        Some(scheme.bearer_format.clone())
                    };
                    (InitialA2AAgentSecurityKind::Bearer, bearer_format)
                }
                security_scheme::Scheme::MtlsSecurityScheme(scheme) => {
                    validate_optional_display_text(
                        &scheme.description,
                        MAX_A2A_SECURITY_DESCRIPTION_BYTES,
                        "agent_card.security_scheme.description",
                    )?;
                    (InitialA2AAgentSecurityKind::MutualTls, None)
                }
                _ => {
                    return Err(A2AContractError::UnsupportedField {
                        field: "agent_card.security_scheme",
                    });
                }
            };
            Ok(InitialA2AAgentSecurity {
                name,
                kind,
                bearer_format,
            })
        })
        .transpose()?;
    validate_security_requirements(&card.security_requirements, security.as_ref())?;
    Ok(security)
}

fn validate_security_requirements(
    requirements: &[SecurityRequirement],
    security: Option<&InitialA2AAgentSecurity>,
) -> Result<(), A2AContractError> {
    let Some(security) = security else {
        if requirements.is_empty() {
            return Ok(());
        }
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.security_requirements",
        });
    };
    if requirements.len() != 1 || requirements[0].schemes.len() != 1 {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.security_requirements",
        });
    }
    let Some(scopes) = requirements[0].schemes.get(security.name()) else {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.security_requirements",
        });
    };
    if !scopes.list.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.security_requirements.scopes",
        });
    }
    Ok(())
}

fn validate_skills(card: &AgentCard) -> Result<Vec<InitialA2AAgentSkill>, A2AContractError> {
    if card.skills.is_empty() {
        return Err(A2AContractError::MissingField {
            field: "agent_card.skills",
        });
    }
    if card.skills.len() > MAX_A2A_AGENT_CARD_SKILLS {
        return Err(A2AContractError::OutOfRange {
            field: "agent_card.skills",
        });
    }
    let mut skill_ids = BTreeSet::new();
    let mut skills = Vec::with_capacity(card.skills.len());
    for skill in &card.skills {
        let id = validate_identifier(skill.id.clone(), "agent_card.skill.id")?;
        if !skill_ids.insert(id.clone()) {
            return Err(A2AContractError::DuplicateValue {
                field: "agent_card.skill.id",
            });
        }
        validate_display_text(
            &skill.name,
            MAX_A2A_AGENT_NAME_BYTES,
            "agent_card.skill.name",
        )?;
        validate_display_text(
            &skill.description,
            MAX_A2A_AGENT_DESCRIPTION_BYTES,
            "agent_card.skill.description",
        )?;
        if skill.tags.is_empty() {
            return Err(A2AContractError::MissingField {
                field: "agent_card.skill.tags",
            });
        }
        if skill.tags.len() > MAX_A2A_AGENT_SKILL_TAGS {
            return Err(A2AContractError::OutOfRange {
                field: "agent_card.skill.tags",
            });
        }
        let mut tags = BTreeSet::new();
        for tag in &skill.tags {
            validate_display_text(tag, MAX_A2A_AGENT_SKILL_TAG_BYTES, "agent_card.skill.tag")?;
            if !tags.insert(tag) {
                return Err(A2AContractError::DuplicateValue {
                    field: "agent_card.skill.tag",
                });
            }
        }
        if !skill.examples.is_empty() {
            return Err(A2AContractError::UnsupportedField {
                field: "agent_card.skill.examples",
            });
        }
        validate_inherited_modes(&skill.input_modes, "agent_card.skill.input_modes")?;
        validate_inherited_modes(&skill.output_modes, "agent_card.skill.output_modes")?;
        if !skill.security_requirements.is_empty() {
            return Err(A2AContractError::UnsupportedField {
                field: "agent_card.skill.security_requirements",
            });
        }
        skills.push(InitialA2AAgentSkill {
            id,
            name: skill.name.clone(),
            description: skill.description.clone(),
            tags: skill.tags.clone(),
        });
    }
    Ok(skills)
}

fn validate_modes(modes: &[String], field: &'static str) -> Result<(), A2AContractError> {
    if modes == [A2A_TEXT_MEDIA_TYPE] {
        Ok(())
    } else {
        Err(A2AContractError::UnsupportedField { field })
    }
}

fn validate_inherited_modes(modes: &[String], field: &'static str) -> Result<(), A2AContractError> {
    if modes.is_empty() || modes == [A2A_TEXT_MEDIA_TYPE] {
        Ok(())
    } else {
        Err(A2AContractError::UnsupportedField { field })
    }
}

fn validate_display_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), A2AContractError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(A2AContractError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_optional_display_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), A2AContractError> {
    if value.is_empty() {
        Ok(())
    } else {
        validate_display_text(value, maximum, field)
    }
}

fn validate_ascii_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), A2AContractError> {
    if !value.is_ascii() {
        return Err(A2AContractError::InvalidText { field });
    }
    validate_display_text(value, maximum, field)
}

fn validate_version(value: &str) -> Result<(), A2AContractError> {
    if value.is_empty()
        || value.len() > MAX_A2A_AGENT_VERSION_BYTES
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        Err(A2AContractError::InvalidText {
            field: "agent_card.version",
        })
    } else {
        Ok(())
    }
}
