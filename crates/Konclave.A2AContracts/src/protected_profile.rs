use crate::A2AContractError;
use crate::initial_profile::{InitialA2AInterfaceEnvironment, validate_initial_service_url};
use crate::wire::AgentExtension;

/// Versioned Agent Card extension for native Konclave protected handoff.
pub const A2A_KONCLAVE_PROTECTED_EXTENSION_URI: &str =
    "https://konclave.dev/a2a/extensions/protected/v1";
/// Fixed protected-profile identifier.
pub const A2A_KONCLAVE_PROTECTED_PROFILE: &str = "konclave-native-v1";
/// Fixed native transport identifier.
pub const A2A_KONCLAVE_PROTECTED_TRANSPORT: &str = "konclave-relay-v1";
/// Fixed payload-protection claim.
pub const A2A_KONCLAVE_PROTECTED_PAYLOAD_PROTECTION: &str = "mls-rfc9420";
/// Fixed relay/gateway visibility claim.
pub const A2A_KONCLAVE_PROTECTED_GATEWAY_VISIBILITY: &str = "application-opaque";
/// Fixed protected-mode downgrade policy.
pub const A2A_KONCLAVE_PROTECTED_DOWNGRADE_POLICY: &str = "fail-closed";
/// Human-readable extension description emitted by the reference publisher.
pub const A2A_KONCLAVE_PROTECTED_DESCRIPTION: &str =
    "Use native Konclave transport for MLS-protected agent communication.";

const RELAY_ENDPOINT_FIELD: &str = "relayEndpoint";
const PARAMETER_COUNT: usize = 1;
const MAX_EXTENSION_DESCRIPTION_BYTES: usize = 512;

/// Validated native Konclave handoff advertised by an A2A Agent Card.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialA2AProtectedProfile {
    required: bool,
    relay_endpoint: String,
}

impl InitialA2AProtectedProfile {
    /// Returns whether clients must understand the protected extension.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Returns the canonical native Konclave relay endpoint.
    #[must_use]
    pub fn relay_endpoint(&self) -> &str {
        &self.relay_endpoint
    }

    /// Returns the fixed protected-profile identifier.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        A2A_KONCLAVE_PROTECTED_PROFILE
    }

    /// Returns the fixed native transport identifier.
    #[must_use]
    pub const fn transport(&self) -> &'static str {
        A2A_KONCLAVE_PROTECTED_TRANSPORT
    }

    /// Returns the fixed payload-protection claim.
    #[must_use]
    pub const fn payload_protection(&self) -> &'static str {
        A2A_KONCLAVE_PROTECTED_PAYLOAD_PROTECTION
    }

    /// Returns the fixed gateway visibility claim.
    #[must_use]
    pub const fn gateway_visibility(&self) -> &'static str {
        A2A_KONCLAVE_PROTECTED_GATEWAY_VISIBILITY
    }

    /// Returns the fixed downgrade policy.
    #[must_use]
    pub const fn downgrade_policy(&self) -> &'static str {
        A2A_KONCLAVE_PROTECTED_DOWNGRADE_POLICY
    }
}

/// Caller-selected trust requirement for one Agent Card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialA2ATrustRequirement {
    /// Explicitly permit the standard plaintext A2A HTTP bridge.
    AllowStandardBridge,
    /// Require the exact native Konclave protected profile.
    RequireKonclaveProtected,
}

/// Trust mode selected without fallback.
#[derive(Clone, PartialEq, Eq)]
pub enum InitialA2ANegotiatedTrust {
    /// Standard HTTP+JSON bridge mode where the gateway sees plaintext.
    StandardBridge,
    /// Native Konclave mode where the relay sees only MLS-protected content.
    KonclaveProtected(InitialA2AProtectedProfile),
}

/// Selects one trust mode without a prefer-and-fallback path.
///
/// # Errors
///
/// Returns a required-extension error when the selected mode is unavailable or a
/// protected-required card is presented to a standard caller.
pub fn negotiate_initial_a2a_trust(
    protected_profile: Option<&InitialA2AProtectedProfile>,
    requirement: InitialA2ATrustRequirement,
) -> Result<InitialA2ANegotiatedTrust, A2AContractError> {
    match (requirement, protected_profile) {
        (InitialA2ATrustRequirement::AllowStandardBridge, Some(profile)) if profile.required() => {
            Err(A2AContractError::RequiredExtensionUnsupported)
        }
        (InitialA2ATrustRequirement::AllowStandardBridge, _) => {
            Ok(InitialA2ANegotiatedTrust::StandardBridge)
        }
        (InitialA2ATrustRequirement::RequireKonclaveProtected, Some(profile)) => Ok(
            InitialA2ANegotiatedTrust::KonclaveProtected(profile.clone()),
        ),
        (InitialA2ATrustRequirement::RequireKonclaveProtected, None) => {
            Err(A2AContractError::RequiredExtensionUnsupported)
        }
    }
}

pub(crate) fn validate_initial_protected_profile(
    extensions: &[AgentExtension],
    environment: InitialA2AInterfaceEnvironment,
) -> Result<Option<InitialA2AProtectedProfile>, A2AContractError> {
    if extensions.is_empty() {
        return Ok(None);
    }
    if extensions.len() != 1 || extensions[0].uri != A2A_KONCLAVE_PROTECTED_EXTENSION_URI {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.capabilities.extensions",
        });
    }
    let extension = &extensions[0];
    if extension.description.is_empty()
        || extension.description.len() > MAX_EXTENSION_DESCRIPTION_BYTES
        || extension.description.trim() != extension.description
        || extension.description.chars().any(char::is_control)
    {
        return Err(A2AContractError::InvalidText {
            field: "agent_card.capabilities.extension.description",
        });
    }
    let parameters = extension
        .params
        .as_ref()
        .ok_or(A2AContractError::MissingField {
            field: "agent_card.capabilities.extension.params",
        })?;
    if parameters.fields.len() != PARAMETER_COUNT {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_card.capabilities.extension.params",
        });
    }
    let relay_endpoint = validate_initial_service_url(
        string_parameter(parameters, RELAY_ENDPOINT_FIELD)?,
        environment,
    )?;
    Ok(Some(InitialA2AProtectedProfile {
        required: extension.required,
        relay_endpoint,
    }))
}

fn string_parameter<'a>(
    parameters: &'a pbjson_types::Struct,
    field: &'static str,
) -> Result<&'a str, A2AContractError> {
    parameters
        .fields
        .get(field)
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            pbjson_types::value::Kind::StringValue(value) => Some(value.as_str()),
            _ => None,
        })
        .ok_or(A2AContractError::MissingField {
            field: "agent_card.capabilities.extension.params",
        })
}
