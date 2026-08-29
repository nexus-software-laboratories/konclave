use prost::Message as _;
use serde::de::DeserializeOwned;
use url::{Host, Url};

use crate::A2AContractError;
use crate::wire::{AgentInterface, GetTaskRequest, Role, SendMessageRequest, part};

/// A2A protocol version exposed by the initial Konclave gateway profile.
pub const A2A_PROTOCOL_VERSION: &str = "1.0";
/// A2A binding exposed by the initial Konclave gateway profile.
pub const A2A_HTTP_JSON_BINDING: &str = "HTTP+JSON";
/// Only media type accepted by the initial text-only profile.
pub const A2A_TEXT_MEDIA_TYPE: &str = "text/plain";
/// Maximum encoded protobuf or ProtoJSON request accepted before decoding.
pub const MAX_A2A_ENCODED_REQUEST_BYTES: usize = 128 * 1024;
/// Maximum UTF-8 byte length of an initial-profile text part.
pub const MAX_A2A_TEXT_BYTES: usize = 64 * 1024;
/// Maximum byte length of an A2A task, context, message, or tenant identifier.
pub const MAX_A2A_IDENTIFIER_BYTES: usize = 128;
const MAX_A2A_INTERFACE_URL_BYTES: usize = 2 * 1024;
const MAX_A2A_HISTORY_LENGTH: i32 = 1;

/// Validated text-only `SendMessage` request accepted by the initial profile.
#[derive(PartialEq, Eq)]
pub struct InitialSendMessageRequest {
    tenant: Option<String>,
    message_id: String,
    context_id: Option<String>,
    text: String,
    return_immediately: bool,
    history_length: Option<u32>,
}

impl InitialSendMessageRequest {
    /// Returns the deployment-selected tenant, when the published interface uses one.
    #[must_use]
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// Returns the caller-generated A2A message identifier.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns the optional caller context identifier.
    #[must_use]
    pub fn context_id(&self) -> Option<&str> {
        self.context_id.as_deref()
    }

    /// Returns the single validated UTF-8 request body.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns whether the caller requested an immediate submitted-task response.
    #[must_use]
    pub const fn return_immediately(&self) -> bool {
        self.return_immediately
    }

    /// Returns the requested bounded history length.
    #[must_use]
    pub const fn history_length(&self) -> Option<u32> {
        self.history_length
    }
}

/// Validated `GetTask` request accepted by the initial profile.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialGetTaskRequest {
    tenant: Option<String>,
    task_id: String,
    history_length: Option<u32>,
}

impl InitialGetTaskRequest {
    /// Returns the deployment-selected tenant, when the published interface uses one.
    #[must_use]
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// Returns the exact gateway-owned task identifier.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Returns the requested bounded history length.
    #[must_use]
    pub const fn history_length(&self) -> Option<u32> {
        self.history_length
    }
}

/// Environment in which an initial A2A interface URL is advertised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialA2AInterfaceEnvironment {
    /// Requires an absolute HTTPS URL.
    Production,
    /// Also permits HTTP when the host is loopback.
    LoopbackDevelopment,
}

/// Validated initial-profile A2A interface advertisement.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialA2AValidatedInterface {
    url: String,
    tenant: Option<String>,
}

impl InitialA2AValidatedInterface {
    /// Returns the validated absolute interface URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the optional deployment-owned tenant routing value.
    #[must_use]
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
}

/// Decodes and validates one bounded initial-profile protobuf `SendMessage` request.
///
/// # Errors
///
/// Returns a stable contract error for oversized, malformed, unsupported, or
/// deployment-mismatched input.
pub fn decode_initial_send_message_protobuf(
    bytes: &[u8],
    expected_tenant: Option<&str>,
) -> Result<InitialSendMessageRequest, A2AContractError> {
    require_encoded_bound(bytes)?;
    let request =
        SendMessageRequest::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_send_message_request(request, expected_tenant)
}

/// Decodes and validates one bounded initial-profile ProtoJSON `SendMessage` request.
///
/// # Errors
///
/// Returns a stable contract error for oversized, malformed, unsupported, or
/// deployment-mismatched input.
pub fn decode_initial_send_message_json(
    bytes: &[u8],
    expected_tenant: Option<&str>,
) -> Result<InitialSendMessageRequest, A2AContractError> {
    let request = decode_json(bytes)?;
    validate_initial_send_message_request(request, expected_tenant)
}

/// Narrows one generated `SendMessage` DTO to the initial text-only profile.
///
/// # Errors
///
/// Returns a stable contract error when the request uses unsupported content,
/// metadata, routing, history, or role semantics.
pub fn validate_initial_send_message_request(
    request: SendMessageRequest,
    expected_tenant: Option<&str>,
) -> Result<InitialSendMessageRequest, A2AContractError> {
    let tenant = validate_tenant(request.tenant, expected_tenant)?;
    require_empty_struct(request.metadata, "send_message.metadata")?;
    let message = request.message.ok_or(A2AContractError::MissingField {
        field: "send_message.message",
    })?;
    let message_id = validate_identifier(message.message_id, "message.message_id")?;
    let context_id = optional_identifier(message.context_id, "message.context_id")?;
    if !message.task_id.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "message.task_id",
        });
    }
    if Role::try_from(message.role).ok() != Some(Role::User) {
        return Err(A2AContractError::UnsupportedField {
            field: "message.role",
        });
    }
    if !message.extensions.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "message.extensions",
        });
    }
    if !message.reference_task_ids.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "message.reference_task_ids",
        });
    }
    require_empty_struct(message.metadata, "message.metadata")?;
    if message.parts.len() != 1 {
        return Err(A2AContractError::UnsupportedField {
            field: "message.parts",
        });
    }
    let mut part = message
        .parts
        .into_iter()
        .next()
        .ok_or(A2AContractError::MissingField {
            field: "message.parts",
        })?;
    require_empty_struct(part.metadata.take(), "part.metadata")?;
    if !part.filename.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "part.filename",
        });
    }
    if !part.media_type.is_empty() && part.media_type != A2A_TEXT_MEDIA_TYPE {
        return Err(A2AContractError::UnsupportedField {
            field: "part.media_type",
        });
    }
    let text = match part.content {
        Some(part::Content::Text(text)) => validate_text(text, "part.text")?,
        Some(_) => {
            return Err(A2AContractError::UnsupportedField {
                field: "part.content",
            });
        }
        None => {
            return Err(A2AContractError::MissingField {
                field: "part.content",
            });
        }
    };
    let (return_immediately, history_length) = match request.configuration {
        Some(configuration) => {
            if configuration.task_push_notification_config.is_some() {
                return Err(A2AContractError::UnsupportedField {
                    field: "configuration.task_push_notification_config",
                });
            }
            if configuration.accepted_output_modes.len() > 1
                || configuration
                    .accepted_output_modes
                    .first()
                    .is_some_and(|mode| mode != A2A_TEXT_MEDIA_TYPE)
            {
                return Err(A2AContractError::UnsupportedField {
                    field: "configuration.accepted_output_modes",
                });
            }
            (
                configuration.return_immediately,
                validate_history_length(configuration.history_length)?,
            )
        }
        None => (false, None),
    };
    Ok(InitialSendMessageRequest {
        tenant,
        message_id,
        context_id,
        text,
        return_immediately,
        history_length,
    })
}

/// Decodes and validates one bounded initial-profile protobuf `GetTask` request.
///
/// # Errors
///
/// Returns a stable contract error for oversized, malformed, or deployment-mismatched
/// input.
pub fn decode_initial_get_task_protobuf(
    bytes: &[u8],
    expected_tenant: Option<&str>,
) -> Result<InitialGetTaskRequest, A2AContractError> {
    require_encoded_bound(bytes)?;
    let request = GetTaskRequest::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_get_task_request(request, expected_tenant)
}

/// Decodes and validates one bounded initial-profile ProtoJSON `GetTask` request.
///
/// # Errors
///
/// Returns a stable contract error for oversized, malformed, or deployment-mismatched
/// input.
pub fn decode_initial_get_task_json(
    bytes: &[u8],
    expected_tenant: Option<&str>,
) -> Result<InitialGetTaskRequest, A2AContractError> {
    let request = decode_json(bytes)?;
    validate_initial_get_task_request(request, expected_tenant)
}

/// Narrows one generated `GetTask` DTO to the initial profile.
///
/// # Errors
///
/// Returns a stable contract error for invalid task, tenant, or history values.
pub fn validate_initial_get_task_request(
    request: GetTaskRequest,
    expected_tenant: Option<&str>,
) -> Result<InitialGetTaskRequest, A2AContractError> {
    Ok(InitialGetTaskRequest {
        tenant: validate_tenant(request.tenant, expected_tenant)?,
        task_id: validate_identifier(request.id, "get_task.id")?,
        history_length: validate_history_length(request.history_length)?,
    })
}

/// Validates one Agent Card interface against the initial HTTP+JSON profile.
///
/// # Errors
///
/// Returns a stable contract error for an unsupported binding/version, invalid tenant,
/// or an insecure/malformed URL.
pub fn validate_initial_agent_interface(
    interface: AgentInterface,
    environment: InitialA2AInterfaceEnvironment,
) -> Result<InitialA2AValidatedInterface, A2AContractError> {
    if interface.protocol_binding != A2A_HTTP_JSON_BINDING {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_interface.protocol_binding",
        });
    }
    if interface.protocol_version != A2A_PROTOCOL_VERSION {
        return Err(A2AContractError::UnsupportedField {
            field: "agent_interface.protocol_version",
        });
    }
    let tenant = optional_identifier(interface.tenant, "agent_interface.tenant")?;
    if interface.url.is_empty()
        || interface.url.len() > MAX_A2A_INTERFACE_URL_BYTES
        || !interface.url.is_ascii()
        || interface
            .url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    let parsed = Url::parse(&interface.url).map_err(|_| A2AContractError::InvalidInterfaceUrl)?;
    if parsed.as_str() != interface.url {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    if parsed.cannot_be_a_base()
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    let secure = parsed.scheme() == "https";
    let loopback_http = environment == InitialA2AInterfaceEnvironment::LoopbackDevelopment
        && parsed.scheme() == "http"
        && parsed.host().is_some_and(is_loopback_host);
    if !secure && !loopback_http {
        return Err(A2AContractError::InvalidInterfaceUrl);
    }
    Ok(InitialA2AValidatedInterface {
        url: parsed.to_string(),
        tenant,
    })
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, A2AContractError> {
    require_encoded_bound(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| A2AContractError::MalformedEncoding)
}

fn require_encoded_bound(bytes: &[u8]) -> Result<(), A2AContractError> {
    if bytes.len() > MAX_A2A_ENCODED_REQUEST_BYTES {
        Err(A2AContractError::EncodedMessageTooLarge {
            maximum: MAX_A2A_ENCODED_REQUEST_BYTES,
            actual: bytes.len(),
        })
    } else {
        Ok(())
    }
}

fn validate_tenant(
    tenant: String,
    expected_tenant: Option<&str>,
) -> Result<Option<String>, A2AContractError> {
    match expected_tenant {
        Some(expected) => {
            validate_identifier(expected.to_owned(), "expected_tenant")?;
            if tenant != expected {
                return Err(A2AContractError::TenantMismatch);
            }
            Ok(Some(tenant))
        }
        None if tenant.is_empty() => Ok(None),
        None => Err(A2AContractError::TenantMismatch),
    }
}

fn optional_identifier(
    value: String,
    field: &'static str,
) -> Result<Option<String>, A2AContractError> {
    if value.is_empty() {
        Ok(None)
    } else {
        validate_identifier(value, field).map(Some)
    }
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, A2AContractError> {
    if value.is_empty()
        || value.len() > MAX_A2A_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Err(A2AContractError::InvalidIdentifier { field })
    } else {
        Ok(value)
    }
}

fn validate_text(value: String, field: &'static str) -> Result<String, A2AContractError> {
    if value.is_empty() || value.len() > MAX_A2A_TEXT_BYTES {
        Err(A2AContractError::InvalidText { field })
    } else {
        Ok(value)
    }
}

fn validate_history_length(value: Option<i32>) -> Result<Option<u32>, A2AContractError> {
    match value {
        None => Ok(None),
        Some(value) if (0..=MAX_A2A_HISTORY_LENGTH).contains(&value) => u32::try_from(value)
            .map(Some)
            .map_err(|_| A2AContractError::OutOfRange {
                field: "history_length",
            }),
        Some(_) => Err(A2AContractError::OutOfRange {
            field: "history_length",
        }),
    }
}

fn require_empty_struct(
    value: Option<pbjson_types::Struct>,
    field: &'static str,
) -> Result<(), A2AContractError> {
    if value.is_some_and(|value| !value.fields.is_empty()) {
        Err(A2AContractError::UnsupportedField { field })
    } else {
        Ok(())
    }
}

fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}
