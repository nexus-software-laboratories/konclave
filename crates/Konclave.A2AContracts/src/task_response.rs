use prost::Message as _;

use crate::A2AContractError;
use crate::initial_profile::{
    A2A_TEXT_MEDIA_TYPE, decode_json_bounded, require_empty_struct, require_encoded_bound,
    validate_identifier, validate_text,
};
use crate::wire::{
    Message, Role, SendMessageResponse, Task, TaskState, part, send_message_response,
};

/// Maximum encoded protobuf or ProtoJSON task response accepted before decoding.
pub const MAX_A2A_ENCODED_RESPONSE_BYTES: usize = 256 * 1024;
const MIN_PROTOBUF_TIMESTAMP_SECONDS: i64 = -62_135_596_800;
const MAX_PROTOBUF_TIMESTAMP_SECONDS: i64 = 253_402_300_799;

/// Validated task returned by the initial non-streaming profile.
pub struct InitialA2ATaskResponse {
    wire: Task,
    state: TaskState,
}

impl InitialA2ATaskResponse {
    /// Returns the canonical task identifier.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.wire.id
    }

    /// Returns the canonical context identifier.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.wire.context_id
    }

    /// Returns the validated current task state.
    #[must_use]
    pub const fn state(&self) -> TaskState {
        self.state
    }

    /// Returns the validated generated wire DTO.
    #[must_use]
    pub const fn as_wire(&self) -> &Task {
        &self.wire
    }

    /// Returns the generated wire DTO and consumes the validated wrapper.
    #[must_use]
    pub fn into_wire(self) -> Task {
        self.wire
    }

    /// Produces deterministic compact ProtoJSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a contract error if generated ProtoJSON unexpectedly cannot be
    /// represented or exceeds the response bound.
    pub fn deterministic_json(&self) -> Result<Vec<u8>, A2AContractError> {
        let value =
            serde_json::to_value(&self.wire).map_err(|_| A2AContractError::MalformedEncoding)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| A2AContractError::MalformedEncoding)?;
        require_encoded_bound(&bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
        Ok(bytes)
    }
}

/// Decodes and validates one bounded protobuf Task response.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, unsupported, or
/// inconsistent task content.
pub fn decode_initial_task_protobuf(
    bytes: &[u8],
) -> Result<InitialA2ATaskResponse, A2AContractError> {
    require_encoded_bound(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    let task = Task::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_task(task)
}

/// Decodes and validates one bounded ProtoJSON Task response.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, unsupported, or
/// inconsistent task content.
pub fn decode_initial_task_json(bytes: &[u8]) -> Result<InitialA2ATaskResponse, A2AContractError> {
    let task = decode_json_bounded(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    validate_initial_task(task)
}

/// Decodes and validates one bounded protobuf `SendMessageResponse` containing a
/// Task.
///
/// # Errors
///
/// Returns a stable contract error when the response is malformed, oversized,
/// unsupported, or contains a direct Message instead of the initial task projection.
pub fn decode_initial_send_message_response_protobuf(
    bytes: &[u8],
) -> Result<InitialA2ATaskResponse, A2AContractError> {
    require_encoded_bound(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    let response =
        SendMessageResponse::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_send_message_response(response)
}

/// Decodes and validates one bounded ProtoJSON `SendMessageResponse` containing a
/// Task.
///
/// # Errors
///
/// Returns a stable contract error when the response is malformed, oversized,
/// unsupported, or contains a direct Message instead of the initial task projection.
pub fn decode_initial_send_message_response_json(
    bytes: &[u8],
) -> Result<InitialA2ATaskResponse, A2AContractError> {
    let response = decode_json_bounded(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    validate_initial_send_message_response(response)
}

/// Narrows one generated `SendMessageResponse` to the initial task-only profile.
///
/// # Errors
///
/// Returns a stable contract error when the response has no task or uses the direct
/// message response shape.
pub fn validate_initial_send_message_response(
    response: SendMessageResponse,
) -> Result<InitialA2ATaskResponse, A2AContractError> {
    match response.payload {
        Some(send_message_response::Payload::Task(task)) => validate_initial_task(task),
        Some(send_message_response::Payload::Message(_)) => {
            Err(A2AContractError::UnsupportedField {
                field: "send_message_response.message",
            })
        }
        None => Err(A2AContractError::MissingField {
            field: "send_message_response.payload",
        }),
    }
}

/// Narrows one generated Task to the initial non-streaming text-only profile.
///
/// # Errors
///
/// Returns a stable contract error for missing identity or status, invalid state or
/// timestamps, unsupported artifacts or metadata, excessive history, or inconsistent
/// message identity.
pub fn validate_initial_task(task: Task) -> Result<InitialA2ATaskResponse, A2AContractError> {
    let task_id = validate_identifier(task.id.clone(), "task.id")?;
    let context_id = validate_identifier(task.context_id.clone(), "task.context_id")?;
    let status = task.status.as_ref().ok_or(A2AContractError::MissingField {
        field: "task.status",
    })?;
    let state = TaskState::try_from(status.state)
        .ok()
        .filter(|state| *state != TaskState::Unspecified)
        .ok_or(A2AContractError::UnsupportedField {
            field: "task.status.state",
        })?;
    let timestamp = status
        .timestamp
        .as_ref()
        .ok_or(A2AContractError::MissingField {
            field: "task.status.timestamp",
        })?;
    validate_timestamp(timestamp)?;
    if let Some(message) = &status.message {
        validate_task_message(message, &task_id, &context_id, Some(Role::Agent))?;
    }
    if !task.artifacts.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "task.artifacts",
        });
    }
    if task.history.len() > 1 {
        return Err(A2AContractError::OutOfRange {
            field: "task.history",
        });
    }
    for message in &task.history {
        validate_task_message(message, &task_id, &context_id, None)?;
    }
    require_empty_struct(task.metadata.clone(), "task.metadata")?;
    Ok(InitialA2ATaskResponse { wire: task, state })
}

fn validate_task_message(
    message: &Message,
    task_id: &str,
    context_id: &str,
    required_role: Option<Role>,
) -> Result<(), A2AContractError> {
    validate_identifier(message.message_id.clone(), "task.message.message_id")?;
    if message.task_id != task_id {
        return Err(A2AContractError::InvalidIdentifier {
            field: "task.message.task_id",
        });
    }
    if message.context_id != context_id {
        return Err(A2AContractError::InvalidIdentifier {
            field: "task.message.context_id",
        });
    }
    let role = Role::try_from(message.role)
        .ok()
        .filter(|role| *role != Role::Unspecified)
        .ok_or(A2AContractError::UnsupportedField {
            field: "task.message.role",
        })?;
    if required_role.is_some_and(|required| required != role) {
        return Err(A2AContractError::UnsupportedField {
            field: "task.status.message.role",
        });
    }
    if message.parts.len() != 1 {
        return Err(A2AContractError::UnsupportedField {
            field: "task.message.parts",
        });
    }
    let part = &message.parts[0];
    require_empty_struct(part.metadata.clone(), "task.message.part.metadata")?;
    if !part.filename.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "task.message.part.filename",
        });
    }
    if !part.media_type.is_empty() && part.media_type != A2A_TEXT_MEDIA_TYPE {
        return Err(A2AContractError::UnsupportedField {
            field: "task.message.part.media_type",
        });
    }
    match &part.content {
        Some(part::Content::Text(text)) => {
            validate_text(text.clone(), "task.message.part.text")?;
        }
        Some(_) => {
            return Err(A2AContractError::UnsupportedField {
                field: "task.message.part.content",
            });
        }
        None => {
            return Err(A2AContractError::MissingField {
                field: "task.message.part.content",
            });
        }
    }
    require_empty_struct(message.metadata.clone(), "task.message.metadata")?;
    if !message.extensions.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "task.message.extensions",
        });
    }
    if !message.reference_task_ids.is_empty() {
        return Err(A2AContractError::UnsupportedField {
            field: "task.message.reference_task_ids",
        });
    }
    Ok(())
}

fn validate_timestamp(timestamp: &pbjson_types::Timestamp) -> Result<(), A2AContractError> {
    if !(MIN_PROTOBUF_TIMESTAMP_SECONDS..=MAX_PROTOBUF_TIMESTAMP_SECONDS)
        .contains(&timestamp.seconds)
        || !(0..1_000_000_000).contains(&timestamp.nanos)
    {
        Err(A2AContractError::OutOfRange {
            field: "task.status.timestamp",
        })
    } else {
        Ok(())
    }
}
