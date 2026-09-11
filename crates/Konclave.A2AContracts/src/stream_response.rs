use prost::Message as _;

use crate::initial_profile::{
    decode_json_bounded, require_encoded_bound, validate_identifier,
};
use crate::task_response::{
    MAX_A2A_ENCODED_RESPONSE_BYTES, validate_task_message, validate_terminal_reason_metadata,
    validate_timestamp,
};
use crate::wire::{
    Role, StreamResponse, TaskState, stream_response,
};
use crate::{A2AContractError, validate_initial_task};

/// Streaming payload shape admitted by Konclave's text-only A2A profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialA2AStreamResponseKind {
    /// Full current Task snapshot.
    Task,
    /// Ordered task-status update.
    StatusUpdate,
}

/// Validated `StreamResponse` admitted by the text-only streaming profile.
pub struct InitialA2AStreamResponse {
    wire: StreamResponse,
    kind: InitialA2AStreamResponseKind,
    task_id: String,
    context_id: String,
    state: TaskState,
}

impl InitialA2AStreamResponse {
    /// Returns the admitted streaming payload shape.
    #[must_use]
    pub const fn kind(&self) -> InitialA2AStreamResponseKind {
        self.kind
    }

    /// Returns the canonical task identifier.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Returns the canonical context identifier.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the validated current or updated task state.
    #[must_use]
    pub const fn state(&self) -> TaskState {
        self.state
    }

    /// Returns the generated wire DTO after validation.
    #[must_use]
    pub const fn as_wire(&self) -> &StreamResponse {
        &self.wire
    }

    /// Returns the generated wire DTO and consumes the validated wrapper.
    #[must_use]
    pub fn into_wire(self) -> StreamResponse {
        self.wire
    }

    /// Produces deterministic compact ProtoJSON bytes for one SSE `data` field.
    ///
    /// # Errors
    ///
    /// Returns a contract error when generated ProtoJSON cannot be represented or
    /// exceeds the response-event bound.
    pub fn deterministic_json(&self) -> Result<Vec<u8>, A2AContractError> {
        let value =
            serde_json::to_value(&self.wire).map_err(|_| A2AContractError::MalformedEncoding)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| A2AContractError::MalformedEncoding)?;
        require_encoded_bound(&bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
        Ok(bytes)
    }
}

/// Decodes and validates one bounded protobuf `StreamResponse`.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, unsupported, or
/// inconsistent stream content.
pub fn decode_initial_stream_response_protobuf(
    bytes: &[u8],
) -> Result<InitialA2AStreamResponse, A2AContractError> {
    require_encoded_bound(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    let response =
        StreamResponse::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_stream_response(response)
}

/// Decodes and validates one bounded ProtoJSON `StreamResponse`.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, unsupported, or
/// inconsistent stream content.
pub fn decode_initial_stream_response_json(
    bytes: &[u8],
) -> Result<InitialA2AStreamResponse, A2AContractError> {
    let response = decode_json_bounded(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    validate_initial_stream_response(response)
}

/// Narrows one generated `StreamResponse` to Task snapshots and status updates.
///
/// Direct Message and artifact-update payloads remain outside the text-only profile.
///
/// # Errors
///
/// Returns a stable contract error for absent, unsupported, or inconsistent payloads.
pub fn validate_initial_stream_response(
    response: StreamResponse,
) -> Result<InitialA2AStreamResponse, A2AContractError> {
    match response.payload {
        Some(stream_response::Payload::Task(task)) => {
            let task = validate_initial_task(task)?;
            let task_id = task.task_id().to_owned();
            let context_id = task.context_id().to_owned();
            let state = task.state();
            Ok(InitialA2AStreamResponse {
                wire: StreamResponse {
                    payload: Some(stream_response::Payload::Task(task.into_wire())),
                },
                kind: InitialA2AStreamResponseKind::Task,
                task_id,
                context_id,
                state,
            })
        }
        Some(stream_response::Payload::StatusUpdate(update)) => {
            let task_id = validate_identifier(
                update.task_id.clone(),
                "stream_response.status_update.task_id",
            )?;
            let context_id = validate_identifier(
                update.context_id.clone(),
                "stream_response.status_update.context_id",
            )?;
            let status = update.status.as_ref().ok_or(A2AContractError::MissingField {
                field: "stream_response.status_update.status",
            })?;
            let state = TaskState::try_from(status.state)
                .ok()
                .filter(|state| *state != TaskState::Unspecified)
                .ok_or(A2AContractError::UnsupportedField {
                    field: "stream_response.status_update.status.state",
                })?;
            let timestamp =
                status
                    .timestamp
                    .as_ref()
                    .ok_or(A2AContractError::MissingField {
                        field: "stream_response.status_update.status.timestamp",
                    })?;
            validate_timestamp(
                timestamp,
                "stream_response.status_update.status.timestamp",
            )?;
            if let Some(message) = &status.message {
                validate_task_message(message, &task_id, &context_id, Some(Role::Agent))?;
            }
            validate_terminal_reason_metadata(
                update.metadata.as_ref(),
                state,
                "stream_response.status_update.metadata",
            )?;
            Ok(InitialA2AStreamResponse {
                wire: StreamResponse {
                    payload: Some(stream_response::Payload::StatusUpdate(update)),
                },
                kind: InitialA2AStreamResponseKind::StatusUpdate,
                task_id,
                context_id,
                state,
            })
        }
        Some(stream_response::Payload::Message(_)) => {
            Err(A2AContractError::UnsupportedField {
                field: "stream_response.message",
            })
        }
        Some(stream_response::Payload::ArtifactUpdate(_)) => {
            Err(A2AContractError::UnsupportedField {
                field: "stream_response.artifact_update",
            })
        }
        None => Err(A2AContractError::MissingField {
            field: "stream_response.payload",
        }),
    }
}
