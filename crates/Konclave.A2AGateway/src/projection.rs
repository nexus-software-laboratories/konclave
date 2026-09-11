use std::collections::HashMap;

use KonclaveA2AContracts::wire::{
    ListTasksResponse, Message, Part, Role, StreamResponse, Task, TaskArtifactUpdateEvent,
    TaskStatus, TaskStatusUpdateEvent, part, send_message_response, stream_response,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, A2AContractError, INITIAL_TASK_TERMINAL_REASON_FIELD,
    InitialA2AStreamResponse, InitialA2ATaskListResponse, InitialA2ATaskResponse,
    MAX_A2A_ARTIFACTS_PER_TASK, decode_initial_artifact_json, validate_initial_list_tasks_response,
    validate_initial_stream_response, validate_initial_task,
};
use KonclaveA2ADomain::A2ATaskState;
use KonclaveA2ATaskStore::{
    A2ATaskMessageRole, A2ATaskRecord, A2ATerminalReason, StoredA2ATaskArtifact,
    StoredA2ATaskMessage, StoredA2ATaskStatus,
};

use crate::A2AGatewayError;

pub(crate) fn project_get_task(
    record: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    artifacts: Vec<StoredA2ATaskArtifact>,
    history_length: Option<u32>,
) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
    let task = project_task(record, messages, artifacts, Some(history_length), true)?;
    validate_initial_task(task).map_err(map_projection_error)
}

fn map_projection_error(error: A2AContractError) -> A2AGatewayError {
    match error {
        A2AContractError::EncodedMessageTooLarge { .. } => A2AGatewayError::ResponseTooLarge,
        _ => A2AGatewayError::InvalidTaskProjection,
    }
}

pub(crate) fn project_list_tasks(
    records: Vec<(A2ATaskRecord, Vec<StoredA2ATaskArtifact>)>,
    next_page_token: Option<String>,
    page_size: usize,
    total_size: usize,
) -> Result<InitialA2ATaskListResponse, A2AGatewayError> {
    let tasks = records
        .into_iter()
        .map(|(record, artifacts)| project_task(record, Vec::new(), artifacts, None, false))
        .collect::<Result<Vec<_>, _>>()?;
    let response = ListTasksResponse {
        tasks,
        next_page_token: next_page_token.unwrap_or_default(),
        page_size: i32::try_from(page_size).map_err(|_| A2AGatewayError::InvalidTaskProjection)?,
        total_size: i32::try_from(total_size)
            .map_err(|_| A2AGatewayError::InvalidTaskProjection)?,
    };
    let response = validate_initial_list_tasks_response(response).map_err(map_projection_error)?;
    response
        .deterministic_json()
        .map_err(map_projection_error)?;
    Ok(response)
}

pub(crate) fn project_stream_task(
    record: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    artifacts: Vec<StoredA2ATaskArtifact>,
    history_length: Option<u32>,
) -> Result<InitialA2AStreamResponse, A2AGatewayError> {
    let task = project_task(record, messages, artifacts, Some(history_length), true)?;
    validate_initial_stream_response(StreamResponse {
        payload: Some(stream_response::Payload::Task(task)),
    })
    .map_err(map_projection_error)
}

pub(crate) fn project_status_update(
    task_id: &str,
    context_id: &str,
    status: StoredA2ATaskStatus,
    messages: &[StoredA2ATaskMessage],
    completion_has_artifact: bool,
) -> Result<InitialA2AStreamResponse, A2AGatewayError> {
    let status_message = response_state(status.state())
        .then(|| {
            messages
                .iter()
                .rev()
                .find(|message| message.role() == A2ATaskMessageRole::Agent)
                .map(|message| project_message(message, task_id, context_id))
        })
        .flatten();
    if status.state() == A2ATaskState::Completed
        && status_message.is_none()
        && !completion_has_artifact
    {
        return Err(A2AGatewayError::InvalidTaskProjection);
    }
    validate_initial_stream_response(StreamResponse {
        payload: Some(stream_response::Payload::StatusUpdate(
            TaskStatusUpdateEvent {
                task_id: task_id.to_owned(),
                context_id: context_id.to_owned(),
                status: Some(TaskStatus {
                    state: status.state().to_wire() as i32,
                    message: status_message,
                    timestamp: Some(timestamp(status.occurred_at_unix_milliseconds())?),
                }),
                metadata: terminal_reason_metadata(status.terminal_reason()),
            },
        )),
    })
    .map_err(map_projection_error)
}

pub(crate) fn project_artifact_update(
    task_id: &str,
    context_id: &str,
    artifact: StoredA2ATaskArtifact,
) -> Result<InitialA2AStreamResponse, A2AGatewayError> {
    let complete = artifact.complete();
    let artifact = decode_initial_artifact_json(artifact.canonical_bytes())
        .map_err(|_| A2AGatewayError::InvalidTaskProjection)?;
    validate_initial_stream_response(StreamResponse {
        payload: Some(stream_response::Payload::ArtifactUpdate(
            TaskArtifactUpdateEvent {
                task_id: task_id.to_owned(),
                context_id: context_id.to_owned(),
                artifact: Some(artifact.into_wire()),
                append: false,
                last_chunk: complete,
                metadata: None,
            },
        )),
    })
    .map_err(map_projection_error)
}

fn project_task(
    record: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    artifacts: Vec<StoredA2ATaskArtifact>,
    history_length: Option<Option<u32>>,
    include_status_message: bool,
) -> Result<Task, A2AGatewayError> {
    let has_artifacts = !artifacts.is_empty();
    let task_id = record.key().task_id().as_str().to_owned();
    let context_id = record.context_id().as_str().to_owned();
    let wire_messages = messages
        .iter()
        .map(|message| project_message(message, &task_id, &context_id))
        .collect::<Vec<_>>();
    let agent_message = messages
        .iter()
        .zip(&wire_messages)
        .rev()
        .find(|(message, _)| message.role() == A2ATaskMessageRole::Agent)
        .map(|(_, message)| message.clone());
    if history_length.is_some()
        && record.state() == A2ATaskState::Completed
        && !record.content_pruned()
        && agent_message.is_none()
        && !has_artifacts
    {
        return Err(A2AGatewayError::InvalidTaskProjection);
    }
    let status_message = if include_status_message && response_state(record.state()) {
        agent_message
    } else {
        None
    };
    let history = match history_length {
        Some(history_length) => {
            let requested_history = usize::try_from(history_length.unwrap_or(1))
                .map_err(|_| A2AGatewayError::InvalidTaskProjection)?;
            if requested_history == 0 {
                vec![]
            } else {
                wire_messages
                    .into_iter()
                    .rev()
                    .take(requested_history.min(1))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            }
        }
        None => vec![],
    };
    let artifacts = project_artifacts(artifacts)?;
    Ok(Task {
        id: task_id,
        context_id,
        status: Some(TaskStatus {
            state: record.state().to_wire() as i32,
            message: status_message,
            timestamp: Some(timestamp(record.updated_at_unix_milliseconds())?),
        }),
        artifacts,
        history,
        metadata: terminal_reason_metadata(record.terminal_reason()),
    })
}

fn project_artifacts(
    artifacts: Vec<StoredA2ATaskArtifact>,
) -> Result<Vec<KonclaveA2AContracts::wire::Artifact>, A2AGatewayError> {
    if artifacts.len() > MAX_A2A_ARTIFACTS_PER_TASK {
        return Err(A2AGatewayError::InvalidTaskProjection);
    }
    artifacts
        .into_iter()
        .map(|artifact| {
            if !artifact.complete() {
                return Err(A2AGatewayError::InvalidTaskProjection);
            }
            decode_initial_artifact_json(artifact.canonical_bytes())
                .map(|artifact| artifact.into_wire())
                .map_err(map_projection_error)
        })
        .collect()
}

pub(crate) fn send_message_response(
    task: InitialA2ATaskResponse,
) -> KonclaveA2AContracts::wire::SendMessageResponse {
    KonclaveA2AContracts::wire::SendMessageResponse {
        payload: Some(send_message_response::Payload::Task(task.into_wire())),
    }
}

fn project_message(message: &StoredA2ATaskMessage, task_id: &str, context_id: &str) -> Message {
    Message {
        message_id: message.message_id().as_str().to_owned(),
        context_id: context_id.to_owned(),
        task_id: task_id.to_owned(),
        role: match message.role() {
            A2ATaskMessageRole::User => Role::User,
            A2ATaskMessageRole::Agent => Role::Agent,
        } as i32,
        parts: vec![Part {
            content: Some(part::Content::Text(message.text().to_owned())),
            metadata: None,
            filename: String::new(),
            media_type: A2A_TEXT_MEDIA_TYPE.to_owned(),
        }],
        metadata: None,
        extensions: vec![],
        reference_task_ids: vec![],
    }
}

fn timestamp(unix_milliseconds: u64) -> Result<pbjson_types::Timestamp, A2AGatewayError> {
    let seconds = i64::try_from(unix_milliseconds / 1_000)
        .map_err(|_| A2AGatewayError::InvalidTaskProjection)?;
    let nanos = i32::try_from((unix_milliseconds % 1_000) * 1_000_000)
        .map_err(|_| A2AGatewayError::InvalidTaskProjection)?;
    Ok(pbjson_types::Timestamp { seconds, nanos })
}

fn response_state(state: A2ATaskState) -> bool {
    matches!(
        state,
        A2ATaskState::Completed
            | A2ATaskState::Failed
            | A2ATaskState::Canceled
            | A2ATaskState::InputRequired
            | A2ATaskState::Rejected
            | A2ATaskState::AuthRequired
    )
}

fn terminal_reason_metadata(reason: Option<&A2ATerminalReason>) -> Option<pbjson_types::Struct> {
    reason.map(|reason| pbjson_types::Struct {
        fields: HashMap::from([(
            INITIAL_TASK_TERMINAL_REASON_FIELD.to_owned(),
            pbjson_types::Value {
                kind: Some(pbjson_types::value::Kind::StringValue(
                    reason.as_str().to_owned(),
                )),
            },
        )]),
    })
}
