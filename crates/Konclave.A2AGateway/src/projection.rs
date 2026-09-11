use std::collections::HashMap;

use KonclaveA2AContracts::wire::{
    ListTasksResponse, Message, Part, Role, Task, TaskStatus, part, send_message_response,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, INITIAL_TASK_TERMINAL_REASON_FIELD, InitialA2ATaskListResponse,
    InitialA2ATaskResponse, validate_initial_list_tasks_response, validate_initial_task,
};
use KonclaveA2ADomain::A2ATaskState;
use KonclaveA2ATaskStore::{
    A2ATaskMessageRole, A2ATaskRecord, A2ATerminalReason, StoredA2ATaskMessage,
};

use crate::A2AGatewayError;

pub(crate) fn project_get_task(
    record: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    history_length: Option<u32>,
) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
    let task = project_task(record, messages, Some(history_length), true)?;
    validate_initial_task(task).map_err(|_| A2AGatewayError::InvalidTaskProjection)
}

pub(crate) fn project_list_tasks(
    records: Vec<A2ATaskRecord>,
    next_page_token: Option<String>,
    page_size: usize,
    total_size: usize,
) -> Result<InitialA2ATaskListResponse, A2AGatewayError> {
    let tasks = records
        .into_iter()
        .map(|record| project_task(record, Vec::new(), None, false))
        .collect::<Result<Vec<_>, _>>()?;
    let response = ListTasksResponse {
        tasks,
        next_page_token: next_page_token.unwrap_or_default(),
        page_size: i32::try_from(page_size).map_err(|_| A2AGatewayError::InvalidTaskProjection)?,
        total_size: i32::try_from(total_size)
            .map_err(|_| A2AGatewayError::InvalidTaskProjection)?,
    };
    validate_initial_list_tasks_response(response)
        .map_err(|_| A2AGatewayError::InvalidTaskProjection)
}

fn project_task(
    record: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    history_length: Option<Option<u32>>,
    include_status_message: bool,
) -> Result<Task, A2AGatewayError> {
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
    Ok(Task {
        id: task_id,
        context_id,
        status: Some(TaskStatus {
            state: record.state().to_wire() as i32,
            message: status_message,
            timestamp: Some(timestamp(record.updated_at_unix_milliseconds())?),
        }),
        artifacts: vec![],
        history,
        metadata: terminal_reason_metadata(record.terminal_reason()),
    })
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
