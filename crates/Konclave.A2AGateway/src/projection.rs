use KonclaveA2AContracts::wire::{
    Message, Part, Role, Task, TaskStatus, part, send_message_response,
};
use KonclaveA2AContracts::{A2A_TEXT_MEDIA_TYPE, InitialA2ATaskResponse, validate_initial_task};
use KonclaveA2ADomain::A2ATaskState;
use KonclaveA2ATaskStore::{A2ATaskMessageRole, A2ATaskRecord, StoredA2ATaskMessage};

use crate::A2AGatewayError;

pub(crate) fn project_task(
    record: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    history_length: Option<u32>,
) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
    let task_id = record.key().task_id().as_str().to_owned();
    let context_id = record.context_id().as_str().to_owned();
    let wire_messages = messages
        .iter()
        .map(|message| project_message(message, &task_id, &context_id))
        .collect::<Vec<_>>();
    let status_message = if response_state(record.state()) {
        messages
            .iter()
            .zip(&wire_messages)
            .rev()
            .find(|(message, _)| message.role() == A2ATaskMessageRole::Agent)
            .map(|(_, message)| message.clone())
    } else {
        None
    };
    let requested_history = usize::try_from(history_length.unwrap_or(1))
        .map_err(|_| A2AGatewayError::InvalidTaskProjection)?;
    let history = if requested_history == 0 {
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
    };
    let task = Task {
        id: task_id,
        context_id,
        status: Some(TaskStatus {
            state: record.state().to_wire() as i32,
            message: status_message,
            timestamp: Some(timestamp(record.updated_at_unix_milliseconds())?),
        }),
        artifacts: vec![],
        history,
        metadata: None,
    };
    validate_initial_task(task).map_err(|_| A2AGatewayError::InvalidTaskProjection)
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
