use crate::A2AContractError;
use crate::initial_profile::{
    MAX_A2A_LIST_PAGE_SIZE, decode_json_bounded, require_encoded_bound, validate_page_token,
};
use crate::task_response::{MAX_A2A_ENCODED_RESPONSE_BYTES, validate_initial_task};
use crate::wire::ListTasksResponse;
use prost::Message as _;

/// Validated `ListTasks` response for the initial Konclave gateway profile.
pub struct InitialA2ATaskListResponse {
    wire: ListTasksResponse,
}

impl InitialA2ATaskListResponse {
    /// Returns the validated generated wire DTO.
    #[must_use]
    pub const fn as_wire(&self) -> &ListTasksResponse {
        &self.wire
    }

    /// Returns the generated wire DTO and consumes the validated wrapper.
    #[must_use]
    pub fn into_wire(self) -> ListTasksResponse {
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

/// Decodes and validates one bounded protobuf `ListTasks` response.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, or unsupported task-list
/// content.
pub fn decode_initial_list_tasks_response_protobuf(
    bytes: &[u8],
) -> Result<InitialA2ATaskListResponse, A2AContractError> {
    require_encoded_bound(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    let response =
        ListTasksResponse::decode(bytes).map_err(|_| A2AContractError::MalformedEncoding)?;
    validate_initial_list_tasks_response(response)
}

/// Decodes and validates one bounded ProtoJSON `ListTasks` response.
///
/// # Errors
///
/// Returns a stable contract error for malformed, oversized, or unsupported task-list
/// content.
pub fn decode_initial_list_tasks_response_json(
    bytes: &[u8],
) -> Result<InitialA2ATaskListResponse, A2AContractError> {
    let response = decode_json_bounded(bytes, MAX_A2A_ENCODED_RESPONSE_BYTES)?;
    validate_initial_list_tasks_response(response)
}

/// Narrows one generated `ListTasksResponse` DTO to the initial profile.
///
/// # Errors
///
/// Returns a stable contract error for invalid pagination metadata or any task that
/// includes message bodies, artifacts, or unsupported metadata.
pub fn validate_initial_list_tasks_response(
    response: ListTasksResponse,
) -> Result<InitialA2ATaskListResponse, A2AContractError> {
    if response.page_size <= 0
        || response.page_size
            > i32::try_from(MAX_A2A_LIST_PAGE_SIZE).expect("page size bound fits in i32")
    {
        return Err(A2AContractError::OutOfRange {
            field: "list_tasks_response.page_size",
        });
    }
    if response.total_size < 0 {
        return Err(A2AContractError::OutOfRange {
            field: "list_tasks_response.total_size",
        });
    }
    if response.tasks.len()
        > usize::try_from(response.page_size).map_err(|_| A2AContractError::OutOfRange {
            field: "list_tasks_response.page_size",
        })?
    {
        return Err(A2AContractError::OutOfRange {
            field: "list_tasks_response.tasks",
        });
    }
    validate_page_token(
        response.next_page_token.clone(),
        "list_tasks_response.next_page_token",
    )?;
    for task in &response.tasks {
        let task = validate_initial_task(task.clone())?;
        if task
            .as_wire()
            .status
            .as_ref()
            .and_then(|status| status.message.as_ref())
            .is_some()
            || !task.as_wire().history.is_empty()
        {
            return Err(A2AContractError::UnsupportedField {
                field: "list_tasks_response.tasks",
            });
        }
    }
    Ok(InitialA2ATaskListResponse { wire: response })
}
