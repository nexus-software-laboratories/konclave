use KonclaveA2AContracts::wire::{
    Artifact, ListTasksResponse, Message, Part, Role, SendMessageResponse, Task, TaskState,
    TaskStatus, part, send_message_response,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, A2AContractError, INITIAL_TASK_TERMINAL_REASON_FIELD,
    MAX_A2A_ENCODED_RESPONSE_BYTES, decode_initial_list_tasks_response_json,
    decode_initial_send_message_response_json, decode_initial_send_message_response_protobuf,
    decode_initial_task_json, decode_initial_task_protobuf, validate_initial_list_tasks_response,
    validate_initial_task,
};
use prost::Message as _;

fn message(id: &str, role: Role, text: &str) -> Message {
    Message {
        message_id: id.to_owned(),
        context_id: "context-1".to_owned(),
        task_id: "task-1".to_owned(),
        role: role as i32,
        parts: vec![Part {
            content: Some(part::Content::Text(text.to_owned())),
            metadata: None,
            filename: String::new(),
            media_type: A2A_TEXT_MEDIA_TYPE.to_owned(),
        }],
        metadata: None,
        extensions: vec![],
        reference_task_ids: vec![],
    }
}

fn task() -> Task {
    Task {
        id: "task-1".to_owned(),
        context_id: "context-1".to_owned(),
        status: Some(TaskStatus {
            state: TaskState::Completed as i32,
            message: Some(message("response-1", Role::Agent, "done")),
            timestamp: Some(pbjson_types::Timestamp {
                seconds: 1_787_875_200,
                nanos: 123_000_000,
            }),
        }),
        artifacts: vec![],
        history: vec![message("response-1", Role::Agent, "done")],
        metadata: None,
    }
}

#[test]
fn task_and_send_response_round_trip_in_both_encodings() {
    let task = task();
    let protobuf = decode_initial_task_protobuf(&task.encode_to_vec()).unwrap();
    assert_eq!(protobuf.task_id(), "task-1");
    assert_eq!(protobuf.context_id(), "context-1");
    assert!(protobuf.state() == TaskState::Completed);

    let json = protobuf.deterministic_json().unwrap();
    let from_json = decode_initial_task_json(&json).unwrap();
    assert_eq!(from_json.task_id(), protobuf.task_id());
    assert!(from_json.state() == protobuf.state());

    let response = SendMessageResponse {
        payload: Some(send_message_response::Payload::Task(task)),
    };
    assert!(
        decode_initial_send_message_response_protobuf(&response.encode_to_vec())
            .unwrap()
            .state()
            == TaskState::Completed
    );
    assert_eq!(
        decode_initial_send_message_response_json(&serde_json::to_vec(&response).unwrap())
            .unwrap()
            .task_id(),
        "task-1"
    );
}

#[test]
fn task_response_rejects_unsupported_or_inconsistent_content() {
    let mut missing_status = task();
    missing_status.status = None;
    assert!(matches!(
        validate_initial_task(missing_status),
        Err(A2AContractError::MissingField {
            field: "task.status"
        })
    ));

    let mut unspecified = task();
    unspecified.status.as_mut().unwrap().state = TaskState::Unspecified as i32;
    assert!(validate_initial_task(unspecified).is_err());

    let mut invalid_timestamp = task();
    invalid_timestamp
        .status
        .as_mut()
        .unwrap()
        .timestamp
        .as_mut()
        .unwrap()
        .nanos = 1_000_000_000;
    assert!(validate_initial_task(invalid_timestamp).is_err());

    let mut wrong_task = task();
    wrong_task.history[0].task_id = "other".to_owned();
    assert!(validate_initial_task(wrong_task).is_err());

    let mut too_much_history = task();
    too_much_history
        .history
        .push(message("request-1", Role::User, "request"));
    assert!(matches!(
        validate_initial_task(too_much_history),
        Err(A2AContractError::OutOfRange {
            field: "task.history"
        })
    ));

    let mut artifact = task();
    artifact.artifacts.push(Artifact {
        artifact_id: "artifact-1".to_owned(),
        name: String::new(),
        description: String::new(),
        parts: vec![],
        metadata: None,
        extensions: vec![],
    });
    assert!(validate_initial_task(artifact).is_err());
}

#[test]
fn task_response_rejects_direct_message_duplicate_json_and_oversize() {
    let direct = SendMessageResponse {
        payload: Some(send_message_response::Payload::Message(message(
            "response-1",
            Role::Agent,
            "done",
        ))),
    };
    assert!(matches!(
        decode_initial_send_message_response_json(&serde_json::to_vec(&direct).unwrap()),
        Err(A2AContractError::UnsupportedField {
            field: "send_message_response.message"
        })
    ));

    let json = serde_json::to_string(&task()).unwrap();
    let duplicate_id = json.replacen('{', r#"{"id":"shadow","#, 1);
    assert_eq!(
        decode_initial_task_json(duplicate_id.as_bytes()).err(),
        Some(A2AContractError::MalformedEncoding)
    );
    assert_eq!(
        decode_initial_task_json(&vec![b' '; MAX_A2A_ENCODED_RESPONSE_BYTES + 1]).err(),
        Some(A2AContractError::EncodedMessageTooLarge {
            maximum: MAX_A2A_ENCODED_RESPONSE_BYTES,
            actual: MAX_A2A_ENCODED_RESPONSE_BYTES + 1,
        })
    );
}

#[test]
fn terminal_reason_metadata_and_list_responses_are_strict() {
    let mut failed = task();
    failed.status.as_mut().unwrap().state = TaskState::Failed as i32;
    failed.status.as_mut().unwrap().message = None;
    failed.history.clear();
    failed.metadata = Some(
        serde_json::from_str(&format!(
            r#"{{"{INITIAL_TASK_TERMINAL_REASON_FIELD}":"konclave_request_rejected"}}"#
        ))
        .unwrap(),
    );
    assert!(validate_initial_task(failed.clone()).is_ok());

    let mut missing_reason = failed.clone();
    missing_reason.metadata = None;
    assert!(matches!(
        validate_initial_task(missing_reason),
        Err(A2AContractError::MissingField {
            field: "task.metadata"
        })
    ));

    let list = ListTasksResponse {
        tasks: vec![failed],
        next_page_token: "v1.100.00112233445566778899aabbccddeeff".to_owned(),
        page_size: 50,
        total_size: 1,
    };
    assert_eq!(
        decode_initial_list_tasks_response_json(&serde_json::to_vec(&list).unwrap())
            .unwrap()
            .as_wire()
            .total_size,
        1
    );

    let mut invalid_task = task();
    invalid_task.history.clear();
    let list = ListTasksResponse {
        tasks: vec![invalid_task],
        next_page_token: String::new(),
        page_size: 50,
        total_size: 1,
    };
    assert!(matches!(
        validate_initial_list_tasks_response(list),
        Err(A2AContractError::UnsupportedField {
            field: "list_tasks_response.tasks"
        })
    ));
}
