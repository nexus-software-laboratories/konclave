use std::collections::HashMap;

use KonclaveA2AContracts::wire::{
    Message, Part, Role, StreamResponse, Task, TaskState, TaskStatus, TaskStatusUpdateEvent, part,
    stream_response,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, A2AContractError, INITIAL_TASK_TERMINAL_REASON_FIELD,
    InitialA2AStreamResponseKind, decode_initial_stream_response_json,
    decode_initial_stream_response_protobuf, validate_initial_stream_response,
};
use prost::Message as _;

fn timestamp() -> pbjson_types::Timestamp {
    pbjson_types::Timestamp {
        seconds: 1,
        nanos: 0,
    }
}

fn agent_message() -> Message {
    Message {
        message_id: "response-1".to_owned(),
        context_id: "context-1".to_owned(),
        task_id: "00112233445566778899aabbccddeeff".to_owned(),
        role: Role::Agent as i32,
        parts: vec![Part {
            content: Some(part::Content::Text("response".to_owned())),
            metadata: None,
            filename: String::new(),
            media_type: A2A_TEXT_MEDIA_TYPE.to_owned(),
        }],
        metadata: None,
        extensions: vec![],
        reference_task_ids: vec![],
    }
}

fn task(state: TaskState) -> Task {
    Task {
        id: "00112233445566778899aabbccddeeff".to_owned(),
        context_id: "context-1".to_owned(),
        status: Some(TaskStatus {
            state: state as i32,
            message: (state == TaskState::Completed).then(agent_message),
            timestamp: Some(timestamp()),
        }),
        artifacts: vec![],
        history: vec![],
        metadata: terminal_metadata(state),
    }
}

fn status_update(state: TaskState) -> TaskStatusUpdateEvent {
    TaskStatusUpdateEvent {
        task_id: "00112233445566778899aabbccddeeff".to_owned(),
        context_id: "context-1".to_owned(),
        status: Some(TaskStatus {
            state: state as i32,
            message: (state == TaskState::Completed).then(agent_message),
            timestamp: Some(timestamp()),
        }),
        metadata: terminal_metadata(state),
    }
}

fn terminal_metadata(state: TaskState) -> Option<pbjson_types::Struct> {
    matches!(
        state,
        TaskState::Failed | TaskState::Rejected | TaskState::Canceled
    )
    .then(|| pbjson_types::Struct {
        fields: HashMap::from([(
            INITIAL_TASK_TERMINAL_REASON_FIELD.to_owned(),
            pbjson_types::Value {
                kind: Some(pbjson_types::value::Kind::StringValue(
                    "konclave_failure".to_owned(),
                )),
            },
        )]),
    })
}

#[test]
fn task_and_status_update_round_trip_both_encodings() {
    for (response, kind, state) in [
        (
            StreamResponse {
                payload: Some(stream_response::Payload::Task(task(TaskState::Working))),
            },
            InitialA2AStreamResponseKind::Task,
            TaskState::Working,
        ),
        (
            StreamResponse {
                payload: Some(stream_response::Payload::StatusUpdate(status_update(
                    TaskState::Completed,
                ))),
            },
            InitialA2AStreamResponseKind::StatusUpdate,
            TaskState::Completed,
        ),
    ] {
        let protobuf = decode_initial_stream_response_protobuf(&response.encode_to_vec()).unwrap();
        assert_eq!(protobuf.kind(), kind);
        assert!(protobuf.state() == state);
        assert_eq!(protobuf.task_id(), "00112233445566778899aabbccddeeff");
        assert_eq!(protobuf.context_id(), "context-1");
        let json = protobuf.deterministic_json().unwrap();
        let json = decode_initial_stream_response_json(&json).unwrap();
        assert_eq!(json.kind(), kind);
        assert!(json.state() == state);
    }
}

#[test]
fn stream_response_rejects_unsupported_payloads_and_invalid_status() {
    let direct_message = StreamResponse {
        payload: Some(stream_response::Payload::Message(agent_message())),
    };
    assert!(matches!(
        validate_initial_stream_response(direct_message),
        Err(A2AContractError::UnsupportedField {
            field: "stream_response.message"
        })
    ));

    let mut missing_reason = status_update(TaskState::Failed);
    missing_reason.metadata = None;
    assert!(matches!(
        validate_initial_stream_response(StreamResponse {
            payload: Some(stream_response::Payload::StatusUpdate(missing_reason)),
        }),
        Err(A2AContractError::MissingField {
            field: "stream_response.status_update.metadata"
        })
    ));

    let mut wrong_task = status_update(TaskState::Completed);
    wrong_task
        .status
        .as_mut()
        .unwrap()
        .message
        .as_mut()
        .unwrap()
        .task_id = "ffffffffffffffffffffffffffffffff".to_owned();
    assert!(matches!(
        validate_initial_stream_response(StreamResponse {
            payload: Some(stream_response::Payload::StatusUpdate(wrong_task)),
        }),
        Err(A2AContractError::InvalidIdentifier {
            field: "task.message.task_id"
        })
    ));
}
