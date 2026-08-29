use KonclaveA2AContracts::wire::{AgentCard, GetTaskRequest, SendMessageRequest};
use KonclaveA2AContracts::{
    A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, InitialA2AInterfaceEnvironment,
    decode_initial_get_task_protobuf, decode_initial_send_message_protobuf,
    validate_initial_agent_interface,
};
use prost::Message as _;

const SEND_MESSAGE: &[u8] = include_bytes!("../../../fixtures/a2a/v1.0.1/send-message-request.bin");
const GET_TASK: &[u8] = include_bytes!("../../../fixtures/a2a/v1.0.1/get-task-request.bin");
const AGENT_CARD: &[u8] = include_bytes!("../../../fixtures/a2a/v1.0.1/agent-card.bin");

#[test]
fn immutable_a2a_fixtures_round_trip_exactly() {
    let send = SendMessageRequest::decode(SEND_MESSAGE).unwrap();
    assert_eq!(send.encode_to_vec(), SEND_MESSAGE);
    assert_eq!(
        decode_initial_send_message_protobuf(SEND_MESSAGE, Some("tenant-a"))
            .unwrap()
            .message_id(),
        "message-1"
    );

    let get = GetTaskRequest::decode(GET_TASK).unwrap();
    assert_eq!(get.encode_to_vec(), GET_TASK);
    assert_eq!(
        decode_initial_get_task_protobuf(GET_TASK, Some("tenant-a"))
            .unwrap()
            .task_id(),
        "task-1"
    );

    let card = AgentCard::decode(AGENT_CARD).unwrap();
    assert_eq!(card.encode_to_vec(), AGENT_CARD);
    assert_eq!(card.supported_interfaces.len(), 1);
    let interface = validate_initial_agent_interface(
        card.supported_interfaces.into_iter().next().unwrap(),
        InitialA2AInterfaceEnvironment::Production,
    )
    .unwrap();
    assert_eq!(interface.tenant(), Some("tenant-a"));
    assert_eq!(
        card.default_input_modes,
        vec![KonclaveA2AContracts::A2A_TEXT_MEDIA_TYPE.to_string()]
    );
    assert_eq!(interface.url(), "https://agent.example.com/a2a/v1");
    assert_eq!(A2A_HTTP_JSON_BINDING, "HTTP+JSON");
    assert_eq!(A2A_PROTOCOL_VERSION, "1.0");
}
