use KonclaveA2AContracts::wire::{
    GetTaskRequest, Message, Part, Role, SendMessageRequest, TaskState, part,
};
use KonclaveA2AContracts::{
    A2A_TEXT_MEDIA_TYPE, validate_initial_get_task_request, validate_initial_send_message_request,
};
use KonclaveA2ADomain::{
    A2AAgentId, A2AAgentRoute, A2AArtifactId, A2AContextId, A2ADomainError, A2AMessageId,
    A2APartIndex, A2ATaskId, A2ATaskState, A2ATenantId, map_initial_get_task,
    map_initial_send_message,
};
use KonclaveDomainCore::{ConversationId, DeviceId};

fn route() -> A2AAgentRoute {
    route_for("agent-a", "context-a", "tenant-a")
}

fn route_for(agent: &str, context: &str, tenant: &str) -> A2AAgentRoute {
    route_bound(agent, context, tenant, 4, 5)
}

fn route_bound(
    agent: &str,
    context: &str,
    tenant: &str,
    conversation: u8,
    target: u8,
) -> A2AAgentRoute {
    A2AAgentRoute::new(
        A2AAgentId::parse(agent).unwrap(),
        A2AContextId::parse(context).unwrap(),
        Some(A2ATenantId::parse(tenant).unwrap()),
        ConversationId::from_bytes([conversation; ConversationId::LENGTH]),
        DeviceId::from_bytes([target; DeviceId::LENGTH]),
    )
}

fn send_request(
    tenant: &str,
    context: &str,
    message_id: &str,
) -> KonclaveA2AContracts::InitialSendMessageRequest {
    validate_initial_send_message_request(
        SendMessageRequest {
            tenant: tenant.to_string(),
            message: Some(Message {
                message_id: message_id.to_string(),
                context_id: context.to_string(),
                task_id: String::new(),
                role: Role::User as i32,
                parts: vec![Part {
                    content: Some(part::Content::Text("review the contract".to_string())),
                    metadata: None,
                    filename: String::new(),
                    media_type: A2A_TEXT_MEDIA_TYPE.to_string(),
                }],
                metadata: None,
                extensions: vec![],
                reference_task_ids: vec![],
            }),
            configuration: None,
            metadata: None,
        },
        Some(tenant),
    )
    .unwrap()
}

#[test]
fn identifiers_are_typed_and_share_the_contract_bound() {
    assert_eq!(A2AAgentId::parse("agent-a").unwrap().as_str(), "agent-a");
    assert_eq!(
        A2AContextId::parse("context-a").unwrap().as_str(),
        "context-a"
    );
    assert_eq!(A2ATaskId::parse("task-a").unwrap().as_str(), "task-a");
    assert_eq!(
        A2AMessageId::parse("message-a").unwrap().as_str(),
        "message-a"
    );
    assert_eq!(
        A2AArtifactId::parse("artifact-a").unwrap().as_str(),
        "artifact-a"
    );
    assert_eq!(A2ATenantId::parse("tenant-a").unwrap().as_str(), "tenant-a");
    assert_eq!(A2APartIndex::from_position(0).unwrap().position(), 0);
    assert_eq!(
        A2APartIndex::from_position(usize::from(u16::MAX) + 1).err(),
        Some(A2ADomainError::PartIndexOutOfRange)
    );
    assert_eq!(
        A2ATaskId::parse("../task").err(),
        Some(A2ADomainError::InvalidIdentifier { kind: "task" })
    );
}

#[test]
fn send_mapping_is_deterministic_and_route_scoped() {
    let route = route();
    let mapping =
        map_initial_send_message(&route, send_request("tenant-a", "context-a", "message-a"))
            .unwrap();
    assert_eq!(mapping.agent_id().as_str(), "agent-a");
    assert_eq!(mapping.context_id().as_str(), "context-a");
    assert_eq!(mapping.tenant().map(A2ATenantId::as_str), Some("tenant-a"));
    assert_eq!(mapping.source_message_id().as_str(), "message-a");
    assert_eq!(
        mapping.task_id().as_str(),
        "0ce3c766e8885b47bf4aceff1926e810"
    );
    assert_eq!(
        mapping.request_message_id().as_bytes(),
        &[
            0x0c, 0xe3, 0xc7, 0x66, 0xe8, 0x88, 0x5b, 0x47, 0xbf, 0x4a, 0xce, 0xff, 0x19, 0x26,
            0xe8, 0x10,
        ]
    );
    assert_eq!(
        mapping.conversation_id(),
        ConversationId::from_bytes([4; ConversationId::LENGTH])
    );
    assert_eq!(
        mapping.target_device_id(),
        DeviceId::from_bytes([5; DeviceId::LENGTH])
    );
    assert_eq!(mapping.text(), "review the contract");
    assert_eq!(mapping.part_index().position(), 0);
    assert!(!mapping.return_immediately());
    assert_eq!(mapping.history_length(), None);

    let retry =
        map_initial_send_message(&route, send_request("tenant-a", "context-a", "message-a"))
            .unwrap();
    assert_eq!(retry.task_id().as_str(), mapping.task_id().as_str());
    assert_eq!(retry.request_message_id(), mapping.request_message_id());

    let other =
        map_initial_send_message(&route, send_request("tenant-a", "context-a", "message-b"))
            .unwrap();
    assert_ne!(other.task_id().as_str(), mapping.task_id().as_str());
    assert_ne!(other.request_message_id(), mapping.request_message_id());

    let other_tenant = map_initial_send_message(
        &route_for("agent-a", "context-a", "tenant-b"),
        send_request("tenant-b", "context-a", "message-a"),
    )
    .unwrap();
    assert_ne!(other_tenant.task_id().as_str(), mapping.task_id().as_str());

    let other_agent = map_initial_send_message(
        &route_for("agent-b", "context-a", "tenant-a"),
        send_request("tenant-a", "context-a", "message-a"),
    )
    .unwrap();
    assert_ne!(other_agent.task_id().as_str(), mapping.task_id().as_str());

    let omitted_context =
        map_initial_send_message(&route, send_request("tenant-a", "", "message-c")).unwrap();
    assert_eq!(omitted_context.context_id().as_str(), "context-a");

    for changed_route in [
        route_bound("agent-a", "context-a", "tenant-a", 6, 5),
        route_bound("agent-a", "context-a", "tenant-a", 4, 6),
    ] {
        let changed = map_initial_send_message(
            &changed_route,
            send_request("tenant-a", "context-a", "message-a"),
        )
        .unwrap();
        assert_ne!(changed.task_id().as_str(), mapping.task_id().as_str());
    }
}

#[test]
fn send_mapping_rejects_caller_route_substitution() {
    assert_eq!(
        map_initial_send_message(&route(), send_request("tenant-a", "context-b", "message-a"))
            .err(),
        Some(A2ADomainError::ContextMismatch)
    );
    assert_eq!(
        map_initial_send_message(&route(), send_request("tenant-b", "context-a", "message-a"))
            .err(),
        Some(A2ADomainError::TenantMismatch)
    );
}

#[test]
fn get_task_mapping_remains_agent_and_tenant_scoped() {
    let request = validate_initial_get_task_request(
        GetTaskRequest {
            tenant: "tenant-a".to_string(),
            id: "task-a".to_string(),
            history_length: Some(1),
        },
        Some("tenant-a"),
    )
    .unwrap();
    let lookup = map_initial_get_task(&route(), request).unwrap();
    assert_eq!(lookup.agent_id().as_str(), "agent-a");
    assert_eq!(lookup.task_id().as_str(), "task-a");
    assert_eq!(lookup.tenant().map(A2ATenantId::as_str), Some("tenant-a"));
    assert_eq!(lookup.history_length(), Some(1));
}

#[test]
fn task_state_is_distinct_and_round_trips_the_a2a_wire_enum() {
    for state in [
        A2ATaskState::Submitted,
        A2ATaskState::Working,
        A2ATaskState::Completed,
        A2ATaskState::Failed,
        A2ATaskState::Canceled,
        A2ATaskState::InputRequired,
        A2ATaskState::Rejected,
        A2ATaskState::AuthRequired,
    ] {
        assert_eq!(
            A2ATaskState::from_wire(state.to_wire() as i32).unwrap(),
            state
        );
    }
    assert_eq!(
        A2ATaskState::from_wire(TaskState::Unspecified as i32),
        Err(A2ADomainError::UnsupportedTaskState)
    );
    assert_eq!(
        A2ATaskState::from_wire(i32::MAX),
        Err(A2ADomainError::UnsupportedTaskState)
    );
}
