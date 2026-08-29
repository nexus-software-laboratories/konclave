use KonclaveA2AContracts::wire::{
    AgentInterface, GetTaskRequest, Message, Part, Role, SendMessageConfiguration,
    SendMessageRequest, part,
};
use KonclaveA2AContracts::{
    A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_TEXT_MEDIA_TYPE, A2AContractError,
    InitialA2AInterfaceEnvironment, MAX_A2A_ENCODED_REQUEST_BYTES, MAX_A2A_TEXT_BYTES,
    decode_initial_get_task_json, decode_initial_get_task_protobuf,
    decode_initial_send_message_json, decode_initial_send_message_protobuf,
    validate_initial_agent_interface, validate_initial_send_message_request,
};
use prost::Message as _;

fn send_request() -> SendMessageRequest {
    SendMessageRequest {
        tenant: "tenant-a".to_string(),
        message: Some(Message {
            message_id: "message-1".to_string(),
            context_id: "context-1".to_string(),
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
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_string()],
            task_push_notification_config: None,
            history_length: Some(1),
            return_immediately: true,
        }),
        metadata: None,
    }
}

#[test]
fn send_message_protobuf_and_protojson_narrow_to_one_text_part() {
    let request = send_request();
    let protobuf = request.encode_to_vec();
    let validated = decode_initial_send_message_protobuf(&protobuf, Some("tenant-a")).unwrap();
    assert_eq!(validated.tenant(), Some("tenant-a"));
    assert_eq!(validated.message_id(), "message-1");
    assert_eq!(validated.context_id(), Some("context-1"));
    assert_eq!(validated.text(), "review the contract");
    assert!(validated.return_immediately());
    assert_eq!(validated.history_length(), Some(1));

    let json = serde_json::to_vec(&request).unwrap();
    let json = decode_initial_send_message_json(&json, Some("tenant-a")).unwrap();
    assert_eq!(json.tenant(), validated.tenant());
    assert_eq!(json.message_id(), validated.message_id());
    assert_eq!(json.context_id(), validated.context_id());
    assert_eq!(json.text(), validated.text());
    assert_eq!(json.return_immediately(), validated.return_immediately());
    assert_eq!(json.history_length(), validated.history_length());
}

#[test]
fn send_message_rejects_unsupported_or_ambiguous_fields() {
    let mut cases = Vec::new();

    let mut request = send_request();
    request.message.as_mut().unwrap().role = Role::Agent as i32;
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().task_id = "task-1".to_string();
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().parts.push(Part {
        content: Some(part::Content::Text("second".to_string())),
        metadata: None,
        filename: String::new(),
        media_type: A2A_TEXT_MEDIA_TYPE.to_string(),
    });
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().parts[0].content =
        Some(part::Content::Raw(vec![1, 2, 3].into()));
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().parts[0].content =
        Some(part::Content::Url("https://example.com/file".to_string()));
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().parts[0].content = Some(part::Content::Data(
        serde_json::from_str::<pbjson_types::Value>(r#"{"key":"value"}"#).unwrap(),
    ));
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().metadata =
        Some(serde_json::from_str(r#"{"key":"value"}"#).unwrap());
    cases.push(request);

    let mut request = send_request();
    request.message.as_mut().unwrap().extensions =
        vec!["https://example.com/extensions/required".to_string()];
    cases.push(request);

    let mut request = send_request();
    request
        .configuration
        .as_mut()
        .unwrap()
        .accepted_output_modes = vec!["application/json".to_string()];
    cases.push(request);

    for request in cases {
        assert!(matches!(
            validate_initial_send_message_request(request, Some("tenant-a")),
            Err(A2AContractError::UnsupportedField { .. })
        ));
    }

    let mut request = send_request();
    request.message.as_mut().unwrap().parts[0].content = Some(part::Content::Text(String::new()));
    assert!(matches!(
        validate_initial_send_message_request(request, Some("tenant-a")),
        Err(A2AContractError::InvalidText { .. })
    ));

    let mut request = send_request();
    request.message.as_mut().unwrap().parts[0].content =
        Some(part::Content::Text("x".repeat(MAX_A2A_TEXT_BYTES + 1)));
    assert!(matches!(
        validate_initial_send_message_request(request, Some("tenant-a")),
        Err(A2AContractError::InvalidText { .. })
    ));

    let mut request = send_request();
    request.message.as_mut().unwrap().message_id = "../message".to_string();
    assert!(matches!(
        validate_initial_send_message_request(request, Some("tenant-a")),
        Err(A2AContractError::InvalidIdentifier { .. })
    ));

    assert_eq!(
        validate_initial_send_message_request(send_request(), Some("tenant-b")).err(),
        Some(A2AContractError::TenantMismatch)
    );
}

#[test]
fn request_decoders_enforce_bounds_and_unknown_protojson_fields() {
    assert_eq!(
        decode_initial_send_message_protobuf(
            &vec![0; MAX_A2A_ENCODED_REQUEST_BYTES + 1],
            Some("tenant-a")
        )
        .err(),
        Some(A2AContractError::EncodedMessageTooLarge {
            maximum: MAX_A2A_ENCODED_REQUEST_BYTES,
            actual: MAX_A2A_ENCODED_REQUEST_BYTES + 1,
        })
    );
    assert_eq!(
        decode_initial_send_message_json(
            br#"{"tenant":"tenant-a","message":{},"unknown":true}"#,
            Some("tenant-a")
        )
        .err(),
        Some(A2AContractError::MalformedEncoding)
    );
}

#[test]
fn get_task_protobuf_and_protojson_are_tenant_and_history_bound() {
    let request = GetTaskRequest {
        tenant: "tenant-a".to_string(),
        id: "task-1".to_string(),
        history_length: Some(1),
    };
    let validated =
        decode_initial_get_task_protobuf(&request.encode_to_vec(), Some("tenant-a")).unwrap();
    assert_eq!(validated.tenant(), Some("tenant-a"));
    assert_eq!(validated.task_id(), "task-1");
    assert_eq!(validated.history_length(), Some(1));
    let json =
        decode_initial_get_task_json(&serde_json::to_vec(&request).unwrap(), Some("tenant-a"))
            .unwrap();
    assert_eq!(json.tenant(), validated.tenant());
    assert_eq!(json.task_id(), validated.task_id());
    assert_eq!(json.history_length(), validated.history_length());

    let unsupported = GetTaskRequest {
        history_length: Some(2),
        ..request
    };
    assert!(matches!(
        decode_initial_get_task_protobuf(&unsupported.encode_to_vec(), Some("tenant-a")),
        Err(A2AContractError::OutOfRange { .. })
    ));
}

#[test]
fn agent_interface_negotiation_requires_http_json_protocol_one() {
    let production = AgentInterface {
        url: "https://agent.example.com/a2a/v1".to_string(),
        protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
        tenant: "tenant-a".to_string(),
        protocol_version: A2A_PROTOCOL_VERSION.to_string(),
    };
    let validated =
        validate_initial_agent_interface(production, InitialA2AInterfaceEnvironment::Production)
            .unwrap();
    assert_eq!(validated.url(), "https://agent.example.com/a2a/v1");
    assert_eq!(validated.tenant(), Some("tenant-a"));

    let loopback = AgentInterface {
        url: "http://127.0.0.1:8080/a2a/v1".to_string(),
        protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
        tenant: String::new(),
        protocol_version: A2A_PROTOCOL_VERSION.to_string(),
    };
    assert!(
        validate_initial_agent_interface(
            loopback.clone(),
            InitialA2AInterfaceEnvironment::LoopbackDevelopment
        )
        .is_ok()
    );
    assert!(matches!(
        validate_initial_agent_interface(loopback, InitialA2AInterfaceEnvironment::Production),
        Err(A2AContractError::InvalidInterfaceUrl)
    ));

    for interface in [
        AgentInterface {
            protocol_version: "1.1".to_string(),
            ..AgentInterface {
                url: "https://agent.example.com/a2a/v1".to_string(),
                protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
                tenant: String::new(),
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            }
        },
        AgentInterface {
            protocol_binding: "GRPC".to_string(),
            ..AgentInterface {
                url: "https://agent.example.com/a2a/v1".to_string(),
                protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
                tenant: String::new(),
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            }
        },
        AgentInterface {
            url: "http://agent.example.com/a2a/v1".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        },
        AgentInterface {
            url: "https://user@agent.example.com/a2a/v1".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        },
        AgentInterface {
            url: "https://agent.example.com/a2a/v1?target=other".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        },
        AgentInterface {
            url: r"https://agent.trusted.example\@attacker.example/a2a/v1".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        },
        AgentInterface {
            url: "https://agent.example.com/\tpath".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        },
        AgentInterface {
            url: "https://agent.example.com:443/a2a/v1".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: String::new(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        },
    ] {
        assert!(
            validate_initial_agent_interface(interface, InitialA2AInterfaceEnvironment::Production)
                .is_err()
        );
    }
}
