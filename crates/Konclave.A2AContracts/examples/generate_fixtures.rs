use std::fs;
use std::path::{Path, PathBuf};

use KonclaveA2AContracts::wire::{
    AgentCapabilities, AgentCard, AgentInterface, AgentSkill, GetTaskRequest, Message, Part, Role,
    SendMessageConfiguration, SendMessageRequest, part,
};
use KonclaveA2AContracts::{A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_TEXT_MEDIA_TYPE};
use prost::Message as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/a2a/v1.0.1");
    fs::create_dir_all(&output)?;
    write(
        &output,
        "send-message-request.bin",
        send_message_request().encode_to_vec(),
    )?;
    write(
        &output,
        "get-task-request.bin",
        GetTaskRequest {
            tenant: "tenant-a".to_string(),
            id: "task-1".to_string(),
            history_length: Some(1),
        }
        .encode_to_vec(),
    )?;
    write(&output, "agent-card.bin", agent_card().encode_to_vec())?;
    Ok(())
}

fn send_message_request() -> SendMessageRequest {
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

fn agent_card() -> AgentCard {
    AgentCard {
        name: "Konclave gateway".to_string(),
        description: "Text-only A2A gateway backed by one configured Konclave target.".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://agent.example.com/a2a/v1".to_string(),
            protocol_binding: A2A_HTTP_JSON_BINDING.to_string(),
            tenant: "tenant-a".to_string(),
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "0.1.0".to_string(),
        documentation_url: None,
        capabilities: Some(AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extensions: vec![],
            extended_agent_card: Some(false),
        }),
        security_schemes: Default::default(),
        security_requirements: vec![],
        default_input_modes: vec![A2A_TEXT_MEDIA_TYPE.to_string()],
        default_output_modes: vec![A2A_TEXT_MEDIA_TYPE.to_string()],
        skills: vec![AgentSkill {
            id: "directed-request".to_string(),
            name: "Directed request".to_string(),
            description: "Send one text request and receive at most one terminal response."
                .to_string(),
            tags: vec!["text".to_string(), "request-response".to_string()],
            examples: vec![],
            input_modes: vec![],
            output_modes: vec![],
            security_requirements: vec![],
        }],
        signatures: vec![],
        icon_url: None,
    }
}

fn write(root: &Path, name: &str, bytes: Vec<u8>) -> std::io::Result<()> {
    fs::write(root.join(name), bytes)
}
