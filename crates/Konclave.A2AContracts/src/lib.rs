#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod agent_card;
mod error;
mod identifier;
mod initial_profile;

pub use agent_card::{
    InitialA2AAgentCard, InitialA2AAgentSecurity, InitialA2AAgentSecurityKind,
    InitialA2AAgentSkill, MAX_A2A_AGENT_CARD_INTERFACES, MAX_A2A_AGENT_CARD_SKILLS,
    MAX_A2A_AGENT_DESCRIPTION_BYTES, MAX_A2A_AGENT_NAME_BYTES, MAX_A2A_AGENT_SKILL_TAG_BYTES,
    MAX_A2A_AGENT_SKILL_TAGS, MAX_A2A_AGENT_VERSION_BYTES, MAX_A2A_BEARER_FORMAT_BYTES,
    MAX_A2A_ENCODED_AGENT_CARD_BYTES, decode_initial_agent_card_json,
    decode_initial_agent_card_protobuf, validate_initial_agent_card,
};
pub use error::A2AContractError;
pub use identifier::{A2AIdentifier, MAX_A2A_IDENTIFIER_BYTES};
pub use initial_profile::{
    A2A_EXTENDED_AGENT_CARD_PATH, A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_TEXT_MEDIA_TYPE,
    A2A_WELL_KNOWN_AGENT_CARD_PATH, InitialA2AInterfaceEnvironment, InitialA2AValidatedInterface,
    InitialGetExtendedAgentCardRequest, InitialGetTaskRequest, InitialSendMessageRequest,
    MAX_A2A_ENCODED_REQUEST_BYTES, MAX_A2A_TEXT_BYTES, decode_initial_get_extended_agent_card_json,
    decode_initial_get_extended_agent_card_protobuf, decode_initial_get_task_json,
    decode_initial_get_task_protobuf, decode_initial_send_message_json,
    decode_initial_send_message_protobuf, validate_initial_agent_interface,
    validate_initial_get_extended_agent_card_request, validate_initial_get_task_request,
    validate_initial_send_message_request,
};

/// Generated A2A v1 Protocol Buffer and ProtoJSON DTOs.
///
/// These values are untrusted wire objects. Callers must narrow exposed operations
/// through the initial-profile validation functions before selecting a Konclave
/// target, allocating durable state, or performing a side effect.
pub mod wire {
    // pbjson-build 0.9 emits `&FIELDS` in formatter calls; keep the generated-code
    // compatibility suppression inside this module rather than weakening crate lints.
    #![allow(clippy::useless_borrows_in_formatting)]

    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.serde.rs"));
}
