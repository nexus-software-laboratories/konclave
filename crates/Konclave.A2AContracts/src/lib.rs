#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod initial_profile;

pub use error::A2AContractError;
pub use initial_profile::{
    A2A_HTTP_JSON_BINDING, A2A_PROTOCOL_VERSION, A2A_TEXT_MEDIA_TYPE,
    InitialA2AInterfaceEnvironment, InitialA2AValidatedInterface, InitialGetTaskRequest,
    InitialSendMessageRequest, MAX_A2A_ENCODED_REQUEST_BYTES, MAX_A2A_IDENTIFIER_BYTES,
    MAX_A2A_TEXT_BYTES, decode_initial_get_task_json, decode_initial_get_task_protobuf,
    decode_initial_send_message_json, decode_initial_send_message_protobuf,
    validate_initial_agent_interface, validate_initial_get_task_request,
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
