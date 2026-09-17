use KonclaveDomainCore::{
    ApplicationContent, ApplicationMessage, MAX_APPLICATION_MESSAGE_BYTES,
    MAX_COLLABORATION_POLICY_BUNDLE_BYTES, MAX_REPEAT_PAIRING_CAPABILITY_BYTES,
    RepeatPairingOperationId, RepeatPairingRequest, RepeatPairingResponse,
};

use crate::KonclaveProtocolError;
use crate::v1::collaboration_policy::{
    proposal_from_wire, proposal_to_wire, response_from_wire, response_to_wire,
    revocation_from_wire, revocation_to_wire,
};
use crate::v1::common::{
    decode_bounded, device_id_from_wire, device_id_to_wire, encode_bounded, message_id_from_wire,
    message_id_to_wire, require_nested_bytes_field_limit, version_from_wire, version_to_wire,
};
use crate::wire::v1 as wire;

const CONTRACT: &str = "ApplicationMessage";

/// Encodes a validated application message as protocol v1 bytes.
///
/// # Errors
///
/// Returns [`KonclaveProtocolError::EncodedMessageTooLarge`] when the encoded
/// message exceeds the protocol v1 application limit.
pub fn encode_application_message(
    value: &ApplicationMessage,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    let content = match value.content() {
        ApplicationContent::Text(body) => {
            wire::application_message::Content::Text(wire::TextContent { body: body.clone() })
        }
        ApplicationContent::DirectedRequest(request) => {
            wire::application_message::Content::DirectedRequest(wire::DirectedRequestContent {
                target_device_id: Some(device_id_to_wire(request.target_device_id())),
                body: request.body().to_owned(),
            })
        }
        ApplicationContent::RepeatPairingRequest(request) => {
            wire::application_message::Content::RepeatPairingRequest(
                wire::RepeatPairingRequestContent {
                    operation_id: Some(repeat_pairing_operation_id_to_wire(request.operation_id())),
                    target_device_id: Some(device_id_to_wire(request.target_device_id())),
                    new_conversation_id: Some(crate::v1::common::conversation_id_to_wire(
                        request.new_conversation_id(),
                    )),
                    expires_at_unix_seconds: request.expires_at_unix_seconds(),
                },
            )
        }
        ApplicationContent::RepeatPairingResponse(response) => {
            wire::application_message::Content::RepeatPairingResponse(
                wire::RepeatPairingResponseContent {
                    operation_id: Some(repeat_pairing_operation_id_to_wire(
                        response.operation_id(),
                    )),
                    requester_device_id: Some(device_id_to_wire(response.requester_device_id())),
                    new_conversation_id: Some(crate::v1::common::conversation_id_to_wire(
                        response.new_conversation_id(),
                    )),
                    capability: response.capability().to_owned(),
                },
            )
        }
        ApplicationContent::CollaborationPolicyProposal(proposal) => {
            wire::application_message::Content::CollaborationPolicyProposal(proposal_to_wire(
                proposal,
            ))
        }
        ApplicationContent::CollaborationPolicyResponse(response) => {
            wire::application_message::Content::CollaborationPolicyResponse(response_to_wire(
                response,
            ))
        }
        ApplicationContent::CollaborationPolicyRevocation(revocation) => {
            wire::application_message::Content::CollaborationPolicyRevocation(revocation_to_wire(
                revocation,
            ))
        }
    };
    let wire = wire::ApplicationMessage {
        version: Some(version_to_wire(value.version())),
        message_id: Some(message_id_to_wire(value.message_id())),
        sender_counter: value.sender_counter(),
        sent_at_unix_milliseconds: value.sent_at_unix_milliseconds(),
        reply_to: value.reply_to().map(message_id_to_wire),
        content: Some(content),
    };
    encode_bounded(&wire, MAX_APPLICATION_MESSAGE_BYTES, CONTRACT)
}

/// Decodes and validates protocol v1 application bytes.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error for malformed, oversized, or
/// semantically invalid input.
pub fn decode_application_message(
    bytes: &[u8],
) -> Result<ApplicationMessage, KonclaveProtocolError> {
    require_nested_bytes_field_limit(
        bytes,
        MAX_APPLICATION_MESSAGE_BYTES,
        CONTRACT,
        11,
        3,
        MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
        "collaboration_policy_bundle",
    )?;
    require_nested_bytes_field_limit(
        bytes,
        MAX_APPLICATION_MESSAGE_BYTES,
        CONTRACT,
        16,
        4,
        MAX_REPEAT_PAIRING_CAPABILITY_BYTES,
        "repeat_pairing_capability",
    )?;
    let wire: wire::ApplicationMessage =
        decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, CONTRACT)?;
    let content = match wire.content {
        Some(wire::application_message::Content::Text(text)) => {
            ApplicationContent::text(text.body)?
        }
        Some(wire::application_message::Content::DirectedRequest(request)) => {
            ApplicationContent::directed_request(
                device_id_from_wire(request.target_device_id)?,
                request.body,
            )?
        }
        Some(wire::application_message::Content::RepeatPairingRequest(request)) => {
            ApplicationContent::repeat_pairing_request(RepeatPairingRequest::new(
                repeat_pairing_operation_id_from_wire(request.operation_id)?,
                device_id_from_wire(request.target_device_id)?,
                crate::v1::common::conversation_id_from_wire(request.new_conversation_id)?,
                request.expires_at_unix_seconds,
            )?)
        }
        Some(wire::application_message::Content::RepeatPairingResponse(response)) => {
            ApplicationContent::repeat_pairing_response(RepeatPairingResponse::new(
                repeat_pairing_operation_id_from_wire(response.operation_id)?,
                device_id_from_wire(response.requester_device_id)?,
                crate::v1::common::conversation_id_from_wire(response.new_conversation_id)?,
                response.capability,
            )?)
        }
        Some(wire::application_message::Content::CollaborationPolicyProposal(proposal)) => {
            ApplicationContent::collaboration_policy_proposal(proposal_from_wire(proposal)?)
        }
        Some(wire::application_message::Content::CollaborationPolicyResponse(response)) => {
            ApplicationContent::CollaborationPolicyResponse(response_from_wire(response)?)
        }
        Some(wire::application_message::Content::CollaborationPolicyRevocation(revocation)) => {
            ApplicationContent::CollaborationPolicyRevocation(revocation_from_wire(revocation)?)
        }
        None => {
            return Err(KonclaveProtocolError::MissingVariant {
                field: "application_message.content",
            });
        }
    };
    Ok(ApplicationMessage::new(
        version_from_wire(wire.version, CONTRACT)?,
        message_id_from_wire(wire.message_id)?,
        wire.sender_counter,
        wire.sent_at_unix_milliseconds,
        wire.reply_to
            .map(|message_id| message_id_from_wire(Some(message_id)))
            .transpose()?,
        content,
    )?)
}

fn repeat_pairing_operation_id_to_wire(
    value: RepeatPairingOperationId,
) -> wire::RepeatPairingOperationId {
    wire::RepeatPairingOperationId {
        value: prost::bytes::Bytes::copy_from_slice(value.as_bytes()),
    }
}

fn repeat_pairing_operation_id_from_wire(
    value: Option<wire::RepeatPairingOperationId>,
) -> Result<RepeatPairingOperationId, KonclaveProtocolError> {
    let value = value.ok_or(KonclaveProtocolError::MissingField {
        field: "repeat_pairing_operation_id",
    })?;
    Ok(RepeatPairingOperationId::from_slice(&value.value)?)
}
