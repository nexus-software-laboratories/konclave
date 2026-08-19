use KonclaveDomainCore::{ApplicationContent, ApplicationMessage, MAX_APPLICATION_MESSAGE_BYTES};

use crate::KonclaveProtocolError;
use crate::v1::common::{
    decode_bounded, encode_bounded, message_id_from_wire, message_id_to_wire, version_from_wire,
    version_to_wire,
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
    let wire: wire::ApplicationMessage =
        decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, CONTRACT)?;
    let content = match wire.content {
        Some(wire::application_message::Content::Text(text)) => {
            ApplicationContent::text(text.body)?
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
