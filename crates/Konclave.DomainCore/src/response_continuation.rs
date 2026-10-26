use thiserror::Error;

use crate::{ApplicationContent, ApplicationMessage, ConversationId, DeviceId, MessageId};

/// Authenticated local-history direction, not a claim supplied by a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseContinuationDirection {
    /// A message sent by this local endpoint.
    Outbound,
    /// A message received from an authenticated remote endpoint.
    Inbound,
}

/// One authenticated, bounded history record considered for response continuation.
///
/// The caller must obtain the conversation, sender, direction, completion, and
/// application message from verified local history, never from delivery hints alone.
pub struct ResponseContinuationMessage<'a> {
    /// Exact conversation authenticated by local history.
    pub conversation: ConversationId,
    /// MLS-authenticated sender.
    pub sender: DeviceId,
    /// Locally recorded direction.
    pub direction: ResponseContinuationDirection,
    /// Whether the journal has durably completed this message.
    pub complete: bool,
    /// Validated application content from the sealed record.
    pub message: &'a ApplicationMessage,
}

/// Exact request and answer identities admitted by content correlation alone.
///
/// This is not tool permission or a handling lease. The caller must separately
/// authorize current local work and atomically claim the original request once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseContinuationBinding {
    /// Original locally sent directed request.
    pub request_message_id: MessageId,
    /// Exact authenticated text answer.
    pub response_message_id: MessageId,
}

/// Finite correlation refusals without message bodies.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ResponseContinuationError {
    /// Only a completed local outbound request can establish an expectation.
    #[error("response continuation requires a completed outbound request")]
    InvalidRequestOrigin,
    /// The original request must belong to the acting local endpoint.
    #[error("response continuation request is not locally authored")]
    RequestNotLocal,
    /// Ordinary text cannot establish an automatic continuation expectation.
    #[error("response continuation requires a directed request")]
    RequestNotDirected,
    /// A directed request to the local endpoint is not a remote conversation.
    #[error("response continuation target must be remote")]
    LocalTarget,
    /// Only a completed incoming message can supply an answer.
    #[error("response continuation requires a completed inbound answer")]
    InvalidResponseOrigin,
    /// Cross-conversation references never satisfy a request.
    #[error("response continuation conversation differs")]
    ConversationMismatch,
    /// Requests and control messages are not terminal answers.
    #[error("response continuation answer must be ordinary text")]
    ResponseNotText,
    /// Only the original exact target can answer the request.
    #[error("response continuation sender differs from the requested target")]
    SenderMismatch,
    /// An answer must reference exactly the original request.
    #[error("response continuation reply reference differs")]
    ReplyMismatch,
}

/// Checks an exact authenticated answer to a locally initiated directed request.
///
/// User-originated and agent-originated requests have identical content semantics.
/// An answer supplies untrusted task input, not authority or another reply request.
///
/// # Errors
///
/// Returns a finite origin, content, conversation, sender, or reply mismatch. Success
/// must still pass current policy, membership, session, and durable claim checks.
pub fn validate_response_continuation(
    local_device: DeviceId,
    request: ResponseContinuationMessage<'_>,
    response: ResponseContinuationMessage<'_>,
) -> Result<ResponseContinuationBinding, ResponseContinuationError> {
    if request.direction != ResponseContinuationDirection::Outbound || !request.complete {
        return Err(ResponseContinuationError::InvalidRequestOrigin);
    }
    if request.sender != local_device {
        return Err(ResponseContinuationError::RequestNotLocal);
    }
    let ApplicationContent::DirectedRequest(directed) = request.message.content() else {
        return Err(ResponseContinuationError::RequestNotDirected);
    };
    if directed.target_device_id() == local_device {
        return Err(ResponseContinuationError::LocalTarget);
    }
    if response.direction != ResponseContinuationDirection::Inbound || !response.complete {
        return Err(ResponseContinuationError::InvalidResponseOrigin);
    }
    if request.conversation != response.conversation {
        return Err(ResponseContinuationError::ConversationMismatch);
    }
    if !matches!(response.message.content(), ApplicationContent::Text(_)) {
        return Err(ResponseContinuationError::ResponseNotText);
    }
    if response.sender != directed.target_device_id() {
        return Err(ResponseContinuationError::SenderMismatch);
    }
    if response.message.reply_to() != Some(request.message.message_id())
        || response.message.message_id() == request.message.message_id()
    {
        return Err(ResponseContinuationError::ReplyMismatch);
    }
    Ok(ResponseContinuationBinding {
        request_message_id: request.message.message_id(),
        response_message_id: response.message.message_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolVersion;

    fn message(id: u8, reply: Option<u8>, content: ApplicationContent) -> ApplicationMessage {
        ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([id; 16]),
            1,
            0,
            reply.map(|value| MessageId::from_bytes([value; 16])),
            content,
        )
        .unwrap()
    }

    fn record(
        message: &ApplicationMessage,
        sender: u8,
        direction: ResponseContinuationDirection,
    ) -> ResponseContinuationMessage<'_> {
        ResponseContinuationMessage {
            conversation: ConversationId::from_bytes([1; 32]),
            sender: DeviceId::from_bytes([sender; 32]),
            direction,
            complete: true,
            message,
        }
    }

    #[test]
    fn exact_answer_binds_the_original_request_without_creating_another_request() {
        let request = message(
            2,
            Some(9),
            ApplicationContent::directed_request(DeviceId::from_bytes([4; 32]), "question")
                .unwrap(),
        );
        let response = message(3, Some(2), ApplicationContent::text("answer").unwrap());
        let binding = validate_response_continuation(
            DeviceId::from_bytes([5; 32]),
            record(&request, 5, ResponseContinuationDirection::Outbound),
            record(&response, 4, ResponseContinuationDirection::Inbound),
        )
        .unwrap();
        assert_eq!(binding.request_message_id, request.message_id());
        assert_eq!(binding.response_message_id, response.message_id());
    }

    #[test]
    fn every_correlation_refusal_is_deterministic() {
        for expected in [
            ResponseContinuationError::InvalidRequestOrigin,
            ResponseContinuationError::RequestNotLocal,
            ResponseContinuationError::RequestNotDirected,
            ResponseContinuationError::LocalTarget,
            ResponseContinuationError::InvalidResponseOrigin,
            ResponseContinuationError::ConversationMismatch,
            ResponseContinuationError::ResponseNotText,
            ResponseContinuationError::SenderMismatch,
            ResponseContinuationError::ReplyMismatch,
        ] {
            let local = DeviceId::from_bytes([5; 32]);
            let target = if expected == ResponseContinuationError::LocalTarget {
                local
            } else {
                DeviceId::from_bytes([4; 32])
            };
            let request = message(
                2,
                None,
                if expected == ResponseContinuationError::RequestNotDirected {
                    ApplicationContent::text("not a request").unwrap()
                } else {
                    ApplicationContent::directed_request(target, "question").unwrap()
                },
            );
            let response = message(
                3,
                if expected == ResponseContinuationError::ReplyMismatch {
                    Some(8)
                } else {
                    Some(2)
                },
                if expected == ResponseContinuationError::ResponseNotText {
                    ApplicationContent::directed_request(local, "another request").unwrap()
                } else {
                    ApplicationContent::text("answer").unwrap()
                },
            );
            let mut request = record(&request, 5, ResponseContinuationDirection::Outbound);
            let mut response = record(&response, 4, ResponseContinuationDirection::Inbound);
            match expected {
                ResponseContinuationError::InvalidRequestOrigin => request.complete = false,
                ResponseContinuationError::RequestNotLocal => {
                    request.sender = DeviceId::from_bytes([8; 32]);
                }
                ResponseContinuationError::InvalidResponseOrigin => response.complete = false,
                ResponseContinuationError::ConversationMismatch => {
                    response.conversation = ConversationId::from_bytes([8; 32]);
                }
                ResponseContinuationError::SenderMismatch => {
                    response.sender = DeviceId::from_bytes([8; 32]);
                }
                _ => {}
            }
            assert_eq!(
                validate_response_continuation(local, request, response),
                Err(expected),
                "{expected:?}"
            );
        }
    }

    #[test]
    fn direction_is_local_evidence_and_cannot_be_inferred_from_reply_text() {
        for (request_direction, response_direction, expected) in [
            (
                ResponseContinuationDirection::Inbound,
                ResponseContinuationDirection::Inbound,
                ResponseContinuationError::InvalidRequestOrigin,
            ),
            (
                ResponseContinuationDirection::Outbound,
                ResponseContinuationDirection::Outbound,
                ResponseContinuationError::InvalidResponseOrigin,
            ),
        ] {
            let request = message(
                2,
                None,
                ApplicationContent::directed_request(DeviceId::from_bytes([4; 32]), "question")
                    .unwrap(),
            );
            let response = message(3, Some(2), ApplicationContent::text("answer").unwrap());
            assert_eq!(
                validate_response_continuation(
                    DeviceId::from_bytes([5; 32]),
                    record(&request, 5, request_direction),
                    record(&response, 4, response_direction),
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn uncorrelated_text_and_reused_request_identity_do_not_continue() {
        for (response_id, reply) in [(3, None), (2, Some(2))] {
            let request = message(
                2,
                None,
                ApplicationContent::directed_request(DeviceId::from_bytes([4; 32]), "question")
                    .unwrap(),
            );
            let response = message(response_id, reply, ApplicationContent::text("answer").unwrap());
            assert_eq!(
                validate_response_continuation(
                    DeviceId::from_bytes([5; 32]),
                    record(&request, 5, ResponseContinuationDirection::Outbound),
                    record(&response, 4, ResponseContinuationDirection::Inbound),
                ),
                Err(ResponseContinuationError::ReplyMismatch)
            );
        }
    }
}
