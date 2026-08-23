use crate::error::AdapterTransportError;
use crate::frame::MAX_AUTHENTICATED_FRAME_BYTES;

/// Byte length of a notification identifier.
pub const NOTIFICATION_ID_LENGTH: usize = 16;

/// Byte length of a conversation or device identifier.
pub const ROUTED_ID_LENGTH: usize = 32;

/// Largest batch an adapter may request in one wait.
pub const MAX_CLAIM_BATCH: u16 = 50;

/// Longest bounded wait an adapter may request, in milliseconds.
///
/// A wait that never expires would hide a wedged consumer, so the daemon always
/// answers within this bound even when no work arrives.
pub const MAX_WAIT_MILLISECONDS: u32 = 60_000;

/// Largest accepted application text in a delivered event.
pub const MAX_EVENT_TEXT_BYTES: usize = 64 * 1024;

const KIND_WAIT_AND_CLAIM: u8 = 16;
const KIND_ACKNOWLEDGE: u8 = 17;
const KIND_RELEASE: u8 = 18;
const KIND_STATUS: u8 = 19;

const KIND_BATCH: u8 = 32;
const KIND_ACCEPTED: u8 = 33;
const KIND_STATUS_REPORT: u8 = 34;
const KIND_FAILURE: u8 = 35;

const EVENT_APPLICATION_MESSAGE: u8 = 1;
const EVENT_MEMBER_ADDED: u8 = 2;
const EVENT_MEMBER_REMOVED: u8 = 3;
const EVENT_MEMBER_ROLE_CHANGED: u8 = 4;
const EVENT_LOCAL_ACCESS_REMOVED: u8 = 5;

const ROLE_ADMINISTRATOR: u8 = 1;
const ROLE_MEMBER: u8 = 2;

/// Membership authority carried by a delivered event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveredRole {
    Administrator,
    Member,
}

/// What a delivered event tells the adapter, separate from peer-controlled content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveredPayload {
    /// Text a remote member sent. This is untrusted peer content.
    ApplicationText(String),
    MemberAdded {
        device: [u8; ROUTED_ID_LENGTH],
        role: DeliveredRole,
    },
    MemberRemoved {
        device: [u8; ROUTED_ID_LENGTH],
    },
    MemberRoleChanged {
        device: [u8; ROUTED_ID_LENGTH],
        role: DeliveredRole,
    },
    LocalAccessRemoved {
        device: [u8; ROUTED_ID_LENGTH],
    },
}

/// One claimed remote event handed to an adapter.
///
/// The authenticated sender, conversation, and stable notification identifier are
/// separate fields rather than embedded in content, so an adapter can frame peer text
/// as untrusted without parsing it for routing information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredEvent {
    pub notification_id: [u8; NOTIFICATION_ID_LENGTH],
    pub lease_generation: u64,
    pub sequence: u64,
    pub conversation: [u8; ROUTED_ID_LENGTH],
    pub sender: [u8; ROUTED_ID_LENGTH],
    pub relay_cursor: u64,
    pub payload: DeliveredPayload,
}

/// An operation an authenticated adapter may request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterRequest {
    /// Waits for and claims a bounded batch.
    WaitAndClaim {
        max_events: u16,
        wait_milliseconds: u32,
    },
    /// Reports that the harness accepted delivery of one event.
    Acknowledge {
        notification_id: [u8; NOTIFICATION_ID_LENGTH],
        lease_generation: u64,
    },
    /// Returns one claimed event for later delivery without acknowledging it.
    Release {
        notification_id: [u8; NOTIFICATION_ID_LENGTH],
        lease_generation: u64,
    },
    /// Requests current delivery health.
    Status,
}

/// What the daemon answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterResponse {
    /// A claimed batch. An empty batch means the bounded wait expired and is not an
    /// event, so a client reissues rather than treating it as work.
    Batch(Vec<DeliveredEvent>),
    /// The requested transition was applied, or was already applied.
    Accepted,
    /// Current delivery health.
    Status(AdapterStatus),
    /// The request failed. The code is stable and carries no plaintext.
    Failure { code: String },
}

/// Bounded delivery health an adapter can surface without reading events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdapterStatus {
    pub pending_events: u32,
    pub claimed_events: u32,
    pub watched_conversations: u32,
    pub delivery_degraded: bool,
}

impl AdapterRequest {
    /// Encodes the canonical request payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::WaitAndClaim {
                max_events,
                wait_milliseconds,
            } => {
                payload.push(KIND_WAIT_AND_CLAIM);
                payload.extend_from_slice(&max_events.to_be_bytes());
                payload.extend_from_slice(&wait_milliseconds.to_be_bytes());
            }
            Self::Acknowledge {
                notification_id,
                lease_generation,
            } => {
                payload.push(KIND_ACKNOWLEDGE);
                payload.extend_from_slice(notification_id);
                payload.extend_from_slice(&lease_generation.to_be_bytes());
            }
            Self::Release {
                notification_id,
                lease_generation,
            } => {
                payload.push(KIND_RELEASE);
                payload.extend_from_slice(notification_id);
                payload.extend_from_slice(&lease_generation.to_be_bytes());
            }
            Self::Status => payload.push(KIND_STATUS),
        }
        payload
    }

    /// Decodes one request payload.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnknownMessageKind`],
    /// [`AdapterTransportError::MalformedFrame`], or
    /// [`AdapterTransportError::RequestOutOfBounds`].
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterTransportError> {
        let (kind, mut rest) = split_kind(payload)?;
        let request = match kind {
            KIND_WAIT_AND_CLAIM => {
                let max_events = u16::from_be_bytes(take::<2>(&mut rest)?);
                let wait_milliseconds = u32::from_be_bytes(take::<4>(&mut rest)?);
                if max_events == 0
                    || max_events > MAX_CLAIM_BATCH
                    || wait_milliseconds > MAX_WAIT_MILLISECONDS
                {
                    return Err(AdapterTransportError::RequestOutOfBounds);
                }
                Self::WaitAndClaim {
                    max_events,
                    wait_milliseconds,
                }
            }
            KIND_ACKNOWLEDGE => Self::Acknowledge {
                notification_id: take::<NOTIFICATION_ID_LENGTH>(&mut rest)?,
                lease_generation: u64::from_be_bytes(take::<8>(&mut rest)?),
            },
            KIND_RELEASE => Self::Release {
                notification_id: take::<NOTIFICATION_ID_LENGTH>(&mut rest)?,
                lease_generation: u64::from_be_bytes(take::<8>(&mut rest)?),
            },
            KIND_STATUS => Self::Status,
            _ => return Err(AdapterTransportError::UnknownMessageKind),
        };
        finish(rest)?;
        Ok(request)
    }
}

impl AdapterResponse {
    /// Encodes the canonical response payload.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::RequestOutOfBounds`] when a batch or failure
    /// code exceeds its bound, so an oversized response fails here rather than being
    /// truncated on the wire.
    pub fn encode(&self) -> Result<Vec<u8>, AdapterTransportError> {
        let mut payload = Vec::new();
        match self {
            Self::Batch(events) => {
                if events.len() > usize::from(MAX_CLAIM_BATCH) {
                    return Err(AdapterTransportError::RequestOutOfBounds);
                }
                payload.push(KIND_BATCH);
                payload.extend_from_slice(
                    &u16::try_from(events.len())
                        .map_err(|_| AdapterTransportError::RequestOutOfBounds)?
                        .to_be_bytes(),
                );
                for event in events {
                    event.encode_into(&mut payload)?;
                }
            }
            Self::Accepted => payload.push(KIND_ACCEPTED),
            Self::Status(status) => {
                payload.push(KIND_STATUS_REPORT);
                payload.extend_from_slice(&status.pending_events.to_be_bytes());
                payload.extend_from_slice(&status.claimed_events.to_be_bytes());
                payload.extend_from_slice(&status.watched_conversations.to_be_bytes());
                payload.push(u8::from(status.delivery_degraded));
            }
            Self::Failure { code } => {
                let bytes = code.as_bytes();
                if bytes.is_empty() || bytes.len() > 64 || !bytes.iter().all(is_code_byte) {
                    return Err(AdapterTransportError::RequestOutOfBounds);
                }
                payload.push(KIND_FAILURE);
                payload.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
                payload.extend_from_slice(bytes);
            }
        }
        if payload.len() > MAX_AUTHENTICATED_FRAME_BYTES {
            return Err(AdapterTransportError::RequestOutOfBounds);
        }
        Ok(payload)
    }

    /// Decodes one response payload.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnknownMessageKind`],
    /// [`AdapterTransportError::MalformedFrame`], or
    /// [`AdapterTransportError::RequestOutOfBounds`].
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterTransportError> {
        let (kind, mut rest) = split_kind(payload)?;
        let response = match kind {
            KIND_BATCH => {
                let count = u16::from_be_bytes(take::<2>(&mut rest)?);
                if count > MAX_CLAIM_BATCH {
                    return Err(AdapterTransportError::RequestOutOfBounds);
                }
                let mut events = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    events.push(DeliveredEvent::decode_from(&mut rest)?);
                }
                Self::Batch(events)
            }
            KIND_ACCEPTED => Self::Accepted,
            KIND_STATUS_REPORT => {
                let pending_events = u32::from_be_bytes(take::<4>(&mut rest)?);
                let claimed_events = u32::from_be_bytes(take::<4>(&mut rest)?);
                let watched_conversations = u32::from_be_bytes(take::<4>(&mut rest)?);
                let degraded = take::<1>(&mut rest)?[0];
                if degraded > 1 {
                    return Err(AdapterTransportError::MalformedFrame);
                }
                Self::Status(AdapterStatus {
                    pending_events,
                    claimed_events,
                    watched_conversations,
                    delivery_degraded: degraded == 1,
                })
            }
            KIND_FAILURE => {
                let length = usize::from(take::<1>(&mut rest)?[0]);
                if length == 0 || length > 64 {
                    return Err(AdapterTransportError::MalformedFrame);
                }
                let bytes = take_slice(&mut rest, length)?;
                if !bytes.iter().all(is_code_byte) {
                    return Err(AdapterTransportError::MalformedFrame);
                }
                Self::Failure {
                    code: String::from_utf8(bytes.to_vec())
                        .map_err(|_| AdapterTransportError::MalformedFrame)?,
                }
            }
            _ => return Err(AdapterTransportError::UnknownMessageKind),
        };
        finish(rest)?;
        Ok(response)
    }
}

impl DeliveredEvent {
    fn encode_into(&self, payload: &mut Vec<u8>) -> Result<(), AdapterTransportError> {
        payload.extend_from_slice(&self.notification_id);
        payload.extend_from_slice(&self.lease_generation.to_be_bytes());
        payload.extend_from_slice(&self.sequence.to_be_bytes());
        payload.extend_from_slice(&self.conversation);
        payload.extend_from_slice(&self.sender);
        payload.extend_from_slice(&self.relay_cursor.to_be_bytes());
        match &self.payload {
            DeliveredPayload::ApplicationText(text) => {
                let bytes = text.as_bytes();
                if bytes.is_empty() || bytes.len() > MAX_EVENT_TEXT_BYTES {
                    return Err(AdapterTransportError::RequestOutOfBounds);
                }
                payload.push(EVENT_APPLICATION_MESSAGE);
                payload.extend_from_slice(
                    &u32::try_from(bytes.len())
                        .map_err(|_| AdapterTransportError::RequestOutOfBounds)?
                        .to_be_bytes(),
                );
                payload.extend_from_slice(bytes);
            }
            DeliveredPayload::MemberAdded { device, role } => {
                payload.push(EVENT_MEMBER_ADDED);
                payload.extend_from_slice(device);
                payload.push(encode_role(*role));
            }
            DeliveredPayload::MemberRemoved { device } => {
                payload.push(EVENT_MEMBER_REMOVED);
                payload.extend_from_slice(device);
            }
            DeliveredPayload::MemberRoleChanged { device, role } => {
                payload.push(EVENT_MEMBER_ROLE_CHANGED);
                payload.extend_from_slice(device);
                payload.push(encode_role(*role));
            }
            DeliveredPayload::LocalAccessRemoved { device } => {
                payload.push(EVENT_LOCAL_ACCESS_REMOVED);
                payload.extend_from_slice(device);
            }
        }
        Ok(())
    }

    fn decode_from(rest: &mut &[u8]) -> Result<Self, AdapterTransportError> {
        let notification_id = take::<NOTIFICATION_ID_LENGTH>(rest)?;
        let lease_generation = u64::from_be_bytes(take::<8>(rest)?);
        let sequence = u64::from_be_bytes(take::<8>(rest)?);
        let conversation = take::<ROUTED_ID_LENGTH>(rest)?;
        let sender = take::<ROUTED_ID_LENGTH>(rest)?;
        let relay_cursor = u64::from_be_bytes(take::<8>(rest)?);
        let payload = match take::<1>(rest)?[0] {
            EVENT_APPLICATION_MESSAGE => {
                let length = u32::from_be_bytes(take::<4>(rest)?) as usize;
                if length == 0 || length > MAX_EVENT_TEXT_BYTES {
                    return Err(AdapterTransportError::RequestOutOfBounds);
                }
                let bytes = take_slice(rest, length)?;
                DeliveredPayload::ApplicationText(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| AdapterTransportError::MalformedFrame)?,
                )
            }
            EVENT_MEMBER_ADDED => DeliveredPayload::MemberAdded {
                device: take::<ROUTED_ID_LENGTH>(rest)?,
                role: decode_role(take::<1>(rest)?[0])?,
            },
            EVENT_MEMBER_REMOVED => DeliveredPayload::MemberRemoved {
                device: take::<ROUTED_ID_LENGTH>(rest)?,
            },
            EVENT_MEMBER_ROLE_CHANGED => DeliveredPayload::MemberRoleChanged {
                device: take::<ROUTED_ID_LENGTH>(rest)?,
                role: decode_role(take::<1>(rest)?[0])?,
            },
            EVENT_LOCAL_ACCESS_REMOVED => DeliveredPayload::LocalAccessRemoved {
                device: take::<ROUTED_ID_LENGTH>(rest)?,
            },
            _ => return Err(AdapterTransportError::UnknownMessageKind),
        };
        Ok(Self {
            notification_id,
            lease_generation,
            sequence,
            conversation,
            sender,
            relay_cursor,
            payload,
        })
    }
}

const fn encode_role(role: DeliveredRole) -> u8 {
    match role {
        DeliveredRole::Administrator => ROLE_ADMINISTRATOR,
        DeliveredRole::Member => ROLE_MEMBER,
    }
}

const fn decode_role(value: u8) -> Result<DeliveredRole, AdapterTransportError> {
    match value {
        ROLE_ADMINISTRATOR => Ok(DeliveredRole::Administrator),
        ROLE_MEMBER => Ok(DeliveredRole::Member),
        _ => Err(AdapterTransportError::MalformedFrame),
    }
}

fn is_code_byte(byte: &u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
}

fn split_kind(payload: &[u8]) -> Result<(u8, &[u8]), AdapterTransportError> {
    payload
        .split_first()
        .map(|(kind, rest)| (*kind, rest))
        .ok_or(AdapterTransportError::MalformedFrame)
}

fn finish(rest: &[u8]) -> Result<(), AdapterTransportError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(AdapterTransportError::MalformedFrame)
    }
}

fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], AdapterTransportError> {
    let slice = take_slice(rest, N)?;
    let mut value = [0_u8; N];
    value.copy_from_slice(slice);
    Ok(value)
}

fn take_slice<'a>(rest: &mut &'a [u8], length: usize) -> Result<&'a [u8], AdapterTransportError> {
    if rest.len() < length {
        return Err(AdapterTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(length);
    *rest = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterRequest, AdapterResponse, AdapterStatus, DeliveredEvent, DeliveredPayload,
        DeliveredRole, MAX_CLAIM_BATCH, MAX_EVENT_TEXT_BYTES, MAX_WAIT_MILLISECONDS,
        NOTIFICATION_ID_LENGTH, ROUTED_ID_LENGTH,
    };
    use crate::error::AdapterTransportError;

    fn event(payload: DeliveredPayload) -> DeliveredEvent {
        DeliveredEvent {
            notification_id: [1_u8; NOTIFICATION_ID_LENGTH],
            lease_generation: 7,
            sequence: 42,
            conversation: [2_u8; ROUTED_ID_LENGTH],
            sender: [3_u8; ROUTED_ID_LENGTH],
            relay_cursor: 9,
            payload,
        }
    }

    #[test]
    fn every_request_round_trips() {
        for request in [
            AdapterRequest::WaitAndClaim {
                max_events: 10,
                wait_milliseconds: 5_000,
            },
            AdapterRequest::Acknowledge {
                notification_id: [4_u8; NOTIFICATION_ID_LENGTH],
                lease_generation: 3,
            },
            AdapterRequest::Release {
                notification_id: [5_u8; NOTIFICATION_ID_LENGTH],
                lease_generation: 4,
            },
            AdapterRequest::Status,
        ] {
            assert_eq!(AdapterRequest::decode(&request.encode()).unwrap(), request);
        }
    }

    #[test]
    fn every_response_and_event_kind_round_trips() {
        let responses = [
            AdapterResponse::Batch(vec![
                event(DeliveredPayload::ApplicationText("hello".to_string())),
                event(DeliveredPayload::MemberAdded {
                    device: [6_u8; ROUTED_ID_LENGTH],
                    role: DeliveredRole::Administrator,
                }),
                event(DeliveredPayload::MemberRemoved {
                    device: [7_u8; ROUTED_ID_LENGTH],
                }),
                event(DeliveredPayload::MemberRoleChanged {
                    device: [8_u8; ROUTED_ID_LENGTH],
                    role: DeliveredRole::Member,
                }),
                event(DeliveredPayload::LocalAccessRemoved {
                    device: [9_u8; ROUTED_ID_LENGTH],
                }),
            ]),
            AdapterResponse::Batch(Vec::new()),
            AdapterResponse::Accepted,
            AdapterResponse::Status(AdapterStatus {
                pending_events: 3,
                claimed_events: 1,
                watched_conversations: 2,
                delivery_degraded: true,
            }),
            AdapterResponse::Failure {
                code: "adapter_stale_lease".to_string(),
            },
        ];
        for response in responses {
            let encoded = response.encode().unwrap();
            assert_eq!(AdapterResponse::decode(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn an_empty_batch_is_distinguishable_from_an_accepted_transition() {
        let empty = AdapterResponse::Batch(Vec::new()).encode().unwrap();
        let accepted = AdapterResponse::Accepted.encode().unwrap();
        assert_ne!(empty, accepted);
        assert_eq!(
            AdapterResponse::decode(&empty).unwrap(),
            AdapterResponse::Batch(Vec::new())
        );
    }

    #[test]
    fn out_of_bounds_wait_requests_are_rejected() {
        for request in [
            AdapterRequest::WaitAndClaim {
                max_events: 0,
                wait_milliseconds: 1,
            },
            AdapterRequest::WaitAndClaim {
                max_events: MAX_CLAIM_BATCH + 1,
                wait_milliseconds: 1,
            },
            AdapterRequest::WaitAndClaim {
                max_events: 1,
                wait_milliseconds: MAX_WAIT_MILLISECONDS + 1,
            },
        ] {
            assert_eq!(
                AdapterRequest::decode(&request.encode()).unwrap_err(),
                AdapterTransportError::RequestOutOfBounds
            );
        }
    }

    #[test]
    fn an_oversized_declared_batch_is_rejected_before_reserving_capacity() {
        let mut payload = AdapterResponse::Batch(Vec::new()).encode().unwrap();
        payload[1..3].copy_from_slice(&(MAX_CLAIM_BATCH + 1).to_be_bytes());
        assert_eq!(
            AdapterResponse::decode(&payload).unwrap_err(),
            AdapterTransportError::RequestOutOfBounds
        );
    }

    #[test]
    fn a_declared_batch_larger_than_its_payload_is_rejected() {
        let mut payload = AdapterResponse::Batch(Vec::new()).encode().unwrap();
        payload[1..3].copy_from_slice(&5_u16.to_be_bytes());
        assert_eq!(
            AdapterResponse::decode(&payload).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
    }

    #[test]
    fn unknown_kinds_and_trailing_bytes_are_rejected() {
        assert_eq!(
            AdapterRequest::decode(&[99, 0, 0]).unwrap_err(),
            AdapterTransportError::UnknownMessageKind
        );
        assert_eq!(
            AdapterResponse::decode(&[99]).unwrap_err(),
            AdapterTransportError::UnknownMessageKind
        );
        let mut padded = AdapterRequest::Status.encode();
        padded.push(0);
        assert_eq!(
            AdapterRequest::decode(&padded).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
        let mut padded = AdapterResponse::Accepted.encode().unwrap();
        padded.push(0);
        assert_eq!(
            AdapterResponse::decode(&padded).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
    }

    #[test]
    fn truncation_is_rejected_at_every_prefix() {
        let payloads = [
            AdapterRequest::Acknowledge {
                notification_id: [4_u8; NOTIFICATION_ID_LENGTH],
                lease_generation: 3,
            }
            .encode(),
            AdapterRequest::WaitAndClaim {
                max_events: 1,
                wait_milliseconds: 1,
            }
            .encode(),
        ];
        for payload in payloads {
            for length in 1..payload.len() {
                assert!(
                    AdapterRequest::decode(&payload[..length]).is_err(),
                    "prefix of {length} bytes must not decode"
                );
            }
        }

        let batch = AdapterResponse::Batch(vec![event(DeliveredPayload::ApplicationText(
            "hello".to_string(),
        ))])
        .encode()
        .unwrap();
        for length in 1..batch.len() {
            assert!(
                AdapterResponse::decode(&batch[..length]).is_err(),
                "prefix of {length} bytes must not decode"
            );
        }
    }

    #[test]
    fn empty_and_oversized_application_text_is_rejected() {
        assert_eq!(
            AdapterResponse::Batch(vec![event(
                DeliveredPayload::ApplicationText(String::new())
            )])
            .encode()
            .unwrap_err(),
            AdapterTransportError::RequestOutOfBounds
        );
        assert_eq!(
            AdapterResponse::Batch(vec![event(DeliveredPayload::ApplicationText(
                "a".repeat(MAX_EVENT_TEXT_BYTES + 1)
            ))])
            .encode()
            .unwrap_err(),
            AdapterTransportError::RequestOutOfBounds
        );
    }

    #[test]
    fn an_unknown_role_or_event_kind_is_rejected() {
        let mut payload = AdapterResponse::Batch(vec![event(DeliveredPayload::MemberAdded {
            device: [6_u8; ROUTED_ID_LENGTH],
            role: DeliveredRole::Member,
        })])
        .encode()
        .unwrap();
        let last = payload.len() - 1;
        payload[last] = 9;
        assert_eq!(
            AdapterResponse::decode(&payload).unwrap_err(),
            AdapterTransportError::MalformedFrame
        );
    }

    #[test]
    fn a_failure_code_is_bounded_and_machine_readable() {
        assert!(
            AdapterResponse::Failure {
                code: String::new()
            }
            .encode()
            .is_err()
        );
        assert!(
            AdapterResponse::Failure {
                code: "a".repeat(65)
            }
            .encode()
            .is_err()
        );
        assert!(
            AdapterResponse::Failure {
                code: "Not A Code".to_string()
            }
            .encode()
            .is_err(),
            "a failure code must not carry free text that could leak content"
        );
    }
}
