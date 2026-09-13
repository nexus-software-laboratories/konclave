use KonclaveLocalServiceTransport::decode_lowercase_hex;
use serde::Deserialize;

use crate::{AdapterSdkError, MAX_EVENT_TEXT_BYTES};

/// Byte length of a delivery notification identifier.
pub const NOTIFICATION_ID_LENGTH: usize = 16;
/// Byte length of a conversation, device, or policy digest identifier.
pub const ROUTED_ID_LENGTH: usize = 32;
/// Byte length of an application message or proposal identifier.
pub const MESSAGE_ID_LENGTH: usize = 16;

/// Membership authority carried by a delivery event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveredRole {
    /// Conversation administrator.
    Administrator,
    /// Ordinary conversation member.
    Member,
}

/// Peer decision carried by a collaboration-policy response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveredPolicyResponseOutcome {
    /// The peer accepted the exact policy digest.
    Accepted,
    /// The peer rejected the exact policy digest.
    Rejected,
}

/// Validated delivery content separated from authenticated routing metadata.
#[derive(PartialEq, Eq)]
pub enum DeliveredPayload {
    /// Untrusted peer-authored application text.
    ApplicationText {
        /// Stable application message identifier.
        message_id: [u8; MESSAGE_ID_LENGTH],
        /// Bounded UTF-8 peer content.
        text: String,
    },
    /// Untrusted peer-authored request directed to this exact device.
    DirectedRequest {
        /// Stable request message identifier.
        message_id: [u8; MESSAGE_ID_LENGTH],
        /// Exact target device authenticated by the message.
        target_device_id: [u8; ROUTED_ID_LENGTH],
        /// Bounded UTF-8 request body.
        text: String,
    },
    /// Authenticated collaboration-policy proposal metadata.
    CollaborationPolicyProposal {
        /// Stable proposal identifier.
        proposal_id: [u8; MESSAGE_ID_LENGTH],
        /// Exact canonical policy digest.
        policy_digest: [u8; ROUTED_ID_LENGTH],
        /// Digest this proposal replaces, when any.
        replaces_policy_digest: Option<[u8; ROUTED_ID_LENGTH]>,
    },
    /// Authenticated peer response to one policy proposal.
    CollaborationPolicyResponse {
        /// Stable proposal identifier.
        proposal_id: [u8; MESSAGE_ID_LENGTH],
        /// Exact canonical policy digest.
        policy_digest: [u8; ROUTED_ID_LENGTH],
        /// Accepted or rejected outcome.
        outcome: DeliveredPolicyResponseOutcome,
    },
    /// Authenticated revocation of one policy digest.
    CollaborationPolicyRevocation {
        /// Exact revoked policy digest.
        policy_digest: [u8; ROUTED_ID_LENGTH],
    },
    /// Authenticated membership addition.
    MemberAdded {
        /// Added device identifier.
        device_id: [u8; ROUTED_ID_LENGTH],
        /// Granted role.
        role: DeliveredRole,
    },
    /// Authenticated membership removal.
    MemberRemoved {
        /// Removed device identifier.
        device_id: [u8; ROUTED_ID_LENGTH],
    },
    /// Authenticated membership role change.
    MemberRoleChanged {
        /// Changed device identifier.
        device_id: [u8; ROUTED_ID_LENGTH],
        /// New role.
        role: DeliveredRole,
    },
    /// Removal of this profile's local access.
    LocalAccessRemoved {
        /// Removed local device identifier.
        device_id: [u8; ROUTED_ID_LENGTH],
    },
}

/// One claimed durable event delivered to a harness adapter.
#[derive(PartialEq, Eq)]
pub struct DeliveredEvent {
    notification_id: [u8; NOTIFICATION_ID_LENGTH],
    lease_generation: u64,
    sequence: u64,
    conversation_id: [u8; ROUTED_ID_LENGTH],
    sender_device_id: [u8; ROUTED_ID_LENGTH],
    relay_cursor: u64,
    payload: DeliveredPayload,
}

impl DeliveredEvent {
    /// Returns the stable notification identifier used for settlement.
    #[must_use]
    pub const fn notification_id(&self) -> &[u8; NOTIFICATION_ID_LENGTH] {
        &self.notification_id
    }

    /// Returns the lease generation that must accompany settlement.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the profile-local delivery sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact conversation identifier.
    #[must_use]
    pub const fn conversation_id(&self) -> &[u8; ROUTED_ID_LENGTH] {
        &self.conversation_id
    }

    /// Returns the authenticated sender device identifier.
    #[must_use]
    pub const fn sender_device_id(&self) -> &[u8; ROUTED_ID_LENGTH] {
        &self.sender_device_id
    }

    /// Returns the relay cursor committed before delivery.
    #[must_use]
    pub const fn relay_cursor(&self) -> u64 {
        self.relay_cursor
    }

    /// Returns the validated event content.
    #[must_use]
    pub const fn payload(&self) -> &DeliveredPayload {
        &self.payload
    }
}

/// Settlement identity for one claimed delivery event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliverySettlement {
    notification_id: [u8; NOTIFICATION_ID_LENGTH],
    lease_generation: u64,
}

impl DeliverySettlement {
    /// Creates the settlement identity carried by a delivered event.
    #[must_use]
    pub const fn from_event(event: &DeliveredEvent) -> Self {
        Self {
            notification_id: event.notification_id,
            lease_generation: event.lease_generation,
        }
    }

    /// Returns the stable notification identifier.
    #[must_use]
    pub const fn notification_id(self) -> [u8; NOTIFICATION_ID_LENGTH] {
        self.notification_id
    }

    /// Returns the current lease generation.
    #[must_use]
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }
}

/// Current bounded delivery health for one profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdapterStatus {
    /// Durable authorization generation observed by the service.
    pub authorization_generation: u64,
    /// Events ready for a consumer.
    pub pending_events: u32,
    /// Events currently held by the active consumer lease.
    pub claimed_events: u32,
    /// Conversations supervised for automatic delivery.
    pub watched_conversations: u32,
    /// Whether delivery supervision is reconnecting or backpressured.
    pub delivery_degraded: bool,
}

/// Active directed-request turn renewed by a delivery heartbeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollaborationTurnClaim {
    conversation_id: [u8; ROUTED_ID_LENGTH],
    policy_digest: [u8; ROUTED_ID_LENGTH],
    request_message_id: [u8; MESSAGE_ID_LENGTH],
    attempt: u32,
}

impl CollaborationTurnClaim {
    /// Creates one exact active turn identity.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error when `attempt` is zero.
    pub fn new(
        conversation_id: [u8; ROUTED_ID_LENGTH],
        policy_digest: [u8; ROUTED_ID_LENGTH],
        request_message_id: [u8; MESSAGE_ID_LENGTH],
        attempt: u32,
    ) -> Result<Self, AdapterSdkError> {
        if attempt == 0 {
            return Err(AdapterSdkError::InvalidConfiguration);
        }
        Ok(Self {
            conversation_id,
            policy_digest,
            request_message_id,
            attempt,
        })
    }

    pub(crate) const fn conversation_id(&self) -> &[u8; ROUTED_ID_LENGTH] {
        &self.conversation_id
    }

    pub(crate) const fn policy_digest(&self) -> &[u8; ROUTED_ID_LENGTH] {
        &self.policy_digest
    }

    pub(crate) const fn request_message_id(&self) -> &[u8; MESSAGE_ID_LENGTH] {
        &self.request_message_id
    }

    pub(crate) const fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct DeliveryEventDocument {
    notification_id: String,
    lease_generation: u64,
    sequence: u64,
    conversation: String,
    sender: String,
    relay_cursor: u64,
    payload: DeliveryPayloadDocument,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum DeliveryPayloadDocument {
    ApplicationText {
        message_id: String,
        text: String,
    },
    DirectedRequest {
        message_id: String,
        target_device_id: String,
        text: String,
    },
    CollaborationPolicyProposal {
        proposal_id: String,
        policy_digest: String,
        replaces_policy_digest: Option<String>,
    },
    CollaborationPolicyResponse {
        proposal_id: String,
        policy_digest: String,
        outcome: String,
    },
    CollaborationPolicyRevocation {
        policy_digest: String,
    },
    MemberAdded {
        device: String,
        role: String,
    },
    MemberRemoved {
        device: String,
    },
    MemberRoleChanged {
        device: String,
        role: String,
    },
    LocalAccessRemoved {
        device: String,
    },
}

impl TryFrom<DeliveryEventDocument> for DeliveredEvent {
    type Error = AdapterSdkError;

    fn try_from(document: DeliveryEventDocument) -> Result<Self, Self::Error> {
        Ok(Self {
            notification_id: decode::<NOTIFICATION_ID_LENGTH>(&document.notification_id)?,
            lease_generation: document.lease_generation,
            sequence: document.sequence,
            conversation_id: decode::<ROUTED_ID_LENGTH>(&document.conversation)?,
            sender_device_id: decode::<ROUTED_ID_LENGTH>(&document.sender)?,
            relay_cursor: document.relay_cursor,
            payload: document.payload.try_into()?,
        })
    }
}

impl TryFrom<DeliveryPayloadDocument> for DeliveredPayload {
    type Error = AdapterSdkError;

    fn try_from(document: DeliveryPayloadDocument) -> Result<Self, Self::Error> {
        Ok(match document {
            DeliveryPayloadDocument::ApplicationText { message_id, text } => {
                Self::ApplicationText {
                    message_id: decode::<MESSAGE_ID_LENGTH>(&message_id)?,
                    text: validate_text(text)?,
                }
            }
            DeliveryPayloadDocument::DirectedRequest {
                message_id,
                target_device_id,
                text,
            } => Self::DirectedRequest {
                message_id: decode::<MESSAGE_ID_LENGTH>(&message_id)?,
                target_device_id: decode::<ROUTED_ID_LENGTH>(&target_device_id)?,
                text: validate_text(text)?,
            },
            DeliveryPayloadDocument::CollaborationPolicyProposal {
                proposal_id,
                policy_digest,
                replaces_policy_digest,
            } => Self::CollaborationPolicyProposal {
                proposal_id: decode::<MESSAGE_ID_LENGTH>(&proposal_id)?,
                policy_digest: decode::<ROUTED_ID_LENGTH>(&policy_digest)?,
                replaces_policy_digest: replaces_policy_digest
                    .map(|value| decode::<ROUTED_ID_LENGTH>(&value))
                    .transpose()?,
            },
            DeliveryPayloadDocument::CollaborationPolicyResponse {
                proposal_id,
                policy_digest,
                outcome,
            } => Self::CollaborationPolicyResponse {
                proposal_id: decode::<MESSAGE_ID_LENGTH>(&proposal_id)?,
                policy_digest: decode::<ROUTED_ID_LENGTH>(&policy_digest)?,
                outcome: match outcome.as_str() {
                    "accepted" => DeliveredPolicyResponseOutcome::Accepted,
                    "rejected" => DeliveredPolicyResponseOutcome::Rejected,
                    _ => return Err(AdapterSdkError::InvalidResponse),
                },
            },
            DeliveryPayloadDocument::CollaborationPolicyRevocation { policy_digest } => {
                Self::CollaborationPolicyRevocation {
                    policy_digest: decode::<ROUTED_ID_LENGTH>(&policy_digest)?,
                }
            }
            DeliveryPayloadDocument::MemberAdded { device, role } => Self::MemberAdded {
                device_id: decode::<ROUTED_ID_LENGTH>(&device)?,
                role: parse_role(&role)?,
            },
            DeliveryPayloadDocument::MemberRemoved { device } => Self::MemberRemoved {
                device_id: decode::<ROUTED_ID_LENGTH>(&device)?,
            },
            DeliveryPayloadDocument::MemberRoleChanged { device, role } => {
                Self::MemberRoleChanged {
                    device_id: decode::<ROUTED_ID_LENGTH>(&device)?,
                    role: parse_role(&role)?,
                }
            }
            DeliveryPayloadDocument::LocalAccessRemoved { device } => Self::LocalAccessRemoved {
                device_id: decode::<ROUTED_ID_LENGTH>(&device)?,
            },
        })
    }
}

fn decode<const LENGTH: usize>(value: &str) -> Result<[u8; LENGTH], AdapterSdkError> {
    decode_lowercase_hex::<LENGTH>(value).ok_or(AdapterSdkError::InvalidResponse)
}

fn validate_text(value: String) -> Result<String, AdapterSdkError> {
    if value.is_empty() || value.len() > MAX_EVENT_TEXT_BYTES {
        Err(AdapterSdkError::InvalidResponse)
    } else {
        Ok(value)
    }
}

fn parse_role(value: &str) -> Result<DeliveredRole, AdapterSdkError> {
    match value {
        "administrator" => Ok(DeliveredRole::Administrator),
        "member" => Ok(DeliveredRole::Member),
        _ => Err(AdapterSdkError::InvalidResponse),
    }
}
