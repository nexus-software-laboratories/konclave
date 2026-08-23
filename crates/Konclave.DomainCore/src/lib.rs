#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod identifiers;
mod model;

pub use error::KonclaveDomainError;
pub use identifiers::{
    AdapterConsumerId, AdapterLeaseId, ConversationId, CredentialBindingHash, DeviceId,
    Ed25519PublicKey, Ed25519Signature, EnvelopeId, InvitationId, InvitationNonce,
    MembershipOperationId, MessageId, NotificationId, PairingId, RoutingId,
};
pub use model::{
    APPLICATION_PROTOCOL_MAJOR, APPLICATION_PROTOCOL_MINOR, AcknowledgeRequest, AddMember,
    ApplicationContent, ApplicationMessage, ChangeMemberRole, ConversationRole, ConversationState,
    DeliveryClass, DeviceCredentialBinding, Invitation, JoinProof, MAX_APPLICATION_MESSAGE_BYTES,
    MAX_CONSUMED_INVITATIONS, MAX_MEMBERS, MAX_MLS_KEY_PACKAGE_BYTES,
    MAX_PROTOBUF_TOP_LEVEL_FIELDS, MAX_RELAY_CONTROL_MESSAGE_BYTES, MAX_RELAY_ENVELOPE_BYTES,
    MAX_RELAY_PAYLOAD_BYTES, MAX_REPLAY_PAGE_BYTES, MAX_REPLAY_PAGE_SIZE, MAX_TEXT_BODY_BYTES,
    Member, MembershipAuthorization, MembershipChange, PairingOffer, ProtocolVersion,
    RelayEnvelope, RemoveMember, ReplayPage, ReplayRequest, SignatureScheme, StoredRelayEnvelope,
};
