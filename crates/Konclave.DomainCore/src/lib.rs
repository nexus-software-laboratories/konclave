#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod collaboration_policy;
mod error;
mod identifiers;
mod model;
mod pairing_rendezvous;
mod short_code_pairing;
mod short_code_relay;
mod trusted_devices;

pub use collaboration_policy::{
    COLLABORATION_POLICY_BUNDLE_MAJOR, COLLABORATION_POLICY_BUNDLE_MINOR,
    CollaborationPolicyBundle, CollaborationPolicyCost, CollaborationPolicyDecision,
    CollaborationPolicyDenialReason, CollaborationPolicyEffect,
    CollaborationPolicyEvaluationContext, CollaborationPolicyEvaluationRequest,
    CollaborationPolicyLimits, CollaborationPolicyProposal, CollaborationPolicyResponse,
    CollaborationPolicyResponseOutcome, CollaborationPolicyRevocation,
    CollaborationPolicyStatement, CollaborationPolicyTarget, CollaborationPolicyUsage,
    MAX_COLLABORATION_POLICY_ACTION_BYTES, MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
    MAX_COLLABORATION_POLICY_GUIDANCE_BYTES, MAX_COLLABORATION_POLICY_HARNESS_CLAIM_BYTES,
    MAX_COLLABORATION_POLICY_HARNESS_CLAIMS, MAX_COLLABORATION_POLICY_NAME_BYTES,
    MAX_COLLABORATION_POLICY_RESOURCE_BYTES, MAX_COLLABORATION_POLICY_STATEMENT_ID_BYTES,
    MAX_COLLABORATION_POLICY_STATEMENTS, evaluate_collaboration_policy,
    validate_collaboration_policy_name,
};
pub use error::KonclaveDomainError;
pub use identifiers::{
    AdapterConsumerId, AdapterLeaseId, CollaborationPolicyDigest, CollaborationPolicyProposalId,
    ConversationId, CredentialBindingHash, DeviceId, Ed25519PublicKey, Ed25519Signature,
    EnvelopeId, InvitationId, InvitationNonce, MembershipOperationId, MessageId, NotificationId,
    PairingContextHash, PairingId, PairingMessageId, PairingNonce, PairingRendezvousId,
    PairingRendezvousNonce, RepeatPairingOperationId, RoutingId, ShortCodeCapabilityTakeId,
    ShortCodePairingAttemptId, ShortCodePairingLocator, ShortCodePairingTranscriptHash,
};
pub use model::{
    APPLICATION_CAPABILITY_DIRECTED_REQUEST, APPLICATION_CAPABILITY_REPEAT_PAIRING,
    APPLICATION_PROTOCOL_MAJOR, APPLICATION_PROTOCOL_MINOR, AcknowledgeRequest, AddMember,
    ApplicationContent, ApplicationMessage, ChangeMemberRole, ConversationRole, ConversationState,
    DeliveryClass, DeviceCredentialBinding, DirectedRequest, Invitation, JoinProof,
    MAX_APPLICATION_MESSAGE_BYTES, MAX_CONSUMED_INVITATIONS, MAX_MEMBERS,
    MAX_MLS_KEY_PACKAGE_BYTES, MAX_PAIRING_CIPHERTEXT_BYTES, MAX_PAIRING_RELAY_ENDPOINT_BYTES,
    MAX_PAIRING_WELCOME_BYTES, MAX_PROTOBUF_TOP_LEVEL_FIELDS, MAX_RELAY_CONTROL_MESSAGE_BYTES,
    MAX_RELAY_ENVELOPE_BYTES, MAX_RELAY_PAYLOAD_BYTES, MAX_REPEAT_PAIRING_CAPABILITY_BYTES,
    MAX_REPLAY_PAGE_BYTES, MAX_REPLAY_PAGE_SIZE, MAX_TEXT_BODY_BYTES, Member,
    MembershipAuthorization, MembershipChange, PairingControl, PairingEnvelope,
    PairingInvitationPayload, PairingOffer, PairingSenderRole, PairingStage, PairingWelcomePayload,
    ProtocolVersion, RelayEnvelope, RemoveMember, RepeatPairingRequest, RepeatPairingResponse,
    ReplayPage, ReplayRequest, SignatureScheme, StoredRelayEnvelope,
};
pub use pairing_rendezvous::{
    MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES, MAX_PAIRING_RENDEZVOUS_RECORD_BYTES,
    PairingRendezvousRecord, PairingRendezvousTakeRequest,
};
pub use short_code_pairing::{
    MAX_SHORT_CODE_PAIRING_SAS, ShortCodeConfirmationEvent, ShortCodeConfirmationRecord,
    ShortCodeConfirmationState, ShortCodeIdentityRecord, ShortCodePairingSas,
    transition_short_code_confirmation,
};
pub use short_code_relay::{
    MAX_SHORT_CODE_RELAY_MESSAGE_BYTES, MAX_SHORT_CODE_RELAY_PAYLOAD_BYTES,
    MAX_SHORT_CODE_RELAY_SNAPSHOT_BYTES, MAX_SHORT_CODE_RELAY_STAGES, ShortCodeAttemptClaimRequest,
    ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest,
    ShortCodeAttemptSnapshot, ShortCodeCapabilityTakeRequest, ShortCodeRelayMessage,
    ShortCodeRelayStage,
};
pub use trusted_devices::{
    MAX_TRUSTED_DEVICE_ALIAS_BYTES, TrustedDeviceAlias, TrustedDeviceAliasDecision,
    TrustedDeviceBinding, TrustedDeviceBindingStatus, TrustedDeviceEvidence,
    TrustedDeviceResolution, decide_trusted_device_alias, resolve_trusted_device,
    trusted_device_binding_status,
};
