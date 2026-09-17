#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod collaboration_policy;
mod error;
mod hmac;
mod identity;
mod local_service;
mod mls;
mod pairing;
mod pairing_rendezvous;
mod short_code_pairing;

pub use collaboration_policy::{
    VerifiedCollaborationPolicyProposal, derive_collaboration_policy_digest,
    derive_collaboration_policy_proposal_message_id,
    derive_collaboration_policy_response_message_id, verify_collaboration_policy_proposal,
};
pub use error::KonclaveCryptographicError;
pub use hmac::{HMAC_SHA256_TAG_LENGTH, HmacSha256Key, fill_random};
pub use identity::{
    ConversationSigningMaterial, DeviceIdentity, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding, verify_invitation, verify_pairing_control,
    verify_pairing_offer,
};
pub use local_service::{
    LOCAL_SERVICE_SIGNING_SEED_LENGTH, LocalServiceIdentity, LocalServiceSigningSeed,
    derive_local_service_session_consumer_id, verify_local_service_signature,
};
pub use mls::{
    AppliedMembershipCommit, DecryptedApplicationMessage, MlsApplicationMessage, MlsCommit,
    MlsConversation, MlsConversationClient, MlsWelcome, OutboundMembershipCommit,
    PreparedJoinedConversation,
};
pub use pairing::{PAIRING_SECRET_BYTES, PairingKeySchedule, PairingSecret};
pub use pairing_rendezvous::{
    MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES, PAIRING_RENDEZVOUS_TOKEN_BYTES,
    PairingRendezvousKeySchedule, PairingRendezvousSecret,
};
pub use short_code_pairing::{
    MAX_SHORT_CODE_PAIRING_PLAINTEXT_BYTES, ShortCodeOpaqueClientLogin, ShortCodeOpaqueServerLogin,
    ShortCodeOpaqueServerRecord, ShortCodeOpaqueSession, ShortCodePairingChannel,
    ShortCodePairingCode, derive_short_code_pairing_transcript_hash,
    generate_short_code_pairing_attempt_id,
};

#[cfg(test)]
mod tests;
