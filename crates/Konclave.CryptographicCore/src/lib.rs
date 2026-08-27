#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod hmac;
mod identity;
mod local_service;
mod mls;
mod pairing;

pub use error::KonclaveCryptographicError;
pub use hmac::{HMAC_SHA256_TAG_LENGTH, HmacSha256Key, fill_random};
pub use identity::{
    ConversationSigningMaterial, DeviceIdentity, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding, verify_invitation, verify_pairing_control,
    verify_pairing_offer,
};
pub use local_service::{
    LOCAL_SERVICE_SIGNING_SEED_LENGTH, LocalServiceIdentity, LocalServiceSigningSeed,
    verify_local_service_signature,
};
pub use mls::{
    AppliedMembershipCommit, DecryptedApplicationMessage, MlsApplicationMessage, MlsCommit,
    MlsConversation, MlsConversationClient, MlsWelcome, OutboundMembershipCommit,
    PreparedJoinedConversation,
};
pub use pairing::{PAIRING_SECRET_BYTES, PairingKeySchedule, PairingSecret};

#[cfg(test)]
mod tests;
