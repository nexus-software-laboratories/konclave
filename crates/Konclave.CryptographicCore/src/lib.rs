#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod hmac;
mod identity;
mod mls;

pub use error::KonclaveCryptographicError;
pub use hmac::{HMAC_SHA256_TAG_LENGTH, HmacSha256Key};
pub use identity::{
    ConversationSigningMaterial, DeviceIdentity, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding, verify_invitation,
};
pub use mls::{
    AppliedMembershipCommit, DecryptedApplicationMessage, MlsApplicationMessage, MlsCommit,
    MlsConversation, MlsConversationClient, MlsWelcome, OutboundMembershipCommit,
    PreparedJoinedConversation,
};

#[cfg(test)]
mod tests;
