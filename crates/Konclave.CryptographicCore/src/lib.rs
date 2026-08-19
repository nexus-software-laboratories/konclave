#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod identity;
mod mls;

pub use error::KonclaveCryptographicError;
pub use identity::{
    ConversationSigningMaterial, DeviceIdentity, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding, verify_invitation,
};
pub use mls::{
    AppliedMembershipCommit, DecryptedApplicationMessage, MlsApplicationMessage, MlsCommit,
    MlsConversation, MlsConversationClient, MlsWelcome, OutboundMembershipCommit,
};

#[cfg(test)]
mod tests;
