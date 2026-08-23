use KonclaveDomainCore::KonclaveDomainError;
use thiserror::Error;

/// Stable failures produced by Konclave cryptographic operations.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KonclaveCryptographicError {
    /// The configured provider failed one cryptographic operation.
    #[error("cryptographic provider failed during {operation}")]
    ProviderFailure { operation: &'static str },

    /// A public credential binding does not authenticate its claimed device.
    #[error("device credential binding is not authentic")]
    InvalidCredentialBinding,

    /// An invitation does not authenticate its claimed issuer.
    #[error("invitation signature is not authentic")]
    InvalidInvitationSignature,

    /// An invitation was presented at or after its expiration time.
    #[error("invitation is expired")]
    ExpiredInvitation,

    /// An invitation was presented by a device other than its intended recipient.
    #[error("invitation targets a different device")]
    InvitationDeviceMismatch,

    /// An invitation was presented for another conversation.
    #[error("invitation targets a different conversation")]
    InvitationConversationMismatch,

    /// MLS rejected an operation or message.
    #[error("MLS operation failed during {operation}")]
    MlsFailure { operation: &'static str },

    /// The receiver ratchet has already consumed this application generation.
    #[error("MLS application message was already processed")]
    ApplicationMessageAlreadyProcessed,

    /// A validated domain value could not be encoded for MLS authentication.
    #[error("protocol contract encoding failed")]
    ProtocolContractFailure,

    /// Sealed secret storage rejected a cryptographic state operation.
    #[error("sealed secret storage failed during {operation}")]
    SecretStorageFailure { operation: &'static str },

    /// A MLS wire message exceeds the applicable Konclave bound.
    #[error("MLS {message_kind} exceeds {maximum} bytes (actual: {actual})")]
    MlsMessageTooLarge {
        message_kind: &'static str,
        maximum: usize,
        actual: usize,
    },

    /// A MLS wire message has a different semantic type than the selected operation.
    #[error("unexpected MLS message type for {operation}")]
    UnexpectedMlsMessage { operation: &'static str },

    /// MLS state identifies a different Konclave conversation.
    #[error("MLS group does not match the Konclave conversation")]
    MlsConversationMismatch,

    /// MLS state selected a ciphersuite outside the accepted initial profile.
    #[error("MLS group uses an unsupported ciphersuite")]
    MlsCipherSuiteMismatch,

    /// A required verified device credential has not been registered.
    #[error("verified device credential is unavailable")]
    CredentialNotRegistered,

    /// A MLS signing identity does not match its verified device credential.
    #[error("MLS signing identity does not match the verified credential")]
    CredentialSigningKeyMismatch,

    /// A membership commit was attempted without an exact application authorization.
    #[error("membership commit has no prepared application authorization")]
    MembershipAuthorizationRequired,

    /// MLS proposals do not match the prepared application authorization.
    #[error("MLS proposals do not match the membership authorization")]
    MembershipAuthorizationMismatch,

    /// A local MLS commit is already awaiting relay acceptance.
    #[error("a MLS commit is already pending")]
    PendingCommitExists,

    /// A one-time join proof is already prepared for this client.
    #[error("a MLS join is already prepared")]
    PendingJoinExists,

    /// No local MLS commit is awaiting acceptance or rejection.
    #[error("no MLS commit is pending")]
    PendingCommitNotFound,

    /// This device has been removed from the conversation.
    #[error("device is no longer an active conversation member")]
    RemovedFromConversation,

    /// An add-member commit did not create exactly one Welcome message.
    #[error("add-member commit did not produce one Welcome message")]
    MissingWelcome,

    /// A Welcome does not carry authenticated Konclave conversation state.
    #[error("Welcome is missing authenticated conversation state")]
    MissingAuthenticatedState,

    /// MLS roster identities do not match authenticated conversation state.
    #[error("MLS roster does not match authenticated conversation state")]
    RosterMismatch,

    /// Internal authorization state could not be accessed.
    #[error("cryptographic authorization state is unavailable")]
    AuthorizationStateUnavailable,

    /// Key material presented for a keyed operation is unusable.
    #[error("keyed authentication material is invalid")]
    InvalidKeyMaterial,

    /// Domain validation rejected a cryptographic input or result.
    #[error(transparent)]
    Domain(#[from] KonclaveDomainError),
}

impl KonclaveCryptographicError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ProviderFailure { .. } => "cryptographic_provider_failure",
            Self::InvalidCredentialBinding => "invalid_credential_binding",
            Self::InvalidInvitationSignature => "invalid_invitation_signature",
            Self::ExpiredInvitation => "expired_invitation",
            Self::InvitationDeviceMismatch => "invitation_device_mismatch",
            Self::InvitationConversationMismatch => "invitation_conversation_mismatch",
            Self::MlsFailure { .. } => "mls_failure",
            Self::ApplicationMessageAlreadyProcessed => "application_message_already_processed",
            Self::ProtocolContractFailure => "protocol_contract_failure",
            Self::SecretStorageFailure { .. } => "secret_storage_failure",
            Self::MlsMessageTooLarge { .. } => "mls_message_too_large",
            Self::UnexpectedMlsMessage { .. } => "unexpected_mls_message",
            Self::MlsConversationMismatch => "mls_conversation_mismatch",
            Self::MlsCipherSuiteMismatch => "mls_ciphersuite_mismatch",
            Self::CredentialNotRegistered => "credential_not_registered",
            Self::CredentialSigningKeyMismatch => "credential_signing_key_mismatch",
            Self::MembershipAuthorizationRequired => "membership_authorization_required",
            Self::MembershipAuthorizationMismatch => "membership_authorization_mismatch",
            Self::PendingCommitExists => "pending_commit_exists",
            Self::PendingJoinExists => "pending_join_exists",
            Self::PendingCommitNotFound => "pending_commit_not_found",
            Self::RemovedFromConversation => "removed_from_conversation",
            Self::MissingWelcome => "missing_welcome",
            Self::MissingAuthenticatedState => "missing_authenticated_state",
            Self::RosterMismatch => "mls_roster_mismatch",
            Self::AuthorizationStateUnavailable => "authorization_state_unavailable",
            Self::InvalidKeyMaterial => "invalid_key_material",
            Self::Domain(error) => error.code(),
        }
    }
}
