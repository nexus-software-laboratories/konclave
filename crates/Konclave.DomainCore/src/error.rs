use thiserror::Error;

/// Stable validation failures for Konclave domain contracts.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KonclaveDomainError {
    /// A fixed-size identifier or public cryptographic value has the wrong length.
    #[error("{field} must contain exactly {expected} bytes (actual: {actual})")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    /// A protocol version uses the reserved zero major version.
    #[error("protocol major version must be positive")]
    InvalidProtocolMajor,

    /// A required numeric value uses the reserved zero value.
    #[error("{field} must be positive")]
    ZeroValue { field: &'static str },

    /// A bounded collection or byte sequence is outside its accepted range.
    #[error("{field} count must be from {minimum} through {maximum} (actual: {actual})")]
    OutOfRange {
        field: &'static str,
        minimum: usize,
        maximum: usize,
        actual: usize,
    },

    /// A required text field is empty after validation.
    #[error("{field} cannot be empty")]
    EmptyText { field: &'static str },

    /// A text field exceeds its UTF-8 byte limit.
    #[error("{field} exceeds {maximum} UTF-8 bytes (actual: {actual})")]
    TextTooLong {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },

    /// A collection repeats an identifier whose uniqueness is part of the contract.
    #[error("{field} contains a duplicate identifier")]
    DuplicateIdentifier { field: &'static str },

    /// An invitation and device credential refer to different device identities.
    #[error("join credential does not match the device authorized by the invitation")]
    MismatchedInvitedDevice,

    /// An invitation and device credential refer to different conversations.
    #[error("join credential does not match the conversation authorized by the invitation")]
    MismatchedInvitedConversation,

    /// A membership snapshot claims a member joined after the represented epoch.
    #[error("member joined at epoch {joined_epoch} after state epoch {state_epoch}")]
    MemberJoinedAfterStateEpoch { joined_epoch: u64, state_epoch: u64 },

    /// A conversation membership snapshot contains no administrator.
    #[error("conversation membership must contain at least one administrator")]
    MissingAdministrator,

    /// A relay envelope has an epoch field that contradicts its delivery class.
    #[error("expected_parent_epoch is invalid for delivery class {delivery_class}")]
    InvalidExpectedParentEpoch { delivery_class: &'static str },

    /// A replay page is not strictly ordered by durable cursor.
    #[error("replay page cursors must be strictly increasing")]
    InvalidReplayOrder,
}

impl KonclaveDomainError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLength { .. } => "invalid_length",
            Self::InvalidProtocolMajor => "invalid_protocol_major",
            Self::ZeroValue { .. } | Self::OutOfRange { .. } | Self::TextTooLong { .. } => {
                "out_of_range"
            }
            Self::EmptyText { .. } => "empty_value",
            Self::DuplicateIdentifier { .. } => "duplicate_identifier",
            Self::MismatchedInvitedDevice => "mismatched_invited_device",
            Self::MismatchedInvitedConversation => "mismatched_invited_conversation",
            Self::MemberJoinedAfterStateEpoch { .. } => "member_joined_after_state_epoch",
            Self::MissingAdministrator => "missing_administrator",
            Self::InvalidExpectedParentEpoch { .. } => "invalid_expected_parent_epoch",
            Self::InvalidReplayOrder => "invalid_replay_order",
        }
    }
}
