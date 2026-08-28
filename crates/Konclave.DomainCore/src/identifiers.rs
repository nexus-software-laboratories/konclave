use crate::KonclaveDomainError;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! define_fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $length:expr, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Required byte length for this identifier or public value.
            pub const LENGTH: usize = $length;

            /// Creates a value from an array that already has the required length.
            #[must_use]
            pub const fn from_bytes(value: [u8; $length]) -> Self {
                Self(value)
            }

            /// Parses a value from a byte slice.
            ///
            /// # Errors
            ///
            /// Returns [`KonclaveDomainError::InvalidLength`] when `value` does not
            /// contain exactly [`Self::LENGTH`] bytes.
            pub fn from_slice(value: &[u8]) -> Result<Self, KonclaveDomainError> {
                let bytes = value.try_into().map_err(|_| {
                    KonclaveDomainError::InvalidLength {
                        field: $field,
                        expected: $length,
                        actual: value.len(),
                    }
                })?;
                Ok(Self(bytes))
            }

            /// Returns the canonical bytes without transferring ownership.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            /// Returns the canonical bytes and consumes the value.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; $length] {
                self.0
            }
        }
    };
}

define_fixed_bytes!(
    /// Digest-derived identifier for one device root public key.
    DeviceId,
    32,
    "device_id"
);
define_fixed_bytes!(
    /// Opaque identifier for one conversation.
    ConversationId,
    32,
    "conversation_id"
);
define_fixed_bytes!(
    /// Identifier for one authenticated application message.
    MessageId,
    16,
    "message_id"
);
define_fixed_bytes!(
    /// Identifier for one idempotent relay submission.
    EnvelopeId,
    16,
    "envelope_id"
);
define_fixed_bytes!(
    /// Stable identifier for one local remote-delivery event.
    NotificationId,
    16,
    "notification_id"
);
define_fixed_bytes!(
    /// Identifier for one harness-neutral local adapter consumer.
    AdapterConsumerId,
    16,
    "adapter_consumer_id"
);
define_fixed_bytes!(
    /// Identifier for one active local adapter consumer lease.
    AdapterLeaseId,
    16,
    "adapter_lease_id"
);
define_fixed_bytes!(
    /// Identifier for one invitation authorization.
    InvitationId,
    16,
    "invitation_id"
);
define_fixed_bytes!(
    /// Identifier for one pairing exchange between two devices.
    PairingId,
    16,
    "pairing_id"
);
define_fixed_bytes!(
    /// Stable identifier for one logical record in a pairing exchange.
    PairingMessageId,
    16,
    "pairing_message_id"
);
define_fixed_bytes!(
    /// Public AES-GCM nonce carried by one pairing envelope.
    PairingNonce,
    12,
    "pairing_nonce"
);
define_fixed_bytes!(
    /// Hash binding one signed offer to its secret-derived route and relay endpoint.
    PairingContextHash,
    32,
    "pairing_context_hash"
);
define_fixed_bytes!(
    /// Opaque identifier used only for relay routing.
    RoutingId,
    32,
    "routing_id"
);
define_fixed_bytes!(
    /// Identifier for one application-authorized membership operation.
    MembershipOperationId,
    16,
    "membership_operation_id"
);
define_fixed_bytes!(
    /// SHA-256 digest of a canonical device credential binding.
    CredentialBindingHash,
    32,
    "credential_binding_hash"
);
define_fixed_bytes!(
    /// SHA-256 digest of one canonical collaboration-policy bundle.
    CollaborationPolicyDigest,
    32,
    "collaboration_policy_digest"
);
define_fixed_bytes!(
    /// Identifier for one collaboration-policy proposal exchange.
    CollaborationPolicyProposalId,
    16,
    "collaboration_policy_proposal_id"
);
define_fixed_bytes!(
    /// Public Ed25519 verification key.
    Ed25519PublicKey,
    32,
    "ed25519_public_key"
);
define_fixed_bytes!(
    /// Public Ed25519 signature bytes.
    Ed25519Signature,
    64,
    "ed25519_signature"
);

/// Cryptographically random bearer capability used by one invitation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InvitationNonce([u8; 32]);

impl InvitationNonce {
    /// Required byte length for an invitation nonce.
    pub const LENGTH: usize = 32;

    /// Creates a nonce from an array that already has the required length.
    #[must_use]
    pub const fn from_bytes(value: [u8; Self::LENGTH]) -> Self {
        Self(value)
    }

    /// Parses a nonce from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveDomainError::InvalidLength`] when `value` is not
    /// exactly [`Self::LENGTH`] bytes.
    pub fn from_slice(value: &[u8]) -> Result<Self, KonclaveDomainError> {
        let bytes = value
            .try_into()
            .map_err(|_| KonclaveDomainError::InvalidLength {
                field: "invitation_nonce",
                expected: Self::LENGTH,
                actual: value.len(),
            })?;
        Ok(Self(bytes))
    }

    /// Returns the nonce bytes without transferring ownership.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}
