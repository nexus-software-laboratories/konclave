use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ConversationId, DeviceId, Ed25519PublicKey, KonclaveDomainError};

/// Maximum UTF-8 bytes in one local trusted-device alias.
pub const MAX_TRUSTED_DEVICE_ALIAS_BYTES: usize = 32;

/// Canonical local name for one authenticated device root.
///
/// Aliases intentionally omit `Debug` so local operator labels do not enter
/// diagnostics by accident.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize, ZeroizeOnDrop)]
pub struct TrustedDeviceAlias(String);

impl TrustedDeviceAlias {
    /// Parses lowercase ASCII letters, digits, and interior hyphens.
    ///
    /// # Errors
    ///
    /// Returns a canonical-text or length error for empty, uppercase, whitespace,
    /// punctuation, leading/trailing-hyphen, or oversized input.
    pub fn parse(value: impl Into<String>) -> Result<Self, KonclaveDomainError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_TRUSTED_DEVICE_ALIAS_BYTES {
            return Err(KonclaveDomainError::OutOfRange {
                field: "trusted_device_alias",
                minimum: 1,
                maximum: MAX_TRUSTED_DEVICE_ALIAS_BYTES,
                actual: value.len(),
            });
        }
        let bytes = value.as_bytes();
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
        {
            return Err(KonclaveDomainError::NonCanonicalText {
                field: "trusted_device_alias",
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical local alias.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One local alias bound to an authenticated device identity and root key.
pub struct TrustedDeviceBinding {
    alias: TrustedDeviceAlias,
    device_id: DeviceId,
    device_root_public_key: Ed25519PublicKey,
}

impl TrustedDeviceBinding {
    /// Creates one binding from already authenticated device evidence.
    #[must_use]
    pub const fn new(
        alias: TrustedDeviceAlias,
        device_id: DeviceId,
        device_root_public_key: Ed25519PublicKey,
    ) -> Self {
        Self {
            alias,
            device_id,
            device_root_public_key,
        }
    }

    /// Returns the local alias.
    #[must_use]
    pub const fn alias(&self) -> &TrustedDeviceAlias {
        &self.alias
    }

    /// Returns the canonical device identifier.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the authenticated device root key.
    #[must_use]
    pub const fn device_root_public_key(&self) -> Ed25519PublicKey {
        self.device_root_public_key
    }
}

/// Current authenticated evidence that one device root remains reachable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedDeviceEvidence {
    conversation_id: ConversationId,
    device_id: DeviceId,
    device_root_public_key: Ed25519PublicKey,
    conversation_supports_repeat_pairing: bool,
}

impl TrustedDeviceEvidence {
    /// Creates evidence from one current authenticated conversation membership.
    #[must_use]
    pub const fn new(
        conversation_id: ConversationId,
        device_id: DeviceId,
        device_root_public_key: Ed25519PublicKey,
        conversation_supports_repeat_pairing: bool,
    ) -> Self {
        Self {
            conversation_id,
            device_id,
            device_root_public_key,
            conversation_supports_repeat_pairing,
        }
    }

    /// Returns the conversation that can bootstrap repeat pairing.
    #[must_use]
    pub const fn conversation_id(self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the authenticated member device.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the authenticated member root key.
    #[must_use]
    pub const fn device_root_public_key(self) -> Ed25519PublicKey {
        self.device_root_public_key
    }

    /// Returns whether every current member can decode repeat-pairing control.
    #[must_use]
    pub const fn conversation_supports_repeat_pairing(self) -> bool {
        self.conversation_supports_repeat_pairing
    }
}

/// Current trust status of one stored alias binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedDeviceBindingStatus {
    /// At least one current conversation authenticates the exact device root.
    Active,
    /// No current conversation contains the stored device identifier.
    Removed,
    /// Current evidence reuses the identifier with another root key.
    RootMismatch,
    /// The root is current, but no shared conversation negotiated repeat pairing.
    Unsupported,
}

/// Pure durable action for one explicit alias command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedDeviceAliasDecision {
    /// Insert a new alias and device binding.
    Insert,
    /// Accept an exact retry without rewriting state.
    Identical,
    /// Move this active device root from its prior alias to the requested alias.
    Rename,
    /// Replace an alias whose prior device root is no longer active.
    RebindStale,
}

/// Resolved active alias and deterministic authenticated bootstrap conversation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedDeviceResolution {
    device_id: DeviceId,
    device_root_public_key: Ed25519PublicKey,
    bootstrap_conversation_id: ConversationId,
}

impl TrustedDeviceResolution {
    /// Returns the canonical device identifier used for every wire authorization.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the authenticated root key retained by the local address book.
    #[must_use]
    pub const fn device_root_public_key(self) -> Ed25519PublicKey {
        self.device_root_public_key
    }

    /// Returns the stable lowest current conversation used as the bootstrap channel.
    #[must_use]
    pub const fn bootstrap_conversation_id(self) -> ConversationId {
        self.bootstrap_conversation_id
    }
}

/// Classifies whether a stored device root remains authenticated by current state.
#[must_use]
pub fn trusted_device_binding_status(
    binding: &TrustedDeviceBinding,
    evidence: &[TrustedDeviceEvidence],
) -> TrustedDeviceBindingStatus {
    let mut saw_device = false;
    let mut saw_matching_root = false;
    let mut saw_compatible_root = false;
    let mut saw_conflicting_root = false;
    for candidate in evidence {
        if candidate.device_id() != binding.device_id() {
            continue;
        }
        saw_device = true;
        if candidate.device_root_public_key() == binding.device_root_public_key() {
            saw_matching_root = true;
            saw_compatible_root |= candidate.conversation_supports_repeat_pairing();
        } else {
            saw_conflicting_root = true;
        }
    }
    if saw_conflicting_root {
        TrustedDeviceBindingStatus::RootMismatch
    } else if saw_compatible_root {
        TrustedDeviceBindingStatus::Active
    } else if saw_matching_root {
        TrustedDeviceBindingStatus::Unsupported
    } else if saw_device {
        TrustedDeviceBindingStatus::RootMismatch
    } else {
        TrustedDeviceBindingStatus::Removed
    }
}

/// Decides one alias insert, retry, rename, stale rebind, or collision.
///
/// The candidate must already be authenticated by current conversation evidence.
///
/// # Errors
///
/// Returns a removed/root-mismatch error for an unauthenticated candidate, or an
/// alias conflict when the requested alias still belongs to another active root.
pub fn decide_trusted_device_alias(
    candidate: &TrustedDeviceBinding,
    existing_by_alias: Option<&TrustedDeviceBinding>,
    existing_by_device: Option<&TrustedDeviceBinding>,
    evidence: &[TrustedDeviceEvidence],
) -> Result<TrustedDeviceAliasDecision, KonclaveDomainError> {
    resolve_trusted_device(candidate, evidence)?;
    if let Some(existing) = existing_by_alias {
        if existing.device_id() == candidate.device_id()
            && existing.device_root_public_key() == candidate.device_root_public_key()
        {
            return if existing.alias() == candidate.alias() {
                Ok(TrustedDeviceAliasDecision::Identical)
            } else {
                Ok(TrustedDeviceAliasDecision::Rename)
            };
        }
        return match trusted_device_binding_status(existing, evidence) {
            TrustedDeviceBindingStatus::Active | TrustedDeviceBindingStatus::Unsupported => {
                Err(KonclaveDomainError::TrustedDeviceAliasConflict)
            }
            TrustedDeviceBindingStatus::Removed | TrustedDeviceBindingStatus::RootMismatch => {
                Ok(TrustedDeviceAliasDecision::RebindStale)
            }
        };
    }
    if let Some(existing) = existing_by_device {
        if existing.device_root_public_key() == candidate.device_root_public_key() {
            return Ok(TrustedDeviceAliasDecision::Rename);
        }
        return match trusted_device_binding_status(existing, evidence) {
            TrustedDeviceBindingStatus::Active | TrustedDeviceBindingStatus::Unsupported => {
                Err(KonclaveDomainError::TrustedDeviceRootMismatch)
            }
            TrustedDeviceBindingStatus::Removed | TrustedDeviceBindingStatus::RootMismatch => {
                Ok(TrustedDeviceAliasDecision::RebindStale)
            }
        };
    }
    Ok(TrustedDeviceAliasDecision::Insert)
}

/// Resolves one stored alias only while its exact root remains a current member.
///
/// # Errors
///
/// Returns a removed or root-mismatch error instead of falling back to stale state.
pub fn resolve_trusted_device(
    binding: &TrustedDeviceBinding,
    evidence: &[TrustedDeviceEvidence],
) -> Result<TrustedDeviceResolution, KonclaveDomainError> {
    match trusted_device_binding_status(binding, evidence) {
        TrustedDeviceBindingStatus::Removed => {
            return Err(KonclaveDomainError::TrustedDeviceRemoved);
        }
        TrustedDeviceBindingStatus::RootMismatch => {
            return Err(KonclaveDomainError::TrustedDeviceRootMismatch);
        }
        TrustedDeviceBindingStatus::Unsupported => {
            return Err(KonclaveDomainError::TrustedDeviceRepeatPairingUnsupported);
        }
        TrustedDeviceBindingStatus::Active => {}
    }
    let bootstrap_conversation_id = evidence
        .iter()
        .filter(|candidate| {
            candidate.device_id() == binding.device_id()
                && candidate.device_root_public_key() == binding.device_root_public_key()
                && candidate.conversation_supports_repeat_pairing()
        })
        .map(|candidate| candidate.conversation_id())
        .min()
        .ok_or(KonclaveDomainError::TrustedDeviceRemoved)?;
    Ok(TrustedDeviceResolution {
        device_id: binding.device_id(),
        device_root_public_key: binding.device_root_public_key(),
        bootstrap_conversation_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(value: &str) -> TrustedDeviceAlias {
        TrustedDeviceAlias::parse(value).unwrap()
    }

    fn binding(name: &str, device: u8, root: u8) -> TrustedDeviceBinding {
        TrustedDeviceBinding::new(
            alias(name),
            DeviceId::from_bytes([device; DeviceId::LENGTH]),
            Ed25519PublicKey::from_bytes([root; Ed25519PublicKey::LENGTH]),
        )
    }

    fn evidence(conversation: u8, device: u8, root: u8) -> TrustedDeviceEvidence {
        TrustedDeviceEvidence::new(
            ConversationId::from_bytes([conversation; ConversationId::LENGTH]),
            DeviceId::from_bytes([device; DeviceId::LENGTH]),
            Ed25519PublicKey::from_bytes([root; Ed25519PublicKey::LENGTH]),
            true,
        )
    }

    #[test]
    fn aliases_are_canonical_and_never_case_folded() {
        assert_eq!(alias("alienware").as_str(), "alienware");
        assert_eq!(alias("desk-2").as_str(), "desk-2");
        for invalid in ["", "Alienware", "-desk", "desk-", "desk_top", "desk top"] {
            assert!(TrustedDeviceAlias::parse(invalid).is_err());
        }
        assert!(TrustedDeviceAlias::parse("a".repeat(MAX_TRUSTED_DEVICE_ALIAS_BYTES + 1)).is_err());
    }

    #[test]
    fn alias_decision_table_covers_collision_rename_and_stale_rebind() {
        let candidate = binding("alienware", 1, 2);
        let active = [evidence(9, 1, 2), evidence(8, 3, 4)];
        assert_eq!(
            decide_trusted_device_alias(&candidate, None, None, &active),
            Ok(TrustedDeviceAliasDecision::Insert)
        );
        let identical = binding("alienware", 1, 2);
        assert_eq!(
            decide_trusted_device_alias(&candidate, Some(&identical), Some(&identical), &active),
            Ok(TrustedDeviceAliasDecision::Identical)
        );
        let prior_name = binding("old-name", 1, 2);
        assert_eq!(
            decide_trusted_device_alias(&candidate, None, Some(&prior_name), &active),
            Ok(TrustedDeviceAliasDecision::Rename)
        );
        let active_collision = binding("alienware", 3, 4);
        assert_eq!(
            decide_trusted_device_alias(&candidate, Some(&active_collision), None, &active),
            Err(KonclaveDomainError::TrustedDeviceAliasConflict)
        );
        let stale_collision = binding("alienware", 5, 6);
        assert_eq!(
            decide_trusted_device_alias(&candidate, Some(&stale_collision), None, &active),
            Ok(TrustedDeviceAliasDecision::RebindStale)
        );
        assert_eq!(
            decide_trusted_device_alias(
                &candidate,
                Some(&stale_collision),
                Some(&prior_name),
                &active,
            ),
            Ok(TrustedDeviceAliasDecision::RebindStale)
        );
    }

    #[test]
    fn resolution_fails_closed_for_removal_or_root_change() {
        let stored = binding("alienware", 1, 2);
        assert_eq!(
            resolve_trusted_device(&stored, &[]).err(),
            Some(KonclaveDomainError::TrustedDeviceRemoved)
        );
        assert_eq!(
            resolve_trusted_device(&stored, &[evidence(7, 1, 3)]).err(),
            Some(KonclaveDomainError::TrustedDeviceRootMismatch)
        );
        assert_eq!(
            resolve_trusted_device(
                &stored,
                &[TrustedDeviceEvidence::new(
                    ConversationId::from_bytes([6; ConversationId::LENGTH]),
                    stored.device_id(),
                    stored.device_root_public_key(),
                    false,
                )],
            )
            .err(),
            Some(KonclaveDomainError::TrustedDeviceRepeatPairingUnsupported)
        );
        let resolved =
            resolve_trusted_device(&stored, &[evidence(9, 1, 2), evidence(7, 1, 2)]).unwrap();
        assert_eq!(
            resolved.bootstrap_conversation_id(),
            ConversationId::from_bytes([7; ConversationId::LENGTH])
        );
        assert_eq!(resolved.device_id(), stored.device_id());
    }
}
