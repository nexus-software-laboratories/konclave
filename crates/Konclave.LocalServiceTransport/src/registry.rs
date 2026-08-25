use crate::error::LocalServiceTransportError;
use crate::handshake::{AdapterAuthorizationRegistry, AdapterRegistration};
use crate::identifiers::{AdapterKeyId, AdapterKeyVersion};

/// Largest number of adapter registrations one in-memory registry may hold.
pub const MAX_ADAPTER_REGISTRATIONS: usize = 256;

/// An in-memory snapshot of the installation's adapter registrations.
///
/// The shared service loads registrations from installation-owned state and hands
/// this to the handshake. Rotation adds a new version before the old one is removed,
/// and revocation removes every version for a key, so lookup answers with exactly the
/// record that is active right now and never falls back to another version.
#[derive(Debug, Default)]
pub struct InMemoryAdapterRegistry {
    entries: Vec<RegistryEntry>,
}

#[derive(Debug)]
struct RegistryEntry {
    adapter_key_id: AdapterKeyId,
    adapter_key_version: AdapterKeyVersion,
    registration: AdapterRegistration,
}

impl InMemoryAdapterRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Registers one active adapter key version.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::DuplicateRegistration`] when this exact
    /// key and version already exists, and
    /// [`LocalServiceTransportError::RegistrationLimitReached`] when the registry is
    /// full.
    pub fn register(
        &mut self,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
        registration: AdapterRegistration,
    ) -> Result<(), LocalServiceTransportError> {
        if self.find(adapter_key_id, adapter_key_version).is_some() {
            return Err(LocalServiceTransportError::DuplicateRegistration);
        }
        if self.entries.len() == MAX_ADAPTER_REGISTRATIONS {
            return Err(LocalServiceTransportError::RegistrationLimitReached);
        }
        self.entries.push(RegistryEntry {
            adapter_key_id,
            adapter_key_version,
            registration,
        });
        Ok(())
    }

    /// Removes every version registered for one adapter key.
    ///
    /// Returns the number of versions removed, which is zero for a key that was never
    /// registered or has already been revoked.
    pub fn revoke(&mut self, adapter_key_id: AdapterKeyId) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|entry| entry.adapter_key_id != adapter_key_id);
        before - self.entries.len()
    }

    /// Removes exactly one registered key version.
    ///
    /// Returns whether a record was removed, so a rotation that retires a version can
    /// tell an already-retired version from an unexpected state.
    pub fn retire_version(
        &mut self,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
    ) -> bool {
        let before = self.entries.len();
        self.entries.retain(|entry| {
            entry.adapter_key_id != adapter_key_id
                || entry.adapter_key_version != adapter_key_version
        });
        before != self.entries.len()
    }

    fn find(
        &self,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
    ) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| {
            entry.adapter_key_id == adapter_key_id
                && entry.adapter_key_version == adapter_key_version
        })
    }
}

impl AdapterAuthorizationRegistry for InMemoryAdapterRegistry {
    fn active_registration(
        &self,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
    ) -> Option<AdapterRegistration> {
        self.find(adapter_key_id, adapter_key_version)
            .map(|entry| entry.registration.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryAdapterRegistry, MAX_ADAPTER_REGISTRATIONS};
    use crate::error::LocalServiceTransportError;
    use crate::handshake::{AdapterAuthorizationRegistry, AdapterRegistration};
    use crate::identifiers::{
        AdapterKeyId, AdapterKeyVersion, HarnessKind, ProfileAuthorization, ServiceProfileId,
    };
    use KonclaveDomainCore::Ed25519PublicKey;

    fn registration() -> AdapterRegistration {
        AdapterRegistration::new(
            Ed25519PublicKey::from_bytes([1_u8; Ed25519PublicKey::LENGTH]),
            HarnessKind::Copilot,
            ProfileAuthorization::Profile(ServiceProfileId::parse("alice").unwrap()),
        )
    }

    fn key(seed: u8) -> AdapterKeyId {
        AdapterKeyId::from_bytes([seed; AdapterKeyId::LENGTH])
    }

    fn version(value: u32) -> AdapterKeyVersion {
        AdapterKeyVersion::new(value).unwrap()
    }

    #[test]
    fn a_registered_key_version_resolves_to_its_record() {
        let mut registry = InMemoryAdapterRegistry::new();
        registry
            .register(key(1), version(1), registration())
            .unwrap();
        assert_eq!(
            registry.active_registration(key(1), version(1)),
            Some(registration())
        );
    }

    #[test]
    fn an_unregistered_key_or_version_never_falls_back() {
        let mut registry = InMemoryAdapterRegistry::new();
        registry
            .register(key(1), version(2), registration())
            .unwrap();
        assert_eq!(registry.active_registration(key(1), version(1)), None);
        assert_eq!(registry.active_registration(key(1), version(3)), None);
        assert_eq!(registry.active_registration(key(2), version(2)), None);
    }

    #[test]
    fn rotation_keeps_both_versions_until_the_old_one_retires() {
        let mut registry = InMemoryAdapterRegistry::new();
        registry
            .register(key(1), version(1), registration())
            .unwrap();
        registry
            .register(key(1), version(2), registration())
            .unwrap();
        assert!(registry.active_registration(key(1), version(1)).is_some());
        assert!(registry.retire_version(key(1), version(1)));
        assert!(!registry.retire_version(key(1), version(1)));
        assert_eq!(registry.active_registration(key(1), version(1)), None);
        assert!(registry.active_registration(key(1), version(2)).is_some());
    }

    #[test]
    fn revocation_removes_every_version_for_one_key() {
        let mut registry = InMemoryAdapterRegistry::new();
        registry
            .register(key(1), version(1), registration())
            .unwrap();
        registry
            .register(key(1), version(2), registration())
            .unwrap();
        registry
            .register(key(2), version(1), registration())
            .unwrap();
        assert_eq!(registry.revoke(key(1)), 2);
        assert_eq!(registry.revoke(key(1)), 0);
        assert_eq!(registry.active_registration(key(1), version(1)), None);
        assert_eq!(registry.active_registration(key(1), version(2)), None);
        assert!(registry.active_registration(key(2), version(1)).is_some());
    }

    #[test]
    fn a_duplicate_registration_is_rejected() {
        let mut registry = InMemoryAdapterRegistry::new();
        registry
            .register(key(1), version(1), registration())
            .unwrap();
        assert_eq!(
            registry
                .register(key(1), version(1), registration())
                .unwrap_err(),
            LocalServiceTransportError::DuplicateRegistration
        );
    }

    #[test]
    fn the_registry_is_bounded() {
        let mut registry = InMemoryAdapterRegistry::new();
        for index in 0..MAX_ADAPTER_REGISTRATIONS {
            registry
                .register(
                    key(1),
                    version(u32::try_from(index).unwrap() + 1),
                    registration(),
                )
                .unwrap();
        }
        assert_eq!(
            registry
                .register(key(2), version(1), registration())
                .unwrap_err(),
            LocalServiceTransportError::RegistrationLimitReached
        );
        assert_eq!(
            registry
                .register(key(1), version(1), registration())
                .unwrap_err(),
            LocalServiceTransportError::DuplicateRegistration
        );
    }
}
