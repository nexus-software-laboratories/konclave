use super::*;

impl ProfileStore {
    pub(crate) fn relay_migration_identity(
        &self,
    ) -> Result<(RelayEndpoint, RelayPrincipalId), ProfileStoreError> {
        let (endpoint, credential) = self.relay_configuration()?;
        Ok((endpoint, credential.principal_id()))
    }

    pub(crate) fn migrate_relay_endpoint(
        &self,
        source: &RelayEndpoint,
        destination: &RelayEndpoint,
        expected_principal: RelayPrincipalId,
    ) -> Result<bool, ProfileStoreError> {
        let (active_endpoint, credential) = self.relay_configuration()?;
        if credential.principal_id() != expected_principal {
            return Err(ProfileStoreError::RelayMigrationConflict);
        }
        if active_endpoint.as_str() == destination.as_str() {
            return Ok(false);
        }
        if active_endpoint.as_str() != source.as_str() || source.as_str() == destination.as_str() {
            return Err(ProfileStoreError::RelayMigrationConflict);
        }
        let migrated = credential
            .seal(
                &self.sealer,
                self.locked_profile.profile_id.as_bytes(),
                destination,
            )
            .map_err(|_| ProfileStoreError::Credential)?;
        if self
            .lock()?
            .execute(
                "UPDATE daemon_profile
                 SET relay_endpoint = ?1, sealed_relay_credential = ?2
                 WHERE singleton_id = 1
                   AND relay_endpoint = ?3
                   AND sealed_relay_credential IS NOT NULL",
                params![destination.as_str(), migrated.as_bytes(), source.as_str(),],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::RelayMigrationConflict);
        }
        let (reopened_endpoint, reopened_credential) = self.relay_configuration()?;
        if reopened_endpoint.as_str() != destination.as_str()
            || reopened_credential.principal_id() != expected_principal
        {
            return Err(ProfileStoreError::RelayMigrationConflict);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use KonclaveSecretStorage::ExternalWrappingKeyProvider;

    use super::*;

    fn endpoint(value: &str) -> RelayEndpoint {
        RelayEndpoint::parse(value).unwrap()
    }

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([3; 32])).unwrap()
    }

    fn open_test_store(root: &Path, profile: &str) -> ProfileStore {
        LockedProfile::acquire(root, ProfileId::parse(profile).unwrap())
            .unwrap()
            .open_store(sealer())
            .unwrap()
    }

    #[test]
    fn relay_endpoint_migration_reseals_one_exact_credential() {
        let root = tempfile::tempdir().unwrap();
        let source = endpoint("http://127.0.0.1:43180");
        let destination = endpoint("https://relay.example.com");
        let credential = RelayAccessCredential::from_bytes([7; 32]);
        let principal = credential.principal_id();
        let store = open_test_store(root.path(), "migration-profile");
        store.configure_relay(&source, &credential).unwrap();

        assert!(
            store
                .migrate_relay_endpoint(&source, &destination, principal)
                .unwrap()
        );
        let (migrated_endpoint, migrated_principal) = store.relay_migration_identity().unwrap();
        assert_eq!(migrated_endpoint.as_str(), destination.as_str());
        assert_eq!(migrated_principal, principal);
        assert!(
            !store
                .migrate_relay_endpoint(&source, &destination, principal)
                .unwrap()
        );
        drop(store);

        let reopened = open_test_store(root.path(), "migration-profile");
        let (reopened_endpoint, reopened_principal) = reopened.relay_migration_identity().unwrap();
        assert_eq!(reopened_endpoint.as_str(), destination.as_str());
        assert_eq!(reopened_principal, principal);
    }

    #[test]
    fn relay_endpoint_migration_rejects_source_or_principal_substitution() {
        let root = tempfile::tempdir().unwrap();
        let source = endpoint("http://127.0.0.1:43180");
        let destination = endpoint("https://relay.example.com");
        let credential = RelayAccessCredential::from_bytes([8; 32]);
        let principal = credential.principal_id();
        let store = open_test_store(root.path(), "migration-profile");
        store.configure_relay(&source, &credential).unwrap();

        assert_eq!(
            store
                .migrate_relay_endpoint(
                    &endpoint("https://other.example.com"),
                    &destination,
                    principal,
                )
                .unwrap_err(),
            ProfileStoreError::RelayMigrationConflict
        );
        assert_eq!(
            store
                .migrate_relay_endpoint(
                    &source,
                    &destination,
                    RelayPrincipalId::from_bytes([9; 32]),
                )
                .unwrap_err(),
            ProfileStoreError::RelayMigrationConflict
        );
        let (retained_endpoint, retained_principal) = store.relay_migration_identity().unwrap();
        assert_eq!(retained_endpoint.as_str(), source.as_str());
        assert_eq!(retained_principal, principal);
    }
}
