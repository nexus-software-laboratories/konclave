use KonclaveClientLibrary::{
    EnrollmentRequestId, RelayAccessCredential, RelayEndpoint, RelayEnrollmentOutcome,
    RelayEnrollmentRequest, RelayEnrollmentResponse, RelayPrincipalId,
};
use KonclaveCryptographicCore::fill_random;
use KonclaveDomainCore::ProtocolVersion;
use zeroize::Zeroizing;

use super::*;

const ENROLLMENT_INTENT_MAGIC: &[u8; 4] = b"KEI1";
const MAX_ENROLLMENT_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_ENROLLMENT_INTENT_BYTES: usize = 8 * 1024;
const MAX_SEALED_ENROLLMENT_INTENT_BYTES: usize = MAX_ENROLLMENT_INTENT_BYTES + 64;

/// One exact profile-generated relay principal registration awaiting promotion.
pub(crate) struct PendingRelayEnrollment {
    endpoint: RelayEndpoint,
    request: RelayEnrollmentRequest,
    credential: RelayAccessCredential,
}

impl PendingRelayEnrollment {
    #[must_use]
    pub(crate) fn endpoint(&self) -> &RelayEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn request(&self) -> RelayEnrollmentRequest {
        self.request
    }

    #[must_use]
    pub(crate) fn into_credential(self) -> RelayAccessCredential {
        self.credential
    }
}

impl ProfileStore {
    /// Reserves or reopens one exact sealed enrollment intent for this profile.
    ///
    /// # Errors
    ///
    /// Returns a configuration, endpoint, randomness, sealing, conflict, corruption,
    /// or storage error. A different endpoint never replaces pending work.
    pub(crate) fn reserve_relay_enrollment(
        &self,
        endpoint: &RelayEndpoint,
    ) -> Result<PendingRelayEnrollment, ProfileStoreError> {
        validate_endpoint(endpoint)?;
        let (active, pending) = self.relay_enrollment_presence()?;
        match (active, pending) {
            (true, true) => return Err(ProfileStoreError::CorruptData),
            (true, false) => return Err(ProfileStoreError::RelayAlreadyConfigured),
            (false, true) => {
                let Some(pending) = self.pending_relay_enrollment()? else {
                    return if self.active_relay_configuration()?.is_some() {
                        Err(ProfileStoreError::RelayAlreadyConfigured)
                    } else {
                        Err(ProfileStoreError::InvalidTransition)
                    };
                };
                return if pending.endpoint.as_str() == endpoint.as_str() {
                    Ok(pending)
                } else {
                    Err(ProfileStoreError::RelayEnrollmentConflict)
                };
            }
            (false, false) => {}
        }

        let mut request_id = [0_u8; EnrollmentRequestId::LENGTH];
        fill_random(&mut request_id).map_err(|_| ProfileStoreError::Cryptographic)?;
        let mut credential_bytes = Zeroizing::new([0_u8; RelayAccessCredential::LENGTH]);
        fill_random(credential_bytes.as_mut()).map_err(|_| ProfileStoreError::Cryptographic)?;
        self.reserve_relay_enrollment_with_material(
            endpoint,
            EnrollmentRequestId::from_bytes(request_id),
            RelayAccessCredential::from_bytes(*credential_bytes),
        )
    }

    /// Reopens the pending intent, when present.
    ///
    /// # Errors
    ///
    /// Returns a bounds, endpoint, authentication, credential, corruption, or
    /// storage error.
    pub(crate) fn pending_relay_enrollment(
        &self,
    ) -> Result<Option<PendingRelayEnrollment>, ProfileStoreError> {
        let connection = self.lock()?;
        let metadata: Option<(i64, i64, i64, i64)> = connection
            .query_row(
                "SELECT
                    length(CAST(endpoint AS BLOB)),
                    length(request_id),
                    length(principal_id),
                    length(sealed_intent)
                 FROM daemon_relay_enrollment
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((endpoint_length, request_length, principal_length, sealed_length)) = metadata
        else {
            return Ok(None);
        };
        validate_pending_lengths(
            endpoint_length,
            request_length,
            principal_length,
            sealed_length,
        )?;
        let (endpoint, request_id, principal_id, sealed): (String, Vec<u8>, Vec<u8>, Vec<u8>) =
            connection
                .query_row(
                    "SELECT endpoint, request_id, principal_id, sealed_intent
                     FROM daemon_relay_enrollment
                     WHERE singleton_id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        drop(connection);
        if endpoint.len() != usize::try_from(endpoint_length).unwrap_or_default()
            || request_id.len() != usize::try_from(request_length).unwrap_or_default()
            || principal_id.len() != usize::try_from(principal_length).unwrap_or_default()
            || sealed.len() != usize::try_from(sealed_length).unwrap_or_default()
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let endpoint =
            RelayEndpoint::parse(&endpoint).map_err(|_| ProfileStoreError::CorruptData)?;
        validate_endpoint(&endpoint)?;
        let request_id = EnrollmentRequestId::from_slice(&request_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let principal_id = RelayPrincipalId::from_slice(&principal_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let request = RelayEnrollmentRequest::new(
            ProtocolVersion::application_v1(),
            request_id,
            principal_id,
        );
        let blob = SealedBlob::from_bytes(sealed).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &enrollment_context(&self.locked_profile.profile_id, &endpoint, request)?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let credential = decode_enrollment_intent(
            &self.sealer,
            &self.locked_profile.profile_id,
            &endpoint,
            request,
            &plaintext,
        )?;
        Ok(Some(PendingRelayEnrollment {
            endpoint,
            request,
            credential,
        }))
    }

    /// Atomically promotes one exact registered principal into active relay config.
    ///
    /// # Errors
    ///
    /// Returns a conflict, missing intent, credential, corruption, transition, or
    /// storage error. Repeating an already committed exact promotion is idempotent.
    pub(crate) fn promote_relay_enrollment(
        &self,
        endpoint: &RelayEndpoint,
        response: RelayEnrollmentResponse,
    ) -> Result<(), ProfileStoreError> {
        validate_endpoint(endpoint)?;
        match response.outcome() {
            RelayEnrollmentOutcome::Registered | RelayEnrollmentOutcome::AlreadyRegistered => {}
            _ => return Err(ProfileStoreError::RelayEnrollmentConflict),
        }
        let (active, pending) = self.relay_enrollment_presence()?;
        match (active, pending) {
            (true, false) => {
                let (active_endpoint, credential) = self
                    .active_relay_configuration()?
                    .ok_or(ProfileStoreError::InvalidTransition)?;
                return if active_endpoint.as_str() == endpoint.as_str()
                    && credential.principal_id() == response.principal_id()
                {
                    Ok(())
                } else {
                    Err(ProfileStoreError::RelayEnrollmentConflict)
                };
            }
            (true, true) => return Err(ProfileStoreError::CorruptData),
            (false, false) => return Err(ProfileStoreError::InvalidTransition),
            (false, true) => {}
        }
        let Some(pending) = self.pending_relay_enrollment()? else {
            return match self.active_relay_configuration()? {
                Some((active_endpoint, credential))
                    if active_endpoint.as_str() == endpoint.as_str()
                        && credential.principal_id() == response.principal_id() =>
                {
                    Ok(())
                }
                _ => Err(ProfileStoreError::RelayEnrollmentConflict),
            };
        };
        if pending.endpoint.as_str() != endpoint.as_str()
            || pending.request.version() != response.version()
            || pending.request.request_id() != response.request_id()
            || pending.request.principal_id() != response.principal_id()
        {
            return Err(ProfileStoreError::RelayEnrollmentConflict);
        }
        let credential_blob = pending
            .credential
            .seal(
                &self.sealer,
                self.locked_profile.profile_id.as_bytes(),
                endpoint,
            )
            .map_err(|_| ProfileStoreError::Credential)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let active_count: i64 = transaction
            .query_row(
                "SELECT count(*) FROM daemon_profile
                 WHERE singleton_id = 1
                   AND relay_endpoint IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if active_count != 0 {
            drop(transaction);
            drop(connection);
            return match self.active_relay_configuration()? {
                Some((active_endpoint, credential))
                    if active_endpoint.as_str() == endpoint.as_str()
                        && credential.principal_id() == response.principal_id() =>
                {
                    Ok(())
                }
                _ => Err(ProfileStoreError::RelayEnrollmentConflict),
            };
        }
        let changed = transaction
            .execute(
                "UPDATE daemon_profile
                 SET relay_endpoint = ?1, sealed_relay_credential = ?2
                 WHERE singleton_id = 1
                   AND relay_endpoint IS NULL
                   AND sealed_relay_credential IS NULL",
                params![endpoint.as_str(), credential_blob.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let removed = transaction
            .execute(
                "DELETE FROM daemon_relay_enrollment
                 WHERE singleton_id = 1
                   AND endpoint = ?1
                   AND request_id = ?2
                   AND principal_id = ?3",
                params![
                    endpoint.as_str(),
                    response.request_id().as_bytes().as_slice(),
                    response.principal_id().as_bytes().as_slice(),
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if removed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    fn reserve_relay_enrollment_with_material(
        &self,
        endpoint: &RelayEndpoint,
        request_id: EnrollmentRequestId,
        credential: RelayAccessCredential,
    ) -> Result<PendingRelayEnrollment, ProfileStoreError> {
        validate_endpoint(endpoint)?;
        let request = RelayEnrollmentRequest::new(
            ProtocolVersion::application_v1(),
            request_id,
            credential.principal_id(),
        );
        let blob = encode_enrollment_intent(
            &self.sealer,
            &self.locked_profile.profile_id,
            endpoint,
            request,
            &credential,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let active_count: i64 = transaction
            .query_row(
                "SELECT count(*) FROM daemon_profile
                 WHERE singleton_id = 1 AND relay_endpoint IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if active_count != 0 {
            return Err(ProfileStoreError::RelayAlreadyConfigured);
        }
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO daemon_relay_enrollment (
                    singleton_id,
                    endpoint,
                    request_id,
                    principal_id,
                    sealed_intent
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    endpoint.as_str(),
                    request.request_id().as_bytes().as_slice(),
                    request.principal_id().as_bytes().as_slice(),
                    blob.as_bytes(),
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if inserted == 1 {
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
            return Ok(PendingRelayEnrollment {
                endpoint: endpoint.clone(),
                request,
                credential,
            });
        }
        drop(transaction);
        drop(connection);
        let pending = self
            .pending_relay_enrollment()?
            .ok_or(ProfileStoreError::InvalidTransition)?;
        if pending.endpoint.as_str() == endpoint.as_str() {
            Ok(pending)
        } else {
            Err(ProfileStoreError::RelayEnrollmentConflict)
        }
    }

    fn active_relay_configuration(
        &self,
    ) -> Result<Option<(RelayEndpoint, RelayAccessCredential)>, ProfileStoreError> {
        match self.relay_configuration() {
            Ok(configuration) => Ok(Some(configuration)),
            Err(ProfileStoreError::RelayNotConfigured) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn relay_enrollment_presence(&self) -> Result<(bool, bool), ProfileStoreError> {
        let connection = self.lock()?;
        let (active, pending): (i64, i64) = connection
            .query_row(
                "SELECT
                    CASE
                        WHEN relay_endpoint IS NULL
                         AND sealed_relay_credential IS NULL
                        THEN 0
                        WHEN relay_endpoint IS NOT NULL
                         AND sealed_relay_credential IS NOT NULL
                        THEN 1
                        ELSE -1
                    END,
                    (SELECT count(*) FROM daemon_relay_enrollment)
                 FROM daemon_profile
                 WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        match (active, pending) {
            (0 | 1, 0 | 1) => Ok((active == 1, pending == 1)),
            _ => Err(ProfileStoreError::CorruptData),
        }
    }
}

pub(super) fn initialize_enrollment_schema(
    connection: &Connection,
) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_relay_enrollment (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                endpoint TEXT NOT NULL,
                request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 16),
                principal_id BLOB NOT NULL UNIQUE CHECK (length(principal_id) = 32),
                sealed_intent BLOB NOT NULL
             );
             PRAGMA user_version = 12;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn validate_endpoint(endpoint: &RelayEndpoint) -> Result<(), ProfileStoreError> {
    if endpoint.as_str().is_empty() || endpoint.as_str().len() > MAX_ENROLLMENT_ENDPOINT_BYTES {
        Err(ProfileStoreError::RelayEnrollmentConflict)
    } else {
        Ok(())
    }
}

fn validate_pending_lengths(
    endpoint: i64,
    request: i64,
    principal: i64,
    sealed: i64,
) -> Result<(), ProfileStoreError> {
    if !(1..=i64::try_from(MAX_ENROLLMENT_ENDPOINT_BYTES).unwrap_or(i64::MAX)).contains(&endpoint)
        || request != EnrollmentRequestId::LENGTH as i64
        || principal != RelayPrincipalId::LENGTH as i64
        || !(1..=i64::try_from(MAX_SEALED_ENROLLMENT_INTENT_BYTES).unwrap_or(i64::MAX))
            .contains(&sealed)
    {
        Err(ProfileStoreError::CorruptData)
    } else {
        Ok(())
    }
}

fn encode_enrollment_intent(
    sealer: &SecretSealer,
    profile_id: &ProfileId,
    endpoint: &RelayEndpoint,
    request: RelayEnrollmentRequest,
    credential: &RelayAccessCredential,
) -> Result<SealedBlob, ProfileStoreError> {
    let credential_blob = credential
        .seal(sealer, profile_id.as_bytes(), endpoint)
        .map_err(|_| ProfileStoreError::Credential)?;
    let endpoint_bytes = endpoint.as_str().as_bytes();
    let endpoint_length =
        u16::try_from(endpoint_bytes.len()).map_err(|_| ProfileStoreError::CorruptData)?;
    let credential_length = u32::try_from(credential_blob.as_bytes().len())
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let capacity = ENROLLMENT_INTENT_MAGIC
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(endpoint_bytes.len()))
        .and_then(|value| value.checked_add(EnrollmentRequestId::LENGTH))
        .and_then(|value| value.checked_add(RelayPrincipalId::LENGTH))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(credential_blob.as_bytes().len()))
        .ok_or(ProfileStoreError::CorruptData)?;
    if capacity > MAX_ENROLLMENT_INTENT_BYTES {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
    plaintext.extend_from_slice(ENROLLMENT_INTENT_MAGIC);
    plaintext.extend_from_slice(&endpoint_length.to_be_bytes());
    plaintext.extend_from_slice(endpoint_bytes);
    plaintext.extend_from_slice(request.request_id().as_bytes());
    plaintext.extend_from_slice(request.principal_id().as_bytes());
    plaintext.extend_from_slice(&credential_length.to_be_bytes());
    plaintext.extend_from_slice(credential_blob.as_bytes());
    sealer
        .seal(
            &enrollment_context(profile_id, endpoint, request)?,
            &plaintext,
        )
        .map_err(|_| ProfileStoreError::Credential)
}

fn decode_enrollment_intent(
    sealer: &SecretSealer,
    profile_id: &ProfileId,
    endpoint: &RelayEndpoint,
    request: RelayEnrollmentRequest,
    plaintext: &[u8],
) -> Result<RelayAccessCredential, ProfileStoreError> {
    let fixed = ENROLLMENT_INTENT_MAGIC.len()
        + 2
        + EnrollmentRequestId::LENGTH
        + RelayPrincipalId::LENGTH
        + 4;
    if plaintext.len() < fixed || plaintext.len() > MAX_ENROLLMENT_INTENT_BYTES {
        return Err(ProfileStoreError::CorruptData);
    }
    let endpoint_length = usize::from(u16::from_be_bytes(
        plaintext[4..6]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    ));
    let request_offset = 6_usize
        .checked_add(endpoint_length)
        .ok_or(ProfileStoreError::CorruptData)?;
    let principal_offset = request_offset
        .checked_add(EnrollmentRequestId::LENGTH)
        .ok_or(ProfileStoreError::CorruptData)?;
    let length_offset = principal_offset
        .checked_add(RelayPrincipalId::LENGTH)
        .ok_or(ProfileStoreError::CorruptData)?;
    let credential_offset = length_offset
        .checked_add(4)
        .ok_or(ProfileStoreError::CorruptData)?;
    if credential_offset > plaintext.len()
        || &plaintext[..4] != ENROLLMENT_INTENT_MAGIC
        || &plaintext[6..request_offset] != endpoint.as_str().as_bytes()
        || &plaintext[request_offset..principal_offset] != request.request_id().as_bytes()
        || &plaintext[principal_offset..length_offset] != request.principal_id().as_bytes()
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let credential_length = usize::try_from(u32::from_be_bytes(
        plaintext[length_offset..credential_offset]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    ))
    .map_err(|_| ProfileStoreError::CorruptData)?;
    if credential_offset.checked_add(credential_length) != Some(plaintext.len()) {
        return Err(ProfileStoreError::CorruptData);
    }
    let credential_blob = SealedBlob::from_slice(&plaintext[credential_offset..])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let credential =
        RelayAccessCredential::open(sealer, profile_id.as_bytes(), endpoint, &credential_blob)
            .map_err(|_| ProfileStoreError::Credential)?;
    if credential.principal_id() != request.principal_id() {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(credential)
}

fn enrollment_context(
    profile_id: &ProfileId,
    endpoint: &RelayEndpoint,
    request: RelayEnrollmentRequest,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::RelayEnrollmentIntent,
        &[
            profile_id.as_bytes(),
            endpoint.as_str().as_bytes(),
            request.request_id().as_bytes(),
            request.principal_id().as_bytes(),
        ],
    )
    .map_err(|_| ProfileStoreError::Credential)
}

#[cfg(test)]
mod tests {
    use KonclaveSecretStorage::ExternalWrappingKeyProvider;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([3; 32])).unwrap()
    }

    fn open_store(root: &Path, profile: &str) -> ProfileStore {
        LockedProfile::acquire(root, ProfileId::parse(profile).unwrap())
            .unwrap()
            .open_store(sealer())
            .unwrap()
    }

    fn endpoint(value: &str) -> RelayEndpoint {
        RelayEndpoint::parse(value).unwrap()
    }

    fn response(
        request: RelayEnrollmentRequest,
        outcome: RelayEnrollmentOutcome,
    ) -> RelayEnrollmentResponse {
        RelayEnrollmentResponse::new(
            request.version(),
            request.request_id(),
            request.principal_id(),
            outcome,
        )
    }

    #[test]
    fn reservation_reopens_exact_material_and_rejects_another_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let first_endpoint = endpoint("https://relay.example.com/base");
        let second_endpoint = endpoint("https://other.example.com/base");
        let store = open_store(root.path(), "reservation");
        let pending = store
            .reserve_relay_enrollment_with_material(
                &first_endpoint,
                EnrollmentRequestId::from_bytes([4; EnrollmentRequestId::LENGTH]),
                RelayAccessCredential::from_bytes([5; RelayAccessCredential::LENGTH]),
            )
            .unwrap();
        let request = pending.request();
        assert_eq!(pending.endpoint().as_str(), first_endpoint.as_str());
        assert_eq!(
            pending.into_credential().principal_id(),
            request.principal_id()
        );
        assert_eq!(
            store.reserve_relay_enrollment(&second_endpoint).err(),
            Some(ProfileStoreError::RelayEnrollmentConflict)
        );
        drop(store);

        let reopened = open_store(root.path(), "reservation");
        let pending = reopened.pending_relay_enrollment().unwrap().unwrap();
        assert_eq!(pending.request(), request);
        assert_eq!(pending.endpoint().as_str(), first_endpoint.as_str());
        assert_eq!(
            pending.into_credential().principal_id(),
            request.principal_id()
        );
    }

    #[test]
    fn promotion_is_atomic_exact_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let endpoint = endpoint("https://relay.example.com/base");
        let store = open_store(root.path(), "promotion");
        let pending = store
            .reserve_relay_enrollment_with_material(
                &endpoint,
                EnrollmentRequestId::from_bytes([6; EnrollmentRequestId::LENGTH]),
                RelayAccessCredential::from_bytes([7; RelayAccessCredential::LENGTH]),
            )
            .unwrap();
        let request = pending.request();
        let conflicting = RelayEnrollmentRequest::new(
            request.version(),
            request.request_id(),
            RelayPrincipalId::from_bytes([8; RelayPrincipalId::LENGTH]),
        );
        assert_eq!(
            store
                .promote_relay_enrollment(
                    &endpoint,
                    response(conflicting, RelayEnrollmentOutcome::Registered),
                )
                .unwrap_err(),
            ProfileStoreError::RelayEnrollmentConflict
        );
        assert!(store.pending_relay_enrollment().unwrap().is_some());
        assert_eq!(
            store.relay_configuration().err(),
            Some(ProfileStoreError::RelayNotConfigured)
        );

        let registered = response(request, RelayEnrollmentOutcome::Registered);
        store
            .promote_relay_enrollment(&endpoint, registered)
            .unwrap();
        assert!(store.pending_relay_enrollment().unwrap().is_none());
        let (active_endpoint, active_credential) = store.relay_configuration().unwrap();
        assert_eq!(active_endpoint.as_str(), endpoint.as_str());
        assert_eq!(active_credential.principal_id(), request.principal_id());
        store
            .promote_relay_enrollment(
                &endpoint,
                response(request, RelayEnrollmentOutcome::AlreadyRegistered),
            )
            .unwrap();
        assert_eq!(
            store.reserve_relay_enrollment(&endpoint).err(),
            Some(ProfileStoreError::RelayAlreadyConfigured)
        );
    }

    #[test]
    fn concurrent_reservation_and_promotion_converge_on_one_identity() {
        let root = tempfile::tempdir().unwrap();
        let endpoint = endpoint("https://relay.example.com/base");
        let store = Arc::new(open_store(root.path(), "concurrent"));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let reservations = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let endpoint = endpoint.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.reserve_relay_enrollment(&endpoint).unwrap().request()
                })
            })
            .collect::<Vec<_>>();
        let requests = reservations
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(requests.iter().all(|request| *request == requests[0]));

        let response = response(requests[0], RelayEnrollmentOutcome::Registered);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let promotions = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let endpoint = endpoint.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.promote_relay_enrollment(&endpoint, response)
                })
            })
            .collect::<Vec<_>>();
        for promotion in promotions {
            promotion.join().unwrap().unwrap();
        }
        assert!(store.pending_relay_enrollment().unwrap().is_none());
        assert_eq!(
            store.relay_configuration().unwrap().1.principal_id(),
            response.principal_id()
        );
    }

    #[test]
    fn lost_registration_result_reopens_and_promotes_exact_retry() {
        let root = tempfile::tempdir().unwrap();
        let endpoint = endpoint("https://relay.example.com/base");
        let store = open_store(root.path(), "lost-response");
        let request = store.reserve_relay_enrollment(&endpoint).unwrap().request();
        drop(store);

        let reopened = open_store(root.path(), "lost-response");
        let retry = reopened.pending_relay_enrollment().unwrap().unwrap();
        assert_eq!(retry.request(), request);
        assert_eq!(
            retry.into_credential().principal_id(),
            request.principal_id()
        );
        reopened
            .promote_relay_enrollment(
                &endpoint,
                response(request, RelayEnrollmentOutcome::AlreadyRegistered),
            )
            .unwrap();
        assert!(reopened.pending_relay_enrollment().unwrap().is_none());
        assert_eq!(
            reopened.relay_configuration().unwrap().1.principal_id(),
            request.principal_id()
        );
    }

    #[test]
    fn pending_metadata_substitution_fails_closed() {
        for mutation in [
            "UPDATE daemon_relay_enrollment
             SET endpoint = 'https://other.example.com/'",
            "UPDATE daemon_relay_enrollment SET request_id = zeroblob(16)",
            "UPDATE daemon_relay_enrollment SET principal_id = zeroblob(32)",
        ] {
            let root = tempfile::tempdir().unwrap();
            let store = open_store(root.path(), "substitution");
            store
                .reserve_relay_enrollment_with_material(
                    &endpoint("https://relay.example.com/base"),
                    EnrollmentRequestId::from_bytes([9; EnrollmentRequestId::LENGTH]),
                    RelayAccessCredential::from_bytes([10; RelayAccessCredential::LENGTH]),
                )
                .unwrap();
            store.lock().unwrap().execute(mutation, []).unwrap();
            assert_eq!(
                store.pending_relay_enrollment().err(),
                Some(ProfileStoreError::CorruptData)
            );
        }
    }

    #[test]
    fn raw_database_and_wal_never_contain_profile_token() {
        let root = tempfile::tempdir().unwrap();
        let endpoint = endpoint("https://relay.example.com/base");
        let token = [0xa7; RelayAccessCredential::LENGTH];
        let encoded = URL_SAFE_NO_PAD.encode(token);
        let store = open_store(root.path(), "opacity");
        let database_path = store.locked_profile.profile_database_path();
        let request = store
            .reserve_relay_enrollment_with_material(
                &endpoint,
                EnrollmentRequestId::from_bytes([0xb8; EnrollmentRequestId::LENGTH]),
                RelayAccessCredential::from_bytes(token),
            )
            .unwrap()
            .request();
        store
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .unwrap();
        assert_storage_opaque(&database_path, &token, encoded.as_bytes());
        store
            .promote_relay_enrollment(
                &endpoint,
                response(request, RelayEnrollmentOutcome::Registered),
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .unwrap();
        assert_storage_opaque(&database_path, &token, encoded.as_bytes());
    }

    #[test]
    fn version_eleven_migrates_to_current_transactionally() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            let path = store.locked_profile.profile_database_path();
            store
                .lock()
                .unwrap()
                .execute_batch(
                    "DROP TABLE daemon_local_request_outcome;
                     DROP TABLE daemon_relay_enrollment;
                     PRAGMA user_version = 11;",
                )
                .unwrap();
            path
        };

        let store = LockedProfile::acquire(root.path(), profile_id.clone())
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        drop(store);

        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE daemon_local_request_outcome;
                 DROP TABLE daemon_relay_enrollment;
                 CREATE TABLE daemon_relay_enrollment (sentinel INTEGER);
                 PRAGMA user_version = 11;",
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let sentinel_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_relay_enrollment')
                 WHERE name = 'sentinel'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 11);
        assert_eq!(sentinel_columns, 1);
    }

    fn assert_storage_opaque(database_path: &Path, token: &[u8], encoded: &[u8]) {
        let mut paths = vec![database_path.to_path_buf()];
        for suffix in ["-wal", "-shm"] {
            let mut path = database_path.as_os_str().to_os_string();
            path.push(suffix);
            paths.push(PathBuf::from(path));
        }
        for path in paths {
            if !path.exists() {
                continue;
            }
            let bytes = std::fs::read(path).unwrap();
            assert!(!bytes.windows(token.len()).any(|window| window == token));
            assert!(!bytes.windows(encoded.len()).any(|window| window == encoded));
        }
    }
}
