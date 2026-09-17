use KonclaveDomainCore::PairingRendezvousRecord;

use crate::{RelayError, RelayPrincipalId};

/// Maximum unexpired rendezvous records retained by one relay deployment.
pub const MAX_ACTIVE_PAIRING_RENDEZVOUS: usize = 10_000;

/// Maximum unexpired rendezvous records retained for one authenticated principal.
pub const MAX_ACTIVE_PAIRING_RENDEZVOUS_PER_PRINCIPAL: usize = 32;

/// Durable relay-owned metadata surrounding one opaque rendezvous record.
#[derive(PartialEq, Eq)]
pub struct StoredPairingRendezvous {
    owner: RelayPrincipalId,
    record: PairingRendezvousRecord,
}

impl StoredPairingRendezvous {
    /// Creates durable metadata for one accepted publish.
    #[must_use]
    pub const fn new(owner: RelayPrincipalId, record: PairingRendezvousRecord) -> Self {
        Self { owner, record }
    }

    /// Returns the authenticated principal that published this record.
    #[must_use]
    pub const fn owner(&self) -> RelayPrincipalId {
        self.owner
    }

    /// Returns the validated opaque record.
    #[must_use]
    pub const fn record(&self) -> &PairingRendezvousRecord {
        &self.record
    }

    /// Consumes the metadata and returns the validated opaque record.
    #[must_use]
    pub fn into_record(self) -> PairingRendezvousRecord {
        self.record
    }
}

/// Pure persistence action selected for one authenticated publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRendezvousPublishDecision {
    /// Insert the candidate under an unused lookup identifier.
    Insert,
    /// Return success without changing an identical active record.
    Identical,
    /// Remove an expired record and insert the candidate atomically.
    ReplaceExpired,
}

/// Pure persistence action selected for one authenticated take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRendezvousTakeDecision {
    /// Return and delete the active record in one transaction.
    Consume,
}

/// Selects the only permitted publish transition from validated transaction state.
///
/// `active_global_count` and `active_principal_count` must exclude expired rows.
///
/// # Errors
///
/// Returns a typed expiry, conflict, or capacity error.
pub fn decide_pairing_rendezvous_publish(
    principal: RelayPrincipalId,
    candidate: &PairingRendezvousRecord,
    existing: Option<&StoredPairingRendezvous>,
    now_unix_seconds: u64,
    active_global_count: usize,
    active_principal_count: usize,
) -> Result<PairingRendezvousPublishDecision, RelayError> {
    if candidate.expires_at_unix_seconds() <= now_unix_seconds {
        return Err(RelayError::ExpiredPairingRendezvous);
    }
    let replaces_expired = existing
        .is_some_and(|existing| existing.record().expires_at_unix_seconds() <= now_unix_seconds);
    if let Some(existing) = existing.filter(|_| !replaces_expired) {
        if existing.owner() == principal && existing.record() == candidate {
            return Ok(PairingRendezvousPublishDecision::Identical);
        }
        return Err(RelayError::PairingRendezvousConflict);
    }
    if active_global_count >= MAX_ACTIVE_PAIRING_RENDEZVOUS {
        return Err(RelayError::PairingRendezvousGlobalCapacityExceeded);
    }
    if active_principal_count >= MAX_ACTIVE_PAIRING_RENDEZVOUS_PER_PRINCIPAL {
        return Err(RelayError::PairingRendezvousPrincipalCapacityExceeded);
    }
    Ok(if replaces_expired {
        PairingRendezvousPublishDecision::ReplaceExpired
    } else {
        PairingRendezvousPublishDecision::Insert
    })
}

/// Selects the only permitted take transition from validated transaction state.
///
/// # Errors
///
/// Returns the same unavailable outcome for absent, expired, or consumed records.
pub fn decide_pairing_rendezvous_take(
    existing: Option<&StoredPairingRendezvous>,
    now_unix_seconds: u64,
) -> Result<PairingRendezvousTakeDecision, RelayError> {
    let existing = existing.ok_or(RelayError::PairingRendezvousUnavailable)?;
    if existing.record().expires_at_unix_seconds() <= now_unix_seconds {
        return Err(RelayError::PairingRendezvousUnavailable);
    }
    Ok(PairingRendezvousTakeDecision::Consume)
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::{
        PairingRendezvousId, PairingRendezvousNonce, PairingRendezvousRecord, ProtocolVersion,
    };

    use super::*;

    const NOW: u64 = 1_000;

    fn principal(value: u8) -> RelayPrincipalId {
        RelayPrincipalId::from_bytes([value; 32])
    }

    fn record(id: u8, ciphertext: u8, expires_at: u64) -> PairingRendezvousRecord {
        PairingRendezvousRecord::new(
            ProtocolVersion::application_v1(),
            PairingRendezvousId::from_bytes([id; 32]),
            expires_at,
            PairingRendezvousNonce::from_bytes([2; 12]),
            vec![ciphertext; 32],
        )
        .unwrap()
    }

    #[test]
    fn publish_decision_table_is_closed() {
        let owner = principal(1);
        let other = principal(2);
        let candidate = record(3, 4, NOW + 1);
        let identical =
            StoredPairingRendezvous::new(owner, record(3, 4, candidate.expires_at_unix_seconds()));
        let conflict =
            StoredPairingRendezvous::new(owner, record(3, 5, candidate.expires_at_unix_seconds()));
        let expired = StoredPairingRendezvous::new(owner, record(3, 4, NOW));

        let cases = [
            (
                decide_pairing_rendezvous_publish(owner, &candidate, None, NOW, 0, 0),
                Ok(PairingRendezvousPublishDecision::Insert),
            ),
            (
                decide_pairing_rendezvous_publish(owner, &candidate, Some(&identical), NOW, 1, 1),
                Ok(PairingRendezvousPublishDecision::Identical),
            ),
            (
                decide_pairing_rendezvous_publish(other, &candidate, Some(&identical), NOW, 1, 0),
                Err(RelayError::PairingRendezvousConflict),
            ),
            (
                decide_pairing_rendezvous_publish(owner, &candidate, Some(&conflict), NOW, 1, 1),
                Err(RelayError::PairingRendezvousConflict),
            ),
            (
                decide_pairing_rendezvous_publish(owner, &candidate, Some(&expired), NOW, 0, 0),
                Ok(PairingRendezvousPublishDecision::ReplaceExpired),
            ),
            (
                decide_pairing_rendezvous_publish(
                    owner,
                    &candidate,
                    Some(&expired),
                    NOW,
                    MAX_ACTIVE_PAIRING_RENDEZVOUS,
                    0,
                ),
                Err(RelayError::PairingRendezvousGlobalCapacityExceeded),
            ),
            (
                decide_pairing_rendezvous_publish(
                    owner,
                    &candidate,
                    None,
                    NOW,
                    MAX_ACTIVE_PAIRING_RENDEZVOUS,
                    0,
                ),
                Err(RelayError::PairingRendezvousGlobalCapacityExceeded),
            ),
            (
                decide_pairing_rendezvous_publish(
                    owner,
                    &candidate,
                    None,
                    NOW,
                    0,
                    MAX_ACTIVE_PAIRING_RENDEZVOUS_PER_PRINCIPAL,
                ),
                Err(RelayError::PairingRendezvousPrincipalCapacityExceeded),
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
        assert_eq!(
            decide_pairing_rendezvous_publish(owner, &record(3, 4, NOW), None, NOW, 0, 0,),
            Err(RelayError::ExpiredPairingRendezvous)
        );
    }

    #[test]
    fn take_decision_collapses_expired_and_unavailable() {
        let active = StoredPairingRendezvous::new(principal(1), record(3, 4, NOW + 1));
        let expired = StoredPairingRendezvous::new(principal(1), record(3, 4, NOW));

        assert_eq!(
            decide_pairing_rendezvous_take(Some(&active), NOW),
            Ok(PairingRendezvousTakeDecision::Consume)
        );
        assert_eq!(
            decide_pairing_rendezvous_take(Some(&expired), NOW),
            Err(RelayError::PairingRendezvousUnavailable)
        );
        assert_eq!(
            decide_pairing_rendezvous_take(None, NOW),
            Err(RelayError::PairingRendezvousUnavailable)
        );
    }
}
