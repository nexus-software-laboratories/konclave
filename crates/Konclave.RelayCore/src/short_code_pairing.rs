use std::collections::BTreeMap;

use KonclaveDomainCore::{
    ShortCodeAttemptClaimRequest, ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest,
    ShortCodeAttemptReadRequest, ShortCodeCapabilityTakeId, ShortCodeCapabilityTakeRequest,
    ShortCodeRelayStage,
};

use crate::{RelayError, RelayPrincipalId};

/// Relay-wide bound on active short-code attempts.
pub const MAX_ACTIVE_SHORT_CODE_ATTEMPTS: usize = 1_000;
/// Per-creator bound on active short-code attempts.
pub const MAX_ACTIVE_SHORT_CODE_ATTEMPTS_PER_CREATOR: usize = 8;
/// Per-principal claim bound within one claim window.
pub const MAX_SHORT_CODE_CLAIMS_PER_PRINCIPAL_WINDOW: usize = 10;
/// Per-locator claim bound within one claim window.
pub const MAX_SHORT_CODE_CLAIMS_PER_LOCATOR_WINDOW: usize = 5;
/// Sliding short-code claim accounting window.
pub const SHORT_CODE_CLAIM_WINDOW_SECONDS: u64 = 10 * 60;
/// Maximum active lifetime for one short-code attempt.
pub const SHORT_CODE_ATTEMPT_LIFETIME_SECONDS: u64 = 10 * 60;

/// Pure relay state for one bounded short-code attempt.
pub struct StoredShortCodeAttempt {
    owner: RelayPrincipalId,
    claimant: Option<RelayPrincipalId>,
    publish: ShortCodeAttemptPublishRequest,
    messages: BTreeMap<ShortCodeRelayStage, Vec<u8>>,
    cancelled: bool,
    capability_take_id: Option<ShortCodeCapabilityTakeId>,
}

impl StoredShortCodeAttempt {
    /// Creates one unclaimed active attempt.
    #[must_use]
    pub fn new(owner: RelayPrincipalId, publish: ShortCodeAttemptPublishRequest) -> Self {
        Self {
            owner,
            claimant: None,
            publish,
            messages: BTreeMap::new(),
            cancelled: false,
            capability_take_id: None,
        }
    }

    /// Returns the authenticated creator.
    #[must_use]
    pub const fn owner(&self) -> RelayPrincipalId {
        self.owner
    }

    /// Returns the authenticated claimant when claimed.
    #[must_use]
    pub const fn claimant(&self) -> Option<RelayPrincipalId> {
        self.claimant
    }

    /// Returns the immutable publish contract.
    #[must_use]
    pub const fn publish(&self) -> ShortCodeAttemptPublishRequest {
        self.publish
    }

    /// Returns one exact opaque stage.
    #[must_use]
    pub fn message(&self, stage: ShortCodeRelayStage) -> Option<&[u8]> {
        self.messages.get(&stage).map(Vec::as_slice)
    }

    /// Returns all exact opaque stages.
    #[must_use]
    pub fn messages(&self) -> &BTreeMap<ShortCodeRelayStage, Vec<u8>> {
        &self.messages
    }

    /// Reports whether either participant cancelled the attempt.
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Reports whether the capability was consumed.
    #[must_use]
    pub const fn capability_consumed(&self) -> bool {
        self.capability_take_id.is_some()
    }

    /// Returns the stable logical capability retrieval identifier when consumed.
    #[must_use]
    pub const fn capability_take_id(&self) -> Option<ShortCodeCapabilityTakeId> {
        self.capability_take_id
    }

    /// Records the one claimant and its credential request.
    ///
    /// # Errors
    ///
    /// Returns invalid stored data when the attempt was already claimed.
    pub fn set_claim(
        &mut self,
        claimant: RelayPrincipalId,
        payload: Vec<u8>,
    ) -> Result<(), RelayError> {
        if self.claimant.is_some()
            || self
                .messages
                .contains_key(&ShortCodeRelayStage::CredentialRequest)
        {
            return Err(RelayError::InvalidStoredData);
        }
        self.messages
            .insert(ShortCodeRelayStage::CredentialRequest, payload);
        self.claimant = Some(claimant);
        Ok(())
    }

    /// Records one later opaque stage.
    ///
    /// # Errors
    ///
    /// Returns invalid stored data for the claim stage or a duplicate stage.
    pub fn insert_message(
        &mut self,
        stage: ShortCodeRelayStage,
        payload: Vec<u8>,
    ) -> Result<(), RelayError> {
        if stage == ShortCodeRelayStage::CredentialRequest || self.messages.contains_key(&stage) {
            return Err(RelayError::InvalidStoredData);
        }
        self.messages.insert(stage, payload);
        Ok(())
    }

    /// Marks the attempt cancelled.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Marks the capability consumed.
    pub fn consume_capability(&mut self, take_id: ShortCodeCapabilityTakeId) {
        self.capability_take_id = Some(take_id);
    }
}

/// Result of evaluating one publish against current bounded state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodePublishDecision {
    /// Insert a new attempt.
    Insert,
    /// Accept an exact creator retry.
    Identical,
}

/// Result of evaluating one atomic locator claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeClaimDecision {
    /// Commit the first claimant.
    Claim,
    /// Accept an exact claimant retry.
    Identical,
}

/// Result of evaluating one opaque stage publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeMessageDecision {
    /// Insert a new stage.
    Insert,
    /// Accept an exact role-matching stage retry.
    Identical,
}

/// Result of evaluating one capability take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortCodeCapabilityDecision {
    /// Atomically consume the capability.
    Consume,
    /// Return the prior result for an exact logical retrieval retry.
    Identical,
}

/// Decides whether one authenticated publish is new, idempotent, or rejected.
///
/// # Errors
///
/// Returns a typed deadline, conflict, or capacity error.
pub fn decide_short_code_publish(
    principal: RelayPrincipalId,
    request: ShortCodeAttemptPublishRequest,
    existing: Option<&StoredShortCodeAttempt>,
    now_unix_seconds: u64,
    active_global_count: usize,
    active_creator_count: usize,
) -> Result<ShortCodePublishDecision, RelayError> {
    if request.deadline_unix_seconds() <= now_unix_seconds {
        return Err(RelayError::ExpiredShortCodeAttempt);
    }
    if request.deadline_unix_seconds()
        > now_unix_seconds.saturating_add(SHORT_CODE_ATTEMPT_LIFETIME_SECONDS)
    {
        return Err(RelayError::InvalidShortCodeDeadline);
    }
    if let Some(existing) = existing {
        if existing.owner() == principal && existing.publish() == request {
            return Ok(ShortCodePublishDecision::Identical);
        }
        return Err(RelayError::ShortCodeAttemptConflict);
    }
    if active_global_count >= MAX_ACTIVE_SHORT_CODE_ATTEMPTS {
        return Err(RelayError::ShortCodeGlobalCapacityExceeded);
    }
    if active_creator_count >= MAX_ACTIVE_SHORT_CODE_ATTEMPTS_PER_CREATOR {
        return Err(RelayError::ShortCodeCreatorCapacityExceeded);
    }
    Ok(ShortCodePublishDecision::Insert)
}

/// Decides whether one authenticated locator claim is new, idempotent, or hidden.
///
/// # Errors
///
/// Returns a typed rate or unavailable error without exposing attempt state.
pub fn decide_short_code_claim(
    principal: RelayPrincipalId,
    request: &ShortCodeAttemptClaimRequest,
    existing: Option<&StoredShortCodeAttempt>,
    now_unix_seconds: u64,
    principal_window_count: usize,
    locator_window_count: usize,
) -> Result<ShortCodeClaimDecision, RelayError> {
    if let Some(existing) = existing {
        if existing.publish().version() != request.version() {
            return Err(RelayError::ShortCodeAttemptUnavailable);
        }
        if existing.claimant() == Some(principal)
            && existing.message(ShortCodeRelayStage::CredentialRequest) == Some(request.payload())
        {
            return Ok(ShortCodeClaimDecision::Identical);
        }
    }
    if principal_window_count >= MAX_SHORT_CODE_CLAIMS_PER_PRINCIPAL_WINDOW {
        return Err(RelayError::ShortCodeClaimRateLimited);
    }
    if locator_window_count >= MAX_SHORT_CODE_CLAIMS_PER_LOCATOR_WINDOW {
        return Err(RelayError::ShortCodeAttemptUnavailable);
    }
    let existing = existing.ok_or(RelayError::ShortCodeAttemptUnavailable)?;
    if existing.publish().deadline_unix_seconds() <= now_unix_seconds
        || existing.cancelled()
        || existing.capability_consumed()
        || existing.owner() == principal
        || existing.claimant().is_some()
    {
        return Err(RelayError::ShortCodeAttemptUnavailable);
    }
    Ok(ShortCodeClaimDecision::Claim)
}

/// Decides whether one authenticated opaque stage is new, idempotent, or rejected.
///
/// # Errors
///
/// Returns a typed unavailable, conflict, or invalid-stage error.
pub fn decide_short_code_message(
    principal: RelayPrincipalId,
    request: &ShortCodeAttemptMessageRequest,
    existing: &StoredShortCodeAttempt,
    now_unix_seconds: u64,
) -> Result<ShortCodeMessageDecision, RelayError> {
    if existing.publish().version() != request.version()
        || existing.publish().deadline_unix_seconds() <= now_unix_seconds
        || existing.cancelled()
    {
        return Err(RelayError::ShortCodeAttemptUnavailable);
    }
    if let Some(payload) = existing.message(request.stage()) {
        return if payload == request.payload()
            && stage_owner(existing, request.stage()) == principal
        {
            Ok(ShortCodeMessageDecision::Identical)
        } else {
            Err(RelayError::ShortCodeAttemptConflict)
        };
    }
    if existing.capability_consumed() {
        return Err(RelayError::ShortCodeAttemptUnavailable);
    }
    if stage_owner(existing, request.stage()) != principal
        || !stage_dependencies_satisfied(existing, request.stage())
    {
        return Err(RelayError::InvalidShortCodeStage);
    }
    Ok(ShortCodeMessageDecision::Insert)
}

/// Authorizes one capability-filtered participant snapshot.
///
/// # Errors
///
/// Returns unavailable for the wrong version, role, deadline, or cancellation state.
pub fn authorize_short_code_read(
    principal: RelayPrincipalId,
    request: ShortCodeAttemptReadRequest,
    existing: &StoredShortCodeAttempt,
    now_unix_seconds: u64,
) -> Result<(), RelayError> {
    if existing.publish().version() != request.version()
        || existing.publish().deadline_unix_seconds() <= now_unix_seconds
        || existing.cancelled()
        || (principal != existing.owner() && Some(principal) != existing.claimant())
    {
        return Err(RelayError::ShortCodeAttemptUnavailable);
    }
    Ok(())
}

/// Authorizes one idempotent participant cancellation.
///
/// # Errors
///
/// Returns unavailable for the wrong version or role.
pub fn authorize_short_code_cancel(
    principal: RelayPrincipalId,
    request: ShortCodeAttemptReadRequest,
    existing: &StoredShortCodeAttempt,
) -> Result<(), RelayError> {
    if existing.publish().version() == request.version()
        && (principal == existing.owner() || Some(principal) == existing.claimant())
    {
        Ok(())
    } else {
        Err(RelayError::ShortCodeAttemptUnavailable)
    }
}

/// Decides whether one authenticated claimant may consume the capability.
///
/// # Errors
///
/// Returns unavailable unless the exact-version attempt is active, mutually confirmed,
/// and contains an unconsumed capability.
pub fn decide_short_code_capability_take(
    principal: RelayPrincipalId,
    request: ShortCodeCapabilityTakeRequest,
    existing: &StoredShortCodeAttempt,
    now_unix_seconds: u64,
) -> Result<ShortCodeCapabilityDecision, RelayError> {
    if existing.publish().version() != request.version()
        || existing.publish().deadline_unix_seconds() <= now_unix_seconds
        || existing.cancelled()
        || Some(principal) != existing.claimant()
        || existing
            .message(ShortCodeRelayStage::CreatorConfirmation)
            .is_none()
        || existing
            .message(ShortCodeRelayStage::ClaimantConfirmation)
            .is_none()
        || existing.message(ShortCodeRelayStage::Capability).is_none()
    {
        return Err(RelayError::ShortCodeAttemptUnavailable);
    }
    match existing.capability_take_id() {
        None => Ok(ShortCodeCapabilityDecision::Consume),
        Some(existing) if existing == request.take_id() => {
            Ok(ShortCodeCapabilityDecision::Identical)
        }
        Some(_) => Err(RelayError::ShortCodeAttemptUnavailable),
    }
}

fn stage_owner(existing: &StoredShortCodeAttempt, stage: ShortCodeRelayStage) -> RelayPrincipalId {
    match stage {
        ShortCodeRelayStage::CredentialRequest
        | ShortCodeRelayStage::ClaimantFinalization
        | ShortCodeRelayStage::ClaimantConfirmation => {
            existing.claimant().unwrap_or(existing.owner())
        }
        ShortCodeRelayStage::CredentialResponse
        | ShortCodeRelayStage::CreatorIdentity
        | ShortCodeRelayStage::CreatorConfirmation
        | ShortCodeRelayStage::Capability => existing.owner(),
    }
}

fn stage_dependencies_satisfied(
    existing: &StoredShortCodeAttempt,
    stage: ShortCodeRelayStage,
) -> bool {
    let has = |stage| existing.message(stage).is_some();
    match stage {
        ShortCodeRelayStage::CredentialRequest => false,
        ShortCodeRelayStage::CredentialResponse => has(ShortCodeRelayStage::CredentialRequest),
        ShortCodeRelayStage::ClaimantFinalization => has(ShortCodeRelayStage::CredentialResponse),
        ShortCodeRelayStage::CreatorIdentity => has(ShortCodeRelayStage::ClaimantFinalization),
        ShortCodeRelayStage::CreatorConfirmation | ShortCodeRelayStage::ClaimantConfirmation => {
            has(ShortCodeRelayStage::CreatorIdentity)
        }
        ShortCodeRelayStage::Capability => {
            has(ShortCodeRelayStage::CreatorConfirmation)
                && has(ShortCodeRelayStage::ClaimantConfirmation)
        }
    }
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::{ProtocolVersion, ShortCodePairingAttemptId, ShortCodePairingLocator};

    use super::*;

    const NOW: u64 = 10;

    fn principal(value: u8) -> RelayPrincipalId {
        RelayPrincipalId::from_bytes([value; 32])
    }

    fn publish() -> ShortCodeAttemptPublishRequest {
        ShortCodeAttemptPublishRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingLocator::from_bytes([3; 32]),
            ShortCodePairingAttemptId::from_bytes([4; 16]),
            20,
        )
        .unwrap()
    }

    fn claimed() -> StoredShortCodeAttempt {
        let mut attempt = StoredShortCodeAttempt::new(principal(1), publish());
        attempt.set_claim(principal(2), vec![1]).unwrap();
        attempt
    }

    fn message(stage: ShortCodeRelayStage) -> ShortCodeAttemptMessageRequest {
        ShortCodeAttemptMessageRequest::new(
            ProtocolVersion::application_v1(),
            publish().attempt_id(),
            stage,
            vec![stage as u8],
        )
        .unwrap()
    }

    fn read() -> ShortCodeAttemptReadRequest {
        ShortCodeAttemptReadRequest::new(ProtocolVersion::application_v1(), publish().attempt_id())
    }

    fn take(value: u8) -> ShortCodeCapabilityTakeRequest {
        ShortCodeCapabilityTakeRequest::new(
            ProtocolVersion::application_v1(),
            publish().attempt_id(),
            ShortCodeCapabilityTakeId::from_bytes([value; 16]),
        )
    }

    #[test]
    fn publish_and_claim_decisions_are_bounded_and_idempotent() {
        let owner = principal(1);
        let claimant = principal(2);
        let publish = publish();
        assert_eq!(
            decide_short_code_publish(owner, publish, None, NOW, 0, 0),
            Ok(ShortCodePublishDecision::Insert)
        );
        let attempt = StoredShortCodeAttempt::new(owner, publish);
        assert_eq!(
            decide_short_code_publish(owner, publish, Some(&attempt), NOW, 0, 0),
            Ok(ShortCodePublishDecision::Identical)
        );
        assert_eq!(
            decide_short_code_publish(principal(3), publish, Some(&attempt), NOW, 0, 0),
            Err(RelayError::ShortCodeAttemptConflict)
        );
        let excessive_deadline = ShortCodeAttemptPublishRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingLocator::from_bytes([5; 32]),
            ShortCodePairingAttemptId::from_bytes([6; 16]),
            NOW + SHORT_CODE_ATTEMPT_LIFETIME_SECONDS + 1,
        )
        .unwrap();
        assert_eq!(
            decide_short_code_publish(owner, excessive_deadline, None, NOW, 0, 0),
            Err(RelayError::InvalidShortCodeDeadline)
        );
        let claim = ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::application_v1(),
            publish.locator(),
            vec![1],
        )
        .unwrap();
        assert_eq!(
            decide_short_code_claim(claimant, &claim, Some(&attempt), NOW, 0, 0),
            Ok(ShortCodeClaimDecision::Claim)
        );
        let wrong_version_claim = ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::new(1, 1).unwrap(),
            publish.locator(),
            vec![1],
        )
        .unwrap();
        assert_eq!(
            decide_short_code_claim(claimant, &wrong_version_claim, Some(&attempt), NOW, 0, 0,),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        assert_eq!(
            decide_short_code_claim(
                claimant,
                &claim,
                Some(&attempt),
                NOW,
                MAX_SHORT_CODE_CLAIMS_PER_PRINCIPAL_WINDOW,
                0,
            ),
            Err(RelayError::ShortCodeClaimRateLimited)
        );
        assert_eq!(
            decide_short_code_claim(claimant, &claim, None, NOW, 0, 0),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
    }

    #[test]
    fn stage_decision_table_requires_role_order_and_both_confirmations() {
        let owner = principal(1);
        let claimant = principal(2);
        let mut attempt = claimed();
        let response = message(ShortCodeRelayStage::CredentialResponse);
        assert_eq!(
            decide_short_code_message(owner, &response, &attempt, NOW),
            Ok(ShortCodeMessageDecision::Insert)
        );
        assert_eq!(
            decide_short_code_message(claimant, &response, &attempt, NOW),
            Err(RelayError::InvalidShortCodeStage)
        );
        let wrong_version_response = ShortCodeAttemptMessageRequest::new(
            ProtocolVersion::new(1, 1).unwrap(),
            response.attempt_id(),
            response.stage(),
            response.payload().to_vec(),
        )
        .unwrap();
        assert_eq!(
            decide_short_code_message(owner, &wrong_version_response, &attempt, NOW),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        attempt
            .insert_message(response.stage(), response.payload().to_vec())
            .unwrap();
        for (stage, principal) in [
            (ShortCodeRelayStage::ClaimantFinalization, claimant),
            (ShortCodeRelayStage::CreatorIdentity, owner),
            (ShortCodeRelayStage::ClaimantConfirmation, claimant),
            (ShortCodeRelayStage::CreatorConfirmation, owner),
        ] {
            let request = message(stage);
            assert_eq!(
                decide_short_code_message(principal, &request, &attempt, NOW),
                Ok(ShortCodeMessageDecision::Insert)
            );
            attempt
                .insert_message(stage, request.payload().to_vec())
                .unwrap();
        }
        let capability = message(ShortCodeRelayStage::Capability);
        assert_eq!(
            decide_short_code_message(owner, &capability, &attempt, NOW),
            Ok(ShortCodeMessageDecision::Insert)
        );
        attempt
            .insert_message(capability.stage(), capability.payload().to_vec())
            .unwrap();
        assert_eq!(
            decide_short_code_capability_take(claimant, take(1), &attempt, NOW),
            Ok(ShortCodeCapabilityDecision::Consume)
        );
        attempt.consume_capability(take(1).take_id());
        assert_eq!(
            decide_short_code_message(owner, &capability, &attempt, NOW),
            Ok(ShortCodeMessageDecision::Identical)
        );
        assert_eq!(
            decide_short_code_capability_take(claimant, take(1), &attempt, NOW),
            Ok(ShortCodeCapabilityDecision::Identical)
        );
        assert_eq!(
            decide_short_code_capability_take(claimant, take(2), &attempt, NOW),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        assert_eq!(
            decide_short_code_capability_take(owner, take(1), &attempt, NOW),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
    }

    #[test]
    fn expiry_cancellation_and_conflicting_claimants_fail_closed() {
        let mut attempt = claimed();
        let claim = ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::application_v1(),
            publish().locator(),
            vec![2],
        )
        .unwrap();
        assert_eq!(
            decide_short_code_claim(principal(3), &claim, Some(&attempt), NOW, 0, 0),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        attempt.cancel();
        assert_eq!(
            authorize_short_code_read(principal(1), read(), &attempt, NOW),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        assert!(authorize_short_code_cancel(principal(2), read(), &attempt).is_ok());
        assert_eq!(
            authorize_short_code_cancel(principal(3), read(), &attempt),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        let expired = StoredShortCodeAttempt::new(
            principal(1),
            ShortCodeAttemptPublishRequest::new(
                ProtocolVersion::application_v1(),
                publish().locator(),
                publish().attempt_id(),
                NOW,
            )
            .unwrap(),
        );
        assert_eq!(
            authorize_short_code_read(principal(1), read(), &expired, NOW),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
        let wrong_version = ShortCodeAttemptReadRequest::new(
            ProtocolVersion::new(1, 1).unwrap(),
            publish().attempt_id(),
        );
        assert_eq!(
            authorize_short_code_cancel(principal(2), wrong_version, &attempt),
            Err(RelayError::ShortCodeAttemptUnavailable)
        );
    }
}
