use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CollaborationPolicyDigest, CollaborationPolicyProposalId, KonclaveDomainError, ProtocolVersion,
};

/// Current collaboration-policy bundle major version.
pub const COLLABORATION_POLICY_BUNDLE_MAJOR: u32 = 1;
/// Current collaboration-policy bundle minor version.
pub const COLLABORATION_POLICY_BUNDLE_MINOR: u32 = 0;
/// Maximum canonical encoded collaboration-policy bundle size.
pub const MAX_COLLABORATION_POLICY_BUNDLE_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 bytes in one policy name.
pub const MAX_COLLABORATION_POLICY_NAME_BYTES: usize = 128;
/// Maximum UTF-8 bytes in optional model guidance.
pub const MAX_COLLABORATION_POLICY_GUIDANCE_BYTES: usize = 32 * 1024;
/// Maximum number of statements in one policy bundle.
pub const MAX_COLLABORATION_POLICY_STATEMENTS: usize = 256;
/// Maximum UTF-8 bytes in one statement identifier.
pub const MAX_COLLABORATION_POLICY_STATEMENT_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes in one namespaced action identifier.
pub const MAX_COLLABORATION_POLICY_ACTION_BYTES: usize = 256;
/// Maximum UTF-8 bytes in one namespaced resource identifier.
pub const MAX_COLLABORATION_POLICY_RESOURCE_BYTES: usize = 256;
/// Maximum harness claims required by one policy bundle.
pub const MAX_COLLABORATION_POLICY_HARNESS_CLAIMS: usize = 64;
/// Maximum UTF-8 bytes in one namespaced harness claim.
pub const MAX_COLLABORATION_POLICY_HARNESS_CLAIM_BYTES: usize = 256;

/// One peer-proposed immutable collaboration-policy bundle.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CollaborationPolicyProposal {
    #[zeroize(skip)]
    proposal_id: CollaborationPolicyProposalId,
    #[zeroize(skip)]
    policy_digest: CollaborationPolicyDigest,
    canonical_bundle: Vec<u8>,
    #[zeroize(skip)]
    replaces_policy_digest: Option<CollaborationPolicyDigest>,
}

impl CollaborationPolicyProposal {
    /// Creates one bounded proposal.
    ///
    /// Content identity must still be verified cryptographically before the proposal
    /// can be stored or bound.
    ///
    /// # Errors
    ///
    /// Returns a validation error when canonical bundle bytes are empty or exceed the
    /// policy bundle bound.
    pub fn new(
        proposal_id: CollaborationPolicyProposalId,
        policy_digest: CollaborationPolicyDigest,
        canonical_bundle: Vec<u8>,
        replaces_policy_digest: Option<CollaborationPolicyDigest>,
    ) -> Result<Self, KonclaveDomainError> {
        if canonical_bundle.is_empty()
            || canonical_bundle.len() > MAX_COLLABORATION_POLICY_BUNDLE_BYTES
        {
            return Err(KonclaveDomainError::OutOfRange {
                field: "collaboration_policy_bundle",
                minimum: 1,
                maximum: MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
                actual: canonical_bundle.len(),
            });
        }
        Ok(Self {
            proposal_id,
            policy_digest,
            canonical_bundle,
            replaces_policy_digest,
        })
    }

    /// Returns the proposal identifier.
    #[must_use]
    pub const fn proposal_id(&self) -> CollaborationPolicyProposalId {
        self.proposal_id
    }

    /// Returns the claimed canonical bundle digest.
    #[must_use]
    pub const fn policy_digest(&self) -> CollaborationPolicyDigest {
        self.policy_digest
    }

    /// Returns the proposed canonical policy bytes.
    #[must_use]
    pub fn canonical_bundle(&self) -> &[u8] {
        &self.canonical_bundle
    }

    /// Returns the prior digest this proposal explicitly replaces, when present.
    #[must_use]
    pub const fn replaces_policy_digest(&self) -> Option<CollaborationPolicyDigest> {
        self.replaces_policy_digest
    }
}

/// Terminal response to one collaboration-policy proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollaborationPolicyResponseOutcome {
    /// The responding endpoint accepted the exact proposed base digest.
    Accepted,
    /// The responding endpoint declined the proposal.
    Rejected,
}

/// Authenticated acknowledgement of one collaboration-policy proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct CollaborationPolicyResponse {
    #[zeroize(skip)]
    proposal_id: CollaborationPolicyProposalId,
    #[zeroize(skip)]
    policy_digest: CollaborationPolicyDigest,
    #[zeroize(skip)]
    outcome: CollaborationPolicyResponseOutcome,
}

impl CollaborationPolicyResponse {
    /// Creates a response bound to one proposal and base digest.
    #[must_use]
    pub const fn new(
        proposal_id: CollaborationPolicyProposalId,
        policy_digest: CollaborationPolicyDigest,
        outcome: CollaborationPolicyResponseOutcome,
    ) -> Self {
        Self {
            proposal_id,
            policy_digest,
            outcome,
        }
    }

    /// Returns the proposal identifier.
    #[must_use]
    pub const fn proposal_id(self) -> CollaborationPolicyProposalId {
        self.proposal_id
    }

    /// Returns the exact base digest being acknowledged.
    #[must_use]
    pub const fn policy_digest(self) -> CollaborationPolicyDigest {
        self.policy_digest
    }

    /// Returns the local acceptance outcome.
    #[must_use]
    pub const fn outcome(self) -> CollaborationPolicyResponseOutcome {
        self.outcome
    }
}

/// Notification that one endpoint removed its local policy binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct CollaborationPolicyRevocation {
    #[zeroize(skip)]
    policy_digest: CollaborationPolicyDigest,
}

impl CollaborationPolicyRevocation {
    /// Creates a revocation notice for one previously accepted base digest.
    #[must_use]
    pub const fn new(policy_digest: CollaborationPolicyDigest) -> Self {
        Self { policy_digest }
    }

    /// Returns the revoked base digest.
    #[must_use]
    pub const fn policy_digest(self) -> CollaborationPolicyDigest {
        self.policy_digest
    }
}

/// Validates one canonical collaboration-policy display name.
///
/// # Errors
///
/// Returns a validation error when the name is empty, oversized, or not canonical
/// lowercase ASCII.
pub fn validate_collaboration_policy_name(value: &str) -> Result<(), KonclaveDomainError> {
    canonical_identifier(
        value.to_string(),
        "collaboration_policy_name",
        MAX_COLLABORATION_POLICY_NAME_BYTES,
    )
    .map(|_| ())
}

/// Primitive decision attached to one collaboration-policy statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CollaborationPolicyEffect {
    /// Permit the matching action when every stricter local boundary also permits it.
    Allow,
    /// Refuse the matching action.
    Deny,
    /// Require a fresh local approval before the matching action.
    RequireLocalApproval,
}

/// One canonical action decision in a collaboration-policy bundle.
#[derive(PartialEq, Eq)]
pub struct CollaborationPolicyStatement {
    statement_id: String,
    effect: CollaborationPolicyEffect,
    action: String,
    resource: Option<String>,
}

impl CollaborationPolicyStatement {
    /// Creates one statement over canonical namespaced identifiers.
    ///
    /// # Errors
    ///
    /// Returns a validation error when an identifier is empty, oversized, or not
    /// canonical lowercase ASCII.
    pub fn new(
        statement_id: impl Into<String>,
        effect: CollaborationPolicyEffect,
        action: impl Into<String>,
        resource: Option<String>,
    ) -> Result<Self, KonclaveDomainError> {
        let statement_id = canonical_identifier(
            statement_id.into(),
            "collaboration_policy_statement_id",
            MAX_COLLABORATION_POLICY_STATEMENT_ID_BYTES,
        )?;
        let action = canonical_namespaced_identifier(
            action.into(),
            "collaboration_policy_action",
            MAX_COLLABORATION_POLICY_ACTION_BYTES,
        )?;
        let resource = resource
            .map(|value| {
                canonical_namespaced_identifier(
                    value,
                    "collaboration_policy_resource",
                    MAX_COLLABORATION_POLICY_RESOURCE_BYTES,
                )
            })
            .transpose()?;
        Ok(Self {
            statement_id,
            effect,
            action,
            resource,
        })
    }

    /// Returns the identifier used for canonical ordering and diagnostics.
    #[must_use]
    pub fn statement_id(&self) -> &str {
        &self.statement_id
    }

    /// Returns the decision primitive.
    #[must_use]
    pub const fn effect(&self) -> CollaborationPolicyEffect {
        self.effect
    }

    /// Returns the namespaced action identifier.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns the optional namespaced resource identifier.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
}

impl Drop for CollaborationPolicyStatement {
    fn drop(&mut self) {
        self.statement_id.zeroize();
        self.action.zeroize();
        self.resource.zeroize();
    }
}

/// Fully resolved optional semantic limits for one collaboration-policy bundle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CollaborationPolicyLimits {
    duration_milliseconds: Option<u64>,
    turns: Option<u64>,
    tokens: Option<u64>,
    concurrent_requests: Option<u32>,
}

impl CollaborationPolicyLimits {
    /// Creates materialized limits where `None` means explicitly unlimited.
    ///
    /// # Errors
    ///
    /// Returns a validation error when any finite limit is zero.
    pub fn new(
        duration_milliseconds: Option<u64>,
        turns: Option<u64>,
        tokens: Option<u64>,
        concurrent_requests: Option<u32>,
    ) -> Result<Self, KonclaveDomainError> {
        require_optional_positive(duration_milliseconds, "collaboration_policy_duration")?;
        require_optional_positive(turns, "collaboration_policy_turns")?;
        require_optional_positive(tokens, "collaboration_policy_tokens")?;
        require_optional_positive(
            concurrent_requests.map(u64::from),
            "collaboration_policy_concurrent_requests",
        )?;
        Ok(Self {
            duration_milliseconds,
            turns,
            tokens,
            concurrent_requests,
        })
    }

    /// Returns the finite duration in milliseconds, or `None` when unlimited.
    #[must_use]
    pub const fn duration_milliseconds(self) -> Option<u64> {
        self.duration_milliseconds
    }

    /// Returns the finite turn count, or `None` when unlimited.
    #[must_use]
    pub const fn turns(self) -> Option<u64> {
        self.turns
    }

    /// Returns the finite token count, or `None` when unlimited.
    #[must_use]
    pub const fn tokens(self) -> Option<u64> {
        self.tokens
    }

    /// Returns the finite concurrent-request count, or `None` when unlimited.
    #[must_use]
    pub const fn concurrent_requests(self) -> Option<u32> {
        self.concurrent_requests
    }
}

/// Fully resolved, source-independent collaboration policy.
#[derive(PartialEq, Eq)]
pub struct CollaborationPolicyBundle {
    version: ProtocolVersion,
    name: String,
    guidance: Option<String>,
    statements: Vec<CollaborationPolicyStatement>,
    required_harness_claims: Vec<String>,
    limits: CollaborationPolicyLimits,
}

impl CollaborationPolicyBundle {
    /// Creates a bounded bundle and canonicalizes unordered collections.
    ///
    /// # Errors
    ///
    /// Returns a validation error for malformed or oversized values, duplicate
    /// statement identifiers, or duplicate harness claims.
    pub fn new(
        version: ProtocolVersion,
        name: impl Into<String>,
        guidance: Option<String>,
        mut statements: Vec<CollaborationPolicyStatement>,
        mut required_harness_claims: Vec<String>,
        limits: CollaborationPolicyLimits,
    ) -> Result<Self, KonclaveDomainError> {
        let name = name.into();
        validate_collaboration_policy_name(&name)?;
        let guidance = guidance
            .map(|value| {
                bounded_text(
                    value,
                    "collaboration_policy_guidance",
                    MAX_COLLABORATION_POLICY_GUIDANCE_BYTES,
                )
            })
            .transpose()?;
        require_collection_bound(
            statements.len(),
            MAX_COLLABORATION_POLICY_STATEMENTS,
            "collaboration_policy_statements",
        )?;
        statements.sort_by(|left, right| left.statement_id.cmp(&right.statement_id));
        if statements
            .windows(2)
            .any(|pair| pair[0].statement_id == pair[1].statement_id)
        {
            return Err(KonclaveDomainError::DuplicateIdentifier {
                field: "collaboration_policy_statement_id",
            });
        }
        require_collection_bound(
            required_harness_claims.len(),
            MAX_COLLABORATION_POLICY_HARNESS_CLAIMS,
            "collaboration_policy_harness_claims",
        )?;
        for claim in &mut required_harness_claims {
            let value = std::mem::take(claim);
            *claim = canonical_namespaced_identifier(
                value,
                "collaboration_policy_harness_claim",
                MAX_COLLABORATION_POLICY_HARNESS_CLAIM_BYTES,
            )?;
        }
        required_harness_claims.sort();
        if required_harness_claims
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(KonclaveDomainError::DuplicateIdentifier {
                field: "collaboration_policy_harness_claim",
            });
        }
        Ok(Self {
            version,
            name,
            guidance,
            statements,
            required_harness_claims,
            limits,
        })
    }

    /// Returns the collaboration-policy bundle version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the human-readable canonical policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns optional model guidance.
    #[must_use]
    pub fn guidance(&self) -> Option<&str> {
        self.guidance.as_deref()
    }

    /// Returns statements in canonical identifier order.
    #[must_use]
    pub fn statements(&self) -> &[CollaborationPolicyStatement] {
        &self.statements
    }

    /// Returns required harness claims in canonical lexical order.
    #[must_use]
    pub fn required_harness_claims(&self) -> &[String] {
        &self.required_harness_claims
    }

    /// Returns fully resolved optional semantic limits.
    #[must_use]
    pub const fn limits(&self) -> CollaborationPolicyLimits {
        self.limits
    }
}

impl Drop for CollaborationPolicyBundle {
    fn drop(&mut self) {
        self.name.zeroize();
        self.guidance.zeroize();
        self.required_harness_claims.zeroize();
    }
}

fn require_optional_positive(
    value: Option<u64>,
    field: &'static str,
) -> Result<(), KonclaveDomainError> {
    if value == Some(0) {
        Err(KonclaveDomainError::ZeroValue { field })
    } else {
        Ok(())
    }
}

fn require_collection_bound(
    actual: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), KonclaveDomainError> {
    if actual > maximum {
        Err(KonclaveDomainError::OutOfRange {
            field,
            minimum: 0,
            maximum,
            actual,
        })
    } else {
        Ok(())
    }
}

fn bounded_text(
    value: String,
    field: &'static str,
    maximum: usize,
) -> Result<String, KonclaveDomainError> {
    if value.is_empty() {
        return Err(KonclaveDomainError::EmptyText { field });
    }
    if value.len() > maximum {
        return Err(KonclaveDomainError::TextTooLong {
            field,
            maximum,
            actual: value.len(),
        });
    }
    Ok(value)
}

fn canonical_identifier(
    value: String,
    field: &'static str,
    maximum: usize,
) -> Result<String, KonclaveDomainError> {
    let value = bounded_text(value, field, maximum)?;
    if !value.is_ascii()
        || value
            .split(['.', '/'])
            .any(|segment| !canonical_identifier_segment(segment))
    {
        return Err(KonclaveDomainError::NonCanonicalText { field });
    }
    Ok(value)
}

fn canonical_namespaced_identifier(
    value: String,
    field: &'static str,
    maximum: usize,
) -> Result<String, KonclaveDomainError> {
    let value = canonical_identifier(value, field, maximum)?;
    if !value.contains('.') && !value.contains('/') {
        return Err(KonclaveDomainError::NonCanonicalText { field });
    }
    Ok(value)
}

fn canonical_identifier_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(id: &str, action: &str) -> CollaborationPolicyStatement {
        CollaborationPolicyStatement::new(id, CollaborationPolicyEffect::Allow, action, None)
            .unwrap()
    }

    #[test]
    fn bundle_canonicalizes_statements_and_claims() {
        let bundle = CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            "contract-alignment",
            Some("Align the API contract.".to_string()),
            vec![
                statement("write", "workspace.modify"),
                statement("reply", "conversation.reply"),
            ],
            vec![
                "copilot.tool-interception".to_string(),
                "copilot.session-identity".to_string(),
            ],
            CollaborationPolicyLimits::new(None, None, Some(10_000), Some(1)).unwrap(),
        )
        .unwrap();

        assert_eq!(bundle.statements()[0].statement_id(), "reply");
        assert_eq!(bundle.statements()[1].statement_id(), "write");
        assert_eq!(
            bundle.required_harness_claims(),
            ["copilot.session-identity", "copilot.tool-interception"]
        );
        assert_eq!(bundle.limits().duration_milliseconds(), None);
        assert_eq!(bundle.limits().tokens(), Some(10_000));
    }

    #[test]
    fn bundle_rejects_noncanonical_and_duplicate_identifiers() {
        assert!(matches!(
            CollaborationPolicyStatement::new(
                "Reply",
                CollaborationPolicyEffect::Allow,
                "conversation.reply",
                None
            ),
            Err(KonclaveDomainError::NonCanonicalText { .. })
        ));
        assert!(matches!(
            CollaborationPolicyStatement::new(
                "reply",
                CollaborationPolicyEffect::Allow,
                "reply",
                None
            ),
            Err(KonclaveDomainError::NonCanonicalText { .. })
        ));
        assert!(matches!(
            CollaborationPolicyBundle::new(
                ProtocolVersion::application_v1(),
                "contract-alignment",
                None,
                vec![
                    statement("reply", "conversation.reply"),
                    statement("reply", "workspace.read"),
                ],
                vec![],
                CollaborationPolicyLimits::default(),
            ),
            Err(KonclaveDomainError::DuplicateIdentifier { .. })
        ));
        assert!(matches!(
            CollaborationPolicyBundle::new(
                ProtocolVersion::application_v1(),
                "contract-alignment",
                None,
                vec![],
                vec!["copilot.session-identity".to_string(); 2],
                CollaborationPolicyLimits::default(),
            ),
            Err(KonclaveDomainError::DuplicateIdentifier { .. })
        ));
    }

    #[test]
    fn finite_limits_must_be_positive() {
        assert_eq!(
            CollaborationPolicyLimits::new(None, Some(0), None, None),
            Err(KonclaveDomainError::ZeroValue {
                field: "collaboration_policy_turns"
            })
        );
        assert_eq!(
            CollaborationPolicyLimits::new(None, None, None, Some(0)),
            Err(KonclaveDomainError::ZeroValue {
                field: "collaboration_policy_concurrent_requests"
            })
        );
    }

    #[test]
    fn proposal_requires_one_bounded_bundle_and_preserves_replacement() {
        let replacement = CollaborationPolicyDigest::from_bytes([4; 32]);
        let proposal = CollaborationPolicyProposal::new(
            CollaborationPolicyProposalId::from_bytes([1; 16]),
            CollaborationPolicyDigest::from_bytes([2; 32]),
            vec![3; MAX_COLLABORATION_POLICY_BUNDLE_BYTES],
            Some(replacement),
        )
        .unwrap();
        assert_eq!(
            proposal.canonical_bundle().len(),
            MAX_COLLABORATION_POLICY_BUNDLE_BYTES
        );
        assert_eq!(proposal.replaces_policy_digest(), Some(replacement));

        assert!(matches!(
            CollaborationPolicyProposal::new(
                CollaborationPolicyProposalId::from_bytes([1; 16]),
                CollaborationPolicyDigest::from_bytes([2; 32]),
                vec![],
                None,
            ),
            Err(KonclaveDomainError::OutOfRange {
                field: "collaboration_policy_bundle",
                minimum: 1,
                maximum: MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
                actual: 0
            })
        ));
        assert!(matches!(
            CollaborationPolicyProposal::new(
                CollaborationPolicyProposalId::from_bytes([1; 16]),
                CollaborationPolicyDigest::from_bytes([2; 32]),
                vec![3; MAX_COLLABORATION_POLICY_BUNDLE_BYTES + 1],
                None,
            ),
            Err(KonclaveDomainError::OutOfRange {
                field: "collaboration_policy_bundle",
                minimum: 1,
                maximum: MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
                actual,
            }) if actual == MAX_COLLABORATION_POLICY_BUNDLE_BYTES + 1
        ));
    }

    #[test]
    fn response_and_revocation_preserve_exact_exchange_identity() {
        let proposal_id = CollaborationPolicyProposalId::from_bytes([6; 16]);
        let digest = CollaborationPolicyDigest::from_bytes([7; 32]);
        let response = CollaborationPolicyResponse::new(
            proposal_id,
            digest,
            CollaborationPolicyResponseOutcome::Accepted,
        );
        let revocation = CollaborationPolicyRevocation::new(digest);

        assert_eq!(response.proposal_id(), proposal_id);
        assert_eq!(response.policy_digest(), digest);
        assert_eq!(
            response.outcome(),
            CollaborationPolicyResponseOutcome::Accepted
        );
        assert_eq!(revocation.policy_digest(), digest);
    }
}
