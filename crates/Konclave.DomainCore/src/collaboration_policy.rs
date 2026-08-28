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

/// One exact namespaced action and optional exact resource boundary.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CollaborationPolicyTarget {
    action: String,
    resource: Option<String>,
}

impl CollaborationPolicyTarget {
    /// Creates one exact evaluator target.
    ///
    /// `None` matches only an unscoped request; it is not a resource wildcard.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the action or resource is not a bounded
    /// canonical namespaced identifier.
    pub fn new(
        action: impl Into<String>,
        resource: Option<String>,
    ) -> Result<Self, KonclaveDomainError> {
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
        Ok(Self { action, resource })
    }

    /// Returns the exact namespaced action.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns the exact resource, or `None` for an unscoped action.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
}

/// Semantic budget requested by one prospective collaboration action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CollaborationPolicyCost {
    turns: u64,
    tokens: u64,
    concurrent_requests: u32,
}

impl CollaborationPolicyCost {
    /// Creates one requested semantic budget reservation.
    #[must_use]
    pub const fn new(turns: u64, tokens: u64, concurrent_requests: u32) -> Self {
        Self {
            turns,
            tokens,
            concurrent_requests,
        }
    }

    /// Returns additional turns reserved by this action.
    #[must_use]
    pub const fn turns(self) -> u64 {
        self.turns
    }

    /// Returns additional tokens reserved by this action.
    #[must_use]
    pub const fn tokens(self) -> u64 {
        self.tokens
    }

    /// Returns additional concurrent request slots reserved by this action.
    #[must_use]
    pub const fn concurrent_requests(self) -> u32 {
        self.concurrent_requests
    }
}

/// Current authenticated semantic usage for one active policy binding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CollaborationPolicyUsage {
    elapsed_milliseconds: u64,
    turns: u64,
    tokens: u64,
    concurrent_requests: u32,
}

impl CollaborationPolicyUsage {
    /// Creates one usage snapshot supplied by the enforcing boundary.
    #[must_use]
    pub const fn new(
        elapsed_milliseconds: u64,
        turns: u64,
        tokens: u64,
        concurrent_requests: u32,
    ) -> Self {
        Self {
            elapsed_milliseconds,
            turns,
            tokens,
            concurrent_requests,
        }
    }

    /// Returns milliseconds elapsed since policy activation.
    #[must_use]
    pub const fn elapsed_milliseconds(self) -> u64 {
        self.elapsed_milliseconds
    }

    /// Returns turns already consumed.
    #[must_use]
    pub const fn turns(self) -> u64 {
        self.turns
    }

    /// Returns tokens already consumed or reserved.
    #[must_use]
    pub const fn tokens(self) -> u64 {
        self.tokens
    }

    /// Returns currently active request slots.
    #[must_use]
    pub const fn concurrent_requests(self) -> u32 {
        self.concurrent_requests
    }
}

/// One validated action evaluation request.
pub struct CollaborationPolicyEvaluationRequest {
    target: CollaborationPolicyTarget,
    cost: CollaborationPolicyCost,
    fresh_local_approval_proven: bool,
}

impl CollaborationPolicyEvaluationRequest {
    /// Creates one request with its prospective semantic cost.
    #[must_use]
    pub const fn new(
        target: CollaborationPolicyTarget,
        cost: CollaborationPolicyCost,
        fresh_local_approval_proven: bool,
    ) -> Self {
        Self {
            target,
            cost,
            fresh_local_approval_proven,
        }
    }

    /// Returns the requested action target.
    #[must_use]
    pub const fn target(&self) -> &CollaborationPolicyTarget {
        &self.target
    }

    /// Returns the prospective semantic cost.
    #[must_use]
    pub const fn cost(&self) -> CollaborationPolicyCost {
        self.cost
    }

    /// Returns whether the enforcing boundary proved fresh local approval.
    #[must_use]
    pub const fn fresh_local_approval_proven(&self) -> bool {
        self.fresh_local_approval_proven
    }
}

/// Locally proven authority, harness controls, evidence, and restrictions.
pub struct CollaborationPolicyEvaluationContext {
    local_user_authority: Vec<CollaborationPolicyTarget>,
    proven_harness_claims: Vec<String>,
    proven_harness_controls: Vec<CollaborationPolicyTarget>,
    local_denials: Vec<CollaborationPolicyTarget>,
    local_approval_requirements: Vec<CollaborationPolicyTarget>,
}

impl CollaborationPolicyEvaluationContext {
    /// Creates one bounded local evaluator context.
    ///
    /// Local authority and harness controls are positive exact-target allowlists.
    /// Local denials and approval requirements can only make the accepted bundle
    /// stricter.
    ///
    /// # Errors
    ///
    /// Returns a validation error for oversized collections, malformed claims, or
    /// duplicate targets and claims.
    pub fn new(
        local_user_authority: Vec<CollaborationPolicyTarget>,
        mut proven_harness_claims: Vec<String>,
        proven_harness_controls: Vec<CollaborationPolicyTarget>,
        local_denials: Vec<CollaborationPolicyTarget>,
        local_approval_requirements: Vec<CollaborationPolicyTarget>,
    ) -> Result<Self, KonclaveDomainError> {
        let local_user_authority =
            canonicalize_targets(local_user_authority, "collaboration_policy_local_authority")?;
        let proven_harness_controls = canonicalize_targets(
            proven_harness_controls,
            "collaboration_policy_harness_controls",
        )?;
        let local_denials =
            canonicalize_targets(local_denials, "collaboration_policy_local_denials")?;
        let local_approval_requirements = canonicalize_targets(
            local_approval_requirements,
            "collaboration_policy_local_approval_requirements",
        )?;
        require_collection_bound(
            proven_harness_claims.len(),
            MAX_COLLABORATION_POLICY_HARNESS_CLAIMS,
            "collaboration_policy_proven_harness_claims",
        )?;
        for claim in &mut proven_harness_claims {
            let value = std::mem::take(claim);
            *claim = canonical_namespaced_identifier(
                value,
                "collaboration_policy_harness_claim",
                MAX_COLLABORATION_POLICY_HARNESS_CLAIM_BYTES,
            )?;
        }
        proven_harness_claims.sort();
        if proven_harness_claims
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(KonclaveDomainError::DuplicateIdentifier {
                field: "collaboration_policy_harness_claim",
            });
        }
        Ok(Self {
            local_user_authority,
            proven_harness_claims,
            proven_harness_controls,
            local_denials,
            local_approval_requirements,
        })
    }

    /// Returns exact targets permitted by local user authority.
    #[must_use]
    pub fn local_user_authority(&self) -> &[CollaborationPolicyTarget] {
        &self.local_user_authority
    }

    /// Returns canonical harness claims proven locally.
    #[must_use]
    pub fn proven_harness_claims(&self) -> &[String] {
        &self.proven_harness_claims
    }

    /// Returns exact action boundaries the harness proves it can enforce.
    #[must_use]
    pub fn proven_harness_controls(&self) -> &[CollaborationPolicyTarget] {
        &self.proven_harness_controls
    }

    /// Returns exact targets denied by local restrictions.
    #[must_use]
    pub fn local_denials(&self) -> &[CollaborationPolicyTarget] {
        &self.local_denials
    }

    /// Returns exact targets requiring fresh local approval.
    #[must_use]
    pub fn local_approval_requirements(&self) -> &[CollaborationPolicyTarget] {
        &self.local_approval_requirements
    }
}

impl Drop for CollaborationPolicyEvaluationContext {
    fn drop(&mut self) {
        self.proven_harness_claims.zeroize();
    }
}

/// Stable reason an otherwise validated collaboration action was denied.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollaborationPolicyDenialReason {
    /// No accepted-bundle statement exactly matches the target.
    NoMatchingStatement,
    /// A matching accepted-bundle statement explicitly denies the target.
    PolicyDenied,
    /// Local user authority does not permit the exact target.
    LocalAuthorityMissing,
    /// At least one globally required harness claim is not proven.
    HarnessClaimMissing,
    /// The harness cannot prove enforcement of the exact target.
    HarnessControlMissing,
    /// A local restriction explicitly denies the target.
    LocalRestrictionDenied,
    /// The finite collaboration duration has expired.
    DurationLimitExceeded,
    /// Existing usage plus the requested turn cost exceeds the finite limit.
    TurnLimitExceeded,
    /// Existing usage plus the requested token cost exceeds the finite limit.
    TokenLimitExceeded,
    /// Active usage plus requested slots exceeds the finite concurrency limit.
    ConcurrencyLimitExceeded,
}

impl CollaborationPolicyDenialReason {
    /// Returns the stable machine-readable denial code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoMatchingStatement => "no_matching_statement",
            Self::PolicyDenied => "policy_denied",
            Self::LocalAuthorityMissing => "local_authority_missing",
            Self::HarnessClaimMissing => "harness_claim_missing",
            Self::HarnessControlMissing => "harness_control_missing",
            Self::LocalRestrictionDenied => "local_restriction_denied",
            Self::DurationLimitExceeded => "duration_limit_exceeded",
            Self::TurnLimitExceeded => "turn_limit_exceeded",
            Self::TokenLimitExceeded => "token_limit_exceeded",
            Self::ConcurrencyLimitExceeded => "concurrency_limit_exceeded",
        }
    }
}

/// Deterministic result of intersecting one accepted policy with local controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollaborationPolicyDecision {
    /// The action is permitted within the supplied usage snapshot and request cost.
    Allow,
    /// The action requires fresh local approval before it can be permitted.
    RequireLocalApproval,
    /// The action is denied for one stable reason.
    Deny(CollaborationPolicyDenialReason),
}

/// Intersects one accepted bundle with local authority and proven enforcement.
///
/// Denial is fail-closed. Exact target matching is used throughout; an absent
/// resource never acts as a wildcard. Callers must atomically persist accepted usage
/// reservations before executing the side effect because this pure evaluator does
/// not own mutable accounting.
#[must_use]
pub fn evaluate_collaboration_policy(
    bundle: &CollaborationPolicyBundle,
    context: &CollaborationPolicyEvaluationContext,
    request: &CollaborationPolicyEvaluationRequest,
    usage: CollaborationPolicyUsage,
) -> CollaborationPolicyDecision {
    let target = request.target();
    let mut matching_effect = None;
    for statement in bundle.statements().iter().filter(|statement| {
        statement.action() == target.action() && statement.resource() == target.resource()
    }) {
        matching_effect = Some(stricter_effect(matching_effect, statement.effect()));
    }
    let Some(matching_effect) = matching_effect else {
        return CollaborationPolicyDecision::Deny(
            CollaborationPolicyDenialReason::NoMatchingStatement,
        );
    };
    if matching_effect == CollaborationPolicyEffect::Deny {
        return CollaborationPolicyDecision::Deny(CollaborationPolicyDenialReason::PolicyDenied);
    }
    if target_in(&context.local_denials, target) {
        return CollaborationPolicyDecision::Deny(
            CollaborationPolicyDenialReason::LocalRestrictionDenied,
        );
    }
    if !target_in(&context.local_user_authority, target) {
        return CollaborationPolicyDecision::Deny(
            CollaborationPolicyDenialReason::LocalAuthorityMissing,
        );
    }
    if bundle
        .required_harness_claims()
        .iter()
        .any(|claim| context.proven_harness_claims.binary_search(claim).is_err())
    {
        return CollaborationPolicyDecision::Deny(
            CollaborationPolicyDenialReason::HarnessClaimMissing,
        );
    }
    if !target_in(&context.proven_harness_controls, target) {
        return CollaborationPolicyDecision::Deny(
            CollaborationPolicyDenialReason::HarnessControlMissing,
        );
    }
    if let Some(reason) = exceeded_limit(bundle.limits(), usage, request.cost()) {
        return CollaborationPolicyDecision::Deny(reason);
    }
    if !request.fresh_local_approval_proven()
        && (matching_effect == CollaborationPolicyEffect::RequireLocalApproval
            || target_in(&context.local_approval_requirements, target))
    {
        CollaborationPolicyDecision::RequireLocalApproval
    } else {
        CollaborationPolicyDecision::Allow
    }
}

fn canonicalize_targets(
    mut targets: Vec<CollaborationPolicyTarget>,
    field: &'static str,
) -> Result<Vec<CollaborationPolicyTarget>, KonclaveDomainError> {
    require_collection_bound(targets.len(), MAX_COLLABORATION_POLICY_STATEMENTS, field)?;
    targets.sort_by(|left, right| {
        left.action
            .cmp(&right.action)
            .then_with(|| left.resource.cmp(&right.resource))
    });
    if targets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(KonclaveDomainError::DuplicateIdentifier { field });
    }
    Ok(targets)
}

fn target_in(targets: &[CollaborationPolicyTarget], target: &CollaborationPolicyTarget) -> bool {
    targets
        .binary_search_by(|candidate| {
            candidate
                .action
                .as_str()
                .cmp(target.action())
                .then_with(|| candidate.resource.as_deref().cmp(&target.resource()))
        })
        .is_ok()
}

const fn stricter_effect(
    current: Option<CollaborationPolicyEffect>,
    candidate: CollaborationPolicyEffect,
) -> CollaborationPolicyEffect {
    match (current, candidate) {
        (Some(CollaborationPolicyEffect::Deny), _) | (_, CollaborationPolicyEffect::Deny) => {
            CollaborationPolicyEffect::Deny
        }
        (Some(CollaborationPolicyEffect::RequireLocalApproval), _)
        | (_, CollaborationPolicyEffect::RequireLocalApproval) => {
            CollaborationPolicyEffect::RequireLocalApproval
        }
        _ => CollaborationPolicyEffect::Allow,
    }
}

fn exceeded_limit(
    limits: CollaborationPolicyLimits,
    usage: CollaborationPolicyUsage,
    cost: CollaborationPolicyCost,
) -> Option<CollaborationPolicyDenialReason> {
    if limits
        .duration_milliseconds()
        .is_some_and(|limit| usage.elapsed_milliseconds() >= limit)
    {
        return Some(CollaborationPolicyDenialReason::DurationLimitExceeded);
    }
    if exceeds_u64(usage.turns(), cost.turns(), limits.turns()) {
        return Some(CollaborationPolicyDenialReason::TurnLimitExceeded);
    }
    if exceeds_u64(usage.tokens(), cost.tokens(), limits.tokens()) {
        return Some(CollaborationPolicyDenialReason::TokenLimitExceeded);
    }
    if exceeds_u32(
        usage.concurrent_requests(),
        cost.concurrent_requests(),
        limits.concurrent_requests(),
    ) {
        return Some(CollaborationPolicyDenialReason::ConcurrencyLimitExceeded);
    }
    None
}

fn exceeds_u64(current: u64, requested: u64, limit: Option<u64>) -> bool {
    limit.is_some_and(|limit| {
        current
            .checked_add(requested)
            .is_none_or(|total| total > limit)
    })
}

fn exceeds_u32(current: u32, requested: u32, limit: Option<u32>) -> bool {
    limit.is_some_and(|limit| {
        current
            .checked_add(requested)
            .is_none_or(|total| total > limit)
    })
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

    fn evaluator_statement(
        id: &str,
        effect: CollaborationPolicyEffect,
        resource: Option<&str>,
    ) -> CollaborationPolicyStatement {
        CollaborationPolicyStatement::new(
            id,
            effect,
            "workspace.modify",
            resource.map(str::to_string),
        )
        .unwrap()
    }

    fn target(resource: Option<&str>) -> CollaborationPolicyTarget {
        CollaborationPolicyTarget::new("workspace.modify", resource.map(str::to_string)).unwrap()
    }

    fn evaluation_context(
        local_authority: bool,
        proven_claims: &[&str],
        harness_control: bool,
        local_denial: bool,
        local_approval: bool,
        resource: Option<&str>,
    ) -> CollaborationPolicyEvaluationContext {
        CollaborationPolicyEvaluationContext::new(
            local_authority
                .then(|| target(resource))
                .into_iter()
                .collect(),
            proven_claims.iter().map(ToString::to_string).collect(),
            harness_control
                .then(|| target(resource))
                .into_iter()
                .collect(),
            local_denial.then(|| target(resource)).into_iter().collect(),
            local_approval
                .then(|| target(resource))
                .into_iter()
                .collect(),
        )
        .unwrap()
    }

    fn evaluation_request(
        resource: Option<&str>,
        fresh_local_approval_proven: bool,
        cost: CollaborationPolicyCost,
    ) -> CollaborationPolicyEvaluationRequest {
        CollaborationPolicyEvaluationRequest::new(
            target(resource),
            cost,
            fresh_local_approval_proven,
        )
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

    #[test]
    fn evaluator_applies_deny_then_approval_then_allow_precedence() {
        let denied = CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            "denied",
            None,
            vec![
                evaluator_statement("allow", CollaborationPolicyEffect::Allow, None),
                evaluator_statement(
                    "approve",
                    CollaborationPolicyEffect::RequireLocalApproval,
                    None,
                ),
                evaluator_statement("deny", CollaborationPolicyEffect::Deny, None),
            ],
            vec![],
            CollaborationPolicyLimits::default(),
        )
        .unwrap();
        let context = evaluation_context(true, &[], true, false, false, None);
        assert_eq!(
            evaluate_collaboration_policy(
                &denied,
                &context,
                &evaluation_request(None, true, CollaborationPolicyCost::default()),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Deny(CollaborationPolicyDenialReason::PolicyDenied)
        );

        let approval = CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            "approval",
            None,
            vec![
                evaluator_statement("allow", CollaborationPolicyEffect::Allow, None),
                evaluator_statement(
                    "approve",
                    CollaborationPolicyEffect::RequireLocalApproval,
                    None,
                ),
            ],
            vec![],
            CollaborationPolicyLimits::default(),
        )
        .unwrap();
        assert_eq!(
            evaluate_collaboration_policy(
                &approval,
                &context,
                &evaluation_request(None, false, CollaborationPolicyCost::default()),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::RequireLocalApproval
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &approval,
                &context,
                &evaluation_request(None, true, CollaborationPolicyCost::default()),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Allow
        );
    }

    #[test]
    fn evaluator_intersects_exact_local_authority_harness_and_restrictions() {
        let bundle = CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            "intersection",
            None,
            vec![evaluator_statement(
                "allow",
                CollaborationPolicyEffect::Allow,
                Some("workspace.current"),
            )],
            vec!["copilot.tool-interception".to_string()],
            CollaborationPolicyLimits::default(),
        )
        .unwrap();
        let request = evaluation_request(
            Some("workspace.current"),
            false,
            CollaborationPolicyCost::default(),
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &evaluation_context(
                    false,
                    &["copilot.tool-interception"],
                    true,
                    false,
                    false,
                    Some("workspace.current"),
                ),
                &evaluation_request(
                    Some("workspace.current"),
                    true,
                    CollaborationPolicyCost::default(),
                ),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Deny(
                CollaborationPolicyDenialReason::LocalAuthorityMissing
            )
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &evaluation_context(true, &[], true, false, false, Some("workspace.current"),),
                &request,
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Deny(CollaborationPolicyDenialReason::HarnessClaimMissing)
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &evaluation_context(
                    true,
                    &["copilot.tool-interception"],
                    false,
                    false,
                    false,
                    Some("workspace.current"),
                ),
                &evaluation_request(
                    Some("workspace.current"),
                    true,
                    CollaborationPolicyCost::default(),
                ),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Deny(
                CollaborationPolicyDenialReason::HarnessControlMissing
            )
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &evaluation_context(
                    true,
                    &["copilot.tool-interception"],
                    true,
                    true,
                    false,
                    Some("workspace.current"),
                ),
                &evaluation_request(
                    Some("workspace.current"),
                    true,
                    CollaborationPolicyCost::default(),
                ),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Deny(
                CollaborationPolicyDenialReason::LocalRestrictionDenied
            )
        );
        let approval_context = evaluation_context(
            true,
            &["copilot.tool-interception"],
            true,
            false,
            true,
            Some("workspace.current"),
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &approval_context,
                &request,
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::RequireLocalApproval
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &approval_context,
                &evaluation_request(
                    Some("workspace.current"),
                    true,
                    CollaborationPolicyCost::default(),
                ),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Allow
        );
        assert_eq!(
            evaluate_collaboration_policy(
                &bundle,
                &evaluation_context(
                    true,
                    &["copilot.tool-interception"],
                    true,
                    false,
                    false,
                    None,
                ),
                &evaluation_request(None, true, CollaborationPolicyCost::default()),
                CollaborationPolicyUsage::default(),
            ),
            CollaborationPolicyDecision::Deny(CollaborationPolicyDenialReason::NoMatchingStatement)
        );
    }

    #[test]
    fn evaluator_checks_usage_plus_cost_without_weakening_unlimited_budgets() {
        let limited = CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            "limited",
            None,
            vec![evaluator_statement(
                "allow",
                CollaborationPolicyEffect::Allow,
                None,
            )],
            vec![],
            CollaborationPolicyLimits::new(Some(100), Some(2), Some(10), Some(1)).unwrap(),
        )
        .unwrap();
        let context = evaluation_context(true, &[], true, false, false, None);
        let cases = [
            (
                CollaborationPolicyUsage::new(100, 0, 0, 0),
                CollaborationPolicyCost::default(),
                CollaborationPolicyDenialReason::DurationLimitExceeded,
            ),
            (
                CollaborationPolicyUsage::new(99, 1, 0, 0),
                CollaborationPolicyCost::new(2, 0, 0),
                CollaborationPolicyDenialReason::TurnLimitExceeded,
            ),
            (
                CollaborationPolicyUsage::new(99, 0, 9, 0),
                CollaborationPolicyCost::new(0, 2, 0),
                CollaborationPolicyDenialReason::TokenLimitExceeded,
            ),
            (
                CollaborationPolicyUsage::new(99, 0, 0, 1),
                CollaborationPolicyCost::new(0, 0, 1),
                CollaborationPolicyDenialReason::ConcurrencyLimitExceeded,
            ),
            (
                CollaborationPolicyUsage::new(99, u64::MAX, 0, 0),
                CollaborationPolicyCost::new(1, 0, 0),
                CollaborationPolicyDenialReason::TurnLimitExceeded,
            ),
        ];
        for (usage, cost, reason) in cases {
            assert_eq!(
                evaluate_collaboration_policy(
                    &limited,
                    &context,
                    &evaluation_request(None, true, cost),
                    usage,
                ),
                CollaborationPolicyDecision::Deny(reason)
            );
        }
        assert_eq!(
            evaluate_collaboration_policy(
                &limited,
                &context,
                &evaluation_request(None, true, CollaborationPolicyCost::new(1, 5, 1)),
                CollaborationPolicyUsage::new(99, 1, 5, 0),
            ),
            CollaborationPolicyDecision::Allow
        );

        let unlimited = CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            "unlimited",
            None,
            vec![evaluator_statement(
                "allow",
                CollaborationPolicyEffect::Allow,
                None,
            )],
            vec![],
            CollaborationPolicyLimits::default(),
        )
        .unwrap();
        assert_eq!(
            evaluate_collaboration_policy(
                &unlimited,
                &context,
                &evaluation_request(
                    None,
                    true,
                    CollaborationPolicyCost::new(u64::MAX, u64::MAX, u32::MAX),
                ),
                CollaborationPolicyUsage::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX),
            ),
            CollaborationPolicyDecision::Allow
        );
    }

    #[test]
    fn evaluator_context_rejects_duplicate_targets_and_unproven_claim_shapes() {
        assert!(matches!(
            CollaborationPolicyEvaluationContext::new(
                vec![target(None), target(None)],
                vec![],
                vec![],
                vec![],
                vec![],
            ),
            Err(KonclaveDomainError::DuplicateIdentifier {
                field: "collaboration_policy_local_authority"
            })
        ));
        assert!(matches!(
            CollaborationPolicyEvaluationContext::new(
                vec![],
                vec!["not-namespaced".to_string()],
                vec![],
                vec![],
                vec![],
            ),
            Err(KonclaveDomainError::NonCanonicalText {
                field: "collaboration_policy_harness_claim"
            })
        ));
        assert_eq!(
            CollaborationPolicyDenialReason::HarnessControlMissing.code(),
            "harness_control_missing"
        );
    }
}
