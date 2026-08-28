use KonclaveDomainCore::{
    COLLABORATION_POLICY_BUNDLE_MAJOR, CollaborationPolicyBundle, CollaborationPolicyDigest,
    CollaborationPolicyEffect, CollaborationPolicyLimits, CollaborationPolicyProposal,
    CollaborationPolicyProposalId, CollaborationPolicyResponse, CollaborationPolicyResponseOutcome,
    CollaborationPolicyRevocation, CollaborationPolicyStatement,
    MAX_COLLABORATION_POLICY_BUNDLE_BYTES, MAX_COLLABORATION_POLICY_HARNESS_CLAIMS,
    MAX_COLLABORATION_POLICY_STATEMENTS,
};

use crate::KonclaveProtocolError;
use crate::v1::common::{
    decode_bounded, encode_bounded, required, version_from_wire, version_to_wire,
};
use crate::wire::v1 as wire;

const CONTRACT: &str = "CollaborationPolicyBundle";

/// Encodes a validated collaboration-policy bundle into canonical protocol v1 bytes.
///
/// # Errors
///
/// Returns a typed protocol error when the bundle version is unsupported or the
/// canonical encoding exceeds its hard bound.
pub fn encode_collaboration_policy_bundle(
    value: &CollaborationPolicyBundle,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    if value.version().major() != COLLABORATION_POLICY_BUNDLE_MAJOR {
        return Err(KonclaveProtocolError::UnsupportedMajor {
            contract: CONTRACT,
            actual: value.version().major(),
        });
    }
    let wire = wire::CollaborationPolicyBundle {
        version: Some(version_to_wire(value.version())),
        name: value.name().to_string(),
        guidance: value.guidance().map(str::to_string),
        statements: value.statements().iter().map(statement_to_wire).collect(),
        required_harness_claims: value.required_harness_claims().to_vec(),
        limits: Some(limits_to_wire(value.limits())),
    };
    encode_bounded(&wire, MAX_COLLABORATION_POLICY_BUNDLE_BYTES, CONTRACT)
}

/// Decodes canonical protocol v1 collaboration-policy bytes.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error for malformed, oversized,
/// noncanonical, or semantically invalid input.
pub fn decode_collaboration_policy_bundle(
    bytes: &[u8],
) -> Result<CollaborationPolicyBundle, KonclaveProtocolError> {
    crate::v1::common::require_repeated_field_limits(
        bytes,
        MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
        CONTRACT,
        [
            (
                4,
                MAX_COLLABORATION_POLICY_STATEMENTS,
                "collaboration_policy_statements",
            ),
            (
                5,
                MAX_COLLABORATION_POLICY_HARNESS_CLAIMS,
                "collaboration_policy_harness_claims",
            ),
        ],
    )?;
    let wire: wire::CollaborationPolicyBundle =
        decode_bounded(bytes, MAX_COLLABORATION_POLICY_BUNDLE_BYTES, CONTRACT)?;
    let version = version_from_wire(wire.version, CONTRACT)?;
    let statements = wire
        .statements
        .into_iter()
        .map(statement_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    let limits = limits_from_wire(required(wire.limits, "collaboration_policy.limits")?)?;
    let bundle = CollaborationPolicyBundle::new(
        version,
        wire.name,
        wire.guidance,
        statements,
        wire.required_harness_claims,
        limits,
    )?;
    if encode_collaboration_policy_bundle(&bundle)? != bytes {
        return Err(KonclaveProtocolError::NonCanonicalEncoding { contract: CONTRACT });
    }
    Ok(bundle)
}

fn statement_to_wire(value: &CollaborationPolicyStatement) -> wire::CollaborationPolicyStatement {
    wire::CollaborationPolicyStatement {
        statement_id: value.statement_id().to_string(),
        effect: match value.effect() {
            CollaborationPolicyEffect::Allow => wire::CollaborationPolicyEffect::Allow as i32,
            CollaborationPolicyEffect::Deny => wire::CollaborationPolicyEffect::Deny as i32,
            CollaborationPolicyEffect::RequireLocalApproval => {
                wire::CollaborationPolicyEffect::RequireLocalApproval as i32
            }
        },
        action: value.action().to_string(),
        resource: value.resource().map(str::to_string),
    }
}

fn statement_from_wire(
    value: wire::CollaborationPolicyStatement,
) -> Result<CollaborationPolicyStatement, KonclaveProtocolError> {
    let effect = match wire::CollaborationPolicyEffect::try_from(value.effect) {
        Ok(wire::CollaborationPolicyEffect::Allow) => CollaborationPolicyEffect::Allow,
        Ok(wire::CollaborationPolicyEffect::Deny) => CollaborationPolicyEffect::Deny,
        Ok(wire::CollaborationPolicyEffect::RequireLocalApproval) => {
            CollaborationPolicyEffect::RequireLocalApproval
        }
        Ok(wire::CollaborationPolicyEffect::Unspecified) | Err(_) => {
            return Err(KonclaveProtocolError::UnsupportedEnum {
                field: "collaboration_policy_effect",
                value: value.effect,
            });
        }
    };
    Ok(CollaborationPolicyStatement::new(
        value.statement_id,
        effect,
        value.action,
        value.resource,
    )?)
}

fn limits_to_wire(value: CollaborationPolicyLimits) -> wire::CollaborationPolicyLimits {
    wire::CollaborationPolicyLimits {
        duration_milliseconds: value.duration_milliseconds(),
        turns: value.turns(),
        tokens: value.tokens(),
        concurrent_requests: value.concurrent_requests(),
    }
}

fn limits_from_wire(
    value: wire::CollaborationPolicyLimits,
) -> Result<CollaborationPolicyLimits, KonclaveProtocolError> {
    Ok(CollaborationPolicyLimits::new(
        value.duration_milliseconds,
        value.turns,
        value.tokens,
        value.concurrent_requests,
    )?)
}

pub(crate) fn proposal_to_wire(
    value: &CollaborationPolicyProposal,
) -> wire::CollaborationPolicyProposal {
    wire::CollaborationPolicyProposal {
        proposal_id: Some(proposal_id_to_wire(value.proposal_id())),
        policy_digest: Some(policy_digest_to_wire(value.policy_digest())),
        canonical_bundle: value.canonical_bundle().to_vec().into(),
        replaces_policy_digest: value.replaces_policy_digest().map(policy_digest_to_wire),
    }
}

pub(crate) fn proposal_from_wire(
    value: wire::CollaborationPolicyProposal,
) -> Result<CollaborationPolicyProposal, KonclaveProtocolError> {
    Ok(CollaborationPolicyProposal::new(
        proposal_id_from_wire(required(
            value.proposal_id,
            "collaboration_policy_proposal.proposal_id",
        )?)?,
        policy_digest_from_wire(required(
            value.policy_digest,
            "collaboration_policy_proposal.policy_digest",
        )?)?,
        value.canonical_bundle.to_vec(),
        value
            .replaces_policy_digest
            .map(policy_digest_from_wire)
            .transpose()?,
    )?)
}

pub(crate) fn response_to_wire(
    value: &CollaborationPolicyResponse,
) -> wire::CollaborationPolicyResponse {
    wire::CollaborationPolicyResponse {
        proposal_id: Some(proposal_id_to_wire(value.proposal_id())),
        policy_digest: Some(policy_digest_to_wire(value.policy_digest())),
        outcome: match value.outcome() {
            CollaborationPolicyResponseOutcome::Accepted => {
                wire::CollaborationPolicyResponseOutcome::Accepted as i32
            }
            CollaborationPolicyResponseOutcome::Rejected => {
                wire::CollaborationPolicyResponseOutcome::Rejected as i32
            }
        },
    }
}

pub(crate) fn response_from_wire(
    value: wire::CollaborationPolicyResponse,
) -> Result<CollaborationPolicyResponse, KonclaveProtocolError> {
    let outcome = match wire::CollaborationPolicyResponseOutcome::try_from(value.outcome) {
        Ok(wire::CollaborationPolicyResponseOutcome::Accepted) => {
            CollaborationPolicyResponseOutcome::Accepted
        }
        Ok(wire::CollaborationPolicyResponseOutcome::Rejected) => {
            CollaborationPolicyResponseOutcome::Rejected
        }
        Ok(wire::CollaborationPolicyResponseOutcome::Unspecified) | Err(_) => {
            return Err(KonclaveProtocolError::UnsupportedEnum {
                field: "collaboration_policy_response_outcome",
                value: value.outcome,
            });
        }
    };
    Ok(CollaborationPolicyResponse::new(
        proposal_id_from_wire(required(
            value.proposal_id,
            "collaboration_policy_response.proposal_id",
        )?)?,
        policy_digest_from_wire(required(
            value.policy_digest,
            "collaboration_policy_response.policy_digest",
        )?)?,
        outcome,
    ))
}

pub(crate) fn revocation_to_wire(
    value: &CollaborationPolicyRevocation,
) -> wire::CollaborationPolicyRevocation {
    wire::CollaborationPolicyRevocation {
        policy_digest: Some(policy_digest_to_wire(value.policy_digest())),
    }
}

pub(crate) fn revocation_from_wire(
    value: wire::CollaborationPolicyRevocation,
) -> Result<CollaborationPolicyRevocation, KonclaveProtocolError> {
    Ok(CollaborationPolicyRevocation::new(policy_digest_from_wire(
        required(
            value.policy_digest,
            "collaboration_policy_revocation.policy_digest",
        )?,
    )?))
}

fn proposal_id_to_wire(
    value: CollaborationPolicyProposalId,
) -> wire::CollaborationPolicyProposalId {
    wire::CollaborationPolicyProposalId {
        value: value.as_bytes().to_vec().into(),
    }
}

fn proposal_id_from_wire(
    value: wire::CollaborationPolicyProposalId,
) -> Result<CollaborationPolicyProposalId, KonclaveProtocolError> {
    Ok(CollaborationPolicyProposalId::from_slice(&value.value)?)
}

fn policy_digest_to_wire(value: CollaborationPolicyDigest) -> wire::CollaborationPolicyDigest {
    wire::CollaborationPolicyDigest {
        value: value.as_bytes().to_vec().into(),
    }
}

fn policy_digest_from_wire(
    value: wire::CollaborationPolicyDigest,
) -> Result<CollaborationPolicyDigest, KonclaveProtocolError> {
    Ok(CollaborationPolicyDigest::from_slice(&value.value)?)
}
