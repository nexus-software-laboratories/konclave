use KonclaveDomainCore::{
    COLLABORATION_POLICY_BUNDLE_MAJOR, CollaborationPolicyBundle, CollaborationPolicyEffect,
    CollaborationPolicyLimits, CollaborationPolicyStatement, MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
    MAX_COLLABORATION_POLICY_HARNESS_CLAIMS, MAX_COLLABORATION_POLICY_STATEMENTS,
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
