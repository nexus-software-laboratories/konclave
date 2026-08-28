use KonclaveDomainCore::{
    CollaborationPolicyBundle, CollaborationPolicyDigest, CollaborationPolicyProposal,
};
use KonclaveProtocolContracts::v1::{
    decode_collaboration_policy_bundle, encode_collaboration_policy_bundle,
};
use aws_lc_rs::digest::{Context, SHA256};

use crate::KonclaveCryptographicError;

const COLLABORATION_POLICY_DIGEST_DOMAIN: &[u8] =
    b"konclave-collaboration-policy-bundle-digest-v1\0";

/// Derives the content identifier for one canonical collaboration-policy bundle.
///
/// # Errors
///
/// Returns [`KonclaveCryptographicError::ProtocolContractFailure`] when the bundle
/// cannot be encoded by the selected canonical policy contract.
pub fn derive_collaboration_policy_digest(
    bundle: &CollaborationPolicyBundle,
) -> Result<CollaborationPolicyDigest, KonclaveCryptographicError> {
    let canonical = encode_collaboration_policy_bundle(bundle)
        .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
    let mut context = Context::new(&SHA256);
    context.update(COLLABORATION_POLICY_DIGEST_DOMAIN);
    context.update(&canonical);
    Ok(CollaborationPolicyDigest::from_slice(
        context.finish().as_ref(),
    )?)
}

/// A proposal whose canonical bundle decodes and matches its claimed digest.
pub struct VerifiedCollaborationPolicyProposal<'a> {
    proposal: &'a CollaborationPolicyProposal,
    bundle: CollaborationPolicyBundle,
}

impl VerifiedCollaborationPolicyProposal<'_> {
    /// Returns the authenticated proposal metadata and canonical bytes.
    #[must_use]
    pub const fn proposal(&self) -> &CollaborationPolicyProposal {
        self.proposal
    }

    /// Returns the decoded canonical policy bundle.
    #[must_use]
    pub const fn bundle(&self) -> &CollaborationPolicyBundle {
        &self.bundle
    }
}

/// Verifies that a proposal carries one canonical bundle matching its claimed digest.
///
/// # Errors
///
/// Returns [`KonclaveCryptographicError::ProtocolContractFailure`] when the
/// embedded bundle is malformed or noncanonical, and
/// [`KonclaveCryptographicError::InvalidCollaborationPolicyDigest`] when its
/// derived digest differs from the proposal.
pub fn verify_collaboration_policy_proposal(
    proposal: &CollaborationPolicyProposal,
) -> Result<VerifiedCollaborationPolicyProposal<'_>, KonclaveCryptographicError> {
    let bundle = decode_collaboration_policy_bundle(proposal.canonical_bundle())
        .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
    let actual_digest = derive_collaboration_policy_digest(&bundle)?;
    if actual_digest != proposal.policy_digest() {
        return Err(KonclaveCryptographicError::InvalidCollaborationPolicyDigest);
    }
    Ok(VerifiedCollaborationPolicyProposal { proposal, bundle })
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::{
        CollaborationPolicyEffect, CollaborationPolicyLimits, CollaborationPolicyProposal,
        CollaborationPolicyProposalId, CollaborationPolicyStatement, ProtocolVersion,
    };

    use super::*;

    fn bundle(name: &str, guidance: &str) -> CollaborationPolicyBundle {
        CollaborationPolicyBundle::new(
            ProtocolVersion::application_v1(),
            name,
            Some(guidance.to_string()),
            vec![
                CollaborationPolicyStatement::new(
                    "conversation-reply",
                    CollaborationPolicyEffect::Allow,
                    "conversation.reply",
                    None,
                )
                .unwrap(),
                CollaborationPolicyStatement::new(
                    "workspace-write",
                    CollaborationPolicyEffect::RequireLocalApproval,
                    "workspace.modify",
                    Some("workspace.current".to_string()),
                )
                .unwrap(),
            ],
            vec![
                "copilot.tool-interception".to_string(),
                "copilot.session-identity".to_string(),
            ],
            CollaborationPolicyLimits::new(None, None, Some(10_000), Some(1)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let first = derive_collaboration_policy_digest(&bundle(
            "contract-alignment",
            "Align the API contract and report decisions.",
        ))
        .unwrap();
        let repeated = derive_collaboration_policy_digest(&bundle(
            "contract-alignment",
            "Align the API contract and report decisions.",
        ))
        .unwrap();
        let changed = derive_collaboration_policy_digest(&bundle(
            "contract-alignment",
            "Align a different contract.",
        ))
        .unwrap();

        assert_eq!(first, repeated);
        assert_ne!(first, changed);
        assert_eq!(
            first.as_bytes(),
            &[
                0xf8, 0x18, 0x9b, 0x64, 0x71, 0x27, 0xaa, 0x9f, 0xf9, 0xd0, 0x3f, 0x5c, 0x2d, 0x04,
                0x8b, 0xcd, 0x8e, 0xb8, 0x60, 0x06, 0x20, 0xbc, 0x17, 0x96, 0xc4, 0xc6, 0x68, 0xfa,
                0x59, 0x90, 0xeb, 0x2e,
            ]
        );
    }

    #[test]
    fn proposal_verification_requires_canonical_matching_bundle() {
        let expected_bundle = bundle(
            "contract-alignment",
            "Align the API contract and report decisions.",
        );
        let canonical = encode_collaboration_policy_bundle(&expected_bundle).unwrap();
        let digest = derive_collaboration_policy_digest(&expected_bundle).unwrap();
        let proposal = CollaborationPolicyProposal::new(
            CollaborationPolicyProposalId::from_bytes([1; 16]),
            digest,
            canonical.clone(),
            Some(CollaborationPolicyDigest::from_bytes([2; 32])),
        )
        .unwrap();

        let verified = verify_collaboration_policy_proposal(&proposal).unwrap();
        assert_eq!(verified.bundle().name(), "contract-alignment");
        assert_eq!(
            verified.proposal().replaces_policy_digest(),
            Some(CollaborationPolicyDigest::from_bytes([2; 32]))
        );

        let mismatched = CollaborationPolicyProposal::new(
            CollaborationPolicyProposalId::from_bytes([3; 16]),
            CollaborationPolicyDigest::from_bytes([4; 32]),
            canonical.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            verify_collaboration_policy_proposal(&mismatched).err(),
            Some(KonclaveCryptographicError::InvalidCollaborationPolicyDigest)
        );

        let mut noncanonical = canonical;
        noncanonical.extend_from_slice(&[0x98, 0x06, 0x01]);
        let malformed = CollaborationPolicyProposal::new(
            CollaborationPolicyProposalId::from_bytes([5; 16]),
            digest,
            noncanonical,
            None,
        )
        .unwrap();
        assert_eq!(
            verify_collaboration_policy_proposal(&malformed).err(),
            Some(KonclaveCryptographicError::ProtocolContractFailure)
        );
    }
}
