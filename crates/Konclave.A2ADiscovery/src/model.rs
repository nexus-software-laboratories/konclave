use KonclaveA2AContracts::InitialA2AAgentCard;
use KonclaveA2ADomain::A2AAgentId;

use crate::OasfAgentRecord;

/// One compiled deployment-owned A2A publication.
pub struct CompiledA2AAgentPublication {
    pub(crate) id: A2AAgentId,
    pub(crate) publicly_discoverable: bool,
    pub(crate) card: InitialA2AAgentCard,
    pub(crate) extended_card: Option<InitialA2AAgentCard>,
    pub(crate) oasf_record: Option<OasfAgentRecord>,
}

impl CompiledA2AAgentPublication {
    /// Returns the canonical deployment-owned publication identifier.
    #[must_use]
    pub const fn id(&self) -> &A2AAgentId {
        &self.id
    }

    /// Returns whether exact unauthenticated well-known lookup may expose the card.
    #[must_use]
    pub const fn publicly_discoverable(&self) -> bool {
        self.publicly_discoverable
    }

    /// Returns the validated base card for direct trusted configuration.
    #[must_use]
    pub const fn card(&self) -> &InitialA2AAgentCard {
        &self.card
    }

    /// Returns the fixed authenticated extended card, when configured.
    #[must_use]
    pub const fn extended_card(&self) -> Option<&InitialA2AAgentCard> {
        self.extended_card.as_ref()
    }

    /// Returns the generated OASF record, when configured.
    #[must_use]
    pub const fn oasf_record(&self) -> Option<&OasfAgentRecord> {
        self.oasf_record.as_ref()
    }
}

/// Private discovery operation presented to deployment authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum A2ADiscoveryAction {
    /// Resolve one private base Agent Card.
    ReadPrivateCard,
    /// Resolve one authenticated extended Agent Card.
    ReadExtendedCard,
    /// Enumerate the bounded private catalog.
    ListCatalog,
    /// Resolve one authenticated OASF projection.
    ReadOasfProjection,
}

/// Explicit deployment authorization outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum A2ADiscoveryAuthorizationDecision {
    /// Permit the requested operation.
    Allow,
    /// Deny the requested operation.
    Deny,
    /// No reliable authorization decision is currently available.
    Unavailable,
}

/// Deployment-owned authorization boundary for private discovery.
///
/// A request-bound implementation may capture authenticated web identity and policy
/// without passing credentials or raw identity values into this crate.
pub trait A2ADiscoveryAuthorizer {
    /// Decides one action for an optional exact publication identifier.
    fn authorize(
        &self,
        action: A2ADiscoveryAction,
        agent_id: Option<&A2AAgentId>,
    ) -> A2ADiscoveryAuthorizationDecision;
}
