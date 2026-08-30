use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use KonclaveA2AContracts::{InitialA2AAgentCard, InitialA2AInterfaceEnvironment};
use KonclaveA2ADomain::A2AAgentId;
use KonclaveBoundedDocuments::{
    BoundedVec, JsonFileCatalogRoot, deserialize_strict, read_bounded_regular_file,
};
use serde::Deserialize;

use crate::source::map_document_error;
use crate::{
    A2ADiscoveryAction, A2ADiscoveryAuthorizationDecision, A2ADiscoveryAuthorizer,
    A2ADiscoveryError, CompiledA2AAgentPublication, OasfAgentRecord,
    compile_a2a_agent_publication_file,
};

/// Maximum byte length of one file-catalog descriptor.
pub const MAX_A2A_AGENT_CATALOG_BYTES: usize = 64 * 1024;
/// Maximum number of publications in one self-hosted file catalog.
pub const MAX_A2A_AGENT_CATALOG_ENTRIES: usize = 64;
const CATALOG_SCHEMA_VERSION: u32 = 1;

/// Eagerly validated private-by-default self-hosted Agent Card catalog.
pub struct FileA2AAgentCatalog {
    entries: BTreeMap<A2AAgentId, CompiledA2AAgentPublication>,
}

impl FileA2AAgentCatalog {
    /// Opens an explicit descriptor and eagerly compiles every listed publication.
    ///
    /// The catalog never scans its directory. Each source must be a unique regular
    /// JSON file beneath the descriptor's physical parent directory.
    ///
    /// # Errors
    ///
    /// Returns a typed descriptor, path, duplicate, identity, publication, or OASF
    /// validation error.
    pub fn open(
        path: &Path,
        environment: InitialA2AInterfaceEnvironment,
    ) -> Result<Self, A2ADiscoveryError> {
        let bytes = read_bounded_regular_file(path, MAX_A2A_AGENT_CATALOG_BYTES)
            .map_err(|error| map_document_error(error, "catalog"))?;
        let descriptor: CatalogDescriptor = deserialize_strict(&bytes, MAX_A2A_AGENT_CATALOG_BYTES)
            .map_err(|error| map_document_error(error, "catalog"))?;
        if descriptor.schema_version != CATALOG_SCHEMA_VERSION {
            return Err(A2ADiscoveryError::UnsupportedCatalogVersion);
        }
        let root = JsonFileCatalogRoot::from_descriptor(path)
            .map_err(|_| A2ADiscoveryError::UnsafeCatalogPath)?;
        let mut entries = BTreeMap::new();
        let mut sources = BTreeSet::new();
        for entry in descriptor.entries.into_inner() {
            let id =
                A2AAgentId::parse(entry.name).map_err(|_| A2ADiscoveryError::InvalidAgentId)?;
            let source = root
                .resolve(&entry.source)
                .map_err(|_| A2ADiscoveryError::UnsafeCatalogPath)?;
            if !sources.insert(source.clone()) {
                return Err(A2ADiscoveryError::DuplicateCatalogEntry { field: "source" });
            }
            let publication = compile_a2a_agent_publication_file(&source, environment)?;
            if publication.id() != &id {
                return Err(A2ADiscoveryError::CatalogNameMismatch);
            }
            if entries.insert(id, publication).is_some() {
                return Err(A2ADiscoveryError::DuplicateCatalogEntry { field: "name" });
            }
        }
        Ok(Self { entries })
    }

    /// Resolves an explicitly public card without revealing private or absent entries.
    #[must_use]
    pub fn public_card(&self, agent_id: &A2AAgentId) -> Option<&InitialA2AAgentCard> {
        self.entries
            .get(agent_id)
            .filter(|publication| publication.publicly_discoverable())
            .map(CompiledA2AAgentPublication::card)
    }

    /// Resolves one private base card after deployment authorization.
    ///
    /// # Errors
    ///
    /// Returns authorization or not-found errors without performing a fallback lookup.
    pub fn private_card(
        &self,
        agent_id: &A2AAgentId,
        authorizer: &impl A2ADiscoveryAuthorizer,
    ) -> Result<&InitialA2AAgentCard, A2ADiscoveryError> {
        authorize(
            authorizer,
            A2ADiscoveryAction::ReadPrivateCard,
            Some(agent_id),
        )?;
        self.entries
            .get(agent_id)
            .map(CompiledA2AAgentPublication::card)
            .ok_or(A2ADiscoveryError::PublicationNotFound)
    }

    /// Resolves one extended card after deployment authorization.
    ///
    /// # Errors
    ///
    /// Returns authorization, not-found, or not-configured errors.
    pub fn extended_card(
        &self,
        agent_id: &A2AAgentId,
        authorizer: &impl A2ADiscoveryAuthorizer,
    ) -> Result<&InitialA2AAgentCard, A2ADiscoveryError> {
        authorize(
            authorizer,
            A2ADiscoveryAction::ReadExtendedCard,
            Some(agent_id),
        )?;
        self.entries
            .get(agent_id)
            .ok_or(A2ADiscoveryError::PublicationNotFound)?
            .extended_card()
            .ok_or(A2ADiscoveryError::ExtendedCardNotConfigured)
    }

    /// Returns canonical catalog identifiers after deployment authorization.
    ///
    /// # Errors
    ///
    /// Returns an authorization error without exposing catalog contents.
    pub fn list(
        &self,
        authorizer: &impl A2ADiscoveryAuthorizer,
    ) -> Result<Vec<A2AAgentId>, A2ADiscoveryError> {
        authorize(authorizer, A2ADiscoveryAction::ListCatalog, None)?;
        Ok(self.entries.keys().cloned().collect())
    }

    /// Resolves one generated OASF record after deployment authorization.
    ///
    /// # Errors
    ///
    /// Returns authorization, not-found, or not-configured errors.
    pub fn oasf_record(
        &self,
        agent_id: &A2AAgentId,
        authorizer: &impl A2ADiscoveryAuthorizer,
    ) -> Result<&OasfAgentRecord, A2ADiscoveryError> {
        authorize(
            authorizer,
            A2ADiscoveryAction::ReadOasfProjection,
            Some(agent_id),
        )?;
        self.entries
            .get(agent_id)
            .ok_or(A2ADiscoveryError::PublicationNotFound)?
            .oasf_record()
            .ok_or(A2ADiscoveryError::OasfProjectionNotConfigured)
    }
}

fn authorize(
    authorizer: &impl A2ADiscoveryAuthorizer,
    action: A2ADiscoveryAction,
    agent_id: Option<&A2AAgentId>,
) -> Result<(), A2ADiscoveryError> {
    match authorizer.authorize(action, agent_id) {
        A2ADiscoveryAuthorizationDecision::Allow => Ok(()),
        A2ADiscoveryAuthorizationDecision::Deny => Err(A2ADiscoveryError::Unauthorized),
        A2ADiscoveryAuthorizationDecision::Unavailable => {
            Err(A2ADiscoveryError::AuthorizationUnavailable)
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogDescriptor {
    schema_version: u32,
    entries: BoundedVec<CatalogEntry, MAX_A2A_AGENT_CATALOG_ENTRIES>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    name: String,
    source: String,
}
