use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use KonclaveBoundedDocuments::{
    BoundedDocumentError, BoundedVec, JsonFileCatalogRoot, deserialize_strict,
    read_bounded_regular_file,
};
use KonclaveDomainCore::{
    CollaborationPolicyLimits, MAX_COLLABORATION_POLICY_STATEMENTS,
    validate_collaboration_policy_name,
};
use serde::Deserialize;

use crate::source::CompiledCollaborationPolicy;
use crate::{CollaborationPolicySourceError, compile_collaboration_policy_file};

const CATALOG_SCHEMA_VERSION: u32 = 1;
const MAX_CATALOG_BYTES: usize = 64 * 1024;
const MAX_CATALOG_ENTRIES: usize = MAX_COLLABORATION_POLICY_STATEMENTS;

/// Explicit descriptor-backed catalog of collaboration-policy source files.
pub struct FileCollaborationPolicyCatalog {
    entries: BTreeMap<String, PathBuf>,
}

impl FileCollaborationPolicyCatalog {
    /// Opens and validates one explicitly selected catalog descriptor.
    ///
    /// The catalog never scans its directory. Every source must be listed and resolve
    /// to a regular JSON file beneath the descriptor's physical parent directory.
    ///
    /// # Errors
    ///
    /// Returns a typed file, schema, duplicate, path, or domain validation failure.
    pub fn open(path: &Path) -> Result<Self, CollaborationPolicySourceError> {
        let bytes = read_bounded_regular_file(path, MAX_CATALOG_BYTES)
            .map_err(map_catalog_document_error)?;
        let descriptor: CatalogDescriptor =
            deserialize_strict(&bytes, MAX_CATALOG_BYTES).map_err(map_catalog_document_error)?;
        if descriptor.schema_version != CATALOG_SCHEMA_VERSION {
            return Err(CollaborationPolicySourceError::UnsupportedCatalogVersion);
        }
        let root =
            JsonFileCatalogRoot::from_descriptor(path).map_err(map_catalog_document_error)?;
        let mut entries = BTreeMap::new();
        let mut source_paths = BTreeSet::new();
        for entry in descriptor.entries.into_inner() {
            validate_collaboration_policy_name(&entry.name)?;
            let canonical_source = root
                .resolve(&entry.source)
                .map_err(map_catalog_document_error)?;
            if entries.contains_key(&entry.name) {
                return Err(CollaborationPolicySourceError::DuplicateCatalogEntry {
                    field: "name",
                });
            }
            if !source_paths.insert(canonical_source.clone()) {
                return Err(CollaborationPolicySourceError::DuplicateCatalogEntry {
                    field: "source",
                });
            }
            entries.insert(entry.name, canonical_source);
        }
        Ok(Self { entries })
    }

    /// Returns catalog names in canonical lexical order.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Compiles one named source using fully materialized local defaults.
    ///
    /// # Errors
    ///
    /// Returns a typed missing-entry, file, source, name-mismatch, encoding, or digest
    /// failure.
    pub fn compile(
        &self,
        name: &str,
        defaults: CollaborationPolicyLimits,
    ) -> Result<CompiledCollaborationPolicy, CollaborationPolicySourceError> {
        validate_collaboration_policy_name(name)?;
        let source = self
            .entries
            .get(name)
            .ok_or(CollaborationPolicySourceError::PolicyNotFound)?;
        let compiled = compile_collaboration_policy_file(source, defaults)?;
        if compiled.bundle().name() != name {
            return Err(CollaborationPolicySourceError::CatalogNameMismatch);
        }
        Ok(compiled)
    }
}

fn map_catalog_document_error(error: BoundedDocumentError) -> CollaborationPolicySourceError {
    match error {
        BoundedDocumentError::DocumentTooLarge { maximum } => {
            CollaborationPolicySourceError::DocumentTooLarge {
                document: "catalog",
                maximum,
            }
        }
        BoundedDocumentError::InvalidJson => CollaborationPolicySourceError::InvalidJson {
            document: "catalog",
        },
        BoundedDocumentError::FileUnavailable | BoundedDocumentError::UnsafeCatalogPath => {
            CollaborationPolicySourceError::UnsafeCatalogPath
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogDescriptor {
    schema_version: u32,
    entries: BoundedVec<CatalogEntry, MAX_CATALOG_ENTRIES>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    name: String,
    source: String,
}
