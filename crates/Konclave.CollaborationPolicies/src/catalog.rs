use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use KonclaveDomainCore::{
    CollaborationPolicyLimits, MAX_COLLABORATION_POLICY_STATEMENTS,
    validate_collaboration_policy_name,
};
use serde::Deserialize;

use crate::file::read_bounded_regular_file;
use crate::source::{BoundedVec, CompiledCollaborationPolicy, deserialize_strict};
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
        let bytes = read_bounded_regular_file(path, MAX_CATALOG_BYTES, "catalog")?;
        let descriptor: CatalogDescriptor = deserialize_strict(&bytes, "catalog")?;
        if descriptor.schema_version != CATALOG_SCHEMA_VERSION {
            return Err(CollaborationPolicySourceError::UnsupportedCatalogVersion);
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_root = parent
            .canonicalize()
            .map_err(|_| CollaborationPolicySourceError::UnsafeCatalogPath)?;
        let mut entries = BTreeMap::new();
        let mut source_paths = BTreeSet::new();
        for entry in descriptor.entries.into_inner() {
            validate_collaboration_policy_name(&entry.name)?;
            if !portable_catalog_source(&entry.source) {
                return Err(CollaborationPolicySourceError::UnsafeCatalogPath);
            }
            let relative = Path::new(&entry.source);
            if relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(CollaborationPolicySourceError::UnsafeCatalogPath);
            }
            let source = canonical_root.join(relative);
            let source_metadata = std::fs::symlink_metadata(&source)
                .map_err(|_| CollaborationPolicySourceError::UnsafeCatalogPath)?;
            if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
                return Err(CollaborationPolicySourceError::UnsafeCatalogPath);
            }
            let canonical_source = source
                .canonicalize()
                .map_err(|_| CollaborationPolicySourceError::UnsafeCatalogPath)?;
            if !canonical_source.starts_with(&canonical_root) {
                return Err(CollaborationPolicySourceError::UnsafeCatalogPath);
            }
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

fn portable_catalog_source(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.starts_with('.')
        && !value.starts_with('/')
        && !value.contains('\\')
        && value.ends_with(".json")
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.ends_with('.')
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
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
