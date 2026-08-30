use std::fmt;
use std::marker::PhantomData;
use std::path::Path;

use KonclaveBoundedDocuments::{
    BoundedDocumentError, BoundedVec, deserialize_strict, read_bounded_regular_file,
};
use KonclaveCryptographicCore::derive_collaboration_policy_digest;
use KonclaveDomainCore::{
    CollaborationPolicyBundle, CollaborationPolicyDigest, CollaborationPolicyEffect,
    CollaborationPolicyLimits, CollaborationPolicyStatement,
    MAX_COLLABORATION_POLICY_HARNESS_CLAIMS, MAX_COLLABORATION_POLICY_STATEMENTS, ProtocolVersion,
    validate_collaboration_policy_name,
};
use KonclaveProtocolContracts::v1::encode_collaboration_policy_bundle;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer};

use crate::CollaborationPolicySourceError;
use crate::file::create_new_file;

pub const MAX_COLLABORATION_POLICY_SOURCE_BYTES: usize = 128 * 1024;
const SOURCE_API_VERSION_V1: &str = "konclave.dev/v1";
const SOURCE_API_VERSION_V2: &str = "konclave.dev/v2";
const SOURCE_KIND: &str = "CollaborationPolicy";

/// Canonical policy bundle, digest, and bytes produced from one editable source.
pub struct CompiledCollaborationPolicy {
    bundle: CollaborationPolicyBundle,
    digest: CollaborationPolicyDigest,
    canonical_bytes: Vec<u8>,
}

impl CompiledCollaborationPolicy {
    /// Returns the validated source-independent policy bundle.
    #[must_use]
    pub const fn bundle(&self) -> &CollaborationPolicyBundle {
        &self.bundle
    }

    /// Returns the domain-separated canonical bundle digest.
    #[must_use]
    pub const fn digest(&self) -> CollaborationPolicyDigest {
        self.digest
    }

    /// Returns the canonical policy-bundle bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Compiles one bounded strict-JSON collaboration-policy source.
///
/// Version 2 rejects legacy guidance. Version 1 remains readable so historical
/// source can reproduce its canonical bytes and digest.
///
/// Missing source limits inherit from `defaults`; explicit JSON `null` is unlimited.
///
/// # Errors
///
/// Returns a typed source, domain, canonical encoding, or digest failure.
pub fn compile_collaboration_policy_source(
    bytes: &[u8],
    defaults: CollaborationPolicyLimits,
) -> Result<CompiledCollaborationPolicy, CollaborationPolicySourceError> {
    if bytes.len() > MAX_COLLABORATION_POLICY_SOURCE_BYTES {
        return Err(CollaborationPolicySourceError::DocumentTooLarge {
            document: "source",
            maximum: MAX_COLLABORATION_POLICY_SOURCE_BYTES,
        });
    }
    let source: CollaborationPolicySource =
        deserialize_strict(bytes, MAX_COLLABORATION_POLICY_SOURCE_BYTES)
            .map_err(|error| map_document_error(error, "source"))?;
    if source.kind != SOURCE_KIND {
        return Err(CollaborationPolicySourceError::UnsupportedKind);
    }
    let guidance = match source.api_version.as_str() {
        SOURCE_API_VERSION_V1 => source.spec.guidance.value,
        SOURCE_API_VERSION_V2 if !source.spec.guidance.present => None,
        SOURCE_API_VERSION_V2 => {
            return Err(CollaborationPolicySourceError::InvalidJson { document: "source" });
        }
        _ => return Err(CollaborationPolicySourceError::UnsupportedApiVersion),
    };
    let statements = source
        .spec
        .statements
        .into_inner()
        .into_iter()
        .map(|statement| {
            CollaborationPolicyStatement::new(
                statement.id,
                statement.effect.into(),
                statement.action,
                statement.resource,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let limits = CollaborationPolicyLimits::new(
        source
            .spec
            .limits
            .duration_milliseconds
            .resolve(defaults.duration_milliseconds()),
        source.spec.limits.turns.resolve(defaults.turns()),
        source.spec.limits.tokens.resolve(defaults.tokens()),
        source
            .spec
            .limits
            .concurrent_requests
            .resolve(defaults.concurrent_requests()),
    )?;
    let bundle = CollaborationPolicyBundle::new(
        ProtocolVersion::application_v1(),
        source.metadata.name,
        guidance,
        statements,
        source.spec.required_harness_claims.into_inner(),
        limits,
    )?;
    let canonical_bytes = encode_collaboration_policy_bundle(&bundle)
        .map_err(|_| CollaborationPolicySourceError::ProtocolContract)?;
    let digest = derive_collaboration_policy_digest(&bundle)
        .map_err(|_| CollaborationPolicySourceError::Digest)?;
    Ok(CompiledCollaborationPolicy {
        bundle,
        digest,
        canonical_bytes,
    })
}

/// Reads and compiles one explicitly selected regular source file.
///
/// # Errors
///
/// Returns a typed file, source, domain, encoding, or digest failure.
pub fn compile_collaboration_policy_file(
    path: &Path,
    defaults: CollaborationPolicyLimits,
) -> Result<CompiledCollaborationPolicy, CollaborationPolicySourceError> {
    let bytes = read_bounded_regular_file(path, MAX_COLLABORATION_POLICY_SOURCE_BYTES)
        .map_err(|error| map_document_error(error, "source"))?;
    compile_collaboration_policy_source(&bytes, defaults)
}

/// Creates one editable strict-JSON policy source without overwriting an existing file.
///
/// The version-2 template contains no guidance or product-defined collaboration
/// statements and resolves every optional semantic limit to explicitly unlimited.
///
/// # Errors
///
/// Returns a name-validation, encoding, or exclusive-file-creation failure.
pub fn create_collaboration_policy_source_file(
    path: &Path,
    name: &str,
) -> Result<(), CollaborationPolicySourceError> {
    validate_collaboration_policy_name(name)?;
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "apiVersion": SOURCE_API_VERSION_V2,
        "kind": SOURCE_KIND,
        "metadata": {
            "name": name,
        },
        "spec": {
            "statements": [],
            "requiredHarnessClaims": [],
            "limits": {
                "durationMilliseconds": null,
                "turns": null,
                "tokens": null,
                "concurrentRequests": null,
            },
        },
    }))
    .map_err(|_| CollaborationPolicySourceError::InvalidJson { document: "source" })?;
    bytes.push(b'\n');
    create_new_file(path, &bytes, "source")
}

/// Writes canonical policy-bundle bytes without overwriting an existing file.
///
/// # Errors
///
/// Returns an exclusive-file-creation failure.
pub fn write_compiled_collaboration_policy_file(
    path: &Path,
    compiled: &CompiledCollaborationPolicy,
) -> Result<(), CollaborationPolicySourceError> {
    create_new_file(path, compiled.canonical_bytes(), "bundle")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CollaborationPolicySource {
    api_version: String,
    kind: String,
    metadata: SourceMetadata,
    spec: SourceSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMetadata {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceSpec {
    #[serde(default)]
    guidance: SourceGuidance,
    #[serde(default)]
    statements: BoundedVec<SourceStatement, MAX_COLLABORATION_POLICY_STATEMENTS>,
    #[serde(default)]
    required_harness_claims: BoundedVec<String, MAX_COLLABORATION_POLICY_HARNESS_CLAIMS>,
    #[serde(default)]
    limits: SourceLimits,
}

#[derive(Default)]
struct SourceGuidance {
    present: bool,
    value: Option<String>,
}

impl<'de> Deserialize<'de> for SourceGuidance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<String>::deserialize(deserializer)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceStatement {
    id: String,
    effect: SourceEffect,
    action: String,
    resource: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceEffect {
    Allow,
    Deny,
    RequireLocalApproval,
}

impl From<SourceEffect> for CollaborationPolicyEffect {
    fn from(value: SourceEffect) -> Self {
        match value {
            SourceEffect::Allow => Self::Allow,
            SourceEffect::Deny => Self::Deny,
            SourceEffect::RequireLocalApproval => Self::RequireLocalApproval,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceLimits {
    #[serde(default)]
    duration_milliseconds: SourceLimitU64,
    #[serde(default)]
    turns: SourceLimitU64,
    #[serde(default)]
    tokens: SourceLimitU64,
    #[serde(default)]
    concurrent_requests: SourceLimitU32,
}

#[derive(Clone, Copy, Default)]
enum SourceLimit<T> {
    #[default]
    Inherit,
    Unlimited,
    Finite(T),
}

type SourceLimitU64 = SourceLimit<u64>;
type SourceLimitU32 = SourceLimit<u32>;

impl<T: Copy> SourceLimit<T> {
    fn resolve(self, default: Option<T>) -> Option<T> {
        match self {
            Self::Inherit => default,
            Self::Unlimited => None,
            Self::Finite(value) => Some(value),
        }
    }
}

impl<'de> Deserialize<'de> for SourceLimitU64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SourceLimitVisitor::<u64>(PhantomData))
    }
}

impl<'de> Deserialize<'de> for SourceLimitU32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SourceLimitVisitor::<u32>(PhantomData))
    }
}

struct SourceLimitVisitor<T>(PhantomData<T>);

impl<'de> Visitor<'de> for SourceLimitVisitor<u64> {
    type Value = SourceLimitU64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a positive integer or null")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(SourceLimit::Unlimited)
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(SourceLimit::Finite(value))
    }
}

impl<'de> Visitor<'de> for SourceLimitVisitor<u32> {
    type Value = SourceLimitU32;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a positive 32-bit integer or null")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(SourceLimit::Unlimited)
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        u32::try_from(value)
            .map(SourceLimit::Finite)
            .map_err(|_| E::custom("integer exceeds uint32"))
    }
}

pub(crate) fn map_document_error(
    error: BoundedDocumentError,
    document: &'static str,
) -> CollaborationPolicySourceError {
    match error {
        BoundedDocumentError::FileUnavailable => {
            CollaborationPolicySourceError::FileUnavailable { document }
        }
        BoundedDocumentError::DocumentTooLarge { maximum } => {
            CollaborationPolicySourceError::DocumentTooLarge { document, maximum }
        }
        BoundedDocumentError::InvalidJson => {
            CollaborationPolicySourceError::InvalidJson { document }
        }
        BoundedDocumentError::UnsafeCatalogPath => {
            CollaborationPolicySourceError::UnsafeCatalogPath
        }
    }
}
