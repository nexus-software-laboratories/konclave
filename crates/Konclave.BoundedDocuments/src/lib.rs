#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::path::{Component, Path};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// Stable failures while reading or decoding bounded documents.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundedDocumentError {
    /// The selected path is unavailable, linked, or not a regular file.
    #[error("bounded document is unavailable")]
    FileUnavailable,
    /// The document exceeded its caller-selected byte bound.
    #[error("bounded document exceeds {maximum} bytes")]
    DocumentTooLarge {
        /// Largest accepted byte length.
        maximum: usize,
    },
    /// The document is not one complete strict JSON value.
    #[error("bounded document JSON is invalid")]
    InvalidJson,
    /// A catalog source path is rooted, linked, nonportable, or escapes its root.
    #[error("bounded document catalog path is unsafe")]
    UnsafeCatalogPath,
}

/// Reads one explicitly selected, non-linked regular file within a byte bound.
///
/// The file is checked both before and after opening. A bounded reader protects
/// against growth between metadata inspection and the read.
///
/// # Errors
///
/// Returns an unavailable error for missing, linked, or non-file paths and a size
/// error when metadata or read content exceeds `maximum`.
pub fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, BoundedDocumentError> {
    let link_metadata =
        std::fs::symlink_metadata(path).map_err(|_| BoundedDocumentError::FileUnavailable)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(BoundedDocumentError::FileUnavailable);
    }
    let file = File::open(path).map_err(|_| BoundedDocumentError::FileUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| BoundedDocumentError::FileUnavailable)?;
    if !metadata.is_file() {
        return Err(BoundedDocumentError::FileUnavailable);
    }
    if usize::try_from(metadata.len())
        .ok()
        .is_none_or(|length| length > maximum)
    {
        return Err(BoundedDocumentError::DocumentTooLarge { maximum });
    }
    let take_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(BoundedDocumentError::DocumentTooLarge { maximum })?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(maximum));
    file.take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedDocumentError::FileUnavailable)?;
    if bytes.len() > maximum {
        return Err(BoundedDocumentError::DocumentTooLarge { maximum });
    }
    Ok(bytes)
}

/// Deserializes exactly one strict JSON value with no trailing document.
///
/// Concrete document types remain responsible for `deny_unknown_fields` and semantic
/// validation.
///
/// # Errors
///
/// Returns [`BoundedDocumentError::InvalidJson`] for malformed input, duplicate
/// object keys, or
/// trailing non-whitespace content.
pub fn deserialize_strict<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, BoundedDocumentError> {
    if bytes.len() > maximum {
        return Err(BoundedDocumentError::DocumentTooLarge { maximum });
    }
    reject_duplicate_json_keys(bytes)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(|_| BoundedDocumentError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| BoundedDocumentError::InvalidJson)?;
    Ok(value)
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), BoundedDocumentError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJsonValue
        .deserialize(&mut deserializer)
        .map_err(|_| BoundedDocumentError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| BoundedDocumentError::InvalidJson)
}

struct UniqueJsonValue;

impl<'de> DeserializeSeed<'de> for UniqueJsonValue {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E: serde::de::Error>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E: serde::de::Error>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        UniqueJsonValue.deserialize(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        UniqueJsonValue.deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        while sequence.next_element_seed(UniqueJsonValue)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("JSON object key is duplicated"));
            }
            map.next_value_seed(UniqueJsonValue)?;
        }
        Ok(())
    }
}

/// Canonical physical root used to confine explicitly listed JSON catalog sources.
pub struct JsonFileCatalogRoot {
    root: Dir,
}

impl JsonFileCatalogRoot {
    /// Resolves the physical parent of one explicitly selected catalog descriptor.
    ///
    /// # Errors
    ///
    /// Returns an unsafe-path error when the descriptor has no usable physical
    /// parent.
    pub fn from_descriptor(path: &Path) -> Result<Self, BoundedDocumentError> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let root = parent
            .canonicalize()
            .map_err(|_| BoundedDocumentError::UnsafeCatalogPath)?;
        let root = Dir::open_ambient_dir(root, ambient_authority())
            .map_err(|_| BoundedDocumentError::UnsafeCatalogPath)?;
        Ok(Self { root })
    }

    /// Opens and reads one portable relative JSON source beneath the pinned catalog
    /// root.
    ///
    /// # Errors
    ///
    /// Returns an unsafe-path error for rooted, hidden, traversing, linked, missing,
    /// non-JSON, or root-escaping sources, and a size error when content exceeds
    /// `maximum`.
    pub fn read(&self, source: &str, maximum: usize) -> Result<Vec<u8>, BoundedDocumentError> {
        if !portable_json_source(source) {
            return Err(BoundedDocumentError::UnsafeCatalogPath);
        }
        let relative = Path::new(source);
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(BoundedDocumentError::UnsafeCatalogPath);
        }
        let metadata = self
            .root
            .symlink_metadata(relative)
            .map_err(|_| BoundedDocumentError::UnsafeCatalogPath)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(BoundedDocumentError::UnsafeCatalogPath);
        }
        let file = self
            .root
            .open(relative)
            .map_err(|_| BoundedDocumentError::UnsafeCatalogPath)?;
        read_bounded_capability_file(file, maximum)
    }
}

/// Sequence wrapper that rejects an item beyond its compile-time bound while
/// deserializing.
pub struct BoundedVec<T, const MAXIMUM: usize>(Vec<T>);

impl<T, const MAXIMUM: usize> BoundedVec<T, MAXIMUM> {
    /// Returns the number of retained items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the bounded sequence is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the retained sequence.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Returns the retained values and consumes the wrapper.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MAXIMUM: usize> Default for BoundedVec<T, MAXIMUM> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<'de, T: Deserialize<'de>, const MAXIMUM: usize> Deserialize<'de> for BoundedVec<T, MAXIMUM> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(BoundedVecVisitor::<T, MAXIMUM>(PhantomData))
    }
}

struct BoundedVecVisitor<T, const MAXIMUM: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const MAXIMUM: usize> Visitor<'de>
    for BoundedVecVisitor<T, MAXIMUM>
{
    type Value = BoundedVec<T, MAXIMUM>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "an array with at most {MAXIMUM} items")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence.size_hint().is_some_and(|size| size > MAXIMUM) {
            return Err(serde::de::Error::custom("array exceeds its item bound"));
        }
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAXIMUM));
        while let Some(value) = sequence.next_element()? {
            if values.len() == MAXIMUM {
                return Err(serde::de::Error::custom("array exceeds its item bound"));
            }
            values.push(value);
        }
        Ok(BoundedVec(values))
    }
}

fn portable_json_source(value: &str) -> bool {
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

fn read_bounded_capability_file(
    file: cap_std::fs::File,
    maximum: usize,
) -> Result<Vec<u8>, BoundedDocumentError> {
    let metadata = file
        .metadata()
        .map_err(|_| BoundedDocumentError::UnsafeCatalogPath)?;
    if !metadata.is_file() {
        return Err(BoundedDocumentError::UnsafeCatalogPath);
    }
    if usize::try_from(metadata.len())
        .ok()
        .is_none_or(|length| length > maximum)
    {
        return Err(BoundedDocumentError::DocumentTooLarge { maximum });
    }
    let take_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(BoundedDocumentError::DocumentTooLarge { maximum })?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(maximum));
    file.take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedDocumentError::UnsafeCatalogPath)?;
    if bytes.len() > maximum {
        return Err(BoundedDocumentError::DocumentTooLarge { maximum });
    }
    Ok(bytes)
}
