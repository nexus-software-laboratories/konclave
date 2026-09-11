#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use KonclaveA2AContracts::wire::{Part, part};
use KonclaveA2AContracts::{
    A2A_ENCRYPTED_ARTIFACT_REFERENCE_PREFIX, InitialA2AArtifactReferenceDescriptor,
    parse_initial_encrypted_artifact_reference,
};
use KonclaveSecretStorage::{
    AUTHENTICATED_CIPHER_TAG_BYTES, AuthenticatedCipher, AuthenticatedCipherKey,
    AuthenticatedCiphertext, create_or_verify_owner_protected_file,
    ensure_owner_protected_directory, open_owner_protected_file,
};
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

/// Maximum ciphertext bytes retained for one encrypted artifact object.
pub const MAX_A2A_ARTIFACT_OBJECT_BYTES: usize =
    64 * 1_024 * 1_024 + AUTHENTICATED_CIPHER_TAG_BYTES;

/// Stable failures from encrypted artifact object storage and opening.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum A2AArtifactStorageError {
    /// A descriptor, reference, object identifier, or base URL is invalid.
    #[error("A2A artifact object configuration is invalid")]
    InvalidConfiguration,
    /// Ciphertext does not match its content-addressed identifier.
    #[error("A2A artifact object digest does not match")]
    DigestMismatch,
    /// Artifact object persistence is unavailable or unsafe.
    #[error("A2A artifact object storage is unavailable")]
    StorageUnavailable,
    /// No exact ciphertext object exists.
    #[error("A2A artifact object does not exist")]
    ObjectNotFound,
    /// Encryption, authentication, or secure randomness failed.
    #[error("A2A artifact object cryptography failed")]
    Cryptography,
}

/// SHA-256 content address of one ciphertext object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A2AArtifactObjectId([u8; 32]);

impl A2AArtifactObjectId {
    /// Computes one object identifier from exact ciphertext bytes.
    #[must_use]
    pub fn from_ciphertext(ciphertext: &[u8]) -> Self {
        Self(Sha256::digest(ciphertext).into())
    }

    /// Parses one canonical 64-character lowercase hexadecimal identifier.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for malformed input.
    pub fn parse(value: &str) -> Result<Self, A2AArtifactStorageError> {
        if value.len() != 64 {
            return Err(A2AArtifactStorageError::InvalidConfiguration);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }

    /// Returns raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        lowercase_hex(&self.0)
    }
}

/// Ciphertext persistence contract shared by self-hosted and managed adapters.
pub trait A2AArtifactObjectStore: Send + Sync {
    /// Stores exact ciphertext under its verified content address.
    ///
    /// Exact repeated content is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a digest, bound, conflict, or storage error.
    fn put(
        &self,
        object_id: A2AArtifactObjectId,
        ciphertext: &[u8],
    ) -> Result<(), A2AArtifactStorageError>;

    /// Reads one bounded ciphertext object and verifies its content address.
    ///
    /// # Errors
    ///
    /// Returns a digest, bound, not-found, unsafe-storage, or read error.
    fn get(
        &self,
        object_id: A2AArtifactObjectId,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, A2AArtifactStorageError>;
}

/// Owner-protected filesystem implementation for one self-hosted gateway.
pub struct FileA2AArtifactObjectStore {
    root: PathBuf,
}

impl FileA2AArtifactObjectStore {
    /// Opens or creates one owner-only object directory.
    ///
    /// # Errors
    ///
    /// Returns a storage error for links, unsafe permissions, foreign ownership, or
    /// an unavailable path.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, A2AArtifactStorageError> {
        let root = root.as_ref().to_path_buf();
        ensure_owner_protected_directory(&root)
            .map_err(|_| A2AArtifactStorageError::StorageUnavailable)?;
        Ok(Self { root })
    }

    fn path(&self, object_id: A2AArtifactObjectId) -> PathBuf {
        self.root.join(object_id.to_hex())
    }
}

impl A2AArtifactObjectStore for FileA2AArtifactObjectStore {
    fn put(
        &self,
        object_id: A2AArtifactObjectId,
        ciphertext: &[u8],
    ) -> Result<(), A2AArtifactStorageError> {
        validate_ciphertext(ciphertext)?;
        if A2AArtifactObjectId::from_ciphertext(ciphertext) != object_id {
            return Err(A2AArtifactStorageError::DigestMismatch);
        }
        create_or_verify_owner_protected_file(&self.path(object_id), ciphertext)
            .map_err(|_| A2AArtifactStorageError::StorageUnavailable)
    }

    fn get(
        &self,
        object_id: A2AArtifactObjectId,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, A2AArtifactStorageError> {
        if maximum_bytes < AUTHENTICATED_CIPHER_TAG_BYTES
            || maximum_bytes > MAX_A2A_ARTIFACT_OBJECT_BYTES
        {
            return Err(A2AArtifactStorageError::InvalidConfiguration);
        }
        let path = self.path(object_id);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(A2AArtifactStorageError::ObjectNotFound);
            }
            Err(_) => return Err(A2AArtifactStorageError::StorageUnavailable),
            Ok(_) => {}
        }
        let file = open_owner_protected_file(&path)
            .map_err(|_| A2AArtifactStorageError::StorageUnavailable)?;
        let bytes = read_bounded(file, maximum_bytes)?;
        validate_ciphertext(&bytes)?;
        if A2AArtifactObjectId::from_ciphertext(&bytes) != object_id {
            return Err(A2AArtifactStorageError::DigestMismatch);
        }
        Ok(bytes)
    }
}

/// Secret-bearing URL Part plus the stored ciphertext identifier.
pub struct StoredA2AArtifactReference {
    part: Part,
    object_id: A2AArtifactObjectId,
}

impl StoredA2AArtifactReference {
    /// Returns the validated URL Part.
    #[must_use]
    pub const fn part(&self) -> &Part {
        &self.part
    }

    /// Consumes the reference into its URL Part.
    #[must_use]
    pub fn into_part(mut self) -> Part {
        std::mem::take(&mut self.part)
    }

    /// Returns the ciphertext content address.
    #[must_use]
    pub const fn object_id(&self) -> A2AArtifactObjectId {
        self.object_id
    }
}

impl Drop for StoredA2AArtifactReference {
    fn drop(&mut self) {
        if let Some(part::Content::Url(url)) = &mut self.part.content {
            url.zeroize();
        }
    }
}

/// Encrypts, stores, and returns one content-addressed A2A URL Part.
///
/// # Errors
///
/// Returns descriptor, URL, bound, secure-randomness, encryption, digest, or storage
/// failures.
pub fn seal_and_store_artifact(
    store: &dyn A2AArtifactObjectStore,
    base_url: &str,
    descriptor: &InitialA2AArtifactReferenceDescriptor,
    plaintext: &[u8],
) -> Result<StoredA2AArtifactReference, A2AArtifactStorageError> {
    let expected_plaintext = usize::try_from(descriptor.plaintext_bytes())
        .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?;
    if plaintext.len() != expected_plaintext {
        return Err(A2AArtifactStorageError::InvalidConfiguration);
    }
    let key =
        AuthenticatedCipherKey::generate().map_err(|_| A2AArtifactStorageError::Cryptography)?;
    let cipher = AuthenticatedCipher::from_key(&key);
    let associated_data = descriptor
        .associated_data()
        .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?;
    let encrypted = cipher
        .seal(&associated_data, plaintext, expected_plaintext)
        .map_err(|_| A2AArtifactStorageError::Cryptography)?;
    let nonce = *encrypted.nonce();
    let ciphertext = encrypted.into_bytes();
    let object_id = A2AArtifactObjectId::from_ciphertext(&ciphertext);
    store.put(object_id, &ciphertext)?;
    let mut url = validate_base_url(base_url)?;
    url.path_segments_mut()
        .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?
        .pop_if_empty()
        .push("sha256")
        .push(&object_id.to_hex());
    let fragment = Zeroizing::new(format!(
        "{}.{}.{}.{}",
        A2A_ENCRYPTED_ARTIFACT_REFERENCE_PREFIX,
        URL_SAFE_NO_PAD.encode(key.as_bytes()),
        URL_SAFE_NO_PAD.encode(nonce),
        descriptor.plaintext_bytes(),
    ));
    url.set_fragment(Some(fragment.as_str()));
    parse_initial_encrypted_artifact_reference(url.as_str())
        .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?;
    Ok(StoredA2AArtifactReference {
        part: Part {
            content: Some(part::Content::Url(url.to_string())),
            metadata: None,
            filename: descriptor.filename().to_owned(),
            media_type: descriptor.media_type().to_owned(),
        },
        object_id,
    })
}

/// Explicitly loads and authenticates one locally available encrypted reference.
///
/// # Errors
///
/// Returns descriptor/reference mismatch, storage, digest, bound, or AES-GCM
/// authentication failure.
pub fn open_stored_artifact(
    store: &dyn A2AArtifactObjectStore,
    descriptor: &InitialA2AArtifactReferenceDescriptor,
    reference_url: &str,
) -> Result<Zeroizing<Vec<u8>>, A2AArtifactStorageError> {
    let reference = parse_initial_encrypted_artifact_reference(reference_url)
        .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?;
    if reference.plaintext_bytes() != descriptor.plaintext_bytes() {
        return Err(A2AArtifactStorageError::InvalidConfiguration);
    }
    let object_id = A2AArtifactObjectId::from_bytes(*reference.ciphertext_digest());
    let maximum = usize::try_from(reference.plaintext_bytes())
        .ok()
        .and_then(|size| size.checked_add(AUTHENTICATED_CIPHER_TAG_BYTES))
        .ok_or(A2AArtifactStorageError::InvalidConfiguration)?;
    let ciphertext = store.get(object_id, maximum)?;
    if A2AArtifactObjectId::from_ciphertext(&ciphertext) != object_id {
        return Err(A2AArtifactStorageError::DigestMismatch);
    }
    let cipher = AuthenticatedCipher::new(reference.key());
    let ciphertext = AuthenticatedCiphertext::from_parts(
        reference.nonce(),
        ciphertext,
        usize::try_from(reference.plaintext_bytes())
            .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?,
    )
    .map_err(|_| A2AArtifactStorageError::Cryptography)?;
    let plaintext = cipher
        .open(
            &descriptor
                .associated_data()
                .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?,
            &ciphertext,
            usize::try_from(reference.plaintext_bytes())
                .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?,
        )
        .map_err(|_| A2AArtifactStorageError::Cryptography)?;
    if plaintext.len()
        != usize::try_from(reference.plaintext_bytes())
            .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?
    {
        return Err(A2AArtifactStorageError::Cryptography);
    }
    Ok(plaintext)
}

impl A2AArtifactObjectId {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

fn validate_base_url(value: &str) -> Result<Url, A2AArtifactStorageError> {
    let url = Url::parse(value).map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err(A2AArtifactStorageError::InvalidConfiguration);
    }
    Ok(url)
}

fn validate_ciphertext(ciphertext: &[u8]) -> Result<(), A2AArtifactStorageError> {
    if ciphertext.len() < AUTHENTICATED_CIPHER_TAG_BYTES
        || ciphertext.len() > MAX_A2A_ARTIFACT_OBJECT_BYTES
    {
        Err(A2AArtifactStorageError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn read_bounded(mut file: File, maximum: usize) -> Result<Vec<u8>, A2AArtifactStorageError> {
    let capacity = maximum
        .checked_add(1)
        .ok_or(A2AArtifactStorageError::InvalidConfiguration)?;
    let file_length = usize::try_from(
        file.metadata()
            .map_err(|_| A2AArtifactStorageError::StorageUnavailable)?
            .len(),
    )
    .map_err(|_| A2AArtifactStorageError::InvalidConfiguration)?;
    if file_length > maximum {
        return Err(A2AArtifactStorageError::InvalidConfiguration);
    }
    let mut bytes = Vec::with_capacity(file_length);
    file.by_ref()
        .take(capacity as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| A2AArtifactStorageError::StorageUnavailable)?;
    if bytes.len() > maximum {
        return Err(A2AArtifactStorageError::InvalidConfiguration);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, A2AArtifactStorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(A2AArtifactStorageError::InvalidConfiguration),
    }
}

fn lowercase_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(64);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticObjectStore {
        bytes: Vec<u8>,
    }

    impl A2AArtifactObjectStore for StaticObjectStore {
        fn put(
            &self,
            _object_id: A2AArtifactObjectId,
            _ciphertext: &[u8],
        ) -> Result<(), A2AArtifactStorageError> {
            Err(A2AArtifactStorageError::StorageUnavailable)
        }

        fn get(
            &self,
            _object_id: A2AArtifactObjectId,
            _maximum_bytes: usize,
        ) -> Result<Vec<u8>, A2AArtifactStorageError> {
            Ok(self.bytes.clone())
        }
    }

    #[test]
    fn filesystem_store_seals_opens_and_reconciles_exact_objects() {
        let root = tempfile::tempdir().unwrap();
        let store = FileA2AArtifactObjectStore::open(root.path().join("objects")).unwrap();
        let descriptor = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-1",
            0,
            "application/octet-stream",
            "result.bin",
            6,
        )
        .unwrap();
        let reference =
            seal_and_store_artifact(&store, "https://objects.example.com/a2a", &descriptor, b"secret")
                .unwrap();
        let url = match reference.part().content.as_ref().unwrap() {
            part::Content::Url(url) => url,
            _ => panic!("stored artifact must be a URL Part"),
        };
        assert_eq!(
            open_stored_artifact(&store, &descriptor, url)
                .unwrap()
                .as_slice(),
            b"secret"
        );
        let ciphertext = store
            .get(
                reference.object_id(),
                AUTHENTICATED_CIPHER_TAG_BYTES + 6,
            )
            .unwrap();
        store.put(reference.object_id(), &ciphertext).unwrap();
    }

    #[test]
    fn descriptor_url_digest_and_context_mismatches_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let store = FileA2AArtifactObjectStore::open(root.path().join("objects")).unwrap();
        let descriptor = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-1",
            0,
            "application/octet-stream",
            "result.bin",
            6,
        )
        .unwrap();
        assert_eq!(
            seal_and_store_artifact(&store, "http://objects.example.com", &descriptor, b"secret")
                .err(),
            Some(A2AArtifactStorageError::InvalidConfiguration)
        );
        let reference =
            seal_and_store_artifact(&store, "https://objects.example.com", &descriptor, b"secret")
                .unwrap();
        let url = match reference.part().content.as_ref().unwrap() {
            part::Content::Url(url) => url,
            _ => panic!("stored artifact must be a URL Part"),
        };
        let wrong_descriptor = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-2",
            0,
            "application/octet-stream",
            "result.bin",
            6,
        )
        .unwrap();
        assert_eq!(
            open_stored_artifact(&store, &wrong_descriptor, url).err(),
            Some(A2AArtifactStorageError::Cryptography)
        );
        for wrong_descriptor in [
            InitialA2AArtifactReferenceDescriptor::new(
                "artifact-1",
                1,
                "application/octet-stream",
                "result.bin",
                6,
            )
            .unwrap(),
            InitialA2AArtifactReferenceDescriptor::new(
                "artifact-1",
                0,
                "application/pdf",
                "result.bin",
                6,
            )
            .unwrap(),
            InitialA2AArtifactReferenceDescriptor::new(
                "artifact-1",
                0,
                "application/octet-stream",
                "other.bin",
                6,
            )
            .unwrap(),
        ] {
            assert_eq!(
                open_stored_artifact(&store, &wrong_descriptor, url).err(),
                Some(A2AArtifactStorageError::Cryptography)
            );
        }
        let wrong_length = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-1",
            0,
            "application/octet-stream",
            "result.bin",
            5,
        )
        .unwrap();
        assert_eq!(
            open_stored_artifact(&store, &wrong_length, url).err(),
            Some(A2AArtifactStorageError::InvalidConfiguration)
        );
        let mut tampered = store
            .get(
                reference.object_id(),
                AUTHENTICATED_CIPHER_TAG_BYTES + 6,
            )
            .unwrap();
        tampered[0] ^= 1;
        assert_eq!(
            open_stored_artifact(
                &StaticObjectStore { bytes: tampered },
                &descriptor,
                url,
            )
            .err(),
            Some(A2AArtifactStorageError::DigestMismatch)
        );
        assert_eq!(
            store
                .put(
                    A2AArtifactObjectId::parse(&"00".repeat(32)).unwrap(),
                    b"0123456789abcdef",
                )
                .err(),
            Some(A2AArtifactStorageError::DigestMismatch)
        );
    }

    #[test]
    fn repeated_plaintext_uses_fresh_content_addresses() {
        let root = tempfile::tempdir().unwrap();
        let store = FileA2AArtifactObjectStore::open(root.path().join("objects")).unwrap();
        let descriptor = InitialA2AArtifactReferenceDescriptor::new(
            "artifact-1",
            0,
            "application/octet-stream",
            "result.bin",
            6,
        )
        .unwrap();
        let first =
            seal_and_store_artifact(&store, "https://objects.example.com", &descriptor, b"secret")
                .unwrap();
        let second =
            seal_and_store_artifact(&store, "https://objects.example.com", &descriptor, b"secret")
                .unwrap();
        assert_ne!(first.object_id(), second.object_id());
        assert_ne!(
            first.part().content.as_ref(),
            second.part().content.as_ref()
        );
    }

    #[test]
    fn oversized_files_are_rejected_before_reading() {
        let file = tempfile::tempfile().unwrap();
        file.set_len((MAX_A2A_ARTIFACT_OBJECT_BYTES + 1) as u64)
            .unwrap();
        assert_eq!(
            read_bounded(file, MAX_A2A_ARTIFACT_OBJECT_BYTES).err(),
            Some(A2AArtifactStorageError::InvalidConfiguration)
        );
    }

}
