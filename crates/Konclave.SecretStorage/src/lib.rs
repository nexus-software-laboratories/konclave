#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod authenticated_cipher;
mod error;
mod key;
mod mls_storage;
#[cfg(feature = "native-keyring")]
mod native;
mod sealed_blob;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use authenticated_cipher::{
    AUTHENTICATED_CIPHER_KEY_BYTES, AUTHENTICATED_CIPHER_NONCE_BYTES,
    AUTHENTICATED_CIPHER_TAG_BYTES, AuthenticatedCipher, AuthenticatedCiphertext,
};
pub use error::SecretStorageError;
pub use key::{ExternalWrappingKeyProvider, WrappingKeyProvider};
pub use mls_storage::SealedMlsStorage;
#[cfg(feature = "native-keyring")]
pub use native::NativeWrappingKeyProvider;
pub use sealed_blob::{
    MAX_SECRET_PLAINTEXT_BYTES, SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer,
};
#[cfg(feature = "sqlite")]
pub use sqlite::SealedSqliteMlsStorage;
