#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod key;
#[cfg(feature = "native-keyring")]
mod native;
mod sealed_blob;

pub use error::SecretStorageError;
pub use key::{ExternalWrappingKeyProvider, WrappingKeyProvider};
#[cfg(feature = "native-keyring")]
pub use native::NativeWrappingKeyProvider;
pub use sealed_blob::{
    MAX_SECRET_PLAINTEXT_BYTES, SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer,
};
