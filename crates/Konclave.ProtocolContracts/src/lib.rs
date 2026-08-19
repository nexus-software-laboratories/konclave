#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
pub mod v1;

pub use error::KonclaveProtocolError;

/// Generated Protocol Buffers DTOs.
///
/// These types represent untrusted wire data. Convert them through the functions in
/// [`v1`] before authorization, persistence, or side effects. Some DTOs carry
/// plaintext or bearer capabilities and must remain transient even when generator
/// traits permit copying them.
pub mod wire {
    /// Protocol v1 generated DTOs.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/konclave.protocol.v1.rs"));
    }
}
