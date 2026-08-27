#![deny(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case)]

//! Safe Windows account and named-pipe security boundaries.
//!
//! Konclave's local transports need the same platform guarantees: an explicit DACL
//! that grants access only to the account hosting the service, a verified account on
//! each connected peer, and rejection of a lower-integrity process. This crate keeps
//! the required Win32 calls and their unsafe invariants behind one small safe API so
//! transport crates do not duplicate or expose raw handles, SIDs, or descriptors.

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    WindowsAccountVerifier, WindowsSecurityError, create_or_verify_owner_restricted_file,
    create_owner_restricted_named_pipe, ensure_owner_restricted_directory,
    open_owner_restricted_file,
};
