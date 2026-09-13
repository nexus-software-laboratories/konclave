#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Owner-protected durable authorization state for Konclave's shared local service.
//!
//! The store is deliberately separate from profile databases and from the immutable
//! installation record. It persists only bounded authority metadata: policy, issuer
//! registrations, suspensions, grants, generation, and non-sensitive audit outcomes.
//! Callers perform these synchronous operations on a blocking boundary, then publish
//! [`AuthorizationSnapshot`] values to async request paths.

mod error;
mod model;
mod store;

pub use error::LocalAuthorizationStoreError;
pub use model::{
    AUTHORIZATION_STORE_BUSY_TIMEOUT_MILLISECONDS, AuthorizationAuditEvent, AuthorizationAuditKind,
    AuthorizationCapacity, AuthorizationGeneration, AuthorizationIssuerRecord,
    AuthorizationMutation, AuthorizationSnapshot, AuthorizationStoreStatus,
    ExistingGrantDisposition, GrantIssuanceKey, GrantIssuanceResult,
    INSTALLATION_FINGERPRINT_LENGTH, InstallationFingerprint, IssuerAvailability,
    LOCAL_AUTHORIZATION_STORE_FILE, MAX_AUTHORIZATION_AUDIT_RECORDS, MAX_GRANT_IDENTIFIERS,
    MAX_SUSPENDED_PROFILES, MAX_TERMINAL_GRANT_RECORDS, MutationEffect,
};
pub use store::{LocalAuthorizationStore, authorization_store_path, installation_fingerprint};
