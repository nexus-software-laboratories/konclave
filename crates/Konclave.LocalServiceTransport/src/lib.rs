#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Harness-neutral authenticated transport for Konclave's shared local service.
//!
//! One per-user service hosts every logical agent profile, and every harness session
//! attaches to it through a thin client. This crate owns that client boundary: the
//! owner-restricted local endpoint, the replay-resistant signature handshake that
//! binds one connection to exactly one authorized profile, and the bounded generic
//! request/response frames that follow.
//!
//! Nothing here knows about Copilot, MCP, prompts, models, slash commands, or any
//! harness user interface. A harness adapter maps its native surface onto these
//! frames, so a new harness needs no transport change.
//!
//! # Boundaries
//!
//! - Signing and verification run through the project's vetted cryptographic
//!   provider. No primitive is implemented here.
//! - Framing is the shared bounded length-prefixed primitive, which carries no
//!   protocol vocabulary of its own.
//! - Adapter registration, rotation, and revocation are installation-owned and reach
//!   the handshake through an injected authorization registry.
//! - The transport carries opaque operation payloads. It never interprets them, and
//!   it opens no TCP listener of any kind.
//!
//! # Attaching a client
//!
//! A client presents its registered key, instance, harness, and requested profile,
//! pins the service verification key it expects, and signs one canonical transcript.
//! The service resolves the registration, verifies that signature, authorizes the
//! harness and profile, and returns its own acceptance signature over a separate
//! domain. The resulting binding is immutable for the life of the connection.

mod authorization_binding;
mod authorization_handshake;
mod authorization_message;
mod authorization_transcript;
mod binding;
mod endpoint;
mod error;
mod grant;
mod handshake;
mod hex;
mod identifiers;
mod installation;
mod message;
mod registry;
mod rpc;
mod transcript;

pub use authorization_binding::AuthorizationBinding;
pub use authorization_handshake::{
    AUTHORIZATION_HANDSHAKE_TIMEOUT, AuthenticatedAuthorizationChannel, IssuerHandshakeRequest,
    SessionHandshakeRequest, complete_authorization_service_handshake,
    complete_issuer_client_handshake, complete_session_client_handshake,
};
pub use authorization_message::{
    AuthorizationHandshakeMessage, MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES,
};
pub use authorization_transcript::AuthorizationTranscript;
pub use binding::LocalServiceBinding;
pub use endpoint::{
    LocalServiceClientStream, LocalServiceEndpoint, LocalServiceListener, LocalServiceServerStream,
    MAX_ENDPOINT_LENGTH, connect_local_service,
};
pub use error::LocalServiceTransportError;
pub use grant::{
    AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicy,
    AuthorizationPolicyVersion, InMemorySessionAuthorizationRegistry, MAX_GRANTS_PER_ISSUER,
    MAX_GRANTS_PER_PROFILE, MAX_POLICY_CLAUSES, MAX_SESSION_GRANTS, SESSION_GRANT_ID_LENGTH,
    SESSION_GRANT_PROTOCOL_VERSION, SessionAuthorizationRegistry, SessionCapabilities,
    SessionGrant, SessionGrantCapacity, SessionGrantClaims, SessionGrantId,
};
pub use handshake::{
    AdapterAuthorizationRegistry, AdapterRegistration, AuthenticatedLocalChannel,
    AuthorizationRegistration, ClientHandshakeRequest, HANDSHAKE_TIMEOUT, IssuerRegistration,
    complete_client_handshake, complete_service_handshake,
};
pub use hex::{decode_lowercase_hex, encode_lowercase_hex};
pub use identifiers::{
    AdapterKeyId, AdapterKeyVersion, CHALLENGE_LENGTH, ClientInstanceId, HarnessKind, IssuerKeyId,
    IssuerKeyVersion, LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceChallenge, MAX_PROFILE_ID_LENGTH,
    ProfileAuthorization, ServiceProfileId,
};
pub use installation::{
    COPILOT_SERVICE_CONFIG_FILE, CopilotServiceConfig, InstalledIssuerRegistration,
    LOCAL_SERVICE_INSTALLATION_FILE, LocalServiceIdentitySource, LocalServiceInstallation,
    LocalServiceInstallationError, LocalServiceProfileCustody,
};
pub use message::{HandshakeMessage, MAX_HANDSHAKE_FRAME_BYTES};
pub use registry::{InMemoryAdapterRegistry, MAX_ADAPTER_REGISTRATIONS};
pub use rpc::{
    LocalServiceErrorCode, LocalServiceRequest, LocalServiceResponse, MAX_OPERATION_LENGTH,
    MAX_RPC_FRAME_BYTES, MAX_RPC_PAYLOAD_BYTES, OperationName, REQUEST_ID_LENGTH, RequestId,
    read_request, read_response, write_request, write_response,
};
pub use transcript::LocalServiceTranscript;

const _: () = assert!(
    MAX_HANDSHAKE_FRAME_BYTES < MAX_RPC_FRAME_BYTES,
    "an unauthenticated peer must never reserve a request-sized buffer"
);
const _: () = assert!(
    MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES < MAX_RPC_FRAME_BYTES,
    "a v2 unauthenticated peer must never reserve a request-sized buffer"
);
