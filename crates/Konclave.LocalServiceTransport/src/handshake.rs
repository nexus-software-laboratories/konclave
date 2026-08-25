use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveDomainCore::Ed25519PublicKey;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::binding::LocalServiceBinding;
use crate::error::LocalServiceTransportError;
use crate::identifiers::{
    AdapterKeyId, AdapterKeyVersion, CHALLENGE_LENGTH, ClientInstanceId, HarnessKind,
    LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceChallenge, ProfileAuthorization, ServiceProfileId,
};
use crate::message::{HandshakeMessage, MAX_HANDSHAKE_FRAME_BYTES};
use crate::transcript::LocalServiceTranscript;

/// Longest a peer may take to complete the handshake.
///
/// An unauthenticated peer that opens a connection and stalls would otherwise hold a
/// task and a buffer indefinitely, so the whole exchange is bounded rather than each
/// individual read.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static ISSUED_CHALLENGES: AtomicU64 = AtomicU64::new(0);

/// The public authorization record the service holds for one registered adapter key.
///
/// The record is installation-owned. Nothing a client sends can create or broaden it,
/// so a client that presents an unregistered key, a retired version, another harness,
/// or a profile outside its namespace has no path to a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRegistration {
    public_key: Ed25519PublicKey,
    harness: HarnessKind,
    profiles: ProfileAuthorization,
}

impl AdapterRegistration {
    /// Creates an authorization record.
    #[must_use]
    pub const fn new(
        public_key: Ed25519PublicKey,
        harness: HarnessKind,
        profiles: ProfileAuthorization,
    ) -> Self {
        Self {
            public_key,
            harness,
            profiles,
        }
    }

    /// Returns the registered verification key.
    #[must_use]
    pub const fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    /// Returns the one harness this registration may claim.
    #[must_use]
    pub const fn harness(&self) -> HarnessKind {
        self.harness
    }

    /// Returns the profiles this registration may attach to.
    #[must_use]
    pub const fn profiles(&self) -> &ProfileAuthorization {
        &self.profiles
    }
}

/// Resolves an adapter key and version to its active authorization record.
///
/// The service never stores adapter registrations in this crate. Injecting the lookup
/// keeps installation-owned registration, rotation, and revocation policy outside the
/// transport: a revoked or rotated key simply stops resolving, and the handshake fails
/// closed without any protocol change.
pub trait AdapterAuthorizationRegistry: Send + Sync {
    /// Returns the active record for this exact key and version, if one exists.
    ///
    /// An implementation returns `None` for an unknown key, a retired version, or a
    /// revoked registration. It must not fall back to another version.
    fn active_registration(
        &self,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
    ) -> Option<AdapterRegistration>;
}

/// The values a client presents when it attaches to the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshakeRequest {
    /// The registered adapter key this client signs with.
    pub adapter_key_id: AdapterKeyId,
    /// The version of that registered key.
    pub adapter_key_version: AdapterKeyVersion,
    /// A fresh identifier for this connection attempt.
    pub client_instance: ClientInstanceId,
    /// The harness this client serves.
    pub harness: HarnessKind,
    /// The profile this connection asks to be bound to.
    pub profile: ServiceProfileId,
}

/// An established local service channel and the binding it is fixed to.
///
/// The binding cannot change for the life of the channel. A caller that needs another
/// profile opens another connection and performs another handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedLocalChannel {
    binding: LocalServiceBinding,
}

impl AuthenticatedLocalChannel {
    /// Returns the immutable authorization this channel is bound to.
    #[must_use]
    pub const fn binding(&self) -> &LocalServiceBinding {
        &self.binding
    }
}

/// Runs the client side of the handshake over an already connected stream.
///
/// The client pins the exact service verification key it expects, so a squatting
/// endpoint that answers with any other identity fails before the client signs
/// anything.
///
/// # Errors
///
/// Returns [`LocalServiceTransportError::HandshakeTimeout`] when the exchange exceeds
/// [`HANDSHAKE_TIMEOUT`], [`LocalServiceTransportError::ServiceKeyMismatch`] when the
/// peer presents another identity, [`LocalServiceTransportError::UnauthenticService`]
/// when the acceptance signature does not verify, or a frame, identifier, or version
/// failure.
pub async fn complete_client_handshake<S>(
    stream: &mut S,
    request: &ClientHandshakeRequest,
    identity: &LocalServiceIdentity,
    expected_service_key: Ed25519PublicKey,
) -> Result<AuthenticatedLocalChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake(stream, request, identity, expected_service_key),
    )
    .await
    .map_err(|_| LocalServiceTransportError::HandshakeTimeout)?
}

async fn client_handshake<S>(
    stream: &mut S,
    request: &ClientHandshakeRequest,
    identity: &LocalServiceIdentity,
    expected_service_key: Ed25519PublicKey,
) -> Result<AuthenticatedLocalChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_challenge = LocalServiceChallenge::from_bytes(next_challenge()?);
    write_message(
        stream,
        &HandshakeMessage::ClientHello {
            version: LOCAL_SERVICE_PROTOCOL_VERSION,
            adapter_key_id: request.adapter_key_id,
            adapter_key_version: request.adapter_key_version,
            client_instance: request.client_instance,
            harness: request.harness,
            profile: request.profile.clone(),
            challenge: client_challenge,
        },
    )
    .await?;

    let HandshakeMessage::ServiceChallenge {
        service_public_key,
        challenge: service_challenge,
    } = read_message(stream).await?
    else {
        return Err(LocalServiceTransportError::UnexpectedMessage);
    };
    if service_public_key != expected_service_key {
        return Err(LocalServiceTransportError::ServiceKeyMismatch);
    }

    let transcript = LocalServiceTranscript::new(
        LocalServiceBinding::new(
            LOCAL_SERVICE_PROTOCOL_VERSION,
            request.adapter_key_id,
            request.adapter_key_version,
            request.client_instance,
            request.harness,
            request.profile.clone(),
        )?,
        client_challenge,
        service_challenge,
        service_public_key,
    );

    write_message(
        stream,
        &HandshakeMessage::ClientAuth {
            signature: transcript.sign_as_client(identity)?,
        },
    )
    .await?;

    let HandshakeMessage::ServiceAccept { signature } = read_message(stream).await? else {
        return Err(LocalServiceTransportError::UnexpectedMessage);
    };
    transcript.verify_service_signature(&signature)?;

    Ok(AuthenticatedLocalChannel {
        binding: transcript.into_binding(),
    })
}

/// Runs the service side of the handshake over an already accepted connection.
///
/// The service authenticates the client before it authorizes it: the registration is
/// resolved only to obtain the verification key, the signature is checked over the
/// full transcript, and only then are the claimed harness and requested profile
/// checked against the record. An unauthentic peer therefore never learns which
/// harness or profile a registration would have permitted.
///
/// # Errors
///
/// Returns [`LocalServiceTransportError::UnknownAdapterRegistration`],
/// [`LocalServiceTransportError::UnauthenticClient`],
/// [`LocalServiceTransportError::HarnessNotAuthorized`],
/// [`LocalServiceTransportError::ProfileNotAuthorized`],
/// [`LocalServiceTransportError::HandshakeTimeout`], or a frame, identifier, or
/// version failure.
pub async fn complete_service_handshake<S>(
    stream: &mut S,
    registry: &dyn AdapterAuthorizationRegistry,
    identity: &LocalServiceIdentity,
) -> Result<AuthenticatedLocalChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        service_handshake(stream, registry, identity),
    )
    .await
    .map_err(|_| LocalServiceTransportError::HandshakeTimeout)?
}

async fn service_handshake<S>(
    stream: &mut S,
    registry: &dyn AdapterAuthorizationRegistry,
    identity: &LocalServiceIdentity,
) -> Result<AuthenticatedLocalChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let HandshakeMessage::ClientHello {
        version,
        adapter_key_id,
        adapter_key_version,
        client_instance,
        harness,
        profile,
        challenge: client_challenge,
    } = read_message(stream).await?
    else {
        return Err(LocalServiceTransportError::UnexpectedMessage);
    };

    let registration = registry
        .active_registration(adapter_key_id, adapter_key_version)
        .ok_or(LocalServiceTransportError::UnknownAdapterRegistration)?;

    let service_challenge = LocalServiceChallenge::from_bytes(next_challenge()?);
    write_message(
        stream,
        &HandshakeMessage::ServiceChallenge {
            service_public_key: identity.public_key(),
            challenge: service_challenge,
        },
    )
    .await?;

    let transcript = LocalServiceTranscript::new(
        LocalServiceBinding::new(
            version,
            adapter_key_id,
            adapter_key_version,
            client_instance,
            harness,
            profile.clone(),
        )?,
        client_challenge,
        service_challenge,
        identity.public_key(),
    );

    let HandshakeMessage::ClientAuth { signature } = read_message(stream).await? else {
        return Err(LocalServiceTransportError::UnexpectedMessage);
    };
    transcript.verify_client_signature(registration.public_key(), &signature)?;

    if registration.harness() != harness {
        return Err(LocalServiceTransportError::HarnessNotAuthorized);
    }
    if !registration.profiles().permits(&profile) {
        return Err(LocalServiceTransportError::ProfileNotAuthorized);
    }

    write_message(
        stream,
        &HandshakeMessage::ServiceAccept {
            signature: transcript.sign_as_service(identity)?,
        },
    )
    .await?;

    Ok(AuthenticatedLocalChannel {
        binding: transcript.into_binding(),
    })
}

async fn read_message<S>(stream: &mut S) -> Result<HandshakeMessage, LocalServiceTransportError>
where
    S: AsyncRead + Unpin,
{
    let payload = KonclaveLocalFraming::read_frame(stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
    HandshakeMessage::decode(&payload)
}

async fn write_message<S>(
    stream: &mut S,
    message: &HandshakeMessage,
) -> Result<(), LocalServiceTransportError>
where
    S: AsyncWrite + Unpin,
{
    KonclaveLocalFraming::write_frame(stream, &message.encode(), MAX_HANDSHAKE_FRAME_BYTES)
        .await
        .map_err(LocalServiceTransportError::from)
}

/// Returns fresh process-global challenge material.
///
/// Operating-system randomness makes the next value unpredictable. The monotonic
/// suffix makes repetition within one process impossible even if the provider were
/// to return the same random bytes twice. This source is not injectable: production
/// callers cannot accidentally replace it with deterministic test data.
fn next_challenge() -> Result<[u8; CHALLENGE_LENGTH], LocalServiceTransportError> {
    let previous = ISSUED_CHALLENGES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| LocalServiceTransportError::ChallengeExhausted)?;
    let issued = previous
        .checked_add(1)
        .ok_or(LocalServiceTransportError::ChallengeExhausted)?;
    let mut challenge = [0_u8; CHALLENGE_LENGTH];
    KonclaveCryptographicCore::fill_random(&mut challenge)
        .map_err(|_| LocalServiceTransportError::ChallengeExhausted)?;
    let counter = issued.to_be_bytes();
    challenge[CHALLENGE_LENGTH - counter.len()..].copy_from_slice(&counter);
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::next_challenge;

    #[test]
    fn operating_system_challenges_never_repeat_and_are_not_sequential() {
        let mut seen = HashSet::new();
        let mut previous = None;
        for _ in 0..256 {
            let challenge = next_challenge().unwrap();
            assert!(
                seen.insert(challenge),
                "challenge repeated within one process"
            );
            if let Some(previous) = previous {
                assert_ne!(
                    challenge, previous,
                    "consecutive challenges must not be identical"
                );
            }
            // The leading bytes carry randomness rather than the counter, so an
            // observer cannot predict the next challenge from the previous one.
            assert_ne!(challenge[..8], [0_u8; 8]);
            previous = Some(challenge);
        }
    }
}
