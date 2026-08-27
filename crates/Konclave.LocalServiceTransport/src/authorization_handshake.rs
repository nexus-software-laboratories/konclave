use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveDomainCore::Ed25519PublicKey;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    AuthorizationBinding, AuthorizationHandshakeMessage, AuthorizationTranscript, ClientInstanceId,
    HarnessKind, IssuerKeyId, IssuerKeyVersion, LocalServiceChallenge, LocalServiceTransportError,
    MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES, SESSION_GRANT_PROTOCOL_VERSION,
    SessionAuthorizationRegistry, SessionGrant,
};

/// Longest an unauthenticated peer may hold one authorization handshake.
pub const AUTHORIZATION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static AUTHORIZATION_CHALLENGES: AtomicU64 = AtomicU64::new(0);

/// Client request for an account-issuer connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerHandshakeRequest {
    /// Installed issuer identifier.
    pub issuer_key_id: IssuerKeyId,
    /// Installed issuer key version.
    pub issuer_key_version: IssuerKeyVersion,
    /// Fresh connection instance.
    pub client_instance: ClientInstanceId,
    /// Integration using this issuer.
    pub harness: HarnessKind,
}

/// Client request for one exact-profile grant connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionHandshakeRequest {
    /// Complete service-issued grant claims.
    pub grant: SessionGrant,
    /// Fresh connection instance.
    pub client_instance: ClientInstanceId,
}

/// Established protocol-v2 channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedAuthorizationChannel {
    binding: AuthorizationBinding,
}

impl AuthenticatedAuthorizationChannel {
    /// Returns the immutable issuer or session binding.
    #[must_use]
    pub const fn binding(&self) -> &AuthorizationBinding {
        &self.binding
    }
}

/// Completes an issuer client handshake.
///
/// # Errors
///
/// Returns a bounded protocol, key, service-proof, or timeout failure.
pub async fn complete_issuer_client_handshake<S>(
    stream: &mut S,
    request: &IssuerHandshakeRequest,
    issuer_identity: &LocalServiceIdentity,
    expected_service_key: Ed25519PublicKey,
) -> Result<AuthenticatedAuthorizationChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let binding = AuthorizationBinding::Issuer {
        issuer_key_id: request.issuer_key_id,
        issuer_key_version: request.issuer_key_version,
        issuer_public_key: issuer_identity.public_key(),
        client_instance: request.client_instance,
        harness: request.harness,
    };
    complete_client(stream, binding, issuer_identity, expected_service_key).await
}

/// Completes a session-grant client handshake.
///
/// # Errors
///
/// Returns a bounded protocol, grant, key, service-proof, or timeout failure.
pub async fn complete_session_client_handshake<S>(
    stream: &mut S,
    request: &SessionHandshakeRequest,
    session_identity: &LocalServiceIdentity,
    expected_service_key: Ed25519PublicKey,
) -> Result<AuthenticatedAuthorizationChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if request.grant.session_public_key() != session_identity.public_key() {
        return Err(LocalServiceTransportError::UnauthenticClient);
    }
    let binding = AuthorizationBinding::Session {
        grant: request.grant.clone(),
        client_instance: request.client_instance,
    };
    complete_client(stream, binding, session_identity, expected_service_key).await
}

async fn complete_client<S>(
    stream: &mut S,
    binding: AuthorizationBinding,
    client_identity: &LocalServiceIdentity,
    expected_service_key: Ed25519PublicKey,
) -> Result<AuthenticatedAuthorizationChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(AUTHORIZATION_HANDSHAKE_TIMEOUT, async {
        let client_challenge = LocalServiceChallenge::from_bytes(next_challenge()?);
        let hello = match &binding {
            AuthorizationBinding::Issuer {
                issuer_key_id,
                issuer_key_version,
                issuer_public_key,
                client_instance,
                harness,
            } => AuthorizationHandshakeMessage::IssuerHello {
                version: SESSION_GRANT_PROTOCOL_VERSION,
                issuer_key_id: *issuer_key_id,
                issuer_key_version: *issuer_key_version,
                issuer_public_key: *issuer_public_key,
                client_instance: *client_instance,
                harness: *harness,
                challenge: client_challenge,
            },
            AuthorizationBinding::Session {
                grant,
                client_instance,
            } => AuthorizationHandshakeMessage::SessionHello {
                version: SESSION_GRANT_PROTOCOL_VERSION,
                grant: grant.clone(),
                client_instance: *client_instance,
                challenge: client_challenge,
            },
        };
        write_message(stream, &hello).await?;
        let AuthorizationHandshakeMessage::ServiceChallenge {
            service_public_key,
            challenge: service_challenge,
        } = read_service_message(stream).await?
        else {
            return Err(LocalServiceTransportError::UnexpectedMessage);
        };
        if service_public_key != expected_service_key {
            return Err(LocalServiceTransportError::ServiceKeyMismatch);
        }
        let transcript = AuthorizationTranscript::new(
            binding,
            client_challenge,
            service_challenge,
            service_public_key,
        );
        write_message(
            stream,
            &AuthorizationHandshakeMessage::ClientAuth {
                signature: transcript.sign_as_client(client_identity)?,
            },
        )
        .await?;
        match read_service_message(stream).await? {
            AuthorizationHandshakeMessage::ServiceAccept { signature } => {
                transcript.verify_service_signature(&signature)?;
            }
            AuthorizationHandshakeMessage::ServiceReject { signature } => {
                transcript.verify_service_signature(&signature)?;
                return Err(LocalServiceTransportError::UnauthenticClient);
            }
            _ => return Err(LocalServiceTransportError::UnexpectedMessage),
        }
        Ok(AuthenticatedAuthorizationChannel {
            binding: transcript.into_binding(),
        })
    })
    .await
    .map_err(|_| LocalServiceTransportError::HandshakeTimeout)?
}

/// Completes the service side for either authorization role.
///
/// The peer first proves possession of the public key it presented. Registry and
/// grant details are checked only afterward and collapse to one external
/// unauthentic-client failure, preventing registration and grant enumeration.
///
/// # Errors
///
/// Returns a bounded uniform authentication, protocol, or timeout failure.
pub async fn complete_authorization_service_handshake<S>(
    stream: &mut S,
    registry: &dyn SessionAuthorizationRegistry,
    service_identity: &LocalServiceIdentity,
    now_unix_milliseconds: u64,
) -> Result<AuthenticatedAuthorizationChannel, LocalServiceTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(AUTHORIZATION_HANDSHAKE_TIMEOUT, async {
        let hello = read_message(stream).await?;
        let (binding, client_challenge, presented_key) = match hello {
            AuthorizationHandshakeMessage::IssuerHello {
                version: _,
                issuer_key_id,
                issuer_key_version,
                issuer_public_key,
                client_instance,
                harness,
                challenge,
            } => (
                AuthorizationBinding::Issuer {
                    issuer_key_id,
                    issuer_key_version,
                    issuer_public_key,
                    client_instance,
                    harness,
                },
                challenge,
                issuer_public_key,
            ),
            AuthorizationHandshakeMessage::SessionHello {
                version: _,
                grant,
                client_instance,
                challenge,
            } => {
                let key = grant.session_public_key();
                (
                    AuthorizationBinding::Session {
                        grant,
                        client_instance,
                    },
                    challenge,
                    key,
                )
            }
            _ => return Err(LocalServiceTransportError::UnexpectedMessage),
        };
        let service_challenge = LocalServiceChallenge::from_bytes(next_challenge()?);
        write_message(
            stream,
            &AuthorizationHandshakeMessage::ServiceChallenge {
                service_public_key: service_identity.public_key(),
                challenge: service_challenge,
            },
        )
        .await?;
        let transcript = AuthorizationTranscript::new(
            binding.clone(),
            client_challenge,
            service_challenge,
            service_identity.public_key(),
        );
        let AuthorizationHandshakeMessage::ClientAuth { signature } = read_message(stream).await?
        else {
            return Err(LocalServiceTransportError::UnexpectedMessage);
        };
        transcript.verify_client_signature(presented_key, &signature)?;
        let authorized = match &binding {
            AuthorizationBinding::Issuer {
                issuer_key_id,
                issuer_key_version,
                issuer_public_key,
                harness,
                ..
            } => registry
                .active_issuer(*issuer_key_id, *issuer_key_version)
                .is_some_and(|registration| {
                    registration.public_key() == *issuer_public_key
                        && (registration.harness() == *harness
                            || registration.harness() == HarnessKind::Generic)
                }),
            AuthorizationBinding::Session { grant, .. } => registry
                .active_grant(grant.grant_id(), now_unix_milliseconds)
                .is_some_and(|active| active == grant.clone()),
        };
        if !authorized {
            write_message(
                stream,
                &AuthorizationHandshakeMessage::ServiceReject {
                    signature: transcript.sign_as_service(service_identity)?,
                },
            )
            .await?;
            return Err(LocalServiceTransportError::UnauthenticClient);
        }
        write_message(
            stream,
            &AuthorizationHandshakeMessage::ServiceAccept {
                signature: transcript.sign_as_service(service_identity)?,
            },
        )
        .await?;
        Ok(AuthenticatedAuthorizationChannel {
            binding: transcript.into_binding(),
        })
    })
    .await
    .map_err(|_| LocalServiceTransportError::HandshakeTimeout)?
}

async fn read_service_message<S>(
    stream: &mut S,
) -> Result<AuthorizationHandshakeMessage, LocalServiceTransportError>
where
    S: AsyncRead + Unpin,
{
    match read_message(stream).await {
        Err(LocalServiceTransportError::ChannelClosed) => {
            Err(LocalServiceTransportError::ServiceUpgradeRequired)
        }
        result => result,
    }
}

async fn read_message<S>(
    stream: &mut S,
) -> Result<AuthorizationHandshakeMessage, LocalServiceTransportError>
where
    S: AsyncRead + Unpin,
{
    let payload =
        KonclaveLocalFraming::read_frame(stream, MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES).await?;
    AuthorizationHandshakeMessage::decode(&payload)
}

async fn write_message<S>(
    stream: &mut S,
    message: &AuthorizationHandshakeMessage,
) -> Result<(), LocalServiceTransportError>
where
    S: AsyncWrite + Unpin,
{
    KonclaveLocalFraming::write_frame(
        stream,
        &message.encode(),
        MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES,
    )
    .await
    .map_err(LocalServiceTransportError::from)
}

fn next_challenge() -> Result<[u8; 32], LocalServiceTransportError> {
    let issued = AUTHORIZATION_CHALLENGES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| LocalServiceTransportError::ChallengeExhausted)?
        .checked_add(1)
        .ok_or(LocalServiceTransportError::ChallengeExhausted)?;
    let mut challenge = [0_u8; 32];
    KonclaveCryptographicCore::fill_random(&mut challenge)
        .map_err(|_| LocalServiceTransportError::ChallengeExhausted)?;
    challenge[24..].copy_from_slice(&issued.to_be_bytes());
    Ok(challenge)
}
