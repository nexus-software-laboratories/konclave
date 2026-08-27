use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};

use crate::{
    AuthorizationEvidenceSet, AuthorizationPolicyVersion, CHALLENGE_LENGTH, ClientInstanceId,
    HarnessKind, IssuerKeyId, IssuerKeyVersion, LocalServiceChallenge, LocalServiceTransportError,
    MAX_PROFILE_ID_LENGTH, SESSION_GRANT_ID_LENGTH, SESSION_GRANT_PROTOCOL_VERSION,
    ServiceProfileId, SessionCapabilities, SessionGrant, SessionGrantClaims, SessionGrantId,
};

/// Hard bound for every protocol-v2 pre-authentication frame.
pub const MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES: usize = 256;

const KIND_ISSUER_HELLO: u8 = 5;
const KIND_SESSION_HELLO: u8 = 6;
const KIND_SERVICE_CHALLENGE: u8 = 2;
const KIND_CLIENT_AUTH: u8 = 3;
const KIND_SERVICE_ACCEPT: u8 = 4;
const KIND_SERVICE_REJECT: u8 = 7;

/// Protocol-v2 messages exchanged before an issuer or session may send requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationHandshakeMessage {
    /// Opens an AccountTrusted issuer connection.
    IssuerHello {
        version: u16,
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        issuer_public_key: Ed25519PublicKey,
        client_instance: ClientInstanceId,
        harness: HarnessKind,
        challenge: LocalServiceChallenge,
    },
    /// Opens one exact-profile operational connection.
    SessionHello {
        version: u16,
        grant: SessionGrant,
        client_instance: ClientInstanceId,
        challenge: LocalServiceChallenge,
    },
    /// Returns the pinned service identity and its fresh challenge.
    ServiceChallenge {
        service_public_key: Ed25519PublicKey,
        challenge: LocalServiceChallenge,
    },
    /// Proves possession of the issuer or session private key.
    ClientAuth { signature: Ed25519Signature },
    /// Accepts the immutable authorization binding.
    ServiceAccept { signature: Ed25519Signature },
    /// Rejects authorization without disclosing which claim failed.
    ServiceReject { signature: Ed25519Signature },
}

impl AuthorizationHandshakeMessage {
    /// Encodes one canonical bounded handshake payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        match self {
            Self::IssuerHello {
                version,
                issuer_key_id,
                issuer_key_version,
                issuer_public_key,
                client_instance,
                harness,
                challenge,
            } => {
                encoded.push(KIND_ISSUER_HELLO);
                encoded.extend_from_slice(&version.to_be_bytes());
                encoded.extend_from_slice(issuer_key_id.as_bytes());
                encoded.extend_from_slice(&issuer_key_version.get().to_be_bytes());
                encoded.extend_from_slice(issuer_public_key.as_bytes());
                encoded.extend_from_slice(client_instance.as_bytes());
                encoded.extend_from_slice(&harness.wire_value().to_be_bytes());
                encoded.extend_from_slice(challenge.as_bytes());
            }
            Self::SessionHello {
                version,
                grant,
                client_instance,
                challenge,
            } => {
                encoded.push(KIND_SESSION_HELLO);
                encoded.extend_from_slice(&version.to_be_bytes());
                encode_grant(&mut encoded, grant);
                encoded.extend_from_slice(client_instance.as_bytes());
                encoded.extend_from_slice(challenge.as_bytes());
            }
            Self::ServiceChallenge {
                service_public_key,
                challenge,
            } => {
                encoded.push(KIND_SERVICE_CHALLENGE);
                encoded.extend_from_slice(service_public_key.as_bytes());
                encoded.extend_from_slice(challenge.as_bytes());
            }
            Self::ClientAuth { signature } => {
                encoded.push(KIND_CLIENT_AUTH);
                encoded.extend_from_slice(signature.as_bytes());
            }
            Self::ServiceAccept { signature } => {
                encoded.push(KIND_SERVICE_ACCEPT);
                encoded.extend_from_slice(signature.as_bytes());
            }
            Self::ServiceReject { signature } => {
                encoded.push(KIND_SERVICE_REJECT);
                encoded.extend_from_slice(signature.as_bytes());
            }
        }
        encoded
    }

    /// Decodes one exact protocol-v2 payload.
    ///
    /// # Errors
    ///
    /// Rejects protocol v1, unknown kinds, malformed fields, unsupported evidence,
    /// and any trailing bytes before a value reaches authorization.
    pub fn decode(payload: &[u8]) -> Result<Self, LocalServiceTransportError> {
        let (kind, mut rest) = payload
            .split_first()
            .ok_or(LocalServiceTransportError::MalformedFrame)?;
        let message = match *kind {
            KIND_ISSUER_HELLO => {
                let version = take_version(&mut rest)?;
                Self::IssuerHello {
                    version,
                    issuer_key_id: IssuerKeyId::from_bytes(take::<16>(&mut rest)?),
                    issuer_key_version: IssuerKeyVersion::new(u32::from_be_bytes(take::<4>(
                        &mut rest,
                    )?))?,
                    issuer_public_key: Ed25519PublicKey::from_bytes(take::<32>(&mut rest)?),
                    client_instance: ClientInstanceId::from_bytes(take::<16>(&mut rest)?),
                    harness: HarnessKind::from_wire_value(u16::from_be_bytes(take::<2>(
                        &mut rest,
                    )?))?,
                    challenge: LocalServiceChallenge::from_bytes(take::<CHALLENGE_LENGTH>(
                        &mut rest,
                    )?),
                }
            }
            KIND_SESSION_HELLO => {
                let version = take_version(&mut rest)?;
                let grant = decode_grant(&mut rest)?;
                Self::SessionHello {
                    version,
                    grant,
                    client_instance: ClientInstanceId::from_bytes(take::<16>(&mut rest)?),
                    challenge: LocalServiceChallenge::from_bytes(take::<CHALLENGE_LENGTH>(
                        &mut rest,
                    )?),
                }
            }
            KIND_SERVICE_CHALLENGE => Self::ServiceChallenge {
                service_public_key: Ed25519PublicKey::from_bytes(take::<32>(&mut rest)?),
                challenge: LocalServiceChallenge::from_bytes(take::<CHALLENGE_LENGTH>(&mut rest)?),
            },
            KIND_CLIENT_AUTH => Self::ClientAuth {
                signature: Ed25519Signature::from_bytes(take::<64>(&mut rest)?),
            },
            KIND_SERVICE_ACCEPT => Self::ServiceAccept {
                signature: Ed25519Signature::from_bytes(take::<64>(&mut rest)?),
            },
            KIND_SERVICE_REJECT => Self::ServiceReject {
                signature: Ed25519Signature::from_bytes(take::<64>(&mut rest)?),
            },
            1 => return Err(LocalServiceTransportError::ClientUpgradeRequired),
            _ => return Err(LocalServiceTransportError::UnknownMessageKind),
        };
        if !rest.is_empty() {
            return Err(LocalServiceTransportError::MalformedFrame);
        }
        Ok(message)
    }
}

fn take_version(rest: &mut &[u8]) -> Result<u16, LocalServiceTransportError> {
    let version = u16::from_be_bytes(take::<2>(rest)?);
    if version == 1 {
        return Err(LocalServiceTransportError::ClientUpgradeRequired);
    }
    if version != SESSION_GRANT_PROTOCOL_VERSION {
        return Err(LocalServiceTransportError::UnsupportedVersion);
    }
    Ok(version)
}

fn encode_grant(encoded: &mut Vec<u8>, grant: &SessionGrant) {
    encoded.extend_from_slice(grant.grant_id().as_bytes());
    encoded.extend_from_slice(grant.issuer_key_id().as_bytes());
    encoded.extend_from_slice(&grant.issuer_key_version().get().to_be_bytes());
    encoded.extend_from_slice(grant.session_public_key().as_bytes());
    encoded.extend_from_slice(&grant.harness().wire_value().to_be_bytes());
    let profile = grant.profile().as_str().as_bytes();
    encoded.extend_from_slice(
        &u16::try_from(profile.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    encoded.extend_from_slice(profile);
    encoded.push(grant.evidence().bits());
    encoded.extend_from_slice(&grant.policy_version().get().to_be_bytes());
    encoded.extend_from_slice(&grant.issued_at_unix_milliseconds().to_be_bytes());
    encoded.extend_from_slice(&grant.expires_at_unix_milliseconds().to_be_bytes());
    encoded.extend_from_slice(&grant.capabilities().bits().to_be_bytes());
}

fn decode_grant(rest: &mut &[u8]) -> Result<SessionGrant, LocalServiceTransportError> {
    let grant_id = SessionGrantId::from_bytes(take::<SESSION_GRANT_ID_LENGTH>(rest)?);
    let issuer_key_id = IssuerKeyId::from_bytes(take::<16>(rest)?);
    let issuer_key_version = IssuerKeyVersion::new(u32::from_be_bytes(take::<4>(rest)?))?;
    let session_public_key = Ed25519PublicKey::from_bytes(take::<32>(rest)?);
    let harness = HarnessKind::from_wire_value(u16::from_be_bytes(take::<2>(rest)?))?;
    let profile = take_profile(rest)?;
    let evidence = AuthorizationEvidenceSet::from_bits(take::<1>(rest)?[0])?;
    let policy_version = AuthorizationPolicyVersion::new(u64::from_be_bytes(take::<8>(rest)?))?;
    let issued_at = u64::from_be_bytes(take::<8>(rest)?);
    let expires_at = u64::from_be_bytes(take::<8>(rest)?);
    let capabilities = SessionCapabilities::from_bits(u64::from_be_bytes(take::<8>(rest)?))?;
    SessionGrant::new(SessionGrantClaims {
        grant_id,
        issuer_key_id,
        issuer_key_version,
        profile,
        session_public_key,
        harness,
        evidence,
        policy_version,
        issued_at_unix_milliseconds: issued_at,
        expires_at_unix_milliseconds: expires_at,
        capabilities,
    })
}

fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], LocalServiceTransportError> {
    if rest.len() < N {
        return Err(LocalServiceTransportError::MalformedFrame);
    }
    let (head, tail) = rest.split_at(N);
    *rest = tail;
    head.try_into()
        .map_err(|_| LocalServiceTransportError::MalformedFrame)
}

fn take_profile(rest: &mut &[u8]) -> Result<ServiceProfileId, LocalServiceTransportError> {
    let length = usize::from(u16::from_be_bytes(take::<2>(rest)?));
    if length == 0 || length > MAX_PROFILE_ID_LENGTH || rest.len() < length {
        return Err(LocalServiceTransportError::InvalidIdentifier { field: "profile" });
    }
    let (profile, tail) = rest.split_at(length);
    *rest = tail;
    ServiceProfileId::parse(
        core::str::from_utf8(profile)
            .map_err(|_| LocalServiceTransportError::InvalidIdentifier { field: "profile" })?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizationEvidenceKind, SessionGrantId};

    fn grant() -> SessionGrant {
        SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes([1; 16]),
            issuer_key_id: IssuerKeyId::from_bytes([2; 16]),
            issuer_key_version: IssuerKeyVersion::new(3).unwrap(),
            profile: ServiceProfileId::parse("session-a").unwrap(),
            session_public_key: Ed25519PublicKey::from_bytes([4; 32]),
            harness: HarnessKind::Generic,
            evidence: AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
                .unwrap(),
            policy_version: AuthorizationPolicyVersion::new(5).unwrap(),
            issued_at_unix_milliseconds: 6,
            expires_at_unix_milliseconds: 7,
            capabilities: SessionCapabilities::ALL,
        })
        .unwrap()
    }

    #[test]
    fn every_v2_message_round_trips_within_the_pre_authentication_bound() {
        let messages = [
            AuthorizationHandshakeMessage::IssuerHello {
                version: SESSION_GRANT_PROTOCOL_VERSION,
                issuer_key_id: IssuerKeyId::from_bytes([1; 16]),
                issuer_key_version: IssuerKeyVersion::new(2).unwrap(),
                issuer_public_key: Ed25519PublicKey::from_bytes([3; 32]),
                client_instance: ClientInstanceId::from_bytes([4; 16]),
                harness: HarnessKind::Copilot,
                challenge: LocalServiceChallenge::from_bytes([5; 32]),
            },
            AuthorizationHandshakeMessage::SessionHello {
                version: SESSION_GRANT_PROTOCOL_VERSION,
                grant: grant(),
                client_instance: ClientInstanceId::from_bytes([6; 16]),
                challenge: LocalServiceChallenge::from_bytes([7; 32]),
            },
            AuthorizationHandshakeMessage::ServiceChallenge {
                service_public_key: Ed25519PublicKey::from_bytes([8; 32]),
                challenge: LocalServiceChallenge::from_bytes([9; 32]),
            },
            AuthorizationHandshakeMessage::ClientAuth {
                signature: Ed25519Signature::from_bytes([10; 64]),
            },
            AuthorizationHandshakeMessage::ServiceAccept {
                signature: Ed25519Signature::from_bytes([11; 64]),
            },
            AuthorizationHandshakeMessage::ServiceReject {
                signature: Ed25519Signature::from_bytes([12; 64]),
            },
        ];
        for message in messages {
            let encoded = message.encode();
            assert!(encoded.len() <= MAX_AUTHORIZATION_HANDSHAKE_FRAME_BYTES);
            assert_eq!(
                AuthorizationHandshakeMessage::decode(&encoded).unwrap(),
                message
            );
        }
    }

    #[test]
    fn a_v1_hello_requires_a_client_upgrade() {
        assert_eq!(
            AuthorizationHandshakeMessage::decode(&[1, 0, 1]).unwrap_err(),
            LocalServiceTransportError::ClientUpgradeRequired
        );
    }
}
