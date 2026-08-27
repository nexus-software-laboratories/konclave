use KonclaveDomainCore::Ed25519PublicKey;

use crate::{
    ClientInstanceId, HarnessKind, IssuerKeyId, IssuerKeyVersion, SESSION_GRANT_PROTOCOL_VERSION,
    SessionGrant,
};

/// Immutable authorization role negotiated for one v2 local connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationBinding {
    /// Account issuer connection. It may request grants but cannot operate a profile.
    Issuer {
        issuer_key_id: IssuerKeyId,
        issuer_key_version: IssuerKeyVersion,
        issuer_public_key: Ed25519PublicKey,
        client_instance: ClientInstanceId,
        harness: HarnessKind,
    },
    /// Operational connection authorized by one exact-profile session grant.
    Session {
        grant: SessionGrant,
        client_instance: ClientInstanceId,
    },
}

impl AuthorizationBinding {
    /// Returns protocol version 2.
    #[must_use]
    pub const fn version(&self) -> u16 {
        SESSION_GRANT_PROTOCOL_VERSION
    }

    /// Returns the fresh connection instance.
    #[must_use]
    pub const fn client_instance(&self) -> ClientInstanceId {
        match self {
            Self::Issuer {
                client_instance, ..
            }
            | Self::Session {
                client_instance, ..
            } => *client_instance,
        }
    }

    /// Returns the integration kind.
    #[must_use]
    pub const fn harness(&self) -> HarnessKind {
        match self {
            Self::Issuer { harness, .. } => *harness,
            Self::Session { grant, .. } => grant.harness(),
        }
    }

    /// Returns the exact session grant for an operational connection.
    #[must_use]
    pub const fn session_grant(&self) -> Option<&SessionGrant> {
        match self {
            Self::Issuer { .. } => None,
            Self::Session { grant, .. } => Some(grant),
        }
    }

    /// Returns the issuer key identifier for either role.
    #[must_use]
    pub const fn issuer_key_id(&self) -> IssuerKeyId {
        match self {
            Self::Issuer { issuer_key_id, .. } => *issuer_key_id,
            Self::Session { grant, .. } => grant.issuer_key_id(),
        }
    }

    /// Returns the issuer key version for either role.
    #[must_use]
    pub const fn issuer_key_version(&self) -> IssuerKeyVersion {
        match self {
            Self::Issuer {
                issuer_key_version, ..
            } => *issuer_key_version,
            Self::Session { grant, .. } => grant.issuer_key_version(),
        }
    }
}
