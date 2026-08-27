use thiserror::Error;

/// Stable failures produced while establishing or using a local service channel.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalServiceTransportError {
    /// The peer offered a protocol version this build does not implement.
    #[error("local service protocol version is unsupported")]
    UnsupportedVersion,

    /// A protocol-v1 client reached a protocol-v2 service.
    #[error("local service client upgrade is required")]
    ClientUpgradeRequired,

    /// A protocol-v2 client reached an older service.
    #[error("local service upgrade is required")]
    ServiceUpgradeRequired,

    /// A frame declared more bytes than its stage permits.
    #[error("local service frame exceeds its bound")]
    FrameTooLarge,

    /// A frame was empty, truncated, or carried bytes past its last field.
    #[error("local service frame is malformed")]
    MalformedFrame,

    /// A frame carried a message tag this build does not implement.
    #[error("local service message kind is unknown")]
    UnknownMessageKind,

    /// A valid message arrived out of handshake order.
    #[error("local service message arrived out of order")]
    UnexpectedMessage,

    /// The channel ended before the exchange completed.
    #[error("local service channel closed")]
    ChannelClosed,

    /// The peer did not finish the handshake within its bound.
    #[error("local service handshake did not complete in time")]
    HandshakeTimeout,

    /// The process-global challenge counter cannot issue another unique value.
    #[error("local service challenge space is exhausted")]
    ChallengeExhausted,

    /// A bounded identifier was empty, oversized, or not an accepted character.
    #[error("local service {field} identifier is invalid")]
    InvalidIdentifier { field: &'static str },

    /// A harness value on the wire is not one this build implements.
    #[error("local service harness kind is unknown")]
    UnknownHarnessKind,

    /// A stable error code on the wire is not one this build implements.
    #[error("local service error code is unknown")]
    UnknownErrorCode,

    /// An evidence set or policy clause is empty, duplicated, or contains unknown bits.
    #[error("local service authorization evidence is invalid")]
    InvalidEvidence,

    /// A grant's capability set is empty or contains unknown bits.
    #[error("local service session capabilities are invalid")]
    InvalidCapabilities,

    /// A grant has contradictory issuance or expiry values.
    #[error("local service session grant is invalid")]
    InvalidGrant,

    /// A grant identifier already exists.
    #[error("local service session grant already exists")]
    DuplicateGrant,

    /// The service cannot admit another grant without evicting an active one.
    #[error("local service session grant limit is reached")]
    GrantLimitReached,

    /// No active registration exists for the presented adapter key and version.
    #[error("local service adapter registration is not active")]
    UnknownAdapterRegistration,

    /// The registration does not authorize the harness the client claimed.
    #[error("local service harness is not authorized for this registration")]
    HarnessNotAuthorized,

    /// The registration does not authorize the requested profile.
    #[error("local service profile is not authorized for this registration")]
    ProfileNotAuthorized,

    /// An adapter registration already exists for this exact key and version.
    #[error("local service adapter registration already exists")]
    DuplicateRegistration,

    /// The registry cannot hold another adapter registration.
    #[error("local service adapter registration limit is reached")]
    RegistrationLimitReached,

    /// The client signature does not authenticate the negotiated transcript.
    #[error("local service client is not authentic")]
    UnauthenticClient,

    /// The service signature does not authenticate the negotiated transcript.
    #[error("local service is not authentic")]
    UnauthenticService,

    /// The service presented a public key other than the one the client pinned.
    #[error("local service identity does not match the pinned key")]
    ServiceKeyMismatch,

    /// A request or response value falls outside its declared bound.
    #[error("local service request is outside its bound")]
    RequestOutOfBounds,

    /// The configured endpoint is empty, oversized, or not a local endpoint.
    #[error("local service endpoint is invalid")]
    InvalidEndpoint,

    /// The endpoint could not be reached.
    #[error("local service endpoint is unavailable")]
    EndpointUnavailable,

    /// The endpoint or its directory is reachable by an account other than the owner,
    /// or is a link that could redirect the channel.
    #[error("local service endpoint is not owner-protected")]
    EndpointNotOwnerProtected,

    /// Another process already owns this endpoint name.
    #[error("local service endpoint is already in use")]
    EndpointInUse,

    /// The connecting peer does not belong to the account that owns this service.
    #[error("local service peer is not the owning account")]
    UnauthorizedPeer,

    /// Peer ownership could not be established on this platform or connection.
    #[error("local service peer ownership could not be verified")]
    PeerVerificationUnavailable,

    /// The vetted cryptographic provider rejected a signing or verifying operation.
    #[error("local service signing material is unusable")]
    UnusableKeyMaterial,
}

impl LocalServiceTransportError {
    /// Returns the stable machine-readable error code.
    ///
    /// A code never includes a challenge, key, identifier, or path, so it is safe to
    /// log and to return on a failed handshake or request.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "local_service_unsupported_version",
            Self::ClientUpgradeRequired => "local_service_client_upgrade_required",
            Self::ServiceUpgradeRequired => "local_service_upgrade_required",
            Self::FrameTooLarge => "local_service_frame_too_large",
            Self::MalformedFrame => "local_service_malformed_frame",
            Self::UnknownMessageKind => "local_service_unknown_message_kind",
            Self::UnexpectedMessage => "local_service_unexpected_message",
            Self::ChannelClosed => "local_service_channel_closed",
            Self::HandshakeTimeout => "local_service_handshake_timeout",
            Self::ChallengeExhausted => "local_service_challenge_exhausted",
            Self::InvalidIdentifier { .. } => "local_service_invalid_identifier",
            Self::UnknownHarnessKind => "local_service_unknown_harness_kind",
            Self::UnknownErrorCode => "local_service_unknown_error_code",
            Self::InvalidEvidence => "local_service_invalid_evidence",
            Self::InvalidCapabilities => "local_service_invalid_capabilities",
            Self::InvalidGrant => "local_service_invalid_grant",
            Self::DuplicateGrant => "local_service_duplicate_grant",
            Self::GrantLimitReached => "local_service_grant_limit_reached",
            Self::UnknownAdapterRegistration => "local_service_unknown_adapter_registration",
            Self::HarnessNotAuthorized => "local_service_harness_not_authorized",
            Self::ProfileNotAuthorized => "local_service_profile_not_authorized",
            Self::DuplicateRegistration => "local_service_duplicate_registration",
            Self::RegistrationLimitReached => "local_service_registration_limit_reached",
            Self::UnauthenticClient => "local_service_unauthentic_client",
            Self::UnauthenticService => "local_service_unauthentic_service",
            Self::ServiceKeyMismatch => "local_service_key_mismatch",
            Self::RequestOutOfBounds => "local_service_request_out_of_bounds",
            Self::InvalidEndpoint => "local_service_invalid_endpoint",
            Self::EndpointUnavailable => "local_service_endpoint_unavailable",
            Self::EndpointNotOwnerProtected => "local_service_endpoint_not_owner_protected",
            Self::EndpointInUse => "local_service_endpoint_in_use",
            Self::UnauthorizedPeer => "local_service_unauthorized_peer",
            Self::PeerVerificationUnavailable => "local_service_peer_verification_unavailable",
            Self::UnusableKeyMaterial => "local_service_unusable_key_material",
        }
    }
}

impl From<KonclaveLocalFraming::FrameError> for LocalServiceTransportError {
    fn from(error: KonclaveLocalFraming::FrameError) -> Self {
        match error {
            KonclaveLocalFraming::FrameError::TooLarge => Self::FrameTooLarge,
            KonclaveLocalFraming::FrameError::Malformed => Self::MalformedFrame,
            KonclaveLocalFraming::FrameError::Closed => Self::ChannelClosed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LocalServiceTransportError;

    #[test]
    fn every_code_is_distinct_and_namespaced() {
        let errors = [
            LocalServiceTransportError::UnsupportedVersion,
            LocalServiceTransportError::ClientUpgradeRequired,
            LocalServiceTransportError::ServiceUpgradeRequired,
            LocalServiceTransportError::FrameTooLarge,
            LocalServiceTransportError::MalformedFrame,
            LocalServiceTransportError::UnknownMessageKind,
            LocalServiceTransportError::UnexpectedMessage,
            LocalServiceTransportError::ChannelClosed,
            LocalServiceTransportError::HandshakeTimeout,
            LocalServiceTransportError::ChallengeExhausted,
            LocalServiceTransportError::InvalidIdentifier { field: "profile" },
            LocalServiceTransportError::UnknownHarnessKind,
            LocalServiceTransportError::UnknownErrorCode,
            LocalServiceTransportError::InvalidEvidence,
            LocalServiceTransportError::InvalidCapabilities,
            LocalServiceTransportError::InvalidGrant,
            LocalServiceTransportError::DuplicateGrant,
            LocalServiceTransportError::GrantLimitReached,
            LocalServiceTransportError::UnknownAdapterRegistration,
            LocalServiceTransportError::HarnessNotAuthorized,
            LocalServiceTransportError::ProfileNotAuthorized,
            LocalServiceTransportError::DuplicateRegistration,
            LocalServiceTransportError::RegistrationLimitReached,
            LocalServiceTransportError::UnauthenticClient,
            LocalServiceTransportError::UnauthenticService,
            LocalServiceTransportError::ServiceKeyMismatch,
            LocalServiceTransportError::RequestOutOfBounds,
            LocalServiceTransportError::InvalidEndpoint,
            LocalServiceTransportError::EndpointUnavailable,
            LocalServiceTransportError::EndpointNotOwnerProtected,
            LocalServiceTransportError::EndpointInUse,
            LocalServiceTransportError::UnauthorizedPeer,
            LocalServiceTransportError::PeerVerificationUnavailable,
            LocalServiceTransportError::UnusableKeyMaterial,
        ];
        let mut codes: Vec<&'static str> = errors
            .iter()
            .map(LocalServiceTransportError::code)
            .collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "error codes must be unique");
        assert!(
            codes.iter().all(|code| code.starts_with("local_service_")),
            "codes must stay namespaced"
        );
    }

    #[test]
    fn a_rendered_error_carries_no_untrusted_value() {
        let rendered = format!(
            "{}",
            LocalServiceTransportError::InvalidIdentifier { field: "profile" }
        );
        assert_eq!(rendered, "local service profile identifier is invalid");
    }
}
