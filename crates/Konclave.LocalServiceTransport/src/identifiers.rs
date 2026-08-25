use crate::error::LocalServiceTransportError;

/// Local service protocol version implemented by this build.
pub const LOCAL_SERVICE_PROTOCOL_VERSION: u16 = 1;

/// Byte length of a handshake challenge.
pub const CHALLENGE_LENGTH: usize = 32;

/// Largest accepted profile identifier, in bytes.
///
/// This matches the daemon runtime's durable profile bound, so every authenticated
/// request can address a profile the service can actually open without a second,
/// narrower validation step.
pub const MAX_PROFILE_ID_LENGTH: usize = 32;

/// Wire value for a Copilot harness.
const HARNESS_COPILOT: u16 = 1;

/// Wire value for a Claude Code harness.
const HARNESS_CLAUDE_CODE: u16 = 2;

/// Wire value for a Codex harness.
const HARNESS_CODEX: u16 = 3;

macro_rules! define_fixed_identifier {
    ($(#[$meta:meta])* $name:ident, $length:expr, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Required byte length for this identifier.
            pub const LENGTH: usize = $length;

            /// Wraps an array that already has the required length.
            #[must_use]
            pub const fn from_bytes(value: [u8; $length]) -> Self {
                Self(value)
            }

            /// Parses an identifier from a byte slice.
            ///
            /// # Errors
            ///
            /// Returns [`LocalServiceTransportError::InvalidIdentifier`] when `value`
            /// does not contain exactly [`Self::LENGTH`] bytes.
            pub fn from_slice(value: &[u8]) -> Result<Self, LocalServiceTransportError> {
                let bytes = value.try_into().map_err(|_| {
                    LocalServiceTransportError::InvalidIdentifier { field: $field }
                })?;
                Ok(Self(bytes))
            }

            /// Returns the canonical bytes without transferring ownership.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }
    };
}

define_fixed_identifier!(
    /// Random identifier for one registered harness adapter signing key.
    ///
    /// The identifier is public routing information for the service registry. It is
    /// not a credential: possession of it proves nothing without the matching private
    /// key.
    AdapterKeyId,
    16,
    "adapter_key"
);

define_fixed_identifier!(
    /// Identifier for one live client connection attempt.
    ///
    /// A reconnect uses the same registered adapter key with a fresh instance, so
    /// this value distinguishes connections without becoming a durable identity.
    ClientInstanceId,
    16,
    "client_instance"
);

/// Version of one registered adapter signing key.
///
/// Rotation registers a new version before the previous one is retired, so the
/// version is part of the authorization lookup rather than a display value. Zero is
/// rejected because an uninitialized field must never resolve to a real registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdapterKeyVersion(u32);

impl AdapterKeyVersion {
    /// Creates a key version.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::InvalidIdentifier`] when `value` is
    /// zero.
    pub const fn new(value: u32) -> Result<Self, LocalServiceTransportError> {
        if value == 0 {
            return Err(LocalServiceTransportError::InvalidIdentifier {
                field: "adapter_key_version",
            });
        }
        Ok(Self(value))
    }

    /// Returns the version number.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0
    }
}

/// One fresh, single-use handshake challenge contributed by one peer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalServiceChallenge([u8; CHALLENGE_LENGTH]);

impl LocalServiceChallenge {
    /// Wraps exactly [`CHALLENGE_LENGTH`] fresh bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHALLENGE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the challenge bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHALLENGE_LENGTH] {
        &self.0
    }
}

impl core::fmt::Debug for LocalServiceChallenge {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalServiceChallenge")
            .finish_non_exhaustive()
    }
}

/// The finite set of agent harnesses this build implements.
///
/// The value is a closed enumeration rather than free text, so a client cannot invent
/// a harness the service has never authorized. Unimplemented wire values are rejected
/// instead of being retained, which keeps a future harness additive here and fail
/// closed on an older service.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HarnessKind {
    /// A GitHub Copilot CLI session.
    Copilot,
    /// A Claude Code session.
    ClaudeCode,
    /// A Codex session.
    Codex,
}

impl HarnessKind {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn wire_value(&self) -> u16 {
        match self {
            Self::Copilot => HARNESS_COPILOT,
            Self::ClaudeCode => HARNESS_CLAUDE_CODE,
            Self::Codex => HARNESS_CODEX,
        }
    }

    /// Parses a wire value.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnknownHarnessKind`] for any value this
    /// build does not implement.
    pub const fn from_wire_value(value: u16) -> Result<Self, LocalServiceTransportError> {
        match value {
            HARNESS_COPILOT => Ok(Self::Copilot),
            HARNESS_CLAUDE_CODE => Ok(Self::ClaudeCode),
            HARNESS_CODEX => Ok(Self::Codex),
            _ => Err(LocalServiceTransportError::UnknownHarnessKind),
        }
    }

    /// Returns the stable machine-readable name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Copilot => "copilot",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }
}

/// A validated local profile identifier a client may request.
///
/// The accepted characters and length match the daemon runtime identifier, so this
/// value can address a real profile without any further escaping, path joining, or
/// normalization.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceProfileId(String);

impl ServiceProfileId {
    /// Parses a bounded profile identifier.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::InvalidIdentifier`] when the value is
    /// empty, longer than [`MAX_PROFILE_ID_LENGTH`], or contains a character outside
    /// ASCII alphanumerics, `-`, and `_`.
    pub fn parse(value: &str) -> Result<Self, LocalServiceTransportError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_ID_LENGTH {
            return Err(LocalServiceTransportError::InvalidIdentifier { field: "profile" });
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(LocalServiceTransportError::InvalidIdentifier { field: "profile" });
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The profiles one adapter registration may attach to.
///
/// An installation usually registers one adapter for one profile. A namespace exists
/// for an installation that owns a family of profiles, and it authorizes only the
/// label itself plus identifiers that continue with `-`. A namespace label therefore
/// never authorizes a longer unrelated identifier that merely starts with the same
/// characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileAuthorization {
    /// Exactly one profile identifier.
    Profile(ServiceProfileId),
    /// One label plus every `label-suffix` profile beneath it.
    Namespace(ServiceProfileId),
}

impl ProfileAuthorization {
    /// Reports whether this authorization covers `profile`.
    #[must_use]
    pub fn permits(&self, profile: &ServiceProfileId) -> bool {
        match self {
            Self::Profile(allowed) => allowed == profile,
            Self::Namespace(label) => {
                let label = label.as_str();
                let requested = profile.as_str();
                requested == label
                    || (requested.len() > label.len()
                        && requested.starts_with(label)
                        && requested.as_bytes()[label.len()] == b'-')
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterKeyId, AdapterKeyVersion, HarnessKind, MAX_PROFILE_ID_LENGTH, ProfileAuthorization,
        ServiceProfileId,
    };
    use crate::error::LocalServiceTransportError;

    fn profile(value: &str) -> ServiceProfileId {
        ServiceProfileId::parse(value).unwrap()
    }

    #[test]
    fn a_fixed_identifier_requires_its_exact_length() {
        assert_eq!(
            AdapterKeyId::from_slice(&[1_u8; AdapterKeyId::LENGTH])
                .unwrap()
                .as_bytes(),
            &[1_u8; AdapterKeyId::LENGTH]
        );
        for length in [0, AdapterKeyId::LENGTH - 1, AdapterKeyId::LENGTH + 1] {
            assert_eq!(
                AdapterKeyId::from_slice(&vec![1_u8; length]).unwrap_err(),
                LocalServiceTransportError::InvalidIdentifier {
                    field: "adapter_key"
                }
            );
        }
    }

    #[test]
    fn a_zero_key_version_is_rejected() {
        assert_eq!(
            AdapterKeyVersion::new(0).unwrap_err(),
            LocalServiceTransportError::InvalidIdentifier {
                field: "adapter_key_version"
            }
        );
        assert_eq!(AdapterKeyVersion::new(1).unwrap().get(), 1);
    }

    #[test]
    fn every_harness_round_trips_and_unknown_values_fail_closed() {
        for harness in [
            HarnessKind::Copilot,
            HarnessKind::ClaudeCode,
            HarnessKind::Codex,
        ] {
            assert_eq!(
                HarnessKind::from_wire_value(harness.wire_value()).unwrap(),
                harness
            );
        }
        for value in [0_u16, 4, u16::MAX] {
            assert_eq!(
                HarnessKind::from_wire_value(value).unwrap_err(),
                LocalServiceTransportError::UnknownHarnessKind
            );
        }
    }

    #[test]
    fn a_profile_identifier_is_bounded_and_portable() {
        assert_eq!(profile("alice_01-b").as_str(), "alice_01-b");
        assert!(ServiceProfileId::parse(&"a".repeat(MAX_PROFILE_ID_LENGTH)).is_ok());
        for value in [
            String::new(),
            "a".repeat(MAX_PROFILE_ID_LENGTH + 1),
            "alice/../bob".to_string(),
            "alice.bob".to_string(),
            "alice bob".to_string(),
            "alice\u{0}".to_string(),
            "álice".to_string(),
        ] {
            assert_eq!(
                ServiceProfileId::parse(&value).unwrap_err(),
                LocalServiceTransportError::InvalidIdentifier { field: "profile" },
                "value must not parse: {value:?}"
            );
        }
    }

    #[test]
    fn an_exact_authorization_permits_only_that_profile() {
        let authorization = ProfileAuthorization::Profile(profile("alice"));
        assert!(authorization.permits(&profile("alice")));
        assert!(!authorization.permits(&profile("alice-work")));
        assert!(!authorization.permits(&profile("bob")));
    }

    #[test]
    fn a_namespace_permits_only_its_label_and_separated_children() {
        let authorization = ProfileAuthorization::Namespace(profile("team"));
        assert!(authorization.permits(&profile("team")));
        assert!(authorization.permits(&profile("team-alice")));
        assert!(authorization.permits(&profile("team-alice-work")));
        assert!(!authorization.permits(&profile("teamalice")));
        assert!(!authorization.permits(&profile("team_alice")));
        assert!(!authorization.permits(&profile("other-team")));
    }
}
