use crate::error::LocalServiceTransportError;
use crate::identifiers::{
    AdapterKeyId, AdapterKeyVersion, ClientInstanceId, HarnessKind, LOCAL_SERVICE_PROTOCOL_VERSION,
    ServiceProfileId,
};

/// The immutable authorization a local service connection is bound to.
///
/// The binding is established once, during the handshake, and every value in it is
/// covered by both signatures. A client therefore cannot switch profile, harness,
/// registration, or version by changing a later request field: the only way to reach
/// a different binding is a new connection and a new handshake.
///
/// Every field is public routing or authorization information. None of it is secret,
/// so this object is safe to carry alongside a connection and to include in a
/// structured log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalServiceBinding {
    version: u16,
    adapter_key_id: AdapterKeyId,
    adapter_key_version: AdapterKeyVersion,
    client_instance: ClientInstanceId,
    harness: HarnessKind,
    profile: ServiceProfileId,
}

impl LocalServiceBinding {
    /// Validates and assembles a connection binding.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnsupportedVersion`] for a version this
    /// build does not implement.
    pub fn new(
        version: u16,
        adapter_key_id: AdapterKeyId,
        adapter_key_version: AdapterKeyVersion,
        client_instance: ClientInstanceId,
        harness: HarnessKind,
        profile: ServiceProfileId,
    ) -> Result<Self, LocalServiceTransportError> {
        if version != LOCAL_SERVICE_PROTOCOL_VERSION {
            return Err(LocalServiceTransportError::UnsupportedVersion);
        }
        Ok(Self {
            version,
            adapter_key_id,
            adapter_key_version,
            client_instance,
            harness,
            profile,
        })
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the registered adapter key identifier.
    #[must_use]
    pub const fn adapter_key_id(&self) -> AdapterKeyId {
        self.adapter_key_id
    }

    /// Returns the registered adapter key version.
    #[must_use]
    pub const fn adapter_key_version(&self) -> AdapterKeyVersion {
        self.adapter_key_version
    }

    /// Returns the identifier of this client connection attempt.
    #[must_use]
    pub const fn client_instance(&self) -> ClientInstanceId {
        self.client_instance
    }

    /// Returns the authorized harness.
    #[must_use]
    pub const fn harness(&self) -> HarnessKind {
        self.harness
    }

    /// Returns the authorized profile.
    #[must_use]
    pub const fn profile(&self) -> &ServiceProfileId {
        &self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::LocalServiceBinding;
    use crate::error::LocalServiceTransportError;
    use crate::identifiers::{
        AdapterKeyId, AdapterKeyVersion, ClientInstanceId, HarnessKind,
        LOCAL_SERVICE_PROTOCOL_VERSION, ServiceProfileId,
    };

    fn binding(version: u16) -> Result<LocalServiceBinding, LocalServiceTransportError> {
        LocalServiceBinding::new(
            version,
            AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH]),
            AdapterKeyVersion::new(2).unwrap(),
            ClientInstanceId::from_bytes([3_u8; ClientInstanceId::LENGTH]),
            HarnessKind::Copilot,
            ServiceProfileId::parse("alice").unwrap(),
        )
    }

    #[test]
    fn a_binding_exposes_every_authorized_value() {
        let binding = binding(LOCAL_SERVICE_PROTOCOL_VERSION).unwrap();
        assert_eq!(binding.version(), LOCAL_SERVICE_PROTOCOL_VERSION);
        assert_eq!(
            binding.adapter_key_id(),
            AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH])
        );
        assert_eq!(binding.adapter_key_version().get(), 2);
        assert_eq!(
            binding.client_instance(),
            ClientInstanceId::from_bytes([3_u8; ClientInstanceId::LENGTH])
        );
        assert_eq!(binding.harness(), HarnessKind::Copilot);
        assert_eq!(binding.profile().as_str(), "alice");
    }

    #[test]
    fn an_unimplemented_version_never_produces_a_binding() {
        assert_eq!(
            binding(LOCAL_SERVICE_PROTOCOL_VERSION + 1).unwrap_err(),
            LocalServiceTransportError::UnsupportedVersion
        );
    }
}
