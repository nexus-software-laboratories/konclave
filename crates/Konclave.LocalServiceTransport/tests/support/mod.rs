//! Shared attach fixture for the endpoint integration tests.
//!
//! Both platform test binaries need one registered adapter and one authorized
//! profile before they can exercise a real endpoint, and neither should restate the
//! registration rules to do it.

#![allow(dead_code)]

use KonclaveCryptographicCore::LocalServiceIdentity;
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AdapterRegistration, AuthenticatedLocalChannel,
    ClientHandshakeRequest, ClientInstanceId, HarnessKind, InMemoryAdapterRegistry,
    LocalServiceTransportError, ProfileAuthorization, ServiceProfileId, complete_client_handshake,
    complete_service_handshake,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// One service identity plus the registrations and client keys that may attach.
pub struct AttachFixture {
    service_identity: LocalServiceIdentity,
    clients: Vec<ClientFixture>,
    registry: InMemoryAdapterRegistry,
}

struct ClientFixture {
    identity: LocalServiceIdentity,
    request: ClientHandshakeRequest,
}

impl AttachFixture {
    /// Registers one adapter key per profile, each authorized for that profile only.
    ///
    /// # Panics
    ///
    /// Panics when a profile identifier is invalid or a registration is rejected,
    /// because a fixture that cannot be built has no meaningful outcome.
    #[must_use]
    pub fn for_profiles(profiles: &[&str]) -> Self {
        let service_identity = LocalServiceIdentity::generate().unwrap();
        let mut registry = InMemoryAdapterRegistry::new();
        let mut clients = Vec::with_capacity(profiles.len());

        for (index, profile) in profiles.iter().enumerate() {
            let seed = u8::try_from(index).unwrap() + 1;
            let identity = LocalServiceIdentity::generate().unwrap();
            let adapter_key_id = AdapterKeyId::from_bytes([seed; AdapterKeyId::LENGTH]);
            let adapter_key_version = AdapterKeyVersion::new(1).unwrap();
            let profile = ServiceProfileId::parse(profile).unwrap();
            registry
                .register(
                    adapter_key_id,
                    adapter_key_version,
                    AdapterRegistration::new(
                        identity.public_key(),
                        HarnessKind::Copilot,
                        ProfileAuthorization::Profile(profile.clone()),
                    ),
                )
                .unwrap();
            clients.push(ClientFixture {
                identity,
                request: ClientHandshakeRequest {
                    adapter_key_id,
                    adapter_key_version,
                    client_instance: ClientInstanceId::from_bytes([seed; ClientInstanceId::LENGTH]),
                    harness: HarnessKind::Copilot,
                    profile,
                },
            });
        }

        Self {
            service_identity,
            clients,
            registry,
        }
    }

    /// Returns the public key a client pins.
    #[must_use]
    pub fn service_public_key(&self) -> KonclaveDomainCore::Ed25519PublicKey {
        self.service_identity.public_key()
    }

    /// Runs the client role for the registered client at `index`.
    ///
    /// # Errors
    ///
    /// Returns whatever the handshake rejects.
    pub async fn attach_client<S>(
        &self,
        stream: &mut S,
        index: usize,
    ) -> Result<AuthenticatedLocalChannel, LocalServiceTransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let client = &self.clients[index];
        complete_client_handshake(
            stream,
            &client.request,
            &client.identity,
            self.service_identity.public_key(),
        )
        .await
    }

    /// Runs the service role.
    ///
    /// # Errors
    ///
    /// Returns whatever the handshake rejects.
    pub async fn attach_service<S>(
        &self,
        stream: &mut S,
    ) -> Result<AuthenticatedLocalChannel, LocalServiceTransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        complete_service_handshake(stream, &self.registry, &self.service_identity).await
    }
}
