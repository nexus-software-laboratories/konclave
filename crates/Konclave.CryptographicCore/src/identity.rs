use std::mem::size_of;

use KonclaveDomainCore::{
    APPLICATION_CAPABILITY_DIRECTED_REQUEST, ConversationId, ConversationRole,
    CredentialBindingHash, DeviceCredentialBinding, DeviceId, Ed25519PublicKey, Ed25519Signature,
    EnvelopeId, Invitation, InvitationId, InvitationNonce, MessageId, NotificationId,
    PairingContextHash, PairingControl, PairingId, PairingMessageId, PairingOffer, PairingStage,
    ProtocolVersion, RoutingId, SignatureScheme,
};
use KonclaveProtocolContracts::v1::{
    decode_device_credential_binding, encode_device_credential_binding,
};
use KonclaveSecretStorage::{SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer};
use mls_rs::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_awslc::{AwsLcCipherSuite, AwsLcCryptoProvider};
use zeroize::Zeroizing;

use crate::KonclaveCryptographicError;

pub(crate) const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;
const DEVICE_ID_DOMAIN: &[u8] = b"konclave-device-id-v1\0";
const CREDENTIAL_DOMAIN: &[u8] = b"konclave-device-credential-binding-v1\0";
const CREDENTIAL_CAPABILITY_DOMAIN: &[u8] = b"konclave-device-credential-capabilities-v1\0";
const CREDENTIAL_HASH_DOMAIN: &[u8] = b"konclave-device-credential-binding-hash-v1\0";
const INVITATION_DOMAIN: &[u8] = b"konclave-invitation-v1\0";
const PAIRING_OFFER_DOMAIN: &[u8] = b"konclave-pairing-offer-v1\0";
const PAIRING_CONTROL_DOMAIN: &[u8] = b"konclave-pairing-control-v1\0";
const DEVICE_IDENTITY_V1_MAGIC: &[u8; 4] = b"KDI1";
const DEVICE_IDENTITY_V2_MAGIC: &[u8; 4] = b"KDI2";
const CONVERSATION_SIGNING_MAGIC: &[u8; 4] = b"KCS1";

/// Device-scoped root identity whose secret key remains inside the trusted daemon.
pub struct DeviceIdentity {
    provider: AwsLcCryptoProvider,
    secret_key: SignatureSecretKey,
    public_key: Ed25519PublicKey,
    device_id: DeviceId,
}

impl DeviceIdentity {
    /// Generates a new Ed25519 device root identity with provider-backed randomness.
    ///
    /// # Errors
    ///
    /// Returns a provider or domain validation error when key generation or
    /// identifier derivation fails.
    pub fn generate() -> Result<Self, KonclaveCryptographicError> {
        let provider = configured_provider();
        let cipher_suite = cipher_suite(&provider)?;
        let (secret_key, public_key) = cipher_suite
            .signature_key_generate()
            .map_err(|_| provider_failure("device root key generation"))?;
        let public_key = Ed25519PublicKey::from_slice(public_key.as_bytes())?;
        let device_id = derive_device_id_with_suite(&cipher_suite, public_key)?;
        Ok(Self {
            provider,
            secret_key,
            public_key,
            device_id,
        })
    }

    /// Returns the digest-derived public device identifier.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the public device-root verification key.
    #[must_use]
    pub const fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    /// Generates a high-entropy conversation identifier.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate_conversation_id(&self) -> Result<ConversationId, KonclaveCryptographicError> {
        Ok(ConversationId::from_slice(
            &self.generate_identifier_bytes(ConversationId::LENGTH)?,
        )?)
    }

    /// Generates a high-entropy opaque relay route.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate_routing_id(&self) -> Result<RoutingId, KonclaveCryptographicError> {
        Ok(RoutingId::from_slice(
            &self.generate_identifier_bytes(RoutingId::LENGTH)?,
        )?)
    }

    /// Generates a high-entropy application-message identifier.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate_message_id(&self) -> Result<MessageId, KonclaveCryptographicError> {
        Ok(MessageId::from_slice(
            &self.generate_identifier_bytes(MessageId::LENGTH)?,
        )?)
    }

    /// Generates a high-entropy relay-envelope identifier.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate_envelope_id(&self) -> Result<EnvelopeId, KonclaveCryptographicError> {
        Ok(EnvelopeId::from_slice(
            &self.generate_identifier_bytes(EnvelopeId::LENGTH)?,
        )?)
    }

    /// Generates a high-entropy local notification identifier.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate_notification_id(&self) -> Result<NotificationId, KonclaveCryptographicError> {
        Ok(NotificationId::from_slice(
            &self.generate_identifier_bytes(NotificationId::LENGTH)?,
        )?)
    }

    fn generate_identifier_bytes(
        &self,
        length: usize,
    ) -> Result<Vec<u8>, KonclaveCryptographicError> {
        let cipher_suite = cipher_suite(&self.provider)?;
        random_bytes(&cipher_suite, length)
    }

    /// Seals this device-root identity for one bounded local profile identifier.
    ///
    /// # Errors
    ///
    /// Returns a typed storage error when context construction or authenticated
    /// encryption fails.
    pub fn seal(
        &self,
        sealer: &SecretSealer,
        profile_id: &[u8],
    ) -> Result<SealedBlob, KonclaveCryptographicError> {
        self.seal_encoded(sealer, profile_id, None)
    }

    /// Seals this device root with an authenticated minimum profile-schema version.
    ///
    /// # Errors
    ///
    /// Returns a typed storage error when context construction, framing, or
    /// authenticated encryption fails.
    pub fn seal_with_profile_schema_floor(
        &self,
        sealer: &SecretSealer,
        profile_id: &[u8],
        profile_schema_floor: u32,
    ) -> Result<SealedBlob, KonclaveCryptographicError> {
        self.seal_encoded(sealer, profile_id, Some(profile_schema_floor))
    }

    fn seal_encoded(
        &self,
        sealer: &SecretSealer,
        profile_id: &[u8],
        profile_schema_floor: Option<u32>,
    ) -> Result<SealedBlob, KonclaveCryptographicError> {
        let secret = self.secret_key.as_bytes();
        let length = u16::try_from(secret.len()).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity encoding",
            }
        })?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            DEVICE_IDENTITY_V2_MAGIC.len()
                + profile_schema_floor.map_or(0, |_| size_of::<u32>())
                + size_of::<u16>()
                + secret.len(),
        ));
        match profile_schema_floor {
            Some(profile_schema_floor) => {
                plaintext.extend_from_slice(DEVICE_IDENTITY_V2_MAGIC);
                plaintext.extend_from_slice(&profile_schema_floor.to_be_bytes());
            }
            None => plaintext.extend_from_slice(DEVICE_IDENTITY_V1_MAGIC),
        }
        plaintext.extend_from_slice(&length.to_be_bytes());
        plaintext.extend_from_slice(secret);
        let context = device_identity_context(profile_id)?;
        sealer.seal(&context, &plaintext).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity sealing",
            }
        })
    }

    /// Reopens one sealed device-root identity.
    ///
    /// # Errors
    ///
    /// Returns a typed error when authentication, framing, key derivation, or
    /// identifier reconstruction fails.
    pub fn open(
        sealer: &SecretSealer,
        profile_id: &[u8],
        blob: &SealedBlob,
    ) -> Result<Self, KonclaveCryptographicError> {
        Self::open_with_profile_schema_floor(sealer, profile_id, blob).map(|(identity, _)| identity)
    }

    /// Reopens a device root and its authenticated minimum profile-schema version.
    ///
    /// Legacy device identities return a floor of zero.
    ///
    /// # Errors
    ///
    /// Returns a typed error when authentication, framing, key derivation, or
    /// identifier reconstruction fails.
    pub fn open_with_profile_schema_floor(
        sealer: &SecretSealer,
        profile_id: &[u8],
        blob: &SealedBlob,
    ) -> Result<(Self, u32), KonclaveCryptographicError> {
        let context = device_identity_context(profile_id)?;
        let plaintext = sealer.open(&context, blob).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity opening",
            }
        })?;
        if plaintext.len() < DEVICE_IDENTITY_V1_MAGIC.len() + size_of::<u16>() {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity decoding",
            });
        }
        let (profile_schema_floor, length_offset) = if &plaintext[..4] == DEVICE_IDENTITY_V1_MAGIC {
            (0, 4)
        } else if &plaintext[..4] == DEVICE_IDENTITY_V2_MAGIC {
            if plaintext.len()
                < DEVICE_IDENTITY_V2_MAGIC.len() + size_of::<u32>() + size_of::<u16>()
            {
                return Err(KonclaveCryptographicError::SecretStorageFailure {
                    operation: "device identity decoding",
                });
            }
            (
                u32::from_be_bytes(plaintext[4..8].try_into().map_err(|_| {
                    KonclaveCryptographicError::SecretStorageFailure {
                        operation: "device identity decoding",
                    }
                })?),
                8,
            )
        } else {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity decoding",
            });
        };
        let secret_offset = length_offset + size_of::<u16>();
        let length =
            u16::from_be_bytes(plaintext[length_offset..secret_offset].try_into().map_err(
                |_| KonclaveCryptographicError::SecretStorageFailure {
                    operation: "device identity decoding",
                },
            )?) as usize;
        if plaintext.len() != secret_offset + length {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity decoding",
            });
        }
        let provider = configured_provider();
        let cipher_suite = cipher_suite(&provider)?;
        let secret_key = SignatureSecretKey::new(plaintext[secret_offset..].to_vec());
        let public_key = cipher_suite
            .signature_key_derive_public(&secret_key)
            .map_err(|_| provider_failure("device root public key derivation"))?;
        let public_key = Ed25519PublicKey::from_slice(public_key.as_bytes())?;
        let device_id = derive_device_id_with_suite(&cipher_suite, public_key)?;
        Ok((
            Self {
                provider,
                secret_key,
                public_key,
                device_id,
            },
            profile_schema_floor,
        ))
    }

    /// Generates and signs a distinct MLS signing identity for one conversation.
    ///
    /// # Errors
    ///
    /// Returns a provider or domain validation error when key generation or signing
    /// fails.
    pub fn create_conversation_signing_material(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationSigningMaterial, KonclaveCryptographicError> {
        let cipher_suite = cipher_suite(&self.provider)?;
        let (secret_key, public_key) = cipher_suite
            .signature_key_generate()
            .map_err(|_| provider_failure("conversation signature key generation"))?;
        let public_key = Ed25519PublicKey::from_slice(public_key.as_bytes())?;
        let canonical = canonical_credential_binding(
            ProtocolVersion::application_v1(),
            self.device_id,
            conversation_id,
            SignatureScheme::Ed25519,
            self.public_key,
            public_key,
        );
        let signature = cipher_suite
            .sign(&self.secret_key, &canonical)
            .map_err(|_| provider_failure("device credential binding signature"))?;
        let capability_canonical =
            canonical_credential_capabilities(&canonical, APPLICATION_CAPABILITY_DIRECTED_REQUEST);
        let capability_signature = cipher_suite
            .sign(&self.secret_key, &capability_canonical)
            .map_err(|_| provider_failure("device credential capability signature"))?;
        let binding = DeviceCredentialBinding::new_with_capabilities(
            ProtocolVersion::application_v1(),
            self.device_id,
            conversation_id,
            SignatureScheme::Ed25519,
            self.public_key,
            public_key,
            Ed25519Signature::from_slice(&signature)?,
            APPLICATION_CAPABILITY_DIRECTED_REQUEST,
            Some(Ed25519Signature::from_slice(&capability_signature)?),
        )?;
        Ok(ConversationSigningMaterial {
            secret_key,
            binding,
        })
    }

    /// Issues a signed, high-entropy invitation for one expected device.
    ///
    /// Cryptographic signing does not establish that this issuer is a conversation
    /// administrator; callers must enforce that application policy separately.
    ///
    /// # Errors
    ///
    /// Returns a validation or provider error when the expiry is invalid, randomness
    /// generation fails, or the invitation cannot be signed.
    pub fn issue_invitation(
        &self,
        conversation_id: ConversationId,
        routing_id: KonclaveDomainCore::RoutingId,
        expected_device_id: DeviceId,
        role: ConversationRole,
        expires_at_unix_seconds: u64,
    ) -> Result<Invitation, KonclaveCryptographicError> {
        let cipher_suite = cipher_suite(&self.provider)?;
        let invitation_id =
            InvitationId::from_slice(&random_bytes(&cipher_suite, InvitationId::LENGTH)?)?;
        let nonce =
            InvitationNonce::from_slice(&random_bytes(&cipher_suite, InvitationNonce::LENGTH)?)?;
        let canonical = canonical_invitation(
            ProtocolVersion::application_v1(),
            invitation_id,
            conversation_id,
            Some(routing_id),
            expected_device_id,
            role,
            expires_at_unix_seconds,
            &nonce,
            self.device_id,
        );
        let signature = cipher_suite
            .sign(&self.secret_key, &canonical)
            .map_err(|_| provider_failure("invitation signature"))?;
        Ok(Invitation::new(
            ProtocolVersion::application_v1(),
            invitation_id,
            conversation_id,
            Some(routing_id),
            expected_device_id,
            role,
            expires_at_unix_seconds,
            nonce,
            self.device_id,
            Ed25519Signature::from_slice(&signature)?,
        )?)
    }

    /// Signs a pairing offer this device is asking to be enrolled through.
    ///
    /// The offer carries this device's root public key, and verification re-derives
    /// the device identity from it, so a verifier that has never seen this device can
    /// still establish that the claimed identity follows from the signing key.
    ///
    /// # Errors
    ///
    /// Returns a validation or provider error when the expiry is invalid, randomness
    /// generation fails, or the offer cannot be signed.
    pub fn offer_pairing(
        &self,
        pairing_id: KonclaveDomainCore::PairingId,
        requested_role: ConversationRole,
        expires_at_unix_seconds: u64,
        context_hash: PairingContextHash,
    ) -> Result<PairingOffer, KonclaveCryptographicError> {
        let cipher_suite = cipher_suite(&self.provider)?;
        let canonical = canonical_pairing_offer(
            ProtocolVersion::application_v1(),
            pairing_id,
            self.device_id,
            self.public_key,
            requested_role,
            expires_at_unix_seconds,
            context_hash,
        );
        let signature = cipher_suite
            .sign(&self.secret_key, &canonical)
            .map_err(|_| provider_failure("pairing offer signature"))?;
        Ok(PairingOffer::new(
            ProtocolVersion::application_v1(),
            pairing_id,
            self.device_id,
            self.public_key,
            requested_role,
            expires_at_unix_seconds,
            context_hash,
            Ed25519Signature::from_slice(&signature)?,
        )?)
    }

    /// Signs one pairing completion or cancellation control.
    ///
    /// # Errors
    ///
    /// Returns a domain or provider error for an invalid stage or rejected signature.
    pub fn sign_pairing_control(
        &self,
        pairing_id: PairingId,
        message_id: PairingMessageId,
        stage: PairingStage,
        in_reply_to: PairingMessageId,
        conversation_id: ConversationId,
    ) -> Result<PairingControl, KonclaveCryptographicError> {
        let canonical = canonical_pairing_control(
            ProtocolVersion::application_v1(),
            pairing_id,
            message_id,
            stage,
            in_reply_to,
            self.device_id,
            conversation_id,
        )?;
        let cipher_suite = cipher_suite(&self.provider)?;
        let signature = cipher_suite
            .sign(&self.secret_key, &canonical)
            .map_err(|_| provider_failure("pairing control signature"))?;
        Ok(PairingControl::new(
            ProtocolVersion::application_v1(),
            pairing_id,
            message_id,
            stage,
            in_reply_to,
            self.device_id,
            conversation_id,
            Ed25519Signature::from_slice(&signature)?,
        )?)
    }

    /// Verifies that an invitation is authentic, unexpired, and intended for this
    /// device.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error when any check fails.
    pub fn verify_invitation(
        &self,
        invitation: &Invitation,
        issuer_public_key: Ed25519PublicKey,
        now_unix_seconds: u64,
    ) -> Result<(), KonclaveCryptographicError> {
        verify_invitation(invitation, issuer_public_key, now_unix_seconds)?;
        if invitation.expected_device_id() != self.device_id {
            return Err(KonclaveCryptographicError::InvitationDeviceMismatch);
        }
        Ok(())
    }
}

/// Conversation-scoped MLS signing key plus its device-root credential binding.
pub struct ConversationSigningMaterial {
    secret_key: SignatureSecretKey,
    binding: DeviceCredentialBinding,
}

impl ConversationSigningMaterial {
    /// Returns the public credential binding for distribution to conversation peers.
    #[must_use]
    pub const fn binding(&self) -> &DeviceCredentialBinding {
        &self.binding
    }

    /// Seals the signing key and authenticated public binding for one local profile.
    ///
    /// # Errors
    ///
    /// Returns a typed storage or protocol error when framing, context construction,
    /// or authenticated sealing fails.
    pub fn seal(
        &self,
        sealer: &SecretSealer,
        profile_id: &[u8],
    ) -> Result<SealedBlob, KonclaveCryptographicError> {
        let secret = self.secret_key.as_bytes();
        let secret_length = u16::try_from(secret.len()).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material encoding",
            }
        })?;
        let binding = encode_device_credential_binding(&self.binding)
            .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
        let binding_length = u32::try_from(binding.len()).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material encoding",
            }
        })?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            CONVERSATION_SIGNING_MAGIC.len() + 2 + secret.len() + 4 + binding.len(),
        ));
        plaintext.extend_from_slice(CONVERSATION_SIGNING_MAGIC);
        plaintext.extend_from_slice(&secret_length.to_be_bytes());
        plaintext.extend_from_slice(secret);
        plaintext.extend_from_slice(&binding_length.to_be_bytes());
        plaintext.extend_from_slice(&binding);
        let context =
            Self::conversation_signing_context(profile_id, self.binding.conversation_id())?;
        sealer.seal(&context, &plaintext).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material sealing",
            }
        })
    }

    /// Reopens one sealed conversation signing key and verifies its public binding.
    ///
    /// # Errors
    ///
    /// Returns a typed error when framing, authentication, credential verification,
    /// or signing-key reconstruction fails.
    pub fn open(
        sealer: &SecretSealer,
        profile_id: &[u8],
        conversation_id: ConversationId,
        blob: &SealedBlob,
    ) -> Result<Self, KonclaveCryptographicError> {
        let context = Self::conversation_signing_context(profile_id, conversation_id)?;
        let plaintext = sealer.open(&context, blob).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material opening",
            }
        })?;
        if plaintext.len() < CONVERSATION_SIGNING_MAGIC.len() + 2 + 4
            || &plaintext[..4] != CONVERSATION_SIGNING_MAGIC
        {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            });
        }
        let secret_length = usize::from(u16::from_be_bytes(plaintext[4..6].try_into().map_err(
            |_| KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            },
        )?));
        let binding_length_offset = 6_usize.checked_add(secret_length).ok_or(
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            },
        )?;
        let binding_offset = binding_length_offset.checked_add(4).ok_or(
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            },
        )?;
        if plaintext.len() < binding_offset {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            });
        }
        let binding_length = usize::try_from(u32::from_be_bytes(
            plaintext[binding_length_offset..binding_offset]
                .try_into()
                .map_err(|_| KonclaveCryptographicError::SecretStorageFailure {
                    operation: "conversation signing material decoding",
                })?,
        ))
        .map_err(|_| KonclaveCryptographicError::SecretStorageFailure {
            operation: "conversation signing material decoding",
        })?;
        let expected_length = binding_offset.checked_add(binding_length).ok_or(
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            },
        )?;
        if plaintext.len() != expected_length {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing material decoding",
            });
        }
        let binding = decode_device_credential_binding(&plaintext[binding_offset..])
            .map_err(|_| KonclaveCryptographicError::ProtocolContractFailure)?;
        if binding.conversation_id() != conversation_id {
            return Err(KonclaveCryptographicError::MlsConversationMismatch);
        }
        verify_device_credential_binding(&binding)?;
        let secret_key = SignatureSecretKey::new(plaintext[6..binding_length_offset].to_vec());
        let provider = configured_provider();
        let cipher_suite = cipher_suite(&provider)?;
        let public_key = cipher_suite
            .signature_key_derive_public(&secret_key)
            .map_err(|_| provider_failure("conversation signing public key derivation"))?;
        if public_key.as_bytes() != binding.conversation_signature_public_key().as_bytes() {
            return Err(KonclaveCryptographicError::CredentialSigningKeyMismatch);
        }
        Ok(Self {
            secret_key,
            binding,
        })
    }

    pub(crate) fn into_parts(self) -> (SignatureSecretKey, DeviceCredentialBinding) {
        (self.secret_key, self.binding)
    }

    fn conversation_signing_context(
        profile_id: &[u8],
        conversation_id: ConversationId,
    ) -> Result<SecretRecordContext, KonclaveCryptographicError> {
        if profile_id.is_empty() {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing context",
            });
        }
        let profile_length = u8::try_from(profile_id.len()).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing context",
            }
        })?;
        let mut identifier = Vec::with_capacity(1 + profile_id.len() + ConversationId::LENGTH);
        identifier.push(profile_length);
        identifier.extend_from_slice(profile_id);
        identifier.extend_from_slice(conversation_id.as_bytes());
        SecretRecordContext::new(SecretRecordKind::ConversationSigningMaterial, identifier).map_err(
            |_| KonclaveCryptographicError::SecretStorageFailure {
                operation: "conversation signing context",
            },
        )
    }
}

/// Public credential binding proven authentic under its included device root.
pub struct VerifiedDeviceCredentialBinding {
    binding: DeviceCredentialBinding,
    hash: CredentialBindingHash,
}

impl VerifiedDeviceCredentialBinding {
    /// Returns the verified public binding.
    #[must_use]
    pub const fn binding(&self) -> &DeviceCredentialBinding {
        &self.binding
    }

    /// Returns the digest used by membership authorization contracts.
    #[must_use]
    pub const fn hash(&self) -> CredentialBindingHash {
        self.hash
    }

    pub(crate) fn into_binding(self) -> DeviceCredentialBinding {
        self.binding
    }
}

/// Verifies a device-root signature and all self-authenticating binding fields.
///
/// # Errors
///
/// Returns [`KonclaveCryptographicError::InvalidCredentialBinding`] when the
/// device identifier or signature is invalid.
pub fn verify_device_credential_binding(
    binding: &DeviceCredentialBinding,
) -> Result<VerifiedDeviceCredentialBinding, KonclaveCryptographicError> {
    if binding.version() != ProtocolVersion::application_v1() {
        return Err(KonclaveCryptographicError::InvalidCredentialBinding);
    }
    let provider = configured_provider();
    let cipher_suite = cipher_suite(&provider)?;
    let derived_device_id =
        derive_device_id_with_suite(&cipher_suite, binding.device_root_public_key())?;
    if derived_device_id != binding.device_id() {
        return Err(KonclaveCryptographicError::InvalidCredentialBinding);
    }
    let canonical = canonical_credential_binding(
        binding.version(),
        binding.device_id(),
        binding.conversation_id(),
        binding.signature_scheme(),
        binding.device_root_public_key(),
        binding.conversation_signature_public_key(),
    );
    let public_key = SignaturePublicKey::new_slice(binding.device_root_public_key().as_bytes());
    cipher_suite
        .verify(
            &public_key,
            binding.device_binding_signature().as_bytes(),
            &canonical,
        )
        .map_err(|_| KonclaveCryptographicError::InvalidCredentialBinding)?;
    match (
        binding.application_capabilities(),
        binding.application_capabilities_signature(),
    ) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => {
            return Err(KonclaveCryptographicError::InvalidCredentialBinding);
        }
        (capabilities, Some(signature)) => {
            let capability_canonical = canonical_credential_capabilities(&canonical, capabilities);
            cipher_suite
                .verify(&public_key, signature.as_bytes(), &capability_canonical)
                .map_err(|_| KonclaveCryptographicError::InvalidCredentialBinding)?;
        }
    }
    let hash = credential_binding_hash_with_suite(&cipher_suite, binding)?;
    Ok(VerifiedDeviceCredentialBinding {
        binding: binding.clone(),
        hash,
    })
}

/// Verifies an invitation issuer, signature, and expiration time.
///
/// This function does not establish administrator authorization or enforce
/// single-use consumption.
///
/// # Errors
///
/// Returns a typed validation error when the issuer, signature, or expiry is invalid.
pub fn verify_invitation(
    invitation: &Invitation,
    issuer_public_key: Ed25519PublicKey,
    now_unix_seconds: u64,
) -> Result<(), KonclaveCryptographicError> {
    if invitation.version() != ProtocolVersion::application_v1() {
        return Err(KonclaveCryptographicError::InvalidInvitationSignature);
    }
    let provider = configured_provider();
    let cipher_suite = cipher_suite(&provider)?;
    let issuer_device_id = derive_device_id_with_suite(&cipher_suite, issuer_public_key)?;
    if issuer_device_id != invitation.issuer_device_id() {
        return Err(KonclaveCryptographicError::InvalidInvitationSignature);
    }
    if invitation.expires_at_unix_seconds() <= now_unix_seconds {
        return Err(KonclaveCryptographicError::ExpiredInvitation);
    }
    let canonical = canonical_invitation(
        invitation.version(),
        invitation.invitation_id(),
        invitation.conversation_id(),
        invitation.routing_id(),
        invitation.expected_device_id(),
        invitation.role(),
        invitation.expires_at_unix_seconds(),
        invitation.nonce(),
        invitation.issuer_device_id(),
    );
    let public_key = SignaturePublicKey::new_slice(issuer_public_key.as_bytes());
    cipher_suite
        .verify(
            &public_key,
            invitation.issuer_signature().as_bytes(),
            &canonical,
        )
        .map_err(|_| KonclaveCryptographicError::InvalidInvitationSignature)
}

/// Verifies a pairing offer without any prior knowledge of the offering device.
///
/// The claimed device identity is re-derived from the offer's own public key, so an
/// offer that names one device while being signed by another is rejected rather than
/// being accepted as whatever it says it is. That, plus the expiry, is the whole
/// authenticity claim an offer makes; it says nothing about who the device belongs to.
///
/// # Errors
///
/// Returns a typed validation error when the version, claimed identity, expiry, or
/// signature does not hold.
pub fn verify_pairing_offer(
    offer: &PairingOffer,
    now_unix_seconds: u64,
) -> Result<(), KonclaveCryptographicError> {
    if offer.version() != ProtocolVersion::application_v1() {
        return Err(KonclaveCryptographicError::InvalidInvitationSignature);
    }

    let provider = configured_provider();
    let cipher_suite = cipher_suite(&provider)?;
    let derived = derive_device_id_with_suite(&cipher_suite, offer.device_root_public_key())?;
    if derived != offer.device_id() {
        return Err(KonclaveCryptographicError::InvalidInvitationSignature);
    }
    if offer.expires_at_unix_seconds() <= now_unix_seconds {
        return Err(KonclaveCryptographicError::ExpiredInvitation);
    }
    let canonical = canonical_pairing_offer(
        offer.version(),
        offer.pairing_id(),
        offer.device_id(),
        offer.device_root_public_key(),
        offer.requested_role(),
        offer.expires_at_unix_seconds(),
        offer.context_hash(),
    );
    let public_key = SignaturePublicKey::new_slice(offer.device_root_public_key().as_bytes());
    cipher_suite
        .verify(&public_key, offer.device_signature().as_bytes(), &canonical)
        .map_err(|_| KonclaveCryptographicError::InvalidInvitationSignature)
}

/// Verifies a pairing completion or cancellation against an expected device root.
///
/// # Errors
///
/// Returns a typed failure for a wrong version, device, stage, key, or signature.
pub fn verify_pairing_control(
    control: &PairingControl,
    expected_public_key: Ed25519PublicKey,
) -> Result<(), KonclaveCryptographicError> {
    if control.version() != ProtocolVersion::application_v1() {
        return Err(KonclaveCryptographicError::InvalidPairingControl);
    }
    let provider = configured_provider();
    let cipher_suite = cipher_suite(&provider)?;
    let derived = derive_device_id_with_suite(&cipher_suite, expected_public_key)?;
    if derived != control.device_id() {
        return Err(KonclaveCryptographicError::InvalidPairingControl);
    }
    let canonical = canonical_pairing_control(
        control.version(),
        control.pairing_id(),
        control.message_id(),
        control.stage(),
        control.in_reply_to(),
        control.device_id(),
        control.conversation_id(),
    )?;
    cipher_suite
        .verify(
            &SignaturePublicKey::new_slice(expected_public_key.as_bytes()),
            control.device_signature().as_bytes(),
            &canonical,
        )
        .map_err(|_| KonclaveCryptographicError::InvalidPairingControl)
}

pub(crate) fn configured_provider() -> AwsLcCryptoProvider {
    AwsLcCryptoProvider::with_enabled_cipher_suites(vec![CIPHER_SUITE])
}

pub(crate) fn cipher_suite(
    provider: &AwsLcCryptoProvider,
) -> Result<AwsLcCipherSuite, KonclaveCryptographicError> {
    provider
        .cipher_suite_provider(CIPHER_SUITE)
        .ok_or_else(|| provider_failure("cipher suite selection"))
}

pub(crate) fn credential_binding_hash(
    binding: &DeviceCredentialBinding,
) -> Result<CredentialBindingHash, KonclaveCryptographicError> {
    let provider = configured_provider();
    let cipher_suite = cipher_suite(&provider)?;
    credential_binding_hash_with_suite(&cipher_suite, binding)
}

fn credential_binding_hash_with_suite(
    cipher_suite: &AwsLcCipherSuite,
    binding: &DeviceCredentialBinding,
) -> Result<CredentialBindingHash, KonclaveCryptographicError> {
    let canonical = canonical_credential_binding(
        binding.version(),
        binding.device_id(),
        binding.conversation_id(),
        binding.signature_scheme(),
        binding.device_root_public_key(),
        binding.conversation_signature_public_key(),
    );
    let mut input = Vec::with_capacity(
        CREDENTIAL_HASH_DOMAIN.len() + canonical.len() + Ed25519Signature::LENGTH,
    );
    input.extend_from_slice(CREDENTIAL_HASH_DOMAIN);
    input.extend_from_slice(&canonical);
    input.extend_from_slice(binding.device_binding_signature().as_bytes());
    let digest = cipher_suite
        .hash(&input)
        .map_err(|_| provider_failure("credential binding hash"))?;
    Ok(CredentialBindingHash::from_slice(&digest)?)
}

fn derive_device_id_with_suite(
    cipher_suite: &AwsLcCipherSuite,
    public_key: Ed25519PublicKey,
) -> Result<DeviceId, KonclaveCryptographicError> {
    let mut canonical = Vec::with_capacity(DEVICE_ID_DOMAIN.len() + Ed25519PublicKey::LENGTH);
    canonical.extend_from_slice(DEVICE_ID_DOMAIN);
    canonical.extend_from_slice(public_key.as_bytes());
    let digest = cipher_suite
        .hash(&canonical)
        .map_err(|_| provider_failure("device identifier derivation"))?;
    Ok(DeviceId::from_slice(&digest)?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the canonical signed credential fields remain explicit"
)]
fn canonical_credential_binding(
    version: ProtocolVersion,
    device_id: DeviceId,
    conversation_id: ConversationId,
    signature_scheme: SignatureScheme,
    device_root_public_key: Ed25519PublicKey,
    conversation_signature_public_key: Ed25519PublicKey,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(CREDENTIAL_DOMAIN);
    append_version(&mut output, version);
    output.extend_from_slice(device_id.as_bytes());
    output.extend_from_slice(conversation_id.as_bytes());
    output.push(signature_scheme_code(signature_scheme));
    output.extend_from_slice(device_root_public_key.as_bytes());
    output.extend_from_slice(conversation_signature_public_key.as_bytes());
    output
}

fn canonical_credential_capabilities(
    credential_canonical: &[u8],
    application_capabilities: u64,
) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(CREDENTIAL_CAPABILITY_DOMAIN.len() + credential_canonical.len() + 8);
    output.extend_from_slice(CREDENTIAL_CAPABILITY_DOMAIN);
    output.extend_from_slice(credential_canonical);
    output.extend_from_slice(&application_capabilities.to_be_bytes());
    output
}

#[allow(
    clippy::too_many_arguments,
    reason = "the canonical signed invitation fields remain explicit"
)]
fn canonical_invitation(
    version: ProtocolVersion,
    invitation_id: InvitationId,
    conversation_id: ConversationId,
    routing_id: Option<KonclaveDomainCore::RoutingId>,
    expected_device_id: DeviceId,
    role: ConversationRole,
    expires_at_unix_seconds: u64,
    nonce: &InvitationNonce,
    issuer_device_id: DeviceId,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(192);
    output.extend_from_slice(INVITATION_DOMAIN);
    append_version(&mut output, version);
    output.extend_from_slice(invitation_id.as_bytes());
    output.extend_from_slice(conversation_id.as_bytes());
    if let Some(routing_id) = routing_id {
        output.extend_from_slice(routing_id.as_bytes());
    }
    output.extend_from_slice(expected_device_id.as_bytes());
    output.push(role_code(role));
    output.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    output.extend_from_slice(nonce.as_bytes());
    output.extend_from_slice(issuer_device_id.as_bytes());
    output
}

fn canonical_pairing_offer(
    version: ProtocolVersion,
    pairing_id: KonclaveDomainCore::PairingId,
    device_id: DeviceId,
    device_root_public_key: Ed25519PublicKey,
    requested_role: ConversationRole,
    expires_at_unix_seconds: u64,
    context_hash: PairingContextHash,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(PAIRING_OFFER_DOMAIN);
    append_version(&mut output, version);
    output.extend_from_slice(pairing_id.as_bytes());
    output.extend_from_slice(device_id.as_bytes());
    output.extend_from_slice(device_root_public_key.as_bytes());
    output.push(role_code(requested_role));
    output.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    output.extend_from_slice(context_hash.as_bytes());
    output
}

fn canonical_pairing_control(
    version: ProtocolVersion,
    pairing_id: PairingId,
    message_id: PairingMessageId,
    stage: PairingStage,
    in_reply_to: PairingMessageId,
    device_id: DeviceId,
    conversation_id: ConversationId,
) -> Result<Vec<u8>, KonclaveCryptographicError> {
    let stage = match stage {
        PairingStage::Completion => 1,
        PairingStage::Cancellation => 2,
        _ => {
            return Err(
                KonclaveDomainCore::KonclaveDomainError::InvalidPairingEnvelope {
                    field: "control_stage",
                }
                .into(),
            );
        }
    };
    let mut output = Vec::with_capacity(160);
    output.extend_from_slice(PAIRING_CONTROL_DOMAIN);
    append_version(&mut output, version);
    output.extend_from_slice(pairing_id.as_bytes());
    output.extend_from_slice(message_id.as_bytes());
    output.push(stage);
    output.extend_from_slice(in_reply_to.as_bytes());
    output.extend_from_slice(device_id.as_bytes());
    output.extend_from_slice(conversation_id.as_bytes());
    Ok(output)
}

fn append_version(output: &mut Vec<u8>, version: ProtocolVersion) {
    output.extend_from_slice(&version.major().to_be_bytes());
    output.extend_from_slice(&version.minor().to_be_bytes());
}

const fn signature_scheme_code(value: SignatureScheme) -> u8 {
    match value {
        SignatureScheme::Ed25519 => 1,
    }
}

const fn role_code(value: ConversationRole) -> u8 {
    match value {
        ConversationRole::Administrator => 1,
        ConversationRole::Member => 2,
    }
}

fn random_bytes(
    cipher_suite: &AwsLcCipherSuite,
    length: usize,
) -> Result<Vec<u8>, KonclaveCryptographicError> {
    cipher_suite
        .random_bytes_vec(length)
        .map_err(|_| provider_failure("random byte generation"))
}

fn device_identity_context(
    profile_id: &[u8],
) -> Result<SecretRecordContext, KonclaveCryptographicError> {
    SecretRecordContext::new(SecretRecordKind::DeviceRootIdentity, profile_id.to_vec()).map_err(
        |_| KonclaveCryptographicError::SecretStorageFailure {
            operation: "device identity context",
        },
    )
}

const fn provider_failure(operation: &'static str) -> KonclaveCryptographicError {
    KonclaveCryptographicError::ProviderFailure { operation }
}

#[cfg(test)]
mod tests {
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;

    // RFC 8032 test vector 1 supplies an independently published Ed25519 key pair.
    const ROOT_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ROOT_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const DEVICE_ID: &str = "b2d3febedf65e69979aa2c0c2ea47870a760ee3030613382eb6b775f2a0c0e93";
    const CREDENTIAL_SIGNATURE: &str = "e94d639344a2af53f8b155c6871d4528397df8a4b4aa1e83c46464f68c494d30e566a4c47e1fa18757eb8587026494d9f76b870ac387654b0ca1ad3550beb401";
    const CAPABILITY_SIGNATURE: &str = "3a78fe1936f628c6e470e20a9ad4c612aba4ef43348ced62d33b448d294e23a6bd7811e1bf35d3a77694976da0c66aa71d300e50a21cf8373b867ce6fb660603";
    const CREDENTIAL_HASH: &str =
        "ee10d5432136d42fc389d49eb1c2c70cca03da8ccdfbf58d687eb34f81a28a47";
    const INVITATION_SIGNATURE: &str = "312b28a1b5d395e56e1f251a8e2f1f2d6d55eb8d68ca795ebbe98ba8669188d5a7430d1804a00c5a98474c0c3433df074b8737d0b9513be858dc3225aad76c07";

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([9; 32])).unwrap()
    }

    #[test]
    fn conversation_signing_material_reopens_only_in_its_bound_context() {
        let identity = DeviceIdentity::generate().unwrap();
        let conversation_id = ConversationId::from_bytes([0x71; ConversationId::LENGTH]);
        let material = identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let binding = material.binding().clone();
        let encoded_binding = encode_device_credential_binding(&binding).unwrap();
        assert!(material.seal(&sealer(), b"").is_err());
        let blob = material.seal(&sealer(), b"profile-a").unwrap();
        assert!(
            !blob
                .as_bytes()
                .windows(encoded_binding.len())
                .any(|window| window == encoded_binding)
        );

        let reopened =
            ConversationSigningMaterial::open(&sealer(), b"profile-a", conversation_id, &blob)
                .unwrap();
        assert_eq!(reopened.binding(), &binding);
        assert!(
            ConversationSigningMaterial::open(
                &sealer(),
                b"profile-a",
                ConversationId::from_bytes([0x72; ConversationId::LENGTH]),
                &blob,
            )
            .is_err()
        );
    }

    #[test]
    fn directed_request_capability_is_root_signed() {
        let identity = DeviceIdentity::generate().unwrap();
        let material = identity
            .create_conversation_signing_material(ConversationId::from_bytes([0x73; 32]))
            .unwrap();
        let binding = material.binding();
        assert!(binding.supports_directed_requests());
        verify_device_credential_binding(binding).unwrap();

        let stripped = DeviceCredentialBinding::new(
            binding.version(),
            binding.device_id(),
            binding.conversation_id(),
            binding.signature_scheme(),
            binding.device_root_public_key(),
            binding.conversation_signature_public_key(),
            binding.device_binding_signature(),
        );
        assert!(!stripped.supports_directed_requests());
        verify_device_credential_binding(&stripped).unwrap();

        let altered = DeviceCredentialBinding::new_with_capabilities(
            binding.version(),
            binding.device_id(),
            binding.conversation_id(),
            binding.signature_scheme(),
            binding.device_root_public_key(),
            binding.conversation_signature_public_key(),
            binding.device_binding_signature(),
            binding.application_capabilities() | 2,
            binding.application_capabilities_signature(),
        )
        .unwrap();
        assert_eq!(
            verify_device_credential_binding(&altered).err(),
            Some(KonclaveCryptographicError::InvalidCredentialBinding)
        );
    }

    #[test]
    fn provider_generates_every_public_identifier_shape() {
        let identity = DeviceIdentity::generate().unwrap();

        assert_eq!(
            identity
                .generate_conversation_id()
                .unwrap()
                .as_bytes()
                .len(),
            ConversationId::LENGTH
        );
        assert_eq!(
            identity.generate_routing_id().unwrap().as_bytes().len(),
            RoutingId::LENGTH
        );
        assert_eq!(
            identity.generate_message_id().unwrap().as_bytes().len(),
            MessageId::LENGTH
        );
        assert_eq!(
            identity.generate_envelope_id().unwrap().as_bytes().len(),
            EnvelopeId::LENGTH
        );
        assert_eq!(
            identity
                .generate_notification_id()
                .unwrap()
                .as_bytes()
                .len(),
            NotificationId::LENGTH
        );
    }

    #[test]
    fn device_identity_profile_schema_floor_is_authenticated_and_backward_compatible() {
        let identity = DeviceIdentity::generate().unwrap();
        let legacy = identity.seal(&sealer(), b"profile-a").unwrap();
        let (legacy_reopened, legacy_floor) =
            DeviceIdentity::open_with_profile_schema_floor(&sealer(), b"profile-a", &legacy)
                .unwrap();
        assert_eq!(legacy_reopened.device_id(), identity.device_id());
        assert_eq!(legacy_floor, 0);

        let current = identity
            .seal_with_profile_schema_floor(&sealer(), b"profile-a", 17)
            .unwrap();
        let (current_reopened, current_floor) =
            DeviceIdentity::open_with_profile_schema_floor(&sealer(), b"profile-a", &current)
                .unwrap();
        assert_eq!(current_reopened.device_id(), identity.device_id());
        assert_eq!(current_floor, 17);
        assert!(
            DeviceIdentity::open_with_profile_schema_floor(&sealer(), b"profile-b", &current)
                .is_err()
        );
    }

    #[test]
    fn identity_signature_vectors_are_stable() {
        let cipher_suite = cipher_suite(&configured_provider()).unwrap();
        let public_key = Ed25519PublicKey::from_slice(&decode_hex(ROOT_PUBLIC)).unwrap();
        let mut secret_bytes = decode_hex(ROOT_SEED);
        secret_bytes.extend_from_slice(public_key.as_bytes());
        let secret_key = SignatureSecretKey::new(secret_bytes);
        let device_id = derive_device_id_with_suite(&cipher_suite, public_key).unwrap();
        assert_eq!(device_id.as_bytes(), decode_hex(DEVICE_ID).as_slice());

        let conversation_id = ConversationId::from_bytes([0x11; ConversationId::LENGTH]);
        let conversation_key = Ed25519PublicKey::from_bytes([0x22; Ed25519PublicKey::LENGTH]);
        let credential_input = canonical_credential_binding(
            ProtocolVersion::application_v1(),
            device_id,
            conversation_id,
            SignatureScheme::Ed25519,
            public_key,
            conversation_key,
        );
        let credential_signature = cipher_suite.sign(&secret_key, &credential_input).unwrap();
        assert_eq!(credential_signature, decode_hex(CREDENTIAL_SIGNATURE));
        let capability_signature = cipher_suite
            .sign(
                &secret_key,
                &canonical_credential_capabilities(
                    &credential_input,
                    APPLICATION_CAPABILITY_DIRECTED_REQUEST,
                ),
            )
            .unwrap();
        assert_eq!(capability_signature, decode_hex(CAPABILITY_SIGNATURE));
        let binding = DeviceCredentialBinding::new(
            ProtocolVersion::application_v1(),
            device_id,
            conversation_id,
            SignatureScheme::Ed25519,
            public_key,
            conversation_key,
            Ed25519Signature::from_slice(&credential_signature).unwrap(),
        );
        assert_eq!(
            credential_binding_hash_with_suite(&cipher_suite, &binding)
                .unwrap()
                .as_bytes(),
            decode_hex(CREDENTIAL_HASH).as_slice()
        );

        let invitation_id = InvitationId::from_bytes([0x33; InvitationId::LENGTH]);
        let routing_id = RoutingId::from_bytes([0x66; RoutingId::LENGTH]);
        let expected_device_id = DeviceId::from_bytes([0x44; DeviceId::LENGTH]);
        let nonce = InvitationNonce::from_bytes([0x55; InvitationNonce::LENGTH]);
        let invitation_input = canonical_invitation(
            ProtocolVersion::application_v1(),
            invitation_id,
            conversation_id,
            Some(routing_id),
            expected_device_id,
            ConversationRole::Member,
            1_800_000_000,
            &nonce,
            device_id,
        );
        assert_eq!(
            cipher_suite.sign(&secret_key, &invitation_input).unwrap(),
            decode_hex(INVITATION_SIGNATURE)
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
