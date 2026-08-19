use KonclaveDomainCore::{
    ConversationId, ConversationRole, CredentialBindingHash, DeviceCredentialBinding, DeviceId,
    Ed25519PublicKey, Ed25519Signature, Invitation, InvitationId, InvitationNonce, ProtocolVersion,
    SignatureScheme,
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
const CREDENTIAL_HASH_DOMAIN: &[u8] = b"konclave-device-credential-binding-hash-v1\0";
const INVITATION_DOMAIN: &[u8] = b"konclave-invitation-v1\0";
const DEVICE_IDENTITY_MAGIC: &[u8; 4] = b"KDI1";

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
        let cipher_suite = cipher_suite(&self.provider)?;
        Ok(ConversationId::from_slice(&random_bytes(
            &cipher_suite,
            ConversationId::LENGTH,
        )?)?)
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
        let secret = self.secret_key.as_bytes();
        let length = u16::try_from(secret.len()).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity encoding",
            }
        })?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            DEVICE_IDENTITY_MAGIC.len() + 2 + secret.len(),
        ));
        plaintext.extend_from_slice(DEVICE_IDENTITY_MAGIC);
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
        let context = device_identity_context(profile_id)?;
        let plaintext = sealer.open(&context, blob).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity opening",
            }
        })?;
        if plaintext.len() < DEVICE_IDENTITY_MAGIC.len() + 2
            || &plaintext[..4] != DEVICE_IDENTITY_MAGIC
        {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity decoding",
            });
        }
        let length = u16::from_be_bytes(plaintext[4..6].try_into().map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity decoding",
            }
        })?) as usize;
        if plaintext.len() != 6 + length {
            return Err(KonclaveCryptographicError::SecretStorageFailure {
                operation: "device identity decoding",
            });
        }
        let provider = configured_provider();
        let cipher_suite = cipher_suite(&provider)?;
        let secret_key = SignatureSecretKey::new(plaintext[6..].to_vec());
        let public_key = cipher_suite
            .signature_key_derive_public(&secret_key)
            .map_err(|_| provider_failure("device root public key derivation"))?;
        let public_key = Ed25519PublicKey::from_slice(public_key.as_bytes())?;
        let device_id = derive_device_id_with_suite(&cipher_suite, public_key)?;
        Ok(Self {
            provider,
            secret_key,
            public_key,
            device_id,
        })
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
        let binding = DeviceCredentialBinding::new(
            ProtocolVersion::application_v1(),
            self.device_id,
            conversation_id,
            SignatureScheme::Ed25519,
            self.public_key,
            public_key,
            Ed25519Signature::from_slice(&signature)?,
        );
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
            expected_device_id,
            role,
            expires_at_unix_seconds,
            nonce,
            self.device_id,
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

    pub(crate) fn into_parts(self) -> (SignatureSecretKey, DeviceCredentialBinding) {
        (self.secret_key, self.binding)
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

#[allow(
    clippy::too_many_arguments,
    reason = "the canonical signed invitation fields remain explicit"
)]
fn canonical_invitation(
    version: ProtocolVersion,
    invitation_id: InvitationId,
    conversation_id: ConversationId,
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
    output.extend_from_slice(expected_device_id.as_bytes());
    output.push(role_code(role));
    output.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    output.extend_from_slice(nonce.as_bytes());
    output.extend_from_slice(issuer_device_id.as_bytes());
    output
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
    use super::*;

    // RFC 8032 test vector 1 supplies an independently published Ed25519 key pair.
    const ROOT_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ROOT_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const DEVICE_ID: &str = "b2d3febedf65e69979aa2c0c2ea47870a760ee3030613382eb6b775f2a0c0e93";
    const CREDENTIAL_SIGNATURE: &str = "e94d639344a2af53f8b155c6871d4528397df8a4b4aa1e83c46464f68c494d30e566a4c47e1fa18757eb8587026494d9f76b870ac387654b0ca1ad3550beb401";
    const CREDENTIAL_HASH: &str =
        "ee10d5432136d42fc389d49eb1c2c70cca03da8ccdfbf58d687eb34f81a28a47";
    const INVITATION_SIGNATURE: &str = "c5a72e285813c1ed9c98f3f5dac6bec25945307be8b212806240cddeadc6bebf374d2087550a4954d18351cd9da7e2d00829dffc4e98c84e2fda030340f6d700";

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
        let expected_device_id = DeviceId::from_bytes([0x44; DeviceId::LENGTH]);
        let nonce = InvitationNonce::from_bytes([0x55; InvitationNonce::LENGTH]);
        let invitation_input = canonical_invitation(
            ProtocolVersion::application_v1(),
            invitation_id,
            conversation_id,
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
