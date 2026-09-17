use std::io::Write;

use aws_lc_rs::hkdf::{self, KeyType};
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use KonclaveDomainCore::{
    DeviceId, ProtocolVersion, ShortCodePairingAttemptId, ShortCodePairingLocator,
    ShortCodePairingSas, ShortCodePairingTranscriptHash,
};
use KonclaveSecretStorage::{
    AUTHENTICATED_CIPHER_KEY_BYTES, AuthenticatedCipher, AuthenticatedCiphertext,
    SecretStorageError,
};

use crate::{KonclaveCryptographicError, fill_random};

const CODE_DIGITS: usize = 6;
const CODE_SPACE: u32 = 1_000_000;
const CODE_REJECTION_LIMIT: u32 =
    ((u32::MAX as u64 + 1) - ((u32::MAX as u64 + 1) % CODE_SPACE as u64)) as u32;
const STATE_VERSION: u8 = 1;
const MAX_OPAQUE_STATE_BYTES: usize = 16 * 1024;
const MAX_OPAQUE_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_TRANSCRIPT_MESSAGES: usize = 8;
const MAX_TRANSCRIPT_BYTES: usize = 32 * 1024;
const OPAQUE_CREDENTIAL_DOMAIN: &[u8] = b"konclave-short-code-opaque-credential-v1\0";
const OPAQUE_CLIENT_ID_DOMAIN: &[u8] = b"konclave-short-code-opaque-client-v1\0";
const OPAQUE_SERVER_ID_DOMAIN: &[u8] = b"konclave-short-code-opaque-server-v1\0";
const OPAQUE_CONTEXT_DOMAIN: &[u8] = b"konclave-short-code-opaque-context-v1\0";
const LOCATOR_DOMAIN: &[u8] = b"konclave-short-code-locator-v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"konclave-short-code-transcript-v1\0";
const SAS_SALT: &[u8] = b"konclave-short-code-sas-v1\0";
const SAS_INFO: &[u8] = b"konclave-short-code-sas-output-v1\0";
const CHANNEL_SALT: &[u8] = b"konclave-short-code-channel-schedule-v1\0";
const CHANNEL_INFO: &[u8] = b"konclave-short-code-channel-key-v1\0";
const CHANNEL_AAD_DOMAIN: &[u8] = b"konclave-short-code-channel-record-v1\0";

/// Maximum plaintext protected by one OPAQUE-derived short-code channel record.
pub const MAX_SHORT_CODE_PAIRING_PLAINTEXT_BYTES: usize = 8 * 1024;

/// Role- and purpose-separated OPAQUE session channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShortCodePairingChannel {
    /// Creator public identity sent to the claimant.
    CreatorIdentity = 1,
    /// Claimant public identity sent to the creator.
    ClaimantIdentity = 2,
    /// Creator's explicit transcript confirmation.
    CreatorConfirmation = 3,
    /// Claimant's explicit transcript confirmation.
    ClaimantConfirmation = 4,
    /// Existing member-only pairing capability released after mutual confirmation.
    Capability = 5,
}

struct ShortCodeOpaqueCipherSuite;

impl CipherSuite for ShortCodeOpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

/// Six-digit one-time OPAQUE password and relay locator input.
///
/// This type implements neither `Clone` nor `Debug` and zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShortCodePairingCode([u8; CODE_DIGITS]);

impl ShortCodePairingCode {
    /// Generates six unbiased decimal digits.
    ///
    /// # Errors
    ///
    /// Returns a provider failure when secure randomness is unavailable.
    pub fn generate() -> Result<Self, KonclaveCryptographicError> {
        for _ in 0..128 {
            let mut random = [0_u8; 4];
            fill_random(&mut random)?;
            let value = u32::from_be_bytes(random);
            if value < CODE_REJECTION_LIMIT {
                return Ok(Self::from_value(value % CODE_SPACE));
            }
        }
        Err(KonclaveCryptographicError::ProviderFailure {
            operation: "short-code generation",
        })
    }

    /// Parses exactly six ASCII decimal digits.
    ///
    /// # Errors
    ///
    /// Returns an opaque invalid-code error for every other input.
    pub fn parse(value: &str) -> Result<Self, KonclaveCryptographicError> {
        if value.len() != CODE_DIGITS || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(KonclaveCryptographicError::InvalidShortCodePairingCode);
        }
        let mut digits = [0_u8; CODE_DIGITS];
        digits.copy_from_slice(value.as_bytes());
        Ok(Self(digits))
    }

    /// Returns the code for one explicit handoff operation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("short-code digits are always ASCII")
    }

    /// Derives the non-secret relay locator.
    #[must_use]
    pub fn locator(&self) -> ShortCodePairingLocator {
        let mut digest = Sha256::new();
        digest.update(LOCATOR_DOMAIN);
        digest.update(self.0);
        ShortCodePairingLocator::from_bytes(digest.finalize().into())
    }

    fn from_value(value: u32) -> Self {
        let mut digits = [0_u8; CODE_DIGITS];
        let mut remaining = value;
        for digit in digits.iter_mut().rev() {
            *digit = b'0' + (remaining % 10) as u8;
            remaining /= 10;
        }
        Self(digits)
    }
}

/// Sealed-persistence input for the creator's OPAQUE setup and password file.
pub struct ShortCodeOpaqueServerRecord {
    state: Zeroizing<Vec<u8>>,
}

/// Sealed-persistence input for one claimant's in-progress OPAQUE login.
pub struct ShortCodeOpaqueClientLogin {
    state: Zeroizing<Vec<u8>>,
    code: ShortCodePairingCode,
}

/// Sealed-persistence input for one creator's in-progress OPAQUE login.
pub struct ShortCodeOpaqueServerLogin {
    state: Zeroizing<Vec<u8>>,
}

/// Session key established only by matching OPAQUE executions.
pub struct ShortCodeOpaqueSession {
    key: Zeroizing<[u8; 64]>,
}

impl ShortCodeOpaqueServerRecord {
    /// Performs local ephemeral OPAQUE registration under one short code.
    ///
    /// # Errors
    ///
    /// Returns an opaque provider or OPAQUE protocol failure.
    pub fn register(
        code: &ShortCodePairingCode,
        attempt_id: ShortCodePairingAttemptId,
    ) -> Result<Self, KonclaveCryptographicError> {
        Self::register_with_rng(code, attempt_id, &mut OsRng)
    }

    fn register_with_rng<R: CryptoRng + RngCore>(
        code: &ShortCodePairingCode,
        attempt_id: ShortCodePairingAttemptId,
        rng: &mut R,
    ) -> Result<Self, KonclaveCryptographicError> {
        let ids = opaque_identifiers(attempt_id);
        let credential_identifier = opaque_credential_identifier(attempt_id);
        let server_setup = ServerSetup::<ShortCodeOpaqueCipherSuite>::new(rng);
        let client =
            ClientRegistration::<ShortCodeOpaqueCipherSuite>::start(rng, code.as_str().as_bytes())
                .map_err(opaque_protocol_error)?;
        let server = ServerRegistration::<ShortCodeOpaqueCipherSuite>::start(
            &server_setup,
            canonical_registration_request(&client.message.serialize())?,
            &credential_identifier,
        )
        .map_err(opaque_protocol_error)?;
        let ksf = Argon2::default();
        let mut upload = client
            .state
            .finish(
                rng,
                code.as_str().as_bytes(),
                canonical_registration_response(&server.message.serialize())?,
                ClientRegistrationFinishParameters::new(ids.as_opaque(), Some(&ksf)),
            )
            .map_err(opaque_protocol_error)?;
        let password_file = ServerRegistration::<ShortCodeOpaqueCipherSuite>::finish(
            canonical_registration_upload(&upload.message.serialize())?,
        );
        upload.export_key.zeroize();
        let setup = server_setup.serialize();
        let password_file = password_file.serialize();
        Ok(Self {
            state: encode_server_record(&setup, &password_file)?,
        })
    }

    /// Opens one claimant request and returns the exact response and resumable state.
    ///
    /// # Errors
    ///
    /// Returns an opaque state, message, randomness, or OPAQUE protocol failure.
    pub fn start_login(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        request: &[u8],
    ) -> Result<(ShortCodeOpaqueServerLogin, Vec<u8>), KonclaveCryptographicError> {
        self.start_login_with_rng(attempt_id, request, &mut OsRng)
    }

    fn start_login_with_rng<R: CryptoRng + RngCore>(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        request: &[u8],
        rng: &mut R,
    ) -> Result<(ShortCodeOpaqueServerLogin, Vec<u8>), KonclaveCryptographicError> {
        let (setup_bytes, password_file_bytes) = decode_server_record(&self.state)?;
        let server_setup = canonical_server_setup(setup_bytes).map_err(|_| state_invalid())?;
        let password_file =
            canonical_server_registration(password_file_bytes).map_err(|_| state_invalid())?;
        let ids = opaque_identifiers(attempt_id);
        let context = opaque_context(attempt_id);
        let credential_identifier = opaque_credential_identifier(attempt_id);
        let login = ServerLogin::<ShortCodeOpaqueCipherSuite>::start(
            rng,
            &server_setup,
            Some(password_file),
            canonical_credential_request(request)?,
            &credential_identifier,
            ServerLoginParameters {
                context: Some(&context),
                identifiers: ids.as_opaque(),
            },
        )
        .map_err(opaque_protocol_error)?;
        let response = login.message.serialize().to_vec();
        require_message_bound(&response)?;
        Ok((
            ShortCodeOpaqueServerLogin {
                state: encode_single_state(&login.state.serialize())?,
            },
            response,
        ))
    }

    /// Writes the opaque creator state for sealing by the daemon.
    ///
    /// # Errors
    ///
    /// Returns a provider failure when the destination rejects the write.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), KonclaveCryptographicError> {
        writer
            .write_all(&self.state)
            .map_err(|_| state_write_failed())
    }

    /// Restores one exact opaque creator state blob.
    ///
    /// # Errors
    ///
    /// Returns an opaque invalid-state error for malformed or non-canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        let (setup, password_file) = decode_server_record(bytes)?;
        canonical_server_setup(setup).map_err(|_| state_invalid())?;
        canonical_server_registration(password_file).map_err(|_| state_invalid())?;
        Ok(Self {
            state: Zeroizing::new(bytes.to_vec()),
        })
    }
}

impl ShortCodeOpaqueClientLogin {
    /// Starts one claimant OPAQUE login under the entered code.
    ///
    /// # Errors
    ///
    /// Returns an opaque code, randomness, or OPAQUE protocol failure.
    pub fn start(
        code: ShortCodePairingCode,
        attempt_id: ShortCodePairingAttemptId,
    ) -> Result<(Self, Vec<u8>), KonclaveCryptographicError> {
        Self::start_with_rng(code, attempt_id, &mut OsRng)
    }

    fn start_with_rng<R: CryptoRng + RngCore>(
        code: ShortCodePairingCode,
        _: ShortCodePairingAttemptId,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), KonclaveCryptographicError> {
        let login = ClientLogin::<ShortCodeOpaqueCipherSuite>::start(rng, code.as_str().as_bytes())
            .map_err(opaque_protocol_error)?;
        let request = login.message.serialize().to_vec();
        require_message_bound(&request)?;
        Ok((
            Self {
                state: encode_single_state(&login.state.serialize())?,
                code,
            },
            request,
        ))
    }

    /// Finishes the claimant login and returns exact finalization bytes and session.
    ///
    /// # Errors
    ///
    /// Returns one opaque authentication failure for a wrong code or modified input.
    pub fn finish(
        self,
        attempt_id: ShortCodePairingAttemptId,
        response: &[u8],
    ) -> Result<(Vec<u8>, ShortCodeOpaqueSession), KonclaveCryptographicError> {
        self.finish_with_rng(attempt_id, response, &mut OsRng)
    }

    fn finish_with_rng<R: CryptoRng + RngCore>(
        self,
        attempt_id: ShortCodePairingAttemptId,
        response: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, ShortCodeOpaqueSession), KonclaveCryptographicError> {
        let state_bytes = decode_single_state(&self.state)?;
        let login = canonical_client_login(state_bytes).map_err(|_| state_invalid())?;
        let ids = opaque_identifiers(attempt_id);
        let context = opaque_context(attempt_id);
        let ksf = Argon2::default();
        let mut finished = login
            .finish(
                rng,
                self.code.as_str().as_bytes(),
                canonical_credential_response(response)?,
                ClientLoginFinishParameters::new(Some(&context), ids.as_opaque(), Some(&ksf)),
            )
            .map_err(|_| KonclaveCryptographicError::ShortCodePairingAuthenticationFailed)?;
        let finalization = finished.message.serialize().to_vec();
        require_message_bound(&finalization)?;
        let session = ShortCodeOpaqueSession::from_slice(&finished.session_key)?;
        finished.session_key.zeroize();
        finished.export_key.zeroize();
        Ok((finalization, session))
    }

    /// Writes the opaque claimant state and code for sealing by the daemon.
    ///
    /// # Errors
    ///
    /// Returns a provider failure when the destination rejects the write.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), KonclaveCryptographicError> {
        writer
            .write_all(&encode_client_state(&self.code, &self.state)?)
            .map_err(|_| state_write_failed())
    }

    /// Restores one exact opaque claimant state blob.
    ///
    /// # Errors
    ///
    /// Returns an opaque invalid-state error for malformed or non-canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        let (code, state) = decode_client_state(bytes)?;
        canonical_client_login(state).map_err(|_| state_invalid())?;
        Ok(Self {
            state: encode_single_state(state)?,
            code,
        })
    }
}

impl ShortCodeOpaqueServerLogin {
    /// Finishes the creator login and returns the matching session.
    ///
    /// # Errors
    ///
    /// Returns one opaque authentication failure for a wrong code or modified input.
    pub fn finish(
        self,
        attempt_id: ShortCodePairingAttemptId,
        finalization: &[u8],
    ) -> Result<ShortCodeOpaqueSession, KonclaveCryptographicError> {
        let login = canonical_server_login(decode_single_state(&self.state)?)
            .map_err(|_| state_invalid())?;
        let ids = opaque_identifiers(attempt_id);
        let context = opaque_context(attempt_id);
        let mut finished = login
            .finish(
                canonical_credential_finalization(finalization)?,
                ServerLoginParameters {
                    context: Some(&context),
                    identifiers: ids.as_opaque(),
                },
            )
            .map_err(|_| KonclaveCryptographicError::ShortCodePairingAuthenticationFailed)?;
        let session = ShortCodeOpaqueSession::from_slice(&finished.session_key)?;
        finished.session_key.zeroize();
        Ok(session)
    }

    /// Writes the opaque creator login state for sealing by the daemon.
    ///
    /// # Errors
    ///
    /// Returns a provider failure when the destination rejects the write.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), KonclaveCryptographicError> {
        writer
            .write_all(&self.state)
            .map_err(|_| state_write_failed())
    }

    /// Restores one exact opaque creator login state blob.
    ///
    /// # Errors
    ///
    /// Returns an opaque invalid-state error for malformed or non-canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        canonical_server_login(decode_single_state(bytes)?).map_err(|_| state_invalid())?;
        Ok(Self {
            state: Zeroizing::new(bytes.to_vec()),
        })
    }
}

impl ShortCodeOpaqueSession {
    fn from_slice(value: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        let key = value.try_into().map_err(|_| state_invalid())?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// Derives the six-digit SAS for one exact OPAQUE and identity transcript.
    ///
    /// # Errors
    ///
    /// Returns a provider failure when key derivation cannot complete.
    pub fn derive_sas(
        &self,
        attempt_id: ShortCodePairingAttemptId,
        transcript_hash: ShortCodePairingTranscriptHash,
        creator_device_id: DeviceId,
        claimant_device_id: DeviceId,
    ) -> Result<ShortCodePairingSas, KonclaveCryptographicError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, SAS_SALT);
        let prk = salt.extract(self.key.as_slice());
        let info = [
            SAS_INFO,
            attempt_id.as_bytes().as_slice(),
            transcript_hash.as_bytes().as_slice(),
            creator_device_id.as_bytes().as_slice(),
            claimant_device_id.as_bytes().as_slice(),
        ];
        let okm = prk
            .expand(&info, FixedLength(32))
            .map_err(|_| provider_failure("short-code SAS derivation"))?;
        let mut output = Zeroizing::new([0_u8; 32]);
        okm.fill(&mut *output)
            .map_err(|_| provider_failure("short-code SAS derivation"))?;
        for chunk in output.chunks_exact(4) {
            let value = u32::from_be_bytes(chunk.try_into().map_err(|_| state_invalid())?);
            if value < CODE_REJECTION_LIMIT {
                return Ok(ShortCodePairingSas::new(value % CODE_SPACE)?);
            }
        }
        Err(provider_failure("short-code SAS derivation"))
    }

    /// Encrypts one bounded identity, confirmation, or capability record.
    ///
    /// # Errors
    ///
    /// Returns a provider or size error when encryption cannot complete.
    pub fn seal(
        &self,
        channel: ShortCodePairingChannel,
        attempt_id: ShortCodePairingAttemptId,
        transcript_hash: ShortCodePairingTranscriptHash,
        plaintext: &[u8],
    ) -> Result<AuthenticatedCiphertext, KonclaveCryptographicError> {
        let cipher = self.channel_cipher(channel)?;
        cipher
            .seal_with_associated_data(plaintext, MAX_SHORT_CODE_PAIRING_PLAINTEXT_BYTES, |nonce| {
                channel_header(channel, attempt_id, transcript_hash, nonce)
            })
            .map_err(short_code_cipher_error)
    }

    /// Authenticates and decrypts one bounded session channel record.
    ///
    /// # Errors
    ///
    /// Returns an authentication or size error for the wrong session, channel,
    /// attempt, transcript, nonce, or ciphertext.
    pub fn open(
        &self,
        channel: ShortCodePairingChannel,
        attempt_id: ShortCodePairingAttemptId,
        transcript_hash: ShortCodePairingTranscriptHash,
        ciphertext: &AuthenticatedCiphertext,
    ) -> Result<Zeroizing<Vec<u8>>, KonclaveCryptographicError> {
        let cipher = self.channel_cipher(channel)?;
        cipher
            .open(
                &channel_header(channel, attempt_id, transcript_hash, ciphertext.nonce()),
                ciphertext,
                MAX_SHORT_CODE_PAIRING_PLAINTEXT_BYTES,
            )
            .map_err(short_code_cipher_error)
    }

    fn channel_cipher(
        &self,
        channel: ShortCodePairingChannel,
    ) -> Result<AuthenticatedCipher, KonclaveCryptographicError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, CHANNEL_SALT);
        let prk = salt.extract(self.key.as_slice());
        let channel = [channel as u8];
        let info = [CHANNEL_INFO, channel.as_slice()];
        let okm = prk
            .expand(&info, FixedLength(AUTHENTICATED_CIPHER_KEY_BYTES))
            .map_err(|_| provider_failure("short-code channel key derivation"))?;
        let mut key = Zeroizing::new([0_u8; AUTHENTICATED_CIPHER_KEY_BYTES]);
        okm.fill(&mut *key)
            .map_err(|_| provider_failure("short-code channel key derivation"))?;
        Ok(AuthenticatedCipher::new(&key))
    }
}

/// Generates one random short-code pairing attempt identifier.
///
/// # Errors
///
/// Returns a provider failure when secure randomness is unavailable.
pub fn generate_short_code_pairing_attempt_id()
-> Result<ShortCodePairingAttemptId, KonclaveCryptographicError> {
    let mut bytes = [0_u8; ShortCodePairingAttemptId::LENGTH];
    fill_random(&mut bytes)?;
    Ok(ShortCodePairingAttemptId::from_bytes(bytes))
}

/// Hashes one bounded canonical OPAQUE and encrypted-identity transcript.
///
/// # Errors
///
/// Returns a size error for too many messages or excessive cumulative bytes.
pub fn derive_short_code_pairing_transcript_hash(
    attempt_id: ShortCodePairingAttemptId,
    messages: &[&[u8]],
) -> Result<ShortCodePairingTranscriptHash, KonclaveCryptographicError> {
    if messages.len() > MAX_TRANSCRIPT_MESSAGES {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field: "short_code_pairing_transcript_messages",
            minimum: 0,
            maximum: MAX_TRANSCRIPT_MESSAGES,
            actual: messages.len(),
        }
        .into());
    }
    let total = messages.iter().try_fold(0_usize, |total, message| {
        total
            .checked_add(message.len())
            .ok_or(KonclaveCryptographicError::PairingPayloadTooLarge {
                maximum: MAX_TRANSCRIPT_BYTES,
                actual: usize::MAX,
            })
    })?;
    if total > MAX_TRANSCRIPT_BYTES {
        return Err(KonclaveCryptographicError::PairingPayloadTooLarge {
            maximum: MAX_TRANSCRIPT_BYTES,
            actual: total,
        });
    }
    let mut digest = Sha256::new();
    digest.update(TRANSCRIPT_DOMAIN);
    digest.update(attempt_id.as_bytes());
    for message in messages {
        digest.update(
            u32::try_from(message.len())
                .map_err(|_| state_invalid())?
                .to_be_bytes(),
        );
        digest.update(message);
    }
    Ok(ShortCodePairingTranscriptHash::from_bytes(
        digest.finalize().into(),
    ))
}

struct OpaqueIdentifiers {
    client: Vec<u8>,
    server: Vec<u8>,
}

impl OpaqueIdentifiers {
    fn as_opaque(&self) -> Identifiers<'_> {
        Identifiers {
            client: Some(&self.client),
            server: Some(&self.server),
        }
    }
}

fn opaque_identifiers(attempt_id: ShortCodePairingAttemptId) -> OpaqueIdentifiers {
    OpaqueIdentifiers {
        client: domain_value(OPAQUE_CLIENT_ID_DOMAIN, attempt_id),
        server: domain_value(OPAQUE_SERVER_ID_DOMAIN, attempt_id),
    }
}

fn opaque_credential_identifier(attempt_id: ShortCodePairingAttemptId) -> Vec<u8> {
    domain_value(OPAQUE_CREDENTIAL_DOMAIN, attempt_id)
}

fn opaque_context(attempt_id: ShortCodePairingAttemptId) -> Vec<u8> {
    domain_value(OPAQUE_CONTEXT_DOMAIN, attempt_id)
}

fn domain_value(domain: &[u8], attempt_id: ShortCodePairingAttemptId) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + ShortCodePairingAttemptId::LENGTH);
    output.extend_from_slice(domain);
    output.extend_from_slice(attempt_id.as_bytes());
    output
}

fn encode_server_record(
    setup: &[u8],
    password_file: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KonclaveCryptographicError> {
    if setup.is_empty()
        || password_file.is_empty()
        || setup.len() + password_file.len() + 5 > MAX_OPAQUE_STATE_BYTES
    {
        return Err(state_invalid());
    }
    let setup_length = u32::try_from(setup.len()).map_err(|_| state_invalid())?;
    let mut output = Zeroizing::new(Vec::with_capacity(5 + setup.len() + password_file.len()));
    output.push(STATE_VERSION);
    output.extend_from_slice(&setup_length.to_be_bytes());
    output.extend_from_slice(setup);
    output.extend_from_slice(password_file);
    Ok(output)
}

fn decode_server_record(bytes: &[u8]) -> Result<(&[u8], &[u8]), KonclaveCryptographicError> {
    if bytes.len() > MAX_OPAQUE_STATE_BYTES || bytes.first() != Some(&STATE_VERSION) {
        return Err(state_invalid());
    }
    let setup_length = bytes
        .get(1..5)
        .ok_or_else(state_invalid)?
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| state_invalid())? as usize;
    let setup_end = 5_usize
        .checked_add(setup_length)
        .ok_or_else(state_invalid)?;
    let setup = bytes.get(5..setup_end).ok_or_else(state_invalid)?;
    let password_file = bytes.get(setup_end..).ok_or_else(state_invalid)?;
    if setup.is_empty() || password_file.is_empty() {
        return Err(state_invalid());
    }
    Ok((setup, password_file))
}

fn encode_single_state(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KonclaveCryptographicError> {
    if bytes.is_empty() || bytes.len() + 1 > MAX_OPAQUE_STATE_BYTES {
        return Err(state_invalid());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    output.push(STATE_VERSION);
    output.extend_from_slice(bytes);
    Ok(output)
}

fn decode_single_state(bytes: &[u8]) -> Result<&[u8], KonclaveCryptographicError> {
    if bytes.len() > MAX_OPAQUE_STATE_BYTES
        || bytes.first() != Some(&STATE_VERSION)
        || bytes.len() == 1
    {
        return Err(state_invalid());
    }
    Ok(&bytes[1..])
}

fn encode_client_state(
    code: &ShortCodePairingCode,
    state: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KonclaveCryptographicError> {
    let state = decode_single_state(state)?;
    if 1 + CODE_DIGITS + state.len() > MAX_OPAQUE_STATE_BYTES {
        return Err(state_invalid());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(1 + CODE_DIGITS + state.len()));
    output.push(STATE_VERSION);
    output.extend_from_slice(code.as_str().as_bytes());
    output.extend_from_slice(state);
    Ok(output)
}

fn decode_client_state(
    bytes: &[u8],
) -> Result<(ShortCodePairingCode, &[u8]), KonclaveCryptographicError> {
    if bytes.len() > MAX_OPAQUE_STATE_BYTES
        || bytes.first() != Some(&STATE_VERSION)
        || bytes.len() <= 1 + CODE_DIGITS
    {
        return Err(state_invalid());
    }
    let code = std::str::from_utf8(&bytes[1..1 + CODE_DIGITS])
        .map_err(|_| state_invalid())
        .and_then(ShortCodePairingCode::parse)?;
    Ok((code, &bytes[1 + CODE_DIGITS..]))
}

fn require_message_bound(bytes: &[u8]) -> Result<(), KonclaveCryptographicError> {
    if bytes.is_empty() || bytes.len() > MAX_OPAQUE_MESSAGE_BYTES {
        return Err(KonclaveCryptographicError::PairingPayloadTooLarge {
            maximum: MAX_OPAQUE_MESSAGE_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(())
}

macro_rules! canonical_opaque {
    ($function:ident, $type:ty) => {
        fn $function(bytes: &[u8]) -> Result<$type, KonclaveCryptographicError> {
            require_message_bound(bytes)?;
            let value = <$type>::deserialize(bytes).map_err(opaque_protocol_error)?;
            if value.serialize().as_slice() != bytes {
                return Err(state_invalid());
            }
            Ok(value)
        }
    };
}

canonical_opaque!(
    canonical_registration_request,
    RegistrationRequest<ShortCodeOpaqueCipherSuite>
);
canonical_opaque!(
    canonical_registration_response,
    RegistrationResponse<ShortCodeOpaqueCipherSuite>
);
canonical_opaque!(
    canonical_registration_upload,
    RegistrationUpload<ShortCodeOpaqueCipherSuite>
);
canonical_opaque!(
    canonical_credential_request,
    CredentialRequest<ShortCodeOpaqueCipherSuite>
);
canonical_opaque!(
    canonical_credential_response,
    CredentialResponse<ShortCodeOpaqueCipherSuite>
);
canonical_opaque!(
    canonical_credential_finalization,
    CredentialFinalization<ShortCodeOpaqueCipherSuite>
);

fn canonical_server_setup(
    bytes: &[u8],
) -> Result<ServerSetup<ShortCodeOpaqueCipherSuite>, KonclaveCryptographicError> {
    let value = ServerSetup::<ShortCodeOpaqueCipherSuite>::deserialize(bytes)
        .map_err(|_| state_invalid())?;
    if value.serialize().as_slice() != bytes {
        return Err(state_invalid());
    }
    Ok(value)
}

fn canonical_server_registration(
    bytes: &[u8],
) -> Result<ServerRegistration<ShortCodeOpaqueCipherSuite>, KonclaveCryptographicError> {
    let value = ServerRegistration::<ShortCodeOpaqueCipherSuite>::deserialize(bytes)
        .map_err(|_| state_invalid())?;
    if value.serialize().as_slice() != bytes {
        return Err(state_invalid());
    }
    Ok(value)
}

fn canonical_client_login(
    bytes: &[u8],
) -> Result<ClientLogin<ShortCodeOpaqueCipherSuite>, KonclaveCryptographicError> {
    let value = ClientLogin::<ShortCodeOpaqueCipherSuite>::deserialize(bytes)
        .map_err(|_| state_invalid())?;
    if value.serialize().as_slice() != bytes {
        return Err(state_invalid());
    }
    Ok(value)
}

fn canonical_server_login(
    bytes: &[u8],
) -> Result<ServerLogin<ShortCodeOpaqueCipherSuite>, KonclaveCryptographicError> {
    let value = ServerLogin::<ShortCodeOpaqueCipherSuite>::deserialize(bytes)
        .map_err(|_| state_invalid())?;
    if value.serialize().as_slice() != bytes {
        return Err(state_invalid());
    }
    Ok(value)
}

fn opaque_protocol_error(_: opaque_ke::errors::ProtocolError) -> KonclaveCryptographicError {
    KonclaveCryptographicError::ShortCodePairingAuthenticationFailed
}

const fn state_invalid() -> KonclaveCryptographicError {
    KonclaveCryptographicError::InvalidShortCodePairingState
}

const fn state_write_failed() -> KonclaveCryptographicError {
    KonclaveCryptographicError::ProviderFailure {
        operation: "short-code state serialization",
    }
}

const fn provider_failure(operation: &'static str) -> KonclaveCryptographicError {
    KonclaveCryptographicError::ProviderFailure { operation }
}

fn channel_header(
    channel: ShortCodePairingChannel,
    attempt_id: ShortCodePairingAttemptId,
    transcript_hash: ShortCodePairingTranscriptHash,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let version = ProtocolVersion::application_v1();
    let mut output = Vec::with_capacity(
        CHANNEL_AAD_DOMAIN.len()
            + 4
            + 1
            + ShortCodePairingAttemptId::LENGTH
            + ShortCodePairingTranscriptHash::LENGTH
            + nonce.len(),
    );
    output.extend_from_slice(CHANNEL_AAD_DOMAIN);
    output.extend_from_slice(&version.major().to_be_bytes());
    output.extend_from_slice(&version.minor().to_be_bytes());
    output.push(channel as u8);
    output.extend_from_slice(attempt_id.as_bytes());
    output.extend_from_slice(transcript_hash.as_bytes());
    output.extend_from_slice(nonce);
    output
}

fn short_code_cipher_error(error: SecretStorageError) -> KonclaveCryptographicError {
    match error {
        SecretStorageError::PlaintextTooLarge { maximum, actual }
        | SecretStorageError::SealedBlobTooLarge { maximum, actual } => {
            KonclaveCryptographicError::PairingPayloadTooLarge { maximum, actual }
        }
        SecretStorageError::RandomGenerationFailed => provider_failure("short-code channel nonce"),
        _ => KonclaveCryptographicError::ShortCodePairingAuthenticationFailed,
    }
}

#[derive(Clone, Copy)]
struct FixedLength(usize);

impl KeyType for FixedLength {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    fn attempt() -> ShortCodePairingAttemptId {
        ShortCodePairingAttemptId::from_bytes([7; 16])
    }

    fn write_state(
        write: impl FnOnce(&mut Vec<u8>) -> Result<(), KonclaveCryptographicError>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        write(&mut bytes).unwrap();
        bytes
    }

    fn complete(
        code: ShortCodePairingCode,
        client_code: ShortCodePairingCode,
    ) -> Result<
        (ShortCodeOpaqueSession, ShortCodeOpaqueSession, Vec<Vec<u8>>),
        KonclaveCryptographicError,
    > {
        let attempt = attempt();
        let server = ShortCodeOpaqueServerRecord::register_with_rng(
            &code,
            attempt,
            &mut StdRng::seed_from_u64(1),
        )?;
        let server_bytes = write_state(|writer| server.write_to(writer));
        let server = ShortCodeOpaqueServerRecord::from_bytes(&server_bytes)?;
        let (client, request) = ShortCodeOpaqueClientLogin::start_with_rng(
            client_code,
            attempt,
            &mut StdRng::seed_from_u64(2),
        )?;
        let client_bytes = write_state(|writer| client.write_to(writer));
        let client = ShortCodeOpaqueClientLogin::from_bytes(&client_bytes)?;
        let (server_login, response) =
            server.start_login_with_rng(attempt, &request, &mut StdRng::seed_from_u64(3))?;
        let server_login_bytes = write_state(|writer| server_login.write_to(writer));
        let server_login = ShortCodeOpaqueServerLogin::from_bytes(&server_login_bytes)?;
        let (finalization, client_session) =
            client.finish_with_rng(attempt, &response, &mut StdRng::seed_from_u64(4))?;
        let server_session = server_login.finish(attempt, &finalization)?;
        Ok((
            client_session,
            server_session,
            vec![request, response, finalization],
        ))
    }

    #[test]
    fn code_is_canonical_and_locator_is_stable() {
        let code = ShortCodePairingCode::parse("000042").unwrap();
        assert_eq!(code.as_str(), "000042");
        assert_eq!(
            code.locator(),
            ShortCodePairingCode::parse("000042").unwrap().locator()
        );
        assert!(ShortCodePairingCode::parse("42").is_err());
        assert!(ShortCodePairingCode::parse("00004O").is_err());
    }

    #[test]
    fn opaque_login_and_sas_match_only_for_the_same_code_and_transcript() {
        let (client, server, messages) = complete(
            ShortCodePairingCode::parse("123456").unwrap(),
            ShortCodePairingCode::parse("123456").unwrap(),
        )
        .unwrap();
        let transcript = derive_short_code_pairing_transcript_hash(
            attempt(),
            &messages.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
        let creator = DeviceId::from_bytes([8; 32]);
        let claimant = DeviceId::from_bytes([9; 32]);
        assert!(
            client
                .derive_sas(attempt(), transcript, creator, claimant)
                .unwrap()
                == server
                    .derive_sas(attempt(), transcript, creator, claimant)
                    .unwrap()
        );
        assert_ne!(
            client
                .derive_sas(attempt(), transcript, creator, claimant)
                .unwrap()
                .value(),
            client
                .derive_sas(
                    attempt(),
                    transcript,
                    DeviceId::from_bytes([10; 32]),
                    claimant,
                )
                .unwrap()
                .value()
        );

        assert!(
            complete(
                ShortCodePairingCode::parse("123456").unwrap(),
                ShortCodePairingCode::parse("654321").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn opaque_messages_and_state_reject_trailing_or_modified_bytes() {
        let code = ShortCodePairingCode::parse("123456").unwrap();
        let server = ShortCodeOpaqueServerRecord::register(&code, attempt()).unwrap();
        let mut state = write_state(|writer| server.write_to(writer));
        state.push(0);
        assert!(ShortCodeOpaqueServerRecord::from_bytes(&state).is_err());

        let (client, mut request) = ShortCodeOpaqueClientLogin::start(
            ShortCodePairingCode::parse("123456").unwrap(),
            attempt(),
        )
        .unwrap();
        request.push(0);
        assert!(server.start_login(attempt(), &request).is_err());
        let mut client_state = write_state(|writer| client.write_to(writer));
        client_state[0] = 2;
        assert!(ShortCodeOpaqueClientLogin::from_bytes(&client_state).is_err());
    }

    #[test]
    fn deterministic_opaque_vector_is_stable() {
        let (client, _, messages) = complete(
            ShortCodePairingCode::parse("123456").unwrap(),
            ShortCodePairingCode::parse("123456").unwrap(),
        )
        .unwrap();
        let transcript = derive_short_code_pairing_transcript_hash(
            attempt(),
            &messages.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
        let sas = client
            .derive_sas(
                attempt(),
                transcript,
                DeviceId::from_bytes([8; 32]),
                DeviceId::from_bytes([9; 32]),
            )
            .unwrap();
        assert_eq!(sas.to_text(), "742539");
        assert_eq!(
            transcript.as_bytes(),
            &[
                0x6e, 0x13, 0xec, 0xd7, 0x11, 0xd8, 0x16, 0x4d, 0xee, 0x09, 0x69, 0xff, 0xaf, 0x3c,
                0x8f, 0x19, 0x22, 0x3e, 0xbc, 0xfd, 0x7f, 0x89, 0x0f, 0x5b, 0x66, 0x07, 0xe9, 0xaf,
                0x77, 0xf9, 0x9f, 0x16,
            ]
        );
    }

    #[test]
    fn session_channels_are_role_and_transcript_bound() {
        let (client, server, messages) = complete(
            ShortCodePairingCode::parse("123456").unwrap(),
            ShortCodePairingCode::parse("123456").unwrap(),
        )
        .unwrap();
        let transcript = derive_short_code_pairing_transcript_hash(
            attempt(),
            &messages.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
        let ciphertext = client
            .seal(
                ShortCodePairingChannel::CreatorIdentity,
                attempt(),
                transcript,
                b"identity",
            )
            .unwrap();
        assert_eq!(
            server
                .open(
                    ShortCodePairingChannel::CreatorIdentity,
                    attempt(),
                    transcript,
                    &ciphertext,
                )
                .unwrap()
                .as_slice(),
            b"identity"
        );
        assert!(
            server
                .open(
                    ShortCodePairingChannel::ClaimantIdentity,
                    attempt(),
                    transcript,
                    &ciphertext,
                )
                .is_err()
        );
        assert!(
            server
                .open(
                    ShortCodePairingChannel::CreatorIdentity,
                    ShortCodePairingAttemptId::from_bytes([8; 16]),
                    transcript,
                    &ciphertext,
                )
                .is_err()
        );
        assert!(
            server
                .open(
                    ShortCodePairingChannel::CreatorIdentity,
                    attempt(),
                    ShortCodePairingTranscriptHash::from_bytes([9; 32]),
                    &ciphertext,
                )
                .is_err()
        );
    }
}
