use passkey_auth::{
    Attachment, AuthenticationChallenge, AuthenticationResponse, AuthenticationState,
    PasskeyCredential, RegistrationChallenge, RegistrationResponse, RegistrationState, Webauthn,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    UserPresenceAssertionDigest, UserPresenceChallenge, UserPresenceCredentialDigest,
    UserPresenceCredentialId, UserPresenceProviderId, VerifiedUserPresenceAssertion,
};

const PROVIDER_ID: &str = "windows-native-webauthn-v1";
const RELYING_PARTY_ID: &str = "konclave.local";
const RELYING_PARTY_NAME: &str = "Konclave";
const NATIVE_ORIGIN: &str = "https://konclave.local";
const LOCAL_USER_NAME: &str = "konclave-local-user";
const LOCAL_USER_DISPLAY_NAME: &str = "Konclave local user";
const USER_ID_DOMAIN: &[u8] = b"konclave.user-presence.webauthn-user.v1\0";
const CREDENTIAL_DOCUMENT_VERSION: u16 = 1;
/// Largest accepted native WebAuthn request, response, or credential document.
pub const MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES: usize = 64 * 1024;

/// Stable failures from the native WebAuthn provider boundary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum UserPresenceWebAuthnError {
    /// A bounded challenge or credential document could not be encoded.
    #[error("user-presence WebAuthn document could not be encoded")]
    Encoding,
    /// A registration response did not satisfy the required WebAuthn policy.
    #[error("user-presence WebAuthn registration is invalid")]
    InvalidRegistration,
    /// An authentication response did not satisfy the required WebAuthn policy.
    #[error("user-presence WebAuthn assertion is invalid")]
    InvalidAssertion,
    /// Persisted credential state is malformed or belongs to another provider.
    #[error("user-presence WebAuthn credential is invalid")]
    InvalidCredential,
    /// This build, platform, or authenticator cannot perform required verification.
    #[error("user-presence WebAuthn provider is unavailable")]
    ProviderUnavailable,
    /// The user cancelled the native ceremony.
    #[error("user-presence WebAuthn ceremony was cancelled")]
    Cancelled,
    /// The native authenticator failed without producing a proof.
    #[error("user-presence WebAuthn provider failed")]
    ProviderFailed,
}

impl UserPresenceWebAuthnError {
    /// Returns the stable machine-readable provider outcome.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::InvalidRegistration => "invalid_registration",
            Self::InvalidAssertion => "invalid_assertion",
            Self::InvalidCredential => "invalid_credential",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Cancelled => "cancelled",
            Self::ProviderFailed => "provider_failed",
        }
    }
}

/// Pure-Rust relying-party verifier for the fixed Konclave native WebAuthn scope.
#[derive(Clone)]
pub struct UserPresenceWebAuthnVerifier {
    webauthn: Webauthn,
}

impl UserPresenceWebAuthnVerifier {
    /// Creates the fixed relying-party verifier with strict base64 and required UV.
    #[must_use]
    pub fn new() -> Self {
        Self {
            webauthn: Webauthn::new(RELYING_PARTY_ID, RELYING_PARTY_NAME, NATIVE_ORIGIN)
                .strict_base64(true)
                .require_user_verification(true)
                .authenticator_attachment(Attachment::Any),
        }
    }

    /// Starts one user-verifying credential registration.
    ///
    /// # Errors
    ///
    /// Returns an encoding failure when the standard native request exceeds its hard
    /// bound.
    pub fn begin_enrollment(
        &self,
        installation_fingerprint: [u8; 32],
        existing: Option<&NativeWebAuthnCredential>,
    ) -> Result<(NativeWebAuthnRequest, NativeWebAuthnEnrollment), UserPresenceWebAuthnError> {
        let user_handle = installation_user_id(installation_fingerprint);
        let existing = existing
            .map(|credential| vec![credential.passkey.id.clone()])
            .unwrap_or_default();
        let (request, state) = self.webauthn.start_registration(
            &user_handle,
            LOCAL_USER_NAME,
            LOCAL_USER_DISPLAY_NAME,
            &existing,
        );
        Ok((
            NativeWebAuthnRequest::from_registration(&request, &state)?,
            NativeWebAuthnEnrollment { state, user_handle },
        ))
    }

    /// Completes one user-verifying credential registration.
    ///
    /// The returned credential still requires a successful authentication challenge
    /// before an installer may persist it.
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceWebAuthnError::InvalidRegistration`] when parsing,
    /// challenge, origin, relying-party, signature, or user-verification checks fail.
    pub fn finish_enrollment(
        &self,
        response: &[u8],
        enrollment: &NativeWebAuthnEnrollment,
    ) -> Result<NativeWebAuthnCredential, UserPresenceWebAuthnError> {
        let response = registration_response(response)?;
        let passkey = self
            .webauthn
            .finish_registration(&enrollment.state, &response)
            .map_err(|_| UserPresenceWebAuthnError::InvalidRegistration)?;
        NativeWebAuthnCredential::from_passkey(passkey, enrollment.user_handle)
    }

    /// Starts a fresh authentication for one enrolled credential.
    ///
    /// # Errors
    ///
    /// Returns an encoding failure when the standard native request exceeds its hard
    /// bound.
    pub fn begin_authentication(
        &self,
        credential: &NativeWebAuthnCredential,
    ) -> Result<(NativeWebAuthnRequest, NativeWebAuthnAuthentication), UserPresenceWebAuthnError>
    {
        let (request, state) = self.webauthn.start_authentication_with_creds_for_user(
            &credential.user_handle,
            std::slice::from_ref(&credential.passkey),
        );
        let request = NativeWebAuthnRequest::from_authentication(&request, &state)?;
        let challenge = request.challenge;
        Ok((
            request,
            NativeWebAuthnAuthentication {
                state,
                challenge,
                credential_digest: credential.credential_id.digest(),
            },
        ))
    }

    /// Verifies one native assertion and updates its credential counter state.
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceWebAuthnError::InvalidAssertion`] when parsing,
    /// challenge, origin, relying-party, credential, signature, user-presence,
    /// user-verification, user-handle, or counter validation fails.
    pub fn finish_authentication(
        &self,
        response: &[u8],
        authentication: &NativeWebAuthnAuthentication,
        credential: &mut NativeWebAuthnCredential,
        verified_at_unix_milliseconds: u64,
    ) -> Result<VerifiedUserPresenceAssertion, UserPresenceWebAuthnError> {
        if response.is_empty() || response.len() > MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES {
            return Err(UserPresenceWebAuthnError::InvalidAssertion);
        }
        let assertion_digest = UserPresenceAssertionDigest::sha256(response);
        let response = authentication_response(response)?;
        let result = self
            .webauthn
            .finish_authentication(&authentication.state, &response, &credential.passkey)
            .map_err(|_| UserPresenceWebAuthnError::InvalidAssertion)?;
        if !result.user_verified {
            return Err(UserPresenceWebAuthnError::InvalidAssertion);
        }
        credential.passkey.counter = result.new_counter;
        Ok(VerifiedUserPresenceAssertion::new(
            authentication.challenge,
            provider_id()?,
            authentication.credential_digest,
            assertion_digest,
            verified_at_unix_milliseconds,
        ))
    }
}

impl Default for UserPresenceWebAuthnVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded serialized native WebAuthn request passed to the platform helper.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeWebAuthnRequest {
    challenge: UserPresenceChallenge,
    json: Vec<u8>,
}

impl NativeWebAuthnRequest {
    fn from_registration(
        request: &RegistrationChallenge,
        state: &RegistrationState,
    ) -> Result<Self, UserPresenceWebAuthnError> {
        Self::from_json_and_challenge(request, state.challenge.as_bytes())
    }

    fn from_authentication(
        request: &AuthenticationChallenge,
        state: &AuthenticationState,
    ) -> Result<Self, UserPresenceWebAuthnError> {
        Self::from_json_and_challenge(request, state.challenge.as_bytes())
    }

    fn from_json_and_challenge<T: Serialize>(
        request: &T,
        challenge: &[u8],
    ) -> Result<Self, UserPresenceWebAuthnError> {
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| UserPresenceWebAuthnError::Encoding)?;
        let json = encode_bounded(&PublicKeyRequest {
            public_key: request,
        })?;
        Ok(Self {
            challenge: UserPresenceChallenge::from_bytes(challenge),
            json,
        })
    }

    /// Returns the exact random challenge retained by the verifier state.
    #[must_use]
    pub const fn challenge(&self) -> UserPresenceChallenge {
        self.challenge
    }

    /// Returns the standard WebAuthn request JSON for the platform helper.
    #[must_use]
    pub fn as_json(&self) -> &[u8] {
        &self.json
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyRequest<'a, T> {
    public_key: &'a T,
}

/// Opaque server-side state paired with one registration challenge.
#[derive(Clone)]
pub struct NativeWebAuthnEnrollment {
    state: RegistrationState,
    user_handle: [u8; 16],
}

/// Opaque server-side state paired with one authentication challenge.
#[derive(Clone)]
pub struct NativeWebAuthnAuthentication {
    state: AuthenticationState,
    challenge: UserPresenceChallenge,
    credential_digest: UserPresenceCredentialDigest,
}

/// Persistable public WebAuthn credential state. It contains no private key.
#[derive(Clone)]
pub struct NativeWebAuthnCredential {
    passkey: PasskeyCredential,
    provider_id: UserPresenceProviderId,
    credential_id: UserPresenceCredentialId,
    user_handle: [u8; 16],
}

impl NativeWebAuthnCredential {
    fn from_passkey(
        passkey: PasskeyCredential,
        user_handle: [u8; 16],
    ) -> Result<Self, UserPresenceWebAuthnError> {
        let credential_id = UserPresenceCredentialId::from_bytes(passkey.id.as_bytes().to_vec())
            .map_err(|_| UserPresenceWebAuthnError::InvalidCredential)?;
        Ok(Self {
            passkey,
            provider_id: provider_id()?,
            credential_id,
            user_handle,
        })
    }

    /// Returns the opaque authenticator credential identifier.
    #[must_use]
    pub const fn credential_id(&self) -> &UserPresenceCredentialId {
        &self.credential_id
    }

    /// Returns the installed provider identifier represented by this document.
    #[must_use]
    pub const fn provider_id(&self) -> &UserPresenceProviderId {
        &self.provider_id
    }

    /// Encodes bounded credential state for owner-protected durable storage.
    ///
    /// # Errors
    ///
    /// Returns an encoding failure when the credential exceeds its hard bound.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UserPresenceWebAuthnError> {
        encode_bounded(&CredentialDocument {
            schema_version: CREDENTIAL_DOCUMENT_VERSION,
            provider: PROVIDER_ID,
            user_handle: self.user_handle,
            passkey: &self.passkey,
        })
    }

    /// Decodes one bounded credential document from trusted local storage.
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceWebAuthnError::InvalidCredential`] for malformed,
    /// oversized, unknown-version, or wrong-provider state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UserPresenceWebAuthnError> {
        let document: OwnedCredentialDocument =
            decode_bounded(bytes, UserPresenceWebAuthnError::InvalidCredential)?;
        if document.schema_version != CREDENTIAL_DOCUMENT_VERSION
            || document.provider != PROVIDER_ID
        {
            return Err(UserPresenceWebAuthnError::InvalidCredential);
        }
        Self::from_passkey(document.passkey, document.user_handle)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialDocument<'a> {
    schema_version: u16,
    provider: &'a str,
    user_handle: [u8; 16],
    passkey: &'a PasskeyCredential,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedCredentialDocument {
    schema_version: u16,
    provider: String,
    user_handle: [u8; 16],
    passkey: PasskeyCredential,
}

#[derive(Deserialize)]
struct StandardRegistrationCredential {
    id: String,
    response: StandardRegistrationResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StandardRegistrationResponse {
    attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Deserialize)]
struct StandardAuthenticationCredential {
    id: String,
    response: StandardAuthenticationResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StandardAuthenticationResponse {
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
    #[serde(default)]
    user_handle: Option<String>,
}

fn registration_response(bytes: &[u8]) -> Result<RegistrationResponse, UserPresenceWebAuthnError> {
    let response: StandardRegistrationCredential =
        decode_bounded(bytes, UserPresenceWebAuthnError::InvalidRegistration)?;
    Ok(RegistrationResponse {
        id: response.id,
        transports: response.response.transports,
        attestation_object: response.response.attestation_object,
        client_data_json: response.response.client_data_json,
    })
}

fn authentication_response(
    bytes: &[u8],
) -> Result<AuthenticationResponse, UserPresenceWebAuthnError> {
    let response: StandardAuthenticationCredential =
        decode_bounded(bytes, UserPresenceWebAuthnError::InvalidAssertion)?;
    Ok(AuthenticationResponse {
        id: response.id,
        authenticator_data: response.response.authenticator_data,
        signature: response.response.signature,
        client_data_json: response.response.client_data_json,
        user_handle: response.response.user_handle,
    })
}

fn installation_user_id(fingerprint: [u8; 32]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(USER_ID_DOMAIN);
    digest.update(fingerprint);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn provider_id() -> Result<UserPresenceProviderId, UserPresenceWebAuthnError> {
    UserPresenceProviderId::parse(PROVIDER_ID)
        .map_err(|_| UserPresenceWebAuthnError::ProviderFailed)
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, UserPresenceWebAuthnError> {
    let bytes = serde_json::to_vec(value).map_err(|_| UserPresenceWebAuthnError::Encoding)?;
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES {
        return Err(UserPresenceWebAuthnError::Encoding);
    }
    Ok(bytes)
}

fn decode_bounded<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    error: UserPresenceWebAuthnError,
) -> Result<T, UserPresenceWebAuthnError> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES {
        return Err(error);
    }
    serde_json::from_slice(bytes).map_err(|_| error)
}

/// Performs one native registration using the service-provided standard request.
///
/// # Errors
///
/// Returns a finite unsupported, cancellation, provider, or encoding failure.
pub fn perform_native_registration(
    request: &NativeWebAuthnRequest,
) -> Result<Vec<u8>, UserPresenceWebAuthnError> {
    #[cfg(windows)]
    {
        use webauthn_authenticator_rs::prelude::{
            CreationChallengeResponse, WebauthnAuthenticator,
        };
        use webauthn_authenticator_rs::win10::Win10;

        let options: CreationChallengeResponse =
            decode_bounded(request.as_json(), UserPresenceWebAuthnError::Encoding)?;
        let origin =
            url::Url::parse(NATIVE_ORIGIN).map_err(|_| UserPresenceWebAuthnError::Encoding)?;
        let mut authenticator = WebauthnAuthenticator::new(Win10::default());
        let response = authenticator
            .do_registration(origin, options)
            .map_err(map_native_error)?;
        encode_bounded(&response)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        Err(UserPresenceWebAuthnError::ProviderUnavailable)
    }
}

/// Performs one native authentication using the service-provided standard request.
///
/// # Errors
///
/// Returns a finite unsupported, cancellation, provider, or encoding failure.
pub fn perform_native_authentication(
    request: &NativeWebAuthnRequest,
) -> Result<Vec<u8>, UserPresenceWebAuthnError> {
    #[cfg(windows)]
    {
        use webauthn_authenticator_rs::prelude::{RequestChallengeResponse, WebauthnAuthenticator};
        use webauthn_authenticator_rs::win10::Win10;

        let options: RequestChallengeResponse =
            decode_bounded(request.as_json(), UserPresenceWebAuthnError::Encoding)?;
        let origin =
            url::Url::parse(NATIVE_ORIGIN).map_err(|_| UserPresenceWebAuthnError::Encoding)?;
        let mut authenticator = WebauthnAuthenticator::new(Win10::default());
        let response = authenticator
            .do_authentication(origin, options)
            .map_err(map_native_error)?;
        encode_bounded(&response)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        Err(UserPresenceWebAuthnError::ProviderUnavailable)
    }
}

#[cfg(windows)]
fn map_native_error(
    error: webauthn_authenticator_rs::error::WebauthnCError,
) -> UserPresenceWebAuthnError {
    use webauthn_authenticator_rs::error::WebauthnCError;

    match error {
        WebauthnCError::Cancelled => UserPresenceWebAuthnError::Cancelled,
        WebauthnCError::NotSupported
        | WebauthnCError::PlatformAuthenticator
        | WebauthnCError::UserVerificationRequired
        | WebauthnCError::NoSelectedToken => UserPresenceWebAuthnError::ProviderUnavailable,
        _ => UserPresenceWebAuthnError::ProviderFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn verifier_configuration_and_user_id_are_stable() {
        let verifier = UserPresenceWebAuthnVerifier::new();
        let (request, _) = verifier.begin_enrollment([0x11; 32], None).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(request.as_json()).unwrap();
        assert_eq!(decoded["publicKey"]["rp"]["id"], RELYING_PARTY_ID);
        assert_eq!(
            installation_user_id([0x11; 32]),
            [
                0x4d, 0x00, 0x09, 0x79, 0x9f, 0x6b, 0x59, 0xd4, 0xbb, 0x5b, 0x76, 0x8d, 0xf5, 0x07,
                0x30, 0x31,
            ]
        );
    }

    #[test]
    fn bounded_documents_fail_closed() {
        let verifier = UserPresenceWebAuthnVerifier::new();
        let (_, enrollment) = verifier.begin_enrollment([0x22; 32], None).unwrap();
        assert_eq!(
            verifier.finish_enrollment(&[], &enrollment).err(),
            Some(UserPresenceWebAuthnError::InvalidRegistration)
        );
        assert_eq!(
            NativeWebAuthnCredential::from_bytes(&vec![0; MAX_NATIVE_WEBAUTHN_DOCUMENT_BYTES + 1])
                .err(),
            Some(UserPresenceWebAuthnError::InvalidCredential)
        );
        #[cfg(not(windows))]
        assert_eq!(
            perform_native_authentication(&NativeWebAuthnRequest {
                challenge: UserPresenceChallenge::from_bytes([0; 32]),
                json: b"{}".to_vec(),
            })
            .err(),
            Some(UserPresenceWebAuthnError::ProviderUnavailable)
        );
    }

    #[test]
    fn synthetic_authenticator_proves_registration_persistence_and_authentication() {
        let (verifier, mut authenticator, mut credential) = enrolled_credential();
        let (authentication_request, authentication) =
            verifier.begin_authentication(&credential).unwrap();
        let assertion = authenticator.authentication_response(&authentication_request, true);
        let verified = verifier
            .finish_authentication(
                &assertion,
                &authentication,
                &mut credential,
                1_700_000_000_000,
            )
            .unwrap();

        assert_eq!(verified.challenge, authentication_request.challenge());
        assert_eq!(verified.provider_id, provider_id().unwrap());
        assert_eq!(
            verified.credential_digest,
            credential.credential_id().digest()
        );
        assert_eq!(
            verified.assertion_digest.as_bytes(),
            &Sha256::digest(&assertion)[..]
        );
    }

    #[test]
    fn user_verification_cannot_be_downgraded_by_the_client() {
        let (verifier, mut authenticator, mut credential) = enrolled_credential();
        let (authentication_request, authentication) =
            verifier.begin_authentication(&credential).unwrap();
        let assertion = authenticator.authentication_response(&authentication_request, false);

        assert_eq!(
            verifier
                .finish_authentication(
                    &assertion,
                    &authentication,
                    &mut credential,
                    1_700_000_000_000,
                )
                .err(),
            Some(UserPresenceWebAuthnError::InvalidAssertion)
        );
    }

    fn enrolled_credential() -> (
        UserPresenceWebAuthnVerifier,
        FakeAuthenticator,
        NativeWebAuthnCredential,
    ) {
        let verifier = UserPresenceWebAuthnVerifier::new();
        let (registration_request, enrollment) =
            verifier.begin_enrollment([0x33; 32], None).unwrap();
        let authenticator = FakeAuthenticator::new();
        let registration = authenticator.registration_response(&registration_request);
        let credential = verifier
            .finish_enrollment(&registration, &enrollment)
            .unwrap();
        let encoded = credential.to_bytes().unwrap();
        let credential = NativeWebAuthnCredential::from_bytes(&encoded).unwrap();
        (verifier, authenticator, credential)
    }

    struct FakeAuthenticator {
        signing_key: ed25519_dalek::SigningKey,
        credential_id: Vec<u8>,
        counter: u32,
    }

    impl FakeAuthenticator {
        fn new() -> Self {
            Self {
                signing_key: ed25519_dalek::SigningKey::from_bytes(&[0x41; 32]),
                credential_id: b"konclave-test-credential".to_vec(),
                counter: 0,
            }
        }

        fn registration_response(&self, request: &NativeWebAuthnRequest) -> Vec<u8> {
            let challenge = request_challenge(request);
            let (_, client_data_json) = client_data("webauthn.create", &challenge);
            let mut authenticator_data = Vec::new();
            authenticator_data.extend_from_slice(&Sha256::digest(RELYING_PARTY_ID.as_bytes()));
            authenticator_data.push(FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_DATA);
            authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
            authenticator_data.extend_from_slice(&[0_u8; 16]);
            authenticator_data.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            authenticator_data.extend_from_slice(&self.credential_id);
            authenticator_data.extend_from_slice(&self.cose_public_key());

            let attestation = ciborium::value::Value::Map(vec![
                (
                    ciborium::value::Value::Text("fmt".into()),
                    ciborium::value::Value::Text("none".into()),
                ),
                (
                    ciborium::value::Value::Text("attStmt".into()),
                    ciborium::value::Value::Map(Vec::new()),
                ),
                (
                    ciborium::value::Value::Text("authData".into()),
                    ciborium::value::Value::Bytes(authenticator_data),
                ),
            ]);
            let mut attestation_bytes = Vec::new();
            ciborium::ser::into_writer(&attestation, &mut attestation_bytes).unwrap();
            standard_registration_json(&self.credential_id, &attestation_bytes, &client_data_json)
        }

        fn authentication_response(
            &mut self,
            request: &NativeWebAuthnRequest,
            user_verified: bool,
        ) -> Vec<u8> {
            use ed25519_dalek::Signer as _;

            self.counter += 1;
            let challenge = request_challenge(request);
            let (client_data_json, encoded_client_data) = client_data("webauthn.get", &challenge);
            let mut authenticator_data = Vec::new();
            authenticator_data.extend_from_slice(&Sha256::digest(RELYING_PARTY_ID.as_bytes()));
            authenticator_data
                .push(FLAG_USER_PRESENT | if user_verified { FLAG_USER_VERIFIED } else { 0 });
            authenticator_data.extend_from_slice(&self.counter.to_be_bytes());
            let mut signed = authenticator_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data_json));
            let signature = self.signing_key.sign(&signed).to_bytes();
            serde_json::to_vec(&serde_json::json!({
                "id": URL_SAFE_NO_PAD.encode(&self.credential_id),
                "rawId": URL_SAFE_NO_PAD.encode(&self.credential_id),
                "type": "public-key",
                "response": {
                    "authenticatorData": URL_SAFE_NO_PAD.encode(authenticator_data),
                    "clientDataJSON": encoded_client_data,
                    "signature": URL_SAFE_NO_PAD.encode(signature),
                    "userHandle": URL_SAFE_NO_PAD.encode(installation_user_id([0x33; 32])),
                }
            }))
            .unwrap()
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let map = ciborium::value::Value::Map(vec![
                (
                    ciborium::value::Value::Integer(1.into()),
                    ciborium::value::Value::Integer(1.into()),
                ),
                (
                    ciborium::value::Value::Integer(3.into()),
                    ciborium::value::Value::Integer((-8).into()),
                ),
                (
                    ciborium::value::Value::Integer((-1).into()),
                    ciborium::value::Value::Integer(6.into()),
                ),
                (
                    ciborium::value::Value::Integer((-2).into()),
                    ciborium::value::Value::Bytes(
                        self.signing_key.verifying_key().to_bytes().to_vec(),
                    ),
                ),
            ]);
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&map, &mut bytes).unwrap();
            bytes
        }
    }

    const FLAG_USER_PRESENT: u8 = 1;
    const FLAG_USER_VERIFIED: u8 = 1 << 2;
    const FLAG_ATTESTED_DATA: u8 = 1 << 6;

    fn request_challenge(request: &NativeWebAuthnRequest) -> String {
        let value: serde_json::Value = serde_json::from_slice(request.as_json()).unwrap();
        value["publicKey"]["challenge"].as_str().unwrap().to_owned()
    }

    fn client_data(kind: &str, challenge: &str) -> (Vec<u8>, String) {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": challenge,
            "origin": NATIVE_ORIGIN,
            "crossOrigin": false,
        }))
        .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        (bytes, encoded)
    }

    fn standard_registration_json(
        credential_id: &[u8],
        attestation_object: &[u8],
        client_data_json: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": URL_SAFE_NO_PAD.encode(credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation_object),
                "clientDataJSON": client_data_json,
                "transports": ["internal"],
            }
        }))
        .unwrap()
    }
}
