use KonclaveClientLibrary::MAX_PAIRING_CAPABILITY_TEXT_BYTES;
use KonclaveCryptographicCore::{
    KonclaveCryptographicError, ShortCodeOpaqueClientLogin, ShortCodeOpaqueServerLogin,
    ShortCodeOpaqueServerRecord, ShortCodeOpaqueSession,
};
use KonclaveDomainCore::{
    DeviceId, PairingId, ShortCodeCapabilityTakeId, ShortCodeConfirmationState,
    ShortCodePairingAttemptId, ShortCodePairingLocator, ShortCodePairingSas,
    ShortCodePairingTranscriptHash,
};
use thiserror::Error;
use zeroize::Zeroizing;

const STATE_MAGIC: &[u8; 4] = b"KSCP";
const STATE_VERSION: u8 = 1;
const MAX_STATE_BYTES: usize = 128 * 1024;
const MAX_OPAQUE_STATE_BYTES: usize = 16 * 1024;
const MAX_STAGE_BYTES: usize = 10 * 1024;

/// This profile's role in one short-code verification exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ShortCodeRole {
    Creator = 1,
    Claimant = 2,
}

/// Durable high-level phase for one short-code verification exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ShortCodePhase {
    CreatorAwaitingClaim = 1,
    CreatorAwaitingFinalization = 2,
    CreatorAwaitingConfirmation = 3,
    CreatorPublishingCapability = 4,
    CreatorCompleted = 5,
    ClaimantClaiming = 6,
    ClaimantAwaitingResponse = 7,
    ClaimantAwaitingCreatorIdentity = 8,
    ClaimantAwaitingConfirmation = 9,
    ClaimantTakingCapability = 10,
    ClaimantCompleted = 11,
    Cancelling = 12,
    Cancelled = 13,
}

impl ShortCodePhase {
    #[must_use]
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CreatorCompleted | Self::ClaimantCompleted | Self::Cancelled
        )
    }
}

/// Secret-bearing durable state stored only inside one sealed profile record.
pub(crate) struct ShortCodeOperationState {
    pub(crate) role: ShortCodeRole,
    pub(crate) phase: ShortCodePhase,
    pub(crate) locator: ShortCodePairingLocator,
    pub(crate) attempt_id: Option<ShortCodePairingAttemptId>,
    pub(crate) deadline_unix_seconds: Option<u64>,
    pub(crate) local_device_id: DeviceId,
    pub(crate) peer_device_id: Option<DeviceId>,
    pub(crate) confirmation: ShortCodeConfirmationState,
    pub(crate) base_transcript_hash: Option<ShortCodePairingTranscriptHash>,
    pub(crate) final_transcript_hash: Option<ShortCodePairingTranscriptHash>,
    pub(crate) sas: Option<ShortCodePairingSas>,
    pub(crate) pairing_id: Option<PairingId>,
    pub(crate) take_id: Option<ShortCodeCapabilityTakeId>,
    pub(crate) server_record: Option<ShortCodeOpaqueServerRecord>,
    pub(crate) client_login: Option<ShortCodeOpaqueClientLogin>,
    pub(crate) server_login: Option<ShortCodeOpaqueServerLogin>,
    pub(crate) session: Option<ShortCodeOpaqueSession>,
    pub(crate) credential_request: Option<Vec<u8>>,
    pub(crate) credential_response: Option<Vec<u8>>,
    pub(crate) claimant_finalization: Option<Vec<u8>>,
    pub(crate) creator_identity: Option<Vec<u8>>,
    pub(crate) local_confirmation: Option<Vec<u8>>,
    pub(crate) capability_payload: Option<Vec<u8>>,
    pub(crate) capability_text: Option<Zeroizing<String>>,
}

impl ShortCodeOperationState {
    pub(crate) fn creator(
        locator: ShortCodePairingLocator,
        attempt_id: ShortCodePairingAttemptId,
        deadline_unix_seconds: u64,
        local_device_id: DeviceId,
        server_record: ShortCodeOpaqueServerRecord,
    ) -> Self {
        Self {
            role: ShortCodeRole::Creator,
            phase: ShortCodePhase::CreatorAwaitingClaim,
            locator,
            attempt_id: Some(attempt_id),
            deadline_unix_seconds: Some(deadline_unix_seconds),
            local_device_id,
            peer_device_id: None,
            confirmation: ShortCodeConfirmationState::AwaitingBoth,
            base_transcript_hash: None,
            final_transcript_hash: None,
            sas: None,
            pairing_id: None,
            take_id: None,
            server_record: Some(server_record),
            client_login: None,
            server_login: None,
            session: None,
            credential_request: None,
            credential_response: None,
            claimant_finalization: None,
            creator_identity: None,
            local_confirmation: None,
            capability_payload: None,
            capability_text: None,
        }
    }

    pub(crate) fn claimant(
        locator: ShortCodePairingLocator,
        local_device_id: DeviceId,
        client_login: ShortCodeOpaqueClientLogin,
        credential_request: Vec<u8>,
    ) -> Self {
        Self {
            role: ShortCodeRole::Claimant,
            phase: ShortCodePhase::ClaimantClaiming,
            locator,
            attempt_id: None,
            deadline_unix_seconds: None,
            local_device_id,
            peer_device_id: None,
            confirmation: ShortCodeConfirmationState::AwaitingBoth,
            base_transcript_hash: None,
            final_transcript_hash: None,
            sas: None,
            pairing_id: None,
            take_id: None,
            server_record: None,
            client_login: Some(client_login),
            server_login: None,
            session: None,
            credential_request: Some(credential_request),
            credential_response: None,
            claimant_finalization: None,
            creator_identity: None,
            local_confirmation: None,
            capability_payload: None,
            capability_text: None,
        }
    }

    /// Encodes exact bounded state for profile sealing.
    ///
    /// # Errors
    ///
    /// Returns a typed state or cryptographic serialization error.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ShortCodeStateError> {
        self.validate()?;
        let mut output = Zeroizing::new(Vec::with_capacity(1024));
        output.extend_from_slice(STATE_MAGIC);
        output.push(STATE_VERSION);
        output.push(self.role as u8);
        output.push(self.phase as u8);
        output.extend_from_slice(self.locator.as_bytes());
        write_optional_fixed(
            &mut output,
            self.attempt_id.map(ShortCodePairingAttemptId::into_bytes),
        );
        write_optional_u64(&mut output, self.deadline_unix_seconds);
        output.extend_from_slice(self.local_device_id.as_bytes());
        write_optional_fixed(&mut output, self.peer_device_id.map(DeviceId::into_bytes));
        output.push(confirmation_to_byte(self.confirmation));
        write_optional_fixed(
            &mut output,
            self.base_transcript_hash
                .map(ShortCodePairingTranscriptHash::into_bytes),
        );
        write_optional_fixed(
            &mut output,
            self.final_transcript_hash
                .map(ShortCodePairingTranscriptHash::into_bytes),
        );
        write_optional_u32(&mut output, self.sas.map(ShortCodePairingSas::value));
        write_optional_fixed(&mut output, self.pairing_id.map(PairingId::into_bytes));
        write_optional_fixed(
            &mut output,
            self.take_id.map(ShortCodeCapabilityTakeId::into_bytes),
        );
        write_opaque_blob(&mut output, self.server_record.as_ref())?;
        write_opaque_blob(&mut output, self.client_login.as_ref())?;
        write_opaque_blob(&mut output, self.server_login.as_ref())?;
        write_opaque_blob(&mut output, self.session.as_ref())?;
        write_blob(&mut output, self.credential_request.as_deref())?;
        write_blob(&mut output, self.credential_response.as_deref())?;
        write_blob(&mut output, self.claimant_finalization.as_deref())?;
        write_blob(&mut output, self.creator_identity.as_deref())?;
        write_blob(&mut output, self.local_confirmation.as_deref())?;
        write_blob(&mut output, self.capability_payload.as_deref())?;
        write_blob(
            &mut output,
            self.capability_text.as_ref().map(|value| value.as_bytes()),
        )?;
        if output.len() > MAX_STATE_BYTES {
            return Err(ShortCodeStateError::InvalidEncoding);
        }
        Ok(output)
    }

    /// Restores and validates one exact sealed-state plaintext.
    ///
    /// # Errors
    ///
    /// Returns a typed malformed, trailing, or cryptographic-state error.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ShortCodeStateError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ShortCodeStateError::InvalidEncoding);
        }
        let mut input = bytes;
        if take::<4>(&mut input)? != *STATE_MAGIC || take_u8(&mut input)? != STATE_VERSION {
            return Err(ShortCodeStateError::InvalidEncoding);
        }
        let role = role_from_byte(take_u8(&mut input)?)?;
        let phase = phase_from_byte(take_u8(&mut input)?)?;
        let locator = ShortCodePairingLocator::from_bytes(take(&mut input)?);
        let attempt_id =
            read_optional_fixed(&mut input)?.map(ShortCodePairingAttemptId::from_bytes);
        let deadline_unix_seconds = read_optional_u64(&mut input)?;
        let local_device_id = DeviceId::from_bytes(take(&mut input)?);
        let peer_device_id = read_optional_fixed(&mut input)?.map(DeviceId::from_bytes);
        let confirmation = confirmation_from_byte(take_u8(&mut input)?)?;
        let base_transcript_hash =
            read_optional_fixed(&mut input)?.map(ShortCodePairingTranscriptHash::from_bytes);
        let final_transcript_hash =
            read_optional_fixed(&mut input)?.map(ShortCodePairingTranscriptHash::from_bytes);
        let sas = read_optional_u32(&mut input)?
            .map(ShortCodePairingSas::new)
            .transpose()
            .map_err(|_| ShortCodeStateError::InvalidEncoding)?;
        let pairing_id = read_optional_fixed(&mut input)?.map(PairingId::from_bytes);
        let take_id = read_optional_fixed(&mut input)?.map(ShortCodeCapabilityTakeId::from_bytes);
        let server_record = read_blob(&mut input, MAX_OPAQUE_STATE_BYTES)?
            .map(|bytes| ShortCodeOpaqueServerRecord::from_bytes(&bytes))
            .transpose()?;
        let client_login = read_blob(&mut input, MAX_OPAQUE_STATE_BYTES)?
            .map(|bytes| ShortCodeOpaqueClientLogin::from_bytes(&bytes))
            .transpose()?;
        let server_login = read_blob(&mut input, MAX_OPAQUE_STATE_BYTES)?
            .map(|bytes| ShortCodeOpaqueServerLogin::from_bytes(&bytes))
            .transpose()?;
        let session = read_blob(&mut input, MAX_OPAQUE_STATE_BYTES)?
            .map(|bytes| ShortCodeOpaqueSession::from_bytes(&bytes))
            .transpose()?;
        let credential_request = read_blob(&mut input, MAX_STAGE_BYTES)?;
        let credential_response = read_blob(&mut input, MAX_STAGE_BYTES)?;
        let claimant_finalization = read_blob(&mut input, MAX_STAGE_BYTES)?;
        let creator_identity = read_blob(&mut input, MAX_STAGE_BYTES)?;
        let local_confirmation = read_blob(&mut input, MAX_STAGE_BYTES)?;
        let capability_payload = read_blob(&mut input, MAX_STAGE_BYTES)?;
        let capability_text = read_blob(&mut input, MAX_PAIRING_CAPABILITY_TEXT_BYTES)?
            .map(|bytes| String::from_utf8(bytes).map(Zeroizing::new))
            .transpose()
            .map_err(|_| ShortCodeStateError::InvalidEncoding)?;
        if !input.is_empty() {
            return Err(ShortCodeStateError::InvalidEncoding);
        }
        let state = Self {
            role,
            phase,
            locator,
            attempt_id,
            deadline_unix_seconds,
            local_device_id,
            peer_device_id,
            confirmation,
            base_transcript_hash,
            final_transcript_hash,
            sas,
            pairing_id,
            take_id,
            server_record,
            client_login,
            server_login,
            session,
            credential_request,
            credential_response,
            claimant_finalization,
            creator_identity,
            local_confirmation,
            capability_payload,
            capability_text,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), ShortCodeStateError> {
        let role_matches = match self.role {
            ShortCodeRole::Creator => matches!(
                self.phase,
                ShortCodePhase::CreatorAwaitingClaim
                    | ShortCodePhase::CreatorAwaitingFinalization
                    | ShortCodePhase::CreatorAwaitingConfirmation
                    | ShortCodePhase::CreatorPublishingCapability
                    | ShortCodePhase::CreatorCompleted
                    | ShortCodePhase::Cancelling
                    | ShortCodePhase::Cancelled
            ),
            ShortCodeRole::Claimant => matches!(
                self.phase,
                ShortCodePhase::ClaimantClaiming
                    | ShortCodePhase::ClaimantAwaitingResponse
                    | ShortCodePhase::ClaimantAwaitingCreatorIdentity
                    | ShortCodePhase::ClaimantAwaitingConfirmation
                    | ShortCodePhase::ClaimantTakingCapability
                    | ShortCodePhase::ClaimantCompleted
                    | ShortCodePhase::Cancelling
                    | ShortCodePhase::Cancelled
            ),
        };
        let attempt_metadata_valid = match self.phase {
            ShortCodePhase::ClaimantClaiming => {
                self.attempt_id.is_none() && self.deadline_unix_seconds.is_none()
            }
            ShortCodePhase::Cancelled
                if self.role == ShortCodeRole::Claimant && self.attempt_id.is_none() =>
            {
                true
            }
            _ => self.attempt_id.is_some() && self.deadline_unix_seconds.is_some(),
        };
        let verified_fields = (
            self.peer_device_id.is_some(),
            self.final_transcript_hash.is_some(),
            self.sas.is_some(),
        );
        let verified_fields_valid =
            verified_fields == (false, false, false) || verified_fields == (true, true, true);
        let cancellation_valid = matches!(
            self.phase,
            ShortCodePhase::Cancelling | ShortCodePhase::Cancelled
        ) == (self.confirmation == ShortCodeConfirmationState::Cancelled);
        if !role_matches
            || !attempt_metadata_valid
            || !verified_fields_valid
            || !cancellation_valid
            || self.base_transcript_hash.is_some() != self.session.is_some()
            || self.final_transcript_hash.is_some() && self.base_transcript_hash.is_none()
            || self.local_confirmation.is_some()
                && !matches!(
                    self.confirmation,
                    ShortCodeConfirmationState::AwaitingPeer
                        | ShortCodeConfirmationState::Confirmed
                )
            || self.take_id.is_some() && self.role != ShortCodeRole::Claimant
            || self.capability_text.is_some() && self.pairing_id.is_none()
        {
            return Err(ShortCodeStateError::InvalidEncoding);
        }
        Ok(())
    }
}

trait OpaqueState {
    fn write_state(&self, output: &mut Vec<u8>) -> Result<(), KonclaveCryptographicError>;
}

impl OpaqueState for ShortCodeOpaqueServerRecord {
    fn write_state(&self, output: &mut Vec<u8>) -> Result<(), KonclaveCryptographicError> {
        self.write_to(output)
    }
}

impl OpaqueState for ShortCodeOpaqueClientLogin {
    fn write_state(&self, output: &mut Vec<u8>) -> Result<(), KonclaveCryptographicError> {
        self.write_to(output)
    }
}

impl OpaqueState for ShortCodeOpaqueServerLogin {
    fn write_state(&self, output: &mut Vec<u8>) -> Result<(), KonclaveCryptographicError> {
        self.write_to(output)
    }
}

impl OpaqueState for ShortCodeOpaqueSession {
    fn write_state(&self, output: &mut Vec<u8>) -> Result<(), KonclaveCryptographicError> {
        self.write_to(output)
    }
}

fn serialized<T: OpaqueState>(
    value: Option<&T>,
) -> Result<Option<Zeroizing<Vec<u8>>>, ShortCodeStateError> {
    value
        .map(|value| {
            let mut output = Zeroizing::new(Vec::new());
            value.write_state(&mut output)?;
            Ok(output)
        })
        .transpose()
}

fn write_opaque_blob<T: OpaqueState>(
    output: &mut Vec<u8>,
    value: Option<&T>,
) -> Result<(), ShortCodeStateError> {
    let value = serialized(value)?;
    write_blob(output, value.as_ref().map(|value| value.as_slice()))
}

fn write_optional_fixed<const N: usize>(output: &mut Vec<u8>, value: Option<[u8; N]>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value);
        }
        None => output.push(0),
    }
}

fn write_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn write_optional_u32(output: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn write_blob(output: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), ShortCodeStateError> {
    let length = value.map_or(0, <[u8]>::len);
    if length > u32::MAX as usize {
        return Err(ShortCodeStateError::InvalidEncoding);
    }
    output.extend_from_slice(&(length as u32).to_be_bytes());
    if let Some(value) = value {
        if value.is_empty() {
            return Err(ShortCodeStateError::InvalidEncoding);
        }
        output.extend_from_slice(value);
    }
    Ok(())
}

fn read_optional_fixed<const N: usize>(
    input: &mut &[u8],
) -> Result<Option<[u8; N]>, ShortCodeStateError> {
    match take_u8(input)? {
        0 => Ok(None),
        1 => Ok(Some(take(input)?)),
        _ => Err(ShortCodeStateError::InvalidEncoding),
    }
}

fn read_optional_u64(input: &mut &[u8]) -> Result<Option<u64>, ShortCodeStateError> {
    match take_u8(input)? {
        0 => Ok(None),
        1 => Ok(Some(u64::from_be_bytes(take(input)?))),
        _ => Err(ShortCodeStateError::InvalidEncoding),
    }
}

fn read_optional_u32(input: &mut &[u8]) -> Result<Option<u32>, ShortCodeStateError> {
    match take_u8(input)? {
        0 => Ok(None),
        1 => Ok(Some(u32::from_be_bytes(take(input)?))),
        _ => Err(ShortCodeStateError::InvalidEncoding),
    }
}

fn read_blob(input: &mut &[u8], maximum: usize) -> Result<Option<Vec<u8>>, ShortCodeStateError> {
    let length = usize::try_from(u32::from_be_bytes(take(input)?))
        .map_err(|_| ShortCodeStateError::InvalidEncoding)?;
    if length == 0 {
        return Ok(None);
    }
    if length > maximum || input.len() < length {
        return Err(ShortCodeStateError::InvalidEncoding);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(Some(value.to_vec()))
}

fn take_u8(input: &mut &[u8]) -> Result<u8, ShortCodeStateError> {
    let (value, rest) = input
        .split_first()
        .ok_or(ShortCodeStateError::InvalidEncoding)?;
    *input = rest;
    Ok(*value)
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], ShortCodeStateError> {
    if input.len() < N {
        return Err(ShortCodeStateError::InvalidEncoding);
    }
    let (value, rest) = input.split_at(N);
    *input = rest;
    value
        .try_into()
        .map_err(|_| ShortCodeStateError::InvalidEncoding)
}

const fn confirmation_to_byte(value: ShortCodeConfirmationState) -> u8 {
    match value {
        ShortCodeConfirmationState::AwaitingBoth => 1,
        ShortCodeConfirmationState::AwaitingLocal => 2,
        ShortCodeConfirmationState::AwaitingPeer => 3,
        ShortCodeConfirmationState::Confirmed => 4,
        ShortCodeConfirmationState::Cancelled => 5,
    }
}

fn confirmation_from_byte(value: u8) -> Result<ShortCodeConfirmationState, ShortCodeStateError> {
    match value {
        1 => Ok(ShortCodeConfirmationState::AwaitingBoth),
        2 => Ok(ShortCodeConfirmationState::AwaitingLocal),
        3 => Ok(ShortCodeConfirmationState::AwaitingPeer),
        4 => Ok(ShortCodeConfirmationState::Confirmed),
        5 => Ok(ShortCodeConfirmationState::Cancelled),
        _ => Err(ShortCodeStateError::InvalidEncoding),
    }
}

fn role_from_byte(value: u8) -> Result<ShortCodeRole, ShortCodeStateError> {
    match value {
        1 => Ok(ShortCodeRole::Creator),
        2 => Ok(ShortCodeRole::Claimant),
        _ => Err(ShortCodeStateError::InvalidEncoding),
    }
}

fn phase_from_byte(value: u8) -> Result<ShortCodePhase, ShortCodeStateError> {
    match value {
        1 => Ok(ShortCodePhase::CreatorAwaitingClaim),
        2 => Ok(ShortCodePhase::CreatorAwaitingFinalization),
        3 => Ok(ShortCodePhase::CreatorAwaitingConfirmation),
        4 => Ok(ShortCodePhase::CreatorPublishingCapability),
        5 => Ok(ShortCodePhase::CreatorCompleted),
        6 => Ok(ShortCodePhase::ClaimantClaiming),
        7 => Ok(ShortCodePhase::ClaimantAwaitingResponse),
        8 => Ok(ShortCodePhase::ClaimantAwaitingCreatorIdentity),
        9 => Ok(ShortCodePhase::ClaimantAwaitingConfirmation),
        10 => Ok(ShortCodePhase::ClaimantTakingCapability),
        11 => Ok(ShortCodePhase::ClaimantCompleted),
        12 => Ok(ShortCodePhase::Cancelling),
        13 => Ok(ShortCodePhase::Cancelled),
        _ => Err(ShortCodeStateError::InvalidEncoding),
    }
}

/// Stable failures from sealed short-code operation state.
#[derive(Debug, Error)]
pub(crate) enum ShortCodeStateError {
    #[error("short-code operation state is malformed")]
    InvalidEncoding,
    #[error(transparent)]
    Cryptographic(#[from] KonclaveCryptographicError),
}

#[cfg(test)]
mod tests {
    use KonclaveCryptographicCore::ShortCodePairingCode;

    use super::*;

    #[test]
    fn creator_and_claimant_state_round_trip_without_debug_or_clone() {
        let attempt = ShortCodePairingAttemptId::from_bytes([1; 16]);
        let code = ShortCodePairingCode::parse("123456").unwrap();
        let creator = ShortCodeOperationState::creator(
            code.locator(),
            attempt,
            100,
            DeviceId::from_bytes([2; 32]),
            ShortCodeOpaqueServerRecord::register(&code, attempt).unwrap(),
        );
        let encoded = creator.encode().unwrap();
        let decoded = ShortCodeOperationState::decode(&encoded).unwrap();
        assert_eq!(decoded.role, ShortCodeRole::Creator);
        assert_eq!(decoded.attempt_id, Some(attempt));

        let (login, request) =
            ShortCodeOpaqueClientLogin::start(ShortCodePairingCode::parse("123456").unwrap())
                .unwrap();
        let claimant = ShortCodeOperationState::claimant(
            code.locator(),
            DeviceId::from_bytes([3; 32]),
            login,
            request,
        );
        let encoded = claimant.encode().unwrap();
        let decoded = ShortCodeOperationState::decode(&encoded).unwrap();
        assert_eq!(decoded.role, ShortCodeRole::Claimant);
        assert_eq!(decoded.phase, ShortCodePhase::ClaimantClaiming);
    }

    #[test]
    fn malformed_trailing_and_inconsistent_state_fail_closed() {
        assert!(ShortCodeOperationState::decode(&[]).is_err());
        let code = ShortCodePairingCode::parse("123456").unwrap();
        let attempt = ShortCodePairingAttemptId::from_bytes([1; 16]);
        let state = ShortCodeOperationState::creator(
            code.locator(),
            attempt,
            100,
            DeviceId::from_bytes([2; 32]),
            ShortCodeOpaqueServerRecord::register(&code, attempt).unwrap(),
        );
        let mut encoded = state.encode().unwrap();
        encoded.push(0);
        assert!(ShortCodeOperationState::decode(&encoded).is_err());
    }
}
