use std::collections::BTreeSet;

use KonclaveClientLibrary::{KonclaveClientError, PairingCapability};
use KonclaveCryptographicCore::fill_random;
use KonclaveDomainCore::{
    ConversationId, DeliveryClass, EnvelopeId, PairingEnvelope, PairingMessageId,
    PairingSenderRole, PairingStage, ProtocolVersion, RelayEnvelope, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::KonclaveProtocolError;
use KonclaveProtocolContracts::v1::{
    decode_pairing_envelope, decode_relay_envelope, decode_stored_relay_envelope,
    encode_pairing_envelope, encode_relay_envelope, encode_stored_relay_envelope,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::persistence::pairing::{PairingCheckpoint, PairingRole};

const STATE_VERSION: u8 = 1;
const MAX_OBSERVATIONS: usize = 8;
const MAX_OUTBOUNDS: usize = 8;
const MAX_CAPABILITY_BYTES: usize = 8 * 1024;
const MAX_ENCODED_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_ENCODED_STORED_ENVELOPE_BYTES: usize = MAX_ENCODED_ENVELOPE_BYTES + 64;

/// Maximum plaintext bytes accepted for one sealed pairing checkpoint.
pub(crate) const MAX_PAIRING_STATE_BYTES: usize = 4 * 1024 * 1024;

/// Result of applying one authenticated relay observation.
pub(crate) enum PairingObservationResult {
    /// A new remote logical record was added to durable state.
    Added(Zeroizing<Vec<u8>>),
    /// An exact logical record was already present.
    Duplicate(Zeroizing<Vec<u8>>),
    /// This profile observed the exact outer envelope it submitted earlier.
    LocalEcho,
}

/// One prepared pairing submission and its optional relay acceptance.
pub(crate) struct PairingOutbound {
    envelope: RelayEnvelope,
    accepted_cursor: Option<u64>,
}

/// One authenticated pairing record opened from sealed operation state.
///
/// Plaintext is zeroized on drop and this type intentionally implements neither
/// `Clone` nor `Debug`.
pub(crate) struct OpenedPairingRecord {
    envelope: PairingEnvelope,
    plaintext: Zeroizing<Vec<u8>>,
}

impl OpenedPairingRecord {
    pub(crate) const fn envelope(&self) -> &PairingEnvelope {
        &self.envelope
    }

    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

impl PairingOutbound {
    pub(crate) fn envelope(&self) -> &RelayEnvelope {
        &self.envelope
    }

    pub(crate) const fn accepted_cursor(&self) -> Option<u64> {
        self.accepted_cursor
    }

    pub(crate) fn pairing_envelope(&self) -> Result<PairingEnvelope, PairingStateError> {
        decode_pairing_envelope(self.envelope.payload()).map_err(Into::into)
    }
}

/// Secret-bearing durable state encoded inside one sealed pairing checkpoint.
///
/// The transferable capability and decrypted stage payloads never cross into SQLite
/// plaintext. This type implements neither `Clone` nor `Debug`; temporary encodings
/// are zeroized.
///
/// Envelope authentication proves possession of the shared capability, not endpoint
/// role: either holder can derive both directional keys. The later phase handler must
/// verify the root-signed invitation, JoinProof credential, MLS Welcome receipt, and
/// signed completion/cancellation payload before authorizing a transition.
pub(crate) struct PairingOperationState {
    role: PairingRole,
    capability: PairingCapability,
    conversation_id: Option<ConversationId>,
    observations: Vec<StoredRelayEnvelope>,
    outbounds: Vec<PairingOutbound>,
}

impl PairingOperationState {
    pub(crate) fn new(role: PairingRole, capability: PairingCapability) -> Self {
        Self {
            role,
            capability,
            conversation_id: None,
            observations: Vec::new(),
            outbounds: Vec::new(),
        }
    }

    pub(crate) fn from_checkpoint(
        checkpoint: &PairingCheckpoint,
    ) -> Result<Self, PairingStateError> {
        let state = Self::decode(&checkpoint.state)?;
        let schedule = state.capability.key_schedule()?;
        if state.role != checkpoint.role
            || state.capability.offer().pairing_id() != checkpoint.pairing_id
            || schedule.routing_id() != checkpoint.routing_id
            || state.capability.offer().expires_at_unix_seconds()
                != checkpoint.authorization_deadline_unix_seconds
            || state
                .observations
                .last()
                .is_some_and(|observed| observed.cursor() > checkpoint.replay_cursor)
        {
            return Err(PairingStateError::CheckpointMismatch);
        }
        Ok(state)
    }

    pub(crate) const fn role(&self) -> PairingRole {
        self.role
    }

    pub(crate) const fn conversation_id(&self) -> Option<ConversationId> {
        self.conversation_id
    }

    pub(crate) fn capability(&self) -> &PairingCapability {
        &self.capability
    }

    pub(crate) fn set_conversation_id(
        &mut self,
        conversation_id: ConversationId,
    ) -> Result<(), PairingStateError> {
        match self.conversation_id {
            None => {
                self.conversation_id = Some(conversation_id);
                Ok(())
            }
            Some(existing) if existing == conversation_id => Ok(()),
            Some(_) => Err(PairingStateError::Conflict),
        }
    }

    pub(crate) fn observations(&self) -> &[StoredRelayEnvelope] {
        &self.observations
    }

    pub(crate) fn outbounds(&self) -> &[PairingOutbound] {
        &self.outbounds
    }

    /// Opens the authenticated remote record for one stage, when observed.
    ///
    /// # Errors
    ///
    /// Returns a protocol or authentication error for malformed sealed state.
    pub(crate) fn remote_record(
        &self,
        stage: PairingStage,
    ) -> Result<Option<OpenedPairingRecord>, PairingStateError> {
        for observed in &self.observations {
            let envelope = decode_pairing_envelope(observed.envelope().payload())?;
            if envelope.stage() == stage {
                let plaintext = self.capability.key_schedule()?.open(&envelope)?;
                return Ok(Some(OpenedPairingRecord {
                    envelope,
                    plaintext,
                }));
            }
        }
        Ok(None)
    }

    /// Opens the authenticated local record prepared for one stage, when present.
    ///
    /// # Errors
    ///
    /// Returns a protocol or authentication error for malformed sealed state.
    pub(crate) fn local_record(
        &self,
        stage: PairingStage,
    ) -> Result<Option<OpenedPairingRecord>, PairingStateError> {
        for outbound in &self.outbounds {
            let envelope = outbound.pairing_envelope()?;
            if envelope.stage() == stage {
                let plaintext = self.capability.key_schedule()?.open(&envelope)?;
                return Ok(Some(OpenedPairingRecord {
                    envelope,
                    plaintext,
                }));
            }
        }
        Ok(None)
    }

    /// Creates and journals one exact outbound pairing envelope before submission.
    ///
    /// # Errors
    ///
    /// Returns a capacity, duplicate-stage, cryptographic, protocol, or domain error.
    pub(crate) fn prepare_outbound(
        &mut self,
        stage: PairingStage,
        in_reply_to: Option<PairingMessageId>,
        expires_at_unix_seconds: u64,
        plaintext: &[u8],
    ) -> Result<PairingMessageId, PairingStateError> {
        let message_id = generate_pairing_message_id()?;
        self.prepare_outbound_with_id(
            message_id,
            stage,
            in_reply_to,
            expires_at_unix_seconds,
            plaintext,
        )?;
        Ok(message_id)
    }

    /// Journals one outbound with a caller-reserved logical identifier.
    ///
    /// This is used when the identifier must be covered by a root signature inside
    /// the encrypted payload. The identifier remains random and is supplied only
    /// after [`generate_pairing_message_id`] succeeds.
    ///
    /// # Errors
    ///
    /// Returns a capacity, duplicate-stage, cryptographic, protocol, or domain error.
    pub(crate) fn prepare_outbound_with_id(
        &mut self,
        message_id: PairingMessageId,
        stage: PairingStage,
        in_reply_to: Option<PairingMessageId>,
        expires_at_unix_seconds: u64,
        plaintext: &[u8],
    ) -> Result<(), PairingStateError> {
        if self.outbounds.len() >= MAX_OUTBOUNDS {
            return Err(PairingStateError::Capacity);
        }
        for existing in &self.outbounds {
            if existing.pairing_envelope()?.stage() == stage {
                return Err(PairingStateError::Conflict);
            }
        }
        let sender = local_sender(self.role);
        let pairing = self.capability.key_schedule()?.seal(
            message_id,
            sender,
            stage,
            in_reply_to,
            expires_at_unix_seconds,
            plaintext,
        )?;
        let payload = encode_pairing_envelope(&pairing)?;
        let mut envelope_id = [0_u8; EnvelopeId::LENGTH];
        fill_random(&mut envelope_id)?;
        let envelope = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            self.capability.key_schedule()?.routing_id(),
            EnvelopeId::from_bytes(envelope_id),
            DeliveryClass::Pairing,
            None,
            expires_at_unix_seconds,
            payload,
        )?;
        self.outbounds.push(PairingOutbound {
            envelope,
            accepted_cursor: None,
        });
        Ok(())
    }

    /// Marks one prepared outbound record accepted by the relay.
    ///
    /// The same cursor is idempotent. A different cursor for the same logical message
    /// is relay equivocation and fails closed.
    pub(crate) fn mark_outbound_accepted(
        &mut self,
        message_id: PairingMessageId,
        cursor: u64,
    ) -> Result<(), PairingStateError> {
        if cursor == 0 {
            return Err(PairingStateError::InvalidEncoding);
        }

        if self
            .observations
            .iter()
            .any(|observation| observation.cursor() == cursor)
        {
            return Err(PairingStateError::Conflict);
        }
        let index = self
            .outbounds
            .iter()
            .position(|outbound| {
                outbound
                    .pairing_envelope()
                    .is_ok_and(|envelope| envelope.message_id() == message_id)
            })
            .ok_or(PairingStateError::OperationNotFound)?;
        if self
            .outbounds
            .iter()
            .enumerate()
            .any(|(other, outbound)| other != index && outbound.accepted_cursor == Some(cursor))
        {
            return Err(PairingStateError::Conflict);
        }
        let outbound = &mut self.outbounds[index];
        match outbound.accepted_cursor {
            None => {
                outbound.accepted_cursor = Some(cursor);
                Ok(())
            }
            Some(existing) if existing == cursor => Ok(()),
            Some(_) => Err(PairingStateError::Conflict),
        }
    }

    /// Authenticates and applies one relay observation.
    ///
    /// Invalid ciphertext returns without mutating state. An exact remote logical
    /// record under another relay cursor is an idempotent duplicate. Reusing its
    /// message identifier for different authenticated content is a conflict.
    ///
    /// # Errors
    ///
    /// Returns a bounded validation, authentication, capacity, or conflict error.
    pub(crate) fn observe(
        &mut self,
        stored: &StoredRelayEnvelope,
    ) -> Result<PairingObservationResult, PairingStateError> {
        if stored.cursor() == 0 {
            return Err(PairingStateError::Conflict);
        }
        validate_outer_envelope(&self.capability, stored.envelope())?;
        let pairing = decode_pairing_envelope(stored.envelope().payload())?;
        if pairing.expires_at_unix_seconds() != stored.envelope().expires_at_unix_seconds() {
            return Err(PairingStateError::Conflict);
        }
        let plaintext = self.capability.key_schedule()?.open(&pairing)?;

        if pairing.sender() == local_sender(self.role) {
            let index = self
                .outbounds
                .iter()
                .position(|outbound| {
                    outbound
                        .pairing_envelope()
                        .is_ok_and(|candidate| candidate.message_id() == pairing.message_id())
                })
                .ok_or(PairingStateError::UnexpectedSender)?;
            if self
                .observations
                .iter()
                .any(|observation| observation.cursor() == stored.cursor())
                || self.outbounds.iter().enumerate().any(|(other, outbound)| {
                    other != index && outbound.accepted_cursor == Some(stored.cursor())
                })
            {
                return Err(PairingStateError::Conflict);
            }
            let outbound = &mut self.outbounds[index];
            if outbound.envelope != *stored.envelope() {
                return Err(PairingStateError::Conflict);
            }
            match outbound.accepted_cursor {
                None => outbound.accepted_cursor = Some(stored.cursor()),
                Some(cursor) if cursor == stored.cursor() => {}
                Some(_) => return Err(PairingStateError::Conflict),
            }
            return Ok(PairingObservationResult::LocalEcho);
        }

        let expected_remote = match self.role {
            PairingRole::Joiner => PairingSenderRole::Inviter,
            PairingRole::Inviter => PairingSenderRole::Joiner,
        };
        if pairing.sender() != expected_remote {
            return Err(PairingStateError::UnexpectedSender);
        }
        if self
            .outbounds
            .iter()
            .any(|outbound| outbound.accepted_cursor == Some(stored.cursor()))
        {
            return Err(PairingStateError::Conflict);
        }
        for observed in &self.observations {
            let existing = decode_pairing_envelope(observed.envelope().payload())?;
            if existing.message_id() == pairing.message_id() {
                if existing == pairing {
                    return Ok(PairingObservationResult::Duplicate(plaintext));
                }
                return Err(PairingStateError::Conflict);
            }
            if existing.stage() == pairing.stage() {
                return Err(PairingStateError::Conflict);
            }
            if observed.cursor() == stored.cursor() {
                return Err(PairingStateError::Conflict);
            }
        }
        if self
            .observations
            .last()
            .is_some_and(|observed| stored.cursor() <= observed.cursor())
        {
            return Err(PairingStateError::Conflict);
        }
        if self.observations.len() >= MAX_OBSERVATIONS {
            return Err(PairingStateError::Capacity);
        }
        self.observations.push(stored.clone());
        Ok(PairingObservationResult::Added(plaintext))
    }

    /// Encodes the complete bounded checkpoint plaintext.
    ///
    /// # Errors
    ///
    /// Returns a client, protocol, bounds, or state-consistency error.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PairingStateError> {
        validate_loaded_state(self)?;
        let capability = self.capability.encode()?;
        let observations = self
            .observations
            .iter()
            .map(encode_stored_relay_envelope)
            .collect::<Result<Vec<_>, _>>()?;
        let outbounds = self
            .outbounds
            .iter()
            .map(|outbound| encode_relay_envelope(&outbound.envelope))
            .collect::<Result<Vec<_>, _>>()?;
        let mut total = 2_usize;
        total = encoded_bytes_length(total, capability.as_str().len())?;
        total = total
            .checked_add(1 + self.conversation_id.map_or(0, |_| ConversationId::LENGTH))
            .and_then(|value| value.checked_add(1))
            .ok_or(PairingStateError::Capacity)?;
        for encoded in &observations {
            total = encoded_bytes_length(total, encoded.len())?;
        }
        total = total.checked_add(1).ok_or(PairingStateError::Capacity)?;
        for (outbound, encoded) in self.outbounds.iter().zip(&outbounds) {
            total = encoded_bytes_length(total, encoded.len())?
                .checked_add(1 + outbound.accepted_cursor.map_or(0, |_| 8))
                .ok_or(PairingStateError::Capacity)?;
        }
        if total > MAX_PAIRING_STATE_BYTES {
            return Err(PairingStateError::Capacity);
        }

        // Allocate exactly once before copying the bearer capability. Reallocating
        // afterwards could leave a freed heap copy that Zeroizing no longer owns.
        let mut output = Zeroizing::new(Vec::with_capacity(total));
        output.push(STATE_VERSION);
        output.push(self.role as u8);
        append_bytes(
            &mut output,
            capability.as_str().as_bytes(),
            MAX_CAPABILITY_BYTES,
        )?;
        match self.conversation_id {
            Some(conversation_id) => {
                output.push(1);
                output.extend_from_slice(conversation_id.as_bytes());
            }
            None => output.push(0),
        }
        output
            .push(u8::try_from(self.observations.len()).map_err(|_| PairingStateError::Capacity)?);
        for encoded in &observations {
            append_bytes(&mut output, encoded, MAX_ENCODED_STORED_ENVELOPE_BYTES)?;
        }
        output.push(u8::try_from(self.outbounds.len()).map_err(|_| PairingStateError::Capacity)?);
        for (outbound, encoded) in self.outbounds.iter().zip(&outbounds) {
            append_bytes(&mut output, encoded, MAX_ENCODED_ENVELOPE_BYTES)?;
            match outbound.accepted_cursor {
                Some(cursor) => {
                    output.push(1);
                    output.extend_from_slice(&cursor.to_be_bytes());
                }
                None => output.push(0),
            }
        }
        debug_assert_eq!(output.len(), total);
        Ok(output)
    }

    /// Decodes and validates one bounded checkpoint plaintext.
    ///
    /// # Errors
    ///
    /// Returns a bounded framing, capability, protocol, or consistency error before
    /// the state is made available to orchestration.
    fn decode(bytes: &[u8]) -> Result<Self, PairingStateError> {
        if bytes.is_empty() || bytes.len() > MAX_PAIRING_STATE_BYTES {
            return Err(PairingStateError::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        if reader.read_u8()? != STATE_VERSION {
            return Err(PairingStateError::InvalidEncoding);
        }
        let role = decode_role(reader.read_u8()?)?;
        let capability_bytes = reader.read_bytes(MAX_CAPABILITY_BYTES)?;
        let capability_text = std::str::from_utf8(capability_bytes)
            .map_err(|_| PairingStateError::InvalidEncoding)?;
        // Zero is deliberate: persistence re-authenticates the signed capability but
        // the pairing phase and its two deadlines own current-time policy.
        let capability = PairingCapability::decode(capability_text, 0)?;
        let conversation_id = match reader.read_u8()? {
            0 => None,
            1 => Some(ConversationId::from_slice(
                reader.read_exact(ConversationId::LENGTH)?,
            )?),
            _ => return Err(PairingStateError::InvalidEncoding),
        };
        let observation_count = usize::from(reader.read_u8()?);
        if observation_count > MAX_OBSERVATIONS {
            return Err(PairingStateError::Capacity);
        }
        let mut observations = Vec::with_capacity(observation_count);
        for _ in 0..observation_count {
            let encoded = reader.read_bytes(MAX_ENCODED_STORED_ENVELOPE_BYTES)?;
            observations.push(decode_stored_relay_envelope(encoded)?);
        }
        let outbound_count = usize::from(reader.read_u8()?);
        if outbound_count > MAX_OUTBOUNDS {
            return Err(PairingStateError::Capacity);
        }
        let mut outbounds = Vec::with_capacity(outbound_count);
        for _ in 0..outbound_count {
            let envelope = decode_relay_envelope(reader.read_bytes(MAX_ENCODED_ENVELOPE_BYTES)?)?;
            let accepted_cursor = match reader.read_u8()? {
                0 => None,
                1 => {
                    let cursor = reader.read_u64()?;
                    if cursor == 0 {
                        return Err(PairingStateError::InvalidEncoding);
                    }
                    Some(cursor)
                }
                _ => return Err(PairingStateError::InvalidEncoding),
            };
            outbounds.push(PairingOutbound {
                envelope,
                accepted_cursor,
            });
        }
        reader.finish()?;
        let state = Self {
            role,
            capability,
            conversation_id,
            observations,
            outbounds,
        };
        validate_loaded_state(&state)?;
        Ok(state)
    }
}

/// Generates a random logical identifier before a signed control is constructed.
///
/// # Errors
///
/// Returns a cryptographic provider error when secure randomness is unavailable.
pub(crate) fn generate_pairing_message_id()
-> Result<PairingMessageId, KonclaveCryptographicCore::KonclaveCryptographicError> {
    let mut message_id = [0_u8; PairingMessageId::LENGTH];
    fill_random(&mut message_id)?;
    Ok(PairingMessageId::from_bytes(message_id))
}

/// Stable bounded failures from pairing state encoding and transitions.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum PairingStateError {
    #[error("pairing state encoding is invalid")]
    InvalidEncoding,
    #[error("pairing state capacity is exceeded")]
    Capacity,
    #[error("pairing state conflicts with a prior logical record")]
    Conflict,
    #[error("pairing state belongs to another checkpoint")]
    CheckpointMismatch,
    #[error("pairing record has an unexpected sender")]
    UnexpectedSender,
    #[error("pairing operation is not found")]
    OperationNotFound,
    #[error(transparent)]
    Client(#[from] KonclaveClientError),
    #[error(transparent)]
    Cryptographic(#[from] KonclaveCryptographicCore::KonclaveCryptographicError),
    #[error(transparent)]
    Domain(#[from] KonclaveDomainCore::KonclaveDomainError),
    #[error(transparent)]
    Protocol(#[from] KonclaveProtocolError),
}

fn validate_loaded_state(state: &PairingOperationState) -> Result<(), PairingStateError> {
    if state.observations.len() > MAX_OBSERVATIONS || state.outbounds.len() > MAX_OUTBOUNDS {
        return Err(PairingStateError::Capacity);
    }
    let pairing_id = state.capability.offer().pairing_id();
    let routing_id = state.capability.key_schedule()?.routing_id();
    let mut observed_messages = BTreeSet::new();
    let mut observed_stages = Vec::new();
    let mut used_relay_cursors = BTreeSet::new();
    let mut prior_observed_cursor = 0;
    for observation in &state.observations {
        validate_outer_envelope(&state.capability, observation.envelope())?;
        let pairing = decode_pairing_envelope(observation.envelope().payload())?;
        if pairing.pairing_id() != pairing_id
            || pairing.sender() == local_sender(state.role)
            || pairing.expires_at_unix_seconds() != observation.envelope().expires_at_unix_seconds()
            || observation.cursor() <= prior_observed_cursor
            || !observed_messages.insert(pairing.message_id())
            || observed_stages.contains(&pairing.stage())
            || !used_relay_cursors.insert(observation.cursor())
        {
            return Err(PairingStateError::Conflict);
        }
        observed_stages.push(pairing.stage());
        prior_observed_cursor = observation.cursor();
        state.capability.key_schedule()?.open(&pairing)?;
    }
    let mut outbound_messages = BTreeSet::new();
    let mut outbound_envelopes = BTreeSet::new();
    let mut outbound_stages = Vec::new();
    for outbound in &state.outbounds {
        if outbound.envelope.routing_id() != routing_id
            || outbound.envelope.delivery_class() != DeliveryClass::Pairing
            || outbound.envelope.expected_parent_epoch().is_some()
            || !outbound_envelopes.insert(outbound.envelope.envelope_id())
        {
            return Err(PairingStateError::Conflict);
        }
        let pairing = outbound.pairing_envelope()?;
        if pairing.pairing_id() != pairing_id
            || pairing.sender() != local_sender(state.role)
            || !outbound_messages.insert(pairing.message_id())
            || outbound_stages.contains(&pairing.stage())
            || pairing.expires_at_unix_seconds() != outbound.envelope.expires_at_unix_seconds()
            || outbound
                .accepted_cursor
                .is_some_and(|cursor| !used_relay_cursors.insert(cursor))
        {
            return Err(PairingStateError::Conflict);
        }
        outbound_stages.push(pairing.stage());
        state.capability.key_schedule()?.open(&pairing)?;
    }
    Ok(())
}

fn validate_outer_envelope(
    capability: &PairingCapability,
    envelope: &RelayEnvelope,
) -> Result<(), PairingStateError> {
    if envelope.version() != ProtocolVersion::application_v1()
        || envelope.routing_id() != capability.key_schedule()?.routing_id()
        || envelope.delivery_class() != DeliveryClass::Pairing
        || envelope.expected_parent_epoch().is_some()
    {
        return Err(PairingStateError::Conflict);
    }
    Ok(())
}

fn local_sender(role: PairingRole) -> PairingSenderRole {
    match role {
        PairingRole::Joiner => PairingSenderRole::Joiner,
        PairingRole::Inviter => PairingSenderRole::Inviter,
    }
}

fn decode_role(value: u8) -> Result<PairingRole, PairingStateError> {
    match value {
        1 => Ok(PairingRole::Joiner),
        2 => Ok(PairingRole::Inviter),
        _ => Err(PairingStateError::InvalidEncoding),
    }
}

fn append_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
    maximum: usize,
) -> Result<(), PairingStateError> {
    if value.is_empty() || value.len() > maximum {
        return Err(PairingStateError::Capacity);
    }
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| PairingStateError::Capacity)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn encoded_bytes_length(current: usize, value_length: usize) -> Result<usize, PairingStateError> {
    current
        .checked_add(4)
        .and_then(|value| value.checked_add(value_length))
        .ok_or(PairingStateError::Capacity)
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, PairingStateError> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or(PairingStateError::InvalidEncoding)?;
        self.cursor += 1;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, PairingStateError> {
        Ok(u32::from_be_bytes(
            self.read_exact(4)?
                .try_into()
                .map_err(|_| PairingStateError::InvalidEncoding)?,
        ))
    }

    fn read_u64(&mut self) -> Result<u64, PairingStateError> {
        Ok(u64::from_be_bytes(
            self.read_exact(8)?
                .try_into()
                .map_err(|_| PairingStateError::InvalidEncoding)?,
        ))
    }

    fn read_bytes(&mut self, maximum: usize) -> Result<&'a [u8], PairingStateError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| PairingStateError::InvalidEncoding)?;
        if length == 0 || length > maximum {
            return Err(PairingStateError::Capacity);
        }
        self.read_exact(length)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PairingStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(PairingStateError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PairingStateError::InvalidEncoding)?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), PairingStateError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(PairingStateError::InvalidEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use KonclaveClientLibrary::RelayEndpoint;
    use KonclaveCryptographicCore::DeviceIdentity;
    use KonclaveDomainCore::ConversationRole;

    const NOW: u64 = 1_700_000_000;
    const DEADLINE: u64 = NOW + 300;

    fn capabilities() -> (PairingCapability, PairingCapability) {
        let issued = PairingCapability::issue(
            &DeviceIdentity::generate().unwrap(),
            RelayEndpoint::parse("https://relay.example.com").unwrap(),
            ConversationRole::Member,
            DEADLINE,
            NOW,
        )
        .unwrap();
        let encoded = issued.encode().unwrap();
        (
            PairingCapability::decode(encoded.as_str(), NOW).unwrap(),
            PairingCapability::decode(encoded.as_str(), NOW).unwrap(),
        )
    }

    fn message_id(value: u8) -> PairingMessageId {
        PairingMessageId::from_bytes([value; PairingMessageId::LENGTH])
    }

    fn envelope_id(value: u8) -> EnvelopeId {
        EnvelopeId::from_bytes([value; EnvelopeId::LENGTH])
    }

    fn stored(envelope: &RelayEnvelope, cursor: u64) -> StoredRelayEnvelope {
        StoredRelayEnvelope::new(envelope.clone(), cursor).unwrap()
    }

    #[test]
    fn checkpoint_round_trip_preserves_secret_operation_state() {
        let (capability, _) = capabilities();
        let mut state = PairingOperationState::new(PairingRole::Joiner, capability);
        state
            .set_conversation_id(ConversationId::from_bytes([9; ConversationId::LENGTH]))
            .unwrap();
        state
            .prepare_outbound(
                PairingStage::JoinProof,
                Some(message_id(1)),
                DEADLINE,
                b"join proof",
            )
            .unwrap();
        let encoded = state.encode().unwrap();
        assert_eq!(
            encoded.len(),
            encoded.capacity(),
            "secret-bearing checkpoint encoding must never reallocate"
        );
        let decoded = PairingOperationState::decode(&encoded).unwrap();

        assert_eq!(decoded.role(), PairingRole::Joiner);
        assert_eq!(decoded.conversation_id(), state.conversation_id());
        assert_eq!(decoded.capability().offer(), state.capability().offer());
        assert_eq!(decoded.observations().len(), 0);
        assert_eq!(decoded.outbounds().len(), 1);
        assert_eq!(
            decoded.outbounds()[0].pairing_envelope().unwrap().stage(),
            PairingStage::JoinProof
        );
        assert!(
            decoded.outbounds()[0]
                .pairing_envelope()
                .unwrap()
                .ciphertext()
                .windows(b"join proof".len())
                .all(|window| window != b"join proof")
        );
    }

    #[test]
    fn remote_record_is_authenticated_deduplicated_and_conflict_checked() {
        let (joiner_capability, inviter_capability) = capabilities();
        let mut joiner = PairingOperationState::new(PairingRole::Joiner, joiner_capability);
        let mut inviter = PairingOperationState::new(PairingRole::Inviter, inviter_capability);
        let invitation_id = inviter
            .prepare_outbound(PairingStage::Invitation, None, DEADLINE, b"invitation")
            .unwrap();
        let invitation = inviter.outbounds()[0].envelope().clone();

        match joiner.observe(&stored(&invitation, 1)).unwrap() {
            PairingObservationResult::Added(plaintext) => {
                assert_eq!(plaintext.as_slice(), b"invitation");
            }
            _ => panic!("first authenticated record must be added"),
        }
        let checkpoint = |replay_cursor, state| PairingCheckpoint {
            pairing_id: joiner.capability().offer().pairing_id(),
            routing_id: joiner.capability().key_schedule().unwrap().routing_id(),
            role: PairingRole::Joiner,
            phase: crate::persistence::pairing::PairingPhase::JoinerAwaitingInvitation,
            authorization_deadline_unix_seconds: DEADLINE,
            completion_deadline_unix_seconds: None,
            replay_cursor,
            generation: 1,
            state,
        };
        assert!(matches!(
            PairingOperationState::from_checkpoint(&checkpoint(0, joiner.encode().unwrap())),
            Err(PairingStateError::CheckpointMismatch)
        ));
        PairingOperationState::from_checkpoint(&checkpoint(1, joiner.encode().unwrap())).unwrap();

        let replayed_outer = RelayEnvelope::new(
            invitation.version(),
            invitation.routing_id(),
            envelope_id(7),
            invitation.delivery_class(),
            None,
            invitation.expires_at_unix_seconds(),
            invitation.payload().to_vec(),
        )
        .unwrap();
        match joiner.observe(&stored(&replayed_outer, 2)).unwrap() {
            PairingObservationResult::Duplicate(plaintext) => {
                assert_eq!(plaintext.as_slice(), b"invitation");
            }
            _ => panic!("same logical record must be an idempotent duplicate"),
        }
        assert_eq!(joiner.observations().len(), 1);

        let conflicting_pairing = joiner
            .capability()
            .key_schedule()
            .unwrap()
            .seal(
                invitation_id,
                PairingSenderRole::Inviter,
                PairingStage::Invitation,
                None,
                DEADLINE,
                b"different invitation",
            )
            .unwrap();
        let conflicting = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            invitation.routing_id(),
            envelope_id(8),
            DeliveryClass::Pairing,
            None,
            DEADLINE,
            encode_pairing_envelope(&conflicting_pairing).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            joiner.observe(&stored(&conflicting, 3)),
            Err(PairingStateError::Conflict)
        ));
        assert_eq!(joiner.observations().len(), 1);

        let repeated_stage = joiner
            .capability()
            .key_schedule()
            .unwrap()
            .seal(
                message_id(9),
                PairingSenderRole::Inviter,
                PairingStage::Invitation,
                None,
                DEADLINE,
                b"another invitation",
            )
            .unwrap();
        let repeated_stage = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            invitation.routing_id(),
            envelope_id(9),
            DeliveryClass::Pairing,
            None,
            DEADLINE,
            encode_pairing_envelope(&repeated_stage).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            joiner.observe(&stored(&repeated_stage, 3)),
            Err(PairingStateError::Conflict)
        ));
        assert_eq!(joiner.observations().len(), 1);
    }

    #[test]
    fn own_echo_reconciles_only_the_exact_prepared_envelope() {
        let (_, capability) = capabilities();
        let mut inviter = PairingOperationState::new(PairingRole::Inviter, capability);
        let message_id = inviter
            .prepare_outbound(PairingStage::Invitation, None, DEADLINE, b"invitation")
            .unwrap();
        let envelope = inviter.outbounds()[0].envelope().clone();

        assert!(matches!(
            inviter.observe(&stored(&envelope, 4)).unwrap(),
            PairingObservationResult::LocalEcho
        ));
        assert_eq!(inviter.outbounds()[0].accepted_cursor(), Some(4));
        inviter.mark_outbound_accepted(message_id, 4).unwrap();
        assert!(matches!(
            inviter.mark_outbound_accepted(message_id, 5),
            Err(PairingStateError::Conflict)
        ));

        let rewritten = RelayEnvelope::new(
            envelope.version(),
            envelope.routing_id(),
            envelope_id(9),
            envelope.delivery_class(),
            None,
            envelope.expires_at_unix_seconds(),
            envelope.payload().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            inviter.observe(&stored(&rewritten, 5)),
            Err(PairingStateError::Conflict)
        ));
    }

    #[test]
    fn cursor_order_and_acceptance_uniqueness_fail_closed() {
        let (joiner_capability, inviter_capability) = capabilities();
        let mut joiner = PairingOperationState::new(PairingRole::Joiner, joiner_capability);
        let mut inviter = PairingOperationState::new(PairingRole::Inviter, inviter_capability);
        let invitation_id = inviter
            .prepare_outbound(PairingStage::Invitation, None, DEADLINE, b"invitation")
            .unwrap();
        let welcome_id = inviter
            .prepare_outbound(
                PairingStage::Welcome,
                Some(invitation_id),
                DEADLINE,
                b"welcome",
            )
            .unwrap();
        let invitation = inviter.outbounds()[0].envelope().clone();
        let welcome = inviter.outbounds()[1].envelope().clone();

        assert!(matches!(
            joiner.observe(&stored(&welcome, 2)).unwrap(),
            PairingObservationResult::Added(_)
        ));
        let join_proof_id = joiner
            .prepare_outbound(
                PairingStage::JoinProof,
                Some(invitation_id),
                DEADLINE,
                b"join proof",
            )
            .unwrap();
        assert!(matches!(
            joiner.mark_outbound_accepted(join_proof_id, 2),
            Err(PairingStateError::Conflict)
        ));
        assert!(matches!(
            joiner.observe(&stored(&invitation, 1)),
            Err(PairingStateError::Conflict)
        ));

        assert!(matches!(
            inviter.observe(&stored(&invitation, 5)).unwrap(),
            PairingObservationResult::LocalEcho
        ));
        assert!(matches!(
            inviter.observe(&stored(&welcome, 5)),
            Err(PairingStateError::Conflict)
        ));
        inviter.mark_outbound_accepted(invitation_id, 5).unwrap();
        assert!(matches!(
            inviter.mark_outbound_accepted(welcome_id, 5),
            Err(PairingStateError::Conflict)
        ));
    }

    #[test]
    fn outbound_stage_is_unique_and_reply_grammar_stays_authoritative() {
        let (_, capability) = capabilities();
        let mut inviter = PairingOperationState::new(PairingRole::Inviter, capability);
        inviter
            .prepare_outbound(PairingStage::Invitation, None, DEADLINE, b"first")
            .unwrap();
        assert!(matches!(
            inviter.prepare_outbound(PairingStage::Invitation, None, DEADLINE, b"second"),
            Err(PairingStateError::Conflict)
        ));
        assert!(matches!(
            inviter.prepare_outbound(PairingStage::Welcome, None, DEADLINE, b"welcome"),
            Err(PairingStateError::Cryptographic(_))
        ));
    }

    #[test]
    fn decoding_rejects_trailing_truncated_and_role_rewritten_state() {
        let (capability, _) = capabilities();
        let state = PairingOperationState::new(PairingRole::Joiner, capability);
        let encoded = state.encode().unwrap();

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            PairingOperationState::decode(&trailing),
            Err(PairingStateError::InvalidEncoding)
        ));
        assert!(PairingOperationState::decode(&encoded[..encoded.len() - 1]).is_err());

        let mut rewritten = encoded.to_vec();
        rewritten[1] = PairingRole::Inviter as u8;
        let decoded = PairingOperationState::decode(&rewritten).unwrap();
        assert_eq!(decoded.role(), PairingRole::Inviter);
        // Persistence authenticates this sealed role separately; a checkpoint that
        // claims Joiner cannot load state rewritten to Inviter.
        let checkpoint = PairingCheckpoint {
            pairing_id: decoded.capability().offer().pairing_id(),
            routing_id: decoded.capability().key_schedule().unwrap().routing_id(),
            role: PairingRole::Joiner,
            phase: crate::persistence::pairing::PairingPhase::JoinerAwaitingInvitation,
            authorization_deadline_unix_seconds: DEADLINE,
            completion_deadline_unix_seconds: None,
            replay_cursor: 0,
            generation: 1,
            state: Zeroizing::new(rewritten),
        };
        assert!(matches!(
            PairingOperationState::from_checkpoint(&checkpoint),
            Err(PairingStateError::CheckpointMismatch)
        ));
    }

    #[test]
    fn state_capacity_and_conversation_binding_fail_closed() {
        let (capability, _) = capabilities();
        let mut state = PairingOperationState::new(PairingRole::Joiner, capability);
        let conversation = ConversationId::from_bytes([1; ConversationId::LENGTH]);
        state.set_conversation_id(conversation).unwrap();
        state.set_conversation_id(conversation).unwrap();
        assert!(matches!(
            state.set_conversation_id(ConversationId::from_bytes([2; ConversationId::LENGTH])),
            Err(PairingStateError::Conflict)
        ));
        assert!(matches!(
            PairingOperationState::decode(&vec![0; MAX_PAIRING_STATE_BYTES + 1]),
            Err(PairingStateError::InvalidEncoding)
        ));
    }
}
