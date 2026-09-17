use KonclaveDomainCore::{
    ConversationId, DeviceId, Ed25519PublicKey, MAX_REPEAT_PAIRING_CAPABILITY_BYTES, PairingId,
    RepeatPairingOperationId, RoutingId,
};
use thiserror::Error;
use zeroize::Zeroizing;

const REPEAT_PAIRING_STATE_VERSION: u8 = 1;
const OPTIONAL_ROUTING_BYTES: usize = 1 + RoutingId::LENGTH;
const OPTIONAL_PAIRING_BYTES: usize = 1 + PairingId::LENGTH;
const FIXED_STATE_BYTES: usize = 3
    + RepeatPairingOperationId::LENGTH
    + ConversationId::LENGTH
    + ConversationId::LENGTH
    + OPTIONAL_ROUTING_BYTES
    + DeviceId::LENGTH
    + Ed25519PublicKey::LENGTH
    + 8
    + OPTIONAL_PAIRING_BYTES
    + 4;
pub(crate) const MAX_REPEAT_PAIRING_STATE_BYTES: usize =
    FIXED_STATE_BYTES + MAX_REPEAT_PAIRING_CAPABILITY_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RepeatPairingRole {
    Initiator = 1,
    Responder = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RepeatPairingPhase {
    InitiatorSendingRequest = 1,
    InitiatorAwaitingResponse = 2,
    InitiatorRedeemingCapability = 3,
    InitiatorCreatingConversation = 4,
    InitiatorPairing = 5,
    ResponderIssuingCapability = 6,
    ResponderReservingPairing = 7,
    ResponderSendingResponse = 8,
    ResponderPairing = 9,
    Completed = 10,
    Cancelling = 11,
    Cancelled = 12,
}

impl RepeatPairingPhase {
    #[must_use]
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

pub(crate) struct RepeatPairingOperationState {
    pub(crate) operation_id: RepeatPairingOperationId,
    pub(crate) role: RepeatPairingRole,
    pub(crate) phase: RepeatPairingPhase,
    pub(crate) bootstrap_conversation_id: ConversationId,
    pub(crate) new_conversation_id: ConversationId,
    pub(crate) new_routing_id: Option<RoutingId>,
    pub(crate) peer_device_id: DeviceId,
    pub(crate) peer_root_public_key: Ed25519PublicKey,
    pub(crate) deadline_unix_seconds: u64,
    pub(crate) pairing_id: Option<PairingId>,
    pub(crate) capability: Option<Zeroizing<String>>,
}

impl RepeatPairingOperationState {
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated repeat-pairing boundary remains explicit"
    )]
    pub(crate) const fn initiator(
        operation_id: RepeatPairingOperationId,
        bootstrap_conversation_id: ConversationId,
        new_conversation_id: ConversationId,
        new_routing_id: RoutingId,
        peer_device_id: DeviceId,
        peer_root_public_key: Ed25519PublicKey,
        deadline_unix_seconds: u64,
    ) -> Self {
        Self {
            operation_id,
            role: RepeatPairingRole::Initiator,
            phase: RepeatPairingPhase::InitiatorSendingRequest,
            bootstrap_conversation_id,
            new_conversation_id,
            new_routing_id: Some(new_routing_id),
            peer_device_id,
            peer_root_public_key,
            deadline_unix_seconds,
            pairing_id: None,
            capability: None,
        }
    }

    #[must_use]
    pub(crate) const fn responder(
        operation_id: RepeatPairingOperationId,
        bootstrap_conversation_id: ConversationId,
        new_conversation_id: ConversationId,
        peer_device_id: DeviceId,
        peer_root_public_key: Ed25519PublicKey,
        deadline_unix_seconds: u64,
    ) -> Self {
        Self {
            operation_id,
            role: RepeatPairingRole::Responder,
            phase: RepeatPairingPhase::ResponderIssuingCapability,
            bootstrap_conversation_id,
            new_conversation_id,
            new_routing_id: None,
            peer_device_id,
            peer_root_public_key,
            deadline_unix_seconds,
            pairing_id: None,
            capability: None,
        }
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RepeatPairingStateError> {
        validate_state(self)?;
        let capability = self
            .capability
            .as_ref()
            .map_or(&[][..], |value| value.as_bytes());
        let capability_length =
            u32::try_from(capability.len()).map_err(|_| RepeatPairingStateError::InvalidState)?;
        let mut output = Zeroizing::new(Vec::with_capacity(FIXED_STATE_BYTES + capability.len()));
        output.push(REPEAT_PAIRING_STATE_VERSION);
        output.push(self.role as u8);
        output.push(self.phase as u8);
        output.extend_from_slice(self.operation_id.as_bytes());
        output.extend_from_slice(self.bootstrap_conversation_id.as_bytes());
        output.extend_from_slice(self.new_conversation_id.as_bytes());
        write_optional_fixed(&mut output, self.new_routing_id.map(RoutingId::into_bytes));
        output.extend_from_slice(self.peer_device_id.as_bytes());
        output.extend_from_slice(self.peer_root_public_key.as_bytes());
        output.extend_from_slice(&self.deadline_unix_seconds.to_be_bytes());
        write_optional_fixed(&mut output, self.pairing_id.map(PairingId::into_bytes));
        output.extend_from_slice(&capability_length.to_be_bytes());
        output.extend_from_slice(capability);
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, RepeatPairingStateError> {
        if bytes.len() < FIXED_STATE_BYTES || bytes.len() > MAX_REPEAT_PAIRING_STATE_BYTES {
            return Err(RepeatPairingStateError::InvalidState);
        }
        let mut input = bytes;
        if take::<1>(&mut input)?[0] != REPEAT_PAIRING_STATE_VERSION {
            return Err(RepeatPairingStateError::InvalidState);
        }
        let role = repeat_pairing_role(take::<1>(&mut input)?[0])?;
        let phase = repeat_pairing_phase(take::<1>(&mut input)?[0])?;
        let operation_id = RepeatPairingOperationId::from_bytes(take(&mut input)?);
        let bootstrap_conversation_id = ConversationId::from_bytes(take(&mut input)?);
        let new_conversation_id = ConversationId::from_bytes(take(&mut input)?);
        let new_routing_id = read_optional_fixed(&mut input)?.map(RoutingId::from_bytes);
        let peer_device_id = DeviceId::from_bytes(take(&mut input)?);
        let peer_root_public_key = Ed25519PublicKey::from_bytes(take(&mut input)?);
        let deadline_unix_seconds = u64::from_be_bytes(take(&mut input)?);
        let pairing_id = read_optional_fixed(&mut input)?.map(PairingId::from_bytes);
        let capability_length = usize::try_from(u32::from_be_bytes(take(&mut input)?))
            .map_err(|_| RepeatPairingStateError::InvalidState)?;
        if capability_length != input.len()
            || capability_length > MAX_REPEAT_PAIRING_CAPABILITY_BYTES
        {
            return Err(RepeatPairingStateError::InvalidState);
        }
        let capability = if capability_length == 0 {
            None
        } else {
            Some(Zeroizing::new(
                std::str::from_utf8(input)
                    .map_err(|_| RepeatPairingStateError::InvalidState)?
                    .to_owned(),
            ))
        };
        let state = Self {
            operation_id,
            role,
            phase,
            bootstrap_conversation_id,
            new_conversation_id,
            new_routing_id,
            peer_device_id,
            peer_root_public_key,
            deadline_unix_seconds,
            pairing_id,
            capability,
        };
        validate_state(&state)?;
        Ok(state)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum RepeatPairingStateError {
    #[error("repeat-pairing state is invalid")]
    InvalidState,
}

#[must_use]
pub(crate) fn repeat_pairing_transition_allowed(
    role: RepeatPairingRole,
    current: RepeatPairingPhase,
    next: RepeatPairingPhase,
) -> bool {
    if current.is_terminal() {
        return current == next;
    }
    if next == RepeatPairingPhase::Cancelling {
        return true;
    }
    if current == RepeatPairingPhase::Cancelling {
        return next == RepeatPairingPhase::Cancelled;
    }
    matches!(
        (role, current, next),
        (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorSendingRequest,
            RepeatPairingPhase::InitiatorAwaitingResponse
                | RepeatPairingPhase::InitiatorRedeemingCapability
        ) | (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorAwaitingResponse,
            RepeatPairingPhase::InitiatorRedeemingCapability
        ) | (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorRedeemingCapability,
            RepeatPairingPhase::InitiatorCreatingConversation
        ) | (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorCreatingConversation,
            RepeatPairingPhase::InitiatorPairing
        ) | (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorPairing,
            RepeatPairingPhase::Completed
        ) | (
            RepeatPairingRole::Responder,
            RepeatPairingPhase::ResponderIssuingCapability,
            RepeatPairingPhase::ResponderReservingPairing
        ) | (
            RepeatPairingRole::Responder,
            RepeatPairingPhase::ResponderReservingPairing,
            RepeatPairingPhase::ResponderSendingResponse
        ) | (
            RepeatPairingRole::Responder,
            RepeatPairingPhase::ResponderSendingResponse,
            RepeatPairingPhase::ResponderPairing
        ) | (
            RepeatPairingRole::Responder,
            RepeatPairingPhase::ResponderPairing,
            RepeatPairingPhase::Completed
        )
    )
}

fn validate_state(state: &RepeatPairingOperationState) -> Result<(), RepeatPairingStateError> {
    if state.deadline_unix_seconds == 0 {
        return Err(RepeatPairingStateError::InvalidState);
    }
    let shape_valid = match (state.role, state.phase) {
        (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorSendingRequest
            | RepeatPairingPhase::InitiatorAwaitingResponse,
        ) => {
            state.new_routing_id.is_some()
                && state.pairing_id.is_none()
                && state.capability.is_none()
        }
        (RepeatPairingRole::Initiator, RepeatPairingPhase::InitiatorRedeemingCapability) => {
            state.new_routing_id.is_some()
                && state.pairing_id.is_none()
                && state.capability.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
                })
        }
        (RepeatPairingRole::Initiator, RepeatPairingPhase::InitiatorCreatingConversation) => {
            state.new_routing_id.is_some()
                && state.pairing_id.is_some()
                && state.capability.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
                })
        }
        (
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorPairing | RepeatPairingPhase::Completed,
        ) => {
            state.new_routing_id.is_some()
                && state.pairing_id.is_some()
                && state.capability.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
                })
        }
        (RepeatPairingRole::Responder, RepeatPairingPhase::ResponderIssuingCapability) => {
            state.new_routing_id.is_none()
                && state.pairing_id.is_none()
                && state.capability.is_none()
        }
        (RepeatPairingRole::Responder, RepeatPairingPhase::ResponderReservingPairing) => {
            state.new_routing_id.is_none()
                && state.pairing_id.is_none()
                && state.capability.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
                })
        }
        (RepeatPairingRole::Responder, RepeatPairingPhase::ResponderSendingResponse) => {
            state.new_routing_id.is_none()
                && state.pairing_id.is_some()
                && state.capability.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
                })
        }
        (
            RepeatPairingRole::Responder,
            RepeatPairingPhase::ResponderPairing | RepeatPairingPhase::Completed,
        ) => {
            state.new_routing_id.is_none()
                && state.pairing_id.is_some()
                && state.capability.as_ref().is_some_and(|value| {
                    !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
                })
        }
        (_, RepeatPairingPhase::Cancelling | RepeatPairingPhase::Cancelled) => {
            state.capability.as_ref().is_none_or(|value| {
                !value.is_empty() && value.len() <= MAX_REPEAT_PAIRING_CAPABILITY_BYTES
            }) && match state.role {
                RepeatPairingRole::Initiator => state.new_routing_id.is_some(),
                RepeatPairingRole::Responder => state.new_routing_id.is_none(),
            }
        }
        _ => false,
    };
    if shape_valid {
        Ok(())
    } else {
        Err(RepeatPairingStateError::InvalidState)
    }
}

fn write_optional_fixed<const N: usize>(output: &mut Vec<u8>, value: Option<[u8; N]>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value);
        }
        None => {
            output.push(0);
            output.extend_from_slice(&[0; N]);
        }
    }
}

fn read_optional_fixed<const N: usize>(
    input: &mut &[u8],
) -> Result<Option<[u8; N]>, RepeatPairingStateError> {
    let present = take::<1>(input)?[0];
    let value = take::<N>(input)?;
    match present {
        0 if value.iter().all(|byte| *byte == 0) => Ok(None),
        1 => Ok(Some(value)),
        _ => Err(RepeatPairingStateError::InvalidState),
    }
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], RepeatPairingStateError> {
    if input.len() < N {
        return Err(RepeatPairingStateError::InvalidState);
    }
    let (value, remaining) = input.split_at(N);
    *input = remaining;
    value
        .try_into()
        .map_err(|_| RepeatPairingStateError::InvalidState)
}

fn repeat_pairing_role(value: u8) -> Result<RepeatPairingRole, RepeatPairingStateError> {
    match value {
        1 => Ok(RepeatPairingRole::Initiator),
        2 => Ok(RepeatPairingRole::Responder),
        _ => Err(RepeatPairingStateError::InvalidState),
    }
}

fn repeat_pairing_phase(value: u8) -> Result<RepeatPairingPhase, RepeatPairingStateError> {
    match value {
        1 => Ok(RepeatPairingPhase::InitiatorSendingRequest),
        2 => Ok(RepeatPairingPhase::InitiatorAwaitingResponse),
        3 => Ok(RepeatPairingPhase::InitiatorRedeemingCapability),
        4 => Ok(RepeatPairingPhase::InitiatorCreatingConversation),
        5 => Ok(RepeatPairingPhase::InitiatorPairing),
        6 => Ok(RepeatPairingPhase::ResponderIssuingCapability),
        7 => Ok(RepeatPairingPhase::ResponderReservingPairing),
        8 => Ok(RepeatPairingPhase::ResponderSendingResponse),
        9 => Ok(RepeatPairingPhase::ResponderPairing),
        10 => Ok(RepeatPairingPhase::Completed),
        11 => Ok(RepeatPairingPhase::Cancelling),
        12 => Ok(RepeatPairingPhase::Cancelled),
        _ => Err(RepeatPairingStateError::InvalidState),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initiator() -> RepeatPairingOperationState {
        RepeatPairingOperationState::initiator(
            RepeatPairingOperationId::from_bytes([1; 16]),
            ConversationId::from_bytes([2; 32]),
            ConversationId::from_bytes([3; 32]),
            RoutingId::from_bytes([4; 32]),
            DeviceId::from_bytes([5; 32]),
            Ed25519PublicKey::from_bytes([6; 32]),
            100,
        )
    }

    #[test]
    fn repeat_pairing_state_round_trips_exactly() {
        let mut state = initiator();
        for phase in [
            RepeatPairingPhase::InitiatorSendingRequest,
            RepeatPairingPhase::InitiatorAwaitingResponse,
        ] {
            state.phase = phase;
            let encoded = state.encode().unwrap();
            assert_eq!(
                RepeatPairingOperationState::decode(&encoded).unwrap().phase,
                phase
            );
        }
        state.phase = RepeatPairingPhase::InitiatorRedeemingCapability;
        state.capability = Some(Zeroizing::new("capability".to_owned()));
        let encoded = state.encode().unwrap();
        let decoded = RepeatPairingOperationState::decode(&encoded).unwrap();
        assert_eq!(
            decoded.capability.as_deref().map(String::as_str),
            Some("capability")
        );
        assert_eq!(decoded.encode().unwrap().as_slice(), encoded.as_slice());
    }

    #[test]
    fn repeat_pairing_state_rejects_invalid_shapes_and_trailing_bytes() {
        let mut state = initiator();
        state.phase = RepeatPairingPhase::InitiatorPairing;
        assert_eq!(
            state.encode().err(),
            Some(RepeatPairingStateError::InvalidState)
        );
        let mut encoded = initiator().encode().unwrap();
        encoded.push(0);
        assert_eq!(
            RepeatPairingOperationState::decode(&encoded).err(),
            Some(RepeatPairingStateError::InvalidState)
        );
    }

    #[test]
    fn repeat_pairing_transitions_are_role_separated_and_terminal() {
        assert!(repeat_pairing_transition_allowed(
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::InitiatorAwaitingResponse,
            RepeatPairingPhase::InitiatorRedeemingCapability,
        ));
        assert!(!repeat_pairing_transition_allowed(
            RepeatPairingRole::Responder,
            RepeatPairingPhase::ResponderIssuingCapability,
            RepeatPairingPhase::InitiatorSendingRequest,
        ));
        assert!(!repeat_pairing_transition_allowed(
            RepeatPairingRole::Initiator,
            RepeatPairingPhase::Completed,
            RepeatPairingPhase::Cancelling,
        ));
    }
}
