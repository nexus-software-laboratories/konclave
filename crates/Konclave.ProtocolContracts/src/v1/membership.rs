use KonclaveDomainCore::{
    AddMember, ChangeMemberRole, ConversationState, MAX_APPLICATION_MESSAGE_BYTES,
    MAX_CONSUMED_INVITATIONS, MAX_MEMBERS, Member, MembershipAuthorization, MembershipChange,
    RemoveMember,
};

use crate::KonclaveProtocolError;
use crate::v1::common::{
    conversation_id_from_wire, conversation_id_to_wire, credential_hash_from_bytes,
    credential_hash_to_bytes, decode_bounded, device_id_from_wire, device_id_to_wire,
    encode_bounded, invitation_id_from_wire, invitation_id_to_wire, operation_id_from_wire,
    operation_id_to_wire, require_repeated_field_limits, required, role_from_wire, role_to_wire,
    version_from_wire, version_to_wire,
};
use crate::wire::v1 as wire;

const STATE_CONTRACT: &str = "ConversationState";
const CHANGE_CONTRACT: &str = "MembershipChange";

/// Encodes application-authorized conversation membership state.
///
/// # Errors
///
/// Returns a size error when the encoded state exceeds the v1 application limit.
pub fn encode_conversation_state(
    value: &ConversationState,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    let wire = wire::ConversationState {
        version: Some(version_to_wire(value.version())),
        conversation_id: Some(conversation_id_to_wire(value.conversation_id())),
        epoch: value.epoch(),
        members: value
            .members()
            .iter()
            .map(|member| wire::Member {
                device_id: Some(device_id_to_wire(member.device_id())),
                role: role_to_wire(member.role()),
                joined_epoch: member.joined_epoch(),
            })
            .collect(),
        consumed_invitation_ids: value
            .consumed_invitation_ids()
            .iter()
            .copied()
            .map(invitation_id_to_wire)
            .collect(),
    };
    encode_bounded(&wire, MAX_APPLICATION_MESSAGE_BYTES, STATE_CONTRACT)
}

/// Decodes and validates conversation membership state.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_conversation_state(bytes: &[u8]) -> Result<ConversationState, KonclaveProtocolError> {
    require_repeated_field_limits(
        bytes,
        MAX_APPLICATION_MESSAGE_BYTES,
        STATE_CONTRACT,
        [
            (4, MAX_MEMBERS, "members"),
            (5, MAX_CONSUMED_INVITATIONS, "consumed_invitation_ids"),
        ],
    )?;
    let wire: wire::ConversationState =
        decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, STATE_CONTRACT)?;
    require_collection_bound(wire.members.len(), 1, MAX_MEMBERS, "members")?;
    require_collection_bound(
        wire.consumed_invitation_ids.len(),
        0,
        MAX_CONSUMED_INVITATIONS,
        "consumed_invitation_ids",
    )?;
    let members = wire
        .members
        .into_iter()
        .map(|member| {
            Ok(Member::new(
                device_id_from_wire(member.device_id)?,
                role_from_wire(member.role)?,
                member.joined_epoch,
            ))
        })
        .collect::<Result<Vec<_>, KonclaveProtocolError>>()?;
    let consumed_invitation_ids = wire
        .consumed_invitation_ids
        .into_iter()
        .map(|id| invitation_id_from_wire(Some(id)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConversationState::new(
        version_from_wire(wire.version, STATE_CONTRACT)?,
        conversation_id_from_wire(wire.conversation_id)?,
        wire.epoch,
        members,
        consumed_invitation_ids,
    )?)
}

fn require_collection_bound(
    actual: usize,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), KonclaveProtocolError> {
    if actual < minimum || actual > maximum {
        return Err(KonclaveDomainCore::KonclaveDomainError::OutOfRange {
            field,
            minimum,
            maximum,
            actual,
        }
        .into());
    }
    Ok(())
}

/// Encodes one application-authorized membership transition.
///
/// # Errors
///
/// Returns a size error when the encoded transition exceeds the v1 application limit.
pub fn encode_membership_change(
    value: &MembershipAuthorization,
) -> Result<Vec<u8>, KonclaveProtocolError> {
    let change = match value.change() {
        MembershipChange::Add(add) => wire::membership_change::Change::Add(wire::AddMember {
            device_id: Some(device_id_to_wire(add.device_id())),
            role: role_to_wire(add.role()),
            invitation_id: Some(invitation_id_to_wire(add.invitation_id())),
            credential_binding_hash: credential_hash_to_bytes(add.credential_binding_hash()),
        }),
        MembershipChange::Remove(remove) => {
            wire::membership_change::Change::Remove(wire::RemoveMember {
                device_id: Some(device_id_to_wire(remove.device_id())),
            })
        }
        MembershipChange::ChangeRole(change) => {
            wire::membership_change::Change::ChangeRole(wire::ChangeMemberRole {
                device_id: Some(device_id_to_wire(change.device_id())),
                role: role_to_wire(change.role()),
            })
        }
    };
    let wire = wire::MembershipChange {
        version: Some(version_to_wire(value.version())),
        conversation_id: Some(conversation_id_to_wire(value.conversation_id())),
        parent_epoch: value.parent_epoch(),
        operation_id: Some(operation_id_to_wire(value.operation_id())),
        change: Some(change),
    };
    encode_bounded(&wire, MAX_APPLICATION_MESSAGE_BYTES, CHANGE_CONTRACT)
}

/// Decodes and validates one application-authorized membership transition.
///
/// Cryptographic sender authentication and administrator authorization remain the
/// caller's responsibility.
///
/// # Errors
///
/// Returns a typed protocol or domain validation error.
pub fn decode_membership_change(
    bytes: &[u8],
) -> Result<MembershipAuthorization, KonclaveProtocolError> {
    let wire: wire::MembershipChange =
        decode_bounded(bytes, MAX_APPLICATION_MESSAGE_BYTES, CHANGE_CONTRACT)?;
    let change = match required(wire.change, "membership_change.change")? {
        wire::membership_change::Change::Add(add) => MembershipChange::Add(AddMember::new(
            device_id_from_wire(add.device_id)?,
            role_from_wire(add.role)?,
            invitation_id_from_wire(add.invitation_id)?,
            credential_hash_from_bytes(&add.credential_binding_hash)?,
        )),
        wire::membership_change::Change::Remove(remove) => {
            MembershipChange::Remove(RemoveMember::new(device_id_from_wire(remove.device_id)?))
        }
        wire::membership_change::Change::ChangeRole(change) => {
            MembershipChange::ChangeRole(ChangeMemberRole::new(
                device_id_from_wire(change.device_id)?,
                role_from_wire(change.role)?,
            ))
        }
    };
    Ok(MembershipAuthorization::new(
        version_from_wire(wire.version, CHANGE_CONTRACT)?,
        conversation_id_from_wire(wire.conversation_id)?,
        wire.parent_epoch,
        operation_id_from_wire(wire.operation_id)?,
        change,
    ))
}
