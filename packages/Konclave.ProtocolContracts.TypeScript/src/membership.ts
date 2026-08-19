import {
  bytesKey,
  decodeBounded,
  encodeBounded,
  MAX_APPLICATION_MESSAGE_BYTES,
  MAX_CONSUMED_INVITATIONS,
  MAX_MEMBERS,
  required,
  validateFixedBytes,
  validateLengthRange,
  validateRole,
  validateRepeatedFieldLimits,
  validateUint64,
  validateVersion,
} from './common.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';
import { ConversationRole } from './generated/konclave/protocol/v1/common_pb.js';
import {
  ConversationStateSchema,
  MembershipChangeSchema,
  type ConversationState,
  type MembershipChange,
} from './generated/konclave/protocol/v1/membership_pb.js';

const stateContract = 'ConversationState';
const changeContract = 'MembershipChange';

/**
 * Encodes validated application-authorized conversation state.
 *
 * @throws {ProtocolValidationError} When the state violates a v1 bound or invariant.
 */
export function encodeConversationState(value: ConversationState): Uint8Array {
  validateConversationState(value);
  return encodeBounded(
    ConversationStateSchema,
    value,
    MAX_APPLICATION_MESSAGE_BYTES,
    stateContract,
  );
}

/**
 * Decodes and validates application-authorized conversation state.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeConversationState(bytes: Uint8Array): ConversationState {
  validateRepeatedFieldLimits(bytes, MAX_APPLICATION_MESSAGE_BYTES, stateContract, [
    { field: 'members', fieldNumber: 4, maximum: MAX_MEMBERS },
    {
      field: 'consumed_invitation_ids',
      fieldNumber: 5,
      maximum: MAX_CONSUMED_INVITATIONS,
    },
  ]);
  const value = decodeBounded(
    ConversationStateSchema,
    bytes,
    MAX_APPLICATION_MESSAGE_BYTES,
    stateContract,
  );
  validateConversationState(value);
  return value;
}

/**
 * Encodes one validated application-authorized membership transition.
 *
 * @throws {ProtocolValidationError} When the transition violates a v1 bound or invariant.
 */
export function encodeMembershipChange(value: MembershipChange): Uint8Array {
  validateMembershipChange(value);
  return encodeBounded(
    MembershipChangeSchema,
    value,
    MAX_APPLICATION_MESSAGE_BYTES,
    changeContract,
  );
}

/**
 * Decodes one application-authorized membership transition.
 *
 * MLS sender authentication and administrator authorization remain the caller's
 * responsibility.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeMembershipChange(bytes: Uint8Array): MembershipChange {
  const value = decodeBounded(
    MembershipChangeSchema,
    bytes,
    MAX_APPLICATION_MESSAGE_BYTES,
    changeContract,
  );
  validateMembershipChange(value);
  return value;
}

function validateConversationState(value: ConversationState): void {
  validateVersion(value.version, stateContract);
  validateFixedBytes(
    required(value.conversationId, 'conversation_id').value,
    32,
    'conversation_id',
  );
  validateUint64(value.epoch, 'epoch', false);
  validateLengthRange(value.members.length, 1, MAX_MEMBERS, 'members');
  validateLengthRange(
    value.consumedInvitationIds.length,
    0,
    MAX_CONSUMED_INVITATIONS,
    'consumed_invitation_ids',
  );

  const memberIds = new Set<string>();
  let hasAdministrator = false;
  for (const member of value.members) {
    const deviceId = required(member.deviceId, 'member.device_id').value;
    validateFixedBytes(deviceId, 32, 'member.device_id');
    validateRole(member.role);
    validateUint64(member.joinedEpoch, 'joined_epoch', false);
    if (member.joinedEpoch > value.epoch) {
      throw new ProtocolValidationError(
        protocolErrorCodes.memberJoinedAfterStateEpoch,
        'member joined after the represented conversation epoch',
      );
    }
    const key = bytesKey(deviceId);
    if (memberIds.has(key)) {
      throw new ProtocolValidationError(
        protocolErrorCodes.duplicateIdentifier,
        'member_device_id contains a duplicate identifier',
      );
    }
    memberIds.add(key);
    hasAdministrator ||= member.role === ConversationRole.ADMINISTRATOR;
  }
  if (!hasAdministrator) {
    throw new ProtocolValidationError(
      protocolErrorCodes.missingAdministrator,
      'conversation membership requires an administrator',
    );
  }

  const invitationIds = new Set<string>();
  for (const invitationId of value.consumedInvitationIds) {
    validateFixedBytes(invitationId.value, 16, 'consumed_invitation_id');
    const key = bytesKey(invitationId.value);
    if (invitationIds.has(key)) {
      throw new ProtocolValidationError(
        protocolErrorCodes.duplicateIdentifier,
        'consumed_invitation_id contains a duplicate identifier',
      );
    }
    invitationIds.add(key);
  }
}

function validateMembershipChange(value: MembershipChange): void {
  validateVersion(value.version, changeContract);
  validateFixedBytes(
    required(value.conversationId, 'conversation_id').value,
    32,
    'conversation_id',
  );
  validateUint64(value.parentEpoch, 'parent_epoch', false);
  validateFixedBytes(required(value.operationId, 'operation_id').value, 16, 'operation_id');

  switch (value.change.case) {
    case 'add':
      validateFixedBytes(
        required(value.change.value.deviceId, 'add.device_id').value,
        32,
        'add.device_id',
      );
      validateRole(value.change.value.role);
      validateFixedBytes(
        required(value.change.value.invitationId, 'add.invitation_id').value,
        16,
        'add.invitation_id',
      );
      validateFixedBytes(value.change.value.credentialBindingHash, 32, 'credential_binding_hash');
      return;
    case 'remove':
      validateFixedBytes(
        required(value.change.value.deviceId, 'remove.device_id').value,
        32,
        'remove.device_id',
      );
      return;
    case 'changeRole':
      validateFixedBytes(
        required(value.change.value.deviceId, 'change_role.device_id').value,
        32,
        'change_role.device_id',
      );
      validateRole(value.change.value.role);
      return;
    case undefined:
      throw new ProtocolValidationError(
        protocolErrorCodes.missingVariant,
        'membership_change.change is missing',
      );
  }
}
