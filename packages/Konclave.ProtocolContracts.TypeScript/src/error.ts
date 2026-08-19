/** Stable machine-readable protocol validation error codes. */
export const protocolErrorCodes = {
  encodedMessageTooLarge: 'encoded_message_too_large',
  malformed: 'malformed',
  missingField: 'missing_field',
  unsupportedEnum: 'unsupported_enum',
  missingVariant: 'missing_variant',
  unsupportedMajor: 'unsupported_major',
  invalidLength: 'invalid_length',
  outOfRange: 'out_of_range',
  emptyValue: 'empty_value',
  duplicateIdentifier: 'duplicate_identifier',
  missingAdministrator: 'missing_administrator',
  mismatchedInvitedDevice: 'mismatched_invited_device',
  mismatchedInvitedConversation: 'mismatched_invited_conversation',
  memberJoinedAfterStateEpoch: 'member_joined_after_state_epoch',
  invalidExpectedParentEpoch: 'invalid_expected_parent_epoch',
  invalidReplayOrder: 'invalid_replay_order',
} as const;

/** A stable machine-readable protocol validation error code. */
export type ProtocolErrorCode = (typeof protocolErrorCodes)[keyof typeof protocolErrorCodes];

/** Failure produced while decoding, validating, or encoding a protocol contract. */
export class ProtocolValidationError extends Error {
  /** Creates a protocol failure with a stable code and bounded diagnostic message. */
  public constructor(
    public readonly code: ProtocolErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ProtocolValidationError';
  }
}
