import { fromBinary, toBinary, type DescMessage, type MessageShape } from '@bufbuild/protobuf';
import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';

import type {
  ConversationRole,
  ProtocolVersion,
} from './generated/konclave/protocol/v1/common_pb.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';

/** Current application protocol major version. */
export const APPLICATION_PROTOCOL_MAJOR = 1;
/** Current application protocol minor version. */
export const APPLICATION_PROTOCOL_MINOR = 0;
/** Maximum encoded application-message bytes in protocol v1. */
export const MAX_APPLICATION_MESSAGE_BYTES = 256 * 1024;
/** Maximum UTF-8 text body bytes after reserving application framing overhead. */
export const MAX_TEXT_BODY_BYTES = MAX_APPLICATION_MESSAGE_BYTES - 1024;
/** Maximum encoded relay-envelope bytes in protocol v1. */
export const MAX_RELAY_ENVELOPE_BYTES = 1024 * 1024;
/** Maximum opaque payload bytes after reserving relay framing overhead. */
export const MAX_RELAY_PAYLOAD_BYTES = MAX_RELAY_ENVELOPE_BYTES - 1024;
/** Maximum active device count in one conversation. */
export const MAX_MEMBERS = 128;
/** Maximum consumed invitation identifiers retained in conversation state. */
export const MAX_CONSUMED_INVITATIONS = 1024;
/** Maximum accepted MLS KeyPackage bytes in one join proof. */
export const MAX_MLS_KEY_PACKAGE_BYTES = 64 * 1024;
/** Maximum envelope count in one replay page. */
export const MAX_REPLAY_PAGE_SIZE = 100;
export const MAX_STORED_RELAY_ENVELOPE_BYTES = MAX_RELAY_ENVELOPE_BYTES + 32;
/** Maximum encoded replay-page bytes in protocol v1. */
export const MAX_REPLAY_PAGE_BYTES = 16 * 1024 * 1024;
/** Maximum encoded replay-request or acknowledgment bytes in protocol v1. */
export const MAX_RELAY_CONTROL_MESSAGE_BYTES = 1024;
/** Maximum top-level fields accepted in one protocol v1 Protobuf message. */
export const MAX_PROTOBUF_TOP_LEVEL_FIELDS = 4096;

const UINT64_MAX = 18_446_744_073_709_551_615n;

export function decodeBounded<Desc extends DescMessage>(
  schema: Desc,
  bytes: Uint8Array,
  maximum: number,
  contract: string,
): MessageShape<Desc> {
  validateRepeatedFieldLimits(bytes, maximum, contract, []);
  try {
    return fromBinary(schema, bytes, { readUnknownFields: false });
  } catch {
    throw new ProtocolValidationError(
      protocolErrorCodes.malformed,
      `${contract} is not valid Protocol Buffers`,
    );
  }
}

export function encodeBounded<Desc extends DescMessage>(
  schema: Desc,
  message: MessageShape<Desc>,
  maximum: number,
  contract: string,
): Uint8Array {
  const bytes = toBinary(schema, message);
  assertEncodedSize(bytes, maximum, contract);
  return bytes;
}

export function validateRepeatedFieldLimits(
  bytes: Uint8Array,
  maximumBytes: number,
  contract: string,
  limits: ReadonlyArray<{
    field: string;
    fieldNumber: number;
    maximum: number;
  }>,
): void {
  assertEncodedSize(bytes, maximumBytes, contract);
  const counts = new Map<number, number>();
  const reader = new BinaryReader(bytes);
  let fieldCount = 0;
  try {
    while (reader.pos < reader.len) {
      fieldCount += 1;
      if (fieldCount > MAX_PROTOBUF_TOP_LEVEL_FIELDS) {
        throw new ProtocolValidationError(
          protocolErrorCodes.outOfRange,
          'protobuf_top_level_fields exceeds its collection bound',
        );
      }
      const [fieldNumber, wireType] = reader.tag();
      if (wireType === WireType.StartGroup || wireType === WireType.EndGroup) {
        throw new ProtocolValidationError(
          protocolErrorCodes.malformed,
          `${contract} contains unsupported group framing`,
        );
      }
      if (wireType === WireType.LengthDelimited) {
        for (const limit of limits) {
          if (limit.fieldNumber === fieldNumber) {
            const count = (counts.get(fieldNumber) ?? 0) + 1;
            counts.set(fieldNumber, count);
            if (count > limit.maximum) {
              throw new ProtocolValidationError(
                protocolErrorCodes.outOfRange,
                `${limit.field} exceeds its collection bound`,
              );
            }
          }
        }
      }
      reader.skip(wireType, fieldNumber);
    }
  } catch (error: unknown) {
    if (error instanceof ProtocolValidationError) {
      throw error;
    }
    throw new ProtocolValidationError(
      protocolErrorCodes.malformed,
      `${contract} is not valid Protocol Buffers`,
    );
  }
}

export function required<T>(value: T | undefined, field: string): T {
  if (value === undefined) {
    throw new ProtocolValidationError(
      protocolErrorCodes.missingField,
      `required field ${field} is missing`,
    );
  }
  return value;
}

export function validateVersion(version: ProtocolVersion | undefined, contract: string): void {
  const present = required(version, 'version');
  if (present.major !== APPLICATION_PROTOCOL_MAJOR) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedMajor,
      `${contract} requires protocol major version ${APPLICATION_PROTOCOL_MAJOR}`,
    );
  }
}

export function validateFixedBytes(value: Uint8Array, expected: number, field: string): void {
  if (value.byteLength !== expected) {
    throw new ProtocolValidationError(
      protocolErrorCodes.invalidLength,
      `${field} must contain exactly ${expected} bytes`,
    );
  }
}

export function validateLengthRange(
  actual: number,
  minimum: number,
  maximum: number,
  field: string,
): void {
  if (actual < minimum || actual > maximum) {
    throw new ProtocolValidationError(
      protocolErrorCodes.outOfRange,
      `${field} must contain from ${minimum} through ${maximum} items or bytes`,
    );
  }
}

export function validateUint64(value: bigint, field: string, positive: boolean): void {
  if (value < (positive ? 1n : 0n) || value > UINT64_MAX) {
    throw new ProtocolValidationError(
      protocolErrorCodes.outOfRange,
      `${field} is outside its uint64 contract`,
    );
  }
}

export function validateRole(role: ConversationRole): void {
  if (role !== 1 && role !== 2) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedEnum,
      'conversation_role is unsupported',
    );
  }
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength && left.every((value, index) => value === right[index])
  );
}

export function bytesKey(value: Uint8Array): string {
  return Array.from(value, (byte) => String.fromCharCode(byte)).join('');
}

function assertEncodedSize(bytes: Uint8Array, maximum: number, contract: string): void {
  if (bytes.byteLength > maximum) {
    throw new ProtocolValidationError(
      protocolErrorCodes.encodedMessageTooLarge,
      `${contract} exceeds ${maximum} encoded bytes`,
    );
  }
}
