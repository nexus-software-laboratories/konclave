import {
  decodeBounded,
  encodeBounded,
  MAX_APPLICATION_MESSAGE_BYTES,
  MAX_TEXT_BODY_BYTES,
  required,
  validateFixedBytes,
  validateLengthRange,
  validateUint64,
  validateVersion,
} from './common.js';
import {
  ApplicationMessageSchema,
  type ApplicationMessage,
} from './generated/konclave/protocol/v1/application_pb.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';

const textEncoder = new TextEncoder();
const contract = 'ApplicationMessage';

/**
 * Encodes one validated protocol v1 application message.
 *
 * @throws {ProtocolValidationError} When the message violates a v1 bound or invariant.
 */
export function encodeApplicationMessage(value: ApplicationMessage): Uint8Array {
  validateApplicationMessage(value);
  return encodeBounded(ApplicationMessageSchema, value, MAX_APPLICATION_MESSAGE_BYTES, contract);
}

/**
 * Decodes and validates untrusted protocol v1 application bytes.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeApplicationMessage(bytes: Uint8Array): ApplicationMessage {
  const value = decodeBounded(
    ApplicationMessageSchema,
    bytes,
    MAX_APPLICATION_MESSAGE_BYTES,
    contract,
  );
  validateApplicationMessage(value);
  return value;
}

function validateApplicationMessage(value: ApplicationMessage): void {
  validateVersion(value.version, contract);
  validateFixedBytes(required(value.messageId, 'message_id').value, 16, 'message_id');
  validateUint64(value.senderCounter, 'sender_counter', true);
  validateUint64(value.sentAtUnixMilliseconds, 'sent_at_unix_milliseconds', false);
  if (value.replyTo !== undefined) {
    validateFixedBytes(value.replyTo.value, 16, 'reply_to');
  }
  if (value.content.case !== 'text') {
    throw new ProtocolValidationError(
      protocolErrorCodes.missingVariant,
      'application_message.content is missing',
    );
  }
  const bodyLength = textEncoder.encode(value.content.value.body).byteLength;
  if (bodyLength === 0) {
    throw new ProtocolValidationError(protocolErrorCodes.emptyValue, 'text_body must not be empty');
  }
  validateLengthRange(bodyLength, 1, MAX_TEXT_BODY_BYTES, 'text_body');
}
