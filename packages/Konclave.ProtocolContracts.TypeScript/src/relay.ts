import {
  decodeBounded,
  encodeBounded,
  MAX_RELAY_CONTROL_MESSAGE_BYTES,
  MAX_RELAY_ENVELOPE_BYTES,
  MAX_RELAY_PAYLOAD_BYTES,
  MAX_REPLAY_PAGE_BYTES,
  MAX_REPLAY_PAGE_SIZE,
  MAX_STORED_RELAY_ENVELOPE_BYTES,
  required,
  validateFixedBytes,
  validateLengthRange,
  validateRepeatedFieldLimits,
  validateUint64,
  validateVersion,
} from './common.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';
import {
  AcknowledgeRequestSchema,
  DeliveryClass,
  RelayEnvelopeSchema,
  ReplayPageSchema,
  ReplayRequestSchema,
  StoredRelayEnvelopeSchema,
  type AcknowledgeRequest,
  type RelayEnvelope,
  type ReplayPage,
  type ReplayRequest,
  type StoredRelayEnvelope,
} from './generated/konclave/protocol/v1/relay_pb.js';

const relayContract = 'RelayEnvelope';

/**
 * Encodes one validated opaque relay envelope.
 *
 * @throws {ProtocolValidationError} When the envelope violates a v1 bound or invariant.
 */
export function encodeRelayEnvelope(value: RelayEnvelope): Uint8Array {
  validateRelayEnvelope(value);
  return encodeBounded(RelayEnvelopeSchema, value, MAX_RELAY_ENVELOPE_BYTES, relayContract);
}

/**
 * Decodes and validates one untrusted opaque relay envelope.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeRelayEnvelope(bytes: Uint8Array): RelayEnvelope {
  const value = decodeBounded(RelayEnvelopeSchema, bytes, MAX_RELAY_ENVELOPE_BYTES, relayContract);
  validateRelayEnvelope(value);
  return value;
}

/**
 * Encodes one relay envelope with its durable cursor.
 *
 * @throws {ProtocolValidationError} When the stored envelope violates a v1 invariant.
 */
export function encodeStoredRelayEnvelope(value: StoredRelayEnvelope): Uint8Array {
  validateStoredRelayEnvelope(value);
  return encodeBounded(
    StoredRelayEnvelopeSchema,
    value,
    MAX_STORED_RELAY_ENVELOPE_BYTES,
    'StoredRelayEnvelope',
  );
}

/**
 * Decodes and validates one relay envelope with its durable cursor.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeStoredRelayEnvelope(bytes: Uint8Array): StoredRelayEnvelope {
  const value = decodeBounded(
    StoredRelayEnvelopeSchema,
    bytes,
    MAX_STORED_RELAY_ENVELOPE_BYTES,
    'StoredRelayEnvelope',
  );
  validateStoredRelayEnvelope(value);
  return value;
}

/**
 * Encodes one bounded relay replay request.
 *
 * @throws {ProtocolValidationError} When the request violates a v1 bound or invariant.
 */
export function encodeReplayRequest(value: ReplayRequest): Uint8Array {
  validateReplayRequest(value);
  return encodeBounded(
    ReplayRequestSchema,
    value,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    'ReplayRequest',
  );
}

/**
 * Decodes and validates one bounded relay replay request.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeReplayRequest(bytes: Uint8Array): ReplayRequest {
  const value = decodeBounded(
    ReplayRequestSchema,
    bytes,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    'ReplayRequest',
  );
  validateReplayRequest(value);
  return value;
}

/**
 * Encodes one ordered relay replay page.
 *
 * @throws {ProtocolValidationError} When the page violates a v1 bound or ordering rule.
 */
export function encodeReplayPage(value: ReplayPage): Uint8Array {
  validateReplayPage(value);
  return encodeBounded(ReplayPageSchema, value, MAX_REPLAY_PAGE_BYTES, 'ReplayPage');
}

/**
 * Decodes and validates one ordered relay replay page.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeReplayPage(bytes: Uint8Array): ReplayPage {
  validateRepeatedFieldLimits(bytes, MAX_REPLAY_PAGE_BYTES, 'ReplayPage', [
    { field: 'replay_envelopes', fieldNumber: 1, maximum: MAX_REPLAY_PAGE_SIZE },
  ]);
  const value = decodeBounded(ReplayPageSchema, bytes, MAX_REPLAY_PAGE_BYTES, 'ReplayPage');
  validateReplayPage(value);
  return value;
}

/**
 * Encodes one contiguous durable-cursor acknowledgment.
 *
 * @throws {ProtocolValidationError} When the acknowledgment violates a v1 invariant.
 */
export function encodeAcknowledgeRequest(value: AcknowledgeRequest): Uint8Array {
  validateAcknowledgeRequest(value);
  return encodeBounded(
    AcknowledgeRequestSchema,
    value,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    'AcknowledgeRequest',
  );
}

/**
 * Decodes and validates one contiguous durable-cursor acknowledgment.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeAcknowledgeRequest(bytes: Uint8Array): AcknowledgeRequest {
  const value = decodeBounded(
    AcknowledgeRequestSchema,
    bytes,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    'AcknowledgeRequest',
  );
  validateAcknowledgeRequest(value);
  return value;
}

function validateRelayEnvelope(value: RelayEnvelope): void {
  validateVersion(value.version, relayContract);
  validateFixedBytes(required(value.routingId, 'routing_id').value, 32, 'routing_id');
  validateFixedBytes(required(value.envelopeId, 'envelope_id').value, 16, 'envelope_id');
  if (
    value.deliveryClass < DeliveryClass.KEY_PACKAGE ||
    value.deliveryClass > DeliveryClass.PAIRING
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedEnum,
      'delivery_class is unsupported',
    );
  }
  const requiresParentEpoch =
    value.deliveryClass === DeliveryClass.GROUP_PROPOSAL ||
    value.deliveryClass === DeliveryClass.GROUP_COMMIT;
  if (requiresParentEpoch !== (value.expectedParentEpoch !== undefined)) {
    throw new ProtocolValidationError(
      protocolErrorCodes.invalidExpectedParentEpoch,
      'expected_parent_epoch does not match the delivery class',
    );
  }
  if (value.expectedParentEpoch !== undefined) {
    validateUint64(value.expectedParentEpoch, 'expected_parent_epoch', false);
  }
  validateUint64(value.expiresAtUnixSeconds, 'expires_at_unix_seconds', true);
  validateLengthRange(value.payload.byteLength, 1, MAX_RELAY_PAYLOAD_BYTES, 'relay_payload');
}

function validateStoredRelayEnvelope(value: StoredRelayEnvelope): void {
  const envelope = required(value.envelope, 'stored_relay_envelope.envelope');
  validateRelayEnvelope(envelope);
  encodeBounded(RelayEnvelopeSchema, envelope, MAX_RELAY_ENVELOPE_BYTES, relayContract);
  validateUint64(value.cursor, 'cursor', true);
}

function validateReplayRequest(value: ReplayRequest): void {
  validateFixedBytes(required(value.routingId, 'routing_id').value, 32, 'routing_id');
  validateUint64(value.afterCursor, 'after_cursor', false);
  if (!Number.isInteger(value.limit) || value.limit < 1 || value.limit > MAX_REPLAY_PAGE_SIZE) {
    throw new ProtocolValidationError(
      protocolErrorCodes.outOfRange,
      'replay_limit must be from 1 through 100',
    );
  }
}

function validateReplayPage(value: ReplayPage): void {
  validateLengthRange(value.envelopes.length, 0, MAX_REPLAY_PAGE_SIZE, 'replay_envelopes');
  validateUint64(value.nextCursor, 'next_cursor', false);
  let previousCursor = 0n;
  for (const envelope of value.envelopes) {
    validateStoredRelayEnvelope(envelope);
    if (envelope.cursor <= previousCursor) {
      throw new ProtocolValidationError(
        protocolErrorCodes.invalidReplayOrder,
        'replay cursors must be strictly increasing',
      );
    }
    previousCursor = envelope.cursor;
  }
  if (value.nextCursor < previousCursor) {
    throw new ProtocolValidationError(
      protocolErrorCodes.invalidReplayOrder,
      'next_cursor cannot precede the final envelope',
    );
  }
}

function validateAcknowledgeRequest(value: AcknowledgeRequest): void {
  validateFixedBytes(required(value.routingId, 'routing_id').value, 32, 'routing_id');
  validateUint64(value.cursor, 'cursor', true);
}
