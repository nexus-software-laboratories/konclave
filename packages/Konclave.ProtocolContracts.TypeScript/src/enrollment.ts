import {
  decodeBounded,
  encodeBounded,
  MAX_RELAY_CONTROL_MESSAGE_BYTES,
  required,
  validateFixedBytes,
  validateVersion,
} from './common.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';
import {
  RelayEnrollmentOutcome,
  RelayEnrollmentRequestSchema,
  RelayEnrollmentResponseSchema,
  type RelayEnrollmentRequest,
  type RelayEnrollmentResponse,
} from './generated/konclave/protocol/v1/enrollment_pb.js';

const requestContract = 'RelayEnrollmentRequest';
const responseContract = 'RelayEnrollmentResponse';

/** Encodes one bounded principal-registration request. */
export function encodeRelayEnrollmentRequest(value: RelayEnrollmentRequest): Uint8Array {
  validateRequest(value);
  return encodeBounded(
    RelayEnrollmentRequestSchema,
    value,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    requestContract,
  );
}

/** Decodes and validates one untrusted principal-registration request. */
export function decodeRelayEnrollmentRequest(bytes: Uint8Array): RelayEnrollmentRequest {
  const value = decodeBounded(
    RelayEnrollmentRequestSchema,
    bytes,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    requestContract,
  );
  validateRequest(value);
  return value;
}

/** Encodes one bounded principal-registration response. */
export function encodeRelayEnrollmentResponse(value: RelayEnrollmentResponse): Uint8Array {
  validateResponse(value);
  return encodeBounded(
    RelayEnrollmentResponseSchema,
    value,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    responseContract,
  );
}

/** Decodes and validates one untrusted principal-registration response. */
export function decodeRelayEnrollmentResponse(bytes: Uint8Array): RelayEnrollmentResponse {
  const value = decodeBounded(
    RelayEnrollmentResponseSchema,
    bytes,
    MAX_RELAY_CONTROL_MESSAGE_BYTES,
    responseContract,
  );
  validateResponse(value);
  return value;
}

function validateRequest(value: RelayEnrollmentRequest): void {
  validateVersion(value.version, requestContract);
  validateFixedBytes(
    required(value.requestId, 'enrollment_request_id').value,
    16,
    'enrollment_request_id',
  );
  validateFixedBytes(
    required(value.principalId, 'relay_principal_id').value,
    32,
    'relay_principal_id',
  );
}

function validateResponse(value: RelayEnrollmentResponse): void {
  validateVersion(value.version, responseContract);
  validateFixedBytes(
    required(value.requestId, 'enrollment_request_id').value,
    16,
    'enrollment_request_id',
  );
  validateFixedBytes(
    required(value.principalId, 'relay_principal_id').value,
    32,
    'relay_principal_id',
  );
  if (
    value.outcome !== RelayEnrollmentOutcome.REGISTERED &&
    value.outcome !== RelayEnrollmentOutcome.ALREADY_REGISTERED
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedEnum,
      'relay_enrollment_outcome is unsupported',
    );
  }
}
