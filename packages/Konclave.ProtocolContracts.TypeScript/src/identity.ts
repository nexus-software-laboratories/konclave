import {
  bytesEqual,
  decodeBounded,
  encodeBounded,
  MAX_APPLICATION_MESSAGE_BYTES,
  MAX_MLS_KEY_PACKAGE_BYTES,
  required,
  validateFixedBytes,
  validateLengthRange,
  validateRole,
  validateUint64,
  validateVersion,
} from './common.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';
import {
  DeviceCredentialBindingSchema,
  InvitationSchema,
  JoinProofSchema,
  SignatureScheme,
  type DeviceCredentialBinding,
  type Invitation,
  type JoinProof,
} from './generated/konclave/protocol/v1/identity_pb.js';

const credentialContract = 'DeviceCredentialBinding';
const invitationContract = 'Invitation';
const joinProofContract = 'JoinProof';

/**
 * Encodes a shape-validated public device credential binding.
 *
 * @throws {ProtocolValidationError} When the binding violates a v1 bound or invariant.
 */
export function encodeDeviceCredentialBinding(value: DeviceCredentialBinding): Uint8Array {
  validateDeviceCredentialBinding(value);
  return encodeBounded(
    DeviceCredentialBindingSchema,
    value,
    MAX_APPLICATION_MESSAGE_BYTES,
    credentialContract,
  );
}

/**
 * Decodes and shape-validates a public device credential binding.
 *
 * Signature verification and `DeviceId` derivation remain the caller's responsibility.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeDeviceCredentialBinding(bytes: Uint8Array): DeviceCredentialBinding {
  const value = decodeBounded(
    DeviceCredentialBindingSchema,
    bytes,
    MAX_APPLICATION_MESSAGE_BYTES,
    credentialContract,
  );
  validateDeviceCredentialBinding(value);
  return value;
}

/**
 * Encodes a shape-validated invitation.
 *
 * @throws {ProtocolValidationError} When the invitation violates a v1 bound or invariant.
 */
export function encodeInvitation(value: Invitation): Uint8Array {
  validateInvitation(value);
  return encodeBounded(InvitationSchema, value, MAX_APPLICATION_MESSAGE_BYTES, invitationContract);
}

/**
 * Decodes and shape-validates an invitation.
 *
 * Signature, expiry, and consumption checks remain the caller's responsibility.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeInvitation(bytes: Uint8Array): Invitation {
  const value = decodeBounded(
    InvitationSchema,
    bytes,
    MAX_APPLICATION_MESSAGE_BYTES,
    invitationContract,
  );
  validateInvitation(value);
  return value;
}

/**
 * Encodes a shape-validated invitation-bound join proof.
 *
 * @throws {ProtocolValidationError} When the proof violates a v1 bound or invariant.
 */
export function encodeJoinProof(value: JoinProof): Uint8Array {
  validateJoinProof(value);
  return encodeBounded(JoinProofSchema, value, MAX_APPLICATION_MESSAGE_BYTES, joinProofContract);
}

/**
 * Decodes and shape-validates an invitation-bound join proof.
 *
 * Cryptographic and administrator authorization checks remain the caller's responsibility.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized, or invalid.
 */
export function decodeJoinProof(bytes: Uint8Array): JoinProof {
  const value = decodeBounded(
    JoinProofSchema,
    bytes,
    MAX_APPLICATION_MESSAGE_BYTES,
    joinProofContract,
  );
  validateJoinProof(value);
  return value;
}

function validateDeviceCredentialBinding(value: DeviceCredentialBinding): void {
  validateVersion(value.version, credentialContract);
  validateFixedBytes(required(value.deviceId, 'device_id').value, 32, 'device_id');
  validateFixedBytes(
    required(value.conversationId, 'conversation_id').value,
    32,
    'conversation_id',
  );
  if (value.signatureScheme !== SignatureScheme.ED25519) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedEnum,
      'signature_scheme is unsupported',
    );
  }
  validateFixedBytes(value.deviceRootPublicKey, 32, 'device_root_public_key');
  validateFixedBytes(value.conversationSignaturePublicKey, 32, 'conversation_signature_public_key');
  validateFixedBytes(value.deviceBindingSignature, 64, 'device_binding_signature');
}

function validateInvitation(value: Invitation): void {
  validateVersion(value.version, invitationContract);
  validateFixedBytes(required(value.invitationId, 'invitation_id').value, 16, 'invitation_id');
  validateFixedBytes(
    required(value.conversationId, 'conversation_id').value,
    32,
    'conversation_id',
  );
  validateFixedBytes(
    required(value.expectedDeviceId, 'expected_device_id').value,
    32,
    'expected_device_id',
  );
  validateRole(value.role);
  validateUint64(value.expiresAtUnixSeconds, 'expires_at_unix_seconds', true);
  validateFixedBytes(value.nonce, 32, 'invitation_nonce');
  validateFixedBytes(
    required(value.issuerDeviceId, 'issuer_device_id').value,
    32,
    'issuer_device_id',
  );
  validateFixedBytes(value.issuerSignature, 64, 'issuer_signature');
}

function validateJoinProof(value: JoinProof): void {
  const invitation = required(value.invitation, 'join_proof.invitation');
  const credential = required(value.credential, 'join_proof.credential');
  validateInvitation(invitation);
  validateDeviceCredentialBinding(credential);
  if (
    !bytesEqual(
      required(invitation.expectedDeviceId, 'expected_device_id').value,
      required(credential.deviceId, 'device_id').value,
    )
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.mismatchedInvitedDevice,
      'join credential does not match the invited device',
    );
  }
  if (
    !bytesEqual(
      required(invitation.conversationId, 'conversation_id').value,
      required(credential.conversationId, 'conversation_id').value,
    )
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.mismatchedInvitedConversation,
      'join credential does not match the invited conversation',
    );
  }
  validateLengthRange(
    value.mlsKeyPackage.byteLength,
    1,
    MAX_MLS_KEY_PACKAGE_BYTES,
    'mls_key_package',
  );
}
