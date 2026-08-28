import { createHash } from 'node:crypto';

import { create } from '@bufbuild/protobuf';

import {
  bytesEqual,
  decodeBounded,
  encodeBounded,
  required,
  validateFixedBytes,
  validateLengthRange,
  validateRepeatedFieldLimits,
  validateUint64,
  validateVersion,
} from './common.js';
import {
  CollaborationPolicyBundleSchema,
  CollaborationPolicyEffect,
  CollaborationPolicyResponseOutcome,
  type CollaborationPolicyBundle,
  type CollaborationPolicyLimits,
  type CollaborationPolicyProposal,
  type CollaborationPolicyResponse,
  type CollaborationPolicyRevocation,
  type CollaborationPolicyStatement,
} from './generated/konclave/protocol/v1/collaboration_policy_pb.js';
import { protocolErrorCodes, ProtocolValidationError } from './error.js';

/** Maximum canonical encoded collaboration-policy bundle size. */
export const MAX_COLLABORATION_POLICY_BUNDLE_BYTES = 64 * 1024;
/** Maximum UTF-8 bytes in one policy name. */
export const MAX_COLLABORATION_POLICY_NAME_BYTES = 128;
/** Maximum UTF-8 bytes in optional model guidance. */
export const MAX_COLLABORATION_POLICY_GUIDANCE_BYTES = 32 * 1024;
/** Maximum statements in one policy bundle. */
export const MAX_COLLABORATION_POLICY_STATEMENTS = 256;
/** Maximum UTF-8 bytes in one statement identifier. */
export const MAX_COLLABORATION_POLICY_STATEMENT_ID_BYTES = 128;
/** Maximum UTF-8 bytes in one namespaced action identifier. */
export const MAX_COLLABORATION_POLICY_ACTION_BYTES = 256;
/** Maximum UTF-8 bytes in one namespaced resource identifier. */
export const MAX_COLLABORATION_POLICY_RESOURCE_BYTES = 256;
/** Maximum harness claims required by one policy bundle. */
export const MAX_COLLABORATION_POLICY_HARNESS_CLAIMS = 64;
/** Maximum UTF-8 bytes in one namespaced harness claim. */
export const MAX_COLLABORATION_POLICY_HARNESS_CLAIM_BYTES = 256;

const contract = 'CollaborationPolicyBundle';
const textEncoder = new TextEncoder();
const digestDomain = textEncoder.encode('konclave-collaboration-policy-bundle-digest-v1\0');
const UINT32_MAX = 4_294_967_295;

/**
 * Encodes one validated canonical collaboration-policy bundle.
 *
 * @throws {ProtocolValidationError} When the bundle violates a bound, invariant, or
 * canonical ordering rule.
 */
export function encodeCollaborationPolicyBundle(value: CollaborationPolicyBundle): Uint8Array {
  const canonical = canonicalizeCollaborationPolicyBundle(value);
  return encodeBounded(
    CollaborationPolicyBundleSchema,
    canonical,
    MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
    contract,
  );
}

/**
 * Decodes and validates canonical collaboration-policy bundle bytes.
 *
 * @throws {ProtocolValidationError} When the bytes are malformed, oversized,
 * noncanonical, or semantically invalid.
 */
export function decodeCollaborationPolicyBundle(bytes: Uint8Array): CollaborationPolicyBundle {
  validateRepeatedFieldLimits(bytes, MAX_COLLABORATION_POLICY_BUNDLE_BYTES, contract, [
    {
      field: 'collaboration_policy_statements',
      fieldNumber: 4,
      maximum: MAX_COLLABORATION_POLICY_STATEMENTS,
    },
    {
      field: 'collaboration_policy_harness_claims',
      fieldNumber: 5,
      maximum: MAX_COLLABORATION_POLICY_HARNESS_CLAIMS,
    },
  ]);
  const value = decodeBounded(
    CollaborationPolicyBundleSchema,
    bytes,
    MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
    contract,
  );
  const canonical = canonicalizeCollaborationPolicyBundle(value);
  if (!bytesEqual(encodeCollaborationPolicyBundle(canonical), bytes)) {
    throw new ProtocolValidationError(
      protocolErrorCodes.nonCanonicalEncoding,
      `${contract} is not canonically encoded`,
    );
  }
  return canonical;
}

/**
 * Derives the domain-separated SHA-256 content identifier for one policy bundle.
 *
 * @throws {ProtocolValidationError} When the bundle cannot be canonically encoded.
 */
export function deriveCollaborationPolicyDigest(value: CollaborationPolicyBundle): Uint8Array {
  const hash = createHash('sha256');
  hash.update(digestDomain);
  hash.update(encodeCollaborationPolicyBundle(value));
  return Uint8Array.from(hash.digest());
}

/**
 * Verifies a collaboration-policy proposal and decodes its canonical bundle.
 *
 * @throws {ProtocolValidationError} When proposal metadata is invalid, the bundle is
 * malformed or noncanonical, or its digest does not match.
 */
export function verifyCollaborationPolicyProposal(
  proposal: CollaborationPolicyProposal,
): CollaborationPolicyBundle {
  validateCollaborationPolicyProposal(proposal);
  const bundle = decodeCollaborationPolicyBundle(proposal.canonicalBundle);
  const actualDigest = deriveCollaborationPolicyDigest(bundle);
  if (!bytesEqual(actualDigest, required(proposal.policyDigest, 'policy_digest').value)) {
    throw new ProtocolValidationError(
      protocolErrorCodes.invalidCollaborationPolicyDigest,
      'collaboration policy digest does not match the proposed bundle',
    );
  }
  return bundle;
}

/**
 * Validates one collaboration-policy proposal envelope.
 *
 * @throws {ProtocolValidationError} When an identifier, digest, or bundle violates
 * the protocol v1 contract.
 */
export function validateCollaborationPolicyProposal(value: CollaborationPolicyProposal): void {
  validateFixedBytes(
    required(value.proposalId, 'collaboration_policy_proposal.proposal_id').value,
    16,
    'collaboration_policy_proposal_id',
  );
  validatePolicyDigest(
    required(value.policyDigest, 'collaboration_policy_proposal.policy_digest').value,
  );
  validateLengthRange(
    value.canonicalBundle.byteLength,
    1,
    MAX_COLLABORATION_POLICY_BUNDLE_BYTES,
    'collaboration_policy_bundle',
  );
  if (value.replacesPolicyDigest !== undefined) {
    validatePolicyDigest(value.replacesPolicyDigest.value);
  }
}

/**
 * Validates one collaboration-policy proposal response.
 *
 * @throws {ProtocolValidationError} When its proposal identity, digest, or outcome
 * violates the protocol v1 contract.
 */
export function validateCollaborationPolicyResponse(value: CollaborationPolicyResponse): void {
  validateFixedBytes(
    required(value.proposalId, 'collaboration_policy_response.proposal_id').value,
    16,
    'collaboration_policy_proposal_id',
  );
  validatePolicyDigest(
    required(value.policyDigest, 'collaboration_policy_response.policy_digest').value,
  );
  if (
    value.outcome !== CollaborationPolicyResponseOutcome.ACCEPTED &&
    value.outcome !== CollaborationPolicyResponseOutcome.REJECTED
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedEnum,
      'collaboration_policy_response_outcome is unsupported',
    );
  }
}

/**
 * Validates one collaboration-policy revocation.
 *
 * @throws {ProtocolValidationError} When its policy digest violates the protocol v1
 * contract.
 */
export function validateCollaborationPolicyRevocation(value: CollaborationPolicyRevocation): void {
  validatePolicyDigest(
    required(value.policyDigest, 'collaboration_policy_revocation.policy_digest').value,
  );
}

function validateCollaborationPolicyBundle(value: CollaborationPolicyBundle): void {
  validateVersion(value.version, contract);
  validateCanonicalIdentifier(
    value.name,
    MAX_COLLABORATION_POLICY_NAME_BYTES,
    'collaboration_policy_name',
  );
  if (value.guidance !== undefined) {
    validateBoundedText(
      value.guidance,
      MAX_COLLABORATION_POLICY_GUIDANCE_BYTES,
      'collaboration_policy_guidance',
    );
  }
  validateSortedStatements(value.statements);
  validateSortedHarnessClaims(value.requiredHarnessClaims);
  validateLimits(required(value.limits, 'collaboration_policy.limits'));
}

function validatePolicyDigest(value: Uint8Array): void {
  validateFixedBytes(value, 32, 'collaboration_policy_digest');
}

function canonicalizeCollaborationPolicyBundle(
  value: CollaborationPolicyBundle,
): CollaborationPolicyBundle {
  const statements = [...value.statements].sort((left, right) =>
    left.statementId < right.statementId ? -1 : left.statementId > right.statementId ? 1 : 0,
  );
  const requiredHarnessClaims = [...value.requiredHarnessClaims].sort();
  const canonical = create(CollaborationPolicyBundleSchema, {
    version: value.version,
    name: value.name,
    guidance: value.guidance,
    statements,
    requiredHarnessClaims,
    limits: value.limits,
  });
  validateCollaborationPolicyBundle(canonical);
  return canonical;
}

function validateSortedStatements(statements: readonly CollaborationPolicyStatement[]): void {
  if (statements.length > MAX_COLLABORATION_POLICY_STATEMENTS) {
    throw outOfRange('collaboration_policy_statements');
  }
  let previous: string | undefined;
  for (const statement of statements) {
    validateCanonicalIdentifier(
      statement.statementId,
      MAX_COLLABORATION_POLICY_STATEMENT_ID_BYTES,
      'collaboration_policy_statement_id',
    );
    validateEffect(statement.effect);
    validateNamespacedIdentifier(
      statement.action,
      MAX_COLLABORATION_POLICY_ACTION_BYTES,
      'collaboration_policy_action',
    );
    if (statement.resource !== undefined) {
      validateNamespacedIdentifier(
        statement.resource,
        MAX_COLLABORATION_POLICY_RESOURCE_BYTES,
        'collaboration_policy_resource',
      );
    }
    if (previous === statement.statementId) {
      throw new ProtocolValidationError(
        protocolErrorCodes.duplicateIdentifier,
        'collaboration_policy_statement_id contains a duplicate',
      );
    }
    previous = statement.statementId;
  }
}

function validateSortedHarnessClaims(claims: readonly string[]): void {
  if (claims.length > MAX_COLLABORATION_POLICY_HARNESS_CLAIMS) {
    throw outOfRange('collaboration_policy_harness_claims');
  }
  let previous: string | undefined;
  for (const claim of claims) {
    validateNamespacedIdentifier(
      claim,
      MAX_COLLABORATION_POLICY_HARNESS_CLAIM_BYTES,
      'collaboration_policy_harness_claim',
    );
    if (previous === claim) {
      throw new ProtocolValidationError(
        protocolErrorCodes.duplicateIdentifier,
        'collaboration_policy_harness_claim contains a duplicate',
      );
    }
    previous = claim;
  }
}

function validateEffect(effect: CollaborationPolicyEffect): void {
  if (
    effect !== CollaborationPolicyEffect.ALLOW &&
    effect !== CollaborationPolicyEffect.DENY &&
    effect !== CollaborationPolicyEffect.REQUIRE_LOCAL_APPROVAL
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.unsupportedEnum,
      'collaboration_policy_effect is unsupported',
    );
  }
}

function validateLimits(limits: CollaborationPolicyLimits): void {
  if (limits.durationMilliseconds !== undefined) {
    validateUint64(limits.durationMilliseconds, 'collaboration_policy_duration', true);
  }
  if (limits.turns !== undefined) {
    validateUint64(limits.turns, 'collaboration_policy_turns', true);
  }
  if (limits.tokens !== undefined) {
    validateUint64(limits.tokens, 'collaboration_policy_tokens', true);
  }
  if (
    limits.concurrentRequests !== undefined &&
    (!Number.isInteger(limits.concurrentRequests) ||
      limits.concurrentRequests <= 0 ||
      limits.concurrentRequests > UINT32_MAX)
  ) {
    throw outOfRange('collaboration_policy_concurrent_requests');
  }
}

function validateCanonicalIdentifier(value: string, maximum: number, field: string): void {
  validateBoundedText(value, maximum, field);
  if (
    !isAscii(value) ||
    value.split(/[./]/u).some((segment) => !/^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/u.test(segment))
  ) {
    throw new ProtocolValidationError(
      protocolErrorCodes.nonCanonicalValue,
      `${field} is not canonical lowercase ASCII`,
    );
  }
}

function isAscii(value: string): boolean {
  for (const character of value) {
    if (character.charCodeAt(0) > 0x7f) {
      return false;
    }
  }
  return true;
}

function validateNamespacedIdentifier(value: string, maximum: number, field: string): void {
  validateCanonicalIdentifier(value, maximum, field);
  if (!/[./]/u.test(value)) {
    throw new ProtocolValidationError(
      protocolErrorCodes.nonCanonicalValue,
      `${field} is not namespaced`,
    );
  }
}

function validateBoundedText(value: string, maximum: number, field: string): void {
  const actual = textEncoder.encode(value).byteLength;
  if (actual === 0) {
    throw new ProtocolValidationError(protocolErrorCodes.emptyValue, `${field} must not be empty`);
  }
  if (actual > maximum) {
    throw outOfRange(field);
  }
}

function outOfRange(field: string): ProtocolValidationError {
  return new ProtocolValidationError(protocolErrorCodes.outOfRange, `${field} exceeds its bound`);
}
