import { create, toBinary } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';

import { decodeApplicationMessage } from '../src/application.js';
import {
  decodeCollaborationPolicyBundle,
  deriveCollaborationPolicyDigest,
  encodeCollaborationPolicyBundle,
  validateCollaborationPolicyProposal,
  validateCollaborationPolicyResponse,
  validateCollaborationPolicyRevocation,
  verifyCollaborationPolicyProposal,
} from '../src/collaboration-policy.js';
import { ProtocolValidationError } from '../src/error.js';
import { ApplicationMessageSchema } from '../src/generated/konclave/protocol/v1/application_pb.js';
import {
  CollaborationPolicyBundleSchema,
  CollaborationPolicyDigestSchema,
  CollaborationPolicyEffect,
  CollaborationPolicyLimitsSchema,
  CollaborationPolicyProposalIdSchema,
  CollaborationPolicyProposalSchema,
  CollaborationPolicyResponseOutcome,
  CollaborationPolicyResponseSchema,
  CollaborationPolicyRevocationSchema,
  CollaborationPolicyStatementSchema,
} from '../src/generated/konclave/protocol/v1/collaboration_policy_pb.js';
import {
  MessageIdSchema,
  ProtocolVersionSchema,
} from '../src/generated/konclave/protocol/v1/common_pb.js';
import { bytes, collaborationPolicyBundle, collaborationPolicyDigest } from './messages.js';

function first<T>(values: readonly T[], label: string): T {
  const value = values[0];
  if (value === undefined) {
    throw new Error(`${label} fixture is empty`);
  }
  return value;
}

describe('collaboration policy contract', () => {
  it('derives stable content-sensitive digests', () => {
    const first = deriveCollaborationPolicyDigest(collaborationPolicyBundle());
    const repeated = deriveCollaborationPolicyDigest(collaborationPolicyBundle());
    const changed = deriveCollaborationPolicyDigest(
      collaborationPolicyBundle({ guidance: 'Align another contract.' }),
    );

    expect(first).toEqual(repeated);
    expect(first).not.toEqual(changed);
    expect(first).toHaveLength(32);
    expect(Buffer.from(first).toString('hex')).toBe(
      'f8189b647127aa9ff9d03f5c2d048bcd8eb8600620bc1796c4c668fa5990eb2e',
    );
  });

  it('canonicalizes statement and claim ordering without mutating the source', () => {
    const canonical = collaborationPolicyBundle();
    const reversed = collaborationPolicyBundle({
      reverseStatements: true,
      reverseClaims: true,
    });
    expect(encodeCollaborationPolicyBundle(reversed)).toEqual(
      encodeCollaborationPolicyBundle(canonical),
    );
    expect(reversed.statements[0]?.statementId).toBe('workspace-write');
    expect(reversed.requiredHarnessClaims[0]).toBe('copilot.tool-interception');

    const duplicateStatements = collaborationPolicyBundle();
    duplicateStatements.statements[1] = first(duplicateStatements.statements, 'statement');
    expect(() => encodeCollaborationPolicyBundle(duplicateStatements)).toThrow(
      ProtocolValidationError,
    );

    const duplicateClaims = collaborationPolicyBundle();
    duplicateClaims.requiredHarnessClaims[1] = first(
      duplicateClaims.requiredHarnessClaims,
      'harness claim',
    );
    expect(() => encodeCollaborationPolicyBundle(duplicateClaims)).toThrow(ProtocolValidationError);
  });

  it('rejects malformed identifiers, effects, limits, and required fields', () => {
    expect(() =>
      encodeCollaborationPolicyBundle(collaborationPolicyBundle({ name: 'Not Canonical' })),
    ).toThrow(ProtocolValidationError);

    const invalidEffect = collaborationPolicyBundle();
    const invalidStatement = invalidEffect.statements[0];
    if (invalidStatement === undefined) {
      throw new Error('policy fixture is missing its first statement');
    }
    invalidStatement.effect = CollaborationPolicyEffect.UNSPECIFIED;
    expect(() => encodeCollaborationPolicyBundle(invalidEffect)).toThrow(ProtocolValidationError);

    const invalidLimit = collaborationPolicyBundle();
    if (invalidLimit.limits === undefined) {
      throw new Error('policy fixture is missing its limits');
    }
    invalidLimit.limits.turns = 0n;
    expect(() => encodeCollaborationPolicyBundle(invalidLimit)).toThrow(ProtocolValidationError);

    const unnamespacedAction = collaborationPolicyBundle();
    const unnamespacedStatement = unnamespacedAction.statements[0];
    if (unnamespacedStatement === undefined) {
      throw new Error('policy fixture is missing its first statement');
    }
    unnamespacedStatement.action = 'reply';
    expect(() => encodeCollaborationPolicyBundle(unnamespacedAction)).toThrow(
      ProtocolValidationError,
    );

    expect(() =>
      encodeCollaborationPolicyBundle(collaborationPolicyBundle({ name: 'contráct' })),
    ).toThrow(ProtocolValidationError);
    expect(() =>
      encodeCollaborationPolicyBundle(collaborationPolicyBundle({ name: 'contract..alignment' })),
    ).toThrow(ProtocolValidationError);
    expect(() =>
      encodeCollaborationPolicyBundle(collaborationPolicyBundle({ name: 'x'.repeat(129) })),
    ).toThrow(ProtocolValidationError);
    expect(() =>
      encodeCollaborationPolicyBundle(collaborationPolicyBundle({ guidance: '' })),
    ).toThrow(ProtocolValidationError);
    expect(() =>
      encodeCollaborationPolicyBundle(collaborationPolicyBundle({ guidance: 'x'.repeat(32_769) })),
    ).toThrow(ProtocolValidationError);

    const missingLimits = collaborationPolicyBundle();
    missingLimits.limits = undefined;
    expect(() => encodeCollaborationPolicyBundle(missingLimits)).toThrow(ProtocolValidationError);
  });

  it('validates every effect and optional limit branch', () => {
    const value = collaborationPolicyBundle();
    value.guidance = undefined;
    first(value.statements, 'statement').effect = CollaborationPolicyEffect.DENY;
    value.limits = create(CollaborationPolicyLimitsSchema, {
      durationMilliseconds: 1n,
      turns: 1n,
    });
    expect(() => encodeCollaborationPolicyBundle(value)).not.toThrow();

    for (const concurrentRequests of [0, 1.5, 4_294_967_296]) {
      const invalid = collaborationPolicyBundle();
      invalid.limits = create(CollaborationPolicyLimitsSchema, { concurrentRequests });
      expect(() => encodeCollaborationPolicyBundle(invalid)).toThrow(ProtocolValidationError);
    }

    const unlimited = collaborationPolicyBundle();
    unlimited.limits = create(CollaborationPolicyLimitsSchema);
    expect(() => encodeCollaborationPolicyBundle(unlimited)).not.toThrow();
  });

  it('rejects oversized statement and harness-claim collections', () => {
    const statements = collaborationPolicyBundle();
    statements.statements = Array.from({ length: 257 }, (_, index) =>
      create(CollaborationPolicyStatementSchema, {
        statementId: `statement-${index}`,
        effect: CollaborationPolicyEffect.ALLOW,
        action: 'conversation.reply',
      }),
    );
    expect(() => encodeCollaborationPolicyBundle(statements)).toThrow(ProtocolValidationError);

    const claims = collaborationPolicyBundle();
    claims.requiredHarnessClaims = Array.from(
      { length: 65 },
      (_, index) => `copilot.claim-${index}`,
    );
    expect(() => encodeCollaborationPolicyBundle(claims)).toThrow(ProtocolValidationError);
  });

  it('rejects semantically valid but noncanonical wire ordering', () => {
    const bytes = toBinary(
      CollaborationPolicyBundleSchema,
      collaborationPolicyBundle({ reverseStatements: true }),
    );
    expect(() => decodeCollaborationPolicyBundle(bytes)).toThrow(ProtocolValidationError);

    const canonical = encodeCollaborationPolicyBundle(collaborationPolicyBundle());
    const unknownField = Uint8Array.from([...canonical, 0x38, 0x01]);
    expect(() => decodeCollaborationPolicyBundle(unknownField)).toThrow(ProtocolValidationError);
  });

  it('rejects an unknown wire effect', () => {
    const value = create(CollaborationPolicyBundleSchema, {
      version: create(ProtocolVersionSchema, { major: 1, minor: 0 }),
      name: 'contract-alignment',
      statements: [
        create(CollaborationPolicyStatementSchema, {
          statementId: 'reply',
          effect: CollaborationPolicyEffect.ALLOW,
          action: 'conversation.reply',
        }),
      ],
      limits: create(CollaborationPolicyLimitsSchema),
    });
    const bytes = toBinary(CollaborationPolicyBundleSchema, value);
    const effectIndex = bytes.findIndex(
      (byte, index) => byte === 0x10 && bytes[index + 1] === CollaborationPolicyEffect.ALLOW,
    );
    expect(effectIndex).toBeGreaterThan(0);
    bytes[effectIndex + 1] = 99;
    expect(() => decodeCollaborationPolicyBundle(bytes)).toThrow(ProtocolValidationError);
  });

  it('verifies canonical proposal bytes against the claimed digest', () => {
    const canonicalBundle = encodeCollaborationPolicyBundle(collaborationPolicyBundle());
    const proposal = create(CollaborationPolicyProposalSchema, {
      proposalId: create(CollaborationPolicyProposalIdSchema, { value: bytes(16, 1) }),
      policyDigest: create(CollaborationPolicyDigestSchema, {
        value: collaborationPolicyDigest(),
      }),
      canonicalBundle,
      replacesPolicyDigest: create(CollaborationPolicyDigestSchema, { value: bytes(32, 2) }),
    });

    const verifiedBundle = verifyCollaborationPolicyProposal(proposal);
    expect(verifiedBundle).toEqual(collaborationPolicyBundle());
    expect(proposal.replacesPolicyDigest?.value).toEqual(bytes(32, 2));

    proposal.policyDigest = create(CollaborationPolicyDigestSchema, { value: bytes(32, 3) });
    expect(() => verifyCollaborationPolicyProposal(proposal)).toThrowError(
      expect.objectContaining({ code: 'invalid_collaboration_policy_digest' }),
    );

    proposal.policyDigest = create(CollaborationPolicyDigestSchema, {
      value: collaborationPolicyDigest(),
    });
    proposal.canonicalBundle = Uint8Array.from([...canonicalBundle, 0x38, 0x01]);
    expect(() => verifyCollaborationPolicyProposal(proposal)).toThrowError(
      expect.objectContaining({ code: 'non_canonical_encoding' }),
    );
  });

  it('validates every policy exchange envelope', () => {
    const canonicalBundle = encodeCollaborationPolicyBundle(collaborationPolicyBundle());
    const proposal = create(CollaborationPolicyProposalSchema, {
      proposalId: create(CollaborationPolicyProposalIdSchema, { value: bytes(16, 1) }),
      policyDigest: create(CollaborationPolicyDigestSchema, {
        value: collaborationPolicyDigest(),
      }),
      canonicalBundle,
    });
    expect(() => validateCollaborationPolicyProposal(proposal)).not.toThrow();

    proposal.proposalId = create(CollaborationPolicyProposalIdSchema, { value: bytes(15, 1) });
    expect(() => validateCollaborationPolicyProposal(proposal)).toThrow(ProtocolValidationError);
    proposal.proposalId = create(CollaborationPolicyProposalIdSchema, { value: bytes(16, 1) });
    proposal.policyDigest = create(CollaborationPolicyDigestSchema, { value: bytes(31, 1) });
    expect(() => validateCollaborationPolicyProposal(proposal)).toThrow(ProtocolValidationError);
    proposal.policyDigest = create(CollaborationPolicyDigestSchema, {
      value: collaborationPolicyDigest(),
    });
    proposal.canonicalBundle = new Uint8Array();
    expect(() => validateCollaborationPolicyProposal(proposal)).toThrow(ProtocolValidationError);
    proposal.canonicalBundle = bytes(65_537, 1);
    expect(() => validateCollaborationPolicyProposal(proposal)).toThrow(ProtocolValidationError);
    proposal.canonicalBundle = canonicalBundle;
    proposal.replacesPolicyDigest = create(CollaborationPolicyDigestSchema, {
      value: bytes(31, 1),
    });
    expect(() => validateCollaborationPolicyProposal(proposal)).toThrow(ProtocolValidationError);

    const response = create(CollaborationPolicyResponseSchema, {
      proposalId: create(CollaborationPolicyProposalIdSchema, { value: bytes(16, 1) }),
      policyDigest: create(CollaborationPolicyDigestSchema, {
        value: collaborationPolicyDigest(),
      }),
      outcome: CollaborationPolicyResponseOutcome.REJECTED,
    });
    expect(() => validateCollaborationPolicyResponse(response)).not.toThrow();
    Object.defineProperty(response, 'outcome', { value: 99 });
    expect(() => validateCollaborationPolicyResponse(response)).toThrow(ProtocolValidationError);

    const revocation = create(CollaborationPolicyRevocationSchema, {
      policyDigest: create(CollaborationPolicyDigestSchema, {
        value: collaborationPolicyDigest(),
      }),
    });
    expect(() => validateCollaborationPolicyRevocation(revocation)).not.toThrow();
    revocation.policyDigest = undefined;
    expect(() => validateCollaborationPolicyRevocation(revocation)).toThrow(
      ProtocolValidationError,
    );
  });

  it('rejects an oversized nested bundle before application decoding', () => {
    const proposal = create(CollaborationPolicyProposalSchema, {
      proposalId: create(CollaborationPolicyProposalIdSchema, { value: bytes(16, 1) }),
      policyDigest: create(CollaborationPolicyDigestSchema, { value: bytes(32, 2) }),
      canonicalBundle: bytes(65_537, 3),
    });
    const application = create(ApplicationMessageSchema, {
      version: create(ProtocolVersionSchema, { major: 1, minor: 0 }),
      messageId: create(MessageIdSchema, { value: bytes(16, 4) }),
      senderCounter: 1n,
      sentAtUnixMilliseconds: 1n,
      content: { case: 'collaborationPolicyProposal', value: proposal },
    });

    expect(() =>
      decodeApplicationMessage(toBinary(ApplicationMessageSchema, application)),
    ).toThrowError(expect.objectContaining({ code: 'out_of_range' }));
  });

  it('rejects malformed nested proposal framing before application decoding', () => {
    const wrongWireType = Uint8Array.from([0x58, 0x00]);
    const truncatedProposal = Uint8Array.from([0x5a, 0x02, 0x00]);

    for (const malformed of [wrongWireType, truncatedProposal]) {
      expect(() => decodeApplicationMessage(malformed)).toThrowError(
        expect.objectContaining({ code: 'malformed' }),
      );
    }
  });
});
