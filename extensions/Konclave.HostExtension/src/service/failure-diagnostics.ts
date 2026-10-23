import { createHash } from 'node:crypto';

/** Diagnostic labels describe a boundary, never an authorization decision or retry permission. */
const localFailureStages = [
  'client_validation',
  'connect',
  'service_challenge',
  'service_identity',
  'service_decision',
  'request_write',
  'response_read',
  'response_decode',
  'tool_dispatch',
  'startup',
  'unknown_boundary',
] as const;

export type LocalFailureStage = (typeof localFailureStages)[number];

/** The closed set of refusal codes carried by the shared local service protocol. */
export const localServiceErrorCodes = {
  1: 'invalid_request',
  2: 'unknown_operation',
  3: 'not_authorized',
  4: 'profile_unavailable',
  5: 'busy',
  6: 'deadline_exceeded',
  7: 'payload_too_large',
  8: 'conflict',
  9: 'internal',
  10: 'cancelled',
  11: 'reconciliation_pending',
  12: 'profile_suspended',
  13: 'issuer_disabled',
  14: 'required_evidence_unavailable',
  15: 'capacity',
} as const;

export type LocalServiceErrorCode =
  (typeof localServiceErrorCodes)[keyof typeof localServiceErrorCodes];

export type LocalFailureCode =
  | LocalServiceErrorCode
  | (typeof transportFailureCodes)[number];

const transportFailureCodes = [
  'channel_closed',
  'frame_invalid',
  'protocol_invalid',
  'service_upgrade_required',
  'connection_unavailable',
  'unclassified_failure',
] as const;

const allowedStages: ReadonlySet<string> = new Set(localFailureStages);
const allowedCodes: ReadonlySet<string> = new Set([
  ...Object.values(localServiceErrorCodes),
  ...transportFailureCodes,
]);

/** Contains only locally created labels and a hash of a fresh handshake nonce. */
export interface LocalFailureDiagnostic {
  readonly stage: LocalFailureStage;
  readonly code: LocalFailureCode;
  readonly connectionReference?: string;
  readonly requestSequence?: number;
}

export function connectionReference(instance: Uint8Array): string {
  if (instance.byteLength !== 16) {
    throw new Error('local diagnostic nonce length is invalid');
  }
  return createHash('sha256')
    .update('konclave:local-connection\0')
    .update(instance)
    .digest('hex')
    .slice(0, 16);
}

export function formatLocalFailure(diagnostic: {
  readonly stage: unknown;
  readonly code: unknown;
  readonly connectionReference?: unknown;
  readonly requestSequence?: unknown;
}): string {
  const stage =
    typeof diagnostic.stage === 'string' && allowedStages.has(diagnostic.stage)
      ? diagnostic.stage
      : 'unknown_boundary';
  const code =
    typeof diagnostic.code === 'string' && allowedCodes.has(diagnostic.code)
      ? diagnostic.code
      : 'unclassified_failure';
  const reference =
    typeof diagnostic.connectionReference === 'string' &&
    diagnostic.connectionReference.length === 16 &&
    /^[a-f0-9]{16}$/.test(diagnostic.connectionReference)
      ? ` connection=${diagnostic.connectionReference}`
      : '';
  const sequence =
    typeof diagnostic.requestSequence === 'number' &&
    Number.isSafeInteger(diagnostic.requestSequence) &&
    diagnostic.requestSequence > 0
      ? ` request=${diagnostic.requestSequence}`
      : '';
  return (
    `Konclave local failure: stage=${stage} code=${code}${reference}${sequence}. ` +
    'An interrupted request may have committed; reconcile using its original identifiers.'
  );
}
