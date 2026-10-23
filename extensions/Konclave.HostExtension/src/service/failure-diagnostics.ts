import { createHash } from 'node:crypto';

/** Diagnostic labels describe a boundary, never an authorization decision or retry permission. */
export type LocalFailureStage =
  | 'client_validation'
  | 'connect'
  | 'service_challenge'
  | 'service_identity'
  | 'service_decision'
  | 'request_write'
  | 'response_read'
  | 'response_decode'
  | 'tool_dispatch'
  | 'startup';

export type LocalFailureCode =
  | 'invalid_request'
  | 'unknown_operation'
  | 'not_authorized'
  | 'profile_unavailable'
  | 'busy'
  | 'deadline_exceeded'
  | 'payload_too_large'
  | 'conflict'
  | 'internal'
  | 'cancelled'
  | 'reconciliation_pending'
  | 'profile_suspended'
  | 'issuer_disabled'
  | 'required_evidence_unavailable'
  | 'capacity'
  | 'channel_closed'
  | 'frame_invalid'
  | 'protocol_invalid'
  | 'service_upgrade_required'
  | 'connection_unavailable'
  | 'unclassified_failure';

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

export function formatLocalFailure(diagnostic: LocalFailureDiagnostic): string {
  const reference =
    diagnostic.connectionReference !== undefined &&
    /^[a-f0-9]{16}$/.test(diagnostic.connectionReference)
      ? ` connection=${diagnostic.connectionReference}`
      : '';
  const sequence =
    diagnostic.requestSequence !== undefined &&
    Number.isSafeInteger(diagnostic.requestSequence) &&
    diagnostic.requestSequence > 0
      ? ` request=${diagnostic.requestSequence}`
      : '';
  return (
    `Konclave local failure: stage=${diagnostic.stage} code=${diagnostic.code}${reference}${sequence}. ` +
    'An interrupted request may have committed; reconcile using its original identifiers.'
  );
}
