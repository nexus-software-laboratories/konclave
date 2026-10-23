import { describe, expect, it } from 'vitest';

import {
  attachLocalFailure,
  connectionReference,
  formatLocalFailure,
  formatLocalFailureError,
  localFailureDiagnostic,
} from '../src/service/failure-diagnostics.js';

describe('local failure diagnostic contract', () => {
  it('preserves frozen error identity and its earliest attached boundary', () => {
    const error = Object.freeze(new Error('PRIVATE-CREDENTIAL'));
    const properties = Object.getOwnPropertyNames(error);
    const diagnostic = {
      stage: 'response_read' as const,
      code: 'channel_closed' as const,
      connectionReference: '0123456789abcdef',
      requestSequence: 1,
    };
    attachLocalFailure(error, diagnostic);
    attachLocalFailure(error, { stage: 'tool_dispatch', code: 'internal' });
    expect(localFailureDiagnostic(error)).toBe(diagnostic);
    expect(Object.getOwnPropertyNames(error)).toEqual(properties);
    expect(formatLocalFailureError(error, 'tool_dispatch')).toContain(
      'stage=response_read code=channel_closed connection=0123456789abcdef request=1',
    );
    expect(formatLocalFailureError(error, 'tool_dispatch')).not.toContain('PRIVATE');
    expect(formatLocalFailureError({ code: 'not_authorized' }, 'tool_dispatch')).toContain(
      'code=unclassified_failure',
    );
  });

  it('correlates only a bounded hash of the fresh connection nonce', () => {
    const nonce = new Uint8Array(32).fill(0x42);
    const reference = connectionReference(nonce);
    expect(reference).toBe('5c80549fc794cd0e');
    expect(reference).toMatch(/^[a-f0-9]{16}$/);
    expect(reference).not.toContain('4242424242424242');
    expect(reference).toBe(connectionReference(nonce));
    expect(reference).not.toBe(connectionReference(new Uint8Array(32).fill(0x43)));
    expect(() => connectionReference(new Uint8Array(33))).toThrow('nonce length');
  });

  it('does not render malformed references or request sequences', () => {
    const rendered = formatLocalFailure({
      stage: 'response_read',
      code: 'channel_closed',
      connectionReference: 'PRIVATE-CREDENTIAL\nforged-log',
      requestSequence: Number.POSITIVE_INFINITY,
    });

    expect(rendered).not.toContain('PRIVATE');
    expect(rendered).not.toContain('forged-log');
    expect(rendered).not.toContain('request=');
    expect(rendered).toContain('may have committed');
  });

  it('rejects unknown labels and never coerces arbitrary diagnostic objects', () => {
    const unsafe = {
      toString: () => {
        throw new Error('PRIVATE-CREDENTIAL-AND-PAYLOAD');
      },
    };
    for (const value of ['PRIVATE-CREDENTIAL\nforged-log', unsafe]) {
      const rendered = formatLocalFailure({
        stage: value,
        code: value,
        connectionReference: unsafe,
        requestSequence: unsafe,
      });
      expect(rendered).toContain('stage=unknown_boundary code=unclassified_failure');
      expect(rendered).not.toMatch(/PRIVATE|forged-log|connection=|request=/);
    }
  });

  it('renders stage, finite code, and connection-local ordering', () => {
    expect(
      formatLocalFailure({
        stage: 'service_decision',
        code: 'not_authorized',
        connectionReference: connectionReference(new Uint8Array(32).fill(0x42)),
        requestSequence: 2,
      }),
    ).toMatch(/stage=service_decision code=not_authorized connection=[a-f0-9]{16} request=2/);
  });
});
