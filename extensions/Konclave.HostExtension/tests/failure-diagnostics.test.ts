import { describe, expect, it } from 'vitest';

import { connectionReference, formatLocalFailure } from '../src/service/failure-diagnostics.js';

describe('local failure diagnostic contract', () => {
  it('correlates only a bounded hash of the fresh connection nonce', () => {
    const nonce = new Uint8Array(16).fill(0x42);
    const reference = connectionReference(nonce);
    expect(reference).toBe('5deed3fe8eee37ab');
    expect(reference).toMatch(/^[a-f0-9]{16}$/);
    expect(reference).not.toContain('4242424242424242');
    expect(reference).toBe(connectionReference(nonce));
    expect(reference).not.toBe(connectionReference(new Uint8Array(16).fill(0x43)));
    expect(() => connectionReference(new Uint8Array(17))).toThrow('nonce length');
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
        connectionReference: connectionReference(new Uint8Array(16).fill(0x42)),
        requestSequence: 2,
      }),
    ).toMatch(/stage=service_decision code=not_authorized connection=[a-f0-9]{16} request=2/);
  });
});
