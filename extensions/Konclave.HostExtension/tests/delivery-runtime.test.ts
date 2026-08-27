import { describe, expect, it } from 'vitest';

import { maximumClaimRetryMilliseconds, startDeliveryRuntime } from '../src/adapter/runtime.js';
import type { DeliveredEvent } from '../src/adapter/session.js';

/**
 * The claim loop is transport-neutral: it drives wait, queue, and back-off over an
 * injected channel. It is exercised here without any daemon, rendezvous, or session,
 * so the same loop can be bound to the shared local service client.
 */
function event(seed: number): DeliveredEvent {
  return {
    notificationId: Buffer.alloc(16, seed),
    leaseGeneration: 1,
    sequence: seed,
    conversation: Buffer.alloc(32, 2),
    sender: Buffer.alloc(32, 3),
    relayCursor: seed,
    payload: { kind: 'application-text', text: `message ${seed}` },
  };
}
describe('delivery runtime loop', () => {
  function coordinator() {
    const queued: DeliveredEvent[] = [];
    return {
      queued,
      enqueue(events: readonly DeliveredEvent[]) {
        queued.push(...events);
      },
      async markIdle() {},
      markActive() {},
      async flush() {},
      get pending() {
        return queued.length;
      },
      get outstanding() {
        return false;
      },
    };
  }

  it('reissues after an expired wait without treating it as work', async () => {
    const target = coordinator();
    let waits = 0;
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          waits += 1;
          if (waits >= 3) {
            runtime.stop();
          }
          return { kind: 'batch', events: [] };
        },
        close: () => {},
      },
      coordinator: target,
      diagnostics: { error: () => {} },
      sleep: async () => {},
    });

    await runtime.completed;
    expect(waits).toBe(3);
    expect(target.queued).toHaveLength(0);
  });

  it('backs off after a rejected claim rather than spinning', async () => {
    const target = coordinator();
    const errors: string[] = [];
    let sleeps = 0;
    let attempts = 0;
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          attempts += 1;
          if (attempts >= 2) {
            runtime.stop();
          }
          return { kind: 'failure', code: 'adapter_stale_lease' };
        },
        close: () => {},
      },
      coordinator: target,
      diagnostics: { error: (message) => errors.push(message) },
      sleep: async () => {
        sleeps += 1;
      },
    });

    await runtime.completed;
    expect(sleeps).toBeGreaterThan(0);
    expect(errors.join(' ')).toContain('adapter_stale_lease');
  });

  it('backs off and retries when the shared service connection is replaced', async () => {
    const errors: string[] = [];
    let attempts = 0;
    let sleeps = 0;
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          attempts += 1;
          if (attempts >= 2) {
            runtime.stop();
            return { kind: 'batch', events: [] };
          }
          throw new Error('adapter channel closed');
        },
        close: () => {},
      },
      coordinator: coordinator(),
      diagnostics: { error: (message) => errors.push(message) },
      sleep: async () => {
        sleeps += 1;
      },
    });

    await runtime.completed;
    expect(errors.join(' ')).toContain('claim failed');
    expect(attempts).toBe(2);
    expect(sleeps).toBe(1);
  });

  it('backs off with its own timer when none is supplied', async () => {
    const errors: string[] = [];
    let attempts = 0;
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          attempts += 1;
          if (attempts >= 2) {
            runtime.stop();
          }
          return { kind: 'failure', code: 'adapter_internal_error' };
        },
        close: () => {},
      },
      coordinator: coordinator(),
      diagnostics: { error: (message) => errors.push(message) },
      retryMilliseconds: 0,
    });

    await runtime.completed;
    expect(attempts).toBe(2);
  });

  it('refuses a response that does not answer a claim', async () => {
    const errors: string[] = [];
    let attempts = 0;
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          attempts += 1;
          if (attempts >= 2) {
            runtime.stop();
          }
          // An accepted transition is a valid response, but not to a claim. Treating
          // it as an empty batch would hide a protocol confusion.
          return { kind: 'accepted' };
        },
        close: () => {},
      },
      coordinator: coordinator(),
      diagnostics: { error: (message) => errors.push(message) },
      sleep: async () => {},
    });

    await runtime.completed;
    expect(errors.join(' ')).toContain('unexpected response');
  });

  it('reports a batch it cannot queue instead of dropping it silently', async () => {
    const errors: string[] = [];
    let attempts = 0;
    // The first request runs while startDeliveryRuntime is still returning, so the
    // loop is stopped through a handle assigned afterwards rather than by naming the
    // runtime from inside its own first call.
    let stopLoop: () => void = () => {};
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          attempts += 1;
          if (attempts >= 2) {
            stopLoop();
            return { kind: 'batch', events: [] };
          }
          return { kind: 'batch', events: [event(1)] };
        },
        close: () => {},
      },
      coordinator: {
        enqueue() {
          throw new Error('adapter request is outside its bound');
        },
        async markIdle() {},
        markActive() {},
        async flush() {},
        pending: 0,
        outstanding: false,
      },
      diagnostics: { error: (message) => errors.push(message) },
      sleep: async () => {},
    });
    stopLoop = () => runtime.stop();

    await runtime.completed;
    expect(errors.join(' ')).toContain('could not queue');
  });

  it('backs off exponentially per profile, caps, and resets after a valid batch', async () => {
    const sleeps: number[] = [];
    const responses = ['failure', 'failure', 'failure', 'batch', 'failure', 'failure', 'stop'];
    let attempt = 0;
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'session-profile-a',
        async request() {
          const response = responses[attempt];
          attempt += 1;
          if (response === 'stop') {
            runtime.stop();
            return { kind: 'batch', events: [] };
          }
          return response === 'batch'
            ? { kind: 'batch', events: [] }
            : { kind: 'failure', code: 'adapter_internal_error' };
        },
        close: () => {},
      },
      coordinator: coordinator(),
      diagnostics: { error: () => {} },
      sleep: async (milliseconds) => {
        sleeps.push(milliseconds);
      },
    });

    await runtime.completed;
    expect(sleeps).toHaveLength(5);
    expect(sleeps[1]).toBeGreaterThan(sleeps[0] ?? 0);
    expect(sleeps[2]).toBeGreaterThan(sleeps[1] ?? 0);
    expect(sleeps[3]).toBe(sleeps[0]);
    expect(sleeps[4]).toBe(sleeps[1]);
    expect(Math.max(...sleeps)).toBeLessThanOrEqual(maximumClaimRetryMilliseconds);
  });
});
