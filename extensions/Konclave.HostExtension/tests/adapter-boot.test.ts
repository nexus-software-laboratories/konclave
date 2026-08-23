import { describe, expect, it, vi } from 'vitest';

import type { AdapterChannel, AdapterListener, AdapterRendezvous } from '../src/adapter/channel.js';
import { startDeliveryRuntime } from '../src/adapter/runtime.js';
import type { AdapterRequest, AdapterResponse, DeliveredEvent } from '../src/adapter/session.js';
import { bootExtension, createExtensionJoinConfig, deriveProfileId } from '../src/runtime.js';

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

function rendezvous(): AdapterRendezvous {
  return {
    endpoint: '/tmp/konclave-test/adapter.sock',
    capabilityFile: '/tmp/konclave-test/capability',
    consumerId: 'Y29uc3VtZXI',
    capability: Buffer.alloc(32, 9),
    dispose: vi.fn(async () => {}),
  };
}

class SessionMock {
  readonly handlers = new Map<string, (event: unknown) => void>();
  readonly sent: string[] = [];

  send = vi.fn(async (message: string | { prompt: string }) => {
    this.sent.push(typeof message === 'string' ? message : message.prompt);
    return 'message-id';
  });

  on(eventType: string, handler: (event: unknown) => void): () => void {
    this.handlers.set(eventType, handler);
    return () => this.handlers.delete(eventType);
  }

  disconnect = vi.fn(async () => {});

  emit(eventType: string, payload: unknown): void {
    this.handlers.get(eventType)?.(payload);
  }
}

describe('adapter launch configuration', () => {
  it('passes the endpoint, capability file, and consumer together', () => {
    const point = rendezvous();
    const config = createExtensionJoinConfig({ SESSION_ID: 'session-a' }, 'linux', point);
    const daemon = config.mcpServers.konclave?.env;

    expect(daemon?.KONCLAVE_ADAPTER_ENDPOINT).toBe(point.endpoint);
    expect(daemon?.KONCLAVE_ADAPTER_CAPABILITY_FILE).toBe(point.capabilityFile);
    expect(daemon?.KONCLAVE_ADAPTER_CONSUMER_ID).toBe(point.consumerId);
  });

  it('omits adapter variables entirely when no rendezvous exists', () => {
    const config = createExtensionJoinConfig({ SESSION_ID: 'session-a' }, 'linux');
    const daemon = config.mcpServers.konclave?.env ?? {};

    // A partial set is rejected by the daemon, so absence must be total.
    expect(Object.keys(daemon).some((name) => name.startsWith('KONCLAVE_ADAPTER_'))).toBe(false);
  });

  it('derives the same profile the daemon is launched with', () => {
    const environment = { SESSION_ID: 'session-a' };
    expect(
      createExtensionJoinConfig(environment, 'linux').mcpServers.konclave?.env.KONCLAVE_PROFILE_ID,
    ).toBe(deriveProfileId(environment));
    expect(() => deriveProfileId({})).toThrow();
  });
});

describe('adapter boot integration', () => {
  it('creates the rendezvous before joining so the daemon can connect on startup', async () => {
    const order: string[] = [];
    const point = rendezvous();
    const session = new SessionMock();

    await bootExtension({
      diagnostics: { error: () => {} },
      environment: { SESSION_ID: 'session-a' },
      platform: 'linux',
      processController: { onSignal: () => {}, offSignal: () => {}, setExitCode: () => {} },
      joinSession: async (config) => {
        order.push('join');
        expect(config.mcpServers.konclave?.env.KONCLAVE_ADAPTER_ENDPOINT).toBe(point.endpoint);
        return session;
      },
      adapter: {
        createRendezvous: async () => {
          order.push('rendezvous');
          return point;
        },
        listen: async () => {
          order.push('listen');
          return { accept: () => new Promise<AdapterChannel>(() => {}), close: async () => {} };
        },
      },
    });

    expect(order[0]).toBe('rendezvous');
    expect(order[1]).toBe('join');
  });

  it('disposes the rendezvous when joining fails', async () => {
    const point = rendezvous();
    const errors: string[] = [];

    const controller = await bootExtension({
      diagnostics: { error: (message) => errors.push(message) },
      environment: { SESSION_ID: 'session-a' },
      platform: 'linux',
      processController: { onSignal: () => {}, offSignal: () => {}, setExitCode: () => {} },
      joinSession: async () => {
        throw new Error('no session');
      },
      adapter: {
        createRendezvous: async () => point,
        listen: async () => {
          throw new Error('unreachable');
        },
      },
    });

    expect(controller).toBeNull();
    // A capability file left behind would outlive the process that owned it.
    expect(point.dispose).toHaveBeenCalled();
    expect(errors.join(' ')).toContain('Failed to join');
  });

  it('serves tools when the delivery channel never connects', async () => {
    const point = rendezvous();
    const errors: string[] = [];

    const controller = await bootExtension({
      diagnostics: { error: (message) => errors.push(message) },
      environment: { SESSION_ID: 'session-a' },
      platform: 'linux',
      processController: { onSignal: () => {}, offSignal: () => {}, setExitCode: () => {} },
      joinSession: async () => new SessionMock(),
      adapter: {
        createRendezvous: async () => point,
        listen: async () => {
          throw new Error('endpoint unavailable');
        },
      },
    });

    // A daemon that never connects must not stop the extension from working.
    expect(controller).not.toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(errors.join(' ')).toContain('delivery channel unavailable');
    expect(point.dispose).toHaveBeenCalled();
  });

  it('delivers a claimed event after the session reports idle', async () => {
    const point = rendezvous();
    const session = new SessionMock();
    let accept!: (channel: AdapterChannel) => void;
    const accepted = new Promise<AdapterChannel>((resolve) => {
      accept = resolve;
    });
    const listener: AdapterListener = {
      accept: () => accepted,
      close: async () => {},
    };

    const controller = await bootExtension({
      diagnostics: { error: () => {} },
      environment: { SESSION_ID: 'session-a' },
      platform: 'linux',
      processController: { onSignal: () => {}, offSignal: () => {}, setExitCode: () => {} },
      joinSession: async () => session,
      adapter: { createRendezvous: async () => point, listen: async () => listener },
    });

    expect(controller).not.toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 0));

    let claims = 0;
    accept({
      profile: deriveProfileId({ SESSION_ID: 'session-a' }),
      async request(request: AdapterRequest): Promise<AdapterResponse> {
        if (request.kind === 'wait-and-claim') {
          claims += 1;
          if (claims === 1) {
            return { kind: 'batch', events: [event(1)] };
          }
          // A real daemon holds the wait open. Standing in for that keeps the loop
          // from spinning while the test drives the idle transition.
          await new Promise((resolve) => setTimeout(resolve, 5));
          return { kind: 'batch', events: [] };
        }
        return { kind: 'accepted' };
      },
      close: () => {},
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    // Nothing is injected until the session reports idle.
    expect(session.sent).toHaveLength(0);

    session.emit('session.idle', { data: {}, timestamp: 'now' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(session.sent).toHaveLength(1);
    expect(session.sent[0]).toContain('message 1');

    controller?.dispose();
  });
});

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

  it('stops when the channel fails rather than looping on a dead socket', async () => {
    const errors: string[] = [];
    const runtime = startDeliveryRuntime({
      channel: {
        profile: 'alice',
        async request() {
          throw new Error('adapter channel closed');
        },
        close: () => {},
      },
      coordinator: coordinator(),
      diagnostics: { error: (message) => errors.push(message) },
      sleep: async () => {},
    });

    await runtime.completed;
    expect(errors.join(' ')).toContain('claim failed');
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
});
