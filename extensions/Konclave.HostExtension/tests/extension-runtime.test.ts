import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { join } from 'node:path';
import {
  bootExtension,
  connectInstalledService,
  createExtensionJoinConfig,
  createProcessController,
  createStderrDiagnostics,
  deriveProfileId,
  type AssistantMessageEvent,
  type ExtensionSession,
  type JoinSessionConfig,
  type ProcessController,
  type SessionErrorEvent,
  type SessionIdleEvent,
  type SessionShutdownEvent,
  type ToolExecutionCompleteEvent,
} from '../src/runtime';
import type { LocalServiceClient } from '../src/service/client.js';

/** A connected client that answers nothing, so no test needs a real service. */
function stubClient(): LocalServiceClient {
  let rejectClaim: ((error: Error) => void) | undefined;
  const close = vi.fn(() => rejectClaim?.(new Error('closed')));
  return {
    profile: 'session-0123456789abcdef01234567',
    request: vi.fn((operation: string) => {
      if (operation === 'delivery.claim') {
        return new Promise<never>((_resolve, reject) => {
          rejectClaim = reject;
        });
      }
      return Promise.resolve({});
    }),
    retire: vi.fn(async () => close()),
    close,
    connected: true,
  };
}

function queuedDeliveryClient(): LocalServiceClient {
  let rejectClaim: ((error: Error) => void) | undefined;
  let claims = 0;
  const close = vi.fn(() => rejectClaim?.(new Error('closed')));
  return {
    profile: 'session-0123456789abcdef01234567',
    connected: true,
    retire: vi.fn(async () => close()),
    close,
    request: vi.fn(async (operation) => {
      if (operation !== 'delivery.claim') {
        return {};
      }
      claims += 1;
      if (claims === 1) {
        return {
          events: [
            {
              notificationId: '01'.repeat(16),
              leaseGeneration: 1,
              sequence: 1,
              conversation: '02'.repeat(32),
              sender: '03'.repeat(32),
              relayCursor: 1,
              payload: {
                kind: 'application_text',
                messageId: '04'.repeat(16),
                text: 'shared hello',
              },
            },
          ],
        };
      }
      return new Promise<never>((_resolve, reject) => {
        rejectClaim = reject;
      });
    }),
  };
}

function requestCount(client: LocalServiceClient, operation: string): number {
  return vi.mocked(client.request).mock.calls.filter(([name]) => name === operation).length;
}

type EventHandlerMap = {
  'user.message': (event: unknown) => void;
  'assistant.turn_start': (event: unknown) => void;
  'assistant.message': (event: AssistantMessageEvent) => void;
  'tool.execution_start': (event: unknown) => void;
  'tool.execution_complete': (event: ToolExecutionCompleteEvent) => void;
  'session.idle': (event: SessionIdleEvent) => void;
  'session.error': (event: SessionErrorEvent) => void;
  'session.shutdown': (event: SessionShutdownEvent) => void;
};

class FakeProcessController implements ProcessController {
  exitCode: number | null = null;
  private readonly handlers = new Map<string, Set<() => void>>();

  onSignal(signal: 'SIGINT' | 'SIGTERM', handler: () => void): void {
    if (!this.handlers.has(signal)) {
      this.handlers.set(signal, new Set());
    }

    this.handlers.get(signal)?.add(handler);
  }

  offSignal(signal: 'SIGINT' | 'SIGTERM', handler: () => void): void {
    this.handlers.get(signal)?.delete(handler);
    if (this.handlers.get(signal)?.size === 0) {
      this.handlers.delete(signal);
    }
  }

  setExitCode(code: number): void {
    this.exitCode = code;
  }

  emit(signal: 'SIGINT' | 'SIGTERM'): void {
    for (const handler of [...(this.handlers.get(signal) ?? [])]) {
      handler();
    }
  }

  get registeredSignals(): string[] {
    return [...this.handlers.keys()].sort();
  }
}

function createSessionMock() {
  const handlers = new Map<keyof EventHandlerMap, unknown>();
  const unsubscribeMocks: Partial<Record<keyof EventHandlerMap, ReturnType<typeof vi.fn>>> = {};
  const send = vi.fn().mockResolvedValue('message-1');
  const log = vi.fn().mockResolvedValue(undefined);
  const disconnect = vi.fn().mockResolvedValue(undefined);

  const session: ExtensionSession = {
    disconnect,
    log,
    send,
    on(eventType, handler) {
      handlers.set(eventType as keyof EventHandlerMap, handler);
      const unsubscribe = vi.fn(() => {
        handlers.delete(eventType as keyof EventHandlerMap);
      });
      unsubscribeMocks[eventType as keyof EventHandlerMap] = unsubscribe;
      return unsubscribe;
    },
  };

  return {
    handlers,
    disconnect,
    log,
    send,
    session,
    unsubscribeMocks,
    emit<K extends keyof EventHandlerMap>(eventType: K, event: Parameters<EventHandlerMap[K]>[0]) {
      const handler = handlers.get(eventType) as
        ((value: Parameters<EventHandlerMap[K]>[0]) => void) | undefined;
      handler?.(event);
    },
  };
}

function createDiagnosticsRecorder() {
  const stdout = vi.fn();
  const stderr = vi.fn();

  return {
    diagnostics: {
      error(message: string) {
        stderr(message);
      },
    },
    stderr,
    stdout,
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubEnv('SESSION_ID', 'foreground-session-123');
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('bootExtension', () => {
  it('fails before connecting when the installed sidecar is absent', async () => {
    await expect(
      connectInstalledService(
        { KONCLAVE_SERVICE_CONFIG_FILE: join(process.cwd(), 'missing-service-config.json') },
        process.cwd(),
        'session-test',
        'win32',
      ),
    ).rejects.toThrow('service configuration is not installed');
  });

  it('joins as a thin client and declares no session-scoped process', () => {
    const client = stubClient();
    const config = createExtensionJoinConfig(client, { write: () => {} });

    // The supported path owns no child: no MCP server, no command, no environment
    // carrying a daemon path, profile root, or key file.
    expect(config.mcpServers).toEqual({});
    expect(config.hooks).toEqual({});
    const serialized = JSON.stringify({
      mcpServers: config.mcpServers,
      hooks: config.hooks,
      tools: config.tools.map((tool) => tool.name),
      commands: config.commands.map((command) => command.name),
    });
    expect(serialized).not.toContain('KonclaveLocalDaemon');
    expect(serialized).not.toContain('KONCLAVE_');
    expect(config.tools.length).toBeGreaterThan(0);
    expect(config.commands.map((command) => command.name)).toEqual(['konclave']);
  });

  it('reuses one durable profile across reloads and refuses an unknown session', () => {
    const first = deriveProfileId({ SESSION_ID: 'session-a' });
    expect(deriveProfileId({ SESSION_ID: 'session-a' })).toBe(first);
    expect(deriveProfileId({ SESSION_ID: 'session-b' })).not.toBe(first);
    expect(first).toMatch(/^session-[0-9a-f]{24}$/);
    expect(() => deriveProfileId({})).toThrow();
  });

  it('fails visibly when the shared service is unavailable', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const joinSession = vi.fn();

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession,
      processController,
      environment: { SESSION_ID: 'session-a' },
      connect: async () => {
        throw new Error('endpoint unavailable');
      },
    });

    // No fallback exists: the extension reports and exits rather than spawning.
    expect(controller).toBeNull();
    expect(joinSession).not.toHaveBeenCalled();
    expect(processController.exitCode).toBe(1);
    expect(diagnostics.stderr.mock.calls.flat().join(' ')).toContain('shared service unavailable');
  });

  it('fails before joining when the host session identity is unavailable', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const joinSession = vi.fn();

    const controller = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession,
      processController,
      environment: {},
      platform: 'linux',
    });

    expect(controller).toBeNull();
    expect(joinSession).not.toHaveBeenCalled();
    expect(processController.exitCode).toBe(1);
    expect(diagnostics.stderr).toHaveBeenCalledWith(
      'Konclave shared service unavailable: SESSION_ID is required to derive the Konclave profile.',
    );
  });

  it('joins the foreground session with the safe default config and cleans up handlers', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const joinSession = vi.fn(async (_config: JoinSessionConfig) => sessionMock.session);
    const client = stubClient();

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession,
      processController,
      connect: async () => client,
    });

    expect(controller).not.toBeNull();
    expect(joinSession).toHaveBeenCalledTimes(1);
    const joined = joinSession.mock.calls[0]?.[0];
    if (!joined) {
      throw new Error('extension did not join the session');
    }
    expect(joined.mcpServers).toEqual({});
    expect(joined.tools.length).toBeGreaterThan(0);
    expect(joined.hooks.onPreToolUse).toEqual(expect.any(Function));
    expect([...sessionMock.handlers.keys()].sort()).toEqual([
      'assistant.message',
      'assistant.turn_start',
      'session.error',
      'session.idle',
      'session.shutdown',
      'tool.execution_complete',
      'tool.execution_start',
      'user.message',
    ]);
    expect(processController.registeredSignals).toEqual(['SIGINT', 'SIGTERM']);

    sessionMock.emit('assistant.message', { data: { messageId: 'assistant-1' } });
    sessionMock.emit('tool.execution_complete', {
      data: { success: true, toolCallId: 'tool-1', toolName: 'view' },
    });
    sessionMock.emit('session.idle', {
      data: { aborted: true },
      timestamp: '2026-08-16T00:00:00.000Z',
    });

    expect(controller?.state).toMatchObject({
      lastAssistantMessageId: 'assistant-1',
      lastToolCallId: 'tool-1',
      lastToolName: 'view',
      lastToolSucceeded: true,
      lastIdleAt: '2026-08-16T00:00:00.000Z',
      lastIdleWasAborted: true,
    });

    controller?.dispose();
    controller?.dispose();

    for (const unsubscribe of Object.values(sessionMock.unsubscribeMocks)) {
      expect(unsubscribe).toHaveBeenCalledTimes(1);
    }
    expect(processController.registeredSignals).toEqual([]);
  });

  it('renders deterministic command output in the session timeline', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const joinSession = vi.fn(async (_config: JoinSessionConfig) => sessionMock.session);
    const client = stubClient();

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession,
      processController,
      connect: async () => client,
    });

    const config = joinSession.mock.calls[0]?.[0];
    if (!config) {
      throw new Error('extension did not join the session');
    }
    const command = config.commands.find((candidate) => candidate.name === 'konclave');
    if (!command) {
      throw new Error('Konclave command was not registered');
    }

    await command.handler({
      args: '',
      command: '/konclave',
      commandName: 'konclave',
      sessionId: 'foreground-session-123',
    });

    expect(sessionMock.log).toHaveBeenCalledWith(
      'Konclave commands (deterministic; no model inference):',
      { level: 'info' },
    );
    expect(sessionMock.log).toHaveBeenCalledWith(expect.stringContaining('/konclave status'), {
      level: 'info',
    });
    vi.mocked(client.request).mockResolvedValueOnce({
      pairing: {
        pairing_id: '11'.repeat(16),
        local_role: 'joiner',
        phase: 'joiner_awaiting_invitation',
        joiner_device_id: '22'.repeat(32),
        requested_role: 'member',
        inviter_device_id: null,
        granted_role: null,
        conversation_id: null,
        authorization_deadline_unix_seconds: 1_787_805_388,
        completion_deadline_unix_seconds: null,
      },
      capability: 'pairing_capability-1',
    });

    await command.handler({
      args: 'pair',
      command: '/konclave pair',
      commandName: 'konclave',
      sessionId: 'foreground-session-123',
    });

    expect(sessionMock.log).toHaveBeenCalledWith('pairing_capability-1', {
      level: 'info',
      ephemeral: true,
    });
    expect(diagnostics.stderr).not.toHaveBeenCalled();

    controller?.dispose();
  });

  it('settles terminal shared-service events only after the session becomes idle', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const client = queuedDeliveryClient();
    const connect = vi.fn().mockResolvedValue(client);

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
      connect,
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(sessionMock.send).not.toHaveBeenCalled();
    expect(requestCount(client, 'delivery.acknowledge')).toBe(0);

    sessionMock.emit('user.message', {});
    await vi.advanceTimersByTimeAsync(5_000);
    expect(sessionMock.send).not.toHaveBeenCalled();

    sessionMock.emit('session.idle', { data: {}, timestamp: '2026-08-16T00:00:00.000Z' });
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(sessionMock.send).not.toHaveBeenCalled();
    expect(requestCount(client, 'delivery.acknowledge')).toBe(1);

    controller?.dispose();
    await Promise.resolve();
    expect(connect).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it('settles a terminal update when a resumed session stays idle after startup', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const client = queuedDeliveryClient();

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
      connect: vi.fn().mockResolvedValue(client),
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(sessionMock.send).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(5_000);
    await Promise.resolve();
    await Promise.resolve();

    expect(sessionMock.send).not.toHaveBeenCalled();
    expect(requestCount(client, 'delivery.acknowledge')).toBe(1);
    controller?.dispose();
    await Promise.resolve();
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it('uses an explicit idle event instead of the pending startup inference', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const client = queuedDeliveryClient();

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
      connect: vi.fn().mockResolvedValue(client),
    });
    await Promise.resolve();
    await Promise.resolve();

    sessionMock.emit('session.idle', {
      data: {},
      timestamp: '2026-08-16T00:00:00.000Z',
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(sessionMock.send).not.toHaveBeenCalled();
    expect(requestCount(client, 'delivery.acknowledge')).toBe(1);

    await vi.advanceTimersByTimeAsync(5_000);
    expect(sessionMock.send).not.toHaveBeenCalled();
    expect(requestCount(client, 'delivery.acknowledge')).toBe(1);

    controller?.dispose();
    await Promise.resolve();
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it.each(['assistant.turn_start', 'tool.execution_start'] as const)(
    'cancels startup delivery when %s shows the session is active',
    async (eventType) => {
      const diagnostics = createDiagnosticsRecorder();
      const processController = new FakeProcessController();
      const sessionMock = createSessionMock();
      const client = queuedDeliveryClient();

      const controller = await bootExtension({
        diagnostics: diagnostics.diagnostics,
        joinSession: vi.fn().mockResolvedValue(sessionMock.session),
        processController,
        connect: vi.fn().mockResolvedValue(client),
      });
      await Promise.resolve();
      await Promise.resolve();

      sessionMock.emit(eventType, {});
      await vi.advanceTimersByTimeAsync(5_000);

      expect(sessionMock.send).not.toHaveBeenCalled();
      expect(requestCount(client, 'delivery.acknowledge')).toBe(0);
      sessionMock.emit('session.idle', {
        data: {},
        timestamp: '2026-08-16T00:00:00.000Z',
      });
      await Promise.resolve();
      await Promise.resolve();
      expect(sessionMock.send).not.toHaveBeenCalled();
      expect(requestCount(client, 'delivery.acknowledge')).toBe(1);

      controller?.dispose();
      await Promise.resolve();
      expect(client.close).toHaveBeenCalledTimes(1);
    },
  );

  it('closes the client and reports a failed clean grant retirement', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const client = stubClient();
    vi.mocked(client.retire).mockRejectedValueOnce(new Error('retirement failed'));

    const controller = await bootExtension({
      connect: async () => client,
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
    });

    controller?.dispose();
    await Promise.resolve();
    await Promise.resolve();

    expect(client.close).toHaveBeenCalledTimes(1);
    expect(diagnostics.stderr).toHaveBeenCalledWith(
      'Konclave grant retirement failed: retirement failed',
    );
  });

  it('schedules deferred sends and supports explicit cancellation', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();

    const controller = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
    });

    expect(controller).not.toBeNull();

    const cancel = controller?.schedulePromptSend({ prompt: 'Review the latest output.' }, 25);
    await vi.advanceTimersByTimeAsync(24);
    expect(sessionMock.send).not.toHaveBeenCalled();

    cancel?.();
    await vi.advanceTimersByTimeAsync(1);
    expect(sessionMock.send).not.toHaveBeenCalled();

    controller?.schedulePromptSend({ prompt: 'Review the latest output.' });
    await vi.runAllTimersAsync();
    expect(sessionMock.send).toHaveBeenCalledTimes(1);
    expect(sessionMock.send).toHaveBeenCalledWith({ prompt: 'Review the latest output.' });

    controller?.dispose();
    controller?.schedulePromptSend({ prompt: 'This should be ignored.' });
    await vi.runAllTimersAsync();
    expect(sessionMock.send).toHaveBeenCalledTimes(1);
  });

  it('cancels pending sends during shutdown and signal cleanup', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();

    const controller = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
    });

    controller?.schedulePromptSend({ prompt: 'This should never send.' }, 50);
    sessionMock.emit('session.shutdown', {
      data: {
        errorReason: 'session ended',
        shutdownType: 'error',
      },
    });

    await vi.runAllTimersAsync();
    expect(sessionMock.send).not.toHaveBeenCalled();
    expect(diagnostics.stderr).toHaveBeenCalledWith('Copilot session shutdown: session ended');

    const secondSession = createSessionMock();
    const secondProcessController = new FakeProcessController();
    const secondController = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(secondSession.session),
      processController: secondProcessController,
    });

    secondController?.schedulePromptSend({ prompt: 'Signal cleanup should cancel this.' }, 50);
    secondProcessController.emit('SIGTERM');
    await Promise.resolve();
    await vi.runAllTimersAsync();
    expect(secondSession.send).not.toHaveBeenCalled();
    expect(secondSession.disconnect).toHaveBeenCalledTimes(1);
    expect(secondProcessController.registeredSignals).toEqual([]);
  });

  it('writes diagnostics for session errors and failed scheduled sends without using stdout', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    sessionMock.send.mockRejectedValueOnce(new Error('send failed'));

    const controller = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
    });

    sessionMock.emit('session.error', {
      data: {
        errorType: 'quota',
        message: 'quota exceeded',
      },
    });
    controller?.schedulePromptSend({ prompt: 'Attempt a scheduled send.' });

    await vi.runAllTimersAsync();

    expect(diagnostics.stderr).toHaveBeenCalledWith(
      'Copilot session error [quota]: quota exceeded',
    );
    expect(diagnostics.stderr).toHaveBeenCalledWith('Scheduled session.send() failed: send failed');
    expect(diagnostics.stdout).not.toHaveBeenCalled();
  });

  it('handles joinSession failures without corrupting stdout', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();

    const controller = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockRejectedValue(new Error('join failed')),
      processController,
    });

    expect(controller).toBeNull();
    expect(processController.exitCode).toBe(1);
    expect(diagnostics.stderr).toHaveBeenCalledWith(
      'Konclave shared service unavailable: join failed',
    );
    expect(diagnostics.stdout).not.toHaveBeenCalled();
  });

  it('covers helper adapters and unknown startup errors', async () => {
    const stderrWriter = { write: vi.fn() };
    const diagnostics = createStderrDiagnostics(stderrWriter);
    diagnostics.error('stderr only');
    expect(stderrWriter.write).toHaveBeenCalledWith('stderr only\n');

    const nodeProcess = {
      exitCode: undefined as number | undefined,
      off: vi.fn(),
      on: vi.fn(),
    };
    const processController = createProcessController(nodeProcess as never);
    const signalHandler = vi.fn();
    processController.onSignal('SIGINT', signalHandler);
    processController.offSignal('SIGINT', signalHandler);
    processController.setExitCode(9);
    expect(nodeProcess.on).toHaveBeenCalledWith('SIGINT', signalHandler);
    expect(nodeProcess.off).toHaveBeenCalledWith('SIGINT', signalHandler);
    expect(nodeProcess.exitCode).toBe(9);

    const failingDiagnostics = createDiagnosticsRecorder();
    const joinSession = vi.fn().mockRejectedValue({ unexpected: true });
    const failedController = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: failingDiagnostics.diagnostics,
      joinSession,
      processController: new FakeProcessController(),
    });

    expect(failedController).toBeNull();
    expect(failingDiagnostics.stderr).toHaveBeenCalledWith(
      'Konclave shared service unavailable: Unknown error',
    );

    const stringDiagnostics = createDiagnosticsRecorder();
    const stringFailedController = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: stringDiagnostics.diagnostics,
      joinSession: vi.fn().mockRejectedValue('string failure'),
      processController: new FakeProcessController(),
    });

    expect(stringFailedController).toBeNull();
    expect(stringDiagnostics.stderr).toHaveBeenCalledWith(
      'Konclave shared service unavailable: string failure',
    );
  });

  it('normalizes invalid send delays', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();

    const controller = await bootExtension({
      connect: async () => stubClient(),
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockResolvedValue(sessionMock.session),
      processController,
    });

    controller?.schedulePromptSend(
      { prompt: 'Send immediately from an invalid delay.' },
      Number.NaN,
    );
    await vi.runAllTimersAsync();
    expect(sessionMock.send).toHaveBeenCalledWith({
      prompt: 'Send immediately from an invalid delay.',
    });
  });
});
