import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  bootExtension,
  createExtensionJoinConfig,
  createProcessController,
  createStderrDiagnostics,
  type AssistantMessageEvent,
  type ExtensionSession,
  type ProcessController,
  type SessionErrorEvent,
  type SessionIdleEvent,
  type SessionShutdownEvent,
  type ToolExecutionCompleteEvent,
} from '../src/runtime';

type EventHandlerMap = {
  'assistant.message': (event: AssistantMessageEvent) => void;
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
  const disconnect = vi.fn().mockResolvedValue(undefined);

  const session: ExtensionSession = {
    disconnect,
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
  it('registers the local daemon as a session-scoped MCP server', () => {
    const windows = createExtensionJoinConfig(
      {
        SESSION_ID: 'session-a',
        KONCLAVE_DAEMON_PATH: 'C:\\tools\\KonclaveLocalDaemon.exe',
        KONCLAVE_PROFILE_ROOT: 'C:\\profiles',
        KONCLAVE_WRAPPING_KEY_FILE: 'C:\\secrets\\wrapping.key',
        KONCLAVE_RELAY_ENDPOINT: 'https://relay.example.test',
        KONCLAVE_RELAY_CREDENTIAL_FILE: 'C:\\secrets\\relay.credential',
      },
      'win32',
    );
    const repeated = createExtensionJoinConfig({ SESSION_ID: 'session-a' }, 'linux');
    const different = createExtensionJoinConfig({ SESSION_ID: 'session-b' }, 'linux');
    const windowsServer = windows.mcpServers.konclave;
    const repeatedServer = repeated.mcpServers.konclave;
    const differentServer = different.mcpServers.konclave;

    if (!windowsServer || !repeatedServer || !differentServer) {
      throw new Error('Konclave MCP server configuration is missing.');
    }

    expect(windowsServer).toMatchObject({
      type: 'stdio',
      command: 'C:\\tools\\KonclaveLocalDaemon.exe',
      args: [],
      tools: ['*'],
      timeout: 90_000,
      env: {
        KONCLAVE_MCP_ALLOW_WRITE: 'true',
        KONCLAVE_PROFILE_ROOT: 'C:\\profiles',
        KONCLAVE_WRAPPING_KEY_FILE: 'C:\\secrets\\wrapping.key',
        KONCLAVE_RELAY_ENDPOINT: 'https://relay.example.test',
        KONCLAVE_RELAY_CREDENTIAL_FILE: 'C:\\secrets\\relay.credential',
      },
    });
    expect(windowsServer.env.KONCLAVE_PROFILE_ID).toMatch(/^session-[0-9a-f]{24}$/);
    expect(repeatedServer.command).toBe('KonclaveLocalDaemon');
    expect(repeatedServer.env.KONCLAVE_PROFILE_ID).toBe(windowsServer.env.KONCLAVE_PROFILE_ID);
    expect(differentServer.env.KONCLAVE_PROFILE_ID).not.toBe(
      repeatedServer.env.KONCLAVE_PROFILE_ID,
    );
    expect(JSON.stringify(windows)).not.toContain('session-a');
  });

  it('fails before joining when the host session identity is unavailable', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const joinSession = vi.fn();

    const controller = await bootExtension({
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
      'Failed to join Copilot session: SESSION_ID is required to derive the Konclave profile.',
    );
  });

  it('joins the foreground session with the safe default config and cleans up handlers', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();
    const joinSession = vi.fn().mockResolvedValue(sessionMock.session);

    const controller = await bootExtension({
      diagnostics: diagnostics.diagnostics,
      joinSession,
      processController,
    });

    expect(controller).not.toBeNull();
    expect(joinSession).toHaveBeenCalledWith(
      createExtensionJoinConfig(process.env, process.platform),
    );
    expect([...sessionMock.handlers.keys()].sort()).toEqual([
      'assistant.message',
      'session.error',
      'session.idle',
      'session.shutdown',
      'tool.execution_complete',
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

  it('schedules deferred sends and supports explicit cancellation', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();

    const controller = await bootExtension({
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
      diagnostics: diagnostics.diagnostics,
      joinSession: vi.fn().mockRejectedValue(new Error('join failed')),
      processController,
    });

    expect(controller).toBeNull();
    expect(processController.exitCode).toBe(1);
    expect(diagnostics.stderr).toHaveBeenCalledWith('Failed to join Copilot session: join failed');
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
      diagnostics: failingDiagnostics.diagnostics,
      joinSession,
      processController: new FakeProcessController(),
    });

    expect(failedController).toBeNull();
    expect(failingDiagnostics.stderr).toHaveBeenCalledWith(
      'Failed to join Copilot session: Unknown error',
    );

    const stringDiagnostics = createDiagnosticsRecorder();
    const stringFailedController = await bootExtension({
      diagnostics: stringDiagnostics.diagnostics,
      joinSession: vi.fn().mockRejectedValue('string failure'),
      processController: new FakeProcessController(),
    });

    expect(stringFailedController).toBeNull();
    expect(stringDiagnostics.stderr).toHaveBeenCalledWith(
      'Failed to join Copilot session: string failure',
    );
  });

  it('normalizes invalid send delays', async () => {
    const diagnostics = createDiagnosticsRecorder();
    const processController = new FakeProcessController();
    const sessionMock = createSessionMock();

    const controller = await bootExtension({
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
