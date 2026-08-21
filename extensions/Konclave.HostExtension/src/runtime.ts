import { createHash } from 'node:crypto';

export interface PromptMessage {
  prompt: string;
  attachments?: unknown[];
}

export interface AssistantMessageEvent {
  data: {
    messageId: string;
  };
}

export interface ToolExecutionCompleteEvent {
  data: {
    success: boolean;
    toolCallId: string;
    toolName: string;
  };
}

export interface SessionIdleEvent {
  data: {
    aborted?: boolean;
  };
  timestamp: string;
}

export interface SessionErrorEvent {
  data: {
    errorType: string;
    message: string;
  };
}

export interface SessionShutdownEvent {
  data: {
    errorReason?: string;
    shutdownType?: string;
  };
}

export interface ExtensionSession {
  send(message: string | PromptMessage): Promise<string>;
  on(eventType: string, handler: (event: unknown) => void): () => void;
  disconnect(): Promise<void>;
}

export interface Diagnostics {
  error(message: string): void;
}

export interface TextWriter {
  write(message: string): unknown;
}

export type ExtensionSignal = 'SIGINT' | 'SIGTERM';

export interface ProcessController {
  onSignal(signal: ExtensionSignal, handler: () => void): void;
  offSignal(signal: ExtensionSignal, handler: () => void): void;
  setExitCode(code: number): void;
}

export type TimerHandle = ReturnType<typeof setTimeout>;

export interface TimerController {
  setTimeout(handler: () => void, delayMs: number): TimerHandle;
  clearTimeout(handle: TimerHandle): void;
}

export interface JoinSessionConfig {
  tools: [];
  hooks: Record<string, never>;
  mcpServers: Record<string, McpStdioServerConfig>;
}

export interface McpStdioServerConfig {
  type: 'stdio';
  command: string;
  args: string[];
  env: Record<string, string>;
  tools: ['*'];
  timeout: number;
}

export interface ExtensionState {
  lastAssistantMessageId: string | null;
  lastToolCallId: string | null;
  lastToolName: string | null;
  lastToolSucceeded: boolean | null;
  lastIdleAt: string | null;
  lastIdleWasAborted: boolean;
  lastErrorMessage: string | null;
  lastShutdownType: string | null;
}

export interface ExtensionController {
  readonly session: ExtensionSession;
  readonly state: ExtensionState;
  schedulePromptSend(message: string | PromptMessage, delayMs?: number): () => void;
  dispose(reason?: string): void;
}

export interface BootExtensionOptions {
  diagnostics: Diagnostics;
  joinSession: (config: JoinSessionConfig) => Promise<ExtensionSession>;
  processController: ProcessController;
  timers?: TimerController;
  environment?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
}

const mcpToolTimeoutMs = 90_000;

const extensionSignals: readonly ExtensionSignal[] = ['SIGINT', 'SIGTERM'];

const defaultTimers: TimerController = {
  setTimeout(handler, delayMs) {
    return setTimeout(handler, delayMs);
  },
  clearTimeout(handle) {
    clearTimeout(handle);
  },
};

function createExtensionState(): ExtensionState {
  return {
    lastAssistantMessageId: null,
    lastToolCallId: null,
    lastToolName: null,
    lastToolSucceeded: null,
    lastIdleAt: null,
    lastIdleWasAborted: false,
    lastErrorMessage: null,
    lastShutdownType: null,
  };
}

export function createProcessController(nodeProcess = process): ProcessController {
  return {
    onSignal(signal, handler) {
      nodeProcess.on(signal, handler);
    },
    offSignal(signal, handler) {
      nodeProcess.off(signal, handler);
    },
    setExitCode(code) {
      nodeProcess.exitCode = code;
    },
  };
}

export function createStderrDiagnostics(writer: TextWriter = process.stderr): Diagnostics {
  return {
    error(message) {
      writer.write(`${message}\n`);
    },
  };
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === 'string' && error.trim().length > 0) {
    return error;
  }

  return 'Unknown error';
}

function normalizeDelay(delayMs: number | undefined): number {
  if (typeof delayMs !== 'number' || Number.isNaN(delayMs) || !Number.isFinite(delayMs)) {
    return 0;
  }

  return Math.max(0, delayMs);
}

export async function bootExtension(
  options: BootExtensionOptions,
): Promise<ExtensionController | null> {
  try {
    const session = await options.joinSession(
      createExtensionJoinConfig(
        options.environment ?? process.env,
        options.platform ?? process.platform,
      ),
    );
    return attachExtension(session, options.diagnostics, options.processController, options.timers);
  } catch (error) {
    options.diagnostics.error(`Failed to join Copilot session: ${formatError(error)}`);
    options.processController.setExitCode(1);
    return null;
  }
}

export function createExtensionJoinConfig(
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): JoinSessionConfig {
  const sessionId = environment.SESSION_ID?.trim();
  if (!sessionId) {
    throw new Error('SESSION_ID is required to derive the Konclave profile.');
  }

  const command =
    environment.KONCLAVE_DAEMON_PATH?.trim() ||
    (platform === 'win32' ? 'KonclaveLocalDaemon.exe' : 'KonclaveLocalDaemon');
  const daemonEnvironment: Record<string, string> = {
    KONCLAVE_PROFILE_ID: `session-${createHash('sha256').update(sessionId).digest('hex').slice(0, 24)}`,
    KONCLAVE_MCP_ALLOW_WRITE: 'true',
  };

  copyNonEmptyEnvironment(environment, daemonEnvironment, 'KONCLAVE_PROFILE_ROOT');
  copyNonEmptyEnvironment(environment, daemonEnvironment, 'KONCLAVE_WRAPPING_KEY_FILE');
  copyNonEmptyEnvironment(environment, daemonEnvironment, 'KONCLAVE_RELAY_ENDPOINT');
  copyNonEmptyEnvironment(environment, daemonEnvironment, 'KONCLAVE_RELAY_CREDENTIAL_FILE');

  return {
    tools: [],
    hooks: {},
    mcpServers: {
      konclave: {
        type: 'stdio',
        command,
        args: [],
        env: daemonEnvironment,
        tools: ['*'],
        timeout: mcpToolTimeoutMs,
      },
    },
  };
}

function copyNonEmptyEnvironment(
  source: Readonly<Record<string, string | undefined>>,
  destination: Record<string, string>,
  name: string,
): void {
  const value = source[name]?.trim();
  if (value) {
    destination[name] = value;
  }
}

function attachExtension(
  session: ExtensionSession,
  diagnostics: Diagnostics,
  processController: ProcessController,
  timers = defaultTimers,
): ExtensionController {
  const state = createExtensionState();
  const pendingTimers = new Set<TimerHandle>();
  const unsubscriptions: Array<() => void> = [];
  const signalHandlers = new Map<ExtensionSignal, () => void>();
  let disposed = false;

  const cancelTimer = (handle: TimerHandle) => {
    if (pendingTimers.delete(handle)) {
      timers.clearTimeout(handle);
    }
  };

  const dispose = () => {
    if (disposed) {
      return;
    }

    disposed = true;
    for (const handle of pendingTimers) {
      timers.clearTimeout(handle);
    }
    pendingTimers.clear();

    while (unsubscriptions.length > 0) {
      const unsubscribe = unsubscriptions.pop();
      unsubscribe?.();
    }

    for (const [signal, handler] of signalHandlers) {
      processController.offSignal(signal, handler);
    }
    signalHandlers.clear();
  };

  const controller: ExtensionController = {
    session,
    state,
    // Copilot's extension docs warn against synchronous session.send() calls from hooks.
    // Centralizing deferred sends here keeps future injections cancelable and loop-safe.
    schedulePromptSend(message, delayMs) {
      if (disposed) {
        return () => {};
      }

      const handle: TimerHandle = timers.setTimeout(() => {
        cancelTimer(handle);

        void session.send(message).catch((error) => {
          diagnostics.error(`Scheduled session.send() failed: ${formatError(error)}`);
        });
      }, normalizeDelay(delayMs));

      pendingTimers.add(handle);

      return () => {
        cancelTimer(handle);
      };
    },
    dispose() {
      dispose();
    },
  };

  unsubscriptions.push(
    session.on('assistant.message', (event) => {
      const assistantEvent = event as AssistantMessageEvent;
      state.lastAssistantMessageId = assistantEvent.data.messageId;
    }),
  );
  unsubscriptions.push(
    session.on('tool.execution_complete', (event) => {
      const toolEvent = event as ToolExecutionCompleteEvent;
      state.lastToolCallId = toolEvent.data.toolCallId;
      state.lastToolName = toolEvent.data.toolName;
      state.lastToolSucceeded = toolEvent.data.success;
    }),
  );
  unsubscriptions.push(
    session.on('session.idle', (event) => {
      const idleEvent = event as SessionIdleEvent;
      state.lastIdleAt = idleEvent.timestamp;
      state.lastIdleWasAborted = Boolean(idleEvent.data.aborted);
    }),
  );
  unsubscriptions.push(
    session.on('session.error', (event) => {
      const errorEvent = event as SessionErrorEvent;
      state.lastErrorMessage = errorEvent.data.message;
      diagnostics.error(
        `Copilot session error [${errorEvent.data.errorType}]: ${errorEvent.data.message}`,
      );
    }),
  );
  unsubscriptions.push(
    session.on('session.shutdown', (event) => {
      const shutdownEvent = event as SessionShutdownEvent;
      state.lastShutdownType = shutdownEvent.data.shutdownType ?? null;

      if (shutdownEvent.data.errorReason) {
        diagnostics.error(`Copilot session shutdown: ${shutdownEvent.data.errorReason}`);
      }

      dispose();
    }),
  );

  for (const signal of extensionSignals) {
    const handler = () => {
      dispose();
      void session.disconnect().catch((error) => {
        diagnostics.error(`Failed to disconnect Copilot session: ${formatError(error)}`);
        processController.setExitCode(1);
      });
    };

    signalHandlers.set(signal, handler);
    processController.onSignal(signal, handler);
  }

  return controller;
}
