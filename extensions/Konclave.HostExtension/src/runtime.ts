import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { JoinSessionConfig as CopilotJoinSessionConfig } from '@github/copilot-sdk/extension';

import { createDeliveryCoordinator, startDeliveryRuntime } from './adapter/runtime.js';
import type { LocalServiceClient } from './service/client.js';
import { createLocalServiceDeliveryChannel } from './service/delivery.js';
import { connectInstalledService } from './service/installed.js';
import {
  createKonclaveCommands,
  type CommandOutput,
  type RegisteredCommand,
} from './service/commands.js';
import { createKonclaveTools, type RegisteredTool } from './service/tools.js';

/**
 * Directory of the running module itself, used to locate a daemon bundled beside
 * the installed plugin. `import.meta.url` reflects the executing file's real
 * on-disk location even after esbuild inlines this module into the single
 * `extension.mjs` bundle, unlike `process.cwd()`, which reflects the caller's
 * working directory instead.
 */
const runtimeModuleDir = dirname(fileURLToPath(import.meta.url));

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

export type JoinSessionConfig = CopilotJoinSessionConfig & {
  tools: RegisteredTool[];
  commands: RegisteredCommand[];
  hooks: Record<string, never>;
  /**
   * Kept empty on purpose.
   *
   * A Copilot session must never start a Konclave process. The shared per-user
   * service owns every profile, and this extension is a thin client of it, so an
   * MCP server entry here would reintroduce the per-session daemon the shared
   * service exists to replace.
   */
  mcpServers: Record<string, never>;
};

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
  /**
   * Binds a delivery coordinator to session activity.
   *
   * Idle observation lives here because the controller already owns the session event
   * subscriptions; duplicating them in the adapter would risk the two disagreeing
   * about whether the session is busy.
   */
  attachDelivery(coordinator: DeliveryBinding, dispose: () => void): void;
  dispose(reason?: string): void;
}

/** The delivery behaviour the controller drives from session activity. */
export interface DeliveryBinding {
  markIdle(): Promise<void>;
  markActive(): void;
}

export interface BootExtensionOptions {
  diagnostics: Diagnostics;
  joinSession: (config: JoinSessionConfig) => Promise<ExtensionSession>;
  processController: ProcessController;
  timers?: TimerController;
  environment?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
  /**
   * Connects the thin client to the shared per-user service.
   *
   * Replaced in tests by an in-process service. There is no fallback: when this
   * fails the extension reports it and exits rather than starting a daemon.
   */
  connect?: (
    environment: Readonly<Record<string, string | undefined>>,
    moduleDir: string,
    profile: string,
    platform: NodeJS.Platform,
  ) => Promise<LocalServiceClient>;
  /** Where deterministic command output is rendered. */
  commandOutput?: CommandOutput;
}

/**
 * Connects to the installed shared service.
 *
 * Every input comes from owner-protected installed state: the endpoint, the adapter
 * registration, and the pinned service key. The signing seed is read at connect time
 * and never passed through arguments, environment, or diagnostics.
 */
export { connectInstalledService };

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
  const environment = options.environment ?? process.env;
  const connect = options.connect ?? connectInstalledService;
  const commandOutput = options.commandOutput ?? createDiagnosticsOutput(options.diagnostics);
  const platform = options.platform ?? process.platform;
  let client: LocalServiceClient | null = null;

  try {
    // The profile is derived before anything connects, so a reconnect or reload
    // binds to the same durable profile rather than creating a second one.
    const profile = deriveProfileId(environment);
    client = await connect(environment, runtimeModuleDir, profile, platform);
    const session = await options.joinSession(createExtensionJoinConfig(client, commandOutput));
    const controller = attachExtension(
      session,
      options.diagnostics,
      options.processController,
      options.timers,
    );
    const deliveryChannel = createLocalServiceDeliveryChannel(client);
    const coordinator = createDeliveryCoordinator({
      channel: deliveryChannel,
      session,
      diagnostics: options.diagnostics,
    });
    const deliveryRuntime = startDeliveryRuntime({
      channel: deliveryChannel,
      coordinator,
      diagnostics: options.diagnostics,
    });
    controller.attachDelivery(coordinator, () => {
      deliveryRuntime.stop();
      deliveryChannel.close();
    });
    void deliveryRuntime.completed.catch((error: unknown) => {
      options.diagnostics.error(`Konclave delivery stopped: ${formatError(error)}`);
    });
    return controller;
  } catch (error) {
    client?.close();
    // There is no per-session daemon to fall back to. An unavailable or unauthorized
    // service is reported and the extension exits.
    options.diagnostics.error(`Konclave shared service unavailable: ${formatError(error)}`);
    options.processController.setExitCode(1);
    return null;
  }
}

function createDiagnosticsOutput(diagnostics: Diagnostics): CommandOutput {
  return {
    write(line) {
      diagnostics.error(line);
    },
  };
}

/**
 * Derives the profile identifier a session owns.
 *
 * The daemon and the delivery channel must agree on this value, so it is computed
 * once here rather than independently on each side.
 */
export function deriveProfileId(environment: Readonly<Record<string, string | undefined>>): string {
  const sessionId = environment.SESSION_ID?.trim();
  if (!sessionId) {
    throw new Error('SESSION_ID is required to derive the Konclave profile.');
  }

  return `session-${createHash('sha256').update(sessionId).digest('hex').slice(0, 24)}`;
}

export function createExtensionJoinConfig(
  client: LocalServiceClient,
  output: CommandOutput,
): JoinSessionConfig {
  return {
    tools: createKonclaveTools({ client }),
    commands: createKonclaveCommands({ client, output }),
    hooks: {},
    mcpServers: {},
  };
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
  const deliveryDisposals: Array<() => void> = [];
  let delivery: DeliveryBinding | null = null;
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
    delivery = null;
    while (deliveryDisposals.length > 0) {
      deliveryDisposals.pop()?.();
    }
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
    attachDelivery(coordinator, disposeDelivery) {
      if (disposed) {
        disposeDelivery();
        return;
      }
      delivery = coordinator;
      deliveryDisposals.push(disposeDelivery);
    },
    dispose() {
      dispose();
    },
  };

  unsubscriptions.push(
    session.on('assistant.message', (event) => {
      const assistantEvent = event as AssistantMessageEvent;
      state.lastAssistantMessageId = assistantEvent.data.messageId;
      delivery?.markActive();
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
      void delivery?.markIdle().catch((error: unknown) => {
        diagnostics.error(`Konclave delivery failed after idle: ${formatError(error)}`);
      });
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
