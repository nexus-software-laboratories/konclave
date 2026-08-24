import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createAdapterRendezvous,
  listenForDaemon,
  type AdapterRendezvous,
} from './adapter/channel.js';
import { createDeliveryCoordinator } from './adapter/delivery.js';
import { startDeliveryRuntime, type AdapterIntegration } from './adapter/runtime.js';
import { resolveDaemonCommand } from './daemon-path.js';

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
   * Adapter hosting used to receive remote events.
   *
   * Absent, the extension mounts the daemon and serves tools without a delivery
   * channel, which is what keeps this entry point testable without a socket. The
   * composition root supplies the real integration.
   */
  adapter?: AdapterIntegration;
}

/** The adapter hosting used in production. */
export const nodeAdapterIntegration: AdapterIntegration = {
  createRendezvous(platform) {
    return createAdapterRendezvous(platform);
  },
  listen(rendezvous, platform) {
    return listenForDaemon(rendezvous, platform);
  },
};

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
  const platform = options.platform ?? process.platform;
  const environment = options.environment ?? process.env;
  let rendezvous: AdapterRendezvous | null = null;

  try {
    // The rendezvous exists before the daemon child starts, because the daemon
    // connects outward to it during its own startup and cannot wait for one to
    // appear later.
    rendezvous = options.adapter ? await options.adapter.createRendezvous(platform) : null;
    const session = await options.joinSession(
      createExtensionJoinConfig(environment, platform, rendezvous),
    );
    const controller = attachExtension(
      session,
      options.diagnostics,
      options.processController,
      options.timers,
    );

    if (options.adapter && rendezvous) {
      attachAdapterDelivery(
        controller,
        options.adapter,
        rendezvous,
        deriveProfileId(environment),
        options.diagnostics,
        platform,
      );
    }

    return controller;
  } catch (error) {
    await rendezvous?.dispose();
    options.diagnostics.error(`Failed to join Copilot session: ${formatError(error)}`);
    options.processController.setExitCode(1);
    return null;
  }
}

/**
 * Runs the delivery channel beside the session without blocking startup.
 *
 * A daemon that never connects must not prevent the extension from serving tools, so
 * the channel is established in the background and its failures are diagnostics
 * rather than startup errors.
 */
function attachAdapterDelivery(
  controller: ExtensionController,
  adapter: AdapterIntegration,
  rendezvous: AdapterRendezvous,
  profileId: string,
  diagnostics: Diagnostics,
  platform: NodeJS.Platform,
): void {
  void (async () => {
    try {
      const listener = await adapter.listen(rendezvous, platform);
      const channel = await listener.accept(profileId);
      const coordinator = createDeliveryCoordinator({
        channel,
        session: controller.session,
        diagnostics,
      });
      const runtime = startDeliveryRuntime({ channel, coordinator, diagnostics });
      // Disposal stops the claim loop first. Closing the channel underneath a running
      // loop would surface as a claim failure rather than an orderly stop.
      controller.attachDelivery(coordinator, () => {
        runtime.stop();
        channel.close();
        void listener.close();
        void rendezvous.dispose();
      });
      await runtime.completed;
    } catch (error) {
      diagnostics.error(`Konclave delivery channel unavailable: ${formatError(error)}`);
      await rendezvous.dispose();
    }
  })();
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
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
  rendezvous: AdapterRendezvous | null = null,
): JoinSessionConfig {
  const command = resolveDaemonCommand(environment, platform, runtimeModuleDir);
  const daemonEnvironment: Record<string, string> = {
    KONCLAVE_PROFILE_ID: deriveProfileId(environment),
    KONCLAVE_MCP_ALLOW_WRITE: 'true',
  };

  if (rendezvous) {
    // All three are supplied together; the daemon rejects a partial set rather than
    // running without a delivery channel.
    daemonEnvironment.KONCLAVE_ADAPTER_ENDPOINT = rendezvous.endpoint;
    daemonEnvironment.KONCLAVE_ADAPTER_CAPABILITY_FILE = rendezvous.capabilityFile;
    daemonEnvironment.KONCLAVE_ADAPTER_CONSUMER_ID = rendezvous.consumerId;
  }

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
