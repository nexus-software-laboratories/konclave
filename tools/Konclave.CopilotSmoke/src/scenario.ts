import { createHash, randomUUID } from "node:crypto";
import { lstatSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  approveAll,
  CopilotClient,
  type CopilotSession,
  type Tool,
  ToolSet,
} from "@github/copilot-sdk";

import {
  requireArray,
  requireRecord,
  requireString,
  optionalString,
} from "./json.js";
import { assertLocalAgentSmoke } from "./local-only.js";
import { SmokeParticipant, type ParticipantUsage } from "./participant.js";

export interface SmokeOptions {
  readonly clientModulePath: string;
  readonly serviceConfigPath: string;
  readonly servicePid: number;
  readonly workingDirectory: string;
  readonly model?: string;
  readonly timeoutMs: number;
  readonly maxAiCreditsPerSession: number;
  readonly onProgress?: (
    stage: string,
    details: Record<string, string | number>,
  ) => void;
}

export interface SmokeReport {
  readonly status: "passed";
  readonly runId: string;
  readonly durationMs: number;
  readonly model: string | null;
  readonly maxAiCreditsPerSession: number;
  readonly sessionA: string;
  readonly sessionB: string;
  readonly servicePid: number;
  readonly pairingId: string;
  readonly conversationId: string;
  readonly pairingPhases: string[];
  readonly messageAToB: string;
  readonly messageBToA: string;
  readonly sessionATools: string[];
  readonly sessionBTools: string[];
  readonly sessionAUsage: ParticipantUsage;
  readonly sessionBUsage: ParticipantUsage;
  readonly pairingSyncRounds: number;
  readonly messageSyncAttempts: number;
  readonly terminationReason: "completed";
}

const instruction =
  "Call exactly the named Konclave tool once with the supplied arguments, then stop. " +
  "Never call shell, filesystem, web, skill, repository, or any other tool. " +
  "Never reproduce a pairing capability in your response.";

const scenarioTools = [
  "create_pairing_capability",
  "redeem_pairing_capability",
  "create_conversation",
  "authorize_pairing_joiner",
  "authorize_pairing_inviter",
  "sync_pairing",
  "cancel_pairing",
  "send_message",
  "sync_messages",
  "read_messages",
] as const;
const scenarioToolNames: ReadonlySet<string> = new Set(scenarioTools);
const smokeProfileA = "session-aaaaaaaaaaaaaaaaaaaaaaaa";
const smokeProfileB = "session-bbbbbbbbbbbbbbbbbbbbbbbb";

function assertRegularFile(path: string, label: string): void {
  if (!isAbsolute(path) || !lstatSync(path).isFile()) {
    throw new Error(`${label} must be an absolute regular file.`);
  }
}

function prompt(tool: string, argumentsValue: Record<string, unknown>): string {
  return `${instruction}\nTool: ${tool}\nArguments: ${JSON.stringify(argumentsValue)}`;
}

function progress(
  options: SmokeOptions,
  stage: string,
  details: Record<string, string | number> = {},
): void {
  options.onProgress?.(stage, details);
}

export function createSessionConfig(
  options: SmokeOptions,
  sessionId: string,
  tools: Tool[],
): Parameters<CopilotClient["createSession"]>[0] {
  const availableTools = new ToolSet();
  for (const tool of scenarioTools) {
    availableTools.addCustom(tool);
  }
  return {
    sessionId,
    model: options.model,
    availableTools,
    enableSessionStore: false,
    enableExperimentalMode: false,
    onPermissionRequest: approveAll,
    sessionLimits: {
      maxAiCredits: options.maxAiCreditsPerSession,
    },
    skipCustomInstructions: true,
    systemMessage: {
      mode: "replace",
      content:
        "You are one participant in a deterministic local Konclave smoke test. " +
        "For every user request, call exactly the one named Konclave tool once " +
        "with exactly the supplied arguments, then end the turn immediately. " +
        instruction,
    },
    tools,
    mcpServers: {},
  };
}

interface SmokeLocalClient {
  request(
    operation: string,
    payload: unknown,
    options?:
      number | { readonly deadlineMs?: number; readonly requestId?: Buffer },
  ): Promise<unknown>;
  close(): void;
}

interface SmokeCommand {
  readonly name: string;
  handler(context: {
    readonly sessionId: string;
    readonly command: string;
    readonly commandName: string;
    readonly args: string;
  }): Promise<void>;
}

interface ThinClientModule {
  connectInstalledService(
    environment: Readonly<Record<string, string | undefined>>,
    moduleDir: string,
    profile: string,
    platform: NodeJS.Platform,
  ): Promise<SmokeLocalClient>;
  createKonclaveTools(options: {
    readonly client: SmokeLocalClient;
    readonly toolDeadlineMs?: number;
  }): Tool[];
  createKonclaveCommands(options: {
    readonly client: SmokeLocalClient;
    readonly output: {
      write(
        line: string,
        options?: { readonly ephemeral?: boolean },
      ): Promise<void> | void;
    };
  }): SmokeCommand[];
}

function isThinClientModule(value: unknown): value is ThinClientModule {
  return (
    typeof value === "object" &&
    value !== null &&
    "connectInstalledService" in value &&
    typeof value.connectInstalledService === "function" &&
    "createKonclaveTools" in value &&
    typeof value.createKonclaveTools === "function" &&
    "createKonclaveCommands" in value &&
    typeof value.createKonclaveCommands === "function"
  );
}

async function loadThinClient(path: string): Promise<ThinClientModule> {
  const loaded: unknown = await import(pathToFileURL(path).href);
  if (!isThinClientModule(loaded)) {
    throw new Error("Thin client module does not expose the required API.");
  }
  return loaded;
}

interface CommandCapture {
  readonly lines: string[];
  readonly capability: Promise<string>;
  readonly output: {
    write(line: string, options?: { readonly ephemeral?: boolean }): void;
  };
}

function createCommandCapture(): CommandCapture {
  const lines: string[] = [];
  let resolveCapability: ((capability: string) => void) | undefined;
  const capability = new Promise<string>((resolve) => {
    resolveCapability = resolve;
  });
  return {
    lines,
    capability,
    output: {
      write(line, options) {
        lines.push(line);
        if (
          options?.ephemeral === true &&
          line.length >= 64 &&
          /^[A-Za-z0-9_-]+$/u.test(line)
        ) {
          resolveCapability?.(line);
          resolveCapability = undefined;
        }
      },
    },
  };
}

async function withinDeadline<T>(
  operation: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  let handle: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    handle = setTimeout(
      () => reject(new Error(`${label} exceeded its deadline.`)),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([operation, deadline]);
  } finally {
    if (handle) {
      clearTimeout(handle);
    }
  }
}

function commandValue(
  lines: readonly string[],
  prefix: string,
  label: string,
): string {
  const values = new Set(
    lines
      .filter((line) => line.startsWith(prefix))
      .map((line) => line.slice(prefix.length))
      .filter((value) => value.length > 0),
  );
  if (values.size !== 1) {
    throw new Error(`${label} command output is missing ${prefix.trim()}.`);
  }
  const value = values.values().next().value;
  if (!value) {
    throw new Error(
      `${label} command output contains an empty ${prefix.trim()}.`,
    );
  }
  return value;
}

function assertCommandSucceeded(lines: readonly string[], label: string): void {
  const failure = lines.find((line) => line.startsWith("konclave:"));
  if (failure) {
    throw new Error(`${label} failed with ${failure}`);
  }
}

function connectCommand(
  command: SmokeCommand,
  args: string,
  sessionId: string,
): Promise<void> {
  return command.handler({
    sessionId,
    command: `/konclave connect${args ? ` ${args}` : ""}`,
    commandName: "konclave",
    args: `connect${args ? ` ${args}` : ""}`,
  });
}

function observePairingSync(
  client: SmokeLocalClient,
  onSync: () => void,
): SmokeLocalClient {
  return {
    request(operation, payload, requestOptions) {
      if (operation === "sync_pairing") {
        onSync();
      }
      return client.request(operation, payload, requestOptions);
    },
    close() {
      client.close();
    },
  };
}

async function receiveMessage(
  participant: SmokeParticipant,
  conversationId: string,
  expectedText: string,
  timeoutMs: number,
): Promise<{
  readonly message: Record<string, unknown>;
  readonly attempts: number;
}> {
  const observedMessageIds = new Set<string>();
  const observedTextHashes = new Set<string>();
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await participant.invokeAll(
      "sync_messages",
      prompt("sync_messages", { conversation_id: conversationId }),
      timeoutMs,
      true,
    );
    const results = await participant.invokeAll(
      "read_messages",
      prompt("read_messages", { conversation_id: conversationId, limit: 100 }),
      timeoutMs,
      true,
    );
    const messages = results.flatMap((result) =>
      requireArray(result, "messages", "sync_messages result"),
    );
    const records = messages.map((message) =>
      requireRecord(message, "message"),
    );
    for (const record of records) {
      const messageId = optionalString(record, "message_id");
      if (messageId) {
        observedMessageIds.add(messageId);
      }
      const text = optionalString(record, "text");
      if (text) {
        observedTextHashes.add(
          createHash("sha256").update(text, "utf8").digest("hex").slice(0, 12),
        );
      }
    }
    const match = records.find((message) => message.text === expectedText);
    if (match) {
      return { message: match, attempts: attempt + 1 };
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(
    `Session ${participant.sessionId} did not receive the expected Konclave message; ` +
      `observed ${observedMessageIds.size} message IDs and text hashes ` +
      `[${[...observedTextHashes].join(",")}].`,
  );
}

function stableMessageId(runId: string, direction: string): string {
  return createHash("sha256")
    .update(`${runId}:${direction}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

async function disconnectAndDelete(
  client: CopilotClient,
  sessions: CopilotSession[],
): Promise<Error[]> {
  const errors: Error[] = [];
  for (const session of sessions) {
    try {
      await session.disconnect();
      await client.deleteSession(session.sessionId);
    } catch (error) {
      errors.push(
        error instanceof Error
          ? error
          : new Error("Unknown session cleanup failure."),
      );
    }
  }
  try {
    errors.push(...(await client.stop()));
  } catch (error) {
    errors.push(
      error instanceof Error
        ? error
        : new Error("Unknown Copilot client stop failure."),
    );
  }
  return errors;
}

export async function runSmoke(options: SmokeOptions): Promise<SmokeReport> {
  assertLocalAgentSmoke(process.env);
  assertRegularFile(options.clientModulePath, "clientModulePath");
  assertRegularFile(options.serviceConfigPath, "serviceConfigPath");
  if (!isAbsolute(options.workingDirectory)) {
    throw new Error("workingDirectory must be an absolute path.");
  }
  if (!Number.isSafeInteger(options.servicePid) || options.servicePid <= 0) {
    throw new Error("servicePid must be a positive process identifier.");
  }

  const startedAt = Date.now();
  const runId = randomUUID().replaceAll("-", "");
  const sdkHome = mkdtempSync(join(tmpdir(), "konclave-copilot-smoke-"));
  const client = new CopilotClient({
    mode: "empty",
    baseDirectory: sdkHome,
    workingDirectory: options.workingDirectory,
    logLevel: "error",
    useLoggedInUser: true,
  });
  const sessions: CopilotSession[] = [];
  const localClients: SmokeLocalClient[] = [];
  let primaryError: Error | undefined;
  let report: SmokeReport | undefined;
  let participantA: SmokeParticipant | undefined;
  let participantB: SmokeParticipant | undefined;
  let activePairingId: string | undefined;
  let pairingCompleted = false;

  try {
    report = await (async (): Promise<SmokeReport> => {
      const thinClient = await loadThinClient(options.clientModulePath);
      const environment = {
        KONCLAVE_SERVICE_CONFIG_FILE: options.serviceConfigPath,
      };
      const moduleDir = dirname(options.clientModulePath);
      const localA = await thinClient.connectInstalledService(
        environment,
        moduleDir,
        smokeProfileA,
        process.platform,
      );
      localClients.push(localA);
      const localB = await thinClient.connectInstalledService(
        environment,
        moduleDir,
        smokeProfileB,
        process.platform,
      );
      localClients.push(localB);
      const toolsA = thinClient
        .createKonclaveTools({
          client: localA,
          toolDeadlineMs: options.timeoutMs,
        })
        .filter((tool) => scenarioToolNames.has(tool.name));
      const toolsB = thinClient
        .createKonclaveTools({
          client: localB,
          toolDeadlineMs: options.timeoutMs,
        })
        .filter((tool) => scenarioToolNames.has(tool.name));
      if (
        toolsA.length !== scenarioTools.length ||
        toolsB.length !== scenarioTools.length
      ) {
        throw new Error(
          "Thin client did not expose the complete smoke tool set.",
        );
      }
      const sessionA = await client.createSession(
        createSessionConfig(options, randomUUID(), toolsA),
      );
      sessions.push(sessionA);
      const sessionB = await client.createSession(
        createSessionConfig(options, randomUUID(), toolsB),
      );
      sessions.push(sessionB);
      participantA = new SmokeParticipant(sessionA, "copilot-smoke-a");
      participantB = new SmokeParticipant(sessionB, "copilot-smoke-b");
      progress(options, "sessions_created", {
        sessionA: sessionA.sessionId,
        sessionB: sessionB.sessionId,
      });

      let pairingSyncRounds = 0;
      const captureA = createCommandCapture();
      const captureB = createCommandCapture();
      const commandA = thinClient.createKonclaveCommands({
        client: observePairingSync(localA, () => {
          pairingSyncRounds += 1;
        }),
        output: captureA.output,
      })[0];
      const commandB = thinClient.createKonclaveCommands({
        client: observePairingSync(localB, () => {
          pairingSyncRounds += 1;
        }),
        output: captureB.output,
      })[0];
      if (!commandA || commandA.name !== "konclave" || !commandB) {
        throw new Error("Thin client did not expose the Konclave command.");
      }
      const joinerConnect = connectCommand(
        commandA,
        "",
        participantA.sessionId,
      );
      const capability = await withinDeadline(
        Promise.race([
          captureA.capability,
          joinerConnect.then(() => {
            assertCommandSucceeded(captureA.lines, "joiner connect");
            throw new Error(
              "Joiner connect completed without publishing a capability.",
            );
          }),
        ]),
        options.timeoutMs,
        "Joiner capability output",
      );
      activePairingId = commandValue(
        captureA.lines,
        "pairing: ",
        "joiner connect",
      );
      progress(options, "capability_created", {
        pairingId: activePairingId,
      });
      const inviterConnect = connectCommand(
        commandB,
        capability,
        participantB.sessionId,
      );
      await withinDeadline(
        Promise.all([joinerConnect, inviterConnect]),
        options.timeoutMs,
        "Two-command connect",
      );
      assertCommandSucceeded(captureA.lines, "joiner connect");
      assertCommandSucceeded(captureB.lines, "inviter connect");
      const pairingId = activePairingId;
      const conversationId = commandValue(
        captureA.lines,
        "connected: ",
        "joiner connect",
      );
      const inviterConversationId = commandValue(
        captureB.lines,
        "connected: ",
        "inviter connect",
      );
      if (conversationId !== inviterConversationId) {
        throw new Error(
          "Two-command connect returned different conversation identifiers.",
        );
      }
      const phases = new Set<string>(
        [...captureA.lines, ...captureB.lines]
          .filter(
            (line) =>
              line.startsWith("connect phase: ") || line.startsWith("phase: "),
          )
          .map((line) => line.slice(line.indexOf(":") + 2)),
      );
      pairingCompleted = true;
      progress(options, "pairing_completed", {
        pairingId,
        conversationId,
        rounds: pairingSyncRounds,
      });

      const firstText = `konclave-smoke:${runId}:A-to-B`;
      await withinDeadline(
        commandA.handler({
          sessionId: participantA.sessionId,
          command: `/konclave send -- ${firstText}`,
          commandName: "konclave",
          args: `send -- ${firstText}`,
        }),
        options.timeoutMs,
        "Implicit-conversation send command",
      );
      assertCommandSucceeded(captureA.lines, "implicit-conversation send");
      const firstMessageId = commandValue(
        captureA.lines,
        "message id: ",
        "implicit-conversation send",
      );
      progress(options, "message_a_sent", {
        conversationId,
        messageId: firstMessageId,
      });
      const receivedByB = await receiveMessage(
        participantB,
        conversationId,
        firstText,
        options.timeoutMs,
      );
      const receivedMessageId = requireString(
        receivedByB.message,
        "message_id",
        "received message",
      );
      progress(options, "message_b_received", {
        conversationId,
        messageId: receivedMessageId,
        attempts: receivedByB.attempts,
      });

      const replyMessageId = stableMessageId(runId, "b-to-a");
      const replyText = `ACK:${firstText}`;
      const replySent = await participantB.invoke(
        "send_message",
        prompt("send_message", {
          conversation_id: conversationId,
          message_id: replyMessageId,
          reply_to_message_id: receivedMessageId,
          text: replyText,
        }),
        options.timeoutMs,
        true,
      );
      if (
        requireString(replySent, "conversation_id", "reply send result") !==
          conversationId ||
        requireString(replySent, "message_id", "reply send result") !==
          replyMessageId
      ) {
        throw new Error(
          "Session B sent an unexpected Konclave reply identity.",
        );
      }
      progress(options, "message_b_sent", {
        conversationId,
        messageId: replyMessageId,
      });
      const receivedByA = await receiveMessage(
        participantA,
        conversationId,
        replyText,
        options.timeoutMs,
      );
      if (
        requireString(
          receivedByA.message,
          "reply_to_message_id",
          "reply message",
        ) !== receivedMessageId
      ) {
        throw new Error(
          "Reply does not reference the original Konclave message.",
        );
      }
      progress(options, "message_a_received", {
        conversationId,
        messageId: replyMessageId,
        attempts: receivedByA.attempts,
      });

      return {
        status: "passed",
        runId,
        durationMs: Date.now() - startedAt,
        model: options.model ?? null,
        maxAiCreditsPerSession: options.maxAiCreditsPerSession,
        sessionA: participantA.sessionId,
        sessionB: participantB.sessionId,
        servicePid: options.servicePid,
        pairingId,
        conversationId,
        pairingPhases: [...phases],
        messageAToB: firstText,
        messageBToA: replyText,
        sessionATools: [...participantA.toolNames],
        sessionBTools: [...participantB.toolNames],
        sessionAUsage: participantA.usage(),
        sessionBUsage: participantB.usage(),
        pairingSyncRounds,
        messageSyncAttempts: receivedByB.attempts + receivedByA.attempts,
        terminationReason: "completed",
      };
    })();
  } catch (error) {
    primaryError =
      error instanceof Error
        ? error
        : new Error("Unknown Copilot smoke failure.");
  }

  const cleanupErrors: Error[] = [];
  if (primaryError && activePairingId && !pairingCompleted && participantA) {
    try {
      await participantA.invoke(
        "cancel_pairing",
        prompt("cancel_pairing", { pairing_id: activePairingId }),
        Math.min(options.timeoutMs, 30_000),
        true,
      );
    } catch (error) {
      cleanupErrors.push(
        error instanceof Error
          ? error
          : new Error("Unknown pairing cancellation failure."),
      );
    }
  }
  cleanupErrors.push(...(await disconnectAndDelete(client, sessions)));
  for (const localClient of localClients) {
    try {
      localClient.close();
    } catch (error) {
      cleanupErrors.push(
        error instanceof Error
          ? error
          : new Error("Unknown local client cleanup failure."),
      );
    }
  }
  try {
    rmSync(sdkHome, { recursive: true, force: true });
  } catch (error) {
    cleanupErrors.push(
      error instanceof Error
        ? error
        : new Error("Unknown SDK home cleanup failure."),
    );
  }
  if (primaryError && cleanupErrors.length > 0) {
    throw new AggregateError(
      [primaryError, ...cleanupErrors],
      "Copilot smoke and cleanup failed.",
    );
  }
  if (primaryError) {
    throw primaryError;
  }
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, "Copilot smoke cleanup failed.");
  }
  if (!report) {
    throw new Error("Copilot smoke completed without a report.");
  }
  return report;
}
