import { createHash } from "node:crypto";

import type { CopilotSession } from "@github/copilot-sdk";

import { requireRecord, type JsonRecord } from "./json.js";

interface StartedTool {
  readonly callId: string;
  readonly serverName: string | undefined;
  readonly toolName: string;
  readonly argumentFingerprint: string;
}

interface CompletedTool {
  readonly callId: string;
  readonly success: boolean;
  readonly structured: unknown;
}

interface ToolCompletionResult {
  readonly content?: string;
  readonly structuredContent?: unknown;
}

const maxToolResultBytes = 1024 * 1024;

export function decodeToolCompletionResult(
  result: ToolCompletionResult | undefined,
): unknown {
  if (result?.structuredContent !== undefined) {
    return result.structuredContent;
  }
  if (
    typeof result?.content !== "string" ||
    Buffer.byteLength(result.content, "utf8") > maxToolResultBytes
  ) {
    return undefined;
  }
  try {
    return JSON.parse(result.content) as unknown;
  } catch {
    return undefined;
  }
}

export interface ParticipantUsage {
  readonly modelCalls: number;
  readonly models: string[];
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens: number;
  readonly cacheWriteTokens: number;
  readonly reasoningTokens: number;
  readonly modelDurationMs: number;
  readonly copilotNanoAiu: number;
  readonly finishReasons: string[];
  readonly iterations: number;
}

export class SmokeParticipant {
  readonly sessionId: string;
  readonly profileId: string;
  readonly toolNames: string[] = [];

  private readonly starts: StartedTool[] = [];
  private readonly completions: CompletedTool[] = [];
  private readonly models = new Set<string>();
  private readonly finishReasons = new Set<string>();
  private modelCalls = 0;
  private inputTokens = 0;
  private outputTokens = 0;
  private cacheReadTokens = 0;
  private cacheWriteTokens = 0;
  private reasoningTokens = 0;
  private modelDurationMs = 0;
  private copilotNanoAiu = 0;
  private iterations = 0;

  constructor(
    private readonly session: CopilotSession,
    profileId: string,
  ) {
    this.sessionId = session.sessionId;
    this.profileId = profileId;
    session.on("tool.execution_start", (event) => {
      this.starts.push({
        callId: event.data.toolCallId,
        serverName: event.data.mcpServerName,
        toolName: event.data.mcpToolName ?? event.data.toolName,
        argumentFingerprint: createHash("sha256")
          .update(JSON.stringify(event.data.arguments), "utf8")
          .digest("hex"),
      });
    });
    session.on("tool.execution_complete", (event) => {
      this.completions.push({
        callId: event.data.toolCallId,
        success: event.data.success,
        structured: decodeToolCompletionResult(event.data.result),
      });
    });
    session.on("assistant.usage", (event) => {
      this.modelCalls += 1;
      this.models.add(event.data.model);
      this.inputTokens += event.data.inputTokens ?? 0;
      this.outputTokens += event.data.outputTokens ?? 0;
      this.cacheReadTokens += event.data.cacheReadTokens ?? 0;
      this.cacheWriteTokens += event.data.cacheWriteTokens ?? 0;
      this.reasoningTokens += event.data.reasoningTokens ?? 0;
      this.modelDurationMs += event.data.duration ?? 0;
      this.copilotNanoAiu += event.data.copilotUsage?.totalNanoAiu ?? 0;
      if (event.data.finishReason) {
        this.finishReasons.add(event.data.finishReason);
      }
    });
  }

  async invoke(
    expectedTool: string,
    prompt: string,
    timeoutMs: number,
    allowRepeated = false,
  ): Promise<JsonRecord> {
    const results = await this.invokeAll(
      expectedTool,
      prompt,
      timeoutMs,
      allowRepeated,
    );
    const last = results.at(-1);
    if (!last) {
      throw new Error(
        `Session ${this.sessionId} produced no result for ${expectedTool}.`,
      );
    }
    return last;
  }

  async invokeAll(
    expectedTool: string,
    prompt: string,
    timeoutMs: number,
    allowRepeated = false,
  ): Promise<JsonRecord[]> {
    this.iterations += 1;
    const startOffset = this.starts.length;
    const completionOffset = this.completions.length;
    try {
      await this.session.sendAndWait({ prompt }, timeoutMs);
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : "unknown session failure";
      throw new Error(
        `Session ${this.sessionId} failed while calling ${expectedTool}: ${reason}`,
        { cause: error },
      );
    }

    const starts = this.starts.splice(startOffset);
    const completions = this.completions.splice(completionOffset);
    if (starts.length === 0) {
      throw new Error(
        `Session ${this.sessionId} did not call ${expectedTool}.`,
      );
    }
    const unexpected = starts.filter(
      (call) =>
        (call.serverName !== undefined && call.serverName !== "konclave") ||
        call.toolName !== expectedTool,
    );
    if (unexpected.length > 0 || (!allowRepeated && starts.length !== 1)) {
      const names = starts.map(
        (call) => `${call.serverName ?? "unknown"}:${call.toolName}`,
      );
      throw new Error(
        `Session ${this.sessionId} called ${starts.length} tools ` +
          `(${names.join(", ")}); expected only ${expectedTool}.`,
      );
    }
    if (
      allowRepeated &&
      new Set(starts.map((call) => call.argumentFingerprint)).size !== 1
    ) {
      throw new Error(
        `Session ${this.sessionId} repeated ${expectedTool} with conflicting arguments.`,
      );
    }
    const results: JsonRecord[] = [];
    for (const started of starts) {
      const completed = completions.find(
        (candidate) => candidate.callId === started.callId,
      );
      if (!completed?.success) {
        throw new Error(
          `Konclave tool ${expectedTool} failed in session ${this.sessionId}.`,
        );
      }
      this.toolNames.push(expectedTool);
      results.push(
        requireRecord(completed.structured, `${expectedTool} result`),
      );
    }
    return results;
  }

  async disconnect(): Promise<void> {
    await this.session.disconnect();
  }

  usage(): ParticipantUsage {
    return {
      modelCalls: this.modelCalls,
      models: [...this.models],
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      cacheReadTokens: this.cacheReadTokens,
      cacheWriteTokens: this.cacheWriteTokens,
      reasoningTokens: this.reasoningTokens,
      modelDurationMs: this.modelDurationMs,
      copilotNanoAiu: this.copilotNanoAiu,
      finishReasons: [...this.finishReasons],
      iterations: this.iterations,
    };
  }
}
