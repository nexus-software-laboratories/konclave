import type { SessionHooks, Tool } from "@github/copilot-sdk";
import { describe, expect, it } from "vitest";

import {
  createSessionConfig,
  createSmokePolicySource,
  type SmokeOptions,
} from "../src/scenario.js";
import { requireArray, requireRecord } from "../src/json.js";

describe("shared-client session configuration", () => {
  it("registers only custom Konclave tools and declares no MCP process", () => {
    const tools: Tool[] = [
      {
        name: "create_conversation",
        handler: async () => ({}),
      },
    ];
    const options: SmokeOptions = {
      clientModulePath: "C:\\konclave\\client.mjs",
      serviceConfigPath: "C:\\konclave\\konclave.service.json",
      servicePid: 123,
      workingDirectory: "C:\\workspace",
      timeoutMs: 30_000,
      maxAiCreditsPerSession: 30,
    };

    const hooks: SessionHooks = {};
    const config = createSessionConfig(options, "session-a", tools, hooks);

    expect(config.mcpServers).toEqual({});
    expect(config.tools).toBe(tools);
    expect(config.hooks).toBe(hooks);
    expect(config.availableTools).toBeInstanceOf(Object);
    expect(JSON.stringify(config)).not.toContain("KonclaveLocalDaemon");
    expect(JSON.stringify(config)).not.toContain('"type":"stdio"');
    expect(JSON.stringify(config)).not.toContain("policy guidance");
  });

  it("builds an exact-digest policy source for two autonomous replies", () => {
    const source = requireRecord(
      JSON.parse(createSmokePolicySource()),
      "policy source",
    );
    const spec = requireRecord(source.spec, "policy source spec");

    expect(source.apiVersion).toBe("konclave.dev/v2");
    expect(spec).not.toHaveProperty("guidance");
    expect(requireArray(spec, "statements", "policy source spec")).toEqual([
      {
        id: "conversation-reply",
        effect: "allow",
        action: "conversation.reply",
      },
    ]);
    expect(
      requireArray(spec, "requiredHarnessClaims", "policy source spec"),
    ).toHaveLength(4);
    expect(requireRecord(spec.limits, "policy source limits")).toEqual({
      durationMilliseconds: null,
      turns: null,
      tokens: null,
      concurrentRequests: 1,
    });
  });
});
