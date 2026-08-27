import type { Tool } from "@github/copilot-sdk";
import { describe, expect, it } from "vitest";

import { createSessionConfig, type SmokeOptions } from "../src/scenario.js";

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

    const config = createSessionConfig(options, "session-a", tools);

    expect(config.mcpServers).toEqual({});
    expect(config.tools).toBe(tools);
    expect(config.availableTools).toBeInstanceOf(Object);
    expect(JSON.stringify(config)).not.toContain("KonclaveLocalDaemon");
    expect(JSON.stringify(config)).not.toContain('"type":"stdio"');
  });
});
