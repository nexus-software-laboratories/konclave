import { describe, expect, it } from "vitest";

import { decodeToolCompletionResult } from "../src/participant.js";

describe("custom tool completion decoding", () => {
  it("prefers structured content when the harness supplies it", () => {
    expect(
      decodeToolCompletionResult({
        content: '{"source":"text"}',
        structuredContent: { source: "structured" },
      }),
    ).toEqual({ source: "structured" });
  });

  it("parses the bounded JSON content emitted for custom SDK tools", () => {
    expect(
      decodeToolCompletionResult({
        content: '{"pairing_id":"0123","phase":"created"}',
      }),
    ).toEqual({ pairing_id: "0123", phase: "created" });
  });

  it("rejects malformed and oversized custom tool content", () => {
    expect(decodeToolCompletionResult({ content: "not-json" })).toBeUndefined();
    expect(
      decodeToolCompletionResult({ content: `"${"x".repeat(1024 * 1024)}"` }),
    ).toBeUndefined();
  });
});
