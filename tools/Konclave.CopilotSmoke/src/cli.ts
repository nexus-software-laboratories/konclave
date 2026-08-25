import { parseArgs } from "node:util";

import { runSmoke } from "./scenario.js";

const parsed = parseArgs({
  options: {
    daemon: { type: "string" },
    "profile-root": { type: "string" },
    "working-directory": { type: "string" },
    model: { type: "string" },
    "timeout-ms": { type: "string", default: "180000" },
    "max-ai-credits": { type: "string", default: "30" },
  },
  strict: true,
});

function required(
  name: "daemon" | "profile-root" | "working-directory",
): string {
  const value = parsed.values[name];
  if (!value) {
    throw new Error(`--${name} is required.`);
  }
  return value;
}

function positiveNumber(value: string | undefined, name: string): number {
  const parsedValue = Number(value);
  if (!Number.isFinite(parsedValue) || parsedValue <= 0) {
    throw new Error(`${name} must be a positive number.`);
  }
  return parsedValue;
}

try {
  const maxAiCreditsPerSession = positiveNumber(
    parsed.values["max-ai-credits"],
    "--max-ai-credits",
  );
  if (maxAiCreditsPerSession < 30) {
    throw new Error(
      "--max-ai-credits must be at least the Copilot SDK minimum of 30.",
    );
  }
  const report = await runSmoke({
    daemonPath: required("daemon"),
    profileRoot: required("profile-root"),
    workingDirectory: required("working-directory"),
    model: parsed.values.model,
    timeoutMs: positiveNumber(parsed.values["timeout-ms"], "--timeout-ms"),
    maxAiCreditsPerSession,
    onProgress: (stage, details) => {
      process.stderr.write(`${JSON.stringify({ stage, ...details })}\n`);
    },
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} catch (error) {
  const message =
    error instanceof Error ? error.message : "Unknown Copilot smoke failure.";
  process.stderr.write(`Konclave Copilot smoke failed: ${message}\n`);
  process.exitCode = 1;
}
