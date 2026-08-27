import { joinSession } from '@github/copilot-sdk/extension';
import { bootExtension, createProcessController, createStderrDiagnostics } from './runtime.js';

// The session joins as a thin client of the shared per-user service. Nothing here
// declares an MCP server, so a Copilot session never starts a Konclave process.
await bootExtension({
  diagnostics: createStderrDiagnostics(),
  joinSession,
  processController: createProcessController(),
});
