import { joinSession } from '@github/copilot-sdk/extension';
import { bootExtension, createProcessController, createStderrDiagnostics } from './runtime.js';

await bootExtension({
  diagnostics: createStderrDiagnostics(),
  joinSession,
  processController: createProcessController(),
});
