---
name: copilot-cli-extension-maintainer
description: Safely evolve the bundled GitHub Copilot CLI extension without breaking stdout ownership, lifecycle cleanup, or package verification.
---

Use this skill when you need to modify the extension under `src/`, `extensions/`, or
the packaging scripts.

- Keep the extension a thin client of the installed shared local service. Never add a
  child process, MCP server, daemon command, endpoint discovery fallback, or unverified
  key-custody path.
- Keep the explicit agent-tool table and deterministic `/konclave` commands aligned
  with the shared operation contract. Command handlers must not invoke a model.
- Preserve `extensions/Konclave.Extension/extension.mjs` as the build output
  declared in `plugin.json`.
- Never write to stdout from the extension runtime. Use the stderr diagnostics seam in
  `src/runtime.ts`.
- Route any future `session.send()` behavior through `schedulePromptSend()` so sends
  stay deferred and cancelable during shutdown.
- Preserve the automatic-delivery coordinator's idle gate, untrusted-content framing,
  claim settlement, and wake budgets.
- Re-run `npm test` and `npm run build` after changing runtime or packaging behavior.
