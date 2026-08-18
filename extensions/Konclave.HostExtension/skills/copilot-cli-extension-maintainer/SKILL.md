---
name: copilot-cli-extension-maintainer
description: Safely evolve the bundled GitHub Copilot CLI extension without breaking stdout ownership, lifecycle cleanup, or package verification.
---

Use this skill when you need to modify the extension under `src/`, `extensions/`, or
the packaging scripts.

- Keep the shipped behavior generic. The template starts from `joinSession({ tools: [],
hooks: {} })` and does not enable commands, hooks, or permissions by default.
- Preserve `extensions/Konclave.Extension/extension.mjs` as the build output
  declared in `plugin.json`.
- Never write to stdout from the extension runtime. Use the stderr diagnostics seam in
  `src/runtime.ts`.
- Route any future `session.send()` behavior through `schedulePromptSend()` so sends
  stay deferred and cancelable during shutdown.
- Re-run `npm test` and `npm run build` after changing runtime or packaging behavior.
