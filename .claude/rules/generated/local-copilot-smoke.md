---
# AUTO-GENERATED from .github/instructions/local-copilot-smoke.instructions.md — do not edit
paths:
  - "tools/Konclave.CopilotSmoke/**"
  - "scripts/demo/Invoke-KonclaveCopilotSmoke.ps1"
  - ".github/workflows/**/*.yml"
---
# Local Copilot smoke boundary

- Never invoke the live Copilot smoke from GitHub Actions or another CI environment.
- Keep deterministic unit, type, lint, and build checks independent of Copilot authentication
  and inference.
- Preserve hard runtime refusal for recognized CI environment markers.
- Use the Copilot SDK in empty mode with an explicit allowlist containing only the scenario's
  Konclave MCP tools.
- Keep capabilities, prompts, model responses, tool arguments, and tool results out of logs and
  reports. Report bounded identifiers, phases, tool names, token counts, durations, and terminal
  outcomes.
- Make every retried side effect idempotent through a stable scenario-derived identifier or the
  underlying Konclave idempotency contract.
