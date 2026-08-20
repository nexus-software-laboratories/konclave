---
# AUTO-GENERATED from .github/instructions/output-retention.instructions.md — do not edit
paths:
  - "**/target/**"
  - "**/dist/**"
  - "**/coverage/**"
  - "**/.vite/**"
  - "**/.stryker-tmp/**"
  - "**/reports/mutation/**"
  - "extensions/Konclave.HostExtension/build/**"
---
# Generated Output Retention

- Every ignored build-output or cache root is limited to 5 GiB and seven days.
  This includes `target/debug/incremental`.
- Audit repository outputs with
  `pwsh scripts/guidance/Invoke-OutputRetention.ps1`. Use `-Prune` only when the
  relevant build and test processes are not running.
- Remove only whole generations selected by the retention command. Never recursively
  delete an unresolved path, a non-ignored path, a reparse target, or tracked content.
- A new output root must be ignored, covered by path-scoped retention guidance, and
  discoverable by the retention command in the same change.
