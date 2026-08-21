---
applyTo: "protocol/releases/*.json,scripts/protocol/Test-ProtocolRelease.ps1"
---

# Protocol release manifests

- A tagged release manifest is immutable. Publish corrections as a new prerelease
  manifest and tag rather than editing a tagged file.
- Record exact supported versions, hard limits, security-critical dependencies,
  lockfile and fixture hashes, conformance evidence, security-review disposition, and
  known limitations.
- Run `pwsh scripts/protocol/Test-ProtocolRelease.ps1` after any matching change.
- Create the declared tag only from the merged `main` commit after every required
  release-manifest pull-request check passes.
