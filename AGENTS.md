# Agent Instructions

Secure, durable communication for software agents.

## Sources of truth

- Use the README and project documentation, when present, for identity, architecture,
  and rationale.
- Path-scoped files under `.github/instructions/` own exact rules for matching edits.
  Genesis-managed instructions are defaults; specialize them in separate project-owned
  files rather than editing the managed subtree.
- Code, manifests, schemas, tests, and workflows are executable truth. Investigate and
  correct stale prose when sources disagree.

## Operating safeguards

- Work from evidence. Distinguish verified facts, assumptions, and material tradeoffs.
- Investigate directly first. Delegate only independent scopes, use at most two
  substantial sub-agents, time-box them, keep synthesis/artifacts with the primary
  agent, and take over promptly when work stalls.
- Keep changes within the project's purpose. Surface significant architecture,
  integration, trust-boundary, or product-scope changes before implementing them.
- Never commit credentials, tokens, live identifiers, or private environment values.
- Before publishing from a public repository, sanitize tracked files, commit messages,
  comments, and pull-request text so they reveal no local filesystem context or private
  repository information.

## Delivery

- Use feature branches and pull requests. Target the default branch unless project
  delivery documentation explicitly enables same-repository stacked pull requests.
  Local commits remain unrestricted checkpoints.
- Run targeted checks while iterating; complete suites and hosted/platform validation
  belong to the repository's configured CI and PitCrew capacity when present.
- Before delivery, run
  [review-changes](.github/skills/review-changes/SKILL.md). It reads repository
  workflows and `.github/genesis-delivery.json`, requires a conventional title, and
  reports gaps, unrun tests, and assumptions.

## Project-specific context

- Never disclose private repositories, hosted-service internals, or private
  operational context in public artifacts.
- External forks never execute on PitCrew. A maintainer must reproduce an external
  contribution on a same-repository branch before self-hosted validation.
