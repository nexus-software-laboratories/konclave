---
# AUTO-GENERATED from .github/instructions/documentation-contracts.instructions.md — do not edit
paths:
  - "**/*.md"
  - "**/*.mdx"
  - "apps/Konclave.LocalDaemon/src/mcp.rs"
  - "extensions/Konclave.HostExtension/src/client-api.ts"
  - "extensions/Konclave.HostExtension/src/service/installed.ts"
  - "proto/**/*.proto"
  - "policy/**/*.schema.json"
---
# Documentation contracts

- Write for the caller's task and audience: operator, agent, harness author, native
  host, or backend implementer. Do not equate an exported symbol with a supported
  integration or a private workspace package with a registry publication.
- Check current owning code, schemas, tests and accepted ADRs before asserting
  behavior. Identify versioned snapshots; cited tests are not newly passing evidence.
- Explain meaningful inputs: encodings, units, defaults, bounds, omitted/null/zero
  distinctions and prerequisites. Describe effects, persistence, finite failures,
  exact-retry identity, cancellation, expiry and what success does NOT prove.
- Include a realistic example with setup, expected observations and cleanup where
  needed. Prefer a shared compiled/tested example; label illustrative fragments and
  unverified platform or production assumptions rather than inventing support.
- Maintain one canonical explanation and real next-step links through `docs/README.md`.
  Reconcile stale adjacent prose when a contract changes; do not create a second
  command, tool or configuration registry for documentation.
- Put selected API semantics in authored rustdoc/JSDoc/proto comments, schema
  descriptions and script help. Do not comment every primitive or add boilerplate
  that merely repeats types. Keep runtime tool-selection descriptions concise.
- Generate tool metadata through the native router fixture owner and document the
  extension's agent-visible projection. Never expose hook-injected authorization as
  agent input, automate human-only SAS confirmation, or hand-edit generated bindings.
- Preserve trust boundaries in examples: labels/discovery/enrollment are not work
  authority; ordinary directed targeting is not private from other group members;
  transport acceptance, receipts and acknowledgments are not proof of execution.
- Keep secrets, live identifiers, private operational context and workstation paths
  out of public content. Use explicit placeholders and portable repository paths.
- Validate changed links/navigation and existing drift checks. Compile executable
  examples with their owning hosted toolchain. Do not claim a website, renderer,
  deployed URL, search index or platform qualification that has not been delivered.
