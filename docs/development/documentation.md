# Writing Konclave documentation

Konclave documentation is a caller contract, not a catalog of symbols. Start with
the reader's next action and use [the documentation map](../README.md) to choose
the canonical home. Preserve architectural rationale in ADRs and detailed security
guarantees in their existing owners.

## What a useful contract includes

Explain the purpose and audience, relevant prerequisites, input meaning, encoding,
units, defaults and limits. State omitted/null/zero distinctions only where they
change behavior. Describe persistence and observable effects, finite failures,
retry identity, cancellation, expiry and partial outcomes. Say what a successful
return proves and what it does not.

A send result is not proof of remote work. A request-service enrollment does not
authorize autonomous execution. A Generic harness label is not attestation.
Ordinary directed requests remain readable by other members of their MLS group.
These distinctions belong next to the example, not solely in a distant threat model.

Use a minimal realistic example with explicit setup, expected observations and
cleanup. Link an existing test or compiled example when it demonstrates the same
contract. Label fragments that require application-provided custody, storage,
authentication or endpoints; do not make incomplete compositions look deployable.
Never represent a test citation as a test you just ran.

## Authored sources and generated views

| Surface | Authoritative owner | Maintenance |
| --- | --- | --- |
| Slash commands | `service/commands.ts` help and handlers | Keep the extension guide synchronized with actual help and semantics. |
| Agent tools | Native `mcp.rs` request/result DTOs and router | Regenerate `fixtures/local-service/v1/copilot-tools.json` through its ignored native test. |
| Agent-visible fields | `service/tools.ts` projection | Document projected parameters, not the unfiltered fixture. |
| Local operations | `service/operations.ts` | Do not invent a second supported-operation registry. |
| TypeScript integrations | `src/client-api.ts` and implementation JSDoc | Verify package manifests before claiming publication or stability. |
| Rust APIs | Selected crate/module rustdoc and existing examples | Cover ownership, lifecycle and errors; use executable examples when feasible. |
| Wire contracts | Authored `.proto` files and compatibility documents | Regenerate bindings; never edit generated Rust/TypeScript. |
| Policy/configuration | Authored schema, parser and command help | Explain defaults and bounds at the source, then link the operator workflow. |

Paths in the table are relative to their owning package; the
[agent reference](../reference/agent-tools.md) links the exact source files.
Field documentation may alter generated runtime schemas even when it changes no
authorization or wire behavior. Regenerate and qualify that metadata rather than
treating it as prose-only.

Use a concise module overview and selected `///`/JSDoc contracts for reusable APIs,
not comments on every internal export. PowerShell operator entrypoints use
comment-based help. Avoid copying a large normative explanation between pages.

## Review and validation

For each change, trace important claims to current code, schema, accepted ADR or
observed output. Check local links and anchors, navigation from the documentation
map, identifier widths, time units, safe retry shapes, platform/version limits and
public example privacy. Register maintained pages in `.github/genesis-guidance.json`.

For identifier or capability changes, maintain the
[operator privacy classification](../reference/identifier-privacy.md) in the same
change. Check possession-alone authority, observers, correlation/abuse risk and
exposure response against the owning code. Update the canonical threat/protocol
contract if its guarantee changes; a non-secret ID can still be private metadata.

Run the owner's existing fixture/staleness checks when metadata changes and compile
executable snippets through the owning hosted validation. Source-only documentation
does not require a binary release. Do not change runtime behavior merely to make a
documentation example pass.

The repository's Markdown is readable on GitHub. A separately generated reference
site, its branding, canonical URLs, breadcrumbs, sitemap, preview indexing and
rendered accessibility require a distinct tooling decision and rendered acceptance.
Do not claim these from Markdown, a successful Rust build or a proposed renderer.
Before selecting tooling, demonstrate representative command/tool, typed SDK and
dense schema/configuration pages from their authored sources. Prefer a thin rendering
adapter over a competing contract inventory.
