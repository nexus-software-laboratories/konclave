# A2A conformance profile

This document is the canonical owner of Konclave's executable Agent2Agent TCK
profile. It records what the upstream suite proves, what the strict Konclave profile
deliberately excludes, and which pinned upstream defects must not be mistaken for
product failures.

The profile is evidence for the advertised HTTP+JSON surface. It is not a blanket
claim that Konclave implements every optional A2A operation, binding, content type,
or lifecycle.

## Pinned inputs

Konclave implements A2A release `v1.0.1`, protocol `1.0`, at commit
`3303592588e388e62e0f69f701af531d2f4e3991`.

The external suite is `a2aproject/a2a-tck` commit
`263b9cfaf16a554bdfb166a7ba5b67716e946349`, package version `1.0.0`.
That TCK commit still embeds A2A specification `v1.0.0` commit
`173695755607e884aa9acf8ce4feed90e32727a1`. The machine-readable profile at
`conformance/a2a/tck-v1.0.1.json` pins the repository, commit, license, lockfile,
runner, `uv` Linux wheel, and specification provenance with byte lengths and
SHA-256 digests.

The workflow executes the upstream code only on a GitHub-hosted runner with a
read-only token. It never runs the TCK or pull-request SUT code on PitCrew, receives
no repository secrets, and binds the SUT only to loopback. Before external
conformance, it applies rustfmt, unit tests, and Clippy with warnings denied to the
standalone A2A gateway host.

Independent client interoperability pins `a2a-sdk` `1.0.3`, release commit
`8a82061571142b12745576c972bf07077930a4ff`. This is the final 1.0.x SDK release
and explicitly implements protocol `1.0`; its release includes the SDK's
protocol-1.0 error-mapping alignment. The project lockfile records exact package
artifacts and transitive dependencies; the conformance profile verifies its digest
before execution. Newer 1.1.x SDK releases remain protocol-1.0 compatible, but
pinning the final 1.0.x line minimizes unrelated SDK behavior while testing
Konclave's selected protocol release.

## Pass policy

The unmodified MUST-level HTTP+JSON suite is run in full. Its raw exit code is not
accepted or ignored on its own. `scripts/a2a/Test-A2ATckProfile.ps1` instead requires:

- every supported requirement ID to be present and `PASS`;
- every incidental or conditional pass to remain separately classified as `PASS`;
- every allowed failure to remain `FAIL` with its exact expected error evidence;
- every expected skip to remain `SKIPPED`;
- every requirement the pinned TCK does not implement to remain `NOT TESTED`;
- every MUST requirement to have exactly one classification; and
- no new, missing, passing-exception, or otherwise unclassified result.

Four requirements fail only when the TCK shares one SUT store across its full run:
`CORE-EXECUTION-MODE-001`, `CORE-EXECUTION-MODE-002`, `CORE-MULTI-001a`, and
`CORE-MULTI-003`. The suite reuses `tck-complete-task` as the message ID while
changing request text or configuration. Konclave correctly treats that as an
idempotency conflict. The runner therefore executes each requirement first against
a fresh SUT and requires it to pass before running the full unmodified suite.

Run the same profile locally with:

```powershell
pwsh ./scripts/a2a/Invoke-A2ATck.ps1 -OutputDirectory <temp-dir>
```

The output directory must be empty. It retains the exact TCK checkout, isolated
reports, SUT diagnostics, and classified full report for inspection.

## Baseline

The baseline measured on 2026-09-12 is:

| Evidence | Result |
|---|---:|
| Supported MUST requirement IDs | 35 passing |
| Conditional or transport-incidental passes | 2 |
| Explicit allowed failure IDs | 18 |
| Expected skipped MUST IDs | 36 |
| Expected untested MUST IDs | 23 |
| Raw TCK MUST compatibility | 47.4% |
| Raw TCK overall compatibility | 39.8% |
| Independent SDK | `a2a-sdk` 1.0.3 passed |

The raw percentages include operations outside the advertised profile and defects in
the pinned TCK. The requirement-ID classifier, not the percentage, is the merge
gate.

The two raw passes not counted as supported are `CORE-STREAM-002`, whose direct
Message-stream condition never occurs in this task-only profile, and
`JSONRPC-SVC-001`, which the TCK records without exercising a JSON-RPC transport.

The SDK check resolves the real Agent Card, selects the HTTP+JSON transport, sends a
non-streaming request, decodes a canonical text artifact, calls `GetTask` and
`ListTasks`, and consumes the SSE path. It also requires the SDK's parsed task
timestamp to remain canonical UTC ending in `Z`.

## Allowed failure classes

| Requirements | Classification | Reason |
|---|---|---|
| `DM-MSG-001` | Profile exclusion | `SendMessage` creates a durable Task; direct Message responses are not advertised. |
| `CORE-LIST-001` through `CORE-LIST-005` | Profile exclusion | The initial route-scoped list accepts bounded pagination and explicit artifact inclusion, but not the context/status/history/timestamp filters the TCK always sends. |
| `CORE-CANCEL-002`, `CORE-CANCEL-003` | Profile exclusion | Cancellation cannot honestly retract an already delivered Konclave directed request, so the operation returns `UNSUPPORTED_OPERATION`. |
| `CORE-MULTI-004` | Profile exclusion | Task-addressed follow-up messages require the deferred multi-turn mapping. |
| `CORE-EXECUTION-MODE-001`, `CORE-EXECUTION-MODE-002`, `CORE-MULTI-001a`, `CORE-MULTI-003` | Upstream suite state collision | The full suite reuses one message ID with conflicting immutable request identity; each test passes against a fresh store. |
| `CORE-MULTI-002a`, `CORE-SEND-003` | Upstream validator defect | [a2aproject/a2a-tck#202](https://github.com/a2aproject/a2a-tck/issues/202) records that these definitions omit `expected_error`, so the generic runner fails the protocol error their titles require. |
| `HTTP_JSON-ERR-001`, `HTTP_JSON-SVC-001` | TCK protocol-version mismatch | The TCK expects v1.0.0 `application/json`; A2A v1.0.1 recommends `application/a2a+json`, including its error example. [a2aproject/a2a-tck#240](https://github.com/a2aproject/a2a-tck/issues/240) tracks the update. |
| `HTTP_JSON-STATUS-001` | Mixed known gap | The aggregate includes unsupported cancellation, v1.0.0 status mappings superseded by v1.0.1, and a raw test that concatenates a trailing-slash base URL with a leading-slash path. |

Konclave's repository tests independently require the v1.0.1 error semantics:
unsupported Message Part media returns HTTP 400 with
`CONTENT_TYPE_NOT_SUPPORTED`, and unsupported push-notification routes return HTTP
400 with `PUSH_NOTIFICATION_NOT_SUPPORTED`.

## Requirements not exercised by the pinned TCK

The TCK registers but reports `NOT TESTED` for 23 MUST requirements. Sixteen cover
authentication, signing, and version-client behavior for which the pinned suite has
no compatibility result. Seven cover cross-binding, gRPC, or JSON-RPC behavior
outside this HTTP+JSON execution. They are recorded separately from passes, failures,
and skips; the profile makes no TCK-backed conformance claim for them.

## Updating the profile

A new TCK commit, A2A release, supported operation, or changed result requires a
reviewed profile update. Update the pinned hashes, run the unmodified suite, remove
exceptions that now pass, classify every new difference with concrete evidence, and
retain isolated proof for any full-suite state collision. The verifier intentionally
fails when an allowed failure unexpectedly passes so stale exceptions cannot remain
invisible.
