---
title: Permit locally authorized ordinary peer work
status: Proposed
date: 2026-10-24
authors:
  - Konclave maintainers
tags:
  - agents
  - authorization
  - collaboration
supersedes:
  - adr-0012-structured-directed-collaboration-requests
  - adr-0028-external-recipe-composition
superseded_by: []
---

# Permit locally authorized ordinary peer work

## Context and scope

Agents need to exchange feedback, inspect code, make changes, and request reviews
without introducing task tracking or a workflow engine into encrypted messaging.
Reply-only turns cannot perform that work. An operator must be able to authorize
ordinary work explicitly without treating a remote request as permission authority.

This decision replaces the automatic-turn tool prohibition in ADRs 0012 and 0028.
Their other messaging and external-composition constraints are carried forward
below. It does not change MLS, identity, storage schemas, message kinds, or policy
bundle encoding.

## Verified facts and assumptions

The daemon already authenticates directed requests, claims one exact request under
a locally active policy, and maintains its handling lease. The Copilot extension
already binds a pre-tool hook to a locally generated synthetic-turn token. Final
responses already have a separate one-use authorization and durable terminal
reservation. These mechanisms provide a bounded admission boundary without task
state.

The policy evaluator matches exact structured actions; a policy name or arbitrary
new action string has no execution semantics by itself. Normal Copilot permissions
and repository instructions remain separate controls.

The operator is assumed to understand that ordinary shell, file, and external-tool
permissions are broad trust in the receiving session. The integration cannot prove
atomic effects or cancellation of arbitrary external tools or their descendants.

## Decision drivers

- Keep secure messaging independent of task-specific orchestration.
- Make broader peer work an explicit local opt-in, never a migration default.
- Reuse current request, policy, claim, and permission mechanisms.
- Preserve terminal replies and narrow existing policies.
- State the limits of broad tool authority without claiming sandbox isolation.

## Decision

Implement one unscoped action, `session.work`, with code-defined Copilot semantics:
an exact directed-request turn may use ordinary tools under that session's existing
permissions and repository instructions. Admission still requires
`conversation.reply`; work permission does not create a separate kind of turn.

The daemon reports a boolean work capability only after evaluating the active
canonical policy under the paved harness controls. Missing evidence is reply-only;
malformed evidence fails closed. The trusted synthetic prompt explains that the
quoted request may supply the task, but cannot alter local policy, permissions,
trust, or higher-priority instructions.

Every work-tool admission re-evaluates `session.work` against the exact active
digest, request, attempt, responder, delivery consumer, and live lease. An
asynchronous policy check cannot admit a tool after the local turn changes.
Approval-required or unsupported actions fail closed. An allowed hook result does
not grant normal Copilot permission or bypass an approval.

Direct Konclave policy, identity/membership, delivery-control, and extension-control
tools remain unavailable in peer turns. Explicit follow-up directed requests and
history operations are limited to the originating conversation. Ordinary tool access
is not a filesystem, process, plugin, or operating-system sandbox: a broadly
authorized shell can act outside those direct-tool restrictions.

Work turns need not call the reply tool first. Reply-only turns continue to require
that tool at admission and cannot use external tools or initiate another request.
Every final response retains its exact correlated one-use send authorization and
existing terminal reservation. Ordinary replies never become new automatic requests.

Revocation, replacement, expiry, lost claims, and unavailable policy checks deny
future tool admission. They cannot retract effects already admitted or terminate an
external process. A reclaimed request may repeat ordinary work after interruption;
Konclave's final-response idempotency does not make arbitrary external effects
exactly once. Operators must reconcile external effects using their own durable
identifiers rather than interpreting a retry as proof nothing happened.

### Carried-forward messaging and composition boundaries

Canonical policy bytes and their domain-separated digest identify a locally accepted
conversation binding. Effective authority intersects that bundle, local user
authority, proven harness controls, and local restrictions. Peer proposal receipt,
policy names, legacy guidance, and response text confer no authority. New policy
sources contain structured statements, required claims, and resolved limits, not
trusted task prose; historical guidance remains readable as untrusted annotation.

Directed requests name one exact authenticated target and bounded task body.
Ordinary messages and terminal responses do not wake models. One response is
correlated by conversation, original request, and authenticated target device.
Existing durable claims, bounded attempts, leases, and terminal outcomes remain the
request lifecycle; no task registry or orchestration state is added.

External providers still own recipe semantics, sequencing, fan-out, cancellation,
and run state. Konclave adds no workflow modes, recipe execution, dynamic loading,
or provider discovery. The existing recipe codec remains a bounded pure-data
boundary with exactly `name`, `provider`, and opaque `configuration`, canonical
UTF-8 JSON, and a domain-separated digest. Decoding, hashing, installing, or selecting
a recipe never activates policy. Provider identifiers remain inert lookup keys.
External adapters still require explicitly selected installed code and an exact
immutable approved run descriptor; missing or changed restore evidence fails closed.
No coordinator terminates original-client-to-agent MLS encryption.

## Serious alternatives

| Alternative | Benefits | Costs and disposition |
| --- | --- | --- |
| Keep all peer turns reply-only | Smallest authority and simplest effect accounting | Cannot inspect, implement, or review; retained as the default, insufficient for explicit ordinary work |
| Broad locally accepted ordinary-tool permission | Reuses normal session permissions and current lifecycle, without task machinery | Coarse trust, non-atomic external effects, and no descendant isolation; chosen with explicit limitations |
| Per-tool/resource permissions and managed effect execution | Potentially narrower authority and stronger reconciliation | Requires reliable cross-provider resource semantics and lifecycle machinery; not implemented or claimed |

## Consequences

Existing accepted policies remain unchanged and reply-only. Each endpoint must
explicitly activate or accept the broader exact policy before it can receive work.
No policy is automatically replaced. Generic clients gain no paved work authority.

The receiving session's permissions determine what work can actually run. Broad
permission may expose local code, files, credentials available to ordinary tools,
and external services to peer-requested work. This is an intentional operator trust
decision, not protection against a malicious peer with broadly delegated access.

## Confirmation

Pure classifier tests cover missing/malformed permission evidence, ordinary tools,
qualified control aliases, conversation-bound operations, and legacy reply handling.
Native tests use the real sealed policy store and request claim to check explicit
allow/deny/approval, policy replacement/revocation, and exact claim bindings.
Hook tests verify normal-permission intersection and foreground/in-flight races;
delivery tests distinguish work framing and optional tool choice from reply-only
admission. These checks cannot prove operating-system isolation or exactly-once
external effects, which this decision explicitly excludes.

## References

- [ADR 0012](adr-0012-structured-directed-collaboration-requests.md) established the
  deterministic policy/request separation and terminal-response contract preserved
  here; its unconditional external-tool prohibition is the restriction replaced.
- [ADR 0028](adr-0028-external-recipe-composition.md) established external recipe
  ownership and non-executable definition data; those boundaries remain unchanged.
- [Collaboration policies](../development/collaboration-policies.md) defines exact
  activation and evaluator semantics, explaining why remote content cannot grant
  the new permission.
- [Threat model](../security/threat-model.md) owns the endpoint trust assumptions
  and acknowledged external-effect limitations.
