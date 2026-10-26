---
title: Continue locally authorized work on exact correlated answers
status: Accepted
date: 2026-10-26
authors:
  - Konclave maintainers
tags:
  - agents
  - authorization
  - collaboration
supersedes:
  - adr-0029-locally-authorized-peer-work
superseded_by: []
---

# Continue locally authorized work on exact correlated answers

## Context and scope

An agent can request feedback, and its peer can answer successfully, while the
requester never processes the answer. Suppressing every response-triggered model
turn prevents automatic acknowledgement loops, but also prevents the original
authorized work from continuing. A terminal answer is not another request; that
does not require it to be invisible to the requesting model.

This decision replaces the unconditional response-wake prohibition in ADR 0029.
It preserves explicit local work authority, narrow reply-only policies, encrypted
message contracts, and external ownership of orchestration. It introduces no task
registry, workflow engine, new wire message kind, or policy migration.

## Verified facts and assumptions

Sealed local history already retains outgoing directed requests with an exact
target and incoming ordinary text with authenticated sender and reply reference.
The handling journal already binds one consumer's turn to an active policy digest,
notification, lease, bounded attempt, and durable terminal outcome. Copilot already
has an idle-only queue, one outstanding synthetic turn, bounded wake budgets, and
token-bound pre-tool policy checks.

A locally activated `session.work` policy is broad ordinary-session trust. Neither
message correlation nor this policy proves exactly-once external effects, process
isolation, termination of admitted tools, or recovery of arbitrary task context.
The current profile's authenticated live delivery consumer owns continuation;
Konclave does not introduce an independently addressable model-session task.

## Decision drivers

- Let both human-originated and agent-originated authorized requests receive useful
  answers without requiring a second human prompt.
- Distinguish continuation of local work from requesting another peer response.
- Reuse authenticated messages and durable claims instead of duplicating task state.
- Preserve exact target, conversation, policy, consumer, and lease bindings.
- Keep unsolicited text, policy content, and unsupported harnesses non-authoritative.

## Decision

An incoming ordinary-text answer may resume work only when verified sealed history
proves all of the following: the original message is a completed outgoing directed
request authored by this device; the answer is completed inbound text in the same
conversation; its authenticated sender is the original exact remote target; and
its reply reference names that request. The answer must have a distinct message
identifier. Delivery metadata is a hint to inspect history, never proof by itself.

Admission evaluates current local `session.work`, current membership, the live
Copilot delivery consumer, and its exact claimed notification and lease. An
operator need not individually initiate every request, but must have explicitly
activated sufficient local policy and normal permissions. Existing policies and
their canonical digests are unchanged. Reply-only policies do not gain continuation.

The original outgoing request is the expectation record. The existing sealed
handling journal is keyed by that request and local device, with the exact inbound
answer identity sealed separately from any locally emitted response. A different
answer cannot acquire another continuation for that request. Ordinary incoming
request claims remain separate; completion of a parent request never revives its
authority. Restart verification reads authenticated history, not prunable terminal
delivery notifications. The profile schema and authenticated rollback floor advance
for this durable representation while preserving older handling-record readers.

The synthetic continuation prompt quotes the answer as untrusted information and
instructs the model to resume the original authorized work. It does not require
`send_message`, reserve a response, or automatically acknowledge the peer. Both the
native action evaluator and pre-tool hook deny a continuation's reply effect.
A deliberate follow-up `send_directed_request` remains ordinary authorized work
within the same conversation, and its own answer has its own outgoing-request
binding. Both request and continuation turns consume the existing wake budget.

Every ordinary effect rechecks current `session.work` against the active digest,
request, attempt, local device, consumer, and lease. Normal Copilot permissions and
repository instructions remain independent. Policy replacement, revocation, expiry,
claim loss, unsupported accounting, or an unavailable check deny further admission.
Prompt tokens prevent queued or delayed synthetic prompts from lending authority
to foreground user work. Idle completion durably closes a continuation without
another peer response.

### Preserved messaging and composition boundaries

Incoming directed requests still name one exact target and bounded body. Their
turn admission requires `conversation.reply`; ordinary work additionally requires
explicit `session.work`. Reply-only turns cannot research or perform external work.
A final answer retains its exact one-use send authorization and atomic durable
response reservation. Ordinary uncorrelated text, membership, and policy exchanges
remain history-only and never grant model authority.

Canonical policy bytes and their domain-separated digest identify exact locally
accepted conversation authority. Effective permission intersects that binding,
local authority, proven harness controls, and normal restrictions. A policy name,
received proposal, legacy guidance, recipe, or peer text cannot activate authority.
Direct policy, identity/membership, delivery-control, and extension-control tools
remain unavailable in peer turns. Generic integrations gain no paved execution
authority from a locally stored policy.

External providers retain recipe semantics, sequencing, fan-out, cancellation, and
run state. Recipe definitions remain bounded inert data with `name`, `provider`,
opaque `configuration`, canonical serialization, and a domain-separated digest.
Provider lookup is not dynamic loading or activation. External adapters require
explicitly selected installed code and exact immutable approved run descriptors.
No coordinator terminates original-client-to-agent MLS encryption.

## Serious alternatives

| Alternative | Benefits | Costs and disposition |
| --- | --- | --- |
| Keep every answer history-only | Smallest wake surface; no response-triggered model budget | Requires manual prompting after successful feedback; rejected for explicitly authorized collaboration |
| Wake on every incoming text | Simple transport implementation | Unsolicited messages and acknowledgements can start loops and spend model budget; rejected |
| Correlate sealed history and reuse exact handling claims | Supports human- and agent-originated requests without task infrastructure | Requires durable answer binding and current-policy admission; chosen |
| Add a pending-task registry and per-task permission lifecycle | Can model cancellation, task ownership, and richer orchestration | Duplicates messaging state and changes product scope; left to external providers |

## Consequences

Agents can use answers without another user prompt, but only while current local
work authority permits it. Explicit follow-ups can form useful conversations; wake
budgets limit their rate, not their total business scope. A response never silently
becomes another incoming request.

Turning off delivery or revoking work authority prevents future automatic
admission. Konclave does not add an outgoing task-cancellation command: a sent
request remains immutable history. Foreground interruption and completion close
the current handling attempt; they do not cancel arbitrary external work.
Recovered attempts may repeat admitted effects. Operators must reconcile such
effects with external durable identifiers.

The authenticated schema floor prevents older runtimes from opening a profile
whose continuation records they cannot interpret. Ordinary handling records keep
their existing representation. These guarantees do not make the peer's answer
correct, trustworthy task instructions, or permission to broaden policy.

## Confirmation

Pure tests assert exact request/answer bindings and every finite correlation
refusal. Real profile tests exercise sealed history, claims, terminal completion,
event pruning, restart verification, migration, and rollback rejection. Native
policy and hook tests must distinguish work authority from reply authority and
deny changed policy or claim evidence. Coordinator tests must demonstrate
idle-only, one-outstanding, bounded answer continuation without a required reply.
Installed acceptance must observe the requesting model consume an answer; message
persistence or successful remote send alone is insufficient evidence.

## References

- [ADR 0029](adr-0029-locally-authorized-peer-work.md) established broad local work
  opt-in and exact native effect checks. Those controls are preserved; its blanket
  response-wake prohibition is the behavior replaced.
- [Collaboration policies](../development/collaboration-policies.md) specifies
  canonical policy identity and paved enforcement, explaining why correlation
  cannot grant authority.
- [Copilot delivery safety](../development/copilot-delivery-safety.md) specifies
  idle injection, prompt binding, leases, completion, and wake budgets reused here.
- [Threat model](../security/threat-model.md) records endpoint compromise and
  external-effect limitations that continuation does not solve.
