---
title: Explain message delivery through authenticated local metadata
status: Accepted
date: 2026-09-20
authors:
  - Konclave maintainers
tags:
  - diagnostics
  - privacy
  - delivery
supersedes: []
superseded_by: []
---

# Explain message delivery through authenticated local metadata

## Context and scope

An operator needs to distinguish an unavailable local consumer from a message still
waiting for relay acceptance. Neither circumstance justifies exposing plaintext to
the relay, collecting complete logs, or inferring that a remote model ran.

This decision covers a read-only diagnostic for one explicitly selected message in
one conversation of an already authorized local profile. It does not add a
conversation viewer, distributed tracing service, repair agent, remote receipt
protocol, or another source of durable delivery state.

## Verified facts

- The local service already binds each connection to one authenticated profile and
  finite capabilities. Message-history reads require read authority.
- The profile journal seals message content, envelopes, cursor observations,
  notifications and directed-request handling. Clear SQLite status or cursor columns
  are not independent proof of the corresponding authenticated transition.
- Relay acceptance, contiguous local completion, harness acknowledgment and request
  handling are separate milestones. A response reservation may precede envelope
  preparation and relay submission.
- Remote notification cleanup retains only a bounded terminal horizon. Absence of a
  retained notification does not prove that delivery never happened.
- A handling claim records an expiry, but expiry alone does not prove the liveness of
  its consumer.
- Existing local health reports expose bounded watch counts and a degraded flag.
  They do not establish the remote outcome of an individual message.

## Assumptions

- The operator can supply the conversation and message identifiers from an existing
  authorized operation.
- Local state is useful even when the remote outcome remains unknown.
- On-demand inspection is preferable to adding work to every message's hot path.

## Decision drivers

- Preserve E2EE, endpoint custody and profile isolation.
- Explain only milestones supported by authenticated local evidence.
- Bound reads, output and retention without duplicating the message journal.
- Keep diagnosis read-only and independent from inference or repair.
- Reuse existing local IPC, CLI and harness command boundaries.

## Decision

### Require existing local read authority

The local operation selects one conversation and one message inside the connection's
exact profile. It accepts no profile override, endpoint, path, device selector, or
arbitrary query. Authorization runs before persistence lookup. Invalid selectors and
unavailable, corrupt or unauthorized state remain explicit operation failures.

The operation is a deterministic command/client surface, not an automatic model turn.
It does not broaden an automatic response turn's tool set or permit a fallback to
another profile or integration.

### Project authenticated evidence without exporting content

The persistence boundary reuses bounded record opening and context verification.
Cursor observations must be verified before reporting relay acceptance. Inbound
completion must be checked against the authenticated replay boundary. Notification
and handling fields must reproduce their sealed records and exact source identity.

Hidden internal application records remain hidden. An unsealed reservation, missing
history, or record outside the inspectable surface is not reported as proof that a
message committed. The diagnostic reports `not_observed`; it never means safe to
allocate a new message identifier or proof that the remote endpoint saw nothing.

The result contains a finite message-status code, the selected conversation's local
automatic-delivery setting, a clearly profile-scoped degraded indicator, and the
constant remote-outcome value `unknown`. It contains no bodies, prompts, file paths,
identity lists, credentials, keys, capabilities, arbitrary error strings or raw
serialized records. Request identifiers need not be echoed in the result.

The pure domain classifier distinguishes:

- authenticated outbound preparation, readiness, relay acceptance, expiry and removal;
- inbound preparation and completion;
- pending, claimed, acknowledged, suppressed or no-longer-retained notifications; and
- recorded or expired request claims, response reservation, and completion without a
  response.

Claim expiry is a recorded local fact, not consumer-liveness evidence or permission
to retry. Harness acknowledgment is not model execution. `response_reserved` is not
remote response delivery.

### Add no remote observation or hidden side effect

Inspection makes no network request, starts no model, changes no delivery state,
renews no lease, performs no retry, and activates no policy. It creates no diagnostic
journal or telemetry upload. Existing authenticated read-request reconciliation may
retain its bounded operation result under the service's normal contract.

The CLI and harness render fixed explanations and safe next actions from the same
finite contract. An old service that lacks the operation fails visibly; it is not a
reason to discover another profile or use an unsupported integration.

### Treat metadata as sensitive

Access is local and profile-authorized by default. Results are ephemeral command
output, not automatically exported activity. Retention remains owned by the
underlying journals and caller's explicitly chosen output destination.

An export is a deliberate disclosure even when it contains no plaintext. No content
hashes, stable cross-profile correlation identifiers or unrestricted metadata map
are introduced as supposedly anonymous substitutes.

### Keep work bounded and off the delivery hot path

An inspection opens only the selected bounded message and its directly associated
records. It uses existing indexed identities/cursors rather than scanning complete
history. Reads must not introduce per-message writes, a network probe or an
unbounded collection. The classifier allocates no memory and performs no I/O.

## Serious alternatives

### Central conversation inspection

**Pros:** convenient combined operator view.

**Cons:** requires plaintext access or a new endpoint trust relationship, widens
metadata collection and confuses relay delivery with agent behavior. Rejected.

### Return raw logs or journal rows

**Pros:** little initial projection code and substantial troubleshooting detail.

**Cons:** exposes content, credentials, internal control records and unauthenticated
storage metadata; couples callers to persistence. Rejected.

### Add encrypted remote progress receipts immediately

**Pros:** could establish more remote milestones.

**Cons:** introduces new message kinds, state, retention, capability negotiation and
traffic metadata before local evidence has proved insufficient. Deferred.

### Report only existing aggregate health

**Pros:** no additional local query.

**Cons:** cannot distinguish a selected message's submission, notification and
handling stages. Retained as context rather than a replacement for exact inspection.

## Consequences

Operators gain useful local explanations without granting the relay message access.
The same operation serves local clients and harness commands. Diagnosis cannot
answer every end-to-end question, and authenticating selected records requires
bounded local decryption inside the existing trusted endpoint. It does not imply
decryption by the caller or any new external plaintext access.

## Confirmation

The implementation must demonstrate:

- complete table coverage of finite classification and exact claim-expiry boundaries;
- authorization before lookup and no caller-selected profile;
- real persistence failures, malformed metadata and seal/context mismatches reaching
  explicit errors;
- no content, credentials, capabilities or paths in results and failure output;
- no exposure of internal application records;
- correct distinctions between reservation, acceptance, acknowledgment and execution;
- bounded indexed reads and measured inspection overhead without hot-path writes; and
- identical safe rendering and visible unsupported-service behavior across clients.

## References

- [ADR 0004](adr-0004-daemon-profile-journal.md) owns authenticated crash-journal
  ordering and source verification.
- [ADR 0008](adr-0008-shared-local-service.md) keeps the trusted service on local IPC.
- [ADR 0012](adr-0012-structured-directed-collaboration-requests.md) separates delivery
  and exact response authority.
- [Daemon profiles](../development/daemon-profiles.md) describes retained records and
  their bounds.
- [Threat model](../security/threat-model.md) defines endpoint and metadata exposure.
