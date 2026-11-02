---
title: Distinguish request delivery from task execution
status: Proposed
date: 2026-11-02
authors:
  - Konclave maintainers
tags:
  - messaging
  - delivery
  - compatibility
supersedes: []
superseded_by: []
---

# Distinguish request delivery from task execution

## Context and scope

Idle-only delivery can retain a directed request while its target is busy. A deadline
written in the body is opaque text: the receiver cannot reject an obsolete request
without asking a model to interpret it. A relay acknowledgement proves durable
transport progress, not acceptance into a locally authorized turn.

Konclave owns secure messaging, authenticated correlation and local admission.
Task meaning, execution budgets, retries, scheduling and external side effects remain
the responsibility of callers. This decision adds no task registry or workflow engine.

## Verified facts and assumptions

Directed requests already name an exact target and stable message identifier.
Authenticated local history retains original requests and correlated answers.
The native handling journal binds current local policy, consumer, notification,
lease and attempt before the adapter enqueues a synthetic turn. Its terminal response
reservation is atomic with the response operation; no-response completion is durable.
These are delivery facts that can be observed without understanding message bodies.

MLS authenticates senders and encrypts application content. Signed credential
capabilities already negotiate additive application semantics. Older protobuf readers
can ignore new optional fields, so adding an expiry field alone cannot guarantee
that an older target will enforce it.

The receiver uses its local wall clock for cutoff comparison. Clock synchronization
and honest peer reporting are assumptions, not guarantees provided by a receipt.
An authorized harness can delay or discard a prompt after native admission.

## Decision drivers

- Reject obsolete requests before spending a model turn.
- Distinguish transport acceptance, local admission and terminal response.
- Preserve ordinary directed requests and their existing encoded representation.
- Keep receipts confidential, authenticated and unable to grant authority.
- Reuse existing bounded journals and outbox recovery rather than task state.

## Decision

Offer optional delivery options on a directed request. Their presence requests
delivery observations; they may include an absolute admission cutoff in Unix
milliseconds. No options means existing behavior and bytes. A cutoff must be nonzero
and exactly representable by supported JSON clients. The sender must not silently
drop options when members lack the new signed capability.

Admission is the native service's durable acceptance of the exact request for a
locally authorized turn immediately before model enqueue. It is not relay receipt,
model execution, task success or an external tool's start. Check the authenticated
cutoff before accepting a new handling claim. Equality is expired. A previously
admitted request is not cancelled when the cutoff passes; its existing lease,
current policy and one-use response rules remain independently enforced.

The receiver emits bounded encrypted observations for admission, expiry before
admission and handling ended without a response. An actual correlated answer proves
the responded outcome. Receipt content carries no task body or free-form reason.
Its reply reference binds the original request, and the authenticated sender must
be that request's exact target in the same conversation. Unrequested, malformed or
mismatched observations fail closed. Restricted channels retain their immutable
endpoints and their single terminal-answer reservation; a receipt is not an answer.

The handling journal records the delivery fact and hence the intent to emit its
receipt. Materialization reuses ordinary encrypted outbound journaling and retry;
restart reconstructs an interrupted receipt from that fact. Stable, domain-separated
receipt identifiers make duplicate materialization idempotent. No receipt claims
exactly-once execution. Removal or incompatible membership can abandon a pending
receipt with a local diagnostic, but cannot block profile recovery or reopen
handling. Existing ciphertext remains bound to its original epoch and reservation.

Receipts remain inspectable authenticated history but never start model turns,
trigger answer continuation or request another reply. Absence of a receipt is
unknown, not success, expiry or failure. Duplicate observations are idempotent,
late admission cannot reopen a terminal result, and contradictory terminal
observations are errors. No automatic retry follows an expiry observation.

## Serious alternatives

| Alternative | Benefits | Costs and disposition |
| --- | --- | --- |
| Keep deadlines in bodies | No wire change | Requires model interpretation and produces obsolete turns; rejected |
| Add optional expiry without negotiation | Smallest schema edit | Older targets can ignore it and execute anyway; rejected |
| Add negotiated delivery options and authority-free receipts | Reuses message identities and durable claims; stays task-agnostic | Adds compatibility and recovery obligations; chosen |
| Track tasks, budgets and retry policies inside Konclave | Rich coordination | Duplicates external orchestration and changes product scope; rejected |

## Consequences

Callers can separate time waiting for admission from their own execution budget.
They must still decide whether and how to retry and reconcile external effects.
Receipts increase encrypted message traffic and history size. Busy, offline,
unauthorized or removed receivers may not produce a timely observation.

The cutoff is measured against a receiver clock, not a trusted global clock.
Admission does not guarantee that the harness will promptly start a model. Expiry
does not interrupt foreground work, revoke permission or terminate admitted tools.
The authenticated profile reader floor must prevent an older runtime from opening
delivery state it cannot safely interpret.

## Confirmation

Pure tests cover numeric boundaries, equality, unknown outcomes and every finite
observation pair. Integration evidence must cover negotiated and legacy wire bytes,
real sealed-history correlation, expiry before a new claim, admission before cutoff
followed by a late response, duplicate materialization, restart recovery, malformed
or substituted receipts, restricted-channel reply uniqueness and receipt-only
history without a model wake. Full platform and package qualification remains
separate from these focused checks.

## References

- [ADR 0004](adr-0004-daemon-profile-journal.md) establishes durable split journals;
  receipt recovery must preserve those crash boundaries.
- [ADR 0030](adr-0030-correlated-response-continuation.md) permits continuation on
  an exact ordinary-text answer; delivery observations deliberately do not qualify.
- [ADR 0032](adr-0032-request-service-channels.md) describes immutable restricted
  endpoints and one terminal response, which receipts must not consume or bypass.
- [Threat model](../security/threat-model.md) distinguishes relay acknowledgement,
  adapter acknowledgement and durable handling; none proves external execution.
