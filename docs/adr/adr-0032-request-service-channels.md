---
title: Isolate directional request services with immutable private channels
status: Proposed
date: 2026-10-31
authors:
  - Konclave maintainers
tags:
  - messaging
  - authorization
  - membership
supersedes: []
superseded_by: []
---

# Isolate directional request services with immutable private channels

## Context and scope

A service operator must receive requests from independently running agents, perform
locally authorized work and answer each requester without initiating requests or
giving requesters a channel to each other. One operator inbox should not imply one
shared encryption group.

This decision owns communication direction, endpoint membership and private channel
identity. It does not define operational recipes, tickets, task scheduling, remote
tool permissions or exactly-once external effects.

## Verified facts and assumptions

MLS delivers group application messages to all members. The current directed-request
target selects a handler, not a private recipient. A shared group therefore cannot
provide confidentiality between its requesters.

The existing domain membership snapshot defines device identities and administrator
roles. The cryptographic adapter authenticates membership context in MLS group
extensions and commits. Invitations already bind expected device, conversation,
role and issuer. These are the boundaries that must authenticate a channel contract,
not model instructions or a display alias.

Directed requests already name an exact device. Terminal replies reference the
original message, and durable claims and response reservations protect automatic
effects. ADR 0030 permits an exact answer to resume locally authorized requester
work without making that answer a new request.

The operator is trusted with all of its own channels' plaintext. A compromised
operator can disclose information across channels. Broad ordinary-session work
authority is not an operating-system sandbox.

## Decision drivers

- No direct requester-to-requester messaging or shared plaintext.
- Native checks that do not depend on a particular model or harness.
- Explicit local work authority, independent of channel enrollment.
- Existing encryption, correlation and durable recovery rather than new cryptography.
- Ordinary conversations retain their current behavior and encoded representation.

## Decision

Introduce an explicitly negotiated request-service channel with one immutable
operator device and one distinct immutable requester device. Each requester uses a
separate MLS conversation. An operator-only state is permitted before enrollment
and after revocation. The operator remains the sole administrator, the requester
remains an ordinary member, and no third device or role promotion is permitted.

Authenticate the contract in the signed invitation and MLS membership snapshot.
Unknown or stripped channel semantics must fail closed. Capability support is
verified before enrollment; legacy ordinary invitations and snapshots retain their
bytes. Existing conversations are not silently converted.

The requester may initiate directed requests only to the operator. The operator may
send text only as a response to an authenticated original request in that exact
channel. Neither endpoint may send unsolicited text. The operator also needs a
current locally authorized original-request claim; generic claim-free manual replies
are refused. One terminal response is reserved durably per original request; a
different response conflicts. An authenticated sealed receipt is committed with
reply history and survives duplicate request echoes and restart. Explicit
policy exchange and separately authorized membership maintenance remain control
operations, not task messages. Internal repeat-pairing cannot introduce another
channel through this restricted conversation.

Apply the same native authorization checks to outbound admission, authenticated
inbound processing and membership changes. The harness presents the restriction
and intersects local policy with ordinary permissions; it is not the sole enforcer.
Enrollment grants no work permission. The operator must explicitly activate current
reply and work authority before an incoming request can start an autonomous work
turn.

An operator's correlated response may ask for clarification. The requester can
deliberately initiate a new request referencing prior context under its existing
local authority. Responses remain terminal, and unsolicited text never starts work.
Existing profile delivery combines the operator's channels through bounded
per-conversation admission and fair event batches. Operator inspection lists bounded
channel pages and reads unreplied history separately for each channel; it does not
claim work, forward messages or introduce a task registry.

## Serious alternatives

| Alternative | Benefits | Costs and disposition |
| --- | --- | --- |
| Shared group with target checks | Fewer groups and simple presentation | Every requester can decrypt other traffic; rejected |
| Private channels with prompt-only restrictions | Reuses current conversations | Alternate clients can bypass direction and membership conventions; rejected |
| Private channels with native immutable contracts | Cryptographic requester separation and consistent authorization | More membership state and explicit negotiation; chosen |
| Decrypting routing coordinator | Centralized routing and scheduling | Adds plaintext custody and can forward between requesters; rejected |

## Consequences

The operator manages more conversations but uses the existing local delivery stream.
Membership changes on one channel do not grant another requester its epoch secrets.
Changing operator identity requires explicit new enrollment, not an implicit alias
update. Channel removal prevents new admission, but cannot retract delivered
plaintext or previously admitted external work.

These restrictions cover the enrolled channels, not devices' separately authorized
ordinary conversations or external systems. They do not protect against intentional
information forwarding by the operator or a broadly authorized shell.

The isolation endpoint is a device/profile, not a Copilot process. Requesters must
use separate identities; sharing a profile shares its channel access. Restricted
history requires profile schema 23 and its protected reader floor, so an older reader
cannot reconstruct an epoch-zero restricted channel as an ordinary group. New native
startup raises that floor even for ordinary profiles. Coherent restore, selective
deletion and independent freshness remain outside sealed-record guarantees.

The existing supervisor bounds active conversations and handles transient failures
in independent workers. It still stops the profile on permanent authentication,
storage or capacity failure; channel isolation is not an availability guarantee.
Unreplied history is not a scheduler: a request completed without a response can
remain visible without becoming claimable again.

Idle-only delivery can queue requests while an operator is busy. Relay acceptance is
not work acceptance. Time-sensitive assignments need a fresh availability exchange;
this mode does not promise prompt interruption or a deadline measured from receipt.

## Confirmation

Pure tests cover endpoint identity, operator-only and active membership, role
mutation, third members, request direction, authenticated original-request binding,
cross-channel replies, removed requesters and forbidden internal content.
Integration must prove signed-contract stripping fails, legacy ordinary bytes remain
compatible, real MLS membership cannot add a third device, native clients cannot
bypass direction, and response reservation remains unique through retries and
restart. Multi-channel evidence must prove requester history isolation and bounded
fair inbox handling. Full platform and packaged evidence remains distinct from
these component checks.

## References

- [ADR 0001](adr-0001-protocol-trust-and-e2ee.md) establishes group E2EE and
  application membership authorization, explaining why targets alone are not privacy.
- [ADR 0004](adr-0004-daemon-profile-journal.md) establishes split-journal durable
  processing, which this mode must preserve rather than replace.
- [ADR 0030](adr-0030-correlated-response-continuation.md) establishes terminal
  responses, exact answer continuation and explicit local authority; this mode
  narrows communication without introducing a workflow engine.
- [Request-service operations](../development/request-services.md) owns current
  commands, explicit enrollment, bounded inspection and operational limitations.
