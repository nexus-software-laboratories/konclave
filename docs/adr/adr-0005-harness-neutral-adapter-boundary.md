---
title: Separate harness delivery from the daemon through an outbound local adapter channel
status: Superseded
date: 2026-08-22
authors:
  - Konclave maintainers
tags:
  - adapters
  - daemon
  - delivery
  - ipc
  - security
supersedes: []
superseded_by:
  - adr-0008-shared-local-service
---

# Separate harness delivery from the daemon through an outbound local adapter channel

## Context and scope

Konclave must notify an active agent harness when a remote conversation event arrives
without asking the model to poll. The daemon already owns MLS state, relay replay,
sealed local history, membership policy, and the durable cursor. Copilot CLI is the
first supported harness, but those responsibilities cannot acquire Copilot-specific
types or lifecycle assumptions.

ADR 0004 assigns watch and reconnect tasks to the daemon service root. It does not
define a durable boundary between relay processing and delivery into an agent
harness. This decision owns that boundary, the local connection direction, delivery
semantics, and the division between neutral core behavior and harness-specific
behavior.

It does not define the final frame encoding or implementation modules. Those are
implementation choices only while they preserve the versioning, bounds,
authentication, and state transitions selected here.

## Verified facts

- The daemon's MCP server is currently declared to Copilot CLI through
  `mcpServers`. The extension supplies configuration, while Copilot owns the MCP
  child and routes tool calls directly.
- GitHub Copilot SDK 1.0.11 lets an extension register custom tools with runtime
  handlers. A real extension probe confirmed that Copilot can invoke such a handler.
- Owning the daemon inside the extension would require rediscovering every MCP schema
  and reimplementing tool lifecycle, cancellation, result conversion, and permission
  parity in the adapter.
- A Node adapter can own a Unix-domain-socket or Windows named-pipe endpoint before a
  child starts. A Rust process can connect outward using launch-provided
  configuration.
- The adapter transport spike rejected wrong capabilities, wrong profiles, and stale
  endpoints; it also accepted daemon and adapter restart scenarios.
- Relay acknowledgment currently means that an envelope was durably processed by the
  daemon. It does not mean that any harness accepted a notification.
- The relay sends an empty initial page to confirm a WebSocket watch. A one-page
  caller therefore cannot provide durable background notification by repeatedly
  invoking the existing watch tool.

## Assumptions

- The daemon remains the only trusted process boundary that handles MLS private state
  and sealed persistence.
- An authorized adapter necessarily receives the application plaintext that it must
  present to its harness, but it never receives identity keys, MLS provider state,
  relay credentials, or wrapping keys.
- The operating-system account and active process memory are trusted. Root,
  administrator, process-injection, or same-account memory compromise is outside the
  local confidentiality guarantee.
- The adapter process starts before the daemon child and can create a local endpoint
  plus an owner-protected capability file before passing non-secret launch
  configuration to that child.
- Harness lifecycle and idle-state APIs differ. The daemon cannot infer when a
  particular harness should start a model turn.
- Delivery into a harness is not transactional with the daemon's SQLite transaction.

## Decision drivers

- Keep protocol, cryptography, persistence, relay, and local delivery state
  independent of any harness.
- Preserve native MCP integrations rather than proxying every daemon tool through
  every adapter.
- Require no internet-facing or loopback TCP listener on an agent device.
- Make relay replay progress independent of harness availability.
- Prevent silent notification loss across daemon, adapter, and harness crashes.
- Bound every frame, wait, lease, queue, backlog, and retry.
- Treat remote member content as untrusted input rather than executable instruction.
- Allow later Claude Code, Codex, and other adapters to use the same daemon contract.

## Decision

### Ownership boundary

The daemon owns:

- identity, MLS, membership authorization, relay access, replay, and acknowledgment;
- sealed application and membership history;
- a profile-global remote-event journal;
- local delivery eligibility, claim, lease, acknowledgment, release, and recovery;
- continuous relay watch and reconnect supervision; and
- the neutral service exposed over the local adapter transport.

An adapter owns:

- the local endpoint and launch capability;
- mapping an authenticated neutral event into one harness;
- harness activity and idle-state observation;
- batching, wake budgets, prompt framing, and model-turn initiation;
- reporting whether the harness accepted a delivery; and
- adapter-specific user experience and diagnostics.

MCP remains a supported tool binding. It is not the normative remote-event API.
Daemon services and persistence contain no Copilot, Claude, Codex, model, prompt, or
session type.

### Connection direction and lifecycle

The adapter creates a random local endpoint before starting or joining its harness:

- a Unix-domain socket inside an adapter-private directory on Unix; or
- a random named pipe on Windows.

The adapter generates a 32-byte operating-system-random launch capability and a
random consumer-instance identifier. It creates a fresh adapter-private directory
and writes the capability to an exclusively created owner-readable file. The adapter
passes only the endpoint, capability-file path, consumer identifier, and validated
profile identifier to the daemon child through the launch environment.

The daemon opens the capability file without following links or reparse points,
requires an ordinary bounded file owned by the current account with no broader
access, reads one canonical unpadded base64url value, and zeroizes its buffer after
use. The adapter retains the file only while its endpoint is live so a harness-owned
daemon restart can authenticate with the same adapter. Adapter shutdown removes the
file and private directory by exact path. The capability never enters command
arguments, harness session configuration, logs, telemetry, or persisted profile
records.

The daemon connects outward to the endpoint. It never opens a TCP listener. Missing,
invalid, or unreachable adapter configuration does not disable MCP or relay recovery;
the daemon records a bounded degraded state and retries with backoff. It never falls
back to an unauthenticated channel.

One authenticated adapter connection may own the active consumer lease for a profile
at a time. A second consumer fails closed. The daemon profile lock remains the
stronger process-ownership boundary and prevents two daemons from owning one profile.

An adapter restart creates a new endpoint, private directory, capability file, and
consumer instance. A daemon restart under the same live adapter may reconnect with
the existing launch configuration. Closing the adapter connection cancels
outstanding waits but does not acknowledge claimed events.

### Local endpoint protection and mutual authentication

Unix adapters create an owner-only directory and socket. Windows adapters use the
process token's restrictive named-pipe security descriptor and verify the effective
access policy before accepting traffic. The random endpoint name is defense in depth,
not authentication.

Every connection performs a bounded, versioned mutual challenge-response before
plaintext event data can flow:

1. The adapter sends a protocol version, consumer instance, and fresh 32-byte
   challenge.
2. The daemon sends its validated profile identifier, a fresh 32-byte challenge, and
   an HMAC-SHA-256 proof over both challenges, the version, profile, and consumer
   instance under the launch capability.
3. The adapter verifies that proof and returns a domain-separated HMAC-SHA-256 proof
   over the same transcript.
4. The daemon verifies the adapter proof before serving requests.

The daemon uses the project's vetted cryptographic adapter and the adapter uses its
platform's standard HMAC-SHA-256 implementation. Shared fixtures prove byte-for-byte
parity; neither side authors a new primitive. Challenges cannot repeat within one
process. Proof domains for daemon and adapter roles are distinct. Comparisons are
constant time.

The authenticated transcript has one canonical binary encoding: a fixed-width
protocol version, bounded length-prefixed profile and consumer identifiers, then the
two fixed 32-byte challenges in role-defined order. Each proof prepends its distinct
fixed role domain. Concatenated variable-length strings and implementation-native
serialization are forbidden.

The raw capability never crosses the channel. Failed authentication closes the
connection with a bounded code and no identifying input. Capability buffers are
zeroized when the channel ends.

Pre-authentication frames use a smaller hard limit than authenticated event frames.
Unknown versions, unknown message kinds, duplicate fields, malformed lengths, and
trailing bytes fail closed before allocation or side effects.

### Profile-global remote-event journal

The daemon records remote delivery events in one sealed profile-global journal.
Events have:

- a monotonically increasing local event sequence;
- a stable random notification identifier generated once when the event is first
  committed;
- a finite event kind;
- bounded operational metadata needed to select eligible work; and
- a sealed payload or sealed reference to the already durable application or
  membership record.

Initial event kinds are:

- remote application message received;
- remote membership change applied;
- remote role change applied; and
- local device access removed by a remote membership change.

Local application echoes and locally initiated membership completion do not create
adapter events. The authenticated MLS sender and persisted operation determine
whether an event is remote; payload fields never do.

Event creation is part of durable inbound completion and occurs before the daemon
advances relay acknowledgment. Once committed, relay replay may progress even when no
adapter is connected. Adapter delivery state never changes the relay cursor.

The journal stores no harness identifier. Its event sequence and per-event state are
the adapter-delivery progress authority and are independent of every relay route
cursor.

### Delivery eligibility and mute behavior

Automatic delivery is a local, transport-neutral policy for each conversation.
Existing conversations begin muted when this feature is introduced. Creating or
joining a conversation does not implicitly enable delivery based on an MCP caller;
an authorized explicit policy operation enables it.

When a conversation is muted:

- relay replay, MLS processing, sealed history, and acknowledgment continue;
- no event becomes claimable by an adapter;
- the event receives a terminal suppressed-delivery state; and
- unmuting affects later events only.

The complete sealed history remains available through explicit read operations.
Muted traffic therefore cannot create an unbounded auto-delivery backlog or block
other conversations.

### Wait, claim, lease, and acknowledgment

The authenticated transport exposes a versioned neutral operation that waits for and
claims a bounded non-empty batch. One consumer may have at most one outstanding wait.
The daemon responds when eligible work exists or when a bounded wait expires. An
empty timeout is not an event and clients reissue it with bounded backoff, preventing
a hot poll loop.

Claiming atomically changes each selected pending event to claimed and records:

- the consumer instance;
- a random lease identifier;
- a lease generation; and
- a bounded expiry.

Claims preserve order within each conversation and use bounded round-robin selection
between eligible conversations. Suppressed events do not block later eligible
conversations. Batch count and encoded bytes are independently bounded.

The adapter acknowledges an event only after its harness accepts the delivery
operation. For Copilot CLI, acceptance means that deferred `session.send()` resolves;
it does not claim that the model completed or obeyed the resulting turn.

Acknowledgment is idempotent for an already acknowledged notification identifier.
An acknowledgment for an expired, released, wrong-consumer, or superseded lease
generation fails as stale and cannot acknowledge a later claim. A consumer may
release a claim before expiry.

Connection loss makes unacknowledged claims reclaimable. Daemon startup invalidates
all active leases before accepting a consumer. A running daemon reclaims an expired
lease using an injected time provider and checked time arithmetic.

The contract is at least once:

- a crash before harness acceptance leaves the event pending or reclaimable;
- a crash after harness acceptance but before durable acknowledgment may deliver the
  same stable notification identifier again; and
- exactly-once harness delivery is not claimed.

Acknowledged and suppressed tombstones are retained for a bounded deduplication and
diagnostic horizon, then removed as whole terminal records.

### Backpressure and degraded state

Pending delivery events are hard bounded by count and encoded bytes at both profile
and conversation scope. Per-conversation quotas and reserved profile capacity prevent
one conversation from consuming every available slot. The daemon never drops an
enabled event to make room. Before a new event would exceed its conversation quota,
replay for that conversation pauses without acknowledging the unprocessed relay
envelope and surfaces a bounded degraded status. Profile-wide replay pauses only when
the independently bounded profile capacity is exhausted despite those quotas.

Muted conversations do not consume pending-event capacity because their events are
terminally suppressed while history remains durable.

Adapter wake budgets do not alter journal correctness. An adapter that reaches a
global or per-conversation budget delays new claims or releases current claims. It
does not acknowledge undelivered work.

### Harness delivery safety

Adapters treat every peer-controlled field as hostile data. A harness delivery:

- identifies the conversation, authenticated sender, event kind, and stable
  notification identifier separately from peer content;
- quotes peer content inside an explicit untrusted-collaborator boundary;
- never promotes peer content to system, developer, permission, or tool authority;
- never automatically executes a peer request or grants a tool permission;
- allows at most one outstanding synthetic turn per adapter;
- coalesces bursts under independent count and byte limits;
- enforces global and per-conversation wake budgets; and
- reports muted, throttled, disconnected, and backlog-degraded states without
  including plaintext or credentials in diagnostics.

Loop prevention uses authenticated local sender identity and notification
identifiers, not text matching. An adapter response becomes a normal explicit
Konclave send operation; receiving a synthetic turn alone never sends a message.

## Serious alternatives

### Extension-owned daemon and MCP proxy

**Pros:** one process can coordinate daemon lifecycle, tool calls, and harness
delivery.

**Cons:** each adapter must rediscover and re-expose every MCP tool, preserve
permissions and cancellation semantics, translate results, and remain compatible
with two evolving APIs. It couples native harness tool support to adapter code.
Rejected despite verified technical feasibility.

### Daemon-owned local listener

**Pros:** conventional client adapters can connect whenever available.

**Cons:** requires persistent rendezvous and credential storage, introduces an
inbound listener owned by the trusted plaintext process, and complicates stale-daemon
discovery. Rejected.

### MCP notifications or repeated watch tools

**Pros:** smaller initial code change.

**Cons:** harnesses do not uniformly turn MCP notifications into model turns, and
repeating the existing one-page watch recreates polling and empty-page loops.
Rejected as the automatic-delivery contract.

### Exactly-once harness delivery

**Pros:** no duplicate model turns.

**Cons:** no atomic transaction spans daemon SQLite and a harness model turn. Claiming
exactly once would either acknowledge before delivery and lose messages or retain an
unprovable distributed transaction. Rejected.

## Consequences

### Positive

- Core delivery and persistence remain independent of Copilot CLI.
- Existing harness-native MCP support remains intact.
- The agent device opens no internet or loopback TCP listener.
- Relay replay can progress while an adapter is disconnected or muted.
- Crash windows have explicit at-least-once behavior and stable deduplication IDs.
- Future adapters share one security and conformance contract.

### Negative

- The daemon and adapter maintain a second local transport beside MCP.
- Mutual authentication, protected capability-file lifecycle, leases, tombstones,
  capacity handling, and reconnect add state-machine complexity.
- An adapter that receives plaintext can disclose it if compromised.
- A send-before-ack crash may create a duplicate synthetic turn.
- Enabled conversations can eventually backpressure relay replay while no adapter
  accepts events.

### Neutral

- MCP tools continue to work without an adapter channel.
- Harness-specific idle detection and wake policy remain adapter concerns.
- The local transport codec may evolve behind its explicit version boundary.

## Confirmation

Continued compliance is demonstrated by:

- conformance tests that exercise the neutral event service without Copilot CLI;
- wrong-capability, wrong-profile, endpoint-squatting, replayed-proof, and stale-lease
  rejection;
- capability-file exclusive creation, ownership, permission, symlink/reparse
  rejection, bounded read, restart reuse, and exact cleanup;
- Unix permission and Windows named-pipe access-policy tests;
- Rust-to-Node integration on every supported platform;
- crash tests before and after event commit, relay acknowledgment, claim response,
  harness acceptance, and adapter acknowledgment;
- tests proving muted traffic advances relay history without becoming claimable;
- capacity tests proving enabled events backpressure rather than disappear;
- adapter tests for idle gating, one outstanding turn, batching, budgets, framing,
  and own-echo prevention;
- raw profile, relay, log, trace, and error scans for plaintext and capabilities; and
- specialized security review before the event journal, local transport, or harness
  injection is delivered.

## References

- [ADR 0001: Protocol trust and E2EE](adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0002: Sealed local secret custody](adr-0002-sealed-local-secret-custody.md)
- [ADR 0004: Daemon profile journal](adr-0004-daemon-profile-journal.md)
- [Harness-neutral adapter transport spike](../development/adapter-transport-spike.md)
- [Threat model](../security/threat-model.md)
