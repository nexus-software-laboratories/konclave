# Daemon profiles and recovery

The local daemon profile is the trusted persistence boundary for one device endpoint.
ADR 0004 defines crash ordering and journal semantics; this page describes the
concrete profile layout.

## Directory layout

One validated profile identifier selects:

```text
<profile-root>/<profile-id>/
  profile.lock
  profile.sqlite
  mls.sqlite
```

The identifier is canonical: bounded lowercase ASCII letters, digits, `-`, and `_`.
Uppercase is rejected rather than folded, because the identifier is also a directory
name and a case-insensitive filesystem would otherwise resolve two spellings to one
profile with two locks and two owners.

An existing mixed-case profile is not opened through a lowercase alias. It requires
an explicit migration of both its directory and native custody record; automatic
renaming or case folding is forbidden because it cannot prove the intended identity.

`profile.lock` is acquired exclusively and without waiting. The daemon holds it until
shutdown. Native wrapping-key load-or-create occurs only while that lock is held.

`profile.sqlite` belongs to the daemon store. `mls.sqlite` belongs to
`SealedSqliteMlsStorage`; their schema versions and migrations are independent.

## Profile store

Schema version 10 stores:

- one profile row with a sealed device root and optional sealed relay credential;
- normalized non-secret relay endpoint;
- conversation and routing identifiers;
- sealed conversation signing material and policy state;
- sealed, root-verified conversation credential bindings;
- sender counter and replay cursor;
- outbound application reservations, sealed envelopes, relay acceptance state, and
  explicit terminal expiry or local-removal reasons;
- sealed outbound membership control, Commit envelopes, next policy state, Welcome
  bytes, and ready/accepted/applied/orphaned state;
- one sealed envelope observation for every accepted route cursor;
- received application envelopes, sealed decoded messages, and completion state;
- received membership Commit envelopes plus sealed decrypted control and validated
  next-policy checkpoints;
- pending invitation joins with sealed conversation signing material, one-time
  KeyPackage proof, peer bindings, checkpointed Welcome state, the Welcome-authenticated
  expected Commit envelope identifier, and the exact relay Commit receipt establishing
  the joined replay baseline;
- one versioned sealed replay head binding the previous and current cursor, exact
  envelope, completion kind, historical completion policy, and independently advanced
  current policy authority;
- one sealed cursor-ordered history for both sent and received messages.
- one sealed per-conversation automatic-delivery policy, defaulting to muted when
  absent;
- one sealed profile-global remote-event journal with stable notification
  identifiers, event sequence, authenticated journal head, typed source references,
  and sealed delivery state; and
- one ephemeral active adapter-consumer lease plus per-event claim generations,
  expiries, acknowledgments, releases, and restart recovery.

Version 1 through 8 schema changes use explicit transactions. Before changing a v2
schema, startup rejects ready or accepted outbound rows whose plaintext cannot be
reconstructed, leaving version 2 unchanged. Sealer-backed inbound history
rehydration runs afterward in bounded, resumable batches; a failure preserves the
source rows and retries forward on the next open.

The version 9 migration reconstructs the application outbox in one transaction so
terminal reason `2` can represent local removal without reusing expiry. Any copy,
constraint, or index failure rolls the migration back and leaves the version 8 table
authoritative.

The version 10 migration adds the remote-event journal and adapter-consumer state in
one transaction. Existing conversations have no sealed delivery policy and therefore
remain muted. No legacy history is converted into synthetic adapter events. A failed
schema change rolls back to version 9.

Remote application and membership completion create one context-bound event before
advancing the relay cursor. Local echoes do not create events. Muted conversations
create terminally suppressed records while relay replay and sealed history continue.
Remote self-removal has a distinct immutable event kind rather than a value derived
from later profile state. Enabled conversations create pending records; hard profile
and conversation count and encoded-source-byte limits stop replay before an event
could be dropped.

One active transport-neutral consumer lease owns claims for the profile. Claim state
is sealed independently from relay progress and carries a generation, expiry, and
stable notification identifier. Acknowledgment is idempotent after harness
acceptance. Expired, released, disconnected, and restart-interrupted claims become
pending without changing their notification identifiers. A stale generation cannot
acknowledge a later claim.

The sealed journal head binds the latest sequence and notification identifier.
Bounded cleanup removes only a contiguous prefix of acknowledged or suppressed
records and advances a separately sealed floor; acknowledgment and suppression
transitions invoke cleanup automatically while retaining a bounded recent terminal
horizon for idempotency. Pending or claimed work stops prefix cleanup, and a separate
hard total-record limit prevents that blockage from growing the table without bound.
Reaching the hard limit pauses replay rather than dropping an event, including for a
muted conversation. Startup verifies the head, floor, retained chain, every mutable
delivery-state record, and the exact event source before accepting a consumer.
Plaintext status, policy, lease, deletion, or sequence edits therefore fail closed.

Schema migration never infers a replay head from legacy plaintext completion fields.
A legacy profile with a nonzero cursor and no sealed replay head fails closed and
requires explicit recovery rather than risking a skipped membership transition.
When upgrading the unified-history schema, sealed inbound messages are re-sealed into
history after the profile key is available. Legacy ready or accepted outbound
operations have no recoverable plaintext and therefore fail startup explicitly
instead of losing idempotency or attempting MLS self-decryption.

The store checks blob lengths before materialization, rejects unknown schema versions,
uses parameterized SQL, and writes a conversation plus all initial bindings in one
transaction. Profile identity mismatches and duplicate conversations fail closed.

Conversation state and binding columns contain only authenticated ciphertext. Reopen
derives the conversation signing public key from its private key, verifies the device
root signature, opens the exact profile/conversation context, and requires the stored
self binding to equal the signing material's binding.

Relay credential sealing authenticates the normalized endpoint alongside the bearer,
so changing the plaintext endpoint cannot redirect a credential. Conversation-policy
and journal sealing include the opaque routing identifier in associated data, so
offline route substitution fails before any relay operation. Journal records also bind
their profile, conversation, operation scope, identifier, counter or cursor, and
authenticated sender where applicable. Metadata is cross-checked against the opened
record before recovery proceeds.

An unconfigured profile can be provisioned outside MCP by setting both
`KONCLAVE_RELAY_ENDPOINT` and `KONCLAVE_RELAY_CREDENTIAL_FILE` in the daemon
environment. The endpoint must satisfy TLS-or-loopback policy. The credential file is
bounded, read only for first-run provisioning, decoded as one canonical unpadded
base64url bearer, and immediately sealed into the profile. Later starts do not require
the file; if the supplied endpoint differs from the sealed profile endpoint, startup
fails instead of redirecting or replacing the credential.

The application outbox transitions from reserved to ready to accepted. A ready
envelope that expires before observed acceptance retains its sealed envelope and
transitions to an explicit terminal-expired state. It no longer consumes retry
capacity or blocks later ready operations, but its stable message ID remains reserved
and an exact retry returns a permanent expiry error. An authenticated exact relay echo
can still prove that an earlier response-lost submission was accepted and atomically
supersede the local expiry reason. Before new outbound work begins, recovery must turn
any unsealed reservation into an abandoned tombstone without rolling back its sender
counter or making its identifiers reusable.

Publishing a policy that removes the local device atomically terminalizes every
unaccepted ready application row for that conversation with the distinct removed
reason. Stable message and envelope identifiers, sender counters, sealed envelopes,
and pending history remain intact. Exact retry returns a permanent not-member error,
and batch retry rechecks sealed current membership immediately before each network
submission. A later exact authenticated echo may still supersede the local terminal
reason and advance replay without poisoning the route.

The application inbox transitions from received to message-saved to complete, and
completion advances only the next contiguous replay cursor. Exact repeats are
idempotent; conflicting identifiers, counters, cursors, routes, senders, or
sealed-record scopes fail closed. Pending outbox and incomplete inbox work are bounded
at persistence and recovery boundaries. A new inbox cursor must remain within one
bounded replay page above the durable cursor, so far-ahead delivery cannot consume the
slot needed to journal the missing contiguous head.

Outbox acceptance and inbox receipt share the same cursor-observation ledger. Each
entry authenticates the exact envelope, not only its identifier, so a relay that
assigns conflicting envelopes or content to one observed cursor halts processing.
Completed messages also retain the authenticated MLS epoch and sender counter. The
first observed counter establishes a sealed sender-and-epoch high-water record;
completion updates that record and the replay cursor in one transaction. Later
counters must be strictly greater than the authenticated high-water value. Lower or
equal counters fail completion as replays or regressions. Forward counter gaps are
valid because crash-before-ready can permanently consume a local sender generation;
the later counter completes and advances both the high-water value and durable replay
cursor.

Every cursor advance writes a version 2 sealed replay head in the same transaction as
inbox completion. The head binds the previous and current cursor, exact envelope,
completion kind, historical completion policy, and current policy authority. Later
local policy acceptance preserves the historical completion fields and advances only
the current authority after verifying the prior head and an exact one-epoch policy
transition. On reopen, the plaintext replay cursor and sealed profile policy must
match the head and its exact sealed cursor observation. Application heads require the
matching sealed inbox message. Membership heads require their historical completion
policy to equal the sealed transition next state. A joined head is the only cursor
without an inbox row, and its historical completion policy must match the exact
GroupCommit receipt parent epoch. Valid version 1 heads are verified under their
legacy constraints and rewritten as version 2; ambiguous or inconsistent version 1
heads fail closed. Plaintext status or cursor edits therefore cannot skip an unapplied
removal or pre-join history.

Membership commits use separate sealed outbox and inbox journals because their
acceptance advances both MLS state and application policy rather than an application
sender counter. Outbound Commit creation persists MLS pending state before the ready
journal record. Relay acceptance is cursor-bound before the daemon applies the pending
Commit, then the profile publishes the next policy and bindings atomically. Recovery
can finish either side of that boundary and rejects an orphaned pending MLS Commit
when no active journal authorizes it. Local request metadata lets an exact
invitation, removal, or role-change retry return the original accepted operation;
an add-member retry therefore cannot lose its sealed Welcome after a relay response
is interrupted.

Plaintext journal status is not recovery authority. For the current policy epoch, the
daemon inspects the one durable membership operation regardless of its status value.
An exact sealed cursor observation derives relay acceptance and normalizes the row
before MLS application. Without that observation, recovery treats the operation as
unaccepted until MLS state proves its pending Commit was already rejected. Pending
MLS state with no journal fails closed rather than being discarded automatically.

Inbound membership control is always received inside an MLS application
PrivateMessage paired with its digest-bound Commit. The daemon journals the opaque
envelope first, then seals the decrypted control, authenticated sender, next policy,
and verified binding set before persisting the receiver ratchet and next MLS epoch.
If MLS persistence completed before the profile transaction, recovery restores the
journaled next state and advances the replay cursor. A sender's own Commit echo uses
the sealed outbound checkpoint rather than attempting MLS self-decryption.

Joining devices reserve and seal their conversation signing material before
generating a one-time MLS KeyPackage. The resulting JoinProof is attached in a second
transition. Welcome processing validates the encrypted state before checkpointing it,
then persists the joined MLS group and publishes the conversation record. Recovery
can retry from the checkpoint when group persistence did not occur, or finish profile
publication when the group was already persisted. Before creating an add Commit, the daemon reserves its relay `EnvelopeId` and places
that expected identifier in a versioned MLS GroupInfo extension authenticated by the
Welcome. Before accepting the Welcome, the daemon replays the claimed relay cursor and
requires that exact identifier in addition to the route, class, parent epoch, and
authenticated state. The checkpoint seals both the expected identifier and exact
receipt, and reopen rechecks their equality. Legacy Welcomes without the binding are
not joinable by the daemon. That sealed receipt initializes the joined conversation's
replay cursor, so
the new member neither reprocesses its already-consumed add Commit nor attempts to
decrypt pre-membership history.

## Startup sequence

1. Validate the profile identifier and root path.
2. Create the profile directory and acquire `profile.lock`.
3. Load or create the native wrapping key.
4. Load the wrapping key once and create two sealer handles that share that in-memory
   key without duplicating or reloading it.
5. Open `profile.sqlite` and `mls.sqlite` with those handles.
6. Reopen or create the device identity.
7. Convert every unsealed outbound reservation into a permanent counter-gap
   tombstone.
8. Finalize any checkpointed pending join whose MLS group was already persisted.
9. Reconcile accepted outbound and checkpointed inbound membership transitions, and
   reject MLS pending state that has no active journal.
10. Open every stored conversation. A missing MLS group is reconstructed only from an
   authenticated epoch-zero profile record; missing state after any epoch advance
   fails startup.

Any failure stops startup. There is no replacement key, plaintext database, anonymous
relay, or unlocked fallback.

## Profile configuration inputs

Every profile is opened from explicit inputs: a profile root, a validated profile
identifier, a stated wrapping-key custody, an optional relay installation record, an
optional first-run relay provisioning pair, and the local write authorization. Custody
is `Native` or an external wrapping-key file, and an external-custody profile whose
file is unavailable fails closed rather than falling back to native custody.

The shared service resolves native per-profile custody. It never reuses one external
wrapping-key file across profiles: an external-custody profile is bound to its own
source through the explicit per-profile rebind ADR 0008 assigns to distribution, and
until that binding exists the service opens the profile under its own native custody
or fails. There is no shared-key fallback and no silent inheritance of a launch-scoped
key.

Only the compatibility stdio host reads process environment, and only that host binds
its single profile to the external wrapping-key file named by
`KONCLAVE_WRAPPING_KEY_FILE`. It builds that profile's configuration directly,
including its relay installation and first-run provisioning, so a launch-scoped key
can never become a service-wide custody root. Nothing below that boundary reads
process-global state, so one process can open unrelated profiles without any of them
inheriting another profile's custody, relay, or authorization settings.

## Profile runtime and hosts

One initialized profile owns one supervised task set: relay watch supervision and
pairing supervision, plus any attachments its host adds. The compatibility stdio host
adds the MCP stdio server and the outbound adapter channel as attachments over that
same task set, so the shared service and the compatibility host cannot drift apart.

A component ending means the profile is stopping: the compatibility host exits when
its stdio peer disconnects, and a permanent relay or pairing failure must not leave a
half-supervised profile behind. Remaining components are asked to stop and drained
within a bounded deadline, and every component failure is reported rather than only
the first one. A session that launched no adapter is not a finished component; the
profile keeps serving MCP and relay recovery.

The task set is owned rather than detached. Coordinated shutdown drains it and reports
its aggregated outcome; dropping a running host without that shutdown, including while
a panic unwinds, signals and aborts the task set instead of leaving supervised tasks
and an exclusive profile lock behind with no owner.

## Shared-service profile registry

ADR 0008 hosts many logical profiles in one per-user service process. The registry
keyed by validated profile identifier owns that lifecycle:

- **Lazy open.** A profile is opened on its first client and not before.
- **Coalescing.** Concurrent requests for one profile wait on one open, so a profile
  is never locked, recovered, or hosted twice inside the process.
- **Isolation.** Each hosted profile keeps its own lock, `profile.sqlite`,
  `mls.sqlite`, sealer, device identity, relay principal, journals, and tasks.
  Consolidation is process-level only.
- **Bounds.** The number of profiles the registry holds resources for — hosted,
  opening, or closing — is capped and refuses further profiles when reached.
  Concurrent opens are admitted through a bounded permit set, so a burst of first
  connections queues instead of starting every lock, custody load, database open, and
  journal recovery at once. Each profile also bounds its attached clients.
- **Failure isolation.** A failed task set marks that profile failed and is reported
  to its clients and to the supervising loop. Unrelated profiles keep running. A
  failed profile is never silently replaced while a client still holds it; once its
  clients detach it is closed, its lock is released, and a later request reopens it.
- **Retention and eviction.** A profile is retained while any client holds it. It is
  evicted only when no client is attached, no supervised pairing or relay recovery
  operation is running, no adapter claim is outstanding, and the idle window has
  elapsed. Pairing sweeps and received relay pages are admitted through the profile's
  operation gate and stay admitted for their whole duration. Eviction closes that gate
  and publishes the closing slot in one transition under the registry lock, so it
  either wins outright — after which no operation is admitted again — or loses to a
  running operation and the profile is retained. Eviction then stops the task set,
  closes both databases, and releases the lock. It removes no durable state, and
  reopening returns the same device identity.
- **Operation admission.** An operation that is refused because the profile is closing
  fails closed and leaves its durable state untouched: an unprocessed relay page is
  left unacknowledged for exact redelivery, and a refused pairing sweep leaves every
  record for the next open. A refusal is a coordinated stop, not a failure, however it
  surfaces. Admission is taken only by top-level operations, so an admitted operation
  never waits on the gate again from inside itself. Closing a relay watch session on
  one of those coordinated exits is best effort: a transport error there is a
  diagnostic, not a profile failure, while processing failures still propagate.
- **Revocation.** A lease holds no service handle of its own. Closing a profile —
  through shutdown, eviction, or a failed runtime — denies further operations and
  revokes lease access as one transition before anything is awaited, so a client that
  still holds its lease object cannot start work while the close drains.
- **Draining.** A close waits, within a bounded deadline, for operations that were
  already admitted before it dropped the profile's stores. Exceeding that deadline is
  reported as an explicit failure rather than closing underneath a running operation.
- **Configuration.** Zero active-profile, open-admission, or client bounds are
  rejected when the supervisor is built. A zero bound is not a stricter policy: it
  refuses or stalls every request.
- **Shutdown.** Shutdown refuses new attaches, releases waiting opens as a stopping
  service rather than a failed open, waits for in-flight opens so none of them leaks a
  lock, closes every hosted runtime exactly once, waits for any close another caller
  already owns, and aggregates every failure it observed — including a concurrent
  close that failed or was abandoned. Close and eviction counts report only profiles
  that actually released their runtime and lock.
- **Duplicate ownership.** A profile whose lock is held by another owner — a second
  service, or a stuck operation that has not released its handles — is refused with a
  stable locked outcome rather than an opaque open failure, and the refusal discloses
  no path or root.
- **Diagnostics.** Registry events log a bounded profile identifier and a stable
  outcome code. Local paths, endpoints, and error chains stay in returned errors,
  which the failed-open variant retains as an internal cause rather than in its
  message or its `Debug` output.

## Conversation lifecycle

Conversation creation generates the conversation and routing identifiers through the
configured cryptographic provider, creates a distinct conversation signing identity,
and persists the authenticated initial administrator policy plus the sealed
automatic-delivery policy in one transaction before creating the MLS group. A failure
to seal either policy leaves no visible conversation. The profile-first order makes an
interrupted initial group creation recoverable: the next startup recreates only the
missing epoch-zero group with the same sealed signing material and verifies the
resulting state. It never fabricates missing MLS state for an advanced conversation.

Operation-record contexts retain their historical concatenated encoding whenever it
fits the sealed-record identifier bound. A versioned length-prefixed derived context
is used only when that legacy encoding is oversized. Such a context could not have
produced prior ciphertext, so this fallback adds full-length session-profile support
without changing the associated data of any readable record.

Outbound application operations serialize sender-counter reservation, MLS
sender-ratchet persistence, sealed-envelope journaling, relay submission, and exact
cursor acceptance. Eligible ready envelopes are retried before a newer message may
reserve a counter, while locally expired rows transition terminal and are skipped so
they cannot block another conversation. Safe sender-counter gaps remain monotonic and
cannot reuse ciphertext generations. Blocking cryptographic and SQLite work runs
outside Tokio executor threads; the ordered relay submission gate is the only lock
intentionally held across network I/O.

Inbound replay preflights the complete page before any journal or MLS mutation. Every
returned cursor must be exactly one greater than the prior cursor, beginning at the
requested durable cursor, and checked arithmetic rejects overflow. The page's next
cursor must equal the final contiguous cursor. Each
application or membership envelope is journaled before decryption. For application
messages, the authenticated sender and MLS epoch are sealed before receiver-ratchet
persistence. For membership commits, decrypted control and validated next policy are
sealed before receiver-ratchet and epoch persistence. The contiguous cursor advances
before relay acknowledgment. Recovery distinguishes state that still needs
persistence from the exact already-consumed MLS generation or applied epoch;
completed replay does not repeat side effects.

Sent history records the relay-assigned cursor but remains pending and hidden until
the sender replays that exact echo and advances the contiguous replay frontier.
Received history remains pending until the receiver ratchet and contiguous inbox
transition complete. A sender's own relay echo reuses the already sealed outbound
message instead of attempting to decrypt an MLS message from self. Authenticating that
full envelope and assigning its cursor atomically reconciles a still-ready outbox to
accepted, including the response-lost case, so a stable retry returns the original
accepted result and one message appears exactly once in cursor order after reconnect.

## Relay watch supervision

When a relay is configured, the daemon service root discovers durable conversations
in bounded pages and owns one authenticated watch worker for each conversation where
the local device remains a member. The initial MVP bounds one profile to 32
simultaneous watched conversations and fails visibly rather than silently leaving an
additional conversation unsynchronized.

A worker opens from the durable replay cursor and keeps the WebSocket session alive
after the relay's empty initial confirmation page. Every later page passes through
the same contiguous preflight, sealed journal, MLS persistence, remote-event
creation, cursor advancement, and relay acknowledgment path used by explicit replay.
Membership removal of the local device ends that conversation's worker.

Relay acknowledgment records route retention, not local delivery. It is monotonic and
shared by every principal-authorized reader of a route, so a concurrent session, or an
acknowledgment that outlived a crash before the local cursor was committed, can leave
the relay ahead of this profile. A worker therefore re-sends its durable cursor on
every connection and accepts an effective cursor at or ahead of the requested one. A
regressed cursor or a rewritten route still fails as an invalid relay response.

Timeouts, transport unavailability, ordinary watch closure, server failures,
rate-limiting, and heartbeat timeout reconnect with bounded exponential backoff from
one to 30 seconds plus conversation-stable jitter. Authorization, protocol,
cryptographic, persistence-integrity, and invalid-response failures are permanent:
the worker returns them to the service root, which signals coordinated daemon
shutdown instead of hiding a corrupt or unauthorized state.

The manager rescans every 30 seconds, including immediately on startup, so newly
created and joined conversations acquire workers without an agent polling tool.
Workers, retry timers, discovery, and shutdown are all owned. Graceful shutdown waits
up to five seconds and aborts an overdue supervisor rather than detaching it.

Pairing progression is owned separately from conversation watches. The daemon sweeps
sealed active pairings immediately and every second, reconciles exact prepared
outbounds, processes one bounded replay page per operation, enforces both deadlines,
and completes compensating removal before terminal cancellation. Transient transport,
rate-limit, server, and stale-epoch failures retry with bounded backoff and
device-stable jitter. Permanent authorization, protocol, cryptographic, and
persistence-integrity failures stop the daemon. Profiles admit at most 32 active
pairings, so one sweep remains bounded.

## MCP application and pairing tools

The stdio daemon exposes `get_identity`, bounded conversation/message tools, and the
membership tools `create_invitation`, `create_join_proof`, `add_member`,
`accept_welcome`, `remove_member`, and `change_member_role`. Invitation packages carry
only signed invitation data, opaque routing, and root-verified public bindings.
JoinProof and Welcome values are one-time protocol capabilities; conversation signing
keys, KeyPackage private state, provider state, relay credentials, decrypted
membership control, and sealed persistence records never cross the MCP boundary.
Stdio is the local process capability boundary, and every handler also passes an
explicit method allowlist before parsing or side effects. Identifiers and bounded
protocol values use canonical lowercase hex.

The paved pairing surface is `create_pairing_capability`,
`redeem_pairing_capability`, `get_pairing_status`, `authorize_pairing_joiner`,
`authorize_pairing_inviter`, `sync_pairing`, and `cancel_pairing`. Only the
short-lived capability crosses between sessions. Invitation, JoinProof, Welcome,
relay cursor/route, peer bindings, directional keys, and sealed operation state stay
behind the daemon boundary. Capability request and response buffers are not
debug-formatted and are zeroized after use. `sync_pairing` is available for explicit
diagnosis; ordinary progress is automatic and does not depend on an agent polling.

`send_message` requires a caller-stable 16-byte `message_id`. Repeating the same
conversation/message ID resumes or returns the exact durable operation; changing its
content or reply target fails with an idempotency conflict. A new logical message must
use a new ID. If the exact never-accepted envelope expired, the stable ID remains
reserved and its retry returns a permanent expiry error rather than producing new
ciphertext. An already accepted identical operation continues returning its original
cursor after envelope expiry.

`accept_welcome` also requires the cursor returned by `add_member`. The daemon verifies
that cursor against the relay and seals the matching GroupCommit receipt before
publishing the joined profile.

MCP starts read-only. `KONCLAVE_MCP_ALLOW_WRITE=true` (or `1`) must be set in the
long-lived daemon environment to authorize conversation creation, invitation/join,
pairing creation/redemption/authorization/sync/cancellation, membership mutation,
send, sync, and watch operations. Pairing status remains read-authorized. Invalid
values fail startup; the daemon never infers write permission from a model request.

`watch_messages` owns one cancellable WebSocket session and returns after one replay
page. It remains an explicit diagnostic/manual operation, as does `sync_messages`;
normal background synchronization is owned by the daemon service and requires no
agent polling loop.
