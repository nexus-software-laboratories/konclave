# Collaboration policy contracts

ADR 0011 separates editable policy sources, immutable shared bundles, and local
conversation bindings. This page owns the evolving implementation contract; it does
not make a hosted registry or one authoring syntax part of the core protocol.

## Implemented core bundle

The source-independent `CollaborationPolicyBundle` is a bounded protocol-v1 contract.
It contains:

- protocol version and canonical human-readable name;
- optional model guidance;
- canonically ordered statements;
- canonically ordered required harness claims; and
- fully resolved optional duration, turn, token, and concurrency limits.

Each statement has a canonical identifier, one primitive effect, one namespaced
action, and an optional namespaced resource. Effects are `allow`, `deny`, and
`require-local-approval`. Action, resource, and harness-claim identifiers are
extensible canonical strings rather than product-defined collaboration modes.

The bundle uses a 64 KiB encoded limit, at most 256 statements, and at most 64
required harness claims. Names, identifiers, guidance, repeated fields, numeric
limits, unknown effects, and top-level Protobuf fields are validated before the
bundle reaches evaluation or persistence.

Canonical construction sorts statements by statement identifier and harness claims
lexically. Duplicate identifiers are invalid. Wire decoding re-encodes the validated
domain value and rejects bytes that differ, so alternate field or collection ordering
cannot create multiple accepted encodings of the same bundle.

The content identifier is:

```text
SHA-256(
  "konclave-collaboration-policy-bundle-digest-v1\0" ||
  canonical CollaborationPolicyBundle bytes
)
```

Names and source locations are not identity. Rust and TypeScript share one immutable
binary fixture and expected digest.

## Optional limits

Canonical bundle limits are already materialized:

- an absent duration, turn, token, or concurrency field means explicitly unlimited;
- a present value must be positive; and
- mandatory parser, frame, queue, journal, and storage bounds are outside the policy
  and cannot be disabled.

An omitted source limit represents inheritance. The current compiler accepts one
fully materialized caller-default set and resolves source values against it before
producing canonical bytes. Future activation and provider layers own the precedence
between activation overrides, user defaults, provider defaults, and shipped defaults.

## Source and catalog boundary

The implemented source compiler accepts bounded strict JSON with API version
`konclave.dev/v1` and kind `CollaborationPolicy`. Unknown fields, unsupported effects,
oversized arrays, malformed canonical identifiers, zero finite limits, and trailing
content fail closed. Editable sources may order statements and harness claims
arbitrarily; compilation canonicalizes them before encoding and digesting.

Missing source limits inherit from caller-provided defaults. Explicit JSON `null`
means unlimited, and a positive integer is a finite override. No inherited or
unresolved value crosses into the canonical bundle.

The explicit file catalog is one bounded JSON descriptor containing a schema version
and listed name-to-source mappings. It never scans its directory. Sources must be
regular `.json` files that physically resolve beneath the descriptor's directory;
duplicate names, duplicate paths, traversal, absent files, and source-name mismatch
fail closed.

Future source providers compile into the same bundle:

- explicit user catalog;
- explicitly selected repository proposal;
- bundle received through a conversation;
- configured self-hosted provider; or
- configured hosted provider.

Provider names and mutable URLs are not persisted as policy authority. Activation
pins canonical bytes and their digest.

The command-line surface operates only on explicit paths:

```text
konclave policy create --name <policy-name> --output <new-source.json>
konclave policy validate --source <source.json>
konclave policy inspect --source <source.json>
konclave policy compile --source <source.json> --output <new-bundle.bin>
konclave policy diff --left <source.json> --right <source.json>
konclave policy list --catalog <catalog.json>
konclave policy validate-catalog --catalog <catalog.json>
```

Create and compile use exclusive file creation and never overwrite existing content.
Inspect and validation output only bounded names, digests, counts, and resolved limits;
model guidance and complete policy bodies are not printed. The repository includes
schemas and editable examples, but repository presence never activates them.

## Binding and exchange boundary

Profile schema version 15 stores bounded canonical bundles as profile-global sealed
records keyed by their public content digest. Repeating identical bytes is
idempotent; a same-digest ciphertext conflict, malformed canonical bundle, or content
identity mismatch fails closed. Bundle count is bounded without evicting an existing
record.

One sealed binding may select a stored digest for each existing local conversation.
The binding authenticates the profile, conversation, digest, and activation timestamp.
It survives restart, replacement is atomic, and deletion immediately removes local
authority. Schema migration creates no bundle or binding, and no client or agent
activation operation is exposed in this persistence-only slice.

Profile schema version 16 adds a bounded append-only exchange index. A completed
proposal, response, or revocation is indexed in the same transaction that completes
its sealed history record, advances the replay cursor, and publishes its delivery
event. The index stores only allowlisted identifiers, digest, kind, outcome, and
cursor metadata; canonical bundle bytes and guidance remain in sealed history.

Every indexed row has a foreign key to that exact conversation and message. Startup
reopens the sealed message and requires its authenticated content to reproduce the
indexed metadata, including canonical proposal verification. Each row also seals its
conversation, message, cursor, kind, proposal identifier, digest, and outcome. A
separate profile-bound sealed state commits the exact row count and one-time backfill
completion, so coordinated clear-metadata edits, row deletion/addition, and a forged
completion marker fail closed. Cursor verification also reuses the sealed inbox
envelope or outbound cursor observation rather than trusting history-table cursor
metadata. The index is bounded to 4,096 profile records and 1,024 records per
conversation without eviction. Capacity failure leaves cursor completion visibly
blocked rather than dropping an authenticated exchange record.

Exchange records are evidence of what authenticated members sent, not policy
authority. Indexing a proposal, accepted response, or revocation never calls the
bundle store or binding operations. Schema migration performs one bounded,
restart-safe pass over completed sealed history so policy messages accepted by an
earlier reader are not lost from the index; it creates no binding. Local
decision/status operations are implemented as a separate service layer over this
journal.

## Explicit local exchange operations

The local service exposes four write operations:

- `propose_collaboration_policy` accepts one caller-stable proposal identifier, one
  complete canonical bundle, and optional replacement digest;
- `accept_collaboration_policy` targets an exact received proposal identifier and
  digest, activates it locally, and reports acceptance;
- `reject_collaboration_policy` targets the same exact identity, reports rejection,
  and never changes local authority; and
- `revoke_collaboration_policy` targets one digest, removes matching local authority,
  and announces the revocation.

Proposing is an explicit local activation decision, not authority derived from peer
content. Before any exchange message is submitted, schema version 17 atomically
commits one terminal local-operation record with its binding activation, replacement,
rejection, or revocation. The record stores the historical `binding_changed` result.
Response records also preserve the exact source proposal message identifier needed
to reconstruct their reply after a crash, independently of later conflicting peer
assertions. The sealed zero-count state is created in the same migration transaction
as the schema-17 tables and version update. That transaction also advances the
authenticated schema floor inside an existing sealed device identity; a plaintext
schema downgrade cannot recreate an erased journal. A missing or null state on a
version-17 profile is corruption, not a bootstrap signal.
If submission is interrupted before or after outbox preparation, retry returns that
record without reapplying authority and resumes the same stable message.

This ordering is conservative: proposal and acceptance authority is local before its
notification, and revocation removes local authority before attempting delivery. A
generic ready-outbox retry can submit only a policy message whose local operation was
already committed. Retrying an older proposal or acceptance after a later revocation
cannot resurrect the binding.

Replacement is exact and fail-closed. A new proposal without `replaces_policy_digest`
can activate only when no policy is active. A replacement must name the currently
active digest. Retrying an operation whose proposed digest is already active is
idempotent and does not rewrite its activation timestamp only when the exact terminal
operation already exists. A new operation targeting the active digest must still
carry replacement intent naming that digest.

Konclave derives application message identifiers with separate proposal and response
SHA-256 domains over fixed-width conversation, local device, and proposal inputs,
retaining the first 16 bytes. Acceptance and rejection for one proposal deliberately
share a message identifier, so contradictory terminal responses conflict in the
local-operation journal before either can become a second valid statement. The caller
supplies the stable proposal identifier.

The terminal operation also reserves its application message identifier. A
pre-existing history or outbox record prevents the authority mutation, inbound
content cannot claim an identifier after it is reserved, and outbound preparation
must reproduce the sealed operation's exact policy content and reply target.
When the relay returns that local operation as an own echo, only the already-recorded
outbound envelope may attach its durable cursor; a different envelope or message
remains a conflicting attempt to claim the reserved identifier.

The paved Copilot command surface exposes these operations under `/konclave policy`.
It can compile and propose one explicitly selected strict-JSON source, replace an
active digest, accept or reject an exact received proposal, revoke a digest, and show
bounded active metadata. Source paths are confined to the current workspace and file
content is bounded before the authenticated local request. Generated operation
identifiers are printed before submission. Proposal recovery uses only the stable
proposal identifier and reconstructs the exact canonical bundle from the sealed
terminal operation plus content-addressed bundle store; it never rereads a mutable
source path. Editing a source requires a new proposal identifier. Status represents
`u64` activation and limit values as canonical decimal strings across the Rust and
JavaScript boundary.

An authenticated peer proposal can be inspected before acceptance. The paved command
shows its complete identity, proposer, replacement intent, statements, required
claims, limits, and guidance. Peer-proposed guidance is explicitly labeled untrusted
and emitted ephemerally; only the later explicit accept operation can make that exact
digest the local policy binding.

Policy proposal notifications include complete identifiers and a local inspect command
inside the existing untrusted-content fence. Receiving that notification still
cannot activate authority; the operator must invoke the deterministic accept command.

Revocation accepts a caller-stable 16-byte message identifier. A retry reuses it and
returns the historical revocation result; reactivating and later revoking the same
digest uses a new identifier so peers receive the later revocation as a distinct
event.

Accept and reject resolve the proposal through the sealed exchange journal. A
conflicted proposal identifier, wrong expected digest, locally authored proposal, or
replacement mismatch fails before the operation reports success. Remote response and
revocation messages remain authenticated information; receiving either never mutates
the local binding.

Protocol-v1 application content now carries three typed exchange messages:

- a proposal identifier, claimed policy digest, complete canonical bundle, and
  optional digest that the proposal is intended to replace;
- an accepted or rejected response bound to the exact proposal identifier and policy
  digest; and
- a revocation notice bound to the policy digest being withdrawn.

Proposal identifiers are 16 bytes and policy digests are 32 bytes. The embedded
bundle is required and retains the core 64 KiB bound. Unknown response outcomes,
malformed identifiers, malformed digests, empty or oversized bundles, and missing
required fields fail closed in Rust and TypeScript.

Proposal verification decodes the embedded bundle through the canonical bundle
contract, derives its domain-separated digest, and requires an exact match with the
claimed digest. This prevents a sender from substituting alternate policy bytes under
an agreed identity. The optional replacement digest is authenticated application
content, but it does not itself mutate a binding.

Receiving a proposal, accepted response, or revocation never activates, replaces, or
deletes local authority at this layer. These messages establish an authenticated
exchange vocabulary only. The explicit service state machine resolves proposals from
the sealed exchange journal and mutates a binding only after a locally authorized
operation. An accepted response authenticates which member reported acceptance of
which proposal and digest; it is not independent proof of that endpoint's effective
harness controls.

Participants acknowledge the same base digest independently. Each endpoint then
intersects that bundle with local user authority, harness-proven controls, and local
restrictions. The public effective projection may be stricter on either endpoint,
while the accepted base definition remains byte-identical.

## Deterministic effective-policy evaluation

The domain evaluator accepts only validated inputs:

- one locally accepted canonical bundle;
- one exact namespaced action and optional exact resource;
- bounded exact-target local-authority and harness-control allowlists;
- bounded canonical harness claims proven by the local integration;
- bounded exact-target local denials and local approval requirements;
- an authenticated usage snapshot; and
- the prospective turn, token, and concurrent-request cost.

Target matching is exact. An absent resource matches only an unscoped action and is
never a wildcard. Unknown actions, unknown resources, and missing base statements
deny. When multiple base statements match, `deny` takes precedence over
`require-local-approval`, which takes precedence over `allow`. A local denial takes
precedence over every positive result. Local authority and harness controls are
positive intersections; neither local restrictions nor a supplied approval can
broaden the accepted bundle.

Every bundle-level required harness claim must appear in the locally proven claim set,
and the harness must separately prove control of the requested exact target. Missing
evidence denies rather than becoming advisory. Model guidance, policy names, peer
responses, and peer instructions are not evaluator inputs.

Finite duration expires when elapsed time reaches the limit. Turn, token, and
concurrency decisions compare existing usage plus the requested reservation against
the finite limit with checked arithmetic. Arithmetic overflow denies. Absent limits
remain explicitly unlimited and do not perform artificial overflow checks.

The evaluator is pure and returns `allow`, `require-local-approval`, or `deny` with a
stable bounded reason. A fresh local approval can satisfy only an approval
requirement; it cannot override a denial, missing authority, missing harness evidence,
or an exhausted limit. The enforcing service must atomically reserve accepted usage
before executing a side effect; the pure evaluator does not claim mutable accounting
or harness enforcement by itself.

Rust-generated immutable fixtures cover every exchange content kind, and both Rust
and TypeScript readers decode and re-encode those application messages byte for byte.
The local daemon verifies proposed bundle identity before outbound encryption or
inbound persistence. The shared local-service delivery surface exposes only typed
proposal identifiers, digests, replacement intent, outcomes, and revocations; it does
not expose the canonical bundle or model guidance through automatic delivery.
Copilot renders that metadata inside the existing untrusted collaborator fence and
explicitly states that proposal receipt activated no local authority.

The closed binary adapter protocol v1 is not extended with new event discriminants.
For compatibility, its text-only application event projects policy exchanges into a
bounded daemon-authored notice that claims no activation and contains no peer bundle
content. This lets an older adapter acknowledge the event instead of repeatedly
rejecting an unknown event kind and blocking its delivery queue.

Manual message-history results use a `content_type` discriminator. Text retains its
existing `text` field, while policy entries expose only the proposal identifier,
digests, replacement intent, response outcome, or revocation digest. The Copilot
history command validates and renders each variant instead of rejecting a page that
contains non-text application content.

## Harness boundary

Model guidance is never treated as proof of enforcement. Paved harness adapters
register the namespaced actions, resources, and evidence they can enforce. Unknown or
unsupported required claims deny or reduce the effective policy. Generic integrations
cannot claim paved tool, permission, resource, or lifecycle controls.

The packaged generic client may inspect and administer exact policy proposals,
bindings, and revocations through the normal closed tool operations. Its operation
allowlist excludes the paved `collaboration.turn.authorize` and
`collaboration.action.evaluate` service methods. A generic harness therefore gains no
autonomous execution authority from an active binding and must keep peer guidance
advisory unless it independently implements and proves an enforcement boundary.

Peer content remains quoted inside the untrusted collaborator boundary. A locally
active binding supplies the separate trusted instruction to evaluate that content and
act only within the effective policy.

The paved Copilot integration evaluates `conversation.reply` before converting an
idle delivery into an autonomous collaboration turn. The shared service derives
local authority from positive targets in the locally activated bundle, supplies only
the claims and exact controls the Copilot adapter proves, and evaluates duration plus
one active collaboration request. The profile's single live delivery consumer and
the extension's one-outstanding-turn gate enforce concurrency conservatively at one.
Interactive and delivery connections retain fresh handshake instance identifiers;
the daemon correlates their consumer authority only when both prove the same
authenticated session public key.

During that turn, Copilot's pre-tool hook maps only Konclave's `send_message` tool to
`conversation.reply`. A successful evaluation issues a one-use authorization bound to
the exact conversation and message arguments, active policy digest, delivery consumer,
and the earliest policy, lease, or proof expiry. The daemon consumes it into the same
SQLite reservation that verifies the digest, live consumer lease, and expiry before
allocating a sender counter or preparing the send.
Workspace, shell, web, MCP, and subagent tools deny because their effects occur
outside that atomic boundary. Approval-required actions also deny until the harness
can compose policy approval with, rather than replace, native permissions.

The extension prepares a pending gate before enqueue and activates it only after the
session observes the exact synthetic prompt carrying a fresh local turn token. Any
other user prompt clears the pending state, preventing collaboration policy from
leaking across an enqueue race into foreground user work. A later token-bearing
collaboration prompt without its matching pending authorization enters a deny-all
tool state until idle instead of running outside the gate.

Locally accepted policy guidance is placed outside the peer-content fence as trusted
configuration, while collaborator text remains quoted as untrusted task input.
Finite turn and token limits currently deny autonomous execution because the adapter
does not yet prove durable accounting for them. This is a truthful reduction, not an
implicit unlimited fallback.
