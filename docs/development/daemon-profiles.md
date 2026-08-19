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

`profile.lock` is acquired exclusively and without waiting. The daemon holds it until
shutdown. Native wrapping-key load-or-create occurs only while that lock is held.

`profile.sqlite` belongs to the daemon store. `mls.sqlite` belongs to
`SealedSqliteMlsStorage`; their schema versions and migrations are independent.

## Profile store

Schema version 2 stores:

- one profile row with a sealed device root and optional sealed relay credential;
- normalized non-secret relay endpoint;
- conversation and routing identifiers;
- sealed conversation signing material and policy state;
- sealed, root-verified conversation credential bindings;
- sender counter and replay cursor;
- outbound application reservations, sealed envelopes, and relay acceptance state;
- one sealed envelope observation for every accepted route cursor;
- received application envelopes, sealed decoded messages, and completion state.

Version 1 profiles migrate transactionally. A failed migration leaves the version 1
schema intact.

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

The application outbox transitions from reserved to ready to accepted. Before new
outbound work begins, recovery must turn any unsealed reservation into an abandoned
tombstone without rolling back its sender counter or making its identifiers reusable.
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
counters must advance by exactly one. Regressions and forward gaps remain incomplete
and therefore cannot advance the durable replay cursor.

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
8. Open every stored conversation. A missing MLS group is reconstructed only from an
   authenticated epoch-zero profile record; missing state after any epoch advance
   fails startup.

Any failure stops startup. There is no replacement key, plaintext database, anonymous
relay, or unlocked fallback.

## Conversation lifecycle

Conversation creation generates the conversation and routing identifiers through the
configured cryptographic provider, creates a distinct conversation signing identity,
and persists the authenticated initial administrator policy before creating the MLS
group. The profile-first order makes an interrupted initial group creation
recoverable: the next startup recreates only the missing epoch-zero group with the
same sealed signing material and verifies the resulting state. It never fabricates
missing MLS state for an advanced conversation.

Outbound application operations serialize sender-counter reservation, MLS
sender-ratchet persistence, sealed-envelope journaling, relay submission, and exact
cursor acceptance. Ready envelopes are retried before a newer message may reserve a
counter, so concurrent callers cannot reorder one sender's relay sequence. Blocking
cryptographic and SQLite work runs outside Tokio executor threads; the ordered relay
submission gate is the only lock intentionally held across network I/O.
