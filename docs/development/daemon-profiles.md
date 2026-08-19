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
at persistence and recovery boundaries.

Outbox acceptance and inbox receipt share the same cursor-observation ledger. Each
entry authenticates the exact envelope, not only its identifier, so a relay that
assigns conflicting envelopes or content to one observed cursor halts processing.
Completed messages also retain the authenticated MLS epoch and sender counter. The
first observed counter establishes that sender-and-epoch baseline; later counters must
advance by exactly one. Regressions and forward gaps remain incomplete and therefore
cannot advance the durable replay cursor.

## Startup sequence

1. Validate the profile identifier and root path.
2. Create the profile directory and acquire `profile.lock`.
3. Load or create the native wrapping key.
4. Load the wrapping key once and create two sealer handles that share that in-memory
   key without duplicating or reloading it.
5. Open `profile.sqlite` and `mls.sqlite` with those handles.
6. Reopen or create the device identity.
7. Reconcile journals before starting relay watches or accepting MCP operations.

Any failure stops startup. There is no replacement key, plaintext database, anonymous
relay, or unlocked fallback.
