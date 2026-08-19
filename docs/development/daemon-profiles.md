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

Schema version 1 stores:

- one profile row with a sealed device root and optional sealed relay credential;
- normalized non-secret relay endpoint;
- conversation and routing identifiers;
- sealed conversation signing material and policy state;
- sealed, root-verified conversation credential bindings;
- sender counter and replay cursor.

The store checks blob lengths before materialization, rejects unknown schema versions,
uses parameterized SQL, and writes a conversation plus all initial bindings in one
transaction. Profile identity mismatches and duplicate conversations fail closed.

Conversation state and binding columns contain only authenticated ciphertext. Reopen
derives the conversation signing public key from its private key, verifies the device
root signature, opens the exact profile/conversation context, and requires the stored
self binding to equal the signing material's binding.

Relay credential sealing authenticates the normalized endpoint alongside the bearer,
so changing the plaintext endpoint cannot redirect a credential. Conversation-policy
sealing includes the opaque routing identifier in associated data, so offline route
substitution fails before any relay operation.

Inbox, outbox, pending-operation, message-history, and contiguous-cursor tables follow
the status transitions in ADR 0004. They must be present before MCP send/read/watch
tools are enabled in the runtime.

## Startup sequence

1. Validate the profile identifier and root path.
2. Create the profile directory and acquire `profile.lock`.
3. Load or create the native wrapping key.
4. Open `profile.sqlite` with one sealer.
5. Open `mls.sqlite` with another sealer loaded from the same custody slot.
6. Reopen or create the device identity.
7. Reconcile journals before starting relay watches or accepting MCP operations.

Any failure stops startup. There is no replacement key, plaintext database, anonymous
relay, or unlocked fallback.
