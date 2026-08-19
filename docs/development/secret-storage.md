# Sealed secret storage

ADR 0002 separates key custody, authenticated sealing, and persistence:

1. a wrapping-key provider obtains one profile KEK;
2. `SecretSealer` creates context-bound AES-256-GCM blobs;
3. an MLS storage wrapper seals private bytes before delegating to a backend.

## Provider selection

`NativeWrappingKeyProvider` uses the daemon account's operating-system credential
store. The caller must hold the profile's exclusive process lock before loading or
creating the credential.

Headless deployments disable the `native-keyring` feature and construct
`ExternalWrappingKeyProvider` from exactly 32 bytes supplied by an external secret
mechanism. The reader rejects short or trailing data. There is no environment-variable
or plaintext-file fallback.

Provider failure is a startup error. Never respond to an unavailable credential store
by generating a replacement key for an existing profile.

## MLS storage

`SealedMlsStorage<S>` wraps any mls-rs `GroupStateStorage` or `KeyPackageStorage`:

- current group snapshots and prior epochs are sealed as complete opaque values;
- KeyPackage init and leaf private keys are sealed independently;
- public KeyPackage bytes and expiration remain queryable but are included in the
  private-key associated-data digest, so tampering fails authentication;
- group state, epoch inserts, and epoch updates are all sealed before one backend
  `write` call.

`SealedSqliteMlsStorage` is the file-backed adapter. It owns its ciphertext-only
backend and commits one group-state update plus all epoch changes in a single SQLite
transaction. SQLite rows never contain a wrapping key or private MLS byte.

`ConversationSigningMaterial` seals the conversation-scoped signature key together
with its authenticated device-root binding. Its associated data binds the local
profile and conversation identifiers. Reopening verifies the binding signature,
conversation identifier, and signing private/public key relationship before mls-rs
receives the key.

`MlsConversationClient::with_storage` configures the same sealed SQLite adapter as
both the mls-rs KeyPackage repository and group-state storage. The cryptographic
wrapper persists:

- new and joined groups before returning them;
- outbound pending commits before they can cross the relay boundary;
- accepted or rejected pending commits transactionally;
- incoming commits before exposing their application transition;
- sender ratchets before returning ciphertext.

Incoming application decryption is deliberately two-phase across the cryptographic
and application boundaries. The daemon first durably records the decoded message and
its idempotency identifier, then calls `MlsConversation::persist` to checkpoint the
receiver ratchet. A crash between those writes replays against the prior MLS snapshot;
the application deduplication record makes that recovery idempotent instead of losing
plaintext.

A persisted join proof can restore its KeyPackage expectation after restart. A
persisted pending next-state can restore and accept an outbound pending commit. An
orphaned pending commit may be restored without next-state metadata solely to reject
and recreate it. A removed endpoint stores a sealed tombstone snapshot one epoch
behind the authenticated removal state, because MLS correctly withholds the new epoch
secrets from that device; restored operations still fail as removed.

Active and pending restores compare the complete canonical conversation-state digest
against the authenticated MLS GroupContext extension or applied Commit proposal.
Matching only epoch and roster is insufficient because roles, joined epochs, protocol
version, and consumed invitations are also authorization state.

The adapter uses mls-rs's opaque storage values and does not enable its general
`serde` feature. The daemon must still seal its policy snapshot, pending-operation
metadata, relay credential, replay counters, and decrypted history, and must hold the
profile lock before opening native custody.

## Validation surfaces

The default feature set tests native custody plus SQLite. CI also tests:

- `--no-default-features` for the minimal external-provider sealing path;
- `--no-default-features --features sqlite` for headless file-backed storage;
- locked fuzz parsing/opening of untrusted sealed blobs.

Cryptographic integration tests additionally reopen signing material, KeyPackages,
groups, pending joins, pending commits, application ratchets, and removed-device
tombstones across independent SQLite handles.
