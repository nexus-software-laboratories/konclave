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

The adapter uses mls-rs's opaque storage values and does not enable its general `serde`
feature. The local daemon has not yet enabled durable MLS profiles by default; profile
locking, startup provider selection, and lifecycle wiring remain required before that
switch is turned on.

## Validation surfaces

The default feature set tests native custody plus SQLite. CI also tests:

- `--no-default-features` for the minimal external-provider sealing path;
- `--no-default-features --features sqlite` for headless file-backed storage;
- locked fuzz parsing/opening of untrusted sealed blobs.
