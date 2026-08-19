---
title: Seal local secrets with explicit platform or operator key custody
status: Accepted
date: 2026-08-19
authors:
  - Konclave maintainers
tags:
  - architecture
  - cryptography
  - persistence
  - security
supersedes: []
superseded_by: []
---

# Seal local secrets with explicit platform or operator key custody

## Context and scope

Konclave's local daemon owns device-root keys, MLS KeyPackage secrets, current group
state, prior-epoch secrets, and resumption material. Losing those values can make a
conversation unrecoverable. Disclosing them defeats endpoint confidentiality,
forward secrecy, removal, and post-compromise recovery.

ADR 0001 requires sealed secret blobs and prohibits plaintext fallback, but deliberately
left platform custody unspecified. This decision defines how a local profile obtains
a wrapping key and how secret bytes are sealed before a persistence adapter can write
them. Database schema and MLS storage transactions remain separate implementation
concerns.

## Verified facts

- Windows Credential Manager, macOS Keychain, and Linux Secret Service provide
  user- or service-account-scoped credential storage. Availability and unlock behavior
  depend on the account/session running the daemon.
- Secret Service is commonly unavailable in headless Linux and container environments.
  Starting a desktop keyring with a known password would only relocate the plaintext
  secret and is not an acceptable automatic fallback.
- The Rust `keyring` 4.1.6 facade supports binary secrets through native Windows,
  Apple, and Secret Service stores, requires Rust 1.88, and is licensed under
  Apache-2.0 OR MIT.
- Linux kernel keyrings are useful for process/session custody but do not by themselves
  provide the reboot-persistent root needed to reopen durable MLS state.
- AWS-LC exposes AES-256-GCM and operating-system randomness. A 32-byte key and unique
  12-byte nonce fit the native credential-store limits while large MLS blobs remain in
  ordinary storage as ciphertext.
- Authenticated encryption detects modification but does not independently detect
  rollback to an older valid ciphertext. MLS epoch and application-state checks still
  reject many stale states; stronger rollback resistance needs a monotonic trusted
  counter or transparency mechanism.

## Assumptions

- The operating system account and daemon process are trusted while running.
- Platform credential stores protect data according to their documented account and
  unlock policies; Konclave cannot improve a compromised operating-system account.
- A headless operator can provide a 32-byte random wrapping key through an external
  secret mechanism such as a Docker/Kubernetes secret mount or inherited descriptor.
- One daemon instance owns a local profile at a time. Profile locking is required
  before concurrent key creation and database writes are enabled.

## Decision drivers

- No plaintext device or MLS secret in SQLite, config files, logs, telemetry, or
  adapter contracts.
- Effortless native custody for ordinary desktop and service-account users.
- An explicit, automatable path for self-hosted headless deployments.
- No network dependency, inbound connectivity, hosted KMS requirement, or silent
  degradation.
- Versioned, storage-agnostic ciphertext that supports future key rotation.
- Small auditable cryptographic surface using the already selected AWS-LC provider.

## Decision

### Wrapping-key providers

The secret-storage boundary consumes exactly one 256-bit key-encryption key (KEK) per
local profile and key slot.

1. **Native provider.** The daemon stores only the random KEK in the operating system's
   native credential store through the exact-pinned Rust keyring facade. The account
   name includes a bounded profile identifier and key slot. Missing credentials are
   generated with operating-system randomness, written once, read back, and validated
   before use.
2. **External provider.** Headless operators supply exactly 32 raw bytes from an
   explicit external secret source. The core provider accepts owned bytes or a bounded
   reader; daemon configuration may wire a mounted secret or inherited descriptor.
   Environment-variable keys are not supported because process environments are
   routinely exposed through diagnostics, child processes, and orchestration metadata.

Provider selection is explicit. Native failure never falls back to a file, environment
variable, hard-coded key, deterministic key, or newly generated replacement. A profile
whose configured KEK is unavailable fails closed before opening secret records.

### Sealed blob v1

Each secret record is encrypted independently with AES-256-GCM:

- a fresh 96-bit nonce from AWS-LC operating-system randomness;
- the profile KEK for key slot `1`;
- plaintext bounded to 16 MiB;
- associated data containing the blob header, record kind, and bounded stable record
  identifier.

The binary header is:

```text
magic "KSC1" [4]
format_version [1] = 1
algorithm [1] = 1 (AES-256-GCM)
key_slot_u32_be [4] = 1
nonce [12]
ciphertext_and_tag [...]
```

Associated data is:

```text
"konclave-sealed-secret-aad-v1\0" ||
header_without_ciphertext ||
record_kind_u8 ||
record_id_length_u16_be ||
record_id
```

Record kinds are a closed enum. Record identifiers are from 1 through 128 bytes.
Opening rejects unknown versions, algorithms, key slots, invalid lengths, tag failure,
or context mismatch without returning partial plaintext. Plaintext and KEKs use
zeroizing containers and are not `Clone`, `Debug`, or generally serializable.

### Persistence boundary

Storage adapters receive only `SealedBlob` plus non-secret lookup metadata. Device
roots, MLS group snapshots, prior epochs, and KeyPackage private data are sealed before
crossing into SQLite. Multi-record MLS updates must be committed atomically. Deletion
removes the database ciphertext and asks the configured credential/storage mechanism
to delete obsolete key material where applicable.

The initial implementation does not enable durable MLS state merely because sealing
exists. The mls-rs storage adapter and profile database schema must separately prove
atomic writes, recovery, and deletion behavior.

### Rotation and rollback

The key-slot field reserves explicit rotation. Rotation writes every record under a new
slot in one recoverable migration before retiring the old KEK. No component guesses a
key slot or silently regenerates a missing key.

The first format authenticates contents and context but does not claim general rollback
prevention. Persisted MLS epoch and application state remain monotonic at the database
transaction boundary; future hardware counters or transparency can strengthen this.

## Serious alternatives

### Direct platform APIs

Rejected initially. Direct DPAPI/Credential Manager, Keychain, and Secret Service
integrations would reduce one dependency but triple security-sensitive code and
platform testing. The keyring facade preserves explicit backend failures and stores
only a small random KEK. A direct adapter remains possible behind the same provider
boundary.

### Passphrase-derived keys

Deferred. A passphrase path requires memory-hard KDF parameters, user interaction,
recovery UX, lockout behavior, and careful unattended-operation semantics. A weak or
automatically supplied passphrase is worse than explicit external custody.

### SQLCipher alone

Rejected as the custody boundary. SQLCipher still needs a securely held database key
and broadens plaintext exposure to every database page while open. Record-level
envelopes keep secret handling explicit and work with alternate stores.

### Persist the KEK beside ciphertext

Rejected. File permissions are defense in depth, not independent custody. A database
or config backup containing both key and ciphertext is effectively plaintext.

### Hosted KMS as the only option

Rejected. It would violate local/offline and self-hosted requirements. A future KMS
provider can implement the external custody interface without changing the blob
format.

## Consequences

- Desktop setup is normally automatic under the daemon's operating-system account.
- Headless setup requires one explicit external secret and fails clearly when absent.
- Moving a profile requires moving both ciphertext and its independently protected KEK.
- Account/keychain availability becomes a startup dependency for durable profiles.
- Ciphertext backups do not disclose secrets, but loss of the KEK is unrecoverable.
- Rollback resistance is bounded by persisted MLS/application monotonic checks.
- Keyring and AWS-LC dependency updates require security and supply-chain review.

## Confirmation

Implementation and CI must prove:

- independent nonces and ciphertext for repeated plaintext;
- wrong key, record kind, identifier, header, nonce, ciphertext, and tag fail closed;
- plaintext and KEKs are absent from `Debug`, logs, panic text, snapshots, and database
  fixtures;
- native provider errors never trigger fallback or replacement-key generation;
- external readers reject short and trailing key data;
- sealed blob fixtures and known-answer vectors remain stable;
- MLS storage writes only sealed values and applies multi-record updates atomically
  before durable state is enabled.

## References

- [Windows Credential Manager](https://learn.microsoft.com/windows/win32/secauthn/credentials-management)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/)
- [Rust keyring ecosystem](https://github.com/open-source-cooperative/keyring-rs)
- [AWS-LC Rust AEAD](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/aead/)
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
