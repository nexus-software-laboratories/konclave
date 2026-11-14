---
title: Protect Windows profile keys with user-scoped DPAPI files
status: Accepted
date: 2026-11-14
authors:
  - Konclave maintainers
tags:
  - architecture
  - security
  - persistence
supersedes:
  - adr-0002-sealed-local-secret-custody
superseded_by: []
---

# Protect Windows profile keys with user-scoped DPAPI files

## Context and scope

Konclave gives each harness session a distinct durable profile. Native custody
previously put each profile's random wrapping key in Windows Credential Manager.
The service opens profiles on attachment and retains their identities after
disconnect. Credential entries therefore grew with lifetime session count rather
than active sessions, consuming a shared operating-system resource used by other
applications. Limiting concurrent profiles does not bound this accumulation.

This decision replaces Windows profile-key custody, not profile isolation or
durability. It supersedes the Windows provider choice in ADR 0002. Its independent
256-bit profile keys, sealed blob v1, explicit external provider, no-fallback rule,
MLS persistence, rotation and bounded rollback guarantees remain unchanged.
macOS/Linux native keyrings and installation-scoped service/enrollment credentials
are outside this change.

## Verified facts and assumptions

- The extension derives distinct profile identifiers from distinct harness
  sessions. The shared service attaches profiles before messaging is used; idle
  eviction preserves their databases and keys.
- A native keyring entry is a separate operating-system credential for each
  profile. A Windows DPAPI-protected file does not create a Credential Manager
  entry for each protected value.
- User-scoped DPAPI binds opening to the Windows account and protection context.
  It is not protection against that account's compromise and does not establish
  rollback resistance.
- Existing owner-restricted file helpers verify ownership, DACLs and ordinary
  file shape. File permissions supplement DPAPI; they do not replace it.
- The trusted endpoint retains an exclusive profile lock before key or database
  access. This ownership assumption remains necessary.

## Decision drivers

- Profile creation must not exhaust shared Windows credential slots.
- Keep independent random profile KEKs and durable identities; do not merge
  sessions or introduce a shared application master key.
- Use an operating-system protection mechanism, never plaintext keys or a
  fallback triggered by credential-store failure.
- Keep the change small and local: no network KMS, background pruning, automatic
  migration, retention heuristics or new database format.

## Decision

Windows native profile custody uses one owner-restricted file,
`custody/wrapping-key-1.dpapi`, under the locked profile directory. Its `KDP1`
envelope contains bounded user-scoped DPAPI ciphertext. The protected plaintext
contains a `KWP1` version marker and one independently random 32-byte KEK. DPAPI's
protection context includes the canonical profile identifier and key slot.
Machine-scope protection and interactive prompts are prohibited.

Creation is allowed only before dependent profile state exists. Write-once
creation, durable flush, readback, authenticated opening and exact key comparison
precede database creation. Existing, malformed, inaccessible, context-mismatched
or incomplete key files are never overwritten or replaced. An interrupted file
creation can leave an unusable file; startup fails rather than guessing whether
it is safe to regenerate.

An existing Windows profile without its DPAPI key fails before opening or
migrating its databases. There is no automatic conversion from Credential Manager
and no silent return to the old keyring provider. Operators retaining legacy
profiles must retain their matching supported runtime; discarding an identity
requires explicit retirement, not inference from empty tables or age.

External custody remains explicitly supplied and unchanged. Non-Windows native
custody still uses the native keyring. Service signing and relay enrollment keys
remain installation-scoped native credentials rather than session-scoped files.

## Serious alternatives

### Keep Credential Manager and prune profiles

Smaller custody changes, but safe pruning needs explicit identity retirement,
cross-root ownership and complete durable-state checks. It still consumes a
credential for every retained profile and cannot protect other applications from
an unbounded number of legitimate profiles.

### Allocate profiles lazily or impose a quota

Reduces unused allocations or stops further growth, but each used profile still
consumes a shared credential slot. A quota refuses otherwise valid sessions and
does not remove accumulated entries. These do not solve the storage coupling.

### One installation wrapping key

Uses fewer slots but couples every profile's compromise and retirement. Adding
derived profile keys or a key registry is unnecessary when Windows already
provides independently protected values.

### Plaintext key files

Rejected. A ciphertext backup containing the raw key is effectively plaintext.
Owner-only ACLs are defense in depth, not independent key protection.

## Consequences

- Windows profile count no longer determines Credential Manager entry count.
- Profiles still occupy application-owned disk space and preserve identities.
  This is not automatic profile-data retention or deletion.
- A profile backup includes a DPAPI-protected key, not a portable raw key.
  Recovery depends on the Windows user's DPAPI material; moving ciphertext alone
  to another account is insufficient.
- Loss of the protected key remains unrecoverable. Old formats are refused, not
  migrated or decrypted with newly generated keys.
- The small Windows FFI boundary requires real Windows tests. Same-account
  attackers and valid-ciphertext rollback remain outside the protection claim.

## Confirmation

Focused hosted Windows tests must execute real DPAPI protection/opening, reject
wrong contexts and damaged data, enforce input/output bounds, preserve readback
identity, prove independent keys across roots, and create/reopen many profiles
without increasing profile Credential Manager entries. Missing keys with
dependent state and malformed existing files must fail without replacement.
Daemon integration must reopen both sealed stores with the original identity and
refuse legacy/missing custody before database side effects.

## References

- [ADR 0002](adr-0002-sealed-local-secret-custody.md) defines the unchanged
  independent KEKs, sealed blob v1 and explicit external custody contracts.
- [Extension runtime](../../extensions/Konclave.HostExtension/src/runtime.ts)
  owns session-derived profile identifiers; [profile supervision](../../apps/Konclave.LocalDaemon/src/profile_supervisor.rs)
  preserves durable state when releasing runtime resources.
- [DPAPI CryptProtectData](https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
  documents user scope, optional entropy and the prohibition on interactive UI.
- [Windows security boundary](../../crates/Konclave.WindowsSecurity/src/data_protection.rs)
  owns bounded DPAPI calls and zeroing/freeing their output.
- [Windows key provider](../../crates/Konclave.SecretStorage/src/windows_key.rs)
  owns versioned profile context, write-once protected files and authenticated
  readback; [owner-file boundary](../../crates/Konclave.SecretStorage/src/owner_file.rs)
  supplies verified owner-restricted storage.
