# Security boundary and implementer reference

Use this page when implementing a custody provider, durable backend, domain adapter,
or parser/transport integration. The [threat model](../security/threat-model.md),
[secret-storage guide](../development/secret-storage.md), and
[protocol compatibility](../protocol/compatibility.md) own the detailed security
claims. This reference does not upgrade fixture guarantees into production claims.

## Select the responsibility

| Implementer journey | Owning sources / obligation |
| --- | --- |
| Supply wrapping keys | [`Konclave.SecretStorage`](../../crates/Konclave.SecretStorage/src/lib.rs), [custody guide](../development/secret-storage.md): exact key material, protected provider, no fallback. |
| Supply sealed MLS persistence | Same crate's `SealedMlsStorageHandle`; preserve atomic backend writes and recovery ordering. |
| Integrate cryptography | [`Konclave.CryptographicCore`](../../crates/Konclave.CryptographicCore/src/lib.rs): use verified results and persist ratchets before exposing effects. |
| Integrate domain state | [`Konclave.DomainCore`](../../crates/Konclave.DomainCore/src/lib.rs): apply authenticated identity, replay, role, epoch, and state-transition rules. |
| Store local authority | [`Konclave.LocalAuthorizationStore`](../../crates/Konclave.LocalAuthorizationStore/src/lib.rs): separate immutable installation and mutable authority state. |
| Parse files or network data | [`Konclave.BoundedDocuments`](../../crates/Konclave.BoundedDocuments/src/lib.rs), [`Konclave.LocalFraming`](../../crates/Konclave.LocalFraming/src/lib.rs), [`Konclave.ProtectedHttp`](../../crates/Konclave.ProtectedHttp/src/lib.rs): bounds and transport controls are necessary, not authorization. |

## Trust and plaintext

The native daemon is a trusted plaintext endpoint and key custodian. Harness adapters
receive permitted plaintext, not profile/MLS keys. AccountTrusted trusts every process
under the OS account; it is not hostile-same-user isolation. UserPresence adds native
Windows WebAuthn UP+UV verification bound to the exact request, and fails unavailable
on unsupported platforms without fallback. No shipped HarnessAttested provider is
implied: a harness name, hook, session ID, environment variable, process ancestry,
path, or manifest is not attestation.

Standard A2A terminates request/response plaintext at the gateway and its task store.
MLS protects the gateway-to-agent leg, not the original HTTP caller-to-agent leg.
Relay code sees routing, expiry, coarse delivery, parent epoch, and opaque MLS content;
it must not deserialize task/application plaintext.

Discovery cards and labels grant no authority. Web access grants no native
membership or policy authority. Request-service requester/operator roles are immutable;
enrollment creates a private channel, not permission to execute work. Only exact
local authority and authenticated protocol transitions can authorize effects.

## Custody and sealed storage

The composition is wrapping-key provider → context-bound AES-256-GCM `SecretSealer`
→ sealed backend. Keep enrollment credentials, service identity, profile wrapping
keys, and client session keys distinct; one identifier/provider namespace must not
accidentally select another secret.

| Contract | Implementer obligation |
| --- | --- |
| Native wrapping-key lookup/create | Hold the exclusive profile process lock before loading or creating. Startup custody failure must not create a replacement key. |
| `NativeEnrollmentCredentialStore` | Separate service namespace and internally derived bounded account identifier; distinguish missing, malformed, and unavailable. Create-or-exact-verify and read back. |
| External wrapping key | Exactly 32 bytes from the explicit reader; reject short/trailing data. Disable native-keyring when selecting this flow; no environment/plaintext fallback. |
| `SecretRecordContext` / `SecretRecordKind` | Bind ciphertext to its intended record context; authentication is not interchangeable across records. |
| `SecretSealer::share` | Shares wrapping-key ownership but uses its own random nonce source. Do not reinterpret sharing as permission to expose the key. |
| Sealed MLS backend | Persist snapshots, epochs, and private material atomically; authenticate public key-package bytes in associated data. |
| `SealedMlsStorageHandle` | Expose only sealed backend operations; poisoned ownership fails closed. Host owns blocking placement and actual durable persistence. |

Native keyring and SQLite exports are feature-gated. A custom provider must preserve
the same fail-closed behavior; merely implementing a trait is not proof of OS custody,
multi-process exclusion, recovery, or durability. In-memory sealed fixtures demonstrate
composition and confidentiality of stored records, not persistence across crashes.
See the [canonical guide](../development/secret-storage.md) for provider-specific
setup and supported recovery limits.

## Cryptographic and domain sequencing

`DeviceIdentity`, `verify_device_credential_binding`, `verify_invitation`,
`MlsConversationClient`, and the verified result types are exported by
[`Konclave.CryptographicCore`](../../crates/Konclave.CryptographicCore/src/lib.rs).
Consume verified results; protobuf shape validation alone does not establish a
valid signature, trusted root, current role, invitation consumption, or route.

- Persist the outbound sender ratchet before returning ciphertext.
- On inbound processing, preserve two-phase ordering between durable application
  deduplication and ratchet persistence. A decrypt result alone is not a durable
  application acceptance.
- Persist accepted message identity and sender counter keyed by authenticated MLS
  sender/epoch, not the sender field asserted inside application content.
- Exact authenticated retries return the original result without repeating effects;
  reused identities with different authenticated content are violations.
- Verify the full conversation-state digest, not only epoch/roster. Validate Commit
  control payload, parent epoch, membership authorization, and exact receipt binding.
- Halt security-sensitive sending on an unresolved branch. Relay compare-and-set
  selects an epoch winner but does not prove malicious-relay non-equivocation.

The [protocol guide](../protocol/compatibility.md) owns these recovery and replay
rules, including first-submission expiry versus exact retry after acceptance.
The alpha profile uses RFC 9420 with
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; do not infer alternate suite support.

## Local authorization persistence and cancellation

The immutable installation binds expected service identity and configuration.
`Konclave.LocalAuthorizationStore` owns mutable policy, issuer registrations,
suspensions, grants, generation, and bounded audit state. Perform its synchronous
database work at the blocking boundary, then atomically publish the validated
snapshot; do not publish partial authority.

Authority reload polls at 500 ms, claim checks at 250 ms, with a 1-second bound.
Reload failure denies use and late reads are discarded. These are bounded local
freshness guarantees, not protection against full rollback by a hostile OS-account
owner. Once an immutable installation exists, missing authority state must not be
silently recreated.

Grants bind a memory-only session key, exact profile/harness/evidence/policy,
capability set, expiry, and pinned service key. Revoking a grant does not stop
AccountTrusted replacement issuance; profile suspension blocks new issuance without
deleting the profile.

Terminal local outcomes are keyed by session public key, profile, and RequestId,
not grant ID. After commit, cancellation, deadline, or disconnect must reconcile the
actual result rather than erase it or invent a canceled state. Acknowledgment,
admission, request claims, and delivery receipts do not prove model completion or
remote execution.

## Bounded inputs and protected transport

| Layer | What it provides | What remains with the caller |
| --- | --- | --- |
| `read_bounded_regular_file` | Rejects linked/nonregular/unavailable files and size excess, including bounded reads if the file grows. | Decide whether the file is trusted, owner-protected, and authoritative for this operation. |
| Strict bounded JSON | One complete strict document with configured byte/shape bounds. | Validate semantic fields and authorization; do not accept unknown options accidentally. |
| Catalog path handling | Root-scoped portable relative-path constraints and link/escape checks. | Choose and protect the root; metadata cannot grant execution authority. |
| Local framing | Four-byte big-endian length; reject zero/over-limit length before allocation. Finite `Malformed`, `TooLarge`, `Closed` errors. | Supply the current stage's bound, enforce deadline, authenticate session and payload. |
| Protected HTTP | Shared controls used by A2A clients/retrieval, including explicit redirect/proxy behavior. | Select trustworthy destinations, validate response identity/size, and never leak bearer credentials across origins. |
| Rust/TypeScript wire codecs | Byte/field/enum/identifier checks for supported wire shapes. | Signature, membership, policy, replay, durability, and exactly-once effect handling. |

An unauthenticated local handshake and an authenticated payload should not inherit
one permissive allocation limit merely because they share framing code. Likewise,
validating an artifact descriptor does not authorize an arbitrary network fetch:
retrieval is explicit, bounded, and must verify descriptor-bound ciphertext.

## Production versus fixture evidence

Use existing focused tests in the owning crates for changes to each boundary.
[`Konclave.CryptographicCore/src/tests.rs`](../../crates/Konclave.CryptographicCore/src/tests.rs)
owns cryptographic composition examples;
[`Konclave.A2AGateway/tests/client.rs`](../../crates/Konclave.A2AGateway/tests/client.rs)
owns HTTP interoperability examples; shared
[`protocol fixtures`](../../fixtures/protocol/v1) and
[`TypeScript fixture tests`](../../packages/Konclave.ProtocolContracts.TypeScript/tests/fixtures.test.ts)
own binary parity examples.

Fixture keys, loopback listeners, in-memory stores, and process-local mutexes are
not production custody, TLS termination, crash durability, or cross-replica fencing.
The shipped SQLite/file implementations have specific local guarantees; alternate
backends must demonstrate equivalent semantics rather than inherit the label.
No fresh tests, builds, ceremonies, deployment probes, or CI runs were performed
for this documentation change.
