# Shared local service transport

`Konclave.LocalServiceTransport` owns the client boundary of the shared per-user
local service defined by
[ADR 0008](../adr/adr-0008-shared-local-service.md). It contains no Copilot, Claude,
Codex, MCP, model, prompt, or slash-command concept, so every harness adapter shares
one authenticated contract.

This crate is the protocol and transport only. Profile registries, per-profile
runtimes, and the operations a service actually implements are separate concerns that
compose on top of it.

## Evidence-bound issuer and session grants

Installation creates an AccountTrusted issuer identity and registers its public
record with the service. The record contains a random 16-byte issuer key identifier,
a non-zero key version, bounded harness metadata, and the profiles for which it may
issue. The issuer can request grants; it cannot invoke profile tools, delivery, status,
or membership operations.

`AccountTrusted` explicitly trusts every process running as the configured operating
system account. The owner-protected issuer key excludes other accounts but does not
isolate mutually hostile same-account processes. Exact grants add profile binding,
expiry, auditability, quotas, and connection containment without overstating that
boundary.

`UserPresence` uses that issuer only to authenticate
`authorization.user_presence.begin`. The service returns one bounded WebAuthn request
whose random challenge represents a canonical binding of the installation, service,
issuer connection and request, policy, exact profile, ephemeral session public key,
harness, evidence, capabilities, enrolled credential, and finite timestamps. The
client invokes only the absolute `userPresenceHelper` path in the owner-protected
installation sidecar, without a shell. The helper returns a standard native assertion;
the daemon independently verifies challenge, relying party, origin, credential,
signature, user-presence and user-verification flags, user handle, and counter state.
The ephemeral session key signs the same canonical binding before grant issuance.
The verified credential update compares the complete begin-time record with current
durable state inside the write transaction. Overlapping ceremonies cannot overwrite a
newer counter; a stale completion returns conflict before grant issuance.

Completion normally occurs on the issuer connection that received the challenge. If
the service durably issued the grant but the response was lost, the client reconnects
with the same issuer client instance, completion request identifier, binding,
signature, and assertion. The service may return only that already-active grant;
changed completion bytes cannot mint replacement authority. A disconnect before
durable issuance requires a new ceremony.

`KonclaveCryptographicCore::LocalServiceIdentity` generates the key pair through the
project's configured provider and signs already-canonical bytes. It is deliberately
not `Clone`, not `Debug`, and not serializable, so the private key cannot be copied by
accident or reach a log, snapshot, or configuration record. Service composition
reconstructs the identity from exactly 32 bytes loaded through native credential
custody or an explicitly configured owner-protected external file. The transport
crate never chooses or persists that custody. The AccountTrusted session key is
different: the client generates it in memory for one process lifetime, and the
service stores only its public key.

The effective authorization policy is a versioned any-of/all-of list of evidence
clauses. Every clause is a nonempty canonical set whose members must all be present;
satisfying any complete clause permits issuance. Missing, empty, malformed, or
unknown policy denies. Clients cannot supply or weaken policy, and evidence is never
relabelled as a stronger kind.

An issued `SessionGrant` binds one random grant identifier, issuer key and version,
ephemeral session public key, exact canonical profile, harness metadata, verified
evidence set, policy version, issuance and expiry, and a closed capability bitset.
Active grants are bounded globally, per issuer, and per profile. Expired grants are
reclaimed before issuance; quota exhaustion denies the new grant and never evicts an
active one.

The daemon opens the owner-protected authorization database beside the immutable
installation record and binds it to a fingerprint of that complete record. Missing,
empty, corrupt, unsafe, mismatched, unsupported, or process-lifetime rolled-back
state prevents endpoint binding. The endpoint, service identity, profile root, and
custody configuration remain installation-owned and are never reloaded from mutable
authorization state.

An exact schema-1 database migrates to schema 2 inside one immediate transaction.
The migration preserves every existing authorization row, adds empty credential
reservation and active-credential tables, widens the closed audit-kind range, and
updates the version last. A modified schema-1 shape, unknown version, or failed
transaction is rejected without partial publication.

One validated durable snapshot supplies the issuer projection, active grants,
suspensions, generation, and effective evidence policy. Publication replaces the
complete in-memory issuer/grant registry while holding the same projection boundary
that exposes policy and issuer availability. Grant issuance and clean retirement
commit through the durable store first, then load and publish the committed
generation before returning success. Grant issuance retries preserve the same issuer
client instance, request identifier, and byte-identical payload so response loss,
including service restart after commit, resolves to the original durable grant rather
than minting replacement authority. A client retrying clean retirement remains bound
to the original grant and never mints a replacement grant as part of cleanup.
`service.status` reports the published authorization generation so diagnostics can
correlate client-visible authority with one exact durable snapshot.

The service polls durable authorization state every 500 milliseconds. A published
generation wakes authenticated connections immediately; a long delivery claim also
rechecks authorization on its 250-millisecond claim cadence. Therefore an exact
revocation, profile suspension, policy invalidation, or revoke-on-disable transition
is observed within one second of a successful durable commit, excluding an
already-failing storage operation. A reload error, corruption finding, installation
mismatch, or generation rollback stops admission, makes the current projection
unusable, and closes clients without terminating the service or retaining stale
authority. A read that misses the 500-millisecond observation deadline remains the
only in-flight read; its late result is discarded, and access reopens only after a
subsequent fresh verified snapshot. Blocking-worker failure or unexpected reload-task
termination remains fatal. If authorization changes while another request is
running, the transport closes immediately; already-committed work remains owned until
reconciliation, but its result is not written to the revoked connection.

Disabling an issuer always denies new issuance. `retain_until_expiry` keeps its
already-issued grants active until expiry or another terminal transition, while
`revoke` terminalizes those grants in the same durable transaction. A disabled
issuer remains handshake-visible only so an authenticated issuance request receives
the stable `issuer_disabled` result; a removed or unknown issuer fails the uniform
handshake.

Operator-only administration is exposed through `konclave authorization`. The
commands inspect bounded state, revoke one exact grant, suspend or resume one exact
profile, register a strictly newer issuer key version, enable, disable, or remove one
exact issuer key version, and replace the evidence policy with a strictly newer
version. Rotation registers and activates the replacement public key before clients
switch credentials and the prior key is disabled or removed.
`authorization replace-policy` cannot remove AccountTrusted through this
owner-account boundary. A fresh Windows `init --authorization-policy user-presence
--allow-no-recovery` performs native registration and confirmation before publishing
the installation, but the first delivery exposes no in-place enrollment or
presence-authorized downgrade command. These commands mutate the owner-protected
authorization database directly; they are not local-service operations available to
agent or model tools.

Examples:

```text
konclave authorization status
konclave authorization revoke-grant --grant-id <grant-id>
konclave authorization suspend-profile --profile <profile-id>
konclave authorization resume-profile --profile <profile-id>
konclave authorization disable-issuer --issuer-key-id <issuer-key-id> --issuer-key-version 1 --existing-grants revoke
konclave authorization register-issuer --issuer-key-id <issuer-key-id> --issuer-key-version 2 --public-key <ed25519-public-key> --harness generic --profile-scope all
konclave authorization remove-issuer --issuer-key-id <issuer-key-id> --issuer-key-version 1 --existing-grants revoke
konclave authorization replace-policy --clause account_trusted
```

The built-in Generic integration and A2A gateway use the same AccountTrusted issuer
and grant contract. `HarnessKind::A2AGateway` has additive wire value `5`, allowing
registration, audit, and policy code to distinguish an internet-facing A2A edge from
an unsupported generic harness. A self-declared harness label remains metadata, not
evidence. A generic client must supply an explicit durable profile alias or use a
clearly ephemeral isolated profile; PID, working directory, time, model name, and
free-form text do not establish continuity.

`Konclave.LocalServiceClient` exposes both one-shot reconciled requests and a
persistent authenticated JSON session. One-shot calls may retry an ambiguous
transport failure with the same request identifier and are not valid for
connection-owned delivery claims. Persistent sessions do not retry operations
automatically; they preserve the connection-owned delivery lease and leave
operation-specific reconciliation to the harness adapter. `Konclave.AdapterSdk`
builds its typed delivery API on that persistent session.

A persistent request temporarily owns its stream. Cancellation, timeout, or
transport failure drops that stream and makes the session unusable; only a fully read
response restores it. This prevents a late response from being interpreted as a
later operation's result.

## Authenticated transcript

Protocol version 2 has separate issuer and session roles. Both transcripts begin with
the two-byte protocol version and one-byte role, and end with the 32-byte client
challenge, 32-byte service challenge, and 32-byte pinned service public key.

The issuer role binds the issuer key identifier and version, issuer public key,
client instance, and harness metadata. The session role binds every grant claim:
grant and issuer identifiers, issuer version, session public key, client instance,
harness, length-prefixed exact profile, evidence bitset, policy version, issuance,
expiry, and capability bitset.

The single variable-length field carries an explicit length and every other field is
fixed width, so no two distinct transcripts share an encoding.

A profile identifier is bounded to 32 bytes of lowercase ASCII letters, digits, `-`,
and `_`, which is exactly what the daemon runtime accepts. Uppercase is rejected
rather than folded: the identifier becomes a profile directory name, so accepting two
spellings would let a case-insensitive filesystem resolve one profile through two
authorizations, two registry entries, and two locks. Path traversal and control
characters therefore cannot enter an authenticated field or pass transport
authentication only to fail a second, narrower runtime check. The harness is a closed
enumeration rather than free text, so an unimplemented value is rejected instead of
retained.

## Role-separated signatures

Each signature is Ed25519 over a fixed 32-byte role domain followed by the encoded
transcript:

- `konclave.local-service.v2.client` for the proof an issuer or session presents; and
- `konclave.local-service.v2.accept` for the acceptance the service returns.

Distinct domains of equal fixed width mean a captured client signature cannot be
replayed as a service acceptance. Verification runs through
`KonclaveCryptographicCore::verify_local_service_signature`; neither side authors a
primitive.

## Handshake exchange

An issuer opens with its complete public identity and fresh challenge. A session opens
with its complete grant and fresh challenge. The service answers with the identity a
client pins and its own challenge. The client proves the corresponding private key,
and the service returns its acceptance over the separate role domain.

The service completes the proof exchange before revealing authorization. Unknown,
expired, revoked, wrong-key, wrong-profile, wrong-harness, or policy-invalid grants
receive the same signed rejection, so the handshake is not a grant-registration
oracle. Protocol version 1 is not negotiated: an old client requires an upgrade and a
version-2 client refuses an old service.

The client pins the exact service public key it expects, so an endpoint that answers
with any other identity fails before the client signs anything, and an acceptance
signed by a key other than the pinned one fails at the last step.

Both peers contribute fresh challenges, so a proof captured from one connection
authenticates nothing on another. The whole exchange is bounded by a single timeout
rather than each read, so a peer that connects and stalls cannot hold a task and a
buffer indefinitely.

The resulting `AuthorizationBinding` is immutable for the life of the connection. An
issuer connection accepts only issuance operations. A session connection accepts
only capabilities in that exact grant. A client that needs another profile obtains
another grant and opens another connection; no request field can move an existing
binding.

## Bounded framing

Framing is the shared `Konclave.LocalFraming` primitive: a four-byte big-endian length
header followed by that many payload bytes, with the applicable limit supplied by the
caller. A declared length is validated before any buffer is reserved, and a zero
length is rejected. The primitive carries no protocol vocabulary, so the adapter
channel and this protocol share it without either inheriting the other's semantics.

Frames accepted before the handshake completes are limited to 256 bytes; authenticated
frames are limited to the exact maximum request encoding, which is 1 MiB of payload
plus its bounded header fields. Keeping the pre-authentication limit far lower means
an unauthenticated peer cannot make the process reserve a request-sized buffer.

## Request and response contract

After acceptance, the client issues bounded requests on the same channel. A request
carries a stable 16-byte request identifier, an operation name of at most 64 ASCII
identifier characters, and an opaque payload of at most 1 MiB. A response is either a
success payload or one stable error code from a closed set that carries no message,
path, identifier, or plaintext.

Wire values `1` through `11` retain their existing meanings. Live authorization adds
`12 profile_suspended`, `13 issuer_disabled`,
`14 required_evidence_unavailable`, and `15 capacity`. Unknown values remain protocol
errors rather than being surfaced as free-form service text.

The transport does not interpret an operation or its payload, so a new operation needs
no transport change and every bound applies to all of them uniformly.

`Konclave.LocalServiceClient` provides the reusable Rust client for these opaque JSON
operations without making the transport interpret operation names or payloads. Its
`LocalServiceJsonClient` pins the configured service key, authenticates through one
installed issuer, generates one memory-only session identity, obtains an exact-profile
grant, and opens a fresh owner-verified local connection for each bounded operation.
It retries an ambiguous transport failure with the same request identifier and
payload. One caller-visible deadline covers grant-lock contention, refresh, retry,
handshake, request, and response. Grant refresh preserves the same session identity,
so request-ledger reconciliation remains stable across replacement grants.

The request identifier is the idempotency key. Pending work is keyed by the ephemeral
session public key, profile, and request identifier, so a replacement grant for the
same live client can reconcile without broadening cancellation authority. Terminal
request and response frames are sealed into the profile database before the response
is published. The journal is bounded to the newest 256 outcomes per profile and
survives shared-service restart. A successful `delivery.claim` outcome is also bound
to its live connection-owned lease. Replaying that request identifier after detach
returns `conflict`; the replacement session uses a fresh request identifier to obtain
current lease generations. A conflicting operation or payload under one key is
rejected rather than replacing the recorded result.

Cancellation is an authenticated control operation carrying the target request
identifier and either caller or deadline reason. A cancellation that wins before the
explicit commit point becomes the terminal `cancelled` or `deadline_exceeded`
outcome. Once committed, the service reports `reconciling`, finishes the operation,
persists its actual durable outcome, and publishes that result. A disconnect or a
dropped async join never fabricates a terminal timeout while blocking work can still
commit. If terminal journaling remains unavailable after bounded retries, the service
caches the known actual result and returns nonterminal `reconciliation_pending`; an
exact retry attempts persistence again before returning that result. Coordinated
shutdown atomically stops new ledger admission, requests pre-commit cancellation, and
continues draining post-commit work after its diagnostic threshold.

Decoding validates every field at an exact offset: an unknown message kind, an
unimplemented error code, an empty or oversized operation length, an operation outside
the accepted character set, a declared payload length above the bound or beyond the
frame, a truncated field, and trailing bytes all fail before any value is used or any
payload buffer is reserved.

## Local endpoint

The service listens on one well-known per-user endpoint. This is local
inter-process communication only; nothing here opens a loopback or non-loopback TCP
listener.

On Unix the endpoint is a socket inside an owner-only runtime directory. Binding
creates that directory with mode `0700` when it is absent and validates it when it
already exists: a symbolic link, another account's ownership, and any group or other
permission bit are all refused. At the endpoint path itself, a symbolic link, an
ordinary file, and a foreign-owned socket are refused and left in place rather than
removed. A socket this account owns is probed first, so a live service is reported as
in use and only a stale socket from a crashed predecessor is replaced. The bound
socket is then restricted to mode `0600`; the owner-only directory remains the
primary protection.

A client validates the same properties before connecting, so a link or a foreign-owned
path fails before any handshake byte is written. Endpoint failures report one bounded
code and never include the endpoint value, because the path encodes a private runtime
directory name.

`OwningUserPeerVerifier` reads the kernel peer credential of an accepted connection
and rejects any other account. That check is independent of the directory policy and
holds even if the directory mode is later relaxed.

Dropping the listener removes the socket by exact path after rechecking ownership, so
a clean shutdown does not leave a path that looks live. A crash leaves the socket
behind, which the next bind detects and replaces.

## Windows endpoint

On Windows the endpoint is a named pipe. Binding claims the first pipe instance
exclusively. Every first and subsequent instance receives a self-relative security
descriptor whose owner, group, and sole allow ACE are the current process account.
The descriptor is read back from the created handle; a missing owner, null DACL,
additional ACE, non-allow ACE, or another SID fails creation.

The service obtains the connecting process identifier from each accepted pipe,
opens its query-only process token, and requires the same user SID and an integrity
level at least as high as the service. Native Rust clients perform the symmetric check
against the server process before writing a handshake byte. Thin clients without a
native token API pin the installation-specific service public key and authenticate
the service proof before sending any operation request or plaintext. A missing
process, inaccessible token, malformed SID, another account, lower-integrity peer, or
invalid service proof fails closed.

The Win32 FFI, owned-handle cleanup, aligned token buffers, SID copying, security
descriptor lifetime, and DACL inspection live behind the safe
`Konclave.WindowsSecurity` API. Local transport code cannot obtain a raw security
handle or opt out of verification.

## Cross-language parity

`fixtures/local-service/v2/authorization-transcript.json` holds the canonical
protocol-v2 issuer and session vectors: every grant claim, both encoded transcripts,
both role-separated signing messages and deterministic Ed25519 signatures, and every
handshake message. Any implementation of this contract must reproduce those bytes
and verify the signatures under the fixture public keys.

Rust's `authorization_vectors` tests and the TypeScript thin-client tests are pinned
to that fixture as data rather than restating the bytes. A layout, signature domain,
message tag, evidence, expiry, or capability change therefore fails cross-language
validation instead of silently desynchronizing clients. The version-1 fixture remains
historical regression data and is not an accepted shared-service compatibility mode.

The fixture keys come from fixed non-secret test seeds. Runtime identities remain
provider-generated and non-exportable; deterministic key material is data in the
cross-language fixture, not a production identity-construction API.
