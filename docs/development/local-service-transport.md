# Shared local service transport

`Konclave.LocalServiceTransport` owns the client boundary of the shared per-user
local service defined by
[ADR 0008](../adr/adr-0008-shared-local-service.md). It contains no Copilot, Claude,
Codex, MCP, model, prompt, or slash-command concept, so every harness adapter shares
one authenticated contract.

This crate is the protocol and transport only. Profile registries, per-profile
runtimes, and the operations a service actually implements are separate concerns that
compose on top of it.

## Registered adapter identity

Installation generates one Ed25519 signing identity per harness adapter and registers
its public record with the service. The record contains a random 16-byte adapter key
identifier, a non-zero key version, the one harness the adapter may claim, and the
profiles it may attach to. Ordinary clients cannot create or broaden a record.

`KonclaveCryptographicCore::LocalServiceIdentity` generates the key pair through the
project's configured provider and signs already-canonical bytes. It is deliberately
not `Clone`, not `Debug`, and not serializable, so the private key cannot be copied by
accident or reach a log, snapshot, or configuration record. Service composition
reconstructs the identity from exactly 32 bytes loaded through native credential
custody or an explicitly configured owner-protected external file. The transport
crate never chooses or persists that custody.

The service resolves a registration through the injected
`AdapterAuthorizationRegistry`. Rotation registers a new version before the old one is
retired, and revocation removes every version for a key. A retired or revoked record
simply stops resolving and the handshake fails closed, with no fallback to another
version.

`ProfileAuthorization` is either one exact profile or one namespace label. A namespace
authorizes the label itself and every `label-suffix` profile beneath it, so `team`
covers `team-alice` but never `teamalice`.

## Authenticated transcript

Both peers authenticate one canonical byte string:

1. the protocol version as two big-endian bytes;
2. the adapter key identifier, exactly 16 bytes;
3. the adapter key version as four big-endian bytes;
4. the client instance identifier, exactly 16 bytes;
5. the harness wire value as two big-endian bytes;
6. the profile length as two big-endian bytes, then the profile bytes;
7. the client challenge, exactly 32 bytes;
8. the service challenge, exactly 32 bytes; and
9. the service public key, exactly 32 bytes.

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

- `konclave.local-service.v1.client` for the proof a client presents; and
- `konclave.local-service.v1.accept` for the acceptance the service returns.

Distinct domains of equal fixed width mean a captured client signature cannot be
replayed as a service acceptance. Verification runs through
`KonclaveCryptographicCore::verify_local_service_signature`; neither side authors a
primitive.

## Handshake exchange

The client opens with its version, registration, instance, harness, requested profile,
and challenge. The service answers with the identity a client pins and its own
challenge. The client signs the transcript, and the service returns its acceptance
over the separate domain.

The service authenticates before it authorizes. It resolves the registration only to
obtain a verification key, checks the signature over the full transcript, and only
then checks the claimed harness and requested profile against the record. An
unauthentic peer therefore never learns which harness or profile a registration would
have permitted.

The client pins the exact service public key it expects, so an endpoint that answers
with any other identity fails before the client signs anything, and an acceptance
signed by a key other than the pinned one fails at the last step.

Both peers contribute fresh challenges, so a proof captured from one connection
authenticates nothing on another. The whole exchange is bounded by a single timeout
rather than each read, so a peer that connects and stalls cannot hold a task and a
buffer indefinitely.

The resulting `LocalServiceBinding` is immutable for the life of the connection. A
client that needs another profile opens another connection and performs another
handshake; no later request field can move it.

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

The transport does not interpret an operation or its payload, so a new operation needs
no transport change and every bound applies to all of them uniformly.

The request identifier is the idempotency key. A client that retries after a
disconnect reuses the same identifier, and a service that has already applied it
answers with the recorded outcome instead of repeating the side effect. Nothing else
in the frame is safe to deduplicate on, because two distinct operations may otherwise
be byte-identical.

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

`fixtures/local-service/v1/handshake-transcript.json` holds the canonical vectors:
every identifier input, the encoded transcript, both domain-separated signing
messages and real deterministic Ed25519 signatures, every handshake message payload,
the request and response encodings, and the bounds each side enforces. Any
implementation of this contract, in any language, must reproduce those bytes exactly
and verify both signatures under the fixture public keys.

`crates/Konclave.LocalServiceTransport/tests/shared_vectors.rs` is pinned to the
fixture as data rather than restating the bytes, so a change to a layout, a signature
domain, a message tag, or a bound fails there instead of silently desynchronizing a
non-Rust client.

The fixture keys come from fixed non-secret test seeds. Runtime identities remain
provider-generated and non-exportable; deterministic key material is data in the
cross-language fixture, not a production identity-construction API.
