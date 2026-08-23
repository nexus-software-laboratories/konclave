# Adapter channel authentication

`Konclave.AdapterTransport` owns the harness-neutral half of the local adapter
channel defined by
[ADR 0005](../adr/adr-0005-harness-neutral-adapter-boundary.md). It contains no
Copilot, Claude, Codex, model, prompt, or session concept, so every adapter shares
one authentication contract.

## Launch capability

An adapter generates 32 random bytes, writes them to an exclusively created
owner-readable file inside an adapter-private directory, and passes only the file
path to the daemon child. The raw value never crosses the channel, never enters
command arguments, and never reaches logs, telemetry, or persisted profile records.

`LaunchCapability::read_launch_file` accepts the file only when it is an ordinary
file of bounded size that is not a link or reparse point, and rejects it when
another account can reach it. On Unix that means group and other bits must be clear
and the owner must be the effective user. An additional hard link is rejected,
because a second path would retain the capability after the adapter removes its own.

The file holds one canonical unpadded base64url value with at most one trailing
newline. Padded encodings, wrong lengths, and embedded newlines fail closed. Every
intermediate buffer, and the capability itself, is zeroized.

## Authenticated transcript

Both sides authenticate one canonical byte string:

1. the protocol version as two big-endian bytes;
2. the profile length as two big-endian bytes, then the profile bytes;
3. the consumer length as two big-endian bytes, then the consumer bytes;
4. the adapter challenge, exactly 32 bytes; and
5. the daemon challenge, exactly 32 bytes.

Every variable-length field carries an explicit length, so no two distinct
transcripts share an encoding. Direct concatenation would let a profile and consumer
identifier trade characters and authenticate the same bytes.

Identifiers are bounded and restricted to alphanumerics, `-`, `_`, and `.`, so path
traversal and control characters cannot enter an authenticated field.

## Role-separated proofs

Each proof is HMAC-SHA-256, keyed by the launch capability, over a fixed 32-byte role
domain followed by the encoded transcript:

- `konclave.adapter.v1.proof.daemon` for the proof a daemon presents; and
- `konclave.adapter.v1.proof.client` for the proof an adapter returns.

Distinct domains of equal fixed width mean a captured daemon proof cannot be replayed
as the adapter proof. Verification is constant time, and a truncated or padded tag is
rejected before comparison. Failures return a bounded code that never includes a
challenge, capability, identifier, or path.

The primitive comes from the project's vetted provider through
`KonclaveCryptographicCore::HmacSha256Key`. Neither side authors a new primitive.

## Bounded framing

Every message is a four-byte big-endian length header followed by that many payload
bytes. A declared length is validated against the applicable limit before any buffer
is reserved, so a peer cannot force a large allocation with a header it never
satisfies. A zero-length frame is rejected.

Frames accepted before both proofs verify are limited to 1 KiB; authenticated frames
are limited to 1 MiB. Keeping the pre-authentication limit far lower means an
unauthenticated peer cannot make the process reserve an event-sized buffer.

Handshake payloads begin with a one-byte message tag. Fields are read at exact
offsets and the payload must end precisely at the last field, so an unknown tag, an
unimplemented version, a truncated field, an identifier length beyond the payload, a
non-UTF-8 identifier, and trailing bytes all fail before any value is used.

## Handshake exchange

The adapter opens with its version, consumer instance, and challenge. The daemon
answers with its profile, its own challenge, and its proof. The adapter verifies that
proof and returns its own, which the daemon verifies before serving any request.

The daemon compares the profile it was launched for against the value both sides
authenticate, so a capability belonging to another profile cannot attach. The adapter
performs the mirror check and rejects a daemon answering for a profile it did not
launch.

The whole exchange is bounded by a single timeout rather than each individual read, so
a peer that connects and then stalls cannot hold a task and buffer indefinitely. A
closed channel fails rather than hanging, and a valid message arriving out of order is
rejected.

Because each channel contributes fresh challenges, a proof captured from one channel
does not authenticate another even under the same capability.

Challenges come from a caller-supplied source, so the operating-system random source
stays outside this crate and the contract can be exercised deterministically without a
test-only branch in the production path.

## Cross-language parity

`fixtures/adapter/v1/auth-transcript.json` holds the canonical vectors: inputs, the
encoded transcript, and both proofs. Any implementation of this contract, in any
language, must reproduce those bytes exactly.

`crates/Konclave.AdapterTransport/tests/shared_vectors.rs` verifies the Rust
implementation against that fixture as data rather than restating the bytes, so a
change to the layout or a proof domain fails before it can silently desynchronize a
non-Rust adapter.
