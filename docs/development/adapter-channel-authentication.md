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

## Local endpoint

The adapter creates the rendezvous point inside an owner-only private directory: a
Unix domain socket, or a named pipe on Windows. The daemon connects outward to it and
never opens a listener, so the device exposes no inbound socket. The random endpoint
name is defense in depth; the launch capability is the authentication.

A launch-provided endpoint is bounded and validated before it reaches a platform
call. It must be non-empty, within the platform's practical path or name limit, free
of NUL, absolute on Unix, and a named-pipe name on Windows.

Connection failures report one bounded code and never include the endpoint value,
because the path encodes an adapter-private directory name. A stale path left behind
by an adapter that exited without cleanup fails the same way as an absent one.

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

## Consumer lease

An attachment takes the profile's single adapter consumer lease only after both
proofs verify, so an unauthenticated peer can never displace a healthy consumer by
attaching first. A second consumer fails closed rather than taking over, and
releasing frees the lease immediately instead of waiting for expiry.

The daemon reads its launch configuration from `KONCLAVE_ADAPTER_ENDPOINT`,
`KONCLAVE_ADAPTER_CAPABILITY_FILE`, and `KONCLAVE_ADAPTER_CONSUMER_ID`. All three are
supplied together or not at all: a partial set is a mistake rather than a request to
run without an adapter, so it fails at startup instead of silently leaving
conversations undelivered. Absent configuration leaves MCP and relay recovery
untouched.

## Session operations

After both proofs verify, the adapter issues bounded requests on the same channel:
wait-and-claim, acknowledge, release, and status. Authenticated frames use the larger
limit; the pre-authentication limit no longer applies.

Wait-and-claim bounds both the batch size and the wait. An expired wait answers with
an empty batch, which is distinguishable from an applied transition on the wire, so an
adapter reissues rather than treating it as work. The daemon has no journal change
notification yet, so a wait polls at a fixed short interval: low enough that delivery
latency stays well under a conversational turn, high enough that an idle profile does
not spin.

A recoverable failure is answered with a stable code rather than closing the channel,
so a stale lease or an unknown notification does not force the adapter to
reauthenticate. Codes are bounded lowercase identifiers, and only conditions an
adapter can act on are distinguished; everything else collapses to one code so
internal storage state never becomes an adapter-visible signal. A malformed frame is
answered rather than dropped, so the adapter learns its frame was rejected instead of
waiting forever.

A delivered event carries the authenticated sender, conversation, kind, and stable
notification identifier as separate fields, so an adapter can frame peer text as
untrusted without parsing it for routing information.

Status reports pending and claimed counts from the journal, and watched-conversation
count and degraded state from the watch supervisor. The supervisor owns that truth and
the adapter channel only reads it, so status cannot disagree with the supervisor about
what is actually being watched. Delivery is reported degraded while a watch is
reconnecting or backpressured, so an adapter can surface that instead of appearing
idle while work is stalled.

## Daemon lifecycle

The adapter channel runs for the life of the daemon. Missing configuration is not an
error: the daemon still serves MCP and still recovers relay state. A configured
adapter that is unreachable or that rejects authentication is retried with bounded
backoff rather than taking the daemon down, because losing the harness connection
must not stop relay processing. There is no fallback to an unauthenticated channel.

The first retry is quick, because the common case is an adapter that has not finished
creating its endpoint yet; repeated failure backs off to a ceiling so a permanently
absent adapter cannot spin. The lease is released on every exit path, so a restarting
adapter is not made to wait out an expiry window that no live consumer owns.

## Cross-language parity

`fixtures/adapter/v1/auth-transcript.json` holds the canonical authentication
vectors: inputs, the encoded transcript, and both proofs.
`fixtures/adapter/v1/session-operations.json` holds the handshake message payloads,
every request and response encoding, every delivered event kind, and the bounds each
side enforces. Any implementation of this contract, in any language, must reproduce
those bytes exactly.

Both implementations are pinned to the fixtures as data rather than restating the
bytes, so a change to a layout, a proof domain, or a bound fails on both sides instead
of silently desynchronizing one of them:

- `crates/Konclave.AdapterTransport/tests/shared_vectors.rs` and
  `shared_session_vectors.rs` for the daemon; and
- `extensions/Konclave.HostExtension/tests/adapter-transcript.test.ts` and
  `adapter-session.test.ts` for the Copilot extension.

Proofs produced by the daemon verify in the extension, and the extension decodes every
event kind the daemon emits.
