# A2A compatibility contract

This document is the canonical owner of Konclave's A2A wire provenance, initial
profile, and compatibility rules. ADR 0013 defines why A2A remains an edge binding
rather than replacing Konclave transport or the local trust boundary. ADR 0016 owns
the standard streaming projection, and ADR 0017 owns bounded artifact content.

## Pinned wire source

Konclave vendors the unmodified Linux Foundation Agent2Agent Protocol release
`v1.0.1` schema, which advertises protocol version `1.0`:

- source: `third_party/a2a/v1.0.1/a2a.proto`;
- upstream commit: `3303592588e388e62e0f69f701af531d2f4e3991`;
- upstream Git blob: `400cdbad934654e27d7abbae1e145923eb40ac52`;
- SHA-256: `e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016`;
- license: Apache-2.0.

`third_party/a2a/v1.0.1/provenance.json` owns the machine-readable source,
license, and generation-stub identities. The option stubs under `google/api/` come
from the official A2A Rust repository at the pinned commit recorded there. They exist
only so `protoc` can interpret schema annotations and do not define runtime behavior.

`Konclave.A2AContracts` generates Protocol Buffer and ProtoJSON DTOs from that source
during the Rust build. The crate is the A2A wire boundary. It does not belong to
`Konclave.ProtocolContracts` or `Konclave.DomainCore`, and generated DTOs remain
untrusted until a project-owned validator narrows them.

## Initial profile

The initial profile negotiates exactly:

- protocol version `1.0`;
- binding `HTTP+JSON`;
- media type `text/plain`;
- `SendMessage`, `ListTasks`, `GetTask`, `CancelTask` placeholder behavior,
  `SendStreamingMessage`, `SubscribeToTask`, `GetExtendedAgentCard`, and bounded
  Agent Cards.

Production interfaces require an absolute HTTPS URL without credentials, query, or
fragment. Development mode additionally permits HTTP on `localhost`, `127.0.0.0/8`,
or `::1`. The wire URL must already equal its canonical parsed serialization and may
not contain backslashes or control characters, so downstream HTTP stacks cannot
reinterpret a different authority. An optional tenant is deployment-owned and each
request must match it exactly; an A2A caller cannot select another Konclave profile,
conversation, device, policy, or relay route.

## `SendMessage` validation

The initial validator accepts one client message with:

- one canonical message identifier of at most 128 ASCII bytes;
- an optional canonical context identifier of the same bound;
- role `USER`;
- exactly one non-empty UTF-8 text part of at most 64 KiB;
- an empty or `text/plain` part media type;
- no task identifier, raw bytes, URL, structured data, filename, metadata, extension,
  reference task, push-notification configuration, or alternate output mode; and
- optional history length `0` or `1`.

The optional `return_immediately` value is preserved for `SendMessage`.
`SendStreamingMessage` normalizes it because A2A defines it as having no effect on a
streaming operation. Semantic task creation, context ownership, idempotency, and
Konclave target selection belong to the
[A2A domain-mapping](../development/a2a-domain-mapping.md) and bridge layers.

## Task lookup, subscription, and encoded bounds

`GetTask` requires one canonical task identifier of at most 128 ASCII bytes, the
exact configured tenant, and optional history length `0` or `1`. `ListTasks`
requires the same tenant, optional `pageSize` in the range `1..=256`, and an opaque
gateway page token when continuing pagination. `SubscribeToTask` requires only the
same exact tenant and task identifier; it has no caller-supplied history or resume
cursor.
The gateway domain layer further requires its own task identifiers to be exactly 32
lowercase hexadecimal characters, matching the mapped Konclave request identifier.

Protocol Buffer and ProtoJSON request bodies are rejected before decoding when they
exceed 128 KiB. Generated DTOs may represent the broader A2A schema, but unsupported
fields never become defaults, flattened text, fetched URLs, or silent truncation.

## HTTP+JSON binding

The reference gateway uses the v1.0.1-preferred media type
`application/a2a+json` for responses and outbound requests. Inbound request bodies
also accept compatibility `application/json`. The optional `A2A-Version` header must
equal `1.0` when present.

The implemented standard routes are:

- `POST /message:send` and `POST /{tenant}/message:send`;
- `POST /message:stream` and `POST /{tenant}/message:stream`;
- `GET /tasks` and `GET /{tenant}/tasks`;
- `GET /tasks/{id}` and `GET /{tenant}/tasks/{id}`;
- `GET` or `POST /tasks/{id}:subscribe` and tenant-prefixed equivalents;
- `POST /tasks/{id}:cancel` and `POST /{tenant}/tasks/{id}:cancel`;
- `GET /extendedAgentCard` and `GET /{tenant}/extendedAgentCard`; and
- `GET /.well-known/agent-card.json` when explicitly published.

`historyLength` is a camel-case GetTask query parameter. `ListTasks` accepts
`pageSize`, `pageToken`, and optional `includeArtifacts=true|false`; artifacts are
omitted by default. Artifact-inclusive pages default to and are capped at `8`.
Artifact-inclusive listing uses a separate authorization action from metadata-only
listing. `CancelTask` authenticates and authorizes normally but returns the A2A
`UNSUPPORTED_OPERATION` reason until the bridge can cancel an already directed
Konclave request.

Streaming uses `text/event-stream`. Every SSE `data` field contains one bounded
ProtoJSON `StreamResponse`. The first event is a current Task snapshot; later events
are complete immutable `TaskArtifactUpdateEvent` values and ordered
`TaskStatusUpdateEvent` values read from one durable snapshot. Internal artifact
sequence and status-generation cursors never appear on the wire. Active streams close
at the configured finite response deadline and recover through a fresh
`SubscribeToTask`; terminal streams close after the terminal event. Disconnecting
never changes task state.

The pinned v1.0.1 protobuf annotation spells task subscription as `GET`, while its
prose HTTP+JSON binding spells it as `POST`. The server accepts both and the outbound
client uses `POST`. Push and multi-turn operations remain outside the current
profile.

## Artifact profile

Artifacts are task outputs; A2A request messages remain one bounded text part. One
artifact contains one to eight canonical Parts and at most 64 KiB of aggregate inline
text, structured JSON, or raw bytes. The complete canonical artifact document is at
most 192 KiB, and one Task contains at most eight artifacts within the existing
256 KiB response bound.

Text Parts use canonical lowercase `text/*` media types and default to `text/plain`.
Structured data is finite canonical JSON with media type `application/json`. Raw
bytes require an explicit canonical lowercase media type. Filenames are bounded safe
basenames. Artifact and Part metadata and extension URIs remain unsupported.

Artifact identifiers are unique within each Task. Streaming binds each identifier to
one canonical artifact digest; duplicate or conflicting updates and unreconciled
final Task snapshots are rejected.

URL Parts accept only the versioned encrypted content-addressed HTTPS reference from
ADR 0017. Arbitrary URLs are rejected and no validation, persistence, task, list, or
stream operation performs DNS resolution or network retrieval. Referenced content is
fetched only through the explicit bounded client operation delivered with the public
object-store layer.

The self-hosted ciphertext router is nested beneath the operator-owned URL prefix and
serves only `GET /sha256/{ciphertext-sha256}`. It rejects range and `HEAD` requests,
streams bounded verified ciphertext, and retains its aggregate byte reservation until
the response body is consumed or disconnected. The built-in retrieval client removes
the secret fragment before transmission, carries no A2A `Authorization` credential,
disables redirects and ambient proxy discovery, enforces exact ciphertext and
plaintext lengths, verifies SHA-256, and authenticates the descriptor-bound AES-GCM
object before returning plaintext.

Harness output publication uses an `A2AGatewayArtifactPublisher` capability extracted
from one exact gateway application route. The operation accepts only a canonical task
identifier and bounded A2A Artifact ProtoJSON; callers cannot supply another agent or
tenant route, and the implementation performs no filename, path, text, or arbitrary
URL inference. Exact publication retries remain idempotent after terminal transition,
while changed content under the same artifact identifier fails as a conflict without
repeating the original directed request.

Errors use an `application/a2a+json` `google.rpc.Status`-shaped envelope with an A2A
`ErrorInfo.reason`; validation errors add a bounded field violation. The
[reference-gateway contract](../development/a2a-reference-gateway.md) owns exact
authentication, error, cache, task projection, client, and binding behavior.

## Agent Cards and private discovery

The standard public discovery path is `/.well-known/agent-card.json`. Konclave
exposes it only when a publication explicitly enables public well-known discovery.
Otherwise clients use direct configuration or the authenticated self-hosted catalog;
there is no public enumeration route.

Agent Cards are rejected before decoding when they exceed 256 KiB. ProtoJSON also
rejects duplicate object keys before generated DTO decoding. The initial
publication profile permits at most four canonical interfaces, 32 unique skills, and
one HTTP Bearer or mutual-TLS security declaration with one matching requirement.
It advertises HTTP+JSON, `text/plain`, standard streaming, no push notifications, and
no arbitrary extension. Provider, documentation, icon, example, metadata, and
signature fields remain unsupported.

Production publication requires Bearer or mutual TLS. Unauthenticated publication is
limited to explicit loopback-development interfaces. `GetExtendedAgentCard` retains
only the exact configured tenant after web authentication and authorization occur at
the gateway.

The [A2A agent discovery contract](../development/a2a-discovery.md) owns publication,
public/private visibility, catalog, and authorization semantics. The
[OASF compatibility contract](oasf-compatibility.md) owns the optional generated
catalog projection and its conformance limits.

## Fixtures and validation

Immutable fixtures live under `fixtures/a2a/v1.0.1/` for:

- `SendMessageRequest`;
- `GetTaskRequest`; and
- the initial Agent Card shape.

`scripts/a2a/Test-A2AProvenance.ps1` verifies every vendored byte and the exact file
set. `scripts/a2a/Test-A2AFixtures.ps1` verifies fixture manifests and prevents
released fixture replacement. Crate tests prove protobuf and ProtoJSON narrowing,
unsupported-field rejection, tenant isolation, version/binding negotiation, secure
interface URLs, exact fixture round trips, streaming event bounds, first-Task
ordering, task/context correlation, deterministic artifact canonicalization, media
types, JSON limits, inline byte limits, filenames, and encrypted-reference shape.

An A2A update uses a new versioned source directory and new immutable fixtures. It
must not rewrite the `v1.0.1` source or reinterpret its validated initial profile.
