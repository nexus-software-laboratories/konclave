# A2A reference gateway

This document is the canonical implementation contract for Konclave's public
single-publication A2A HTTP+JSON gateway and outbound client. ADR 0013 owns the
network-edge trust boundary, ADR 0014 owns durable task-store semantics, ADR 0015
owns publication and discovery visibility, ADR 0016 owns streaming behavior, and ADR
0017 owns artifact content.

## Crate boundaries

`Konclave.A2AGateway` composes:

- one validated `CompiledA2AAgentPublication`;
- one exact `A2AAgentRoute`;
- one portable `A2ATaskStore`, with the public SQLite implementation used by the
  reference path;
- one injected idempotent `A2ATaskSubmitter`;
- one finite clock and response-wait policy;
- one HTTP authentication and authorization boundary; and
- one outbound-only A2A client.

`A2AGatewayApplication::open_sqlite` is the complete public reference constructor
for an injected submitter that does not need direct task-store access.
`A2AGatewayApplication::new` accepts the portable store trait for the Konclave bridge,
managed implementations, or alternative self-hosted implementations. The bridge and
application receive the same store instance through that constructor.

The gateway does not open local daemon storage, MLS provider state, profile keys, or
local service internals. The
[A2A-to-Konclave bridge](a2a-konclave-bridge.md) implements `A2ATaskSubmitter`
through the public authenticated local-service contract.

`Konclave.ProtectedHttp` owns the shared credential-bearing reqwest builder. It
installs the existing rustls ring provider and disables redirects and automatic proxy
discovery for both native Konclave relay clients and A2A clients.

## HTTP+JSON profile

The reference router implements the pinned A2A v1.0.1 HTTP+JSON binding:

| Operation | Without tenant | With tenant |
|---|---|---|
| Public Agent Card | `GET /.well-known/agent-card.json` | Not tenant-prefixed |
| SendMessage | `POST /message:send` | `POST /{tenant}/message:send` |
| SendStreamingMessage | `POST /message:stream` | `POST /{tenant}/message:stream` |
| ListTasks | `GET /tasks` | `GET /{tenant}/tasks` |
| GetTask | `GET /tasks/{id}` | `GET /{tenant}/tasks/{id}` |
| SubscribeToTask | `GET` or `POST /tasks/{id}:subscribe` | `GET` or `POST /{tenant}/tasks/{id}:subscribe` |
| CancelTask | `POST /tasks/{id}:cancel` | `POST /{tenant}/tasks/{id}:cancel` |
| GetExtendedAgentCard | `GET /extendedAgentCard` | `GET /{tenant}/extendedAgentCard` |

`historyLength` is the only accepted GetTask query parameter and remains limited to
`0` or `1`. `ListTasks` accepts `pageSize`, `pageToken`, and
`includeArtifacts=true|false`; the default page size is `50`, the hard maximum is
`256`, and artifacts are omitted by default. `CancelTask` authenticates and
authorizes like `GetTask` but returns `UNSUPPORTED_OPERATION`. The optional
`A2A-Version` header must equal `1.0` when present.

Request bodies accept `application/a2a+json` and compatibility
`application/json`, with an optional UTF-8 charset parameter. Every JSON response
uses the v1.0.1-preferred `application/a2a+json` media type.

Streaming message and task-subscription responses use `text/event-stream`. The
server accepts both subscribe verbs because the pinned v1.0.1 schema annotation and
prose HTTP+JSON binding disagree. Push notification and other task-lifecycle
operations remain outside this profile.

## Authentication and authorization

Protected handlers authenticate and authorize before reading a request body,
validating a tenant path, parsing task identity, or consulting durable state.

`A2AHttpAccess` receives request headers/extensions at the HTTP edge and returns only
an opaque 32-byte principal identifier. It then decides one exact action:

- `SendMessage`;
- `SendStreamingMessage`;
- `ListTasks`;
- `GetTask`;
- `SubscribeToTask`;
- `CancelTask`;
- `GetExtendedAgentCard`; or
- `UnsupportedOperation`.

Missing or invalid credentials return `401` and Bearer access includes
`WWW-Authenticate: Bearer`. Valid but denied identity returns `403`. An unavailable
authorization dependency returns `503` with `Retry-After`.

`StaticBearerAccess` is the complete initial self-hosted adapter. It:

- accepts one to 64 unique visible-ASCII credentials of 32 to 512 bytes;
- stores only a domain-separated SHA-256 principal derived from each token;
- requires exactly one case-insensitive Bearer authorization header; and
- authorizes every protected operation for a configured principal.

The publication's advertised authentication kind must equal the configured access
adapter. A deployment may implement `A2AHttpAccess` for mutual TLS by consuming
certificate identity placed in request extensions by trusted TLS middleware. Raw
credentials never enter application, task, log, error, or telemetry values.

## Durable task submission

`SendMessage` validates and maps the request before opening durable state. Task
creation occurs on a blocking-storage executor.

After a task is durably created, or an exact existing `SUBMITTED` or `WORKING` task
is recovered, the application invokes `A2ATaskSubmitter`. Resubmitting `WORKING`
allows an exact caller retry to restore response observation after gateway process
restart without scanning local daemon state. The submission contains the exact task
key, source A2A message identifier, Konclave conversation and target, deterministic
Konclave request identifier, and request text. It does not implement `Clone` or
`Debug`.

The submitter must use the Konclave request identifier as a stable idempotency key.
Repeated calls are expected after concurrent HTTP retries, process recovery, or a
failure between task creation and downstream acceptance. The gateway never assumes
that a check-then-send sequence is unique.

When `returnImmediately` is true, the gateway reloads and returns current durable
state after submission. Otherwise it polls the portable store until the task reaches:

- `COMPLETED`;
- `FAILED`;
- `CANCELED`;
- `REJECTED`; or
- `WORKING` timeout at the caller's HTTP deadline.

The default response deadline is 30 seconds with a 250-millisecond poll interval. The
deadline begins before downstream submission and covers submission plus durable-state
polling, including immediate requests. It is finite and configurable; the hard
maximum is five minutes and poll maximum is one second. Expiry returns `504` without
changing or fabricating task state. A retry can continue from the same durable task.

## Task response projection

The gateway projects task-store records back into bounded pinned wire DTOs and
revalidates the generated Task through `Konclave.A2AContracts`.

The initial `GetTask` projection:

- uses the exact 32-hex task identifier and configured context;
- maps only the separate A2A task-state enum;
- emits an exact millisecond-derived protobuf timestamp;
- emits only one gateway-owned metadata field, `konclave_terminal_reason`, for
  `FAILED`, `REJECTED`, or `CANCELED` tasks;
- emits up to eight complete retained canonical artifacts within the response bound;
- returns at most one most-recent history message;
- omits history when `historyLength=0`; and
- includes the most-recent agent message in status only for terminal response states
  that actually produced agent text.

`ListTasks` reuses the same bounded Task shape but suppresses all message bodies:
every listed task has empty `history`, no `status.message`, current state, the same
timestamp semantics, and the same terminal-reason metadata when terminal. It includes
artifacts only when `includeArtifacts=true`.

A retained non-pruned `COMPLETED` task must contain an agent text message or one
complete validated artifact. Artifact-only completion has no `status.message`.

Task and SendMessageResponse decoders reject oversized bodies, duplicate JSON keys,
missing status or timestamps, unspecified states, mismatched task/context identity,
invalid artifacts, history beyond the initial bound, and metadata other than the
single terminal-reason field.
Validated task wrappers do not implement `Clone` or `Debug` because they may contain
message plaintext.

## Streaming projection

`SendStreamingMessage` performs the same durable create/reconcile and idempotent
submission as `SendMessage`. `returnImmediately` has no effect on the stream.
`SubscribeToTask` rejects an already terminal task before streaming headers.

Every stream:

1. emits one current Task snapshot;
2. records that snapshot's artifact sequence and task generation as internal cursors;
3. reads later artifacts and statuses from one durable snapshot;
4. emits complete immutable `TaskArtifactUpdateEvent` values in artifact order before
   any terminal status in that snapshot;
5. emits one `TaskStatusUpdateEvent` per status record; and
6. closes after a terminal or interrupted event, or when the finite response deadline
   expires.

The stream emits no direct Message payloads and does not support artifact chunk
mutation: `append=false` and `lastChunk=true`. Completed status updates carry the
exact agent response in `TaskStatus.message` when completion is text-backed; an
artifact-backed completion has no status message. Failed, rejected, and canceled
updates use the same bounded `konclave_terminal_reason` metadata as GetTask.

There is no proprietary resume token or SSE event ID. A caller reconnects with
`SubscribeToTask`; the required first Task snapshot reconciles state accepted while
the caller was disconnected. A closed or dropped HTTP stream never cancels or
otherwise mutates the durable task.

`publish_artifact` is the route-scoped application boundary for one complete
validated artifact. It requires an existing `WORKING` task, appends deterministic
canonical bytes idempotently, and leaves terminal transition to orchestration.
Current Konclave directed responses remain text-only; the explicit agent publication
operation is delivered separately rather than interpreting arbitrary response text
as an artifact.

## Error responses

HTTP failures use a bounded A2A `google.rpc.Status`-shaped JSON envelope:

```json
{
  "error": {
    "code": 404,
    "status": "NOT_FOUND",
    "message": "A2A task or route was not found",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "TASK_NOT_FOUND",
        "domain": "a2a-protocol.org"
      }
    ]
  }
}
```

Validation errors add a `google.rpc.BadRequest`-shaped field violation. Fixed
messages and reasons contain no request body, credential, tenant, task identifier,
filesystem path, or internal exception text.

The initial mapping includes:

| Condition | HTTP | Reason |
|---|---:|---|
| Invalid request or query | 400 | `INVALID_REQUEST` |
| Unsupported operation | 400 | `UNSUPPORTED_OPERATION` |
| Extended card absent | 400 | `EXTENDED_AGENT_CARD_NOT_CONFIGURED` |
| Authentication failed | 401 | `UNAUTHENTICATED` |
| Authorization denied | 403 | `PERMISSION_DENIED` |
| Task or route hidden/missing | 404 | `TASK_NOT_FOUND` |
| Conflicting deterministic task | 409 | `IDEMPOTENCY_CONFLICT` |
| Body exceeds bound | 413 | `REQUEST_TOO_LARGE` |
| Wait expired | 504 | `DEADLINE_EXCEEDED` |
| Capacity or dependency unavailable | 503 | `RESOURCE_EXHAUSTED` or `UNAVAILABLE` |
| Invalid generated response | 500 | `INVALID_AGENT_RESPONSE` |

## Agent Card caching

Public well-known discovery remains disabled unless the publication opts in. When
enabled, it returns:

- an SHA-256 content ETag;
- `Cache-Control: public, max-age=3600` by default; and
- `304 Not Modified` for the exact supplied ETag.

Extended cards use `Cache-Control: private`. Their ETag covers the authenticated
card content. The maximum configured cache lifetime is one day.

## Outbound client

`A2AHttpJsonClient` selects the preferred validated interface from an Agent Card and
supports unauthenticated loopback or Bearer access. Mutual TLS requires a
deployment-specific client adapter.

The built-in client:

- preserves the interface base path and adds the exact optional tenant prefix;
- sends `application/a2a+json` for request and non-stream response content and
  `text/event-stream` as the streaming accept type;
- sends `A2A-Version: 1.0`;
- marks Bearer headers sensitive;
- validates request tenant before transmission;
- disables redirects and automatic system/environment proxies;
- uses normal trusted-CA TLS verification;
- enforces a finite total timeout and bounded non-stream response accumulation;
- parses SSE incrementally with a per-event bound and task/context correlation;
- sends streaming messages and resubscribes only when the Agent Card advertises
  streaming;
- validates encrypted content-addressed artifact references but never retrieves them
  during task, list, or stream processing;
- validates response media type and full Task or Agent Card shape;
- correlates GetTask response identity and SendMessage context;
- requires extended cards to retain the base agent name, version, interfaces, and
  security identity; and
- parses only bounded uppercase A2A error reasons.

`fetch_public_agent_card` accepts only the canonical well-known path on a validated
production HTTPS or loopback-development URL. Conditional `304` is accepted only
when the caller supplied an ETag. Modified results return bounded ETag and
Cache-Control values so the caller can apply its cache policy. The preferred
interface must remain on the discovery origin; intentional cross-origin agents use
direct trusted configuration instead of unauthenticated discovery.

The built-in default client timeout is 60 seconds, leaving headroom above the
gateway's default 30-second stream window. Custom client timeouts remain total
request bounds. When a remote stream window is longer, client timeout is an expected
resubscription boundary rather than a task failure.

## Network binding

`serve_a2a_until` is the inbound network-edge host. It accepts loopback binding
directly. Any non-loopback bind requires the caller to assert trusted TLS
termination. The local daemon and agent sessions remain outbound-only and are not
modified by this gateway.

## Bounds

| Value | Bound |
|---|---:|
| Request body | 128 KiB |
| Task/Card response | 256 KiB |
| SSE data event | 256 KiB |
| Buffered SSE input | 1 MiB |
| Artifacts per Task | 8 |
| Artifact Parts | 8 |
| Aggregate inline artifact content | 64 KiB |
| Canonical artifact document | 192 KiB |
| Encrypted reference plaintext | 64 MiB |
| Remote error body | 64 KiB |
| Query string | 256 bytes |
| Request-body timeout | 60 seconds |
| Client total timeout | 60 seconds |
| Concurrent HTTP requests | 256 |
| Response wait | 5 minutes |
| SSE connection | 5 minutes |
| Response poll interval | 1 second |
| Static Bearer credentials | 64 |
| Bearer credential | 32-512 visible ASCII bytes |
| ETag | 256 ASCII bytes |

## Verification

Focused tests cover:

- task and SendMessageResponse protobuf/ProtoJSON validation;
- durable immediate, exact-retry, resubmission, terminal-wait, and timeout behavior;
- SQLite-backed task projection and history;
- protected tenant and unscoped HTTP paths;
- authentication before body parsing and route disclosure;
- public-card opt-in, ETag, and cache behavior;
- extended-card authorization and private caching;
- first-Task SSE ordering, consecutive status updates, terminal closure, finite
  resubscription windows, and both v1.0.1 subscribe verbs;
- end-to-end client SendMessage, ListTasks, GetTask, extended-card, and conditional discovery;
- redirect refusal with credentials;
- shared protected-client construction with ambient proxy discovery disabled;
- response byte bounds, terminal-reason metadata, task/context correlation, and
  cursor pagination;
- incremental SSE parsing, event bounds, CRLF/comments, and stream correlation; and
- canonical artifact forms, explicit ListTasks inclusion, artifact-backed completion,
  and no automatic URL retrieval; and
- TLS-or-loopback binding policy.

The A2A-to-Konclave bridge test suite runs the application and authenticated
HTTP+JSON path with the real idempotent submitter, SQLite task state, adversarial
message filtering, exact retries, and bounded observation.
