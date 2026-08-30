# A2A compatibility contract

This document is the canonical owner of Konclave's A2A wire provenance, initial
profile, and compatibility rules. ADR 0013 defines why A2A remains an edge binding
rather than replacing Konclave transport or the local trust boundary.

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
- `SendMessage`, `GetTask`, `GetExtendedAgentCard`, and bounded Agent Cards.

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

The optional `return_immediately` value is preserved for the gateway task layer.
Semantic task creation, context ownership, idempotency, and Konclave target selection
belong to the [A2A domain-mapping](../development/a2a-domain-mapping.md) and bridge
layers.

## `GetTask` and encoded bounds

`GetTask` requires one canonical task identifier of at most 128 ASCII bytes, the
exact configured tenant, and optional history length `0` or `1`.
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
- `GET /tasks/{id}` and `GET /{tenant}/tasks/{id}`;
- `GET /extendedAgentCard` and `GET /{tenant}/extendedAgentCard`; and
- `GET /.well-known/agent-card.json` when explicitly published.

`historyLength` is a camel-case GetTask query parameter. Streaming paths authenticate
and return the A2A `UNSUPPORTED_OPERATION` reason. Push, list, cancellation,
subscription, and artifact operations remain outside the initial profile.

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
It advertises only HTTP+JSON, `text/plain`, no streaming, no push notifications, and
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
interface URLs, and exact fixture round trips.

An A2A update uses a new versioned source directory and new immutable fixtures. It
must not rewrite the `v1.0.1` source or reinterpret its validated initial profile.
