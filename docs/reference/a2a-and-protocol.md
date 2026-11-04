# A2A and protocol reference

Use this page to choose an interoperability boundary, implement an A2A adapter, or
consume the native wire contracts. The detailed compatibility profiles remain
authoritative: [A2A](../protocol/a2a-compatibility.md) and
[native protocol](../protocol/compatibility.md).

## Choose the boundary

| Reader goal | Start here | Important boundary |
| --- | --- | --- |
| Call an HTTP agent | `A2AHttpJsonClient` in [client.rs](../../crates/Konclave.A2AGateway/src/client.rs) | Standard A2A exposes plaintext to the gateway. |
| Publish or discover an agent | [A2A profile](../protocol/a2a-compatibility.md), `Konclave.A2ADiscovery` | Cards, labels, skills, catalogs, and OASF metadata are discovery, not authority. |
| Route a task to Konclave | [Bridge guide](../development/a2a-konclave-bridge.md) | Operator-selected conversation and exact target; web callers cannot choose native authority. |
| Replace task persistence | [Task-store contract](../development/a2a-task-store.md) | Preserve atomicity and exact-retry semantics, not just CRUD shapes. |
| Publish output artifacts | [Artifact profile](../protocol/a2a-compatibility.md) | Explicit output publication; ordinary response text is not an artifact. |
| Implement a native peer | [Native compatibility](../protocol/compatibility.md) and [security obligations](security-boundaries.md) | A validating protobuf codec is not authentication, authorization, or durable replay protection. |

Standard bridging and protected handoff solve different problems. Standard HTTP
interoperability is simpler but trusts the gateway with plaintext. Protected handoff
uses the native Konclave path; it is not an encrypted A2A `Part`. A
protected-required card is rejected by the standard gateway/client. An optional
protected profile permits explicitly selected standard mode, not automatic downgrade.
Web authentication grants no native identity, membership, role, or collaboration-policy
authority.

## Supported HTTP profile

The vendored schema is [A2A v1.0.1](../../third_party/a2a/v1.0.1/a2a.proto);
the supported protocol version is `1.0`, HTTP+JSON. This is a narrowed initial
profile, not every feature represented by the upstream DTOs.

| Input or output | Contract |
| --- | --- |
| Initial request | One USER message with one nonempty `text/plain` part; text at most 64 KiB. No incoming task identifier. |
| Caller identifiers | Canonical ASCII message/context identifiers, at most 128 bytes; gateway task identifiers are 32 lowercase hexadecimal characters. |
| Unsupported request content | Bytes, URLs, structured data, filenames, metadata, extensions, references, push configuration, and alternate output modes. |
| History | Requested length is 0 or 1. Task-list projections suppress content/history/status prose. |
| Encoded bounds | Request 128 KiB; Agent Card 256 KiB; response 256 KiB. |
| Listing | Default page 50, maximum 256; artifact-inclusive pages default/max 8. Artifacts are omitted by default. |
| HTTP media type | `application/a2a+json`; inbound compatibility `application/json` is accepted. If supplied, `A2A-Version` must be exactly `1.0`. |
| Interfaces | Canonical HTTPS without credentials/query/fragment/backslashes/control characters. HTTP is limited to explicit loopback development. |

The [gateway guide](../development/a2a-reference-gateway.md) owns endpoint and error
details. Its send/get/list/stream/subscribe routes authenticate and authorize before
inspecting bodies, tenant/task identity, or persistence. Metadata listing and
artifact-inclusive listing are separate authorization actions. Denial uses HTTP
401/403; unavailable authentication uses 503 with `Retry-After`.
Cancellation authenticates and authorizes but returns `UNSUPPORTED_OPERATION`;
push paths return `PUSH_NOTIFICATION_NOT_SUPPORTED`. Do not implement application
cancellation by treating a closed HTTP connection as a cancel command.

`A2AHttpClientConfig::new` accepts a nonzero timeout up to 60 seconds and a nonzero
response limit no larger than the profile maximum; defaults are 60 seconds and that
maximum. `A2AHttpJsonClient::new` accepts a validated card and optional
`A2ABearerCredential`, checks the tenant on requests, and validates response identity.
Its protected HTTP client disables redirects and automatic proxy discovery.
Mutual-TLS cards require a deployment-specific client; this client returns
`UnsupportedAuthentication` rather than silently changing authentication.

### A maintained call sequence

The executable example owner is
[`outbound_client_round_trips_server_tasks_cards_and_etags`](../../crates/Konclave.A2AGateway/tests/client.rs).
It compiles a loopback publication, injects a completing submitter and SQLite store,
constructs `A2AHttpJsonClient`, then exercises:

1. `send_message` with a validated initial text request.
2. `A2ATaskId::parse` on the returned identity, then `get_task(..., Some(0))`.
3. Authenticated extended-card retrieval and metadata-only `list_tasks`.
4. `send_streaming_message`, terminal completion, and finite stream closure.
5. Public card fetch and conditional ETag retrieval.

Request construction is in the test's
[`common::request_with_message_id`](../../crates/Konclave.A2AGateway/tests/common/mod.rs):
tenant `tenant-a`, context `context-1`, one text part, no incoming task ID, explicit
history and `return_immediately`. The publication fixture is
[`a2a/examples/agent-publication.json`](../../a2a/examples/agent-publication.json).
These are source-backed test examples, not evidence that tests were rerun for this
documentation.

## Waiting, retries, bridge recovery, and streams

| Event | Caller-visible consequence |
| --- | --- |
| Normal blocking send | Wait defaults to 30 seconds with 250 ms polling; configurable limits are 5 minutes and 1 second respectively. Submission time counts toward the deadline. |
| `returnImmediately` | Still submits and reloads the durable task; it is not a promise that native work already ran. |
| Wait deadline | HTTP 504; the gateway does not fabricate a terminal task state. |
| Exact retry while SUBMITTED/WORKING | Reinvokes the idempotent submitter using the same immutable task identity. Changed creation content conflicts. |
| Stream connection | Snapshot first, then immutable artifact updates and ordered statuses; finite observation deadline. |
| Stream disconnect | Ends the projection observer, not native execution or the bridge response observer. Reconnect using a fresh subscription; there is no wire resume cursor. |

The bridge maps one task to `send_directed_request` using an operator-configured
conversation and exact device. It derives a deterministic message ID and uses the
same identity as the local RPC RequestId. Exact resend reconciles the daemon request
ledger and durable send identity. Send results must match the configured identities
before SUBMITTED becomes WORKING.

Only an inbound text reply from the configured sender/conversation, replying to the
exact request, can complete the bridge task. Appending that AGENT message and the
WORKING-to-COMPLETED transition are idempotent. A reply over 64 KiB fails with
`konclave_response_out_of_bounds`; it is never truncated. Initial permanent rejection
may reject a still-SUBMITTED task but cannot overwrite WORKING.

Bridge observation defaults to 5 minutes, maximum 24 hours; retry delay is at most
5 seconds. Observer capacity defaults to 256, maximum 1024, and is reserved before
send. Expiry leaves the task WORKING. Restart recovery is driven by an exact caller
resend, not automatic startup enumeration. Relay admission, local persistence,
receipts, and request claims do not guarantee remote execution.

## Task-store and artifact extension points

[`A2ATaskStore`](../../crates/Konclave.A2ATaskStore/src/store.rs) is a synchronous
semantic contract; `A2AGatewayApplication::new` accepts a portable store while
`open_sqlite` supplies the shipped single-gateway SQLite implementation. The gateway
and bridge must share the same logical store.

Implementers must preserve:

- The key `(agent, optional tenant, task)` and immutable route/context/source/options/
  text digest. Exact retry returns the original identity even after content pruning.
- Atomic creation of SUBMITTED generation 0, initial status, and USER message.
- Expected-generation transitions: SUBMITTED to WORKING or terminal, WORKING to
  terminal; no INPUT_REQUIRED/AUTH_REQUIRED. Terminal states are immutable.
- Append-only message/artifact identity: exact content retries preserve the first
  timestamp; changed content conflicts. COMPLETED needs an AGENT message or complete
  canonical artifact; other terminal states need bounded reasons.
- Atomic snapshots and retention tombstones. Active tasks are not pruned;
  idempotency retention outlives content retention.

Use the optional `test-support` feature's `A2ATaskStoreContractFixture` and
`assert_a2a_task_store_contract`, including independent handles and reopen behavior.
The [canonical guide](../development/a2a-task-store.md) owns all configuration bounds
and conformance requirements. SQLite full synchronization and a process mutex do not
provide cross-replica fencing. The standard task store contains plaintext, not the
daemon's sealed profile state.

Artifacts are output-only: 1–8 parts, at most 64 KiB aggregate inline content,
192 KiB canonical document, and 8 artifacts per task within the response bound.
Supported profiles include canonical text, finite canonical JSON, explicitly typed
raw bytes, and encrypted content-addressed URL descriptors. Filenames are safe
basenames; metadata/extensions are not supported.

[`A2AArtifactObjectStore`](../../crates/Konclave.A2AArtifactStorage/src/lib.rs) requires
content-address verification and exact-repeat idempotency. Override `open_object`
for incremental bounded reading; its compatibility default materializes `get`.
`FileA2AArtifactObjectStore` is the shipped owner-protected filesystem adapter.
`A2AGatewayArtifactPublisher` is bound to the exact route; exact retries remain
idempotent after terminalization, while changed content under one artifact ID conflicts.
No managed backend is implied by these traits.

The client never automatically fetches arbitrary output URLs. Explicit encrypted
artifact retrieval removes the secret fragment, sends no A2A authorization header,
disables redirects/proxies, and verifies exact length, SHA-256, and descriptor-bound
AES-GCM. The ciphertext service supports bounded GET `/sha256/{ciphertext-sha256}`,
not HEAD or range requests. See the [artifact profile](../protocol/a2a-compatibility.md)
before implementing storage or retrieval.

## Native protobuf ownership and release profile

Authored native schemas live under
[`proto/konclave/protocol/v1`](../../proto/konclave/protocol/v1), separately from
vendored A2A. [`Konclave.ProtocolContracts`](../../crates/Konclave.ProtocolContracts/src/lib.rs)
exposes generated `wire::v1` DTOs and validating v1 codecs;
[`Konclave.ProtocolContracts.TypeScript`](../../packages/Konclave.ProtocolContracts.TypeScript)
provides corresponding source codecs. Generated objects remain untrusted. Validate
before side effects; verify credentials, signatures, routes, expiry, consumption,
roles, and local authority at their owning boundaries.

| Native contract | Value / obligation |
| --- | --- |
| Protobuf namespace / application version | `konclave.protocol.v1` / 1.0 |
| Shared local-service protocol | 2; no downgrade to 1 |
| Application / text | 262144 / 261120 bytes |
| Relay envelope / payload | 1048576 / 1047552 bytes |
| Replay page | At most 100 envelopes and 16777216 bytes |
| Relay control / active devices | 1024 bytes / 128 devices |
| Application identity | Message ID 16 bytes; directed target 32 bytes; nonzero uint64 sender counter |
| TypeScript integers | `bigint` for uint64; directed expiry additionally constrained to the safe-integer range by its validator |

The latest checked-in profile is
[`protocol-v1.0.0-alpha.4`](../../protocol/releases/protocol-v1.0.0-alpha.4.json):
prerelease, transport endpoint major 1, relay/application 1.0, daemon profile schema
24, RFC 9420 suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, and MLS extensions
`0xff00`–`0xff02`. Package, wire, service, and storage versions are independent axes;
this is not a stable-platform or npm-publication promise.

Relay transport is protobuf: WebSocket binary ReplayRequest/ReplayPage, with HTTP
submit/ack. Application plaintext is inside MLS ciphertext, not relay JSON.
Preserve original bytes for opaque forwarding: TypeScript decoding drops unknown
fields, so decode/re-encode is not a lossless forwarder. Never reuse removed protobuf
field numbers; reserve them.

The shared binary examples are
[`fixtures/protocol/v1`](../../fixtures/protocol/v1); TypeScript parity ownership is
[`fixtures.test.ts`](../../packages/Konclave.ProtocolContracts.TypeScript/tests/fixtures.test.ts).
For example `application-message.bin` and `directed-request-message.bin` are decoded
and re-encoded against maintained builders. Compatibility requires supported prior
fixtures to remain readable; these fixtures are not a substitute for authorization
or crash/replay tests.

The fixture test imports the validating application codecs from
[`src/application.ts`](../../packages/Konclave.ProtocolContracts.TypeScript/src/application.ts).
Its application cases use this exact encode/decode composition:

```typescript
roundTrip: (bytes) => encodeApplicationMessage(decodeApplicationMessage(bytes))
```

Here `bytes` is the fixture's `Uint8Array`; the test compares the decoded value to
the maintained builder and the re-encoded bytes to the original fixture.
For untrusted application input, `decodeApplicationMessage` first checks the byte
and nested-field bounds, decodes protobuf, and validates version, identifiers,
counter, content variant and variant-specific limits. Encoding validates again.
Failures throw `ProtocolValidationError`; neither codec supplies signature,
membership, policy or persistence checks. This is an excerpt of an existing
executable test, not a standalone program or a lossless unknown-field forwarder.
