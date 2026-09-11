---
title: Bound A2A artifacts with canonical inline content and encrypted references
status: Accepted
date: 2026-09-11
authors:
  - Konclave maintainers
tags:
  - a2a
  - artifacts
  - content-addressing
  - encryption
supersedes: []
superseded_by: []
---

# Bound A2A artifacts with canonical inline content and encrypted references

## Context and scope

ADR 0013 deferred A2A raw bytes, structured data, URLs, and artifacts until each had
a bounded semantic mapping. ADR 0014 already provides an opaque canonical artifact
record in the portable task store, and ADR 0016 provides ordered A2A streaming.

Konclave application content currently carries bounded text, directed requests, and
collaboration-policy records. It has no generic binary attachment or structured-data
message type. Treating an arbitrary A2A URL as a file to fetch would also create an
SSRF and ambient-credential boundary that A2A itself leaves to implementations.

This decision owns the public A2A artifact subset, canonical representation, inline
bounds, encrypted content-addressed reference format, task and streaming projection,
explicit retrieval policy, and public versus managed ownership. It does not add
generic binary content to Konclave core, make artifact inputs available to an agent,
or define managed storage topology and billing.

## Verified facts

- A2A distinguishes Messages used for interaction from Artifacts used for task
  output.
- One A2A Artifact contains one or more Parts. A Part can carry text, raw bytes, a
  URL, or structured data and can declare a filename and media type.
- A2A streaming represents artifact delivery with `TaskArtifactUpdateEvent`, including
  `append` and `lastChunk`.
- The pinned A2A schema does not bound part count, bytes, JSON depth, filename, media
  type, URL behavior, or artifact count.
- The portable task store accepts bounded canonical bytes, computes their SHA-256
  digest, assigns an artifact sequence, and prevents one artifact identifier from
  being reused with different bytes or completion semantics.
- The store permits artifact publication only before terminal task state and requires
  an agent message or complete artifact before `COMPLETED`.
- `Konclave.SecretStorage::AuthenticatedCipher` is the project-owned AES-256-GCM
  primitive with fresh operating-system-random nonces and caller-owned associated
  data.
- URL fragments are not sent in an HTTP request, so a decryption key carried in a
  fragment is not disclosed to the ciphertext host during retrieval.

## Assumptions

- The standard A2A gateway remains a plaintext endpoint and may see artifact content
  and reference keys, consistent with ADR 0013.
- A self-hoster can expose an HTTPS object endpoint reachable by the A2A client while
  agent devices remain outbound-only.
- Large artifacts are uncommon enough that an explicit fetch API is preferable to
  automatic dereferencing.
- Managed implementations can replace local object persistence while preserving the
  public descriptor, ciphertext, and retrieval semantics.

## Decision drivers

- Support useful text, JSON, and file outputs without unbounded allocation.
- Prevent arbitrary peer URLs from becoming gateway-side network requests.
- Preserve declared media types instead of sniffing or silently rewriting content.
- Keep large objects confidential from an object host and content-addressed for
  integrity and deduplication.
- Keep public self-hosting complete while allowing private managed operations.
- Avoid adding an A2A-specific binary type to Konclave core.

## Decision

### Keep artifact support output-only at the A2A edge

The current A2A `SendMessage` request remains one bounded text part. Artifacts are
task outputs published through an explicit gateway application or local-service
operation after the task is `WORKING`.

An artifact does not become a Konclave membership, policy, routing, or identity
object. Adding generic agent input attachments requires a separate Konclave
application-content decision rather than encoding A2A DTOs into core protocol state.

### Admit four canonical Part forms

One artifact contains one to eight Parts and at most 64 KiB of aggregate inline
plaintext. The complete canonical artifact document is at most 192 KiB, leaving
response-envelope headroom under the existing 256 KiB A2A response bound.

The admitted forms are:

1. **Text** — non-empty UTF-8. An absent media type canonicalizes to `text/plain`;
   an explicit media type must be canonical lowercase `text/*`.
2. **Structured data** — a finite JSON value with at most 32 levels and 1,024 total
   values. Object keys are serialized in ordinal order. The media type canonicalizes
   to and must equal `application/json`.
3. **Inline bytes** — one to 64 KiB of raw bytes within the aggregate inline bound.
   A canonical lowercase media type is required.
4. **Encrypted reference** — one canonical HTTPS URL in the exact format defined
   below. A canonical lowercase media type is required.

Media types contain one non-wildcard type and subtype, use only RFC token characters,
contain no parameters, and are never inferred from content or filename. Filenames
are optional bounded basenames with no slash, backslash, control character, or dot
segment. Artifact and Part metadata, descriptions beyond their explicit bounded
field, and extension URIs remain unsupported.

The validator converts the admitted generated DTO into deterministic ProtoJSON.
Those exact bytes are the canonical payload supplied to `A2ATaskArtifact`; generated
wire DTOs never enter persistence directly.

### Define one encrypted content-addressed reference

The reference URL is:

```text
https://<authority>/<operator-prefix>/sha256/<ciphertext-sha256>
  #konclave-aes256gcm-v1.<base64url-key>.<base64url-nonce>.<plaintext-bytes>
```

The URL must already equal its canonical serialization and contains no username,
password, query, or alternate fragment fields. The path digest is 64 lowercase
hexadecimal characters. The key is exactly 32 bytes, the nonce is exactly 12 bytes,
and both use unpadded canonical base64url. Plaintext length is a canonical decimal
integer from 1 byte through 64 MiB.

The object body is AES-256-GCM ciphertext with its authentication tag. Its SHA-256
must equal the path digest. Associated data is the versioned canonical descriptor:

```text
"konclave-a2a-artifact-object-v1\0" ||
artifact_id_length_u16 || artifact_id_utf8 ||
part_index_u16 ||
media_type_length_u16 || media_type_utf8 ||
filename_length_u16 || filename_utf8 ||
plaintext_length_u64
```

The key and nonce fragment is removed before the HTTP request, so the object host
receives only the content address. A reference is self-describing but not
self-authorizing: deployments still apply normal download rate, retention, and
availability policy.

### Never dereference an artifact URL automatically

Inbound request handling, task projection, persistence, list/get operations, and SSE
parsing validate reference shape only. They perform no DNS lookup or network request.

The built-in client exposes a separate explicit retrieval operation. It:

- accepts only the encrypted reference profile above;
- removes the fragment before transmission;
- disables redirects and ambient proxy discovery;
- applies finite response and plaintext bounds;
- verifies ciphertext SHA-256 before decryption;
- authenticates AES-GCM with the canonical descriptor; and
- returns content only after length verification.

Arbitrary A2A URL Parts remain unsupported even when a caller is authenticated.

### Project complete immutable artifacts into Tasks and streams

`GetTask` includes all retained validated artifacts within the response bound.
`ListTasks` continues to omit artifacts by default and includes them only when the
standard `includeArtifacts=true` request is explicit and the bounded page can be
projected.

The initial profile publishes one complete immutable artifact per artifact
identifier. It does not accept A2A chunk mutation: streaming uses
`append=false` and `lastChunk=true`.

Task streaming reads artifact sequence and task-status generation from one durable
snapshot. Newly observed artifacts are emitted in artifact-sequence order before a
terminal status accepted in the same or a later snapshot. Reconnection starts with a
current Task containing all retained artifacts, so no wire resume extension is
required.

### Keep public semantics and private operations separate

The public repository owns:

- validators and canonical bytes;
- encrypted-reference and associated-data format;
- portable object-store and retrieval traits;
- a complete self-hosted encrypted object-store adapter;
- task, SSE, and client behavior; and
- conformance and adversarial tests.

A managed implementation may privately own object-provider selection, tenancy,
quotas, lifecycle jobs, regional replication, caching, monitoring, and support. It
cannot change the artifact descriptor, encryption, validation, explicit-fetch, or
no-automatic-dereference semantics.

## Alternatives considered

### Pass arbitrary URL Parts through and let consumers decide

This is maximally compatible but creates ambiguous trust, SSRF, redirect, proxy, and
credential behavior as soon as any component tries to be helpful. It also provides no
content integrity or confidentiality from the object host. Rejected.

### Support only inline artifacts

This is simple and self-contained but forces large objects through every A2A, task
store, SQLite, and SSE byte boundary. It cannot provide a practical self-hosted path
for large files. Rejected as the only mode; retained for small content.

### Add raw artifact bytes directly to Konclave application content

This could make every agent understand attachments, but it changes Konclave's core
wire protocol, storage, MLS payload bounds, adapter contracts, and harness behavior
for an A2A edge feature. Rejected for this workstream. A future generic attachment
decision may reuse the artifact primitives without importing A2A DTOs.

### Use signed plaintext download URLs

Signed URLs can restrict access but expose plaintext to the object provider, place
credentials in logs and referrers, and make provider-specific signing part of the
public semantic contract. Rejected. Managed deployments may authorize ciphertext
downloads in addition to the portable encrypted reference.

### Automatically retrieve only allowlisted hosts

Allowlisting reduces SSRF but still creates DNS rebinding, redirect, credential,
availability, and cost side effects during ordinary task reads. Rejected; retrieval
remains explicit.

## Consequences

- Small useful outputs remain inline and deterministic.
- Large references remain confidential from storage and verifiable by content
  address.
- Artifact consumers must explicitly retrieve referenced content.
- Current agent requests remain text-only; publishing binary agent output needs the
  explicit bridge operation delivered later in this workstream.
- Canonicalization and limits reduce compatibility with arbitrary metadata-rich A2A
  artifacts, but the Agent Card and documentation state the supported subset.
- Self-hosted and managed deployments share wire and cryptographic behavior without
  sharing storage operations.

## Confirmation

- Contract tests cover every admitted Part form, canonical media types, JSON
  depth/count, aggregate bytes, filenames, URL canonicalization, key/nonce lengths,
  content-address paths, and rejection of metadata or arbitrary URLs.
- Store tests prove exact canonical-byte idempotency and atomic task/artifact/status
  snapshots.
- Gateway tests prove GetTask, explicit ListTasks artifact inclusion, response bounds,
  and no network access during projection.
- Streaming tests prove artifact order before terminal status and complete immutable
  `TaskArtifactUpdateEvent` values.
- Retrieval tests prove fragment stripping, redirect/proxy refusal, ciphertext
  digest verification, AEAD authentication, length bounds, and no implicit fetch.
- Bridge tests prove artifact publication is explicit, route-scoped, idempotent, and
  independent from the original directed-request send identity.

## References

- [ADR 0013: A2A edge interoperability](adr-0013-a2a-edge-interoperability.md)
- [ADR 0014: A2A task projection store](adr-0014-a2a-task-projection-store.md)
- [ADR 0016: A2A streaming projection](adr-0016-a2a-streaming-projection.md)
- [A2A compatibility contract](../protocol/a2a-compatibility.md)
- Vendored A2A v1.0.1 schema:
  `third_party/a2a/v1.0.1/a2a.proto`
