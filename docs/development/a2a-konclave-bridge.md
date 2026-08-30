# A2A-to-Konclave bridge

`Konclave.A2AKonclaveBridge` is the public reference implementation of
`A2ATaskSubmitter`. It translates one validated A2A task into one exact Konclave
directed request and projects only the exact target's correlated text response back
into the portable A2A task store.

ADR 0013 owns the network-edge and plaintext trust boundary. ADR 0014 owns task
identity, state, idempotency, and retention. This document records the concrete
bridge contract.

## Trust boundary

The A2A HTTP identity authorizes access to a published route but never becomes a
Konclave `DeviceId`, conversation member, or collaboration-policy authority. The
gateway runs as its own Konclave endpoint through an owner-restricted local service
and an exact configured profile. Its AccountTrusted session grant uses the dedicated
`a2a-gateway` harness kind.

The bridge does not open profile SQLite, secret storage, MLS state, relay state, or
daemon internals. It uses only bounded authenticated local-service operations. The
target agent remains outbound-only.

Standard A2A request and response plaintext is visible to the gateway while it
translates the protocols. Konclave MLS protection covers the gateway-to-agent
conversation; this mode does not claim original-A2A-client-to-agent E2EE.

## Directed-request submission

One `A2ATaskSubmission` becomes this local-service operation:

```text
operation: send_directed_request
payload:
  conversation_id: configured route conversation
  message_id: deterministic task-mapped Konclave MessageId
  target_device_id: configured exact target
  text: validated A2A request text
```

The payload contains no caller-selected reply identifier, route, profile, or target.
All identifiers use their canonical lowercase hexadecimal encoding.

The mapped Konclave `MessageId` is also the local RPC `RequestId`. An ambiguous
disconnect, concurrent HTTP retry, or exact task retry therefore reconciles through
both the daemon request ledger and Konclave's durable send identity instead of
creating another directed request. The bridge verifies that the send result returns
the exact conversation and message identifiers before transitioning the A2A task
from `SUBMITTED` to `WORKING`.

Per-task submission locks suppress duplicate local sends and observers within one
gateway process. Cross-process retries remain safe because the request and message
identities are deterministic.

A local `not_authorized` or directed-request `invalid_request` outcome maps a still
unaccepted `SUBMITTED` task to terminal `REJECTED` with reason
`konclave_request_rejected`. The same error cannot overwrite a `WORKING` task because
that task may already have been delivered and may still receive its authoritative
response. Temporary endpoint, capacity, deadline, reconciliation, or version
failures leave the task retryable.

## Exact response observation

The successful send result supplies the durable local cursor. Observation begins
after that cursor rather than scanning history from zero:

1. Read bounded local history after the latest observed cursor.
2. Synchronize one bounded relay page.
3. Wait for one bounded relay watch page.
4. Repeat with a finite retry delay until completion or the observation deadline.

Only a message satisfying every predicate completes the task:

- exact configured conversation;
- inbound direction;
- exact configured target as sender;
- ordinary text content;
- `reply_to_message_id` equal to the directed-request `MessageId`; and
- canonical bounded identifiers and message shape.

Wrong senders, wrong reply identifiers, outbound messages, directed requests,
collaboration-policy records, and unrelated text are ignored. On the exact response,
the bridge appends one idempotent A2A agent message using the Konclave response
`MessageId`, then applies `WORKING -> COMPLETED`. A crash between append and
transition is safe: the append and transition both reconcile on retry.
The stored A2A response timestamp is the bridge's bounded local acceptance time;
remote sender time never controls task chronology or wire timestamp validity.

Konclave permits a larger text body than the initial A2A profile. An otherwise exact
response above the A2A 64 KiB text bound transitions the task to `FAILED` with reason
`konclave_response_out_of_bounds`; it is never truncated or left permanently
`WORKING`.

Observation is bounded independently from the HTTP response wait. Its default window
is five minutes, with a hard maximum of 24 hours and a maximum five-second retry
delay. The per-process default observer capacity is 256 with a hard maximum of 1,024.
A slot is reserved before the directed send; saturation leaves the task `SUBMITTED`
and retryable instead of accepting work without an observer. Expiry leaves a started
task `WORKING`; it never fabricates failure or completion.

The bridge owns every observer handle. `shutdown` rejects new submissions, signals
cooperative cancellation, and joins all observers within a caller-supplied deadline
of at most 60 seconds. Dropping without graceful shutdown signals cancellation and
aborts remaining handles as a final containment fallback.

## Restart and retry behavior

The gateway application resubmits both `SUBMITTED` and `WORKING` tasks. After process
restart, an exact A2A `SendMessage` retry:

- recreates no task;
- resends the same Konclave message and local RPC request identities;
- recovers the original send result and cursor from durable idempotency;
- starts one new bounded observer; and
- finds a response that arrived while the gateway was offline.

The initial implementation does not enumerate all working tasks at startup. Recovery
is driven by an exact caller retry, which is consistent with the existing A2A task
idempotency contract and avoids adding a task-store scan or daemon-storage
dependency. Startup-driven recovery can be added later through a bounded portable
store query without changing message identity or response authority.

## Local-service grant behavior

`Konclave.LocalServiceClient::LocalServiceJsonClient` authenticates the expected
local service key before sending operation bytes. It obtains grants through the
installed AccountTrusted issuer and keeps one generated session key for the client
process lifetime.

The daemon request ledger keys session operations by:

```text
(session public key, exact profile, request id)
```

It deliberately excludes the replaceable grant identifier. Refreshing an expiring or
rejected grant with the same session key therefore preserves exact request
reconciliation. Observation calls receive fresh request IDs so a cached empty
read/watch response cannot be replayed forever; only the irreversible directed send
uses the task-mapped stable request ID.

## Verification

Focused tests cover:

- exact snake_case local operation payloads;
- stable send request and message identity;
- wrong sender, reply, and content filtering;
- one exact response and idempotent completion;
- temporary failure followed by exact retry;
- local policy rejection;
- deterministic failure for an oversized exact response;
- concurrent retry suppression;
- observer admission before irreversible send;
- bounded cancellation of a stalled watch;
- owned observer cancellation and bounded join on shutdown;
- `WORKING` task recovery after bridge restart;
- replacement-grant ledger identity; and
- authenticated A2A HTTP+JSON submission through the real bridge and SQLite store.
