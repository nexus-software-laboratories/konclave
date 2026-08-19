# Relay transport authentication

This document is the canonical owner of the community relay's data-plane
authentication and route-grant contract. MLS identity and membership authorization
remain end-to-end client responsibilities.

## Bearer credential

One request uses exactly one `Authorization` header:

```text
Authorization: Bearer <base64url-token>
```

`<base64url-token>` is the unpadded base64url encoding of exactly 32 bytes generated
by an operating-system cryptographic random source. It is a secret. Do not place it
in a URL, relay access document, log, metric, trace, or shell history.

The relay derives a non-secret principal lookup identifier:

```text
SHA-256(
  "konclave-relay-principal-v1\0" ||
  bearer_token_bytes
)
```

The 32-byte digest is also represented as unpadded base64url in configuration.
Changing the domain, token length, digest, or text encoding requires a new
authentication contract version.

## Static access document

The community relay loads a JSON document no larger than 1 MiB. Version 1 permits at
most 1,024 principals, 1,024 grant groups per principal, and 8,192 total
route-permission grants. Unknown fields, duplicate principals, duplicate grants,
empty grant sets, and unsupported versions fail startup.

```json
{
  "version": 1,
  "principals": [
    {
      "principal": "<base64url-principal-digest>",
      "grants": [
        {
          "route": "<base64url-routing-id>",
          "permissions": ["send", "replay", "acknowledge"]
        }
      ]
    }
  ]
}
```

`route` may be `"*"` only when the operator deliberately grants that principal the
listed actions on every opaque route. There is no implicit wildcard or anonymous
principal.

The access document contains token digests and authorization metadata, not raw
tokens. Protect its integrity with operating-system ownership and permissions.
Clients retain raw tokens in sealed local storage.

## HTTP data plane

The initial endpoints are:

| Method | Path | Request | Success response |
| --- | --- | --- | --- |
| `POST` | `/v1/envelopes` | `RelayEnvelope` | `StoredRelayEnvelope`; `201` when new, `200` for an exact retry |
| `POST` | `/v1/replay` | `ReplayRequest` | `ReplayPage` |
| `POST` | `/v1/acknowledgments` | `AcknowledgeRequest` | `AcknowledgeRequest` containing the effective monotonic cursor |
| `GET` | `/ws` | WebSocket upgrade, then one `ReplayRequest` binary frame | One or more `ReplayPage` binary frames followed by live replay pages |

Protobuf request and response bodies use `Content-Type: application/protobuf`.
Requests with another media type fail. Request bodies are read only after bearer
authentication, are hard size-bounded, and have a bounded read deadline.

Responses carry a stable failure code in `x-konclave-error-code`. Authentication
failures use `401` plus `WWW-Authenticate`; an authenticated principal without the
requested route action receives `403`. Human-readable response text is never parsed
for behavior.

The relay stores each exact validated `RelayEnvelope` encoding. Submit and replay
responses preserve those bytes inside their protobuf parent messages, including
additive fields unknown to the relay.

## WebSocket watch

The authenticated WebSocket watch is server-to-client delivery, not a second submit
or acknowledgment API:

1. The client sends one binary `ReplayRequest` within 10 seconds of upgrade.
2. The server authorizes `replay` for that request's route.
3. The server sends bounded `ReplayPage` binary messages until `has_more` is false.
   It sends an empty initial page when the route has no newer envelope, confirming
   that the watch is active at the requested cursor.
4. Each new durable submission signals connected watchers. A watcher reloads from
   its last sent cursor and sends another `ReplayPage`.
5. A bounded safety replay runs periodically, so a dropped in-process notification
   or a write by another process cannot leave a healthy connection permanently
   stalled.
6. The client persists and acknowledges processed cursors through the HTTP endpoint.
   After disconnect, it reconnects with its last durable cursor.

Client frames after initialization are limited to Ping, Pong, and Close. A second
binary operation or any text frame closes the session as a protocol error. The
initial request is bounded to 1 KiB; each server replay page remains bounded to
16 MiB and 100 envelopes. Every write has a deadline, concurrent WebSocket sessions
are capped, and a missing heartbeat Pong closes the connection so clients can
reconnect instead of silently stalling.

Close reasons contain stable bounded error codes only. Malformed initialization uses
WebSocket protocol-error code 1002, route denial and heartbeat timeout use
policy-violation code 1008, server failures use 1011, and coordinated shutdown uses
1001.

Endpoint clients do not follow HTTP redirects, bound chunked and length-declared
responses before allocation, and reconnect WebSocket watches from the last durable
cursor. They service Ping frames while awaiting replay pages and classify only stable
bounded relay codes; response text, transport-library diagnostics, URLs, and bearer
values do not become application errors.

## Runtime configuration

The community relay requires:

- `KONCLAVE_RELAY_ACCESS_FILE` — access-document path;
- `KONCLAVE_RELAY_DATABASE_PATH` — durable SQLite path;
- `SERVICE_HTTP_ADDRESS` — listener address, defaulting to `127.0.0.1:8080`.

Direct plaintext HTTP is permitted only on loopback. A non-loopback listener requires
`KONCLAVE_RELAY_TLS_TERMINATED=true`, which is an operator assertion that a trusted
reverse proxy terminates TLS before traffic reaches the relay. The proxy must preserve
the `Authorization` header and prevent direct access to the plaintext listener.

## Security boundaries

- A bearer credential authorizes relay access; it does not authorize MLS membership.
- Routing identifiers are not credentials.
- The relay never receives device roots, MLS secrets, wrapping keys, or application
  plaintext.
- A stolen bearer token remains usable until its principal grant is removed and the
  relay reloads configuration.
- Revoking relay access limits metadata exposure and abuse. MLS removal is still
  required to prevent later message decryption.
- The initial static adapter is fail-closed and restart-loaded. Other deployments may
  replace it behind the same authenticated-principal and route-authorizer seams.
