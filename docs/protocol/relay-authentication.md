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
| `GET` | `/ws` | WebSocket upgrade | Authenticated WebSocket session |

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
