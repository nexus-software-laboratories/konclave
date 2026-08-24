# Relay principal enrollment

ADR 0007 adds a control-plane operation for registering client-generated,
pseudonymous data-plane principals. It does not change submit, replay,
acknowledgment, watch, routing, or MLS authorization.

## Self-hosted bootstrap

Community Relay access documents support version 2:

```json
{
  "version": 2,
  "principals": [],
  "enrollment": {
    "authority": "<base64url-sha256-enrollment-verifier>"
  }
}
```

`authority` is the unpadded base64url encoding of the 32-byte,
domain-separated verifier derived from a random 32-byte enrollment credential. It is
not the credential itself. Version 1 documents remain valid with static principals
and enrollment disabled. Version 2 must configure at least one static principal or an
enrollment authority.

The raw enrollment credential belongs in native credential custody or an explicit
headless secret source. It must not appear in the access document, process arguments,
environment variables, URLs, logs, or plugin configuration. Replacing or removing
the verifier and restarting the relay rotates or disables enrollment. Existing
data-plane principals remain independently active or revoked.

## HTTP contract

The authenticated endpoint is:

```text
POST /v1/enrollment/principals
Content-Type: application/protobuf
Authorization: Bearer <enrollment-credential>
```

Authentication uses the enrollment-specific derivation domain and occurs before
request-body materialization. A data-plane token cannot authenticate enrollment, and
an enrollment credential is not automatically a data-plane principal.

The bounded `RelayEnrollmentRequest` carries:

- protocol version;
- a stable 16-byte request identifier; and
- the 32-byte ADR 0003 principal digest derived from a client-generated data-plane
  token.

It never carries the raw token, profile identity, route, requested permission, account
identity, or hosted-provider field. Community Relay assigns its fixed self-hosted
wildcard `send`, `replay`, and `acknowledge` policy. Other deployments may implement a
different enrollment-authentication adapter while returning the same public outcome.

The response echoes the exact version, request identifier, and principal digest. Its
outcome is `REGISTERED` for a new commit or `ALREADY_REGISTERED` for an exact retry.
Reusing either identifier with a different counterpart is a conflict.

## Status and error behavior

| Outcome | HTTP status | Stable error code |
|---|---:|---|
| Registered | `201` | — |
| Exact retry | `200` | — |
| Missing, malformed, wrong, or disabled enrollment credential | `401` | `relay_authentication_failed` |
| Unsupported media type | `415` | `unsupported_media_type` |
| Malformed, oversized, or unsupported protocol | `400`/`413` | protocol validation code |
| Request/principal identity conflict | `409` | `relay_enrollment_conflict` |
| Principal capacity exhausted | `429` | `relay_principal_capacity` |
| Enrollment request rate exhausted | `429` | `relay_enrollment_rate_limited` |
| Enrollment concurrency exhausted | `503` | `relay_enrollment_capacity` |
| Storage unavailable | `503` | `relay_storage_failure` |

Enrollment permits at most eight concurrent handlers and sixteen authenticated
requests per one-second window. The durable registry independently caps 1,024 active
principals and 4,096 total active/revoked records.

## Data-plane activation and revocation

A successful registration makes the generated principal independently usable on the
unchanged data plane. Authorization is checked from durable state on each operation;
revocation therefore denies later HTTP operations and replay work without changing
another profile's principal. Revoked records remain as tombstones and cannot silently
re-enroll under the same identity.

The relay stores only request identifiers, principal digests, finite status, ordinary
opaque envelope metadata, and ciphertext. Raw enrollment credentials and data-plane
tokens are absent from relay SQLite, WAL, responses, diagnostics, and telemetry.

## References

- [ADR 0003: Relay transport authentication](../adr/adr-0003-relay-transport-authentication.md)
- [ADR 0007: Outbound relay principal enrollment](../adr/adr-0007-outbound-relay-principal-enrollment.md)
- [Relay storage](../development/relay-storage.md)
- [Threat model](../security/threat-model.md)
