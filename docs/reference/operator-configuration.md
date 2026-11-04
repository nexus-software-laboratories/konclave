# Operator configuration reference

This page separates supported installation/control surfaces from embedding and test
configuration. Follow [installation](../distribution/installation.md) for executable
setup, [A2A self-hosting](../distribution/a2a-self-hosting.md) for gateway deployment,
and [security boundaries](security-boundaries.md) before choosing custody or evidence.

## Reader journeys

| Goal | Supported entry point |
| --- | --- |
| Install or upgrade a native client | Verified release set, then `Install-Konclave.ps1`; keep native runtime and thin plugin lifecycle separate. |
| Initialize a manually extracted client | Packaged `konclave init`, followed by `konclave doctor`. |
| Inspect or stop local authority | `konclave authorization` owner-control commands, not agent tools. |
| Host a gateway | Strict gateway JSON plus owner-protected publication, issuer, and bearer files. |
| Host a relay | Access policy file, database path, explicit listener/TLS boundary. |
| Recover a failed deployment | Preserve identity/authority/profile state; inspect finite diagnostics and repair the owning prerequisite. |

## Installer and native control

The implementation owners are
[`Install-Konclave.ps1`](../../scripts/installation/Install-Konclave.ps1) and
[`cli.rs`](../../apps/Konclave.CommandLine/src/cli.rs).
Use PowerShell 7.4 or newer. Verify the complete release set's checksums and
provenance before extracting or executing it. Published unsigned prerelease client
archives cover Linux x64, Windows x64, and macOS arm64/x64; the release guide, not this
table, owns exact asset names and availability.

| Installer parameter | Meaning / default |
| --- | --- |
| `Action` | Defaults to `Install`; also `Update`, `Rollback`, `Uninstall`, `Status`, `PrepareMarketplace`, `ActivatePlugin`, `MigrateRelay`. |
| `ReleaseDirectory` | Candidate verified release input. Do not mix assets from different releases. |
| `DataRoot` | Explicit data-root override; otherwise the platform installation convention. Not a plugin cache. |
| `RelayEndpoint` | Relay URL; TLS is required outside loopback. |
| `AuthorizationPolicy` | Explicit `account-trusted` or `user-presence`; noninteractive initialization has no implicit policy fallback. |
| `ExternalSource` | Explicit Unix headless enrollment source; not a plaintext environment credential. |
| `ServiceIdentityFile`, `ProfileKeyDirectory` | Explicit headless custody inputs; retain independently of versioned binaries. |
| `AllowNoRecovery` | Explicit acknowledgment for a no-recovery setup, not an authorization bypass. |
| `RollbackVersion` | Exact retained version; rollback otherwise selects the recorded previous version. |
| `RemoveState`, `ConfirmStateRemoval` | Both required for permanent state deletion. Ordinary uninstall preserves durable state. |

Normal marketplace setup uses `PrepareMarketplace`; `ActivatePlugin` is an explicit
direct-install compatibility path, not the preferred marketplace lifecycle.
Installer update/rollback does not silently mutate plugin caches. Hook approval and
a Copilot restart remain separate host steps. A degraded plugin exposes fail-closed
repair rather than pretending native tools are healthy.

`Install` repairs the active version idempotently; another version requires
`Update`. A different digest for an already recorded version is rejected. Candidate
health/start/publication failure rolls back to and rechecks the previous version.
Uninstall removes owned supervision/runtime metadata but retains profiles, service
identity, and durable authority unless both destructive flags are present.

### Initialization fields and lifecycle

| CLI input | Contract |
| --- | --- |
| `--relay-endpoint` | Required endpoint-bound enrollment destination. Exact repeated initialization verifies rather than replacing custody. |
| `--profile-root` | Optional platform-default profile-root override. |
| `--authorization-policy` | Required for noninteractive setup. AccountTrusted trusts the OS account; UserPresence requires supported native evidence. |
| `--external-source` | Absolute Unix headless enrollment source. |
| `--local-service-identity-file` | Absolute owner-protected identity source. |
| `--local-service-profile-key-directory` | Explicit per-profile wrapping-key directory. |
| `--local-service-endpoint` | Explicit local transport endpoint override. |
| `--local-service-client-config` | Absolute tests/development override; not the production configuration selector. |
| `--copilot-extension-root` | Legacy migration input, not a new extension installation recommendation. |

Canonical service configuration is under the platform data root at
`service/konclave.service.json`; it is separate from plugin caches and versioned
runtime directories. Initialization publishes immutable installation state only after
the authority database exists. Once published, a missing/empty authorization database
fails closed rather than being recreated. Conflicting endpoint, policy, source, or
existing files fail without replacement.

Public CLI command families are `version`, `init`, `relay-bootstrap`, `doctor`,
`authorization`, and `policy`. Hidden `user-presence-helper` registration/
authentication commands are internal implementation details, not a supported
operator workflow. `doctor` checks configured evidence and prerequisites without
triggering a ceremony; a passing configuration check is not proof that an
authenticator is currently available.

`authorization status` reports generation and bounded counts. Owner-only commands
revoke an exact grant, suspend/resume a profile, register/enable/disable/remove an
issuer, and replace policy. Grant/issuer IDs are 16-byte values encoded as
32 lowercase hex characters; issuer versions are nonzero and public keys are
64 lowercase hex characters. Scope is `all`, `profile:<id>`, or
`namespace:<prefix>`. Disabling/removing an issuer requires an explicit
retain/revoke decision for existing grants.

Revoking a grant does not prevent an AccountTrusted client from requesting another.
Suspend the profile when issuance must stop. UserPresence is shipped on Windows;
Linux/macOS return `required_evidence_unavailable`, with no AccountTrusted fallback.
Fresh UserPresence setup is not an in-place migration of an existing AccountTrusted
installation. See [installation](../distribution/installation.md) for exact commands.

## A2A gateway configuration

The gateway accepts no runtime command arguments except `--healthcheck`.
[`main.rs`](../../apps/Konclave.A2AGateway/src/main.rs) reads
`KONCLAVE_A2A_GATEWAY_CONFIG_FILE`;
[`RuntimeConfig::load`](../../apps/Konclave.A2AGateway/src/config.rs) requires an
absolute path to one non-linked strict JSON document, at most 64 KiB. Unknown fields
and unsupported schema versions fail before listener binding/storage creation.

| JSON field | Required contract |
| --- | --- |
| `schemaVersion` | Exactly `1`. |
| `interfaceEnvironment` | `production` or `loopback_development`; development is not a public HTTP exception. |
| `listener.address` | Parsed socket address; non-loopback requires the explicit TLS boundary assertion. |
| `listener.tlsTerminated` | Operator assertion that a trusted upstream terminates TLS; does not turn on TLS. |
| `publicationFile` | Absolute publication source; self-hosted interfaces use a dedicated origin root `/`. |
| `taskDatabaseFile` | Absolute SQLite path; parent directory disjoint from the artifact directory. Contains standard-bridge plaintext. |
| `artifactObjectDirectory` | Absolute owner-protected ciphertext object directory. |
| `route.contextId`, `route.conversationId`, `route.targetDeviceId` | Validated exact route; not caller-selectable. Native IDs have domain-defined byte lengths. |
| `localService.installationFile`, `localService.issuerKeyFile` | Absolute native installation pin and AccountTrusted issuer custody inputs. |
| `localService.profile` | Validated exact local profile. |
| `bearerTokenFiles` | At most 64 distinct absolute paths; credentials loaded at startup, not from plaintext command arguments/environment. |

Protected-required publications fail startup in this standard gateway. Bearer
credentials are 32–512 visible ASCII bytes, with 1–64 unique credentials for
`StaticBearerAccess`. Authenticate/authorize every data route; publishing a public
well-known card is an explicit discovery choice, not public task access.

Run the gateway as the local service owner, protect secret files and storage roots
(Unix 0600/0700 as documented), and expose only the reverse proxy publicly. Do not
expose the plaintext listener merely because `tlsTerminated` is true. Bearer changes
require loading the changed configuration through restart. `SERVICE_HEALTH_ADDRESS`
selects the healthcheck target; follow the [deployment guide](../distribution/a2a-self-hosting.md)
for the complete worked configuration and supervisor setup. Allow at least 90
seconds for gateway shutdown to drain HTTP/observer work.

## Relay configuration

These are actual runtime environment inputs in
[`http.rs`](../../apps/Konclave.CommunityRelay/src/http.rs), not native client
configuration keys:

| Environment variable | Default / validation |
| --- | --- |
| `SERVICE_HTTP_ADDRESS` | `127.0.0.1:8080`; must parse as a socket address. |
| `KONCLAVE_RELAY_ACCESS_FILE` | Required nonempty path to relay access policy. |
| `KONCLAVE_RELAY_DATABASE_PATH` | Required nonempty database path. |
| `KONCLAVE_RELAY_TLS_TERMINATED` | Absent means false; if present must be exactly `true`. Non-loopback binding without it fails. It does not configure TLS. |
| `SERVICE_HEALTH_ADDRESS` | `127.0.0.1:8080`; healthcheck target, with 3-second connect/read/write timeouts. |

HTTP request bodies have a 10-second bound. The relay limits concurrent requests to
256, WebSocket sessions to 256, enrollment concurrency to 8, and enrollment rate to
16/second. Saturation is finite failure, not unbounded waiting. Enrollment capacity
uses 503; enrollment rate limiting uses 429. Credentials and access policy are not
application-message plaintext; the relay handles opaque MLS content plus routing,
expiry, and delivery metadata.

## Failure and safe recovery

| Symptom | Safe next action |
| --- | --- |
| Custody unavailable, malformed, or missing | Restore the intended provider/source and permissions. Never generate replacement keys to make existing state open. |
| Authority reload/schema/configuration failure | Repair the exact owner-controlled input; leave fail-closed denial in place. Do not delete the authority database. |
| Plugin healthy/configuration mismatch | Inspect `doctor`, native installation record, and restart requirements; do not move authority into the cache. |
| A2A timeout or disconnected stream | Reconcile by task ID/exact request identity; do not claim remote cancellation or create a new logical request blindly. |
| Relay migration failure | Use the journaled apply/abort recovery in the installation guide; retain the old relay until every device is healthy. |

Relay migration preserves identity, conversations, and principals but does not copy
source relay envelopes/cursors. Destination enrollment authority must match;
coordinate devices and sync before cutover when pending delivery matters.

Configuration examples and lifecycle verification belong to the linked installation/
self-hosting guides and owning source tests. These links identify qualification
owners, not evidence that an installer action, live server or production deployment
was exercised. Consult exact-head hosted checks for fresh execution results.
