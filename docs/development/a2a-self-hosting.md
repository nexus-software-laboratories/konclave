# Self-hosted A2A gateway runtime

`KonclaveA2AGateway` is the standalone public process for the standard A2A
HTTP+JSON bridge. It receives inbound A2A traffic while every target agent and the
shared local service remain outbound-only.

The process is a plaintext trust endpoint in standard mode. It validates A2A
requests, translates them into exact Konclave directed requests through the
authenticated local service, and persists the A2A task projection in SQLite. It does
not open profile databases, MLS state, relay credentials, or daemon internals.

Protected A2A does not use this runtime for task traffic. A protected client follows
the Agent Card handoff and communicates through native Konclave.

## Current profile

The first standalone runtime supports:

- one compiled A2A publication on a dedicated origin root;
- production bearer authentication or unauthenticated loopback development;
- one deployment-owned A2A context, Konclave conversation, and exact target device;
- `SendMessage`, `GetTask`, `ListTasks`, standard SSE streaming and subscription;
- explicit unsupported cancellation and push-notification responses;
- bounded SQLite task persistence and restart-safe idempotency; and
- bounded encrypted artifact ciphertext retrieval under
  `/objects/sha256/<ciphertext-sha256>`; and
- `GET /healthz`.

Mutual-TLS caller extraction and path-prefixed interfaces are rejected at startup
until the standalone host has explicit trust adapters for them.

## Configuration

Set `KONCLAVE_A2A_GATEWAY_CONFIG_FILE` to one absolute, non-linked strict-JSON
document. The maintained shape is
[`a2a/examples/gateway-config.json`](../../a2a/examples/gateway-config.json).

The configuration contains no raw local-service, relay, MLS, or A2A bearer secret.
It references:

- one public
  [`A2AAgentPublication`](../../a2a/examples/self-hosted-agent-publication.json);
- one owner-protected local-service installation record;
- the matching owner-protected AccountTrusted issuer seed;
- one canonical local-service profile;
- one owner-protected SQLite parent directory; and
- one separate owner-protected encrypted artifact object directory; and
- one to 64 owner-protected bearer files when the card advertises bearer security.

The publication identity and tenant become the public route identity. The gateway
configuration supplies only the deployment-owned context, conversation, and target.
An A2A caller cannot choose a profile, conversation, target, policy, relay route, or
device identity.

Every advertised interface must use `/` as its path. Deploy the process on a
dedicated hostname and put trusted TLS termination in front of non-loopback
listeners. The process refuses a non-loopback plaintext bind unless
`listener.tls_terminated` is `true`.

## Local-service enrollment

Run the packaged `konclave init` flow first. Its AccountTrusted issuer registration
is generic and may issue the gateway's finite `a2a-gateway` harness grant for an
authorized profile. The runtime:

1. opens the installation and issuer seed through owner-protected file APIs;
2. derives the issuer public key;
3. requires exactly one matching active installation registration;
4. requires that registration to permit the selected profile;
5. pins the installed service public key; and
6. creates a memory-only A2A gateway session identity.

The issuer can issue grants but cannot invoke profile operations. The gateway session
receives only the finite capabilities enforced by the shared local service.

## Persistence and retention

The SQLite task projection contains standard-mode plaintext. Place its parent
directory on owner-controlled encrypted storage, protect backups, and apply the
retention and tombstone policy documented by the public task-store contract. The
runtime verifies or creates an owner-protected parent directory before opening the
database.

Active tasks are never removed by retention. Terminal content and longer-lived
idempotency tombstones remain independently bounded.

The artifact object directory is distinct from the task database directory. The
runtime serves only content-addressed ciphertext from that root and refuses ranges,
HEAD, malformed digests, missing objects, and objects whose bytes do not match their
path digest. Trusted TLS termination and any deployment download-rate policy remain
operator responsibilities.

## Process lifecycle

Start the process with no arguments:

```shell
KONCLAVE_A2A_GATEWAY_CONFIG_FILE=/etc/konclave/a2a/gateway.json \
  <install-root>/bin/KonclaveA2AGateway
```

Health checks use a separate address so they do not need to parse the main
configuration:

```shell
SERVICE_HEALTH_ADDRESS=127.0.0.1:8090 \
  <install-root>/bin/KonclaveA2AGateway --healthcheck
```

Startup loads and validates every file, connects to the authenticated local service,
opens SQLite, constructs the exact bridge, and only then binds the listener. Shutdown
stops accepting requests, drains the HTTP server, signals all response observers,
and waits up to 30 seconds for their completion.

## Container boundary

The Linux AMD64 image and maintained Compose definition live under
[`apps/Konclave.A2AGateway`](../../apps/Konclave.A2AGateway/). The image runs as a
non-root user with a read-only root filesystem. Configuration, owner-protected
credentials, the local-service socket, SQLite state, and encrypted ciphertext objects
use five explicit mounts; the task and object roots remain separate writable
boundaries. Compose publishes the plaintext listener on host loopback only for an
operator-managed TLS reverse proxy.

## Remaining packaging work

Native archives and the Linux AMD64 container are exercised by packaged clean-install
acceptance against an independently installed shared service. Service definitions and
an agent-facing artifact-publication adapter remain separate delivery items. They
must preserve this configuration and trust boundary rather than embedding credentials
or moving plaintext into the relay.
