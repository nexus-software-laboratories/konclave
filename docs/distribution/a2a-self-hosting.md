# Operate the self-hosted A2A gateway

The public `KonclaveA2AGateway` exposes one Linux Foundation A2A v1.0 HTTP+JSON
agent at a dedicated origin and routes each accepted task to one exact Konclave
conversation participant. The target agent remains outbound-only: only the gateway
and operator-managed TLS proxy accept inbound network traffic.

This guide covers the native gateway archive and Linux AMD64 container. Both use the
same publication, route, bearer, SQLite, local-service, and encrypted-object
semantics.

## Trust boundary

Standard A2A mode terminates caller TLS and A2A plaintext before the gateway, and the
gateway stores the bounded task projection as SQLite plaintext. Use an
owner-controlled host, encrypted storage, protected backups, and a reverse proxy that
prevents direct access to the plaintext listener.

The gateway never receives MLS state, relay credentials, profile wrapping keys, or
the local service's private identity. It receives an AccountTrusted issuer seed only
to obtain a finite, memory-only `A2AGateway` session grant for one exact profile.
`AccountTrusted` trusts every process under that operating-system account; it does
not isolate hostile same-user software.

Protected-only Agent Cards do not send tasks through this process. Their clients
follow the fail-closed native Konclave handoff instead.

## Prerequisites

Prepare:

- one initialized and running Konclave shared local service;
- one self-hosted or managed relay reachable by that local service;
- one active Konclave conversation between the gateway's sender profile and the
  target agent device;
- one dedicated HTTPS origin for the A2A Agent Card and task API;
- one high-entropy bearer value for each authorized caller;
- encrypted storage for task state, ciphertext objects, and backups; and
- Docker on Linux AMD64 only when using the container.

Verify the complete release set before extraction or image loading. See
[Verify release integrity and contents](integrity.md).

## Establish the exact Konclave route

Use two paved Copilot CLI sessions to create or join one conversation. The session
whose profile the gateway will use is the sender; the other session is the target.

In the sender session:

```text
/konclave output verbose
/konclave status
/konclave conversations
```

Record the canonical profile identifier and conversation identifier. In the target
session:

```text
/konclave identity
```

Record the target device identifier. Do not infer any of these values from process
IDs, repository paths, model names, or agent text.

If the target should answer automatically, activate a collaboration policy that
permits `conversation.reply` and whose required harness claims the paved target
actually proves. Without a policy-authorized response or an explicit user response,
the A2A task remains non-terminal until the bridge observation deadline.

## Prepare public and secret files

Create separate roots for public configuration, owner-protected credentials, SQLite,
and ciphertext objects. On Unix, the credential, task, and object roots must belong
to the gateway account and use mode `0700`. The installation record, issuer seed,
and bearer files must be ordinary single-link files owned by that account with mode
`0600`.

Copy these existing installation files into the credential root:

- `konclave-local-service.json`;
- `account-issuer.key`; and
- one or more bearer files.

The copied installation record must retain the exact local-service endpoint and
service public key. Do not edit it to bypass endpoint ownership or peer verification.

Generate a bearer without placing it in shell history or an environment variable:

```shell
umask 077
openssl rand -hex 32 > <credential-root>/a2a-bearer
```

Give the bearer to an authorized A2A caller through a separate secure channel. The
gateway loads it once at startup and stores only its derived comparison value in
memory.

## Configure the publication

Copy `agent-publication.json` from the gateway archive and set:

- one unique metadata name;
- `publicWellKnown` only when unauthenticated Agent Card discovery is intended;
- one HTTPS interface at the dedicated origin root;
- optional tenant identity;
- bearer authentication; and
- only the skills this route actually offers.

The interface path must be `/`. Path-prefixed A2A deployments and standalone mTLS
caller extraction are not implemented. A required protected profile is valid for
discovery but intentionally refuses standard gateway startup.

## Configure the route

Copy `gateway-config.json` for a native process or
`gateway-config.container.json` for the container. Replace:

- `route.contextId` with one deployment-owned A2A context;
- `route.conversationId` with the recorded Konclave conversation;
- `route.targetDeviceId` with the recorded target device;
- `localService.profile` with the recorded sender profile;
- every file and directory with an absolute path; and
- the listener according to the deployment boundary below.

Keep the task database parent and artifact object directory disjoint. The gateway
rejects equal or nested roots so one mount, backup, or retention action cannot
silently affect both stores.

For a native process whose listener is host-loopback only:

```json
{
  "listener": {
    "address": "127.0.0.1:8090",
    "tlsTerminated": false
  }
}
```

For the maintained container behind a host-loopback port mapping and trusted reverse
proxy:

```json
{
  "listener": {
    "address": "0.0.0.0:8090",
    "tlsTerminated": true
  }
}
```

`tlsTerminated` is an assertion about the effective trust boundary, not a switch that
adds TLS. Never set it when another process or network path can reach the plaintext
listener without passing through the trusted proxy.

## Run the native gateway

Start the shared local service before the gateway:

```shell
KONCLAVE_A2A_GATEWAY_CONFIG_FILE=<absolute-gateway-config> <gateway-root>/bin/KonclaveA2AGateway
```

Probe the listener without loading configuration or credentials:

```shell
SERVICE_HEALTH_ADDRESS=127.0.0.1:8090 <gateway-root>/bin/KonclaveA2AGateway --healthcheck
```

Supervise the process as the same operating-system account that owns the local
service endpoint and gateway files. Stop it with `SIGTERM`; coordinated shutdown
stops HTTP acceptance and signals response observers. Configure a supervisor timeout
of at least 90 seconds for the bounded HTTP and observer-drain phases plus scheduling
margin.

## Run the container

Load the exact Docker archive:

```shell
docker image load --input konclave-a2a-gateway-container-0.1.0-linux-amd64.docker.tar
```

Prepare all five host roots before starting Compose. The example disables automatic
bind-path creation so a typo fails instead of creating a root-owned directory.

```shell
export KONCLAVE_GATEWAY_UID="$(id -u)"
export KONCLAVE_GATEWAY_GID="$(id -g)"
export KONCLAVE_GATEWAY_CONFIG_ROOT=<absolute-config-root>
export KONCLAVE_GATEWAY_CREDENTIAL_ROOT=<absolute-credential-root>
export KONCLAVE_LOCAL_SERVICE_SOCKET_ROOT=<absolute-local-service-socket-root>
export KONCLAVE_GATEWAY_TASK_ROOT=<absolute-task-root>
export KONCLAVE_GATEWAY_OBJECT_ROOT=<absolute-object-root>
docker compose --file <gateway-root>/share/konclave/a2a/compose.example.yaml up --detach
```

The configured UID must equal the local-service account's numeric UID. The socket
transport verifies kernel peer ownership, and the credential loader verifies file
ownership and mode. If user-namespace mapping changes either apparent identity, the
gateway refuses startup. Do not widen socket or credential permissions.

The container has a read-only root filesystem, no Linux capabilities, no-new-
privileges, a finite PID limit, and separate writable task and object mounts. Its
port is published on host loopback only.

## Configure the TLS proxy

The operator-managed proxy must:

- be the only non-loopback path to the gateway;
- terminate a certificate valid for the Agent Card origin;
- preserve the `Authorization` and `A2A-Version` headers;
- forward standard request and response content types without transformation;
- support long-lived SSE responses without response buffering;
- apply request-size and connection limits no weaker than the gateway's public
  bounds;
- route `/objects/sha256/<digest>` without forwarding URL fragments; and
- apply deployment download authorization, rate, and retention policy.

The gateway's object endpoint serves digest-verified ciphertext only. The
decryption key and nonce remain in the client-side URL fragment and are never sent to
the object endpoint.

## Back up and restore

The task database and ciphertext object root are separate but logically related.
For a simple file-level backup:

1. stop the gateway cleanly;
2. copy the complete task directory, including SQLite WAL and shared-memory files
   when present;
3. copy the complete object directory in the same downtime window;
4. copy public configuration and publication files;
5. back up credential files through a secret-capable channel; and
6. restart and verify `/healthz`, Agent Card discovery, and one authenticated
   GetTask.

Do not back up or restore the Unix socket. The shared local-service installation,
profile databases, profile keys, relay enrollment, and gateway state are separate
recovery domains; a usable restoration needs the original conversation identity and
target membership as well as the gateway files.

Restore into empty owner-controlled directories, reapply exact ownership and modes,
and start with the same route identity. A missing object returns `404`; a digest
mismatch fails closed rather than serving altered bytes.

## Upgrade and rollback

For every prerelease upgrade:

1. verify the complete new release set;
2. stop the gateway;
3. take a coordinated backup;
4. extract the new native archive or load the new image under its exact version tag;
5. compare the maintained configuration shape and release notes;
6. start the new process and verify health, discovery, an existing task, and object
   retrieval; and
7. retain the previous binary or image until those checks pass.

Do not use a floating container tag. The current prerelease has no promised
cross-version migration or downgrade contract. If a newer release migrates persistent
state, restore the coordinated pre-upgrade backup before running an older binary.

## Troubleshooting

| Symptom | Meaning and action |
| --- | --- |
| `owner-protected local storage is unavailable` | A required path is absent, inaccessible, linked, or not an ordinary file. Verify the resolved path without replacing it implicitly. |
| `owner-protected local storage is unsafe` | UID, mode, link count, or directory ownership is wrong. Restore owner-only custody; do not broaden permissions. |
| `local-service issuer does not authorize the A2A gateway profile` | The copied issuer does not match exactly one active Generic/A2AGateway registration that permits the configured profile. Use the installation's AccountTrusted issuer and exact canonical profile. |
| listener trust-boundary refusal | A non-loopback listener lacks an asserted trusted TLS terminator, or unauthenticated access is not direct loopback. Correct the topology rather than disabling the check. |
| protected-only publication refusal | The card requires native Konclave handoff. Do not start the standard plaintext gateway for that route. |
| HTTP `401` | The bearer is missing or does not match a startup-loaded credential file. Rotate deliberately and restart after updating authorized callers. |
| task remains submitted or working | The target may be offline, the conversation or device binding may be stale, or no policy-authorized/explicit response completed the directed request. Inspect the target session and route identifiers. |
| object HTTP `404` | The digest is malformed, absent, or the stored bytes fail content-address verification. Restore the exact ciphertext object. |
| object HTTP `416` | Range retrieval is intentionally unsupported; fetch the complete bounded ciphertext. HEAD is also unsupported. |
| standalone mTLS refusal | mTLS caller extraction is not implemented in the standalone host. Use bearer authentication or provide a separately reviewed trust adapter. |

## Current limits

The first standalone host has one publication, one route, one sender profile, one
target device, and one dedicated origin. It supports bearer-authenticated production
traffic or unauthenticated direct-loopback development. It does not provide
path-prefixed interfaces, standalone mTLS, dynamic route administration, or a
harness-facing artifact publication adapter.

The packaged acceptance suite proves native and container discovery, authorization,
directed request/response, GetTask/ListTasks, SQLite restart recovery, ciphertext
serving, range refusal, relay opacity, and exact container cleanup. See
[Packaged clean-install acceptance](acceptance.md).
