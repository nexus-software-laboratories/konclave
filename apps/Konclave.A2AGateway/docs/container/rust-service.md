# A2A gateway container

See the
[self-hosted A2A operator guide](../../../../docs/distribution/a2a-self-hosting.md)
for route bootstrap, credential preparation, TLS termination, backup, and upgrade
procedures.

The Linux AMD64 image contains only the standalone `KonclaveA2AGateway` binary and
its maintained configuration template. The runtime user is non-root, the root
filesystem is read-only, all Linux capabilities are dropped, and the published port
is host-loopback only. An operator-managed reverse proxy must terminate trusted TLS
before exposing the gateway.

The image has five explicit mounts:

- `/etc/konclave/a2a` is read-only public configuration and publication data;
- `/run/konclave/credentials` is read-only owner-protected installation, issuer, and
  bearer material;
- the local-service socket directory is mounted read-only at the same absolute path
  recorded by the installation document;
- `/var/lib/konclave/a2a/tasks` is the writable SQLite boundary; and
- `/var/lib/konclave/a2a/objects` is the separate writable encrypted-ciphertext
  boundary.

Allow at least 90 seconds when stopping the container. The process enforces a
30-second HTTP drain followed by a separate 30-second observer drain; the outer
window leaves scheduling and supervisor margin without weakening either internal
deadline.

The container process must use the same nonzero numeric UID as the local service.
The local-service socket and credential files intentionally fail closed when user
namespace mapping changes their apparent owner or grants group/other access. Do not
work around that check by widening modes or socket permissions.

Prepare distinct Linux directories. Configuration and publication files may be
world-readable if they contain no deployment secrets. Credential files, task state,
and object state must belong to the gateway UID; credential files use mode `0600`
and mutable directories use mode `0700`.

The installation document copied into the credential root must retain the exact
local-service endpoint. Mount that endpoint's parent at the same absolute path inside
the container. Copy the authorized AccountTrusted issuer seed and one or more A2A
bearer values into the credential root rather than placing values in Compose
environment variables.

Load the unsigned prerelease image, export the required absolute roots, and start the
maintained Compose definition:

```shell
docker image load --input konclave-a2a-gateway-container-0.1.11-linux-amd64.docker.tar
export KONCLAVE_GATEWAY_UID="$(id -u)"
export KONCLAVE_GATEWAY_GID="$(id -g)"
export KONCLAVE_GATEWAY_CONFIG_ROOT=/absolute/path/to/a2a-config
export KONCLAVE_GATEWAY_CREDENTIAL_ROOT=/absolute/path/to/a2a-credentials
export KONCLAVE_LOCAL_SERVICE_SOCKET_ROOT=/absolute/path/to/local-service-runtime
export KONCLAVE_GATEWAY_TASK_ROOT=/absolute/path/to/a2a-tasks
export KONCLAVE_GATEWAY_OBJECT_ROOT=/absolute/path/to/a2a-objects
docker compose --file compose.example.yaml up --detach
```

The image never pulls from or pushes to a registry. The supplied configuration sets
`listener.tlsTerminated` because Compose exposes the plaintext process only on host
loopback for a trusted reverse proxy. Do not publish port 8090 directly or set that
assertion when another local process can bypass the proxy.

`GET /healthz` is intentionally unauthenticated and returns no deployment state.
Artifact retrieval is available beneath `/objects/sha256/`; the process serves only
digest-verified ciphertext and never reveals the decryption fragment carried by an
A2A reference URL.
