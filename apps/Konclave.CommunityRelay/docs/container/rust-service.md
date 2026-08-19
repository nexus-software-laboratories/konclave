# Rust service container

The generated multi-stage Dockerfile uses the committed lockfile when one is present
and otherwise resolves the composed application graph before building a release
binary. Only that binary enters the non-root Debian runtime image. Its image health
check invokes the process-level health probe without opening a network port.

Run the same contract used by generated CI:

```powershell
./scripts/container/Test-ContainerImage.ps1 `
  -ConfigPath .container/image.json `
  -Mode Validate
```

`PublishContainerToGhcr` adds the shared GHCR release workflow. That workflow builds
Linux AMD64 and ARM64 images, generates an SBOM, and emits provenance attestations
without changing the image contract.

## Relay runtime mounts

The relay fails closed until the container has:

- a versioned access document mounted read-only at
  `/run/secrets/konclave-relay-access.json`;
- a persistent volume mounted at `/var/lib/konclave`;
- a trusted TLS reverse proxy in front of port 8080.

Set `KONCLAVE_RELAY_TLS_TERMINATED=true` only when the proxy prevents direct access to
the plaintext container port, terminates TLS, and forwards the standard
`Authorization` header. The image does not set this assertion by default.

The access document contains only derived principal identifiers and route grants.
Raw bearer tokens remain sealed at clients and must not be mounted into the relay
container. See the
[relay transport authentication contract](../../../../docs/protocol/relay-authentication.md)
for the bounded document shape and data-plane rules.
