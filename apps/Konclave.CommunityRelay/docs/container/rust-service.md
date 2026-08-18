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
