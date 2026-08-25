# Verify release integrity and contents

Each complete unsigned prerelease set assembled during package validation contains:

- all native client and standalone-relay archives declared by `RELEASE.json`;
- the Docker-loadable Community Relay archive;
- `SHA256SUMS`, covering every other file in the set;
- target-specific Rust CycloneDX SBOMs;
- one CycloneDX SBOM for the bundled Copilot plugin;
- one Syft-generated CycloneDX SBOM for the relay container;
- one SLSA v1 in-toto provenance statement per executable archive;
- `Verify-Release.ps1` and its shared verification functions; and
- the unsigned-prerelease notice and release-contract schema.

## Verify every file

From the downloaded release-set directory, run:

```shell
pwsh ./Verify-Release.ps1
```

The verifier requires exact coverage against both `RELEASE.json` and `SHA256SUMS`.
Modified, missing, duplicate, unlisted, symbolically linked, malformed, or oversized
content fails closed. On platforms with GNU
`sha256sum`, the standard manifest is also directly consumable:

```shell
sha256sum --check SHA256SUMS
```

The PowerShell verifier is itself listed in `SHA256SUMS`. An unsigned checksum file
cannot establish publisher identity: obtain the complete set through a channel you
trust before using it as the integrity reference.

## Inspect software contents

Files ending in `.rust.cdx.json` describe the target-filtered normal Cargo dependency
closure for one native archive. The plugin SBOM describes the locked runtime npm
graph required by the bundled extension. The container SBOM scans the
Docker-loadable archive and includes operating-system and application packages.

CycloneDX documents omit random serial numbers, timestamps, Cargo path identifiers,
runner paths, and local source locations. Registry package checksums and SPDX license
expressions are retained when the package manager provides them.

## Inspect build identity

Files ending in `.intoto.jsonl` are SLSA provenance v1 statements. Each statement
binds one archive digest to:

- the exact public Git source commit;
- the release workflow and artifact target;
- the release version and unsigned status;
- hashes of locked dependency and build-definition inputs; and
- exact compiler, runtime, packaging, and scanner versions used by that lane.

Provenance deliberately omits run identifiers, timestamps, runner names, workspace
paths, credentials, and hosted-service internals. It supports audit and reproduction;
without a trusted signature, it does not independently authenticate its own origin.

Because both `RELEASE.json` and `SHA256SUMS` are unsigned, a party able to replace the
entire release set can also replace its declared contract. Exact coverage detects
truncation or coordinated removal only relative to the `RELEASE.json` you obtained.

Package validation currently verifies this set on ephemeral runner storage and does
not upload or publish the aggregate. These files become a user-facing download only
after a maintainer explicitly authorizes a public release channel.
