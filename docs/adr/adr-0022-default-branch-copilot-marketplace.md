---
title: Publish the Copilot marketplace from the default branch
status: Accepted
date: 2026-09-14
authors:
  - Konclave maintainers
tags:
  - copilot
  - distribution
  - marketplace
  - releases
supersedes:
  - adr-0021-generated-marketplace-branch
superseded_by: []
---

# Publish the Copilot marketplace from the default branch

## Context and scope

ADR 0021 selected a generated non-default branch because it kept compiled plugin
bytes out of ordinary source history. That decision proved technically viable:
Copilot CLI can register, refresh, update, and roll back an explicit repository ref.
It did not establish that an explicit ref is the standard or simplest user-facing
marketplace topology.

GitHub's documented marketplace layout places `.github/plugin/marketplace.json` and
the referenced plugin directory on the repository default branch. Users register the
repository without a ref suffix. Konclave's plugin is one approximately 247 KiB
compiled extension plus two small manifests, so avoiding that bounded generated file
does not justify a second mutable publication surface or a custom user command.

This decision supersedes ADR 0021. It owns the marketplace repository layout,
canonical artifact relationship, update and rollback ordering, cache boundary,
no-cost requirements, and implementation prerequisites. It does not itself add the
production catalog or plugin tree.

## Verified facts

### The documented path is the default branch

GitHub's
[marketplace guide](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-marketplace)
requires `.github/plugin/marketplace.json`, describes repository-relative plugin
directories, and instructs users to run:

```shell
copilot plugin marketplace add owner/repo
```

Its linked first-party examples resolve the catalog from `main`. The
[Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
also supports `owner/repo#ref`, but support for an optional ref is capability, not a
recommendation to replace the default-branch convention.

### First-party and ecosystem layouts favor the default branch

At inspected commits:

- [`github/copilot-plugins`](https://github.com/github/copilot-plugins/tree/fbf7c536a5c7af0c94ff5f528a39004c55129e6d)
  exposes its catalog on `main`.
- [`github/awesome-copilot`](https://github.com/github/awesome-copilot/tree/1899b18da3fa5183652f86165917d553cba1850a)
  exposes its catalog on `main`. Its generated `marketplace` branch contains
  additional materialized files, but the catalog blob inspected on `main` and that
  branch was identical. The generated branch is publication infrastructure, not
  evidence that ordinary users should register a non-default ref.
- Ten of the twelve maintained public ecosystem repositories inspected for ADR 0021
  contain marketplace catalogs on their default branches. The two without catalogs
  are implementation repositories referenced by another catalog.

The sample permits several source layouts but does not establish a user-facing norm
of explicit branch registration.

### Hosted branch evidence remains useful but does not choose the topology

[Hosted run 34831489855](https://github.com/nexus-software-laboratories/konclave/actions/runs/34831489855)
proved that Copilot CLI `1.0.82` and `1.0.84-5` can register
`owner/repo#ref`, install the exact three-file plugin, update it, refresh a rolled-back
ref, reinstall the prior version, remove the marketplace, and isolate replaceable
cache state.

That evidence remains a compatibility test for refs and rollback. It does not offset
the default branch's simpler command, review model, and lifecycle.

### Immutable Releases remain canonical

Konclave's immutable Releases own the canonical Agent Plugin ZIP, native packages,
checksums, SBOMs, provenance, installer support, tag, and release attestation. The
marketplace directory is an unpacked, byte-verified transport copy required by
Copilot.

GitHub documents that each Release may contain up to 1,000 assets under 2 GiB each,
with no total Release-size or bandwidth limit. Release immutability has no separate
documented billing SKU. Standard GitHub-hosted runners are free for public
repositories.

The current `v0.1.2` Release contains 56 assets totaling approximately 157.5 MiB.
Release assets are not Actions artifacts or Actions caches.

Repository Actions artifact/log retention is one day. Pull requests cannot persist
Rust or npm caches, and trusted caches are pruned to at most 5 GiB. Marketplace
implementation must not add another retained-artifact or cache dependency.

### Copilot cache is not authority

Copilot stores the installed plugin and remote marketplace source in replaceable
cache roots. Marketplace removal deletes the registration and installed plugin, but
may retain reusable source cache data.

Konclave's native runtime, profiles, service identity, authorization database,
credentials, and canonical client configuration remain outside Copilot caches.
Marketplace install, update, rollback, disablement, or removal cannot replace those
records.

### Managed configuration has precedence

An organization- or MDM-managed marketplace cannot be repointed by local user
configuration. The stable default-branch source therefore works for both individual
registration and centrally managed deployment without creating a separate branch
address.

## Assumptions

- The marketplace plugin remains a small bounded generated payload suitable for
  ordinary Git history.
- GitHub continues to recognize the documented default-branch catalog location.
- Immutable Releases remain the canonical source for plugin and native bytes.
- One synchronized version continues to identify the catalog entry, plugin manifest,
  extension package, Release manifest, and native runtime.
- The repository remains public and uses standard rather than larger hosted runners.

## Decision drivers

- Follow the documented and ecosystem-standard user path.
- Minimize user commands and non-obvious repository refs.
- Review every production marketplace change through ordinary branch protection.
- Preserve immutable Release provenance and exact plugin/native version binding.
- Avoid a write-capable mutable-branch publisher and its recovery state machine.
- Keep generated output bounded and mechanically verifiable.
- Keep the complete path within current no-cost GitHub facilities.

## Quantitative comparison

Scores use official compatibility and precedent (25), provenance and rollback (20),
credential and supply-chain simplicity (20), maintainer operations (15), no-cost
certainty (10), and source-history impact (10).

| Topology | Score / 100 | Main tradeoff |
| --- | ---: | --- |
| Immutable Releases plus catalog/plugin on `main` | 97 | Tracks one bounded generated extension bundle in reviewed source history |
| Immutable Releases plus a generated non-default branch | 80 | Keeps generated bytes off `main`, but adds a mutable surface, publisher, branch policy, and explicit-ref command |
| Immutable Releases plus a dedicated public distribution repository | 72 | Clean separation, but requires cross-repository authorization and synchronization |
| GitHub Release asset as the marketplace source | 20 | Immutable but unsupported because Copilot consumes Git directories |

## Decision

### Commit the standard marketplace layout to `main`

The production files are:

```text
.github/plugin/marketplace.json
plugins/konclave/plugin.json
plugins/konclave/com.github.copilot/extensions/konclave/package.json
plugins/konclave/com.github.copilot/extensions/konclave/extension.mjs
```

The marketplace name and plugin name are both `konclave`. The catalog uses the
repository-relative source `plugins/konclave`.

Users run:

```shell
copilot plugin marketplace add nexus-software-laboratories/konclave
copilot plugin install konclave@konclave
```

No production `marketplace` branch or separate distribution repository is created.

### Materialize only from an immutable Release

The marketplace tree is generated from the exact immutable
`konclave-<version>.zip`. It is never rebuilt independently and is never hand-edited.

The materializer must verify:

- the Release is published, immutable, and tied to the expected source commit;
- the archive digest and provenance match the Release contract;
- the archive contains exactly the three Agent Plugins 1.0 files;
- the catalog, plugin manifest, extension package, and Release use one exact version;
- the committed tree is byte-identical to the archive; and
- no source, tests, source maps, `node_modules`, native binaries, credentials,
  profiles, or authority state enter the marketplace directory.

The generated extension is reviewed as a deterministic Release output. Its source and
build logic remain under `extensions/Konclave.HostExtension/`.

### Publish the Release before exposing the marketplace update

For each version:

1. merge and validate the source change that produces the plugin and native packages;
2. publish and independently verify the immutable Release;
3. create a normal pull request that materializes the exact immutable plugin archive
   and updates the catalog on `main`;
4. run focused materialization and current/minimum Copilot marketplace acceptance; and
5. merge only after the matching native runtime is available and healthy.

This ordering prevents the catalog from advertising a plugin version before its
matching native Release exists.

### Keep updates and rollback reviewable

An update first publishes the immutable Release, then advances the marketplace files
through a normal pull request. Clients explicitly refresh and update:

```shell
copilot plugin marketplace update konclave
copilot plugin update konclave@konclave
```

A rollback restores the plugin files from a prior immutable Release through another
reviewed pull request and rolls the native installer back to the same version. Because
`plugin update` does not downgrade, clients refresh, uninstall, and reinstall:

```shell
copilot plugin marketplace update konclave
copilot plugin uninstall konclave@konclave
copilot plugin install konclave@konclave
```

Git history records both transitions without rewriting a distribution branch.

### Keep installation and authority separate

The native installer remains responsible for runtime verification, service
supervision, update, rollback, uninstall, and durable state retention. Marketplace
operations affect only Copilot's registration and replaceable plugin/cache state.

Supported installation changes from direct local plugin activation to marketplace
installation only after the committed marketplace passes lifecycle acceptance.
Direct activation remains a transitional recovery and development path.

### Use no paid distribution facility

The selected topology uses:

- the existing public repository;
- ordinary protected pull requests and Git history;
- standard public GitHub-hosted runners;
- immutable GitHub Releases; and
- the repository-scoped `GITHUB_TOKEN` for ordinary validation and release work.

It does not require larger runners, Git LFS, GitHub Packages, a second repository,
cross-repository credentials, retained Actions artifacts, paid signing, paid hosting,
or a paid marketplace.

## Serious alternatives

### Generated non-default branch

**Pros:** Keeps generated plugin bytes out of `main` and permits atomic ref updates.

**Cons:** Requires `#marketplace` in the user command, creates a second mutable
publication surface, needs a write-capable publisher and branch recovery policy, and
complicates rollback. Rejected because the generated file is bounded and the standard
default-branch path is simpler.

### Dedicated distribution repository

**Pros:** Keeps a minimal marketplace tree on its default branch and permits separate
administration.

**Cons:** Adds repository lifecycle, cross-repository credentials, synchronization,
and another provenance boundary without improving the client experience. Rejected.

### Release asset source

**Pros:** Reuses the canonical immutable ZIP directly.

**Cons:** Copilot marketplace sources are Git directories, not Release archives.
Rejected as unsupported.

### Permanent direct installation

**Pros:** Already works with the three-file archive.

**Cons:** Emits a deprecation warning and lacks supported marketplace discovery and
update semantics. Retained only as a transitional path.

## Consequences

### Positive

- Users follow the conventional `owner/repo` registration command.
- Every marketplace change passes ordinary pull-request review and branch protection.
- Immutable Releases remain the artifact and rollback authority.
- No branch publisher, cross-repository token, or second repository is required.
- Organization-managed and individual installations use the same stable source.
- Marketplace cache replacement cannot affect native or authority state.
- The complete topology remains no-cost under current GitHub facilities.

### Negative

- Each marketplace update commits one generated extension bundle to `main`.
- Git history grows by the bounded plugin payload on each release.
- Each version requires an accepted source commit and immutable Release before a
  separate marketplace pull request.
- Plugin downgrade requires uninstall and reinstall.

### Neutral

- Native binaries remain outside the plugin.
- Existing explicit-ref acceptance remains useful regression coverage.
- Signing and notarization remain independent hardening work.

## Confidence and falsifiers

**Confidence: 98/100.**

Reconsider this decision if:

- GitHub changes the documented default-branch marketplace contract;
- the generated plugin becomes too large for ordinary source history;
- deterministic Release-to-tree verification cannot be maintained;
- organization policy requires a separate administration boundary;
- marketplace cache acquires native or authority ownership; or
- the topology requires a paid GitHub facility.

## Confirmation and prerequisites for #108

Implementation must:

- deliver pure deterministic materialization and verification decisions with focused
  tests before integrating the marketplace files;
- add a draft-running GitHub-hosted marketplace conformance gate and observe it on the
  exact foundation head;
- materialize only from immutable `v0.1.2` Release bytes for the initial marketplace;
- commit exactly the four production files and no branch-based catalog;
- verify byte identity, version synchronization, provenance, schemas, and exclusions;
- test registration without a ref suffix on current and minimum Copilot CLI versions;
- test install, explicit update, rollback/reinstall, disable/enable, removal,
  reinstall, managed-policy precedence, and cache isolation;
- update supported installation documentation after lifecycle acceptance; and
- leave Actions artifacts at one-day retention with zero unnecessary retained
  storage.

## References

- [Creating a plugin marketplace](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-marketplace)
- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [Agent Plugins 1.0 specification](https://github.com/agentplugins/agent-plugins-spec/blob/main/spec/1.0.0.md)
- [About GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
- [Immutable Releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [ADR 0021: Generated marketplace branch](adr-0021-generated-marketplace-branch.md)
- [Installation and cache authority contract](../distribution/installation.md)
- [Issue #208](https://github.com/nexus-software-laboratories/konclave/issues/208)
- [Hosted marketplace compatibility run 34831489855](https://github.com/nexus-software-laboratories/konclave/actions/runs/34831489855)
