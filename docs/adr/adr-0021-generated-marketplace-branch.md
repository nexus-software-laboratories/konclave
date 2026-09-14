---
title: Keep immutable artifacts in Releases and publish the marketplace tree on a generated branch
status: Accepted
date: 2026-09-14
authors:
  - Konclave maintainers
tags:
  - copilot
  - distribution
  - marketplace
  - releases
supersedes: []
superseded_by: []
---

# Keep immutable artifacts in Releases and publish the marketplace tree on a generated branch

## Context and scope

Konclave distributes one Agent Plugins 1.0 payload and a matching native runtime.
The native runtime is installed and supervised outside Copilot's replaceable plugin
cache. The plugin archive is a three-file portable artifact, while Copilot
marketplaces consume a Git directory containing an unpacked plugin and a
`marketplace.json` catalog.

The distribution topology must therefore provide:

- an immutable canonical copy of every released plugin and native artifact;
- a Git-backed marketplace source accepted by supported Copilot CLI versions;
- deterministic install, update, rollback, disablement, and removal;
- exact plugin/native version and provenance binding;
- no generated plugin bundle or marketplace catalog in ordinary `main` history;
- no cross-repository credential or synchronization boundary; and
- no paid repository, runner, storage, signing, hosting, or marketplace feature.

This decision owns the public repository and ref topology, canonical artifact
location, publication ordering, update and rollback model, cache authority boundary,
and prerequisites for marketplace implementation. It does not create the production
catalog or branch, change supported installation commands, or implement marketplace
publication.

## Verified facts

### Copilot and Agent Plugins contracts

- Copilot CLI discovers a marketplace through `.github/plugin/marketplace.json`.
  A user-added source may be `owner/repo`, `owner/repo#ref`, a Git URL, or a local
  path. Marketplace refresh and plugin update are separate operations.
- A marketplace entry may use a repository-relative plugin directory or a GitHub/Git
  source object with optional `ref`, `path`, and full 40-character `sha`.
- Agent Plugins 1.0 defines a directory package. It does not define a GitHub Release
  archive as a marketplace transport.
- Copilot installs marketplace plugins under its replaceable installed-plugin root.
  Remote marketplace repositories use a separate platform source cache, overridable
  with `COPILOT_CACHE_HOME`.
- User-added marketplaces use explicit catalog refresh and plugin update by default.
  Session-start auto-update is opt-in for user marketplaces and is skipped in CI, so
  the supported release flow does not depend on implicit refresh timing.
- `marketplace remove --force` unregisters the marketplace and removes its installed
  plugins. The reusable remote-source cache may remain until ordinary cache cleanup;
  it is not installed plugin state or Konclave authority state.
- An organization- or MDM-managed marketplace entry cannot be repointed locally.
  Managed configuration replaces the same-named user entry and therefore remains an
  administrative trust boundary rather than a local fallback.
- The short CLI `marketplace add --help` text does not enumerate refs, and the older
  open [github/copilot-cli#1296](https://github.com/github/copilot-cli/issues/1296)
  records that branch and tag syntax was previously unavailable or untested. The
  current official reference and the hosted current/minimum CLI results are the
  authoritative evidence for this decision.
- Konclave's canonical service configuration, profiles, service identity, and local
  authorization database live outside both Copilot cache roots. Replacing or removing
  a plugin cannot replace those authority records.

The current command and manifest contracts are documented by:

- [Creating a plugin marketplace for GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-marketplace);
- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference); and
- [Agent Plugins 1.0 specification](https://github.com/agentplugins/agent-plugins-spec/blob/main/spec/1.0.0.md).

### Hosted ref and lifecycle evidence

The repository's
[`Marketplace branch acceptance`](../../.github/workflows/marketplace-branch-acceptance.yml)
workflow creates two unique non-default branches from an exact default-branch head.
It materializes only the catalog, the three-file Konclave plugin, and a root source
record. It then exercises current and minimum supported Copilot CLI versions in
isolated homes.

[Hosted run 34831489855](https://github.com/nexus-software-laboratories/konclave/actions/runs/34831489855)
passed on source commit
`d3c3d1607d894a6c2d69550ea48d867e622b3c1c`. Both Copilot CLI `1.0.82`
and `1.0.84-5`:

1. accepted `nexus-software-laboratories/konclave#<ephemeral-branch>`;
2. listed and browsed the run-owned marketplace;
3. installed exactly the three Konclave plugin files at version `0.1.2`;
4. refreshed the catalog and updated the plugin to a synthetic `0.1.3`;
5. accepted an exact branch rollback;
6. refreshed, uninstalled, and reinstalled version `0.1.2`; and
7. removed the marketplace registration and installed plugin.

The workflow isolated Copilot configuration and source caches under one run-owned
root, deleted that root on exit, deleted both remote branches in a separate bounded
cleanup job, and retained no workflow artifacts.

[Hosted run 34828964031](https://github.com/nexus-software-laboratories/konclave/actions/runs/34828964031)
also passed the complete native install, supervision, update, failed-update recovery,
rollback, plugin activation, and uninstall lifecycle from immutable `v0.1.0` to
immutable `v0.1.2`. The run executed the candidate release's own installer support,
not source-overlay installer files.

### Canonical immutable artifacts

GitHub Releases are based on Git tags and accept up to 1,000 assets per release, each
under 2 GiB, without a total release-size or bandwidth limit. Immutable Releases lock
the associated tag and assets and create a release attestation.

Konclave `v0.1.2` is an immutable prerelease with 56 assets. Its tag identifies source
commit `716350fd8a2e932a379ea4cd7e024c6b360aa616`. The release includes:

- `konclave-0.1.2.zip`, the canonical three-file Agent Plugin;
- matching checksums, SBOM, and provenance;
- native client, relay, and gateway archives;
- container archives and provenance; and
- independently usable release verification and installer support.

The release is the immutable artifact authority. A marketplace branch contains a
verified unpacked transport copy because Copilot requires a Git directory, not
because mutable branch bytes replace Release provenance.

GitHub documents the applicable guarantees in
[About releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
and
[Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

### First-party precedent

At the inspected heads:

- [`github/copilot-plugins`](https://github.com/github/copilot-plugins/tree/fbf7c536a5c7af0c94ff5f528a39004c55129e6d)
  contains 17 catalog entries: 2 repository-relative and 15 external GitHub sources.
- [`github/awesome-copilot`](https://github.com/github/awesome-copilot/tree/1899b18da3fa5183652f86165917d553cba1850a)
  contains 155 catalog entries: 100 repository-relative and 55 external sources.
  Of the external entries, 28 declare `ref`, 31 declare `sha`, and 10 declare
  neither; some declare both.
- The awesome-copilot generated
  [`marketplace` branch](https://github.com/github/awesome-copilot/tree/e46a214376b935d26a373cd6d3620f3a4f3de00e)
  has 1,783 `plugins/` tree entries versus 312 on `main`.
- Its pinned
  [publisher](https://github.com/github/awesome-copilot/blob/1899b18da3fa5183652f86165917d553cba1850a/.github/workflows/publish.yml)
  runs on `ubuntu-latest`, grants same-repository `contents: write`, materializes the
  distribution tree, verifies the remote branch tip, and atomically updates the
  generated branch with the repository's `GITHUB_TOKEN`.

This is direct first-party evidence for keeping source on `main` while publishing a
materialized distribution branch in the same repository.

### Ecosystem sample

The sample covers twelve maintained, non-archived public repositories with complete,
non-truncated Git trees. Ten contain their own marketplace catalog; the two without
one are implementation repositories referenced by an external catalog.

| Repository and inspected head | Observed topology |
| --- | --- |
| [`github/copilot-advanced-security-plugin@9c8cd1a`](https://github.com/github/copilot-advanced-security-plugin/tree/9c8cd1a00c1290bf89db8f068aded1fb5dace200) | Dedicated plugin implementation repository referenced by an external catalog |
| [`microsoft/work-iq@bcc10b3`](https://github.com/microsoft/work-iq/tree/bcc10b3a10d7e423b879c38178b1212b2c733d2e) | Implementation monorepo with multiple plugin directories and catalogs |
| [`microsoft/azure-devops-copilot-plugin@8f30ba3`](https://github.com/microsoft/azure-devops-copilot-plugin/tree/8f30ba3210758239be19e2143943e0830f07601a) | Dedicated plugin implementation repository with its own catalog |
| [`microsoft/skills-for-fabric@24cc0d2`](https://github.com/microsoft/skills-for-fabric/tree/24cc0d296e5e8523cc6a92e1342bc1791d7deb85) | Implementation and plugin monorepo with multiple client catalogs |
| [`microsoft/cpp-language-server@b321661`](https://github.com/microsoft/cpp-language-server/tree/b321661e710eef3d8de5060b413c414cacd29c97) | Product repository with a plugin subdirectory referenced externally |
| [`microsoft/power-platform-skills@8a36dab`](https://github.com/microsoft/power-platform-skills/tree/8a36dab9261371d900748d92cb8182a3952d195c) | Multi-plugin implementation repository with catalogs |
| [`apify/apify-github-copilot-plugin@a88bbba`](https://github.com/apify/apify-github-copilot-plugin/tree/a88bbba24378d0a6e00e788de0772d519307658f) | Plugin repository with its own marketplace |
| [`cockroachdb/copilot-plugin@af7c332`](https://github.com/cockroachdb/copilot-plugin/tree/af7c332399cd326dad898c16d15a5adcf6ab8a1f) | Plugin repository with its own marketplace |
| [`atlassian-labs/twg-plugins@d464e72`](https://github.com/atlassian-labs/twg-plugins/tree/d464e72e7750589e0f0867f171d2dd1d6eece924) | Multi-client plugin repository with several marketplace manifests |
| [`ChromeDevTools/chrome-devtools-mcp@d9a8cb6`](https://github.com/ChromeDevTools/chrome-devtools-mcp/tree/d9a8cb6ec22aadf5cb964c5e97a8b047693046e2) | Product repository with client manifests and an externally referenced plugin |
| [`fastrepl/anarlog@fdd56bf`](https://github.com/fastrepl/anarlog/tree/fdd56bf6e93a6b392266fd946cf5eb9af68aad1f) | Product monorepo with several client catalogs and plugin directories |
| [`ncosentino/pitcrew@3c6106c`](https://github.com/ncosentino/pitcrew/tree/3c6106cb9ab45870897853522e5eb926250a29d6) | Same repository contains the marketplace and plugin source |

The sample shows several valid implementation layouts. It does not show a requirement
to create a second distribution repository for one product, and none uses a Release
archive as the Copilot marketplace source.

### No-cost and credential boundaries

- Standard GitHub-hosted runners are free and unlimited for public repositories.
- The existing public repository and its ordinary Git refs require no paid
  marketplace or hosting feature.
- `GITHUB_TOKEN` is scoped to the repository containing the workflow. Same-repository
  publication therefore needs no personal access token or separately installed
  GitHub App.
- Durable artifacts use Releases rather than retained Actions artifacts. Publication
  and acceptance workflows delete their transient artifacts.
- Code signing is not required by this topology. Unsigned prerelease status remains
  explicit until the separate signing decision is implemented.

The runner and token boundaries are documented by
[Choosing the runner for a job](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
and
[`GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token).

## Assumptions

- GitHub continues to support `owner/repo#ref` for user-added Copilot marketplaces on
  the declared minimum CLI version.
- The repository continues to permit a trusted default-branch workflow to update one
  non-default distribution branch with job-scoped `contents: write`.
- Copilot's marketplace cache remains replaceable implementation data and never
  becomes a storage location for Konclave authority, profiles, or native runtime
  state.
- The Agent Plugin remains small enough to materialize directly in Git and each
  Release remains within documented asset limits.
- Native and plugin compatibility continue to use one synchronized release version.

## Decision drivers

- Use only source forms implemented and accepted by supported Copilot CLI versions.
- Keep immutable Release provenance canonical even though marketplace transport is
  Git-based.
- Avoid generated bundle churn in ordinary implementation history.
- Avoid a cross-repository token, publisher, and provenance boundary.
- Make publication atomic, deterministic, reviewable, recoverable, and fail-closed.
- Keep native installation and authority independent from plugin cache replacement.
- Preserve a no-cost path on standard public hosted infrastructure.

## Quantitative comparison

Scores use six weighted criteria: official compatibility and precedent (25),
provenance and rollback (20), credential and supply-chain simplicity (20),
maintainer operations (15), no-cost certainty (10), and clean source history (10).
The score is a comparative engineering judgment, not a vendor guarantee.

| Topology | Score / 100 | Main advantages | Main costs or risks |
| --- | ---: | --- | --- |
| Immutable Releases plus a generated same-repository `marketplace` branch | 96 | Hosted ref semantics proven on both supported CLIs; canonical immutable artifacts; repository-scoped token; clean `main` | Requires a trusted deterministic publisher and explicit branch registration |
| Immutable Releases plus a committed minimal marketplace subtree on `main` | 86 | Simplest registration and update path; no generated branch publisher | Commits built extension bytes and catalog churn into implementation history |
| Immutable Releases plus a dedicated public distribution repository | 73 | Clean distribution-only default branch and independent administration | Requires cross-repository credentials, synchronization, and another provenance boundary |
| GitHub Release asset as the plugin source | 20 | Artifact is already immutable | Disqualified: Copilot marketplace sources are Git directories, not Release archives |

## Decision

### Keep Releases canonical

Every supported version continues to publish one complete immutable GitHub
prerelease from the validated `main` source commit. The Release owns the canonical
Agent Plugin ZIP, native archives, checksums, SBOMs, provenance, installer support,
and release attestation.

Marketplace publication never rebuilds the plugin. It consumes the exact immutable
plugin archive and verifies its digest, provenance source commit, version, and
three-file allowlist before materialization.

### Publish one generated branch in the existing repository

The production marketplace source is:

```text
nexus-software-laboratories/konclave#marketplace
```

The generated branch contains only:

```text
.github/plugin/marketplace.json
SOURCE.json
plugins/konclave/plugin.json
plugins/konclave/com.github.copilot/extensions/konclave/package.json
plugins/konclave/com.github.copilot/extensions/konclave/extension.mjs
```

`SOURCE.json` is branch-level provenance and is not inside the installed plugin
directory. It binds at least the immutable Release tag, Release source commit,
plugin archive SHA-256, materialized plugin version, and publication workflow commit.

The catalog uses marketplace name `konclave`, one relative source
`plugins/konclave`, and the exact Release version. The catalog, plugin manifest,
extension package, Release manifest, and native installer contract must all agree.

`main` retains source, tests, packaging logic, and acceptance workflows. It does not
track the production catalog or generated extension bundle.

### Restrict publication to trusted validated inputs

The publisher runs only from the exact current default-branch head after the matching
immutable Release exists and has passed release verification. It uses standard
GitHub-hosted capacity, job-scoped `contents: write`, a repository-scoped
`GITHUB_TOKEN`, and no long-lived credential.

The publisher:

1. downloads and independently verifies the immutable plugin artifact;
2. creates the complete allowlisted branch tree outside the source working tree;
3. validates catalog and plugin schemas, exact versions, file modes, digests, and
   provenance;
4. creates one reviewable distribution commit;
5. re-reads the remote branch tip and rejects an unexpected concurrent update; and
6. publishes the complete ref change atomically.

Pull requests and fork-controlled code never receive branch-write credentials.

### Separate install, update, and rollback

The supported install order is:

1. install and health-check the matching native runtime from the immutable Release;
2. add `nexus-software-laboratories/konclave#marketplace`;
3. install `konclave@konclave`; and
4. restart existing Copilot sessions when activation changes.

An update publishes and verifies the new immutable Release first, then advances the
marketplace branch. Clients refresh the marketplace and update the plugin only after
the matching native runtime is healthy. Managed deployments may configure the same
stable marketplace source centrally; local configuration cannot override that source.

A rollback rematerializes the prior immutable plugin archive as a new reviewed branch
snapshot and rolls the native installer back to the same Release version. Because
plugin update is an upgrade operation rather than a downgrade command, clients
refresh the marketplace, uninstall `konclave@konclave`, and reinstall it. The hosted
acceptance proved this exact refresh, uninstall, and reinstall behavior after the
source ref returned to the prior payload.

The mutable branch is a current distribution pointer. Immutable Release bytes and
their provenance remain the rollback authority.

### Treat every Copilot cache as replaceable

Marketplace source caches and installed plugin files may be replaced or removed
without migration. They contain no Konclave profiles, service identity, authorization
database, relay credential, native binary, or canonical client configuration.

Marketplace removal must remove the registration and installed plugin. It need not
purge Copilot's reusable remote-source cache. Installer uninstall and permanent
Konclave state removal remain separate explicit operations.

## Serious alternatives

### Commit the marketplace subtree to `main`

**Pros:** This is the simplest documented registration path, uses the same repository
token boundary, and makes every catalog change visible in an ordinary source PR.

**Cons:** The compiled extension and synchronized catalog are release outputs rather
than maintained source. Committing them duplicates the immutable archive, creates
large generated diffs in implementation history, and makes source review compete with
distribution-byte review. Rejected because the hosted non-default-ref lifecycle is
now proven.

### Create a dedicated public distribution repository

**Pros:** Its default branch could be a minimal catalog and plugin tree with an
independent administration boundary.

**Cons:** `GITHUB_TOKEN` cannot publish across repositories. A PAT or GitHub App,
cross-repository authorization, synchronization recovery, and a second audit boundary
would become mandatory without improving client compatibility or artifact
immutability. Rejected unless future organization policy requires separate
administration.

### Install the plugin directly from a Release asset

**Pros:** The plugin ZIP is already immutable, verified, and paired with native
artifacts.

**Cons:** Copilot marketplace and direct plugin sources are Git repositories,
directories, or Git URLs. Agent Plugins 1.0 specifies a directory package, not an
archive transport. Rejected as unsupported.

### Use direct plugin installation permanently

**Pros:** The current three-file archive already installs and isolates cleanly.

**Cons:** Current Copilot CLI emits a deprecation warning, and direct installation
does not provide the supported marketplace discovery, refresh, and update contract.
Rejected as a pre-marketplace compatibility path only.

## Consequences

### Positive

- Immutable Releases remain the single artifact and provenance authority.
- Users receive the supported marketplace install and update experience.
- Generated extension bytes and catalog churn stay out of `main`.
- Publication uses no cross-repository or long-lived credential.
- Plugin cache replacement cannot replace native or authority state.
- The selected runner, repository, Git ref, Release, and marketplace features are
  no-cost for this public project.
- The topology matches first-party generated-branch precedent and has executable
  evidence on both supported Copilot CLI versions.

### Negative

- A trusted branch publisher becomes a release-critical state machine.
- Users must specify `#marketplace` when registering the marketplace.
- Publication has two durable surfaces: an immutable Release and a mutable current
  branch pointer.
- Plugin rollback requires refresh plus uninstall/reinstall rather than ordinary
  `plugin update`.
- Copilot may retain a replaceable remote-source cache after marketplace removal.

### Neutral

- Native binaries remain outside the Agent Plugin.
- Marketplace publication does not change local authorization, cryptographic custody,
  relay, or profile trust boundaries.
- A future first-party catalog may reference the same immutable plugin source without
  changing the native Release or local installer contract.
- Signing and notarization remain separate hardening work.

## Confidence and falsifiers

**Confidence: 96/100.**

The score is below 100 because the production publisher and branch policy do not yet
exist, and external CLI behavior can change.

Reconsider this decision if:

- the declared minimum Copilot CLI stops accepting or refreshing `owner/repo#ref`;
- organization policy forbids a generated same-repository distribution branch;
- atomic publication cannot reject concurrent or partially materialized updates;
- the materialized tree cannot be reproduced exactly from an immutable Release;
- marketplace or plugin cache acquires authority or native-runtime ownership;
- the selected flow requires a paid runner, repository, storage, signing, hosting, or
  marketplace capability; or
- a supported immutable non-Git marketplace source is documented and implemented.

## Confirmation and prerequisites for implementation

Marketplace implementation remains blocked until explicit maintainer sign-off on
this accepted decision. The implementation issue must then:

- follow the repository's security-sensitive delivery procedure for the publisher's
  materialization and ref-transition state machine;
- add pure deterministic catalog/tree/provenance decisions and focused tests before
  write-capable workflow integration;
- publish only from an exact trusted default-branch head after immutable Release
  verification;
- enforce the five-file branch allowlist and reject source, tests, `node_modules`,
  native binaries, credentials, profiles, or authority state;
- use atomic remote-tip-checked publication with bounded failure and recovery;
- preserve exact plugin/native version synchronization and independently verified
  archive bytes;
- retain hosted current/minimum CLI install, update, rollback, remove, cache-isolation,
  and branch-cleanup acceptance;
- verify that user configuration cannot override a same-named managed marketplace
  source and that explicit refresh remains deterministic when auto-update is disabled;
- update installation documentation only after the production branch exists and
  passes lifecycle acceptance; and
- keep direct local plugin activation as an explicitly transitional compatibility
  path rather than the supported marketplace install.

## References

- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [Creating a plugin marketplace](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-marketplace)
- [Agent Plugins 1.0 specification](https://github.com/agentplugins/agent-plugins-spec/blob/main/spec/1.0.0.md)
- [GitHub Actions `GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token)
- [Standard hosted runners for public repositories](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
- [About GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
- [Immutable Releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [ADR 0008: Shared per-user local service](adr-0008-shared-local-service.md)
- [Installation and cache authority contract](../distribution/installation.md)
- [Issue #208](https://github.com/nexus-software-laboratories/konclave/issues/208)
- [Marketplace branch acceptance run 34831489855](https://github.com/nexus-software-laboratories/konclave/actions/runs/34831489855)
- [Exact `v0.1.2` lifecycle run 34828964031](https://github.com/nexus-software-laboratories/konclave/actions/runs/34828964031)
