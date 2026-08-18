---
applyTo: ".github/workflows/**/*.yml,.github/actions/**/*.yml,scripts/delivery/**/*.ps1,**/*.md"
scope: "public repository privacy and self-hosted runner trust boundary"
---

# Public repository boundary

- Never mention private repository names, paths, service topology, credentials,
  databases, incidents, issues, or implementation plans in tracked files, commits,
  issues, pull requests, or workflow output.
- Treat fork pull requests and outside collaborators as untrusted. They must not
  schedule any PitCrew job, including metadata-only jobs.
- Public pull-request workflows that can reach PitCrew must be defined by the default
  branch through `pull_request_target` or an equivalent trusted control plane.
- Gate every PitCrew entry job on an exact same-repository head before runner
  assignment. Never use an empty or base-repository fallback for missing head data.
- Never check out or execute a fork head from `pull_request_target`. Maintainers
  reproduce accepted external changes on a same-repository branch before validation.
- Pin third-party actions to full commit SHAs and keep repository Actions permissions
  read-only by default.
- Configure public fork workflow approval for all external contributors as
  defense-in-depth; approval does not make fork code safe for self-hosted execution.
