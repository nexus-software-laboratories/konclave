---
applyTo: "Cargo.toml,crates/**/Cargo.toml,apps/**/Cargo.toml,crates/Konclave.*Security/**/*.rs,crates/Konclave.CryptographicCore/**/*.rs,crates/Konclave.LocalAuthorizationStore/**/*.rs,crates/Konclave.LocalServiceTransport/**/*.rs,apps/Konclave.LocalDaemon/**/*.rs,.github/workflows/**/*.yml"
scope: "new crates and security-sensitive state machines"
---

# Security-sensitive delivery

- Invoke `.github/skills/security-sensitive-delivery/SKILL.md` before implementing a
  new crate or security-sensitive state machine.
- Land the component and focused tests in one bounded foundation commit, then add its
  GitHub-hosted component workflow before any daemon, adapter, client, or packaging
  integration.
- Do not begin integration until the focused check passes on the exact foundation
  head.
- Keep error classifiers and state transitions pure and cover their finite decisions
  with table-driven tests.
- Validation claims name the exact command or check that executed the relevant tests;
  builds and unrelated workflows are not substitute evidence.
- Complete workspace, platform, package, and acceptance matrices run only after the
  focused component gate is green.
