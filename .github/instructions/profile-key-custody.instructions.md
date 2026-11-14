---
applyTo: "crates/Konclave.SecretStorage/**,crates/Konclave.WindowsSecurity/**,apps/Konclave.LocalDaemon/src/{runtime,persistence,relay_migration}.rs,apps/Konclave.CommandLine/src/doctor.rs,extensions/Konclave.HostExtension/src/runtime.ts"
scope: "Profile key allocation and Windows credential resource isolation"
---

# Profile key custody

- Windows native profile KEKs use independent user-scoped DPAPI-protected,
  owner-only files. Never allocate a Windows Credential Manager record per harness
  session/profile; installation-scoped service/enrollment records are separate.
- Hold the profile lock before runtime custody or database opening. Missing keys
  with dependent/unexplained state, malformed files and provider failures fail
  closed; never regenerate, overwrite, migrate or fall back implicitly.
- Do not merge session identities, introduce a shared master KEK, or infer safe
  identity retirement from age, empty application tables or an idle runtime.
- Preserve real Windows tests proving repeated profile creation/reopen does not
  increase profile Credential Manager entries, retained identity reopens, and
  missing/corrupt custody causes no replacement or database side effects.
