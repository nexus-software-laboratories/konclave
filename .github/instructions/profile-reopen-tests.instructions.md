---
applyTo: "apps/Konclave.LocalDaemon/src/persistence.rs"
---

# Profile reopen tests

- When adding or modifying a startup or tamper test that reacquires a profile, consume
  the fixture through its close helper so every `ProfileStore` and database guard is
  dropped first.
- Do not partially move the fixture root and manually drop only one known store field
  in new or changed tests; that can leave profile ownership implicit and make parallel
  execution flaky.
