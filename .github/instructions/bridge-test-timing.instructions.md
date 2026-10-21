---
applyTo: "crates/Konclave.A2AKonclaveBridge/src/tests.rs,crates/Konclave.A2AKonclaveBridge/Cargo.toml,scripts/ci/Test-BridgeTestTiming.ps1"
---

# Bridge test timing

- Run bridge fixture async tests on paused, current-thread Tokio time; retain the
  development-only `test-util` feature. Do not increase fixture deadlines to hide
  scheduler or SQLite latency.
- Derive business timestamps from the same simulated elapsed time, not clock-read
  counts. Keep synchronous persistence in the production blocking-task boundary.
- Wait for an observable history or watch event before explicitly advancing time.
  An always-ready history loop prevents idle auto-advance even when it yields, so
  its deadline test must advance time explicitly after history observation starts.
- Preserve exact-response, retry identity, cancellation, capacity, and deadline
  assertions. Run the static timing contract when changing the fixture or manifest.
