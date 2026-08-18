# Rust engineering conventions

Generated Rust repositories use path-scoped instructions for CLI design, workspaces,
libraries, async services, unsafe code, dependencies, testing, data boundaries, and
observability. A rule applies only when the matching code or manifest exists; adding
Rust guidance does not turn every crate into a service or require every specialized
verification tool.

## Design boundaries

- Keep workspace policy at the root and crate responsibilities narrow.
- Treat public library APIs, errors, features, and documentation as compatibility
  commitments.
- Give long-running tasks explicit ownership, cancellation, backpressure, and observed
  shutdown.
- Prefer safe Rust and isolate every necessary unsafe invariant behind a safe API.
- Validate and bound untrusted data before allocation, persistence, or side effects.
- Keep diagnostics structured and keep secrets and protocol payloads out of logs.

Context-specific tools remain evidence-driven:

- Miri is appropriate for unsafe and undefined-behavior-sensitive code.
- Loom is appropriate for small concurrency primitives.
- Fuzzing and property tests are appropriate for parsers and state machines.
- Snapshot tests are useful only when the reviewed snapshot is a meaningful contract.
- MSRV, no-default-feature, and all-feature jobs belong in CI only when the repository
  supports those compatibility surfaces.

## Research basis

The conventions synthesize current public guidance rather than copying one
repository's local policy:

- [The Rust project contributor instructions](https://github.com/rust-lang/rust/blob/master/AGENTS.md)
  demonstrate test selection, invariant-focused comments, and high-stakes safety
  boundaries.
- [Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html),
  [workspace inheritance](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace),
  and [features](https://doc.rust-lang.org/cargo/reference/features.html) define the
  root/member and additive-feature contracts.
- [The Rust API guidelines](https://rust-lang.github.io/api-guidelines/) and
  [rustdoc](https://doc.rust-lang.org/rustdoc/) inform public API and documentation
  expectations.
- [Tokio's contributor documentation](https://github.com/tokio-rs/tokio/tree/master/docs/contributing)
  provides context for async testing, feature compatibility, Loom, and MSRV.
- [The Rustonomicon](https://doc.rust-lang.org/nomicon/) and
  [`unsafe_op_in_unsafe_fn`](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html#unsafe-op-in-unsafe-fn)
  define explicit unsafe proof obligations.
- [Miri](https://github.com/rust-lang/miri), the
  [Rust fuzz book](https://rust-fuzz.github.io/book/), and
  [Loom](https://github.com/tokio-rs/loom) define specialized verification boundaries.
- Public instructions from
  [Ruff](https://github.com/astral-sh/ruff/blob/main/AGENTS.md),
  [uv](https://github.com/astral-sh/uv/blob/main/CONTRIBUTING.md),
  [OpenMLS](https://github.com/openmls/openmls/blob/main/CONTRIBUTING.md),
  [Windows Drivers Rust](https://github.com/microsoft/windows-drivers-rs/blob/main/AGENTS.md),
  [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/AGENTS.md),
  and [Orb Software](https://github.com/worldcoin/orb-software/blob/main/AGENTS.md)
  reinforce narrow visibility, workspace lint inheritance, public documentation, and
  isolated `SAFETY` explanations.

Repository-specific contribution bans, nightly-only formatting, blanket pedantic
lints, mandatory snapshot frameworks, `panic = "abort"`, and universal use of Miri,
Loom, fuzzing, or alternative test runners are intentionally not generalized.
