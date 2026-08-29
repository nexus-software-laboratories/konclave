# A2A protocol v1.0.1 source

This directory vendors the unmodified normative `specification/a2a.proto` from the
Linux Foundation Agent2Agent Protocol release `v1.0.1`. The release advertises A2A
protocol version `1.0`.

`provenance.json` records the exact upstream repository, tag, commit, Git blob
identifiers, byte lengths, SHA-256 digests, and Apache-2.0 license. `LICENSE` is the
upstream release license.

The three files under `google/api/` are generation-only option stubs from the official
`a2aproject/a2a-rs` repository at the pinned commit in `provenance.json`. They let
`protoc` interpret the canonical schema's HTTP, method-signature, and field-behavior
options without importing a runtime SDK or the full Google APIs schema tree. They do
not define Konclave behavior and are not A2A wire authority.

Do not edit vendored files. Updating A2A requires a new versioned directory, updated
provenance, generated-contract review, compatibility evidence, and immutable fixtures.
