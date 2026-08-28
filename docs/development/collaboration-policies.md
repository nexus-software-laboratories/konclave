# Collaboration policy contracts

ADR 0011 separates editable policy sources, immutable shared bundles, and local
conversation bindings. This page owns the evolving implementation contract; it does
not make a hosted registry or one authoring syntax part of the core protocol.

## Implemented core bundle

The source-independent `CollaborationPolicyBundle` is a bounded protocol-v1 contract.
It contains:

- protocol version and canonical human-readable name;
- optional model guidance;
- canonically ordered statements;
- canonically ordered required harness claims; and
- fully resolved optional duration, turn, token, and concurrency limits.

Each statement has a canonical identifier, one primitive effect, one namespaced
action, and an optional namespaced resource. Effects are `allow`, `deny`, and
`require-local-approval`. Action, resource, and harness-claim identifiers are
extensible canonical strings rather than product-defined collaboration modes.

The bundle uses a 64 KiB encoded limit, at most 256 statements, and at most 64
required harness claims. Names, identifiers, guidance, repeated fields, numeric
limits, unknown effects, and top-level Protobuf fields are validated before the
bundle reaches evaluation or persistence.

Canonical construction sorts statements by statement identifier and harness claims
lexically. Duplicate identifiers are invalid. Wire decoding re-encodes the validated
domain value and rejects bytes that differ, so alternate field or collection ordering
cannot create multiple accepted encodings of the same bundle.

The content identifier is:

```text
SHA-256(
  "konclave-collaboration-policy-bundle-digest-v1\0" ||
  canonical CollaborationPolicyBundle bytes
)
```

Names and source locations are not identity. Rust and TypeScript share one immutable
binary fixture and expected digest.

## Optional limits

Canonical bundle limits are already materialized:

- an absent duration, turn, token, or concurrency field means explicitly unlimited;
- a present value must be positive; and
- mandatory parser, frame, queue, journal, and storage bounds are outside the policy
  and cannot be disabled.

An omitted source limit represents inheritance. The current compiler accepts one
fully materialized caller-default set and resolves source values against it before
producing canonical bytes. Future activation and provider layers own the precedence
between activation overrides, user defaults, provider defaults, and shipped defaults.

## Source and catalog boundary

The implemented source compiler accepts bounded strict JSON with API version
`konclave.dev/v1` and kind `CollaborationPolicy`. Unknown fields, unsupported effects,
oversized arrays, malformed canonical identifiers, zero finite limits, and trailing
content fail closed. Editable sources may order statements and harness claims
arbitrarily; compilation canonicalizes them before encoding and digesting.

Missing source limits inherit from caller-provided defaults. Explicit JSON `null`
means unlimited, and a positive integer is a finite override. No inherited or
unresolved value crosses into the canonical bundle.

The explicit file catalog is one bounded JSON descriptor containing a schema version
and listed name-to-source mappings. It never scans its directory. Sources must be
regular `.json` files that physically resolve beneath the descriptor's directory;
duplicate names, duplicate paths, traversal, absent files, and source-name mismatch
fail closed.

Future source providers compile into the same bundle:

- explicit user catalog;
- explicitly selected repository proposal;
- bundle received through a conversation;
- configured self-hosted provider; or
- configured hosted provider.

Provider names and mutable URLs are not persisted as policy authority. Activation
pins canonical bytes and their digest.

The command-line surface operates only on explicit paths:

```text
konclave policy create --name <policy-name> --output <new-source.json>
konclave policy validate --source <source.json>
konclave policy inspect --source <source.json>
konclave policy compile --source <source.json> --output <new-bundle.bin>
konclave policy diff --left <source.json> --right <source.json>
konclave policy list --catalog <catalog.json>
konclave policy validate-catalog --catalog <catalog.json>
```

Create and compile use exclusive file creation and never overwrite existing content.
Inspect and validation output only bounded names, digests, counts, and resolved limits;
model guidance and complete policy bodies are not printed. The repository includes
schemas and editable examples, but repository presence never activates them.

## Binding and exchange boundary

Profile schema version 15 stores bounded canonical bundles as profile-global sealed
records keyed by their public content digest. Repeating identical bytes is
idempotent; a same-digest ciphertext conflict, malformed canonical bundle, or content
identity mismatch fails closed. Bundle count is bounded without evicting an existing
record.

One sealed binding may select a stored digest for each existing local conversation.
The binding authenticates the profile, conversation, digest, and activation timestamp.
It survives restart, replacement is atomic, and deletion immediately removes local
authority. Schema migration creates no bundle or binding, and no client or agent
activation operation is exposed in this persistence-only slice.

Protocol-v1 application content now carries three typed exchange messages:

- a proposal identifier, claimed policy digest, complete canonical bundle, and
  optional digest that the proposal is intended to replace;
- an accepted or rejected response bound to the exact proposal identifier and policy
  digest; and
- a revocation notice bound to the policy digest being withdrawn.

Proposal identifiers are 16 bytes and policy digests are 32 bytes. The embedded
bundle is required and retains the core 64 KiB bound. Unknown response outcomes,
malformed identifiers, malformed digests, empty or oversized bundles, and missing
required fields fail closed in Rust and TypeScript.

Proposal verification decodes the embedded bundle through the canonical bundle
contract, derives its domain-separated digest, and requires an exact match with the
claimed digest. This prevents a sender from substituting alternate policy bytes under
an agreed identity. The optional replacement digest is authenticated application
content, but it does not itself mutate a binding.

Receiving a proposal, accepted response, or revocation never activates, replaces, or
deletes local authority at this layer. These messages establish an authenticated
exchange vocabulary only. A subsequent service state machine must durably track
pending proposals and call the local binding boundary only after an authorized local
decision. An accepted response authenticates which member reported acceptance of
which proposal and digest; it is not independent proof of that endpoint's effective
harness controls.

Participants acknowledge the same base digest independently. Each endpoint then
intersects that bundle with local user authority, harness-proven controls, and local
restrictions. The public effective projection may be stricter on either endpoint,
while the accepted base definition remains byte-identical.

Rust-generated immutable fixtures cover every exchange content kind, and both Rust
and TypeScript readers decode and re-encode those application messages byte for byte.
The local daemon verifies proposed bundle identity before outbound encryption or
inbound persistence. The shared local-service delivery surface exposes only typed
proposal identifiers, digests, replacement intent, outcomes, and revocations; it does
not expose the canonical bundle or model guidance through automatic delivery.
Copilot renders that metadata inside the existing untrusted collaborator fence and
explicitly states that proposal receipt activated no local authority.

The closed binary adapter protocol v1 is not extended with new event discriminants.
For compatibility, its text-only application event projects policy exchanges into a
bounded daemon-authored notice that claims no activation and contains no peer bundle
content. This lets an older adapter acknowledge the event instead of repeatedly
rejecting an unknown event kind and blocking its delivery queue.

Manual message-history results use a `content_type` discriminator. Text retains its
existing `text` field, while policy entries expose only the proposal identifier,
digests, replacement intent, response outcome, or revocation digest. The Copilot
history command validates and renders each variant instead of rejecting a page that
contains non-text application content.

## Harness boundary

Model guidance is never treated as proof of enforcement. Paved harness adapters
register the namespaced actions, resources, and evidence they can enforce. Unknown or
unsupported required claims deny or reduce the effective policy. Generic integrations
cannot claim paved tool, permission, resource, or lifecycle controls.

Peer content remains quoted inside the untrusted collaborator boundary. A locally
active binding supplies the separate trusted instruction to evaluate that content and
act only within the effective policy.
