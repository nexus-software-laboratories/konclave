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

Editable source formats will additionally represent inherited values. The source
compiler resolves activation overrides, source values, user defaults, and shipped
defaults before producing canonical bytes.

## Source and catalog boundary

The next source layer will accept explicit user files and repository proposals. It
will not scan or activate repository content automatically. A source may include
human comments, inheritance, and unresolved defaults; none of those cross into the
canonical bundle.

Source providers compile into the same bundle:

- explicit user catalog;
- explicitly selected repository proposal;
- bundle received through a conversation;
- configured self-hosted provider; or
- configured hosted provider.

Provider names and mutable URLs are not persisted as policy authority. Activation
pins canonical bytes and their digest.

## Binding and exchange boundary

A future profile-schema migration will store sealed policy bundles and local
conversation bindings. Only a locally authorized operation may activate, replace, or
revoke a binding. A peer proposal carries a digest and, when needed, the complete
bounded bundle; receiving it does not activate it.

Participants acknowledge the same base digest independently. Each endpoint then
intersects that bundle with local user authority, harness-proven controls, and local
restrictions. The public effective projection may be stricter on either endpoint,
while the accepted base definition remains byte-identical.

## Harness boundary

Model guidance is never treated as proof of enforcement. Paved harness adapters
register the namespaced actions, resources, and evidence they can enforce. Unknown or
unsupported required claims deny or reduce the effective policy. Generic integrations
cannot claim paved tool, permission, resource, or lifecycle controls.

Peer content remains quoted inside the untrusted collaborator boundary. A locally
active binding supplies the separate trusted instruction to evaluate that content and
act only within the effective policy.
