---
title: Automate two-command pairing only under AccountTrusted capability policy
status: Accepted
date: 2026-08-27
authors:
  - Konclave maintainers
tags:
  - account-trusted
  - pairing
  - usability
  - authorization
supersedes: []
superseded_by: []
---

# Automate two-command pairing only under AccountTrusted capability policy

## Context and scope

ADR 0006 deliberately uses a joiner-issued capability and requires authorization at
both endpoints. It permits a later explicit policy to automate those decisions, but
does not choose one. The initial Copilot integration exposed every durable pairing
stage to the operator. A successful local connection consequently required identity
lookups, capability transfer, conversation creation, two approval commands, and
repeated synchronization commands before messaging could begin.

This decision owns only the local `AccountTrusted` convenience policy and its paved
command experience. It does not change the pairing wire protocol, MLS membership
checks, stronger evidence policies, administrator grants, remote credential
provisioning, or the manual diagnostic operations.

## Verified facts

- `AccountTrusted` already trusts every process under the configured operating-system
  account and explicitly provides no hostile same-user isolation.
- A pairing capability is short-lived, unguessable, one-time state issued and signed
  by the joining device. Possession authorizes an attempt but does not establish a
  human identity.
- Creating the capability in one session and redeeming it in another are two explicit
  same-account operator actions. Repeating device fingerprints in that environment
  does not add evidence beyond the policy the installation actually proves.
- The durable pairing service already authenticates both devices, binds the granted
  role and conversation, and requires the ordinary invitation, JoinProof, Commit,
  Welcome, and completion stages.
- The paved extension can drive those existing operations without receiving
  cryptographic keys or adding a second pairing state machine.
- A stronger authorization policy must not silently fall back to evidence that only
  `AccountTrusted` can satisfy.

## Assumptions

- The operator intentionally transfers the capability between the two local sessions
  they want connected.
- The operating-system account and active Copilot extensions are inside the declared
  `AccountTrusted` boundary.
- Capability theft by another process under that account is not prevented by this
  policy and is reported truthfully rather than described as verified identity.

## Decision drivers

- Reduce the ordinary local path to one command per session and one capability copy.
- Preserve the existing cryptographic and durable pairing protocol.
- Grant least privilege without hidden role escalation.
- State exactly what authorization evidence was used.
- Keep stronger policies and recovery diagnostics fail-closed.
- Prevent a supported harness from escaping its exact profile through Generic
  fallback.

## Decision

### Add one bounded two-command workflow

The joiner runs `/konclave connect`. The command:

1. verifies that the effective policy and evidence are `AccountTrusted`;
2. creates a capability requesting only `member`;
3. displays the capability ephemerally; and
4. remains active while it drives bounded pairing synchronization.

The other session runs `/konclave connect <capability>`. The command:

1. verifies the same effective policy;
2. redeems the capability and refuses any role other than `member`;
3. atomically creates a new conversation with automatic delivery enabled;
4. authorizes the authenticated joiner as `member`; and
5. drives bounded synchronization until both durable pairing state machines complete.

When the joiner receives the signed invitation, its still-running command authorizes
the exact inviter, conversation, and granted role from authenticated pairing state.
Both commands report the authenticated device identifiers and same conversation
identifier after completion.

### Label the actual approval evidence

The command output states:

> AccountTrusted capability possession; no independent identity verification.

The two explicit command invocations and transferred bearer capability are the
approval policy. The system does not claim that a device fingerprint was independently
verified or that another process under the same account was excluded.

The convenience policy grants only `member`. Administrator grants, installations
whose effective policy is stronger than `AccountTrusted`, and recovery from an
interrupted convenience command use the manual `pair`, `join`, `new`, `pairing`,
`approve`, `sync`, and `cancel` operations.

### Keep progress bounded and owned

Each command remains the owner of its progress loop. It uses the pairing authorization
or completion deadline plus a shorter command ceiling, performs one bounded sync
operation at a time with the remaining deadline, sleeps whenever the durable phase
does not advance, and stops on completion, cancellation, deadline, or a finite
iteration cap. It creates no detached worker and no unbounded polling task. Phase
changes and manual recovery/cancellation commands remain visible while either side is
waiting.

If the accepting command has created a conversation before the peer completes, that
empty conversation remains visible for recovery. The command reports this boundary;
it does not fabricate rollback for already committed state.

### Reserve paved profiles from Generic fallback

The Generic client rejects the `session-*` profile namespace. The unsupported-harness
skill is packaged but is not installed into Copilot's skill discovery path. A paved
operation failure remains visible and never authorizes profile scanning, profile
switching, or fallback execution as another session.

## Serious alternatives

### Keep explicit commands for every pairing stage

This preserves maximum operator ceremony but already failed the primary usability
goal: users could not reliably establish their first conversation. It remains
available for stronger policies and diagnosis, not as the ordinary local path.

### Treat capability possession as approval under every policy

This is shorter but would silently downgrade stronger evidence and misrepresent bearer
possession as verified identity. Rejected.

### Let one service request authorize both profiles

This could finish from one command but would cross exact-profile grant boundaries and
let one session act directly for another. Rejected in favor of each connected session
driving its own authenticated state.

### Create an inviter-issued join link

This conflicts with the identity ordering established by ADR 0006: a
conversation-scoped joiner binding cannot exist before the invitation reveals the
conversation. Rejected.

## Consequences

### Positive

- Ordinary local setup becomes two commands and one capability transfer.
- Both profile grants, device identities, pairing journals, and MLS stages remain
  independently enforced.
- The output accurately describes the weaker same-account evidence.
- Least privilege is fixed at `member`.
- Agent prompts and Generic fallback are unnecessary for the paved workflow.

### Negative

- Both command handlers may remain active while the operator switches terminals.
- Interrupting either command can leave a recoverable pairing and, after inviter
  acceptance, an empty durable conversation.
- The policy is unsuitable when same-account processes are mutually hostile.

### Neutral

- The long transferable capability remains terminal-visible and may enter local input
  history when pasted.
- Manual pairing remains part of the supported surface.
- Remote zero-setup pairing still depends on least-privilege relay provisioning.

## Confirmation

Continued compliance requires:

- command tests that run the joiner and inviter paths through completion and prove
  only `member` is granted;
- refusal tests for stronger authorization policies, administrator capabilities,
  cancellation, deadline, malformed state, and progress exhaustion;
- a real two-session Copilot acceptance proving both commands return the same
  conversation and `/konclave send -- <text>` reaches the idle peer;
- Generic client tests rejecting `session-*` profiles;
- installation tests proving the unsupported-harness skill is not installed into
  Copilot and that externally managed content remains untouched; and
- specialized security review before delivery because the policy automates membership
  authorization.

## References

- [ADR 0006](adr-0006-joiner-issued-pairing-capabilities.md) establishes the
  joiner-issued capability, both authorization decisions, and the requirement that
  any automation be explicit.
- [ADR 0009](adr-0009-evidence-bound-session-grants.md) defines the truthful
  `AccountTrusted` boundary and the rule that a client cannot claim stronger evidence
  than it proves.
- [Threat model](../security/threat-model.md) defines capability possession,
  same-account compromise, pairing authorization, and exact-profile grants.
- [Copilot CLI extension](../../extensions/Konclave.HostExtension/docs/copilot-cli-extension.md)
  owns the paved command and automatic-delivery behavior.
