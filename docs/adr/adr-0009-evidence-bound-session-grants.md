---
title: Authorize local sessions through evidence-bound exact-profile grants
status: Accepted
date: 2026-08-26
authors:
  - Konclave maintainers
tags:
  - authorization
  - evidence
  - grants
  - ipc
  - sessions
supersedes: []
superseded_by: []
---

# Authorize local sessions through evidence-bound exact-profile grants

## Context and scope

ADR 0008 established one per-user shared local service and authenticated local RPC.
Its initial authorization mechanism registered one long-lived adapter key for a
harness and allowed that key to select profiles beneath a namespace. That mechanism
proved the process model and thin-client workflow, but it conflates three different
claims:

- the operating-system account may use Konclave;
- one integration is requesting access; and
- one logical harness session may operate one exact profile.

An owner-only file or user-scoped credential excludes other operating-system
accounts. It does not distinguish mutually hostile processes running under the same
account. A namespace-wide adapter credential also cannot provide per-session expiry,
auditing, rekeying, suspension, or future harness attestation without retaining
authority broader than the operational connection needs.

This decision owns local session authorization evidence, grant issuance and use,
evidence policy, issuer and grant lifecycle, session identity continuity, generic
harness participation, recovery authority, and the protocol transition for the local
service. It refines the local authorization portion of ADR 0008; ADR 0008 continues to
govern the shared process, profile supervisor, local transport, and service lifecycle.

This decision does not change MLS membership authorization, relay authentication,
profile cryptographic identity, sealed persistence, conversation roles, or remote
pairing.

## Verified facts

- The initial installation creates one adapter signing seed and registers its public
  key for the `session-*` namespace. Every extension session uses that seed.
- Local-service protocol version 1 binds adapter key identity, harness, client
  instance, profile, and fresh challenges, but has no session public key or grant
  identifier.
- The extension derives a profile from mutable harness session metadata and uses the
  installed adapter key directly for its operational connection.
- The service loads adapter registrations into an in-memory startup snapshot.
  Revocation mutators exist on the in-memory type, but production has no live mutation
  path.
- Request deadlines can drop async dispatch while already-started blocking work
  continues, allowing the recorded timeout to diverge from a later durable side
  effect.
- The shared process, profile isolation, thin client, package lifecycle, twenty-client
  scale, and real two-session messaging have independent passing evidence.
- No supported Konclave release or external user installation exists. The first grant
  protocol can therefore make a clean version transition without preserving protocol
  version 1 as a compatibility mode.

## Assumptions

- `AccountTrusted` intentionally trusts every process operating under the configured
  operating-system account. It is not a hostile same-account isolation boundary.
- Stronger providers may later prove user presence, harness attestation, or workload
  identity, but none is inferred from account ownership, process names, paths, or
  mutable session metadata.
- A harness can generate an ephemeral Ed25519 session key and keep its private key in
  memory for one process lifetime.
- A logical harness session can be mapped to one installation-local profile when its
  integration supplies the continuity signal its evidence contract permits.
- A universal generic client contract is required even when no paved integration
  exists for a harness.

## Decision drivers

- Preserve one-time installation and automatic multi-session use under an explicit
  account-trusted policy.
- Bind operational authority to one exact profile and one ephemeral session key.
- Add stronger evidence providers without changing the operation RPC surface.
- Never claim evidence or isolation the caller did not prove.
- Make downgrade, expiry, rekeying, suspension, and issuer disablement deterministic.
- Keep grants bounded while preserving durable profile and conversation state.
- Permit any harness to participate through a universal minimum-trust contract.
- Establish the correct handshake before the first supported release creates
  compatibility obligations.

## Decision

### Separate evidence, issuance, and operational authority

An installed issuer credential authenticates an authorization issuer. It does not
directly authorize profile tools, delivery, commands, or membership operations.

An issuer evaluates evidence and creates a finite `SessionGrant` containing:

- one random canonical grant identifier;
- one exact profile identifier;
- one ephemeral session public key;
- one harness or generic integration kind;
- the exact verified evidence set;
- the policy version used at issuance;
- issued and expiry times;
- a closed set of allowed operation capabilities; and
- active, retired, expired, revoked, or terminal status.

An operational connection authenticates by proving possession of the session private
key and presenting the matching grant. The binding cannot change profile, harness,
key, grant, or capabilities for the life of the connection.

### Use a breaking local-service protocol version

Protocol version 2 distinguishes issuer and session-grant handshakes.

The session-grant transcript binds:

- protocol version;
- grant identifier;
- session public key;
- client instance identifier;
- harness or generic integration kind;
- exact profile identifier;
- client and service challenges;
- service public key; and
- the grant capability bitset, issuance, and expiry.

The session signs the transcript with its ephemeral private key. The service returns a
role-separated acceptance signature. Unknown, expired, revoked, wrong-profile,
wrong-harness, wrong-key, or policy-invalid grants produce one uniform external
authentication failure after the proof exchange; bounded local diagnostics may retain
a stable internal outcome.

Protocol version 2 never negotiates down to version 1. The service classifies a
protocol-v1 hello as `client_upgrade_required`; the old client, which cannot parse a
new rejection, observes a failed attach. A version-2 client classifies a reachable
old service as `service_upgrade_required`.

### Define authorization policy as any-of all-of evidence clauses

An authorization policy is a versioned list of clauses. Every clause is a nonempty
canonical set of evidence kinds that must all be verified; satisfying any clause is
sufficient. The structure supports `OR` between clauses and `AND` inside a clause. It
is not a general expression language.

Examples:

```text
[[AccountTrusted]]
[[HarnessAttested], [UserPresence]]
[[HarnessAttested, UserPresence], [WorkloadIdentity]]
```

A missing, empty, malformed, or unknown policy denies issuance. Clients cannot supply
or weaken policy. A grant records its verified evidence and policy version. A later
policy version that no longer accepts that evidence invalidates the grant when durable
live policy enforcement is enabled.

### Keep AccountTrusted explicit and automatic

Interactive initialization requires one explicit policy choice and explains:

```text
AccountTrusted trusts every process under this operating-system account.
It does not provide hostile same-user session isolation.
```

Noninteractive initialization, package installers, and demos must pass the policy
explicitly. Repeated initialization is idempotent when the policy agrees.

The account issuer may issue policy-permitted grants for any canonical profile under
its configured account scope. Exact grants provide profile binding, key separation,
expiry, auditability, quotas, and connection containment; they do not prevent another
trusted same-account process from requesting a different grant.

### Make session private-key custody provider-owned

The service stores only session public keys. It never receives or writes a session
private key.

`AccountTrusted` uses an in-process memory-only key. Extension or harness restart
generates a new key and grant automatically. Service restart invalidates the initial
service-lifetime grants; active AccountTrusted clients automatically request
replacements. Clean shutdown retires a grant; crashes rely on finite expiry.

Future providers define the custody they accept. `HarnessAttested` should use
ephemeral keys with re-attestation. `UserPresence` uses ephemeral keys unless a
platform proves durable non-exportable custody. `WorkloadIdentity` binds key lifetime
to the isolated workload. An ordinary owner-only file cannot be presented as stronger
than AccountTrusted custody.

### Preserve logical harness-session identity

A new harness session receives a new profile, key, and grant. Process restart and
`/resume` retain the installation-local profile but use a new key and grant. `/fork`
creates a new profile and device identity. Rename and working-directory changes do not
change identity.

Subagents do not mint independent profiles automatically. A subagent using the parent
tool context acts under the parent grant. An independently addressable subagent must
become a separate harness session.

The same harness session on another machine does not silently open the same Konclave
device identity. It requires explicit new-device enrollment or future identity
migration.

### Provide a universal generic participation floor

Bespoke integration support is not an eligibility gate. A built-in generic issuer can
issue AccountTrusted grants when policy accepts that evidence. Generic integration
labels are bounded diagnostic metadata, not proof.

A generic client generates an ephemeral key and uses an explicit durable profile alias
or a clearly ephemeral isolated profile when no stable session subject exists. It
never fabricates continuity from process ID, working directory, time, model name, or
free-form agent text.

A generic client may satisfy independent evidence providers it actually proves. It
cannot claim HarnessAttested without a verified assertion and never receives a
fallback grant when stronger policy is required.

### Separate disconnect, revocation, suspension, and issuer disablement

- Disconnect closes one transport and permits grant reuse until another terminal
  condition.
- Grant revocation closes every matching connection and permanently rejects that
  key/grant. AccountTrusted may issue a replacement for the logical session.
- Profile suspension closes its grants and durably blocks new issuance without
  deleting profile data.
- Issuer disablement blocks new grants for that issuer and handles existing grants
  through explicit policy.

These administration operations are unavailable to ordinary model or agent tools.
Under AccountTrusted they are operator controls, not a hostile same-account boundary.

### Bound grant retention and preserve profile durability

Active grants are bounded globally, per issuer, and per profile. Quota exhaustion
denies the new request and never evicts an active grant. Terminal grants remain only
for a bounded audit and idempotency window before their detailed records are swept.
Grant identifiers are never reused.

Grant expiry, session deletion, suspension, extension uninstall, package uninstall, or
inactivity never deletes a profile. Idle runtime resources may be evicted while
profile identity, MLS state, messages, and conversation data remain.

Profile states distinguish active, suspended, archived, and pending deletion. Deletion
is a separate confirmed operation that checks grants, clients, operations, locks,
custody, export needs, and unresolved conversation membership.

Smoke and evaluation profiles use isolated temporary roots and test custody with exact
cleanup rather than product deletion.

### Support explicit recovery without a universal bypass

Stronger policies have no implicit operating-system-account bypass. They may
preconfigure a narrow recovery authority. Recovery evidence is exact-profile,
short-lived, separately audited, unavailable to agent tools, and authorizes policy
repair, replacement-key registration, revocation, or recovery-authority rotation. It
does not directly read history, send messages, or operate the profile.

Choosing a stronger policy without recovery requires explicit acknowledgement that
loss of every accepted evidence source can strand profile access. AccountTrusted needs
no separate recovery authority because its issuer can create a replacement grant.

### Scope rollback guarantees to the evidence provider

AccountTrusted state uses atomic writes, versioning, a monotonic generation,
corruption detection, and a process-lifetime high-water mark. Hostile durable rollback
by a same-account process is outside its guarantee.

Stronger providers may require a protected platform, issuer-side, hardware-backed, or
remote monotonic anchor. That anchor is part of the provider contract and is never
inferred from AccountTrusted storage.

### Reconcile cancellation with durable outcomes

Request execution has one owned lifecycle and an explicit irreversible commit point.
Cancellation, disconnect, revocation, shutdown, and deadline are grant-scoped and
cannot cancel another grant's request.

Pre-commit work may stop with a terminal cancellation outcome. Post-commit work
finishes reconciliation and publishes its actual durable outcome. Dropping a
`spawn_blocking` join handle never represents the underlying work as cancelled.
Callers can retry or query by the stable request identifier and observe the recorded
terminal result.

### Make a clean pre-release transition

No supported release or external installation exists. Protocol and installation
schema version 2 therefore replace version 1 without a product compatibility mode.
Fresh initialization emits only version 2. Demo and package refresh atomically replace
the development authorization config, extension sidecar, and package. Existing
synthetic profile data may be retained as regression evidence but is not a
compatibility promise.

Before the first supported release establishes compatibility, the installer must gain
an explicit journaled preview, apply, recovery, and rollback migration engine. Ordinary
`init` never silently changes authorization authority.

## Serious alternatives

### Keep namespace-wide adapter authority

**Pros:** smallest implementation and already proven.

**Cons:** cannot represent an exact session, future evidence, per-session expiry, or
honest revocation boundaries. Rejected.

### Require strong attestation for every harness

**Pros:** uniform high assurance.

**Cons:** excludes unsupported and community harnesses, depends on upstream issuers,
and violates the universal-agent goal. Rejected.

### Treat evidence kinds as numeric levels

**Pros:** simple minimum comparison.

**Cons:** user presence, harness attestation, and workload identity are incomparable
claims and may need conjunction. Rejected.

### Persist every session key in an owner-only file

**Pros:** seamless key reuse after restart.

**Cons:** adds stale key state and cannot support a stronger claim than account trust.
AccountTrusted can reissue automatically without it. Rejected.

### Give the operating-system account a universal recovery bypass

**Pros:** no profile can be stranded.

**Cons:** nullifies every stronger policy against same-account processes. Rejected.

## Consequences

### Positive

- AccountTrusted retains automatic one-time-install usability.
- Operational connections carry exact profile, key, capability, expiry, and policy
  bindings.
- Stronger providers can reuse the grant and operation architecture.
- Unsupported harnesses retain a universal participation path.
- Session key files and their cleanup are unnecessary for the initial provider.
- Grant and profile lifecycles become independently bounded and observable.

### Negative

- The local handshake and installation schema make a breaking version transition.
- The extension opens an issuer connection before its operational and delivery lanes.
- Grant issuance, renewal, quotas, suspension, and cleanup add service state.
- AccountTrusted still cannot isolate mutually hostile same-account processes.
- Resume, fork, subagent, and machine-migration behavior depend on observable harness
  lifecycle contracts.

### Neutral

- Conversation membership and MLS device identity remain separate from local evidence
  policy.
- A generic AccountTrusted profile can participate in conversations with profiles
  using stronger local authorization.
- Durable profile data remains even when every local grant expires.
- Hosted and self-hosted products use the same grant and evidence contracts.

## Confirmation

Continued compliance is demonstrated by:

- protocol vectors that bind grant, session key, profile, harness, evidence, policy,
  capability bitset, issuance, expiry, service identity, and both challenges;
- downgrade, unknown-grant, wrong-key, wrong-profile, wrong-harness, expired, revoked,
  policy-invalid, and uniform-failure tests;
- issuer tests proving it cannot invoke operational profile methods;
- AccountTrusted tests proving automatic first use, restart reissuance, explicit
  disclosure, and no stronger evidence claim;
- policy tests for canonical any-of/all-of clauses, unknown kinds, conjunction,
  policy-version invalidation, and no fallback;
- quota tests proving deny-without-eviction globally, per issuer, and per profile;
- lifecycle tests for clean retire, crash expiry, resume, fork, subagent delegation,
  profile suspension, issuer disablement, archive, and explicit deletion;
- generic-client tests proving an unsupported harness can pair and message under
  AccountTrusted but cannot satisfy a stronger policy without evidence;
- cancellation tests at every commit boundary, including disconnect, revocation,
  response loss, blocking work, and service restart;
- package tests proving v1 rejection, clean v2 initialization, atomic development
  replacement, and no per-session daemon fallback;
- status and doctor output that state effective policy, supplied evidence, expiry,
  provider availability, quotas, and stable remediation without secrets or plaintext;
  and
- focused specialist security review, bounded independent critique, hosted validation,
  and a real two-session Copilot smoke before publication.

## References

- [ADR 0008: Host logical agent profiles in one per-user local service](adr-0008-shared-local-service.md)
  establishes the shared process and local RPC that this decision refines.
- [Threat model](../security/threat-model.md) owns the account, process, adapter,
  profile, and recovery adversaries that evidence contracts must state honestly.
- [Local service transport](../development/local-service-transport.md) describes the
  version 1 handshake whose session-authorization role is replaced by this decision.
- [Copilot delivery safety](../development/copilot-delivery-safety.md) remains the
  untrusted-content boundary after a session grant authorizes the adapter.
