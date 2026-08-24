---
title: Provision per-profile relay principals through an outbound enrollment control plane
status: Proposed
date: 2026-08-24
authors:
  - Konclave maintainers
tags:
  - authentication
  - distribution
  - enrollment
  - relay
  - security
supersedes: []
superseded_by: []
---

# Provision per-profile relay principals through an outbound enrollment control plane

## Context and scope

Konclave's Copilot extension launches one daemon profile per agent session. Separate
profiles provide independent identity, MLS state, crash journals, adapter leases, and
exclusive process locking. The distribution MVP must initialize those profiles
without asking every session to receive a relay credential through environment
variables or a plaintext file.

ADR 0003 defines pseudonymous bearer authentication and route authorization for the
relay data plane. It deliberately leaves remote administration out of scope. This
decision adds the missing enrollment plane while preserving that data-plane contract.
It covers self-hosted bootstrap authority, per-profile credential creation,
idempotent registration, local enrollment-source custody, and the adapter boundary
available to a hosted implementation. It does not define hosted accounts, billing,
artifact installation, or general relay administration.

## Verified facts

- The Copilot extension derives a bounded profile identifier from `SESSION_ID` and
  launches a separate daemon child for that profile. Concurrent sessions therefore
  cannot solve setup by opening one locked profile.
- Relay credentials are currently sealed inside one profile. A credential imported
  into one profile cannot initialize a later profile unless a separate source remains
  available.
- Relay acknowledgment is scoped by pseudonymous principal. Copying one data-plane
  token into every profile collapses their acknowledgment identity and prevents
  revoking one profile independently.
- The Community Relay's static access document stores principal digests rather than
  raw bearer tokens, but it cannot register a principal without an operator edit and
  restart.
- A client can generate a random 32-byte data-plane token locally and derive the
  domain-separated principal digest defined by ADR 0003. Registering that digest does
  not require disclosing the raw data-plane token to the relay.
- A stable digest registration is naturally idempotent. Having the server generate a
  token would require returning a secret exactly once or retaining recoverable secret
  material after a lost response.
- All daemon-to-relay connectivity is already outbound HTTP(S). Adding an
  authenticated enrollment request does not require an inbound endpoint on an agent
  device.

## Assumptions

- Desktop installation runs under an operating-system account whose native credential
  store is available. Headless operators can supply enrollment authority through an
  explicit external secret source.
- A self-hosted relay operator can bootstrap one high-entropy enrollment credential
  and protect its raw value separately from the relay's stored verifier.
- The self-hosted enrollment policy grants the fixed minimum data-plane permissions
  selected by the operator. A requesting profile does not choose arbitrary grants.
- A hosted deployment can replace enrollment authentication and policy while
  preserving the public enrollment client outcome and the unchanged data plane.
- The local account and daemon process are trusted while they handle an enrollment
  credential or newly generated data-plane token.

## Decision drivers

- No per-session secret configuration or repeated setup.
- One independently revocable and acknowledgeable relay principal per daemon profile.
- No raw data-plane or enrollment credential in plugin manifests, process arguments,
  command history, URLs, logs, telemetry, or relay persistence.
- Crash-safe, idempotent enrollment across lost requests and responses.
- Outbound-only agent connectivity.
- One public client boundary usable by self-hosted and future hosted deployments.
- Bounded principal growth and fail-closed authorization.

## Decision

### Keep enrollment separate from the data plane

Relay submit, replay, acknowledge, and watch continue using the bearer authentication,
pseudonymous principal derivation, route grants, and wire contracts from ADR 0003.
Enrollment uses a separate authenticated endpoint and permission. Possessing a
data-plane token never authorizes enrollment, and possessing an enrollment credential
does not itself authenticate data-plane requests.

The shared client boundary returns one outcome: the caller-supplied principal digest
is registered under deployment-selected grants. The Community Relay implements this
with a self-hosted adapter. A hosted service may authenticate an account or
installation differently behind the same boundary without adding account fields to
the public data-plane protocol.

### Generate the profile credential at the endpoint

For a profile with no sealed relay credential, the daemon:

1. generates a fresh 32-byte data-plane token with the existing cryptographic random
   source;
2. derives its ADR 0003 principal digest;
3. seals the token and exact enrollment intent in a profile-owned pending journal;
4. sends only the digest and bounded idempotency metadata to the configured enrollment
   endpoint; and
5. promotes the sealed token to active relay configuration only after authenticated
   registration succeeds.

A crash or lost response retries the same sealed token and digest. Conflicting reuse
of the idempotency identity or digest fails closed. The relay stores the digest,
finite grants, status, and bounded audit metadata, never the raw profile token.

### Keep enrollment authority outside session configuration

`konclave init` writes non-secret installation configuration and stores the
enrollment credential in the operating system's native credential store. It accepts
secret input interactively or through an explicit bounded reader; no secret command
argument or environment-variable option is supported.

Each new profile reads the install-scoped enrollment credential only long enough to
authenticate its registration, then continues with its profile-sealed data-plane
token. The enrollment credential is not copied into profile SQLite, the plugin
manifest, or the Copilot session environment.

Headless deployments use an explicit external enrollment source such as a
permission-restricted secret mount or inherited descriptor. Failure to load the
selected source never falls back to plaintext configuration, a shared data-plane
credential, or anonymous enrollment.

### Bound self-hosted enrollment policy

The Community Relay stores only a verifier for each bootstrap enrollment credential.
Authentication occurs before bounded body materialization. The self-hosted policy
sets:

- a maximum active-principal count;
- fixed data-plane permissions and route scope;
- request rate and body limits; and
- explicit enablement, rotation, revocation, and disablement.

Registration is atomic with the dynamic authorization record. Duplicate identical
registration succeeds; conflicting registration fails. The caller cannot request
broader grants than the server policy. Enrollment is disabled by default until the
operator provisions a verifier.

## Serious alternatives

### Copy one wildcard data-plane token into every profile

**Pros:** smallest implementation, works with the current static access document, and
requires no enrollment endpoint.

**Cons:** collapses acknowledgment identity across sessions, prevents independent
revocation, multiplies one bearer secret across profile journals, and contradicts ADR
0003's rejection of a shared instance token. Rejected.

### Require a data-plane credential for every new session

**Pros:** preserves distinct principals and requires no new relay control plane.

**Cons:** repeats sensitive manual setup, encourages environment-variable or file
copying, and fails the turnkey Copilot MVP requirement. Rejected.

### Generate and return the data-plane token from the relay

**Pros:** centralizes token generation and policy.

**Cons:** a lost response either loses the only token or forces the relay to retain
recoverable raw secret material. Client-generated tokens make registration
idempotent while the relay stores only a digest. Rejected.

### Run one long-lived user daemon for every session

**Pros:** enrolls only once and centralizes relay connectivity.

**Cons:** replaces isolated locked profiles with a local multi-tenant service, requires
a new local connection and authorization model for MCP and adapter clients, and
changes lifecycle and failure isolation beyond distribution scope. Rejected for the
MVP.

### Treat a pairing capability as relay enrollment authority

**Pros:** appears to make remote pairing zero-configuration.

**Cons:** the capability holder would gain authority outside one random pairing route,
or the relay would need to trust an unauthenticated route locator as a credential.
ADR 0006 explicitly rejects embedding durable or wildcard relay authority. Rejected.

## Consequences

### Positive

- A one-time installation setup can provision any later session profile.
- Each profile retains independent relay acknowledgment and revocation identity.
- Raw profile tokens never cross into relay persistence.
- Lost registration responses recover with the same locally sealed credential.
- Self-hosted and hosted deployments share one client outcome without sharing account
  infrastructure.
- Copilot remains the first presentation adapter rather than a core dependency.

### Negative

- The Community Relay gains a separate security-sensitive enrollment surface and
  dynamic authorization persistence.
- Installation now depends on native credential-store availability or an explicit
  headless enrollment source.
- Enrollment credential compromise can register principals until rotation or
  revocation, so its blast radius exceeds one profile token.
- Principal caps, revocation, migration, and bootstrap recovery add operator
  responsibilities.

### Neutral

- Profile data-plane tokens remain bearer credentials after registration.
- Enrollment does not prove a human identity or authorize MLS membership.
- Existing explicitly provisioned profiles remain valid and need not re-enroll.
- Hosted account UX and private service implementation remain outside this public
  repository.

## Confirmation

Continued compliance is demonstrated by:

- tests that one install-scoped enrollment source provisions multiple independently
  identified profiles without session secret configuration;
- fixed vectors proving the registered digest matches the locally retained token;
- crash tests before registration, after relay commit, and before local promotion;
- identical retry and conflicting retry tests;
- principal-cap, rate-limit, disabled-enrollment, wrong-credential, and revoked-
  credential tests;
- raw database, log, trace, process-argument, environment, and plugin-manifest scans
  for both enrollment and data-plane token sentinels;
- tests proving two profiles acknowledge independently and one can be revoked without
  affecting the other;
- headless external-source tests with no plaintext or environment fallback;
- real clean-machine initialization and automatic pairing acceptance; and
- specialized security review before enabling the enrollment endpoint.

## References

- [ADR 0002: Sealed local secret custody](adr-0002-sealed-local-secret-custody.md) —
  defines native and external secret providers and prohibits plaintext fallback.
- [ADR 0003: Relay transport authentication](adr-0003-relay-transport-authentication.md) —
  defines data-plane bearer authentication, pseudonymous principals, and independent
  authorization.
- [ADR 0004: Daemon profile journal](adr-0004-daemon-profile-journal.md) — requires
  profile-sealed credentials and recoverable side-effect journals.
- [ADR 0006: Joiner-issued pairing capabilities](adr-0006-joiner-issued-pairing-capabilities.md) —
  rejects using pairing capabilities to carry durable relay authority.
- [Threat model](../security/threat-model.md) — identifies relay credential escalation,
  metadata access, and endpoint secret custody as explicit threats.
