---
title: Require harness-owned challenge-bound assertions for HarnessAttested grants
status: Proposed
date: 2026-09-13
authors:
  - Konclave maintainers
tags:
  - authorization
  - attestation
  - identity
  - harnesses
supersedes: []
superseded_by: []
---

# Require harness-owned challenge-bound assertions for HarnessAttested grants

## Context and scope

ADR 0009 defines `HarnessAttested` as evidence from a supported harness that can
identify one exact session without trusting account ownership, process names, paths,
or mutable session metadata. It deliberately leaves the issuer contract to a later
decision.

Current harness integrations expose useful lifecycle identifiers but do not all expose
the same trust primitive. GitHub Copilot CLI extensions join the foreground session
through a session identifier supplied to a child process and receive lifecycle events
over the extension SDK. Local Claude Code hooks receive session identifiers and
lifecycle events. Codex app-server exposes thread lifecycle plus experimental
attestation and user-verification surfaces. These interfaces differ in purpose and
assurance, and none is automatically equivalent to a signed exact-session assertion
for Konclave.

This decision defines the minimum provider contract, trust-root model, lifecycle
semantics, and failure behavior required before Konclave may issue a
`HarnessAttested` grant. It does not select a production provider, change the existing
`AccountTrusted` path, define user-presence evidence, or make vendor-specific tokens
part of the Konclave wire protocol.

## Verified facts

- The Copilot extension SDK used by Konclave, `@github/copilot-sdk` 1.0.11, joins the
  current session by reading `SESSION_ID` from the extension process environment and
  resuming that session over parent-process JSON-RPC.
- Copilot session and hook APIs expose a session identifier, start versus resume
  lifecycle, remote-steerable state, extension discovery status, and subagent event
  identifiers. The inspected public SDK schema exposes no challenge-signing or
  session-attestation RPC.
- Copilot extensions run as local child processes with the user's privileges.
  Extension paths, manifests, environment values, process ancestry, and caller-set
  SDK attribution therefore cannot establish a boundary against another process
  running as that user.
- Local Claude Code hooks expose session and subagent lifecycle metadata, but those
  hook payloads are local JSON rather than a verifier-facing signed assertion.
- Claude Code self-hosted cloud environments expose an Anthropic-signed session JWT.
  The token proves a session and environment, but is an exportable bearer credential
  available to code running in that session and is not bound to a Konclave challenge,
  session key, profile, capabilities, or extension digest.
- Codex app-server can request an opaque client attestation token for an upstream
  `x-oai-attestation` header, but the experimental request has no caller challenge and
  publishes no general local verification contract. Its separate native
  user-verification API signs a challenge after a platform ceremony and therefore
  belongs to `UserPresence`, not `HarnessAttested`.

## Assumptions

- A harness vendor or enterprise host can eventually operate a signing authority
  whose private key is unavailable to extensions and arbitrary same-account
  processes.
- A provider can publish or provision verification keys with authenticated rotation
  and a bounded offline cache lifetime.
- Konclave can derive an installation-local profile from a verified opaque session
  subject without receiving a globally reusable user identifier.
- A harness may be unable to provide attestation while offline unless it has a
  platform-protected local signer. Network-independent operation is desirable but is
  not fabricated from an exportable local key.

## Decision drivers

- Distinguish a real harness session from another same-account process.
- Bind authorization to the exact ephemeral session key, profile, service, and
  capability request.
- Preserve resume while making fork, subagent, remote-control, and migration semantics
  explicit.
- Keep vendor assertion formats behind a provider boundary.
- Support outbound-only verification and bounded offline operation where the provider
  can prove it.
- Reject replay, downgrade, stale keys, and missing evidence without falling back to
  `AccountTrusted`.

## Decision

### Treat local lifecycle metadata as input, never evidence

Session IDs, environment variables, hook payloads, process identifiers, executable
paths, extension directories, manifests, package versions, and caller-declared SDK
identity remain diagnostic inputs. They may help select a provider or correlate a
request, but they cannot set the `HarnessAttested` evidence bit.

Only a successful registered provider verifier returns a
`VerifiedHarnessAttestation`. Grant issuance derives `HarnessAttested` from that
verified result; callers never submit an evidence enum or boolean.

### Use a challenge-first provider boundary

Before requesting an assertion, Konclave creates one bounded,
single-use `konclave.harness-attestation.challenge.v1` value containing:

- the contract version;
- a random 256-bit nonce;
- a random 128-bit provisional connection identifier;
- the fixed `konclave.local-service` audience;
- the exact 32-byte installation fingerprint and local-service public key;
- the 16-byte issuer request identifier;
- the client's ephemeral session public key;
- the expected harness kind;
- the requested closed capability bitset;
- the expected extension policy identifier; and
- issued-at and expiry timestamps inside a short challenge window.

Challenge issuance may occur before session authorization because the proof does not
yet exist. The client first verifies the pinned service signature, and the service
accepts the assertion only on the same live provisional connection that received the
challenge and proves possession of the challenged ephemeral private key. The
extension obtains and submits its own challenge internally; it never exposes
attestation as a model tool, command, hook result, or signing oracle. The flow remains
on the owner-restricted local endpoint, allocates no profile runtime, performs no
profile side effect, and is bounded globally and per connection. Disconnect or
restart invalidates every pending challenge.

The canonical challenge bytes begin with
`utf8("konclave.harness-attestation.challenge.v1") || 0x00`, followed by the fields
above in order. Integers use unsigned big-endian encoding. Variable ASCII or UTF-8
fields use an unsigned two-byte big-endian length followed by their exact bytes.
Version and harness use two bytes; capabilities and timestamps use eight bytes.

The harness receives the complete challenge. A successful assertion must bind its
digest and add host-authoritative claims that the caller cannot choose:

- assertion version, issuer, signing-key identifier, issuance, and expiry;
- an opaque session subject stable across a legitimate resume;
- a fresh session-instance identifier for the current harness attachment;
- lifecycle kind: new, resume, or fork;
- an optional parent-subject digest for a fork;
- the actual harness kind;
- the loaded extension's source-qualified identifier, version when known, and digest
  of the code the host executed; and
- an explicit root-session scope rather than an inferred subagent identity.

The assertion carrier may be JWS, COSE, or another provider-defined signed format.
Konclave does not normalize or re-sign unverified claims. A provider adapter verifies
the carrier and maps it to the closed `VerifiedHarnessAttestation` shape.

The provider identifier and extension policy identifier are at most 64 canonical
ASCII characters. Each provider declares tighter maxima for its signing-key
identifiers, session subjects, session instances, extension identifiers, and opaque
carrier beneath global ceilings of 1 KiB per field and 64 KiB per assertion.
Extension digests and challenge digests are exactly 32 bytes. Challenges expire within
60 seconds. Each provider also declares a finite assertion lifetime and clock-skew
tolerance; zero skew is the default, and uncertainty beyond that tolerance fails
closed. A resulting grant never outlives the assertion that authorized it.

### Verify before deriving profile continuity

A verifier must check:

1. the provider, algorithm, signing key, and key validity;
2. the exact audience and local-service installation binding;
3. the complete challenge digest and unused nonce;
4. the matching live provisional connection identifier and proof of the challenged
   ephemeral private key;
5. challenge and assertion expiry;
6. the expected harness and approved extension identity/digest;
7. the requested session key and capabilities;
8. lifecycle and parent-subject consistency; and
9. provider-specific revocation or generation state.

After verification, Konclave derives the installation-local profile from the opaque
session subject:

```text
session- + first_24_hex(
  SHA-256(
    utf8("konclave.harness-profile.v1") || 0x00 ||
    installation_fingerprint_32 ||
    u16_be(provider_identifier_utf8_length) || provider_identifier_utf8 ||
    u16_be(session_subject_length) || session_subject
  )
)
```

The caller does not submit a profile to the attestation flow. The service returns the
derived profile with the grant, so a new or forked session does not need to know its
host-authoritative subject in advance.

Providers should scope opaque subjects to the relying application or organization
when possible. Konclave does not require a human email, account name, or globally
correlatable identifier. The verifier uses the raw subject only for validation and
profile derivation, then discards it; durable state retains the installation-local
profile and no raw provider subject.

Nonce consumption and grant issuance occur atomically. An ambiguous grant response
uses the existing issuer request identifier and exact assertion digest to recover the
same durable result; a different request or assertion cannot reuse the consumed
challenge.

### Define lifecycle semantics

| Harness event | Required attestation behavior |
| --- | --- |
| New session | New session subject, new instance, new ephemeral key, new grant |
| Resume | Same session subject, new instance and assertion, new ephemeral key and grant |
| Extension or CLI restart followed by resume | Same subject only when the harness attests the resume; never infer from local files |
| Fork | New subject with optional signed parent-subject digest; never reuse the parent profile |
| Remote control | Same underlying session subject; controller identity is separate metadata and grants no extra authority |
| Subagent using parent tools | Uses the parent grant and is not represented as an independently attested session |
| Independently addressable subagent | Requires its own host assertion and profile; missing call-scoped identity fails closed |
| Session migration to another machine | Assertion remains bound to the destination installation; profile/device migration stays explicit |

Model changes, working-directory changes, titles, prompts, process IDs, and timestamps
do not change session identity.

### Pin provider trust without TOFU

A provider registration contains a stable provider identifier, accepted algorithms,
verification roots or a signed key-set root, validity policy, and supported lifecycle
claims. Installation is an explicit owner action.

Its extension policy pins exact executable digests or a signed publisher provenance
chain that resolves to the digest the host reports. A name, path, manifest, or
caller-declared version never substitutes for that check.

Key rotation is accepted only through a signature chaining to an already trusted root
or another explicit owner update. Outbound key-set refresh may update a bounded cache,
but an unavailable network never causes trust-on-first-use or fallback. Offline
verification is available only while a previously authenticated key set remains
valid.

Provider key revocation maps to the existing durable issuer lifecycle. Disabling a
provider key blocks new assertions and applies the configured retain-or-revoke policy
to existing grants; the local service observes the resulting authorization generation
within the existing one-second bound.

### Require one minimal upstream capability

The smallest useful harness API is an extension-callable operation conceptually
equivalent to:

```text
attestSession({
  contractVersion,
  nonce,
  connectionId,
  audience,
  installationFingerprint,
  localServicePublicKey,
  requestId,
  sessionPublicKey,
  requestedCapabilities,
  expectedExtensionPolicy
}) -> signedAssertion
```

The host, not the extension, fills the session subject, instance, lifecycle, parent,
harness, and loaded-extension claims. The signing key is not exportable to the
extension. The host returns the assertion only to the extension instance that
requested it; the extension submits it on the same provisional service connection
and does not expose a model-visible signing oracle. The vendor publishes a
verification-key and rotation contract. The assertion is short-lived,
challenge-bound, and valid only for the requesting installation.

An API that only returns the current session ID, an unsigned metadata object, a bearer
token not bound to the challenge, or a signature made with an extension-readable key
does not satisfy this request.

### Ship no production provider yet

Konclave continues using `AccountTrusted` for Copilot CLI and Generic clients.
`HarnessAttested` remains unavailable until a provider satisfies this contract.
Configuring a policy that requires it returns
`required_evidence_unavailable`; there is no heuristic or silent downgrade.

## Serious alternatives

### Trust `SESSION_ID`, hook payloads, or transcript files

**Pros:** available now and sufficient for AccountTrusted continuity.

**Cons:** mutable or replayable by same-account code, not bound to a service challenge
or session key, and not independently verifiable. Rejected.

### Let the extension sign with an owner-protected local key

**Pros:** offline and straightforward to implement.

**Cons:** another same-account process can use or replace the same key, so the result
is still AccountTrusted. Rejected.

### Trust executable signatures, install paths, or package digests alone

**Pros:** can identify distributed code.

**Cons:** does not prove which live session requested the grant, bind an ephemeral key,
or cover resume and fork semantics. Retained only as one assertion claim checked with
session identity, never sufficient alone.

### Accept a vendor bearer session token directly

**Pros:** standard JWT verification can prove vendor-issued session or workload
identity.

**Cons:** a bearer token can be copied by code in its environment and may not bind the
Konclave challenge, profile, key, capabilities, or extension. It may satisfy a
provider-specific workload claim but not this contract without proof-of-possession or
challenge binding. Rejected as the general HarnessAttested mechanism.

### Verify every assertion through an online introspection service

**Pros:** immediate key rotation and revocation.

**Cons:** makes local authorization dependent on network availability and central
observation. Allowed only as an explicit provider mode, not as the universal
contract.

### Reuse user-presence proof

**Pros:** can provide a stronger same-user boundary on supported platforms.

**Cons:** proves a human ceremony rather than harness identity and has different
lifecycle and automation semantics. Kept as the separate `UserPresence` evidence
kind.

## Consequences

### Positive

- `HarnessAttested` has a precise meaning that excludes heuristics and self-assertion.
- Provider-specific token formats do not leak into the core grant protocol.
- Assertions cannot be replayed across services, profiles, session keys, or
  capability sets.
- Resume, fork, remote control, subagents, and migration have explicit behavior.
- Hosted providers may use outbound verification while platform signers can support
  bounded offline operation.

### Negative

- No current local Copilot CLI or Claude Code integration can claim
  `HarnessAttested`.
- Vendor support is required before the strongest automatic path can ship.
- Verification-key distribution and rotation become provider responsibilities.
- Short-lived assertions require renewal and explicit handling of offline expiry.
- Extension updates require an explicit digest/publisher-policy transition before the
  new code can receive attested grants.

### Neutral

- `AccountTrusted`, `UserPresence`, and `WorkloadIdentity` remain independent evidence
  kinds and may be combined by policy.
- Existing exact-profile grants and operational RPCs remain unchanged.
- A future provider may use JWT/JWS, COSE, or another signed carrier as long as its
  verifier produces the same normalized claims.

## Confirmation

Continued compliance requires:

- deterministic challenge and normalized-claim vectors for every provider;
- negative cases for wrong audience, nonce replay, different provisional connection,
  stale challenge, expired assertion, caller-selected or substituted profile, wrong
  session key, capability escalation, unknown key, disallowed algorithm, extension
  mismatch, lifecycle substitution, fork-as-resume, and independent-subagent fallback;
- boundary cases for every provider-declared size and clock-skew limit;
- persistence and logging tests proving raw provider subjects are discarded;
- provider tests proving the signing key is unavailable to extension code;
- resume and restart tests preserving only the verified session subject;
- fork and migration tests preventing silent profile reuse;
- key-rotation tests with cached offline verification and fail-closed expiry;
- a specialized security review before any provider can issue
  `HarnessAttested`; and
- a new ADR if a provider cannot meet this contract but seeks to reuse the evidence
  name.

## References

- [ADR 0009: Evidence-bound exact-profile session grants](adr-0009-evidence-bound-session-grants.md)
- [Harness attestation provider contract](../development/harness-attestation.md)
- [GitHub Copilot CLI extension architecture](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-cli-extensions)
- [GitHub Copilot CLI hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Copilot SDK 1.0.11 extension entry point](https://github.com/github/copilot-sdk/blob/a550258d5c37bd662197536992a23d633bfe5804/nodejs/src/extension.ts)
- [Copilot SDK 1.0.11 session lifecycle hooks](https://github.com/github/copilot-sdk/blob/a550258d5c37bd662197536992a23d633bfe5804/docs/hooks/session-lifecycle.md)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [Claude Code session identity for self-hosted environments](https://code.claude.com/docs/en/self-hosted-environments-identity)
- [Codex app-server attestation request](https://github.com/openai/codex/blob/1715e55076737158ba61d43158ede504de6d4ce1/codex-rs/app-server-protocol/src/protocol/v2/attestation.rs)
- [Codex app-server attestation provider](https://github.com/openai/codex/blob/1715e55076737158ba61d43158ede504de6d4ce1/codex-rs/app-server/src/attestation.rs)
