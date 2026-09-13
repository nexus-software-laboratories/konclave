# Harness attestation provider contract

Issue [#141](https://github.com/nexus-software-laboratories/konclave/issues/141)
asks what a harness must expose before Konclave can truthfully issue
`HarnessAttested` grants. ADR 0019 owns the decision. This page records the public API
survey, normalized provider contract, lifecycle matrix, conformance cases, and the
smallest upstream capability request.

The research baseline is 2026-09-13. Konclave currently packages
`@github/copilot-sdk` 1.0.11 from commit
`a550258d5c37bd662197536992a23d633bfe5804`. Public surfaces can change, so a provider
implementation must re-run this survey against its pinned harness version. The public
SDK 1.0.13 release and public main at
`f45c46fd1812f8bed5b4cbc250f47177c83068f0` were also checked; neither exposes a
verifier-facing session-attestation or challenge-signing contract.

## Finding

No inspected local harness API currently satisfies ADR 0019.

The available session identifiers and lifecycle events are useful for continuity
under `AccountTrusted`, but they are not signed, challenge-bound evidence. Konclave
must not relabel them as `HarnessAttested`.

This conclusion is limited to the documented public surfaces and source revisions
listed below. A private or future vendor API may provide stronger guarantees, but it
cannot be integrated until those guarantees and verifier inputs are public and
testable.

## Public capability matrix

| Surface | Verified public capability | Missing for `HarnessAttested` | Current classification |
| --- | --- | --- | --- |
| Copilot CLI extension | Separate child process; `joinSession()` reads `SESSION_ID`; SDK events expose start/resume, session ID, remote-steerable state, extension discovery, and subagent event IDs | No public challenge-signing API, verifier key set, assertion expiry/revocation contract, or host-computed extension digest | `AccountTrusted` only |
| Copilot SDK embedding host | Can create/resume sessions and declare caller metadata for telemetry/host attribution | Caller-declared identity is not authentication; no extension-callable signed exact-session assertion | Not evidence |
| Claude Code local hooks/plugins | Hook JSON includes `session_id`, lifecycle source, tool metadata, and subagent events | Local hook input is unsigned and available to same-account code; no challenge/session-key binding | `AccountTrusted` only |
| Claude Code self-hosted cloud session | Anthropic-signed ES256 JWT identifies one session, environment, organization, and creator through published JWKS | Exportable bearer token; no Konclave nonce, service, profile, ephemeral key, capability, or loaded-extension binding | Candidate provider-specific workload/session-origin input, not sufficient as-is |
| Codex app-server | Thread lifecycle; experimental client-supplied opaque token for upstream `x-oai-attestation` | `attestation/generate` takes no caller challenge and publishes no general local verification contract | Not sufficient as-is |
| Codex native user verification | Platform ceremony signs a caller challenge with a registered P-256 credential | Proves user presence, not harness/session or extension identity | Candidate `UserPresence` provider |

## Why the current Copilot path is not attestation

The Copilot extension entry calls `joinSession()`. In SDK 1.0.11 that function reads
the plain `SESSION_ID` environment variable, creates a parent-process JSON-RPC client,
and resumes the named session. `ToolInvocation` carries `sessionId`, `toolCallId`,
tool name, and arguments. Lifecycle events add useful facts such as start versus
resume and subagent instance identifiers.

Those values originate from the host process, but the SDK exposes no signed artifact
that another local service can verify. The extension also receives no host-computed
digest of the code actually loaded. A same-account process can set an environment
variable, copy metadata, or run modified extension code. Process ancestry and
installation paths are similarly observations, not cryptographic proof.

This is sufficient for the existing, explicit `AccountTrusted` contract. It is not a
failure of that contract; it is the reason a stronger evidence name must remain
unavailable.

## Provider-neutral challenge

`konclave.harness-attestation.challenge.v1` is a logical, provider-independent value.
A future implementation freezes a canonical encoding and test vector before enabling
any provider.

| Field | Bound | Purpose |
| --- | --- | --- |
| `version` | Exact value `1` | Prevent cross-version interpretation |
| `nonce` | 32 random bytes, one use | Prevent replay |
| `audience` | Exact local-service installation/service identity | Prevent cross-service reuse |
| `profile` | Canonical profile, at most 32 ASCII bytes | Bind exact authority |
| `session_public_key` | 32-byte Ed25519 public key | Bind proof of possession |
| `harness` | Closed `HarnessKind` | Prevent relabeling |
| `capabilities` | Closed nonzero bitset | Prevent privilege expansion |
| `extension_policy` | Bounded configured identifier | Select approved extension identity rules |
| `issued_at` | Unsigned milliseconds | Bound freshness |
| `expires_at` | Greater than `issued_at`, within provider maximum | Bound challenge lifetime |

The caller may supply only the challenge fields. It never supplies session subject,
lifecycle, extension identity, evidence kind, issuer identity, or verified outcome.

The owner-restricted local service may issue this challenge before authorization, but
it allocates no profile runtime and performs no profile side effect. Pending
challenges are bounded globally and per connection, consumed once, and discarded on
service restart.

Provider identifiers and extension policy identifiers are at most 64 canonical ASCII
characters. Signing-key identifiers, opaque session subjects, session instances, and
source-qualified extension identifiers are each at most 128 bytes. Challenge and
extension digests are exactly 32 bytes. Opaque assertion carriers are at most 16 KiB.
Challenges expire within 60 seconds. Each provider declares a finite maximum assertion
lifetime, and grants never outlive their authorizing assertion.

## Normalized verified assertion

A provider adapter accepts an opaque signed carrier and returns this closed shape only
after verification:

```text
VerifiedHarnessAttestation
- contract version
- provider identifier and signing-key identifier
- exact challenge digest
- opaque session subject
- fresh session-instance identifier
- lifecycle: new | resume | fork
- optional parent-subject digest for fork
- exact harness kind
- source-qualified extension identifier
- loaded extension version when known
- SHA-256 digest of the extension code the host executed
- assertion issued-at and expiry
- provider revocation/generation metadata
```

The local service independently compares the normalized claims with its pending
challenge and provider policy. It derives the installation-local profile from the
verified session subject and rejects a caller-selected mismatch. Only this successful
comparison adds `HarnessAttested` to the evidence set used by ordinary grant
issuance.

Provider adapters own token syntax, certificate chains, JWKS parsing, and vendor
claims. The local-service grant protocol consumes only normalized validated claims.

The provider boundary is equivalent to:

```text
createChallenge(requestedProfile, sessionPublicKey, requestedCapabilities)
  -> PendingHarnessChallenge

verifyAssertion(pendingChallenge, opaqueAssertion, now)
  -> VerifiedHarnessAttestation | finite failure

issueGrant(verifiedAttestation)
  -> exact-profile SessionGrant with HarnessAttested evidence
```

The verifier derives the expected profile as:

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

This keeps a provider subject stable across resume while preventing it from becoming
a cross-installation identifier. The challenged profile must equal the derived value.
Providers should scope subjects to the relying application or organization when
possible; Konclave does not require a human email or globally correlatable account
identifier.

The initial deterministic derivation vector is:

| Input | Value |
| --- | --- |
| Installation fingerprint | 32 bytes of `0x11` |
| Provider identifier | UTF-8 `github-copilot` |
| Session subject | UTF-8 `session-example` |
| SHA-256 digest | `dffe52852461b2e6a99f832aa1143a387ec8e69f30284f1aa4511890af92ae06` |
| Derived profile | `session-dffe52852461b2e6a99f832a` |

Provider key disablement uses the existing durable issuer lifecycle. New assertion
verification fails after disablement, while existing grants follow the configured
retain-or-revoke disposition and the daemon's existing one-second observation bound.
Extension policy pins an exact loaded-code digest or a signed publisher provenance
chain that resolves to that digest. File paths, manifests, names, and caller-declared
versions remain diagnostics.

## Lifecycle requirements

| Lifecycle | Subject | Instance and key | Required outcome |
| --- | --- | --- | --- |
| New | New | New | New profile and grant |
| Resume | Same | New | Same profile; fresh assertion and grant |
| Extension/CLI restart with resume | Same only when host attests resume | New | Never recover continuity from local metadata alone |
| Fork | New; parent digest optional | New | New profile; parent context grants no authority |
| Remote control | Same root session | Existing or renewed | Remote controller metadata does not widen authority |
| Parent-owned subagent tool call | Parent | Parent | No independent grant |
| Independently addressable subagent | New signed subject | New | Separate profile/grant; missing identity denies |
| Cross-machine migration | Provider subject may persist | New and installation-bound | No silent device/profile migration |

## Required verification order

1. Parse within provider-specific size and structure bounds.
2. Require an allowlisted algorithm and registered signing key.
3. Verify the signature before trusting claims.
4. Verify provider, key validity, audience, and installation binding.
5. Match the exact challenge digest and consume the nonce once.
6. Check challenge and assertion time windows.
7. Check harness, extension identity/digest, session key, profile, and capabilities.
8. Validate lifecycle and parent relationships.
9. Apply provider revocation/generation state.
10. Produce normalized claims and issue the ordinary exact-profile grant.

Any failure returns a finite unavailable, invalid, expired, replay, or unauthorized
result. Missing provider support returns `required_evidence_unavailable`. No path
falls back to `AccountTrusted`.

## Deterministic conformance cases

A future provider must freeze canonical challenge bytes and provider assertion vectors
for at least these cases:

| Case | Expected result |
| --- | --- |
| Exact challenge and valid assertion | Accept once |
| Same assertion and consumed nonce | Replay rejection |
| Different local-service audience | Audience rejection |
| Different profile | Profile mismatch |
| Different ephemeral session key | Key mismatch |
| Expanded capability bitset | Capability mismatch |
| Challenge or assertion expired | Expired |
| Unknown key or disallowed algorithm | Untrusted issuer |
| Loaded extension digest differs from policy | Extension mismatch |
| Resume changes session subject | Lifecycle mismatch |
| Fork reuses parent subject | Lifecycle mismatch |
| Missing independent subagent identity | Evidence unavailable |
| Remote-control metadata claims extra authority | Ignore metadata; no authority increase |
| Unknown normalized claim or enum | Invalid assertion |

Vectors use fixed keys, timestamps, nonces, identifiers, and expected finite outcomes.
Provider-generated signatures are checked byte-for-byte only when that provider
defines a canonical signature representation.

## Smallest Copilot CLI capability request

Konclave needs one supported extension API:

```typescript
const assertion = await session.attest({
  contractVersion: 1,
  nonce,
  audience,
  localServicePublicKey,
  profile,
  sessionPublicKey,
  requestedCapabilities,
  expectedExtensionPolicy,
});
```

The CLI must:

- fill session subject, instance, lifecycle, optional fork parent, harness, and loaded
  extension identity/digest itself;
- sign the complete challenge and host claims with a key unavailable to the extension
  and arbitrary same-account processes;
- return a bounded, short-lived assertion with a unique identifier;
- publish an authenticated verification-key and rotation contract usable by local
  services;
- document behavior for new, resume, fork, extension reload, remote control,
  subagents, and migration; and
- fail explicitly when the current platform or account cannot produce the assertion.

The API may perform outbound vendor verification. An offline mode is valid only when
the host has a platform-protected signing key and the verifier has a still-valid
authenticated key set. Returning `SESSION_ID`, caller-declared `clientInfo`, an
unsigned object, or an exportable bearer token is insufficient.

No upstream issue is opened from this repository. This request is intentionally kept
as a public, sanitized specification until a maintainer chooses the appropriate
vendor channel.

## Requirements for other integrations

- **Claude Code local and IDE surfaces:** require a challenge-bound host signature,
  not the local `session_id`, transcript path, plugin manifest, or hook origin.
- **Claude self-hosted environments:** treat the signed session JWT as
  provider-specific workload or session-origin input. To become
  `HarnessAttested`, add proof-of-possession or a token exchange that binds the
  Konclave challenge, session key, profile, capabilities, and loaded extension.
- **Codex CLI and app-server:** an opaque `x-oai-attestation` token is insufficient
  without a documented verifier and caller-bound challenge. Native
  `userVerification/verify` belongs to `UserPresence`.
- **IDE integrations:** the editor or extension host must fill and sign the actual
  loaded extension identity. Caller-declared `clientInfo`, extension names, or paths
  remain diagnostics.
- **Workload integrations:** use `WorkloadIdentity` when the proof establishes an
  isolated workload principal rather than a harness session. Do not rename workload
  evidence to `HarnessAttested`.

## Sources

### GitHub Copilot

- [About Copilot CLI extensions](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-cli-extensions)
  documents that extensions are separate local Node.js processes.
- [Copilot CLI hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
  documents session IDs and lifecycle JSON delivered to local hooks.
- [Copilot SDK 1.0.11 `joinSession()`](https://github.com/github/copilot-sdk/blob/a550258d5c37bd662197536992a23d633bfe5804/nodejs/src/extension.ts)
  reads `SESSION_ID` and attaches over parent-process JSON-RPC.
- [Copilot SDK 1.0.11 session types](https://github.com/github/copilot-sdk/blob/a550258d5c37bd662197536992a23d633bfe5804/nodejs/src/types.ts)
  expose session/tool invocation metadata but no verifier-facing assertion API.
- [Copilot SDK 1.0.11 lifecycle events](https://github.com/github/copilot-sdk/blob/a550258d5c37bd662197536992a23d633bfe5804/nodejs/src/generated/session-events.ts)
  distinguish session start/resume, remote steering, extension discovery, and
  subagent events.
- [Copilot SDK 1.0.13 release](https://github.com/github/copilot-sdk/releases/tag/v1.0.13)
  is the newest published SDK release inspected for this decision.
- [Copilot SDK host identity request](https://github.com/github/copilot-sdk/issues/2465)
  explicitly defines `clientInfo` as caller-declared attribution rather than
  authentication.

### Claude Code

- [Claude Code hooks](https://code.claude.com/docs/en/hooks) document local session
  and subagent event metadata.
- [Claude Code sessions](https://code.claude.com/docs/en/sessions) document resume,
  branching, and cross-worktree behavior.
- [Claude Code Remote Control](https://code.claude.com/docs/en/remote-control)
  keeps execution in the same local session while other devices control it.
- [Self-hosted environment session identity](https://code.claude.com/docs/en/self-hosted-environments-identity)
  documents the signed bearer JWT, its JWKS verification, claims, and limitations.

### Codex

- [Codex CLI reference](https://developers.openai.com/codex/cli/reference) documents
  thread resume and fork behavior.
- [Codex attestation request](https://github.com/openai/codex/blob/1715e55076737158ba61d43158ede504de6d4ce1/codex-rs/app-server-protocol/src/protocol/v2/attestation.rs)
  returns one opaque token from an empty request.
- [Codex attestation provider](https://github.com/openai/codex/blob/1715e55076737158ba61d43158ede504de6d4ce1/codex-rs/app-server/src/attestation.rs)
  forwards that token into an upstream request header.
- [Codex app-server user verification](https://github.com/openai/codex/blob/1715e55076737158ba61d43158ede504de6d4ce1/codex-rs/app-server/README.md#user-verification-experimental)
  signs caller challenges after a native ceremony and therefore informs the separate
  `UserPresence` provider.
