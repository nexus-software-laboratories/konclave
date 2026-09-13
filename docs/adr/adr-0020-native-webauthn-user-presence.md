---
title: Prove UserPresence with native WebAuthn verification
status: Accepted
date: 2026-09-13
authors:
  - Konclave maintainers
tags:
  - authorization
  - user-presence
  - webauthn
  - windows
supersedes: []
superseded_by: []
---

# Prove UserPresence with native WebAuthn verification

## Context and scope

ADR 0009 defines `UserPresence` as authorization evidence produced by a human
ceremony that an unattended process cannot satisfy. The existing grant protocol can
record that evidence, but no provider currently proves it. A model-visible
confirmation, terminal prompt, owner-only file, operating-system account token, or
caller-declared success value would let an unattended process approve itself and
therefore cannot set the `UserPresence` evidence bit.

The provider must bind one exact grant request, keep the ephemeral session private key
in the requesting client, and preserve Konclave's requirement that no
internet-reachable or loopback listener is required. It must also distinguish proof
of a fresh user-verification ceremony from proof that a key merely exists.

This decision defines the proof contract, credential lifecycle, first production
adapter, unsupported-platform behavior, and local trust limitations for
`UserPresence`. It does not define harness identity, remote user authentication,
conversation membership approval, or operation-by-operation transaction signing.

## Verified facts

- The local service already issues finite grants bound to one profile, session public
  key, harness, evidence set, policy version, capability bitset, and expiry.
- The installed AccountTrusted issuer credential is available to processes under the
  configured operating-system account. It may authenticate a request for a presence
  challenge, but it cannot itself prove human presence.
- Current Copilot CLI and Claude Code integration surfaces expose no independently
  verifiable challenge-signing ceremony.
- Codex app-server's experimental `userVerification/verify` contract signs an exact
  caller challenge, but the inspected native implementation is macOS-only and its
  credential registration is tied to Codex account state.
- Windows `WebAuthNAuthenticatorMakeCredential` creates a public-key credential and
  returns its public verification material. `WebAuthNAuthenticatorGetAssertion`
  returns an authenticator assertion that represents user consent to a specific
  transaction and accepts an explicit user-verification requirement.
- A WebAuthn assertion signs authenticator data together with the hash of client data.
  The verified client data contains the random challenge and origin; authenticator
  data contains the relying-party hash and user-presence and user-verification flags.
- The pure-Rust `passkey-auth` API can require user verification, retain pending
  challenge state server-side, enforce strict base64url input, and verify challenge,
  origin, relying party, credential, signature, flags, user handle, and counter
  behavior without adding OpenSSL to the package.
- The `webauthn-authenticator-rs` Windows backend maps the same safe challenge DTOs to
  the native Windows WebAuthn API without a browser or listener. It is pre-1.0 and not
  itself a trust boundary because the local service independently verifies every
  returned registration and assertion.
- The repository packages Linux, Windows, and macOS applications, but currently has
  no equivalent native user-verifying adapter for Linux or macOS.

## Assumptions

- The Windows WebAuthn broker and selected authenticator correctly enforce a request
  whose user-verification policy is `required`.
- A user who completes the Windows system ceremony intends to authorize the Konclave
  request shown immediately before it. Social engineering the user into approving an
  attacker-initiated ceremony is outside the cryptographic guarantee.
- A registered passkey may be platform-bound, roaming, or synchronized. This decision
  requires fresh user verification, not device attestation or legal identity.
- Hostile durable rollback by another same-account process remains outside the first
  provider's cross-restart guarantee unless a later provider adds a protected
  monotonic anchor. The running service's existing generation high-water mark still
  rejects rollback during that process lifetime.
- The installed Konclave binaries and credential-registration record are intact.
  Replacing the executable or rolling the complete installation back to a
  pre-enrollment state is outside the first local provider's guarantee.

## Decision drivers

- Require fresh human action that an unattended same-account process cannot complete.
- Bind the action to the exact profile, session key, harness, capabilities, policy,
  service, installation, request, and expiry.
- Preserve the outbound-only network model and avoid a browser callback.
- Use a pinned pure-Rust verifier rather than authoring custom WebAuthn parsing or
  signature validation or adding a second native cryptographic provider.
- Keep platform user-interface mechanics behind an adapter boundary.
- Fail closed on unsupported hardware, platforms, stale credentials, cancellation,
  replay, and downgrade.
- Permit an exact retry after an ambiguous response without issuing a second grant.
- Test the decision component independently before daemon, client, CLI, extension, or
  package integration.

## Decision

### Define UserPresence as verified WebAuthn user verification

Konclave sets `UserPresence` only after the service completes a WebAuthn authentication
with:

- an explicitly enrolled credential;
- the expected relying party and native-application origin;
- the exact pending service challenge;
- the expected credential identifier;
- user presence and user verification both asserted;
- a valid authenticator signature and credential counter transition; and
- no unrecognized or downgraded verification state.

The server uses pinned `passkey-auth` with strict base64url decoding and user
verification required. Pending registration and authentication state remains
service-side and is never accepted from the client. Credential state is serialized
only in the owner-protected durable authorization store.

The first provider identifier is `windows-native-webauthn-v1`. Its relying-party ID is
`konclave.local` and its synthetic native-application origin is
`https://konclave.local`. These values are protocol constants. They do not imply DNS,
HTTP, TLS, or an inbound listener; they scope the authenticator credential and signed
client data used by the native Windows API.

### Bind the random WebAuthn challenge to the exact request

An authenticated issuer connection requests a presence challenge naming:

- the current authorization policy version;
- the exact profile;
- the ephemeral session public key;
- the harness;
- the requested capability bitset; and
- the requested grant expiry, bounded to at most one hour.

The client also proves possession of the ephemeral session private key over a
service-supplied request digest before a platform ceremony is created. This prevents
another same-account process from directing approval to an arbitrary public key it
does not control.

The service creates a fresh WebAuthn authentication challenge and retains one pending
record containing:

- the random challenge and verifier state;
- an issuer-connection identifier;
- installation fingerprint and local-service public key;
- issuer key identifier and version;
- issuer client instance and request identifier;
- policy version;
- profile, session public key, harness, capabilities, and expiry;
- provider and credential identifier;
- the session proof-of-possession digest; and
- issued-at and challenge-expiry timestamps.

The random challenge is therefore a cryptographic handle for the complete
service-owned request. The client cannot modify a bound field by editing WebAuthn
options or returned assertion bytes: the verifier either resolves the original
pending state or rejects the response.

Challenges expire within 120 seconds. An unconsumed challenge is valid only on the
issuer connection that received it and is removed on disconnect, service restart,
policy change, issuer disablement, cancellation, or timeout.

The grant's profile, key, harness, evidence, policy version, capability bitset, and
expiry must exactly match the pending request. Grant expiry never exceeds one hour or
the owner-approved expiry.

### Keep the approval UI outside the agent surface

The Konclave platform helper displays a bounded request summary before invoking
Windows WebAuthn:

- exact profile and harness;
- requested capabilities;
- requested grant duration; and
- an explicit statement that approval authorizes the named local session.

The Windows WebAuthn broker owns the modal user-verification UI. Neither a model tool
response nor terminal input can substitute for the returned signed assertion.
Production APIs accept no caller-supplied "approved" boolean.

A hostile same-account process can initiate its own legitimate ceremony and may try
to mislead the user. If the user approves that system ceremony, the attacker can
obtain the exact grant it requested. `UserPresence` proves fresh human verification;
it does not prove that the human correctly interpreted every prompt. Signed helper
distribution may improve attribution later but is not represented as a stronger
evidence kind.

Batch approval and implicit approve-all behavior are not supported. Every grant
requires a separate native ceremony. One successful ceremony authorizes reuse of the
same grant and ephemeral session key until its expiry; it does not prove user presence
for each later operation.

### Make ambiguous completion recoverable but non-transferable

Challenge completion has two distinct states:

- Before durable grant issuance, the challenge remains connection-bound. Disconnect
  or service restart discards it and the user must repeat the ceremony.
- After durable issuance, the terminal result is keyed by issuer client instance,
  request identifier, challenge digest, assertion digest, and session public key.

An identical retry on another authenticated issuer connection may return that already
issued grant during the bounded idempotency window, even after the original challenge
or connection has expired. It cannot issue a second grant. Any changed assertion,
request, profile, key, harness, capability set, policy, credential, or expiry fails.

Replaying public assertion bytes does not operate the grant because the ordinary
session handshake still requires the approved ephemeral private key.

### Enroll credentials through an explicit owner ceremony

Fresh `UserPresence` setup is an explicit interactive owner action. The service starts
a WebAuthn registration with user verification required; the returned credential is
not retained until the service verifies that registration and the new credential
successfully authenticates an enrollment-lifecycle challenge.

The initial credential record and selected policy are committed together. An existing
installation may add a credential only through an explicit administrative flow that
also completes the new credential's verification ceremony.

Once a credential exists, replacing or deleting it requires either:

- a fresh assertion from the currently registered credential over the exact
  credential-lifecycle request; or
- an explicitly configured recovery authority from ADR 0009.

Creating another authenticator credential does not replace the registered one.
Credential loss, authenticator reset, or removal requires recovery or another already
accepted policy clause.

Selecting a policy whose only satisfiable clause is `UserPresence` requires either a
configured recovery authority or the explicit no-recovery acknowledgement required by
ADR 0009. The interface states that losing every registered credential can
permanently strand profile administration.

Any policy change that makes the effective policy satisfiable by evidence weaker than
the current policy must itself satisfy the current policy or the configured recovery
authority. Adding `AccountTrusted` to a UserPresence-only policy is therefore a
presence-authorized downgrade, not a same-account file operation. Direct hostile
replacement or rollback of the complete persisted installation remains the explicit
cross-restart limitation stated above.

### Ship the Windows native adapter first

The first production adapter uses the Windows WebAuthn API from a user-interactive
Konclave helper process. It requires a Windows build whose WebAuthn API is available
and an authenticator able to satisfy `userVerification: required`, such as Windows
Hello or a compatible FIDO2 authenticator.

The service never trusts the helper's success status. It accepts only the standard
registration or assertion object after independent safe-library verification. The
helper cannot select a different relying party, origin, policy, challenge, or
credential than the service-provided options.

Cancellation uses the Windows WebAuthn cancellation API and produces no proof.
Provider absence, no enrolled credential, user cancellation, timeout, invalid
assertion, stale challenge, and credential counter failure map to distinct finite
provider outcomes.

Linux and macOS initially report `required_evidence_unavailable`. They do not use a
software signing key, terminal confirmation, browser callback, or AccountTrusted
fallback. Future native adapters may use platform WebAuthn, Secure Enclave, or FIDO2
hardware only after satisfying the same server-owned challenge, verified
user-verification, lifecycle, downgrade, and retry contract.

### Treat harness-owned primitives as adapters, not evidence by assertion

A harness user-verification API may participate only when Konclave can enroll its
public credential and independently verify the returned proof over the exact pending
challenge.

The current Codex API is useful prior art, but its availability, account identity,
credential identifier, or caller-provided display text is not itself
`UserPresence`. Copilot and Claude remain unsupported until they expose equivalent
verifiable proof or invoke the Konclave-owned platform helper.

### State the assurance boundary honestly

Given intact installed state and binaries, this provider proves that an authenticator
reported fresh user verification for the exact pending grant request. It does not
prove a legal identity, a hardware make or model, correct human interpretation of the
prompt, presence at each later operation, or confidentiality from a compromised
authorized process.

Another same-account process may trigger a legitimate system prompt, delete or corrupt
availability state, or deny service. It cannot complete the registered credential's
verification unattended or alter fields in an accepted assertion. Full
installation-state replacement or rollback across service restart remains outside the
first provider's guarantee and must not be described as prevented.

## Serious alternatives

### Browser WebAuthn through localhost

**Pros:** standardized browser mediation and broad authenticator support.

**Cons:** adds a loopback listener or another response channel, browser origin and
port lifecycle, and a larger UI surface despite Windows already exposing the native
API. Rejected for the first provider.

### Hosted WebAuthn page with an outbound rendezvous

**Pros:** cross-platform, origin-authenticated UI, no local listener.

**Cons:** turns local authorization into an internet-dependent control plane, adds
rendezvous confidentiality and availability, complicates self-hosting, and cannot
serve offline installations. Rejected.

### Windows CNG strong-key UI

**Pros:** TPM-backed keys, no browser or listener, and configurable strong-key UI.

**Cons:** CNG's strong-key protection and PIN properties vary by provider, while
WebAuthn has explicit challenge, relying-party, user-presence, and user-verification
semantics plus a maintained verifier. Rejected in favor of native WebAuthn.

### macOS Secure Enclave direct signing

**Pros:** arbitrary challenge signing with biometric-protected, non-exportable keys
and no listener.

**Cons:** packaging and keychain entitlement behavior for the current unsigned CLI
distribution is not yet verified, and it would not serve the repository's Windows
first-use path. Deferred pending a signed-package spike.

### Codex userVerification as the universal provider

**Pros:** already exposes challenge signing and protected-key metadata.

**Cons:** the inspected implementation is macOS-only, tied to Codex account state,
experimental, and unavailable to Copilot and generic clients. It may become one
adapter but cannot define the universal contract. Rejected.

### Require an external FIDO2 security key everywhere

**Pros:** portable authenticators and strong user verification.

**Cons:** requires extra hardware and management and is less effortless than allowing
Windows Hello through the same native WebAuthn verifier. Deferred as an optional
authenticator, not the sole provider.

## Consequences

### Positive

- Given intact registration and binaries, an unattended same-account process cannot
  produce an accepted user-verifying assertion.
- Every accepted assertion resolves to one complete service-owned grant request.
- No internet-facing or loopback callback is introduced.
- Windows Hello and compatible FIDO2 authenticators share one standard verifier.
- Exact ambiguous retries recover one grant without making an assertion transferable.
- Unsupported platforms and missing authenticators fail explicitly.

### Negative

- The first production provider works only on supported Windows systems.
- Linux and macOS users cannot select a UserPresence-only policy yet.
- WebAuthn credential state and pending verifier state add a new durable and in-memory
  lifecycle.
- Lost credentials can strand a no-recovery installation.
- A user can approve an attacker-initiated legitimate prompt.
- One ceremony authorizes the resulting grant for up to one hour.
- The first local provider does not add cross-restart hostile rollback resistance.
- The native client adapter is MPL-2.0 and the newer pure-Rust verifier needs focused
  supply-chain and security review.

### Neutral

- AccountTrusted remains the effortless default where the owner explicitly chooses
  same-account trust.
- UserPresence does not identify the harness session; it may be combined with
  HarnessAttested in an all-of policy.
- Conversation membership and message encryption remain unchanged.
- A valid grant may reconnect until expiry with the same session key; a new key or
  process restart requires a new ceremony.

## Confirmation

Continued compliance is demonstrated by:

- deterministic pure state-transition tests for pending, approved, committed,
  recovered, consumed, cancelled, expired, policy-changed, provider-disabled, and
  unavailable requests;
- table-driven binding tests for wrong installation, service, connection, request,
  policy version, profile, session key, session proof, harness, capabilities,
  credential, and expiry;
- WebAuthn registration and authentication vectors proving exact challenge, relying
  party, origin, credential, signature, user-presence flag, user-verification flag,
  and counter validation;
- exact-retry tests proving one durable grant and variant-replay rejection;
- tests proving issued capabilities and expiry exactly match the approved request;
- tests proving model tools and ordinary session grants cannot invoke enrollment,
  credential replacement, policy weakening, or batch approval;
- tests proving a UserPresence-only policy requires recovery or explicit
  no-recovery acknowledgement;
- Windows compile and platform-contract validation plus a real interactive Windows
  Hello or FIDO2 smoke before publication;
- package and status tests proving unsupported platforms fail closed without
  AccountTrusted fallback; and
- focused hosted component validation before daemon, client, CLI, extension, or
  package integration.

## References

- [ADR 0009](adr-0009-evidence-bound-session-grants.md) establishes exact-profile
  grants, non-ordered evidence kinds, provider-owned session-key custody, explicit
  recovery, and no silent downgrade.
- [ADR 0019](adr-0019-harness-owned-session-attestation.md) establishes the related
  challenge-first and provider-verification boundary for a different evidence kind.
- [Threat model](../security/threat-model.md) describes the same-account adversary,
  local-service trust boundary, and explicit AccountTrusted limitation this provider
  strengthens without changing plaintext custody.
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) defines the
  challenge, relying-party, client-data, authenticator-data, user-presence, and
  user-verification bindings verified by the provider.
- [Windows
  `WebAuthNAuthenticatorGetAssertion`](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion)
  defines the native modal assertion ceremony used by the first adapter.
- [`passkey-auth` 0.1.3](https://crates.io/crates/passkey-auth/0.1.3) provides the
  pinned pure-Rust relying-party verifier used by the local service.
- [OpenAI Codex revision
  `1715e55076737158ba61d43158ede504de6d4ce1`](https://github.com/openai/codex/tree/1715e55076737158ba61d43158ede504de6d4ce1/codex-rs/user-verification)
  provides public prior art for challenge-signing lifecycle and explicit
  unsupported-platform behavior.
