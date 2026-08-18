# Threat model

This document is the canonical owner of Konclave's security goals, trust boundaries,
adversaries, and acknowledged limitations. Architecture decisions select mechanisms;
the protocol compatibility contract defines wire behavior; conformance tests provide
evidence that implementations honor both.

## Protected assets

- message plaintext and attachments;
- device root private keys and per-conversation MLS private keys;
- MLS epoch secrets, resumption secrets, and persisted group state;
- invitation capabilities and local authorization credentials;
- membership integrity and administrator policy;
- message authenticity, ordering, acknowledgment, and replay state;
- local daemon control and decrypted history.

## Components and trust boundaries

### Local daemon

The daemon is the trusted endpoint boundary. It owns device identity, MLS state,
plaintext processing, local authorization, and sealed persistence. Inputs from
models, extensions, CLI processes, IPC peers, files, and network services remain
untrusted even when they originate on the same machine.

### Agent harnesses and extensions

Harnesses and extensions are adapters, not cryptographic endpoints. They may request
authorized operations and receive application results, but they never receive raw
identity keys, MLS secrets, provider state, or storage encryption keys. Model-produced
tool arguments are validated like hostile network input.

### Community relay

The relay is untrusted for message confidentiality, message authenticity, membership
policy, and identity validation. It may observe allowlisted routing metadata and
standard MLS framing data needed for delivery. It may delay, drop, duplicate,
reorder, or selectively deliver messages. It cannot be trusted to report complete
history.

The initial protocol explicitly trusts the relay not to equivocate when selecting one
epoch-changing Commit and durable cursor sequence. Clients detect conflicts they
observe and fail closed, but cannot detect permanently isolated split views. A relay
that violates this non-equivocation assumption can keep stale members on a fork and
break membership-removal consistency even though it still cannot forge MLS messages.

### Local persistence and platform key custody

The ordinary filesystem and SQLite database are not trusted to keep secrets
confidential after offline theft. Secret state is stored only as sealed blobs using a
key controlled by a supported platform custody adapter. There is no plaintext
fallback. Root or administrator compromise while the daemon is active is outside the
confidentiality guarantee.

### Network

All network paths are attacker controlled. TLS is still required to protect transport
metadata, tokens, and denial-of-service controls even though MLS protects message
content.

## Adversaries

Konclave considers:

- a passive network observer;
- an active network attacker who can inject, alter, replay, or suppress traffic;
- a compromised or malicious relay;
- an attacker who obtains an invitation capability;
- a malicious or compromised current group member;
- a stale or downgraded client;
- a local unprivileged process attempting unauthorized daemon operations;
- an attacker with offline access to persisted files;
- malformed, oversized, or adversarial protocol input;
- model output attempting to misuse daemon tools;
- compromise of one endpoint's active keys and memory.

## Security goals

### Confidentiality

Only devices in the current MLS epoch can decrypt application content. New members
cannot decrypt earlier epochs, and removed members cannot decrypt later epochs.
Relays and passive network observers cannot decrypt application content.

### Authentication and integrity

Recipients authenticate the sending conversation key and its binding to a device
identity. Every membership change is checked against the shared application policy.
Invalid signatures, credentials, versions, epochs, or authorization fail closed
before durable side effects.

### Forward secrecy and post-compromise recovery

Deleted epoch secrets cannot be recovered from current state. Clients update
conversation keys after membership changes and on a bounded cadence. MLS
post-compromise recovery applies only when the device root identity key remains
uncompromised.

Extraction of a device root key permanently compromises that `DeviceId`. Recovery
requires removal of the old device, an epoch advance, and enrollment of a newly
generated `DeviceId` through an unaffected administrator and independently verified
invitation.

### Replay and duplicate handling

Every application message has a signed, conversation-scoped unique identifier.
Clients persist deduplication state and treat repeated delivery as idempotent. Relay
cursors provide delivery progress but are not accepted as cryptographic freshness.

### Least privilege

Only the daemon handles raw secret material. Relay and adapter interfaces expose the
minimum data required for their role. Logs and telemetry contain bounded,
allowlisted metadata only.

### Version integrity

Peers negotiate supported Konclave and MLS versions. Unsupported versions and empty
intersections fail closed. A peer or relay cannot silently force a lower version than
the mutually supported maximum.

## Threats and required mitigations

| Threat | Required mitigation |
| --- | --- |
| Relay reads content | MLS PrivateMessage application payload; no plaintext fields in relay persistence or logs |
| Relay modifies or forges content | MLS authentication and client-side credential validation |
| Relay suppresses messages | Sender generations, durable cursors, acknowledgments, gap detection, and visible degraded state |
| Relay forks epoch history | Outside the initial non-equivocation assumption; reject observed conflicts, halt sending on unresolved branches, and require a trusted sequencer until transparency or reconciliation is designed |
| Insider replays a valid message | Signed application message identifier and persistent deduplication |
| Unauthorized member change | Administrator policy checked by every client before applying the Commit |
| Invitation theft | Bind the signed invitation to an independently verified expected `DeviceId`, conversation, role, expiry, and nonce; enforce consumption in authenticated conversation state |
| Credential substitution | Device-root binding validation and optional out-of-band fingerprint comparison |
| Device root-key extraction | Remove the compromised `DeviceId`, advance the epoch, and enroll a new independently verified `DeviceId`; do not claim recovery through MLS update alone |
| Protocol downgrade | Signed capability negotiation and fail-closed version selection |
| Oversized or malformed input | Pre-allocation bounds, deterministic parsing, property tests, fuzzing, and regression fixtures |
| Offline database theft | Sealed secret blobs; no plaintext-key fallback |
| Secret disclosure through diagnostics | No `Debug`, serialization, logs, telemetry, panic text, or snapshots containing keys/plaintext |
| Malicious model/tool input | Schema validation, local authorization, bounded values, and explicit user-controlled policy |
| Dependency/provider compromise | Exact versions, supply-chain review, upstream advisories, isolated adapter, and replaceable provider boundary |

## Explicit non-goals and limitations

- Konclave cannot keep plaintext secret from a device compromised while plaintext or
  active keys are available.
- An authorized member can copy or disclose plaintext it legitimately receives.
- Konclave cannot guarantee availability against a malicious relay or network.
- The initial protocol cannot guarantee consistent membership against a relay that
  equivocates between isolated clients.
- Initial releases do not hide routing identifiers, timing, payload sizes, IP
  addresses, or all membership-related metadata.
- Initial device identity does not prove a human legal identity.
- The first release does not provide key transparency or federation.
- Secure deletion depends on operating-system and storage behavior and cannot be
  proven for every physical medium.
- MLS conformance and library tests do not constitute an independent security audit
  of Konclave.

## Security-sensitive change gate

Changes affecting cryptography, identity, invitations, authorization, membership,
wire parsing, replay state, secret persistence, relay-visible metadata, or security
logging require:

1. focused tests against the applicable invariant;
2. conformance evidence defined by the project policy;
3. repository review through `review-changes`;
4. a specialized security review before delivery;
5. an ADR update or superseding ADR when the trust model or mechanism changes.
