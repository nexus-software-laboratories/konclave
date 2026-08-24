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
- pairing capabilities, directional pairing keys, and pairing authorization state;
- ephemeral local adapter capabilities and authenticated delivery leases;
- relay bearer credentials and authorization policy;
- membership integrity and administrator policy;
- message authenticity, ordering, acknowledgment, and replay state;
- local daemon control and decrypted history.
- remote-event ordering, acknowledgment, mute, and suppression state.

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
tool arguments are validated like hostile network input. An authorized adapter
necessarily receives plaintext selected for its harness and can disclose that
plaintext if compromised.

### Local adapter channel

An adapter owns an operating-system local endpoint and an owner-protected ephemeral
capability file. It passes the endpoint and capability-file path to the daemon child.
The daemon validates and reads that file without following links or reparse points,
then connects outward and mutually authenticates the profile and adapter before
serving a neutral wait, claim, and acknowledgment API. The endpoint is not a TCP
listener and is never reachable from the network.

Endpoint names and capability-file paths are not credentials. Unix filesystem
permissions and Windows named-pipe access policy reduce local exposure, while a
256-bit capability and versioned challenge-response provide peer authentication.
The capability file exists only for the lifetime of the adapter endpoint and is
never copied into harness session configuration, profile persistence, or logs. A
failed or absent adapter cannot cause an unauthenticated fallback.

The adapter-delivery journal is independent of relay cursors. Relay acknowledgment
means the daemon durably processed an envelope; adapter acknowledgment means a
harness accepted one bounded notification. Neither means that a model completed or
obeyed a turn.

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

### Pairing capabilities

A pairing capability is a short-lived bearer secret issued by the device asking to
join. It carries a root-signed public offer and enough secret material to derive one
random relay route plus direction-specific pairing keys. Possession authorizes a
pairing attempt; it does not identify the human or organization controlling the
device.

Both endpoints explicitly authorize the identity and role they observe. The inviter
approves the joiner's root-signed device offer before issuing an invitation. The
joiner approves the inviter identity authenticated by that invitation before emitting
a JoinProof. Policy may automate either decision only when it states that it is
trusting bearer-capability possession rather than independently verified identity.

Pairing records are encrypted before relay submission. Their clear header is
authenticated as associated data and binds pairing, logical message, sender role,
stage, reply chain, deadline, and nonce. Direction-specific keys prevent reflection
between inviter and joiner roles. Invalid, replayed, reordered, or conflicting relay
records do not advance durable pairing state.

Capability expiry stops new authorization. An add-member Commit already accepted
before expiry remains a real membership change: its exact Welcome may complete during
a separate recovery deadline, after which the inviter compensates by removing a member
that never completed pairing.

Pairing capabilities never contain relay bearer credentials. Zero-setup remote
pairing remains unavailable until a relay control plane can issue an exact-route,
short-lived principal.

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
- an attacker who obtains, copies, races, replays, or modifies a pairing capability;
- a malicious or compromised current group member;
- a stale or downgraded client;
- a local unprivileged process attempting unauthorized daemon operations;
- a local process attempting endpoint discovery, squatting, cross-profile attachment,
  capability replay, or stale lease acknowledgment;
- an attacker with offline access to persisted files;
- malformed, oversized, or adversarial protocol input;
- model output attempting to misuse daemon tools;
- a group member attempting prompt injection, wake-up abuse, or agent-to-agent loops;
- a crashed or malicious adapter attempting to lose, duplicate, reorder, or
  acknowledge another consumer's notifications;
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

### Harness delivery integrity

Remote events are sealed and ordered before relay acknowledgment. Adapter claims use
bounded leases distinct from relay progress. A harness accepts at-least-once delivery:
a crash before acknowledgment may repeat one stable notification identifier but
cannot silently erase the event.

Adapters safety-frame peer content as untrusted collaborator data. Peer text never
gains system, developer, permission, or tool authority. Automatic delivery is
explicitly enabled per conversation, bounded by wake budgets, and limited to one
outstanding synthetic turn.

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
| Welcome receipt substitution | Reserve the add Commit envelope identifier before MLS creation, authenticate it in signed Welcome GroupInfo, and require the exact relay receipt at checkpoint and reopen |
| Invitation theft | Bind the signed invitation to an independently verified expected `DeviceId`, conversation, role, expiry, and nonce; enforce consumption in authenticated conversation state |
| Pairing capability theft | Root-signed joiner offer, explicit endpoint authorization, short authorization deadline, one durable idempotent state machine, and no claim that bearer possession identifies a human |
| Pairing record injection or replay | Direction-specific AEAD keys, complete canonical-header authentication, stable logical message identifiers, reply-chain validation, and no state advance on invalid or unexpected records |
| Pairing expiry after membership commit | Separate completion deadline; recover the exact Welcome or issue a durable compensating MLS removal |
| Remote pairing credential escalation | Never embed a wildcard or durable relay credential; require pre-provisioned access or an exact-route short-lived principal |
| Credential substitution | Device-root binding validation and optional out-of-band fingerprint comparison |
| Device root-key extraction | Remove the compromised `DeviceId`, advance the epoch, and enroll a new independently verified `DeviceId`; do not claim recovery through MLS update alone |
| Protocol downgrade | Signed capability negotiation and fail-closed version selection |
| Oversized or malformed input | Pre-allocation bounds, deterministic parsing, property tests, fuzzing, and regression fixtures |
| Offline database theft | Sealed secret blobs; no plaintext-key fallback |
| Secret disclosure through diagnostics | No `Debug`, serialization, logs, telemetry, panic text, or snapshots containing keys/plaintext |
| Malicious model/tool input | Schema validation, local authorization, bounded values, and explicit user-controlled policy |
| Local adapter impersonation | Adapter-owned random endpoint, exclusive owner-protected capability file, strict ownership/link validation, mutually authenticated challenge-response, profile binding, and zeroized capability buffers |
| Capability-file substitution | Exclusive creation, owner-only access, no symlink/reparse traversal, bounded canonical decoding, profile-bound proofs, exact-path cleanup, and no unauthenticated fallback |
| Endpoint squatting after adapter failure | Adapter creates the endpoint before daemon launch; mutual proof prevents a replacement endpoint from authenticating; stale endpoints fail closed |
| Delivery cursor or lease tampering | Sealed profile-global event state, consumer-bound lease identifiers and generations, checked expiry, idempotent acknowledgment, and stale-ack rejection |
| Adapter crash before harness delivery | Pending or expired claim is reclaimed without advancing adapter acknowledgment |
| Adapter crash after harness delivery | At-least-once redelivery carries the same stable notification identifier; exactly-once is not claimed |
| Peer prompt injection | Typed safety envelope, peer content quoted as untrusted data, no inherited authority, no automatic tool execution, and explicit send operations |
| Wake-up or token-spend abuse | Explicit per-conversation enablement, mute controls, one outstanding synthetic turn, burst coalescing, and global/per-conversation budgets |
| Agent-to-agent feedback loop | Authenticated sender classification, local-echo suppression, stable notification identifiers, and no send side effect from receipt alone |
| Adapter backlog exhaustion | Hard count/byte bounds, terminal suppression while muted, replay backpressure before enabled events would be dropped, and visible degraded state |
| Dependency/provider compromise | Exact versions, supply-chain review, upstream advisories, isolated adapter, and replaceable provider boundary |

## Explicit non-goals and limitations

- Konclave cannot keep plaintext secret from a device compromised while plaintext or
  active keys are available.
- An authorized member can copy or disclose plaintext it legitimately receives.
- An authorized or compromised harness adapter can copy or disclose plaintext
  delivered to that harness.
- Konclave cannot guarantee availability against a malicious relay or network.
- The initial protocol cannot guarantee consistent membership against a relay that
  equivocates between isolated clients.
- Initial releases do not hide routing identifiers, timing, payload sizes, IP
  addresses, or all membership-related metadata.
- Initial device identity does not prove a human legal identity.
- The first release does not provide key transparency or federation.
- Secure deletion depends on operating-system and storage behavior and cannot be
  proven for every physical medium.
- Exactly-once delivery into a harness is not provided. A crash after harness
  acceptance but before daemon acknowledgment may create a duplicate notification.
- No automatic harness delivery occurs while its adapter is absent. Enabled backlog
  may eventually pause relay replay rather than be dropped.
- Root, administrator, process-injection, or same-account active-memory compromise can
  obtain the ephemeral local adapter capability and is outside the local
  confidentiality guarantee.
- Peer content is delivered as untrusted data; Konclave cannot prevent a model from
  making a poor decision after correctly receiving that data.
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
