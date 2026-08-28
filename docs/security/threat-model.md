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
- install-scoped enrollment credentials and per-profile relay data-plane tokens;
- installed authorization-issuer private keys, ephemeral session keys, exact-profile
  grants, authenticated service connections, and delivery leases;
- relay bearer credentials and authorization policy;
- membership integrity and administrator policy;
- message authenticity, ordering, acknowledgment, and replay state;
- local daemon control and decrypted history.
- remote-event ordering, acknowledgment, mute, and suppression state.
- canonical collaboration-policy bundle content, digest identity, and sealed local
  conversation bindings;
- collaboration-policy exchange metadata and its references to sealed message
  history.

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

### Shared local service channel

The per-user service owns one well-known local endpoint: an owner-restricted Windows
named pipe or a socket inside an owner-only Unix runtime directory. It never opens a
TCP listener and is never reachable from the network. Platform peer credentials and
endpoint policy reject other operating-system users.

The configured authorization policy determines what evidence may obtain profile
access. The initial `AccountTrusted` provider explicitly trusts every process running
under the configured operating-system account. Its owner-protected Ed25519 key is an
issuer credential only: it may request policy-permitted grants but cannot invoke
profile operations. This excludes other accounts but intentionally does not isolate
mutually hostile same-account processes.

Each client generates a memory-only session key. An issued finite grant binds its
public key to one exact profile, harness metadata, verified evidence set, policy
version, expiry, and closed capability set. The service stores no session private key.
Issuer and session roles use separate protocol-v2 transcripts, and every transcript
binds both fresh challenges and the pinned service identity. Unknown, expired,
revoked, substituted, or policy-invalid grants receive one signed uniform rejection
after proof exchange. Protocol downgrade never falls back to version 1, operating
system identity alone, another issuer, another profile, anonymous access, or a
per-session daemon.

The service signing seed uses native operating-system custody by default; an explicit
headless installation may bind it to one owner-protected external file. The
installation record pins the derived service public key, so missing or substituted
custody fails before the endpoint opens. AccountTrusted session keys are re-created
after client restart. Service restart invalidates in-memory grants, and a live client
uses the same session key to obtain a replacement grant.

Active grants are bounded globally, per issuer, and per profile. Revocation removes
one exact grant and closes its connections; AccountTrusted can issue a replacement
because the same account remains trusted. Profile suspension and durable issuer
disablement are stronger operator controls tracked separately and are not claimed by
the initial in-memory registry.

Terminal local request outcomes are sealed in the profile database and keyed by
session public key, profile, and request identifier. Authenticated cancellation can
stop only pre-commit work under that same session identity. Post-commit cancellation,
disconnect, deadline, and shutdown reconcile and publish the actual durable result
rather than a false terminal timeout.

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
The local `AccountTrusted` two-command policy makes that tradeoff explicitly: creating
and redeeming the capability are the two same-account approval actions, output states
that no independent identity verification occurred, and the policy grants only
`member`. Stronger evidence policies and administrator grants retain explicit
approval.

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
- an input attempting to ambiguously encode or substitute a collaboration-policy
  bundle;
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

The collaboration-policy exchange is authenticated inside normal MLS application
messages. Canonical bytes and a domain-separated digest prevent ambiguous bundle
identity, and proposal verification rejects a claimed digest that does not identify
the embedded canonical bundle. Responses bind both the proposal identifier and
digest; revocations bind the withdrawn digest. Receipt of any exchange message has no
binding side effect, so a peer cannot grant itself local authority by proposing or
accepting policy content. Explicit local proposal, acceptance, rejection, and
revocation operations use a sealed terminal journal and atomically mutate local
bindings before their outbound notification can be submitted. Deterministic
effective-policy evaluation is implemented as a pure domain boundary. The paved
Copilot integration now authorizes idle collaboration turns and gates their tools
through the active digest while preserving native permissions. Finite turn and token
policies deny this autonomous path until durable accounting exists. Unsupported and
generic harnesses retain explicit-send behavior.

Shared-local-service automatic delivery exposes only typed policy-exchange
identifiers, digests, replacement intent, and response state for exchange
notifications. Those notifications do not project canonical bundle content or model
guidance, remain inside the untrusted collaborator fence, and state that proposal
receipt did not activate local authority. For application text under an already
active local policy, the service may return that locally accepted policy's bounded
guidance to the paved Copilot adapter, which places it outside the peer-content fence.
The legacy binary adapter receives only a bounded daemon-authored non-authorizing
notice, preserving its closed v1 event grammar.

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
| Enrollment authority theft or abuse | Separate enrollment/data-plane derivation domains, authenticate before body processing, fixed server grants, rate/concurrency/principal caps, verifier-only configuration, rotation, and revocation |
| Credential substitution | Device-root binding validation and optional out-of-band fingerprint comparison |
| Device root-key extraction | Remove the compromised `DeviceId`, advance the epoch, and enroll a new independently verified `DeviceId`; do not claim recovery through MLS update alone |
| Protocol downgrade | Signed capability negotiation and fail-closed version selection |
| Oversized or malformed input | Pre-allocation bounds, deterministic parsing, property tests, fuzzing, and regression fixtures |
| Offline database theft | Sealed secret blobs; no plaintext-key fallback |
| Secret disclosure through diagnostics | No `Debug`, serialization, logs, telemetry, panic text, or snapshots containing keys/plaintext |
| Malicious model/tool input | Schema validation, local authorization, bounded values, and explicit user-controlled policy |
| Local service client impersonation | Owner-restricted endpoint, verified platform peer account, issuer/session role separation, proof of the exact private key, signed fresh protocol-v2 transcript, exact-profile finite grant, capability checks, and uniform rejection |
| Account issuer substitution or theft | Exclusive creation, owner-only access, no symlink/reparse traversal, bounded canonical decoding, installer-owned public registration, key versioning, exact-path cleanup, and explicit AccountTrusted semantics |
| Shared-service endpoint squatting | Owner-protected well-known endpoint, single-instance service ownership, authenticated service/client transcript, and fail-closed startup when endpoint identity conflicts |
| Cross-profile local attachment | Exact profile, session public key, harness, evidence, policy, expiry, and capabilities signed into one immutable grant binding; no profile-switch request |
| False timeout or cancellation outcome | Session-scoped authenticated cancellation, explicit pre/post-commit state, sealed terminal-outcome journal, exact retry reconciliation, and no dropped-join cancellation claim |
| Delivery cursor or lease tampering | Sealed profile-global event state, consumer-bound lease identifiers and generations, checked expiry, idempotent acknowledgment, and stale-ack rejection |
| Adapter crash before harness delivery | Pending or expired claim is reclaimed without advancing adapter acknowledgment |
| Adapter crash after harness delivery | At-least-once redelivery carries the same stable notification identifier; exactly-once is not claimed |
| Peer prompt injection | Typed safety envelope, peer content quoted as untrusted data, no inherited authority, and no automatic tool execution unless an exact locally activated policy and paved harness gate authorize the action |
| Collaboration-policy bundle ambiguity | Canonical bounded encoding, duplicate rejection, exact re-encoding checks, and a domain-separated content digest |
| Collaboration-policy proposal substitution | Fixed-width proposal identity, complete bounded canonical bundle, exact digest verification, and responses bound to both proposal identifier and digest |
| Collaboration-policy exchange-index substitution | Foreign-key every allowlisted index row to sealed history, seal each row's exact metadata, commit row count/backfill completion in separate profile-bound sealed state, verify cursors against sealed delivery evidence, insert atomically with cursor completion, and re-derive typed metadata from sealed history at startup |
| Remote policy activation | Exchange messages have no binding side effect; only a separately authorized local service operation may activate or remove local authority |
| Policy broadening during evaluation | Exact-target base matching, deny-over-approval-over-allow precedence, positive local-authority and harness-control intersections, deny-only local restrictions, and fail-closed missing evidence |
| Policy-limit overflow or approval bypass | Checked usage-plus-cost arithmetic, explicit unlimited values, fresh local approval that satisfies only approval requirements, and no approval override for denial, authority, evidence, or limit failures |
| Peer request becomes local authority | Keep peer text inside immutable untrusted markers and place only locally activated policy identity and guidance outside; policy authorizes evaluation of data without changing its trust class |
| Copilot tool escapes collaboration policy | Keep a turn-scoped pre-tool gate, accept only a bounded object or serialized object with the exact `send_message` field allowlist, correlate fresh interactive and delivery connections through their authenticated session public key, bind a one-use authorization to exact arguments, active digest, live delivery consumer, and bounded expiry, verify those conditions in the send reservation, and deny external, unknown, approval-required, or cross-conversation tools |
| Collaboration gate leaks into a user turn | Prepare with a fresh local turn token, activate only on the matching observed synthetic prompt, clear pending state on every other user prompt, deny every tool if a delayed token-bearing prompt arrives after that clearance, and clear active state on idle or disposal |
| External work outlives the policy gate | Do not register workspace, shell, web, MCP, subagent, or delegation controls until each paved integration can prove atomic effect and descendant lifecycle enforcement |
| Unsupported harness accounting claim | Require the live single-consumer delivery lease for paved autonomy, enforce duration and one outstanding turn, and deny finite turn or token policies until durable accounting exists |
| Contradictory local policy responses | Derive one stable response message identifier per conversation, device, and proposal, then bind its one terminal outcome in a sealed local-operation record |
| Partial local policy exchange operation | Commit the terminal local-operation record and binding mutation in one transaction before submission; retain the owned serialization guard through blocking work; preserve the source proposal identifier; retry returns historical mutation state and reconciles the stable outbox message |
| Policy-operation journal erasure or schema downgrade | Create the initial sealed journal state atomically with schema adoption, authenticate the adopted schema floor inside the sealed device identity, and reject null state or a plaintext version below that floor |
| Policy response identifier preemption | Reserve the application identifier in the terminal-operation transaction, reject pre-existing history or outbox records before authority mutation, accept only an exact already-recorded outbound envelope as its own echo, reject later inbound collisions, and require outbound content to reproduce the sealed operation |
| Paved policy-source path escape or replacement | Accept only an explicit relative path whose physical target remains under the current workspace, require a regular bounded UTF-8 file, compare file-descriptor identity and metadata before and after the read, re-resolve the final path, and compile the transferred source through the shared strict Rust compiler |
| Mutable-source proposal retry | Recover by stable proposal identifier from the sealed terminal operation and content-addressed bundle rather than rereading the source path; an edited source requires a new identifier |
| Blind trust in peer-proposed policy guidance | Provide an explicit inspection operation that renders authenticated proposal semantics and labels guidance as untrusted before a separate exact-digest acceptance |
| Repeated revocation after reactivation | Require a caller-stable revocation message identifier so a later activation cycle can emit a distinct revocation while retries remain idempotent |
| Collaboration-policy persistence tampering | Sealed canonical bundle and binding records, profile/conversation/digest context binding, startup verification, hard capacity, and fail-closed binding deletion |
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
- `AccountTrusted` does not protect one session from another malicious process running
  under the same operating-system account. Exact grants contain authority but do not
  change that declared trust boundary.
- The initial service-lifetime grant registry does not provide durable administrative
  suspension or issuer disablement across service restart. Those controls require the
  live durable registry tracked separately.
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
  obtain the AccountTrusted issuer key, an active session key, or plaintext and is
  outside the local confidentiality guarantee.
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
