---
title: Separate deterministic collaboration policy from directed request content
status: Accepted
date: 2026-08-28
authors:
  - Konclave maintainers
tags:
  - agents
  - automation
  - collaboration
  - policy
  - protocol
supersedes:
  - adr-0011-content-addressed-collaboration-policies
superseded_by: []
---

# Separate deterministic collaboration policy from directed request content

## Context and scope

Konclave needs agents to request information from a specific collaborator and receive
one autonomous response without turning every message into another model turn.
Authorization, interaction intent, and task content are different concerns:

- authorization determines which effects a local agent may perform;
- interaction intent determines whether a particular message requests a response; and
- task content contains the actual question, proposal, or work context.

ADR 0011 established content-addressed policy bundles, exact local activation, and
harness-specific effective authority. It also permitted optional free-form model
guidance inside the canonical policy bundle. The paved Copilot adapter placed that
locally accepted guidance into a trusted portion of each synthetic turn.

That design conflates authority with task prompting. A broad instruction to
collaborate and report blockers can make an ordinary reply look like another request.
The current application message carries text and an optional `reply_to` reference,
but it cannot state that a response is requested or identify the intended responder.
The adapter therefore has no deterministic basis for distinguishing a request from a
notification, acknowledgement, reply, or repeated blocker.

This decision replaces ADR 0011. It preserves content-addressed local policy
activation while removing free-form model guidance from new policies and defining a
directed request-response contract. It does not define task-specific workflows,
conversation topics, model prompts, or command-output verbosity.

## Verified facts

- `CollaborationPolicyBundle` currently contains optional `guidance` in the protocol,
  domain model, source schema, and compiler. The field is content-addressed but is not
  evaluated by the deterministic policy engine.
- The Copilot delivery adapter currently injects accepted guidance outside the
  untrusted collaborator fence, so prose inside a policy can influence model behavior
  even though it proves no enforceable control.
- `ApplicationMessage` authenticates one optional `reply_to` identifier but has no
  directed-request content kind, response expectation, or target participant.
- The effective-policy evaluator already makes exact decisions over structured action,
  resource, harness-claim, local-authority, approval, and limit inputs.
- Message identifiers, sender counters, outbox reservations, sealed history, and
  request outcomes already provide durable idempotency primitives.
- Peer-authored application content remains untrusted after MLS authenticates its
  sender. A remote request may ask for attention but cannot grant local authority.

## Assumptions

- Most agent collaboration messages are notifications or terminal responses and
  should not wake another model automatically.
- A sender can identify the exact conversation member from whom it needs an answer.
- One response is the safe default for one directed request.
- A responder that needs more information can deliberately create a new directed
  request rather than implicitly converting its response into another request.
- Optional duration, turn, token, concurrency, and wake limits remain useful circuit
  breakers, but they do not express whether a response is wanted.

## Decision drivers

- Keep policy evaluation deterministic and independently testable.
- Prevent ordinary replies and acknowledgements from creating agent-to-agent loops.
- Preserve the untrusted-content boundary and local authority intersection.
- Make request intent explicit, authenticated, target-specific, and replay safe.
- Keep task and topic text out of reusable authorization policy.
- Preserve self-hosting and content-addressed policy equality.
- Retain backward readability for existing policy and message history.

## Decision

### Preserve content-addressed deterministic policy

A collaboration policy remains an immutable canonical bundle identified by a
domain-separated digest and activated locally for one conversation. Effective
authority remains:

```text
accepted canonical bundle
intersection local user authority
intersection harness-proven controls
intersection local restrictions
```

New policy sources contain only:

- canonical display metadata;
- structured allow, deny, and require-local-approval statements;
- structured required harness claims; and
- fully resolved optional limits.

Task instructions, conversation topics, desired answers, and other model prompts are
not policy fields and do not contribute to policy identity.

### Retire policy guidance from model authority

The next policy-source version does not accept `guidance`. Newly created and compiled
policies omit it.

Protocol-v1 readers retain the optional bundle field so historical bundles, digests,
exchange records, and bindings remain decodable. Legacy guidance is inspectable as
historical untrusted annotation but is never injected into a model turn or treated as
local instruction. Existing structured statements, claims, and limits remain usable.

This compatibility rule avoids changing an old bundle's canonical bytes or digest
while ensuring no free-form policy prose retains behavioral authority.

### Add an explicit directed-request content kind

The application protocol adds a bounded `DirectedRequest` content variant containing:

- one exact target `DeviceId`; and
- one bounded UTF-8 request body.

The enclosing `ApplicationMessage.message_id` is the request identifier.
`ApplicationMessage.reply_to` may identify prior context when the request is a
follow-up, but it does not change the new request's identity.

Ordinary text remains a notification or response. It never requests an automatic
reply merely because it contains a question or imperative sentence.

The additive content variant requires negotiated support before it is sent to a
member that must interpret it. A recipient that does not support directed requests
fails visibly rather than treating the body as ordinary auto-actionable text.

### Make replies terminal by default

A response uses ordinary text with `reply_to` set to the directed request's message
identifier. That response does not itself request another response.

An authoritative response must be in the same conversation and its authenticated MLS
sender must exactly equal the directed request's target `DeviceId`. Text from another
member may reference the request for context, but it never completes, suppresses, or
conflicts with the targeted member's response.

When an agent independently needs an answer, a locally authorized foreground task
creates a new `DirectedRequest`, optionally referencing prior context through
`reply_to`. Request creation is a separate explicit effect, not a model inference
from response prose and not an alternate effect inside an automatic response turn.

The structured action namespace distinguishes:

- `conversation.request.send` for creating a directed request; and
- `conversation.reply` for answering one exact directed request.

These are evaluator primitives, not product-defined collaboration modes.

### Trigger autonomy only for a valid local request

An inbound message may create an autonomous turn only when all of these conditions
hold:

1. its authenticated content kind is `DirectedRequest`;
2. its exact target is the local device;
3. its durable local handling state is available or safely reclaimable;
4. the locally active policy permits `conversation.reply`;
5. local user authority and harness evidence permit the same action;
6. applicable approval and limit checks succeed; and
7. the live delivery consumer belongs to the authenticated acting session.

The remote sender controls the request body and target but not any local policy,
permission, harness claim, or approval. A directed request asks the local endpoint to
evaluate; it does not authorize the result.

Text notifications, policy exchange records, membership events, responses, and
requests targeting another member do not create an autonomous turn.

### Claim handling before starting a model turn

Before enqueueing an autonomous model turn, the daemon atomically claims:

```text
(conversation id, directed request message id, local responder device id)
```

The sealed handling record has explicit states:

- `claimed`, bound to one delivery consumer, lease generation, and bounded attempt;
- `completed-response`, bound to the committed response message; or
- `completed-no-response`, proving that the observed turn ended without an effect.

Only an available record or a `claimed` record whose owning delivery lease is
unambiguously expired may begin another attempt. A live claim rejects concurrent or
duplicate delivery. An exact retry under the same claim reconciles its current state.

The automatic turn may perform only the one correlated `conversation.reply` effect.
It cannot create a directed request, call external tools, or perform another
side effect. Request initiation belongs to a separate locally authorized task.

When the model turn reaches idle without a response tool call, the paved harness
completes the exact claim as `completed-no-response`. A crash before that completion
may cause another model attempt after lease recovery, but cannot duplicate an effect
because every permitted effect is covered by the response reservation.

### Reserve one automatic response durably

Before a policy-authorized response allocates a sender counter or outbox envelope, the
daemon atomically transitions the existing handling claim to `completed-response`.
The transition binds one response message identifier, exact reply target, exact local
sender, and sealed outbound operation.
An exact retry reconciles the existing response. A different response identifier,
reply target, or content conflicts. Duplicate delivery, adapter restart, service
restart, concurrent tool calls, and repeated model attempts cannot create a second
automatic response for the same request.

If no response is produced, `completed-no-response` records the terminal automatic
outcome without fabricating an outbound message. Delivery and request history remain
visible for explicit later handling.

### Keep model framing generic and subordinate

The paved adapter may explain the protocol fact that one authenticated collaborator
requested a response from this device. That fixed harness instruction is not policy
content and grants no authority.

The request body remains inside the untrusted collaborator fence. The adapter states
that replies are terminal and that another answer requires a new directed request.
The policy hook still gates every effect and native harness permissions still apply.

### Keep limits as optional circuit breakers

Duration, turn, token, concurrency, and wake limits remain structured and optional.
They may stop excessive activity but do not substitute for directed request intent.
Unlimited values do not weaken the one-response-per-request invariant.

## Serious alternatives

### Keep generic free-form guidance in policies

**Pros:** no source or bundle migration and maximum authoring flexibility.

**Cons:** prose remains behavioral authority without deterministic interpretation,
policy equality includes task wording, and terminal behavior depends on model
judgement. Rejected.

### Add a `reply_requested` boolean to every text message

**Pros:** small additive wire change and familiar request/response representation.

**Cons:** permits invalid combinations, leaves ordinary text with context-dependent
meaning, and makes it easier for responses to accidentally propagate the flag.
Rejected in favor of a distinct validated content kind.

### Infer request intent from message text

**Pros:** no protocol change and natural authoring.

**Cons:** nondeterministic, language-dependent, prompt-injection-sensitive, and unable
to distinguish a question from quoted or historical text. Rejected.

### Rely only on turn or time limits

**Pros:** deterministic hard stop with little protocol work.

**Cons:** limits valid collaboration arbitrarily, allows unnecessary replies before
the threshold, and does not represent who owes an answer. Retained only as an optional
circuit breaker.

### Define hardcoded workflow modes

**Pros:** straightforward product UX and implementation branching.

**Cons:** names such as `work`, `discuss`, or `contract-alignment` acquire arbitrary
compiled semantics and cannot express user-defined combinations. Rejected.

## Consequences

### Positive

- New policies are structured deterministic authorization documents, not prompts.
- A message either is or is not a directed request before any model sees it.
- Ordinary responses terminate automatically and cannot create ping-pong by default.
- Exact targets work for both two-party and group conversations.
- One durable response reservation closes duplicate and concurrent reply races.
- Authenticated response authorship prevents another group member from satisfying a
  request targeted elsewhere.
- Task-specific content remains in the request where collaborators expect it.

### Negative

- Application, source, domain, persistence, delivery, tool, and fixture contracts all
  gain new versioned surfaces.
- Senders need a target device identifier or a deterministic single-peer resolution.
- Existing policy guidance loses model-visible behavior and may require users to move
  useful task wording into directed requests.
- Older endpoints cannot participate in directed requests until capability support is
  negotiated.

### Neutral

- Policy names remain display metadata only.
- Peers can still send ordinary chat messages without requesting an automatic reply.
- Generic integrations can inspect and send structured requests but cannot claim
  autonomous enforcement without a paved lifecycle boundary.
- Hosted policy registries remain optional distribution and editing providers.

## Confirmation

Continued compliance requires:

- new policy-source creation rejects free-form guidance while historical bundles
  retain exact decode and digest behavior;
- no policy field or historical annotation is injected as trusted model instruction;
- Rust and TypeScript round-trip one immutable directed-request fixture exactly;
- malformed targets, empty or oversized request bodies, unsupported capability, and
  ambiguous content fail closed;
- ordinary text and replies never authorize an autonomous turn;
- only requests targeting the local device can reach policy evaluation;
- exact request delivery can produce at most one durable automatic response across
  duplicate delivery, concurrency, reconnect, and service restart;
- a durable handling claim exists before model enqueue, and lease recovery cannot
  duplicate any permitted effect;
- only the authenticated target's response can complete a request in a conversation
  with three or more members;
- a model turn with no response reaches a durable `completed-no-response` outcome;
- a response can continue the exchange only by creating a new directed request;
- remote request metadata never broadens local policy or native permissions;
- optional limits remain independently enforced; and
- packaged and live two-session acceptance prove one request, one reply, and terminal
  silence without relying on model judgement to stop.

## References

- [ADR 0008](adr-0008-shared-local-service.md) defines the per-user service and
  harness lifecycle boundary that owns durable delivery.
- [ADR 0009](adr-0009-evidence-bound-session-grants.md) defines the authenticated
  session identity used to bind delivery and action evaluation.
- [ADR 0011](adr-0011-content-addressed-collaboration-policies.md) records the
  superseded design that allowed free-form guidance inside policy bundles.
- [Protocol compatibility contract](../protocol/compatibility.md) requires additive
  content variants and negotiated support within protocol v1.
- [Threat model](../security/threat-model.md) keeps remote request content outside
  local user, developer, permission, and tool authority.
- [Collaboration policy contracts](../development/collaboration-policies.md) owns the
  evolving implementation contract.
