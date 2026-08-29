# Copilot delivery safety

The current adapter does not turn ordinary text, responses, membership changes, or
policy exchange into a Copilot model turn. It retains the canonical event in message
history, emits one concise body-free local diagnostic, and acknowledges the
notification. A directed request is also withheld until the adapter adopts the
daemon's durable claim, correlated-action, and completion protocol.

## Peer content is data

The daemon derives the conversation and sender from authenticated MLS state. Peer
text cannot override either value and never supplies policy, permission, or tool
authority.

When directed-request integration is enabled, its synthetic turn must state the
conversation, authenticated sender, stable notification identifier, exact request
identifier, and local authorization outside the quoted region. The request body
remains inside an explicit untrusted boundary and is data to evaluate, never local
authority.

The boundary cannot be closed from inside. Both marker strings are neutralized in
peer text before quoting, so exactly one adapter-authored marker pair survives.

Membership events are rendered by the adapter from structured fields. No peer-supplied
string is interpolated into them.

Ordinary delivery is explicitly not a request to send anything. Only an exact
`DirectedRequest` targeting the local device may claim an autonomous turn, and that
turn can reserve at most one ordinary-text response correlated to the request.

## Injection timing

Events are queued while the session is active and settled only once it is idle.
Terminal events never enter the model. The directed-request integration must preserve
the existing one-outstanding-turn gate and use the SDK's explicit `enqueue` mode so a
peer turn waits behind foreground work rather than interrupting it.

## Delivery is at least once

A terminal event is acknowledged only after the adapter emits its local diagnostic.
A future directed request is acknowledged only after the exact handling attempt
reaches `completed-response` or `completed-no-response`. Failure before that boundary
releases or expires the claim, so the stable notification remains reclaimable. A
crash before acknowledgment may redeliver the same notification identifier.

## Tool cancellation reflects durable outcomes

The generic thin-client API accepts an `AbortSignal` and converts it into an
authenticated, session-scoped cancellation request. Cancellation before the service's
commit point becomes a terminal cancellation. Cancellation after commit leaves the
tool call pending until the service records and returns the actual durable outcome;
the client never substitutes a local timeout for work that may still commit.

The current public Copilot SDK `ToolInvocation` contract does not expose a
tool-invocation `AbortSignal`. The paved Copilot handler therefore cannot propagate a
harness abort that it does not receive. Its configured deadline still requests
authenticated cancellation, and the generic client is ready to forward a signal when
the SDK adds one. This limitation is explicit rather than approximated from session
events or connection closure.

The paved handler does receive stable session and tool-call identifiers. It hashes
those values under a Konclave-specific domain into the 16-byte local request
identifier, so reconnect or callback replay of the same tool call reconciles the same
sealed outcome without exposing the upstream identifiers on the wire.

## Delivery follows an explicit join

Creating or joining a conversation is what turns delivery on for it. Nothing else
does. A conversation that this profile did not explicitly create or join delivers
nothing, so peer content cannot start entering a session because a conversation
happened to exist in storage.

That choice is deliberate. Requiring a separate opt-in call after joining would leave
a session silently undelivered every time it forgot the extra step, which is the
failure this project exists to remove.

Three daemon tools control and observe this afterwards. `set_active_conversation`
selects the target for later implicit sends without changing delivery policy.
`set_auto_delivery` mutes or re-enables one conversation and is write-authorized,
because it decides whether remote events can produce local notifications or an
authorized directed-request turn. `delivery_status` is
read-authorized and reports queued and in-flight event counts, how many conversations
currently have a live watch worker, whether delivery is degraded, and — when a
conversation is named — whether that conversation is muted.

Muting suppresses delivery for as long as it is set. A message that arrives while a
conversation is muted is never delivered into a session, and re-enabling delivery
later does not replay it — it applies to what arrives afterwards. The message remains
ordinary readable history, so nothing is lost; it simply never woke a session.

## Bursts and wake budgets

A terminal burst becomes one bounded local notification batch without starting a
model turn or consuming its wake budget. A future directed-request turn never mixes
conversations or request identities, so per-conversation limits remain meaningful.

Wakes are capped overall and per conversation within a rolling window. Reaching a
budget delays delivery; it never acknowledges undelivered work. Selection skips a
conversation that is at its budget rather than stopping at the head of the queue,
because stopping there would let one busy conversation starve every other conversation
behind it for the rest of the window.
