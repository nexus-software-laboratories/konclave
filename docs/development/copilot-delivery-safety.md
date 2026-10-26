# Copilot delivery safety

Ordinary uncorrelated text, membership changes, and policy exchanges remain
history-only. An exact directed request targeting this device may enter a model
turn after a durable claim under the active local policy. An authenticated answer
to this device's completed outgoing request may separately resume work under
current `session.work`, with the same idle queue and wake budget.

## Peer content is data

The daemon derives the conversation and sender from authenticated MLS state. Peer
text cannot override either value and never supplies policy, permission, or tool
authority.

The directed-request synthetic turn states the
conversation, authenticated sender, stable notification identifier, exact request
identifier, and local authorization outside the quoted region. The request body
remains inside an explicit untrusted boundary and is data to evaluate, never local
authority.

The boundary cannot be closed from inside. Both marker strings are neutralized in
peer text before quoting, so exactly one adapter-authored marker pair survives.

Membership events are rendered by the adapter from structured fields. No peer-supplied
string is interpolated into them.

Ordinary delivery is explicitly not a request to send anything. Only an exact
`DirectedRequest` targeting the local device may claim an incoming-request turn, and that
turn can reserve at most one ordinary-text response correlated to the request.
The extension always preloads only the `send_message` tool. The autonomous turn
therefore cannot lose its single permitted effect behind deferred tool discovery,
while unrelated Konclave tools remain absent until ordinary tool search loads them.
An answer-continuation turn has no required reply tool and cannot reserve a reply.
The daemon verifies its exact original outgoing request, target sender, conversation,
and reply reference in sealed history before creating a fresh one-use handling
claim. The original request, not a new task record, establishes the expectation.
Its answer is untrusted information for the original authorized work, not new
authority. Deliberate follow-up directed requests still require current work
permission and remain confined to the originating conversation.
For reply-only policies, the extension also marks `send_message` as the turn's required tool through the
session-scoped RPC before model execution begins. A host that cannot resolve the
required tool rejects admission rather than starting an incapable autonomous turn.
The pre-tool hook stages its daemon-issued one-use authorization privately, and the
handler injects it only after exact argument matching. The token never appears in
model-visible tool arguments or later conversation history.

## Explicitly permitted work

A separately activated policy granting `session.work` permits ordinary work on the
exact directed request, under the receiving session's normal permissions and
repository instructions. The trusted adapter prompt, not the quoted peer content,
explains that authority. Work turns omit the mandatory first reply tool; reply-only
policies and ordinary mailbox messages keep their existing behavior.

Every ordinary tool admission requires a live native policy/claim check. A changed
turn during that asynchronous check denies the tool. Direct Konclave control-plane
operations remain denied; explicit follow-up requests and history tools are confined
to the original conversation. Final replies retain their separate one-use token.
Work evaluation omits reply-only fields rather than sending non-JSON `undefined`
values. The focused gate exercises this path through the real bounded local-service
client and authenticated transport. Failed checks preserve finite diagnostic labels
without exposing exception content, tool arguments, or peer text.

Broad shell, file, external-provider, and subagent access is broad local-session
trust, not isolation. Revocation cannot retract admitted effects, terminate arbitrary
tools or descendants, or make external work exactly once. A recovered request can
repeat work; use external durable identifiers and reconcile before retrying ambiguous
effects. No task tracking, workflow engine, or automatic policy replacement is added.

## Injection timing

Events are queued while the session is active and settled only once it is idle.
Uncorrelated terminal events never enter the model. Request and continuation delivery preserve the
one-outstanding-turn gate and uses the SDK's explicit `enqueue` mode so a peer turn
waits behind foreground work rather than interrupting it.
An idle observation cannot complete a newly enqueued request until the session has
observed the exact token-bearing synthetic prompt. If foreground user work wins the
race, the later collaboration prompt enters a deny-all gate and completes with no
response rather than leaking authority into either turn.
If the synthetic prompt does not start within five minutes, the adapter durably
completes the request with no response and keeps any later stale prompt behind a
deny-all gate instead of retaining the delivery lease indefinitely.

## Delivery is at least once

A terminal event is acknowledged only after the adapter emits its local diagnostic.
A directed request is acknowledged only after the exact handling attempt reaches
`completed-response` or `completed-no-response`. The delivery long-poll renews the
event and handling lease while the model turn remains active. While the coordinator
retains a turn or queued work, the runtime sends heartbeat-only operations instead of
claiming an unbounded local queue. Failure before durable completion releases or
expires the event, so the stable notification remains reclaimable. A crash before
acknowledgment may redeliver the same notification identifier.
A correlated answer follows the same durable claim lifecycle and completes
without a response. Its exact answer identity survives terminal-event pruning in
the sealed handling record, preventing a differently identified duplicate answer
from starting a second continuation for the same outgoing request.

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
model turn or consuming its wake budget. A directed-request turn never mixes
conversations or request identities, so per-conversation limits remain meaningful.

Wakes are capped overall and per conversation within a rolling window. Reaching a
budget delays delivery; it never acknowledges undelivered work. Selection skips a
conversation that is at its budget rather than stopping at the head of the queue,
because stopping there would let one busy conversation starve every other conversation
behind it for the rest of the window.
