# Directional request-service channels

A request service has one operator and independently enrolled requesters. Each
requester gets a separate, two-member MLS conversation with that operator: directed
targeting in a shared group would not hide messages from the other group members.

| Application traffic | Permitted |
| --- | --- |
| Requester initiates a directed request to its operator | Yes |
| Operator answers that channel's authenticated original request | Yes, with current local reply authority |
| Operator initiates a request or unsolicited message | No |
| Requester sends ordinary text, replies, or targets another device | No |
| Third member, requester promotion, or operator replacement | No |

These are native restrictions, not suggestions to the model. The immutable channel
descriptor is authenticated by the invitation and MLS membership state. Explicit
policy exchange and authorized membership maintenance remain control-plane traffic.
An existing ordinary conversation cannot be silently converted into this mode.

## Enroll a requester

1. Obtain and independently verify the requester's `get_identity` device identifier.
   In the operator session, run `/konclave service create <requester-device-id>`.
   This creates and selects the operator's channel, without enrolling a peer or
   activating work permission.
2. In the requester session, run `/konclave pair member`. Give its one-time
   capability to the operator through an appropriate handoff.
3. The operator runs `/konclave join <capability>`, checks the authenticated requesting
   device against the expected requester, and runs `/konclave approve <pairing-id>`.
   The selected service channel and ordinary member role are used. A different
   requester or elevated role is refused.
4. The requester checks the displayed inviter, conversation and role, then runs
   `/konclave approve <pairing-id> <operator-device-id> <conversation-id> member`.
   Both sessions process `/konclave sync <pairing-id>` as required by the displayed
   pairing progress. Legacy clients without signed service capability cannot enroll.
5. Explicitly activate the operator's appropriate local collaboration policy for
   this channel using the existing [policy workflow](collaboration-policies.md).
   Enrollment alone never enables autonomous work or broadens ordinary permissions.

The native `create_request_service_channel` tool accepts `requester_device_id`.
Its caller can explicitly select the returned conversation with
`set_active_conversation`; the slash command performs that selection itself.

## Requests and terminal replies

The requester selects its channel and uses `/konclave request -- <request text>`,
or calls `send_directed_request` with that conversation and its operator as target.
Use a stable message ID when retrying the same request.

The operator's existing automatic delivery combines its private channels. An
incoming request can start work only under an independently activated local policy
and the session's ordinary permissions. The operator replies through `send_message`
with the exact conversation and `reply_to_message_id` from the authorized request
turn. The hook supplies its one-use reply authorization; never copy it from another
request or pass it as model-proposed input.

Replies are terminal. The operator can ask for clarification in its answer; the
requester deliberately initiates a new request with the relevant context. Answers
do not request another answer or create reply loops.

Restricted channels intentionally reject claim-free replies, including ordinary
manual `/konclave reply` calls. The current authorized-request reservation path
provides durable response recovery. A different terminal response conflicts;
retrying an already committed response must retain its exact identity and bytes.
This is message-effect idempotence, not exactly-once execution of external tools.

## Inspect the operator's private inbox

```text
/konclave service channels
/konclave service channels <after-conversation-id>
/konclave service inbox <conversation-id>
/konclave service inbox <conversation-id> <after-cursor>
```

The channel listing shows authenticated operator/requester endpoints and whether
the requester is currently enrolled. It scans a bounded local conversation page,
so an empty filtered page can still have a continuation.

The inbox reads bounded, authenticated local history for one operator-owned channel,
showing original requests without a recorded terminal reply. Answered requests and
removed requesters are excluded. Its cursor advances over scanned history, including
empty filtered pages. Requesters cannot invoke this operator view, and it never
falls back to ordinary history.

Inspection does not claim a request, restart completed work, activate a policy, or
authorize a reply. Unreplied history is not a task scheduler: a request completed
without a response can remain visible without becoming claimable again. Automatic
delivery maintains the combined local inbox; these deterministic inspection commands
do not start a model turn or perform implicit network synchronization.

During authorized peer work, inbox inspection is bound to that turn's conversation.
Creating a service channel or enumerating all operator channels is not delegated
by a peer request; those operations require separate local authorization.

## Isolation and operational limits

The endpoint is an authenticated **device/profile**, not a process or display alias.
Sessions sharing one profile share its channel access. Give independently isolated
requesters distinct profiles and identities before enrollment.

Removing a requester prevents new admission and replies but cannot retract plaintext
or external work already admitted. The operator is trusted with all of its own
channels and can intentionally disclose their contents. Restrictions apply to these
enrolled channels, not separately authorized ordinary conversations, external
systems, or a broadly authorized shell.

Idle-only delivery can queue requests while the operator is busy. Relay acceptance
is not work acceptance. For a deadline-sensitive task, initiate an availability
request first and send a fresh assignment after its terminal ready response.

The existing watch supervisor supports at most 32 active-member conversations per
profile, including ordinary and operator-only channels. Removing a requester does
not remove the operator or retire that channel. Do not exceed this profile ceiling:
the existing supervisor reports capacity failure and stops the profile rather than
silently leaving some conversations unwatched. This mode does not add archival,
unbounded enrollment or a new scheduler. Independent workers isolate blocked or
transient relay connections; permanent authentication, storage and capacity failures
still stop the profile. Event delivery retains the existing per-channel and
profile-wide count/byte quotas.

Native startup advances the protected profile floor to schema 23 before restricted
checkpoints can exist. Older native readers must fail closed after that migration,
even if no service channel was created. The sealed reply witness retains the
existing custody, history and relay trust assumptions; it does not independently
prevent coherent database replay or selective restore/deletion.

See [ADR 0032](../adr/adr-0032-request-service-channels.md) for the architectural
decision and its alternatives.
