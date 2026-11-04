# Diagnose and recover safely

This reference is for installed-client operators and harness authors. Start with
`/konclave status` for profile, relay and automatic-delivery state. Plugin presence
is not activation: the matching native runtime, authenticated service connection
and Copilot hook permission must all be available. A degraded extension deliberately
offers repair guidance without registering tools or automatic delivery.

## Identify the failed boundary

Local failures expose bounded `stage` and `code` labels, optionally a connection
reference and request sequence. These are diagnostic metadata, not permission to
retry or evidence that an interrupted operation did not commit.

| Code or observation | Safe next action |
| --- | --- |
| `invalid_request`, `payload_too_large`, `unknown_operation` | Check the exact input schema, size and matching client/native versions. Correcting content creates a different operation. |
| `not_authorized`, `issuer_disabled`, `required_evidence_unavailable` | Repair the intended registration, evidence or explicit local authorization. Do not retry through a Generic fallback or weaken permissions. |
| `profile_unavailable`, `profile_suspended` | Inspect native health and profile ownership/custody. Do not delete the profile, reset identity or open its database directly. |
| `busy`, `capacity` | Reduce concurrency or resolve the documented quota. Do not treat capacity refusal as a dropped request or bypass the bound. |
| `deadline_exceeded`, `cancelled`, `channel_closed`, `connection_unavailable` | The request may have committed. Reconcile with its original operation/message identity before retrying. |
| `conflict` | Reusing an identity with different content or state is not an exact retry. Inspect the original operation; do not generate IDs until an intended new operation is established. |
| `reconciliation_pending` | Reconciliation is incomplete, not successful delivery or permission to replay external work. Preserve the original identity. |
| `frame_invalid`, `protocol_invalid`, `service_upgrade_required` | Verify matching supported packages and authenticated service identity. Do not disable framing, pinning or version checks. |
| `internal`, `unclassified_failure`, `client_closed` | Preserve bounded evidence and the original identifiers; diagnose the service or client lifecycle. Do not infer a remote outcome. |

Stages distinguish validation, connection, service challenge/identity/decision,
admission, request write, response read/decode and tool dispatch. A failure during
response reading can follow a committed write. The
[failure classifier](../../extensions/Konclave.HostExtension/src/service/failure-diagnostics.ts)
owns the finite labels; do not branch on arbitrary exception text.

## Recover the original operation

| Interrupted operation | Recovery |
| --- | --- |
| `send`, `request`, `reply` | Use the printed retry shape with the same conversation, message ID, reply/target and exact body. A new message ID is new work, not recovery. |
| Policy proposal | `/konclave policy resume <proposal-id>` uses durable canonical bytes, not a mutable source file. An edited policy requires a new proposal ID. |
| Policy revocation | Reuse the printed message ID and exact digest. A later revocation after a distinct activation is a new operation. |
| Compact pairing | `/konclave connect resume <pairing-id>`, then inspect its authenticated phase and deadline. Resume does not extend an expired ceremony. |
| Short-code verification | `/konclave verification <attempt-id>` shows current peer, SAS and confirmations. Only the operator can confirm exact values; cancel rather than automate a missing comparison. |
| Alias pairing | `/konclave repeat <operation-id>` or `/konclave cancel-repeat <operation-id>`. An alias is a local identity binding, not authority to replace the peer. |
| History scan | Follow the emitted continuation including order and date filters. Empty filtered pages can still have more history. |

Pairing cancellation can require compensating membership removal after an add.
Inspect terminal state; neither closing the extension nor a local deadline proves
that a remote membership operation was undone.

## Inspect delivery without restarting work

```text
/konclave status
/konclave diagnose <conversation-id> <message-id>
/konclave messages <conversation-id>
```

Replace placeholders with the original authenticated identifiers. `diagnose`
returns body-free **local** evidence, not a global delivery/execution status. Its
direction, outbox, echo/history and local-consumer observations must not be collapsed
into an invented "completed" status. See
[local delivery diagnostics](../development/local-delivery-diagnostics.md).

Muting changes automatic wake delivery, not membership or existing history.
Unmuting is not an instruction to rerun an already completed request. A request
service's unreplied inbox is an inspection view, not a task scheduler.

The current Copilot delivery path can reattach a replacement authenticated socket
to the same still-live exact handling attempt and stable consumer. It fences the
displaced lease generation; it does not revive expired work, extend the lease or
grant additional responses. A foreground local prompt clears a pending peer-work
gate. See [Copilot delivery safety](../development/copilot-delivery-safety.md) for
admission, heartbeat and late-turn behavior.

Do not post capabilities, message bodies, policy source, raw session identifiers,
configuration, credentials or profile files in support reports. Report the package
version and bounded failure labels, with synthetic identifiers in public examples.
For ownership and custody failures, use
[daemon profile recovery](../development/daemon-profiles.md), not database surgery.
