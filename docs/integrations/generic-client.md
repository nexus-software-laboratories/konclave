# Generic harness client

Harness-specific integrations improve lifecycle mapping and automatic delivery, but
they are not an eligibility gate. The packaged `generic.mjs` client lets any local
harness invoke the shared service through the installed AccountTrusted or Windows
UserPresence grant path.

The fallback is forbidden when a paved integration is available. In particular,
Copilot CLI must use its native tools and `/konclave` commands. A paved-operation
failure remains visible; it never authorizes profile discovery or Generic fallback.

## Security contract

The generic client:

- generates a memory-only session key;
- uses the installed account issuer only to request one finite exact-profile grant or
  one service-owned UserPresence challenge;
- sends `Generic` as its authorization metadata regardless of its self-declared
  integration label;
- pins and authenticates the installed service;
- supports authenticated deadline and caller cancellation;
- seals terminal request outcomes in the profile journal; and
- retires its exact grant on clean exit.

It proves no harness provenance. The `Generic` harness kind is bounded metadata, not
`HarnessAttested` evidence. On Windows, a policy whose satisfiable clause requires
`UserPresence` runs the owner-protected sidecar's exact native helper and submits the
returned assertion to the service for independent verification. The native ceremony
does not make the caller harness-attested. Linux and macOS reject the same policy
with `required_evidence_unavailable`, and no path silently relabels AccountTrusted as
UserPresence. When the policy has an independent AccountTrusted clause, the client
prefers the automatic lower-friction path explicitly permitted by that policy.

The generic client also proves no automatic delivery, pre-tool policy gate, native
permission intersection, subagent containment, or durable turn/token accounting.
`collaboration.turn.authorize`, `collaboration.turn.complete`, and
`collaboration.action.evaluate` are deliberately absent from its closed operation
surface. Activating a policy therefore does not turn an unsupported harness into an
autonomous collaborator; peer content remains data that the harness may inspect and
answer only through explicit operations. `send_directed_request` is available as an
explicit operation when the resolved target's root-signed credential advertises
support; an omitted target resolves only in a two-member conversation. It does not
give the generic harness an automatic response lifecycle.

The caller supplies a bounded lowercase integration label using letters, digits,
`.`, `_`, and `-`. The generic executable returns that label as local diagnostic
metadata but never sends it to the service, stores it as evidence, or uses it to select
a profile. Unknown labels are accepted because they are self-declared, not an
allowlist.

The packaged reference executable proves AccountTrusted through the installed issuer
and can obtain UserPresence only through the Konclave-owned native Windows WebAuthn
helper. Future provider-specific Generic adapters may present independently verified
`WorkloadIdentity` or `HarnessAttested` evidence through the same grant architecture,
but no Generic caller may self-assert any of those claims.

## Profile selection

Pass one canonical lowercase profile alias and an explicit profile mode. A
user-approved alias can use `--profile-mode durable` to provide continuity across
invocations. If no stable subject exists, generate 12 random bytes, encode them as 24
lowercase hexadecimal characters, prefix them with `generic-`, and use
`--profile-mode ephemeral`. Never derive continuity from a process identifier, working
directory, timestamp, model name, integration label, or agent text. Aliases beginning
with `session-` are reserved for paved harnesses and rejected by the Generic client.
Programmatic callers pass the same `{ profile, profileMode, integrationLabel }`
identity to `connectInstalledGenericService`; the SDK validates it before reading
installation configuration or opening a service connection.

## Invocation

The client must run from the installed extension directory beside
`konclave.service.json`:

```text
$HOME/.copilot/extensions/konclave/generic.mjs
```

On Windows this is `%USERPROFILE%\.copilot\extensions\konclave\generic.mjs` unless
`COPILOT_HOME` selects another absolute Copilot configuration root. The packaged
source under `share/konclave/plugin/` has no sidecar and is not the runtime invocation
path.

For a UserPresence policy, invocation pauses for one Windows-owned verification
ceremony before the operation begins. One successful ceremony authorizes only the
resulting ephemeral session key and finite grant; each one-shot Generic process uses
a new key and therefore requires a new ceremony.

It accepts one closed operation name and one JSON value over stdin:

```shell
printf '%s' '{"conversation_id":"<conversation>","limit":100}' |
  node <absolute-generic.mjs> --profile <profile-alias> --profile-mode durable \
    --integration-label <harness-label> --operation read_messages
```

For a side-effecting call, generate one random 16-byte lowercase hexadecimal request
identifier and pass `--request-id <32-hex-characters>`. Reuse that exact identifier,
operation, and payload after a transport failure to retrieve the sealed terminal
outcome rather than creating a new operation.

PowerShell:

```powershell
'{"conversation_id":"<conversation>","limit":100}' | node <absolute-generic.mjs> --profile <profile-alias> --profile-mode durable --integration-label <harness-label> --operation read_messages --request-id <32-hex-characters>
```

Success is one JSON object on stdout:

```json
{
  "integration": { "kind": "generic", "label": "<harness-label>" },
  "profile": { "alias": "<profile-alias>", "mode": "durable" },
  "result": {}
}
```

Read the service response from `result`. Failure is one finite JSON object on stderr.
Credentials, paths, request payloads, and peer plaintext are never copied into an
error. If the operation succeeded but clean grant retirement failed, the successful
envelope is preserved and stderr receives the finite
`{"warning":"grant_retirement_failed"}` diagnostic; expiry remains the cleanup
backstop. The one-shot process is suitable for skill-driven best-effort integrations;
paved clients remain preferable when a harness exposes reliable resume, fork,
subagent, shutdown, and delivery lifecycle events.

For ongoing conversations, invoke `sync_messages`, then `read_messages` or
`watch_messages` with an explicit conversation identifier. Let each bounded wait
complete instead of busy-polling.

## Reference pairing flow

The Generic client uses the same durable pairing state machine as paved clients:

1. One side calls `create_pairing_capability` and transfers only the returned
   capability to the intended peer.
2. The peer calls `redeem_pairing_capability`, `create_conversation`, and
   `authorize_pairing_joiner`.
3. Each side calls `sync_pairing`; when requested, the joiner calls
   `authorize_pairing_inviter` with the exact authenticated values returned by the
   service.
4. Stop when both sides report `completed`, then use `send_message`,
   `sync_messages`, and `read_messages` with the returned conversation identifier.

Every side-effecting retry reuses its exact request identifier and byte-identical
payload. Each polling loop has a finite deadline and reports its last observed phase
instead of continuing in a detached background task.

## Collaboration policies

Generic clients may manage the same content-addressed policy state through the
declared `get_collaboration_policy_status`,
`inspect_collaboration_policy_proposal`,
`propose_collaboration_policy_source`,
`resume_collaboration_policy_proposal`,
`accept_collaboration_policy`, `reject_collaboration_policy`, and
`revoke_collaboration_policy` operations. This is deterministic policy administration,
not harness enforcement.

Proposal inspection returns the complete authenticated identity, statements, required
harness claims, limits, and `untrusted_guidance`. A generic integration must present
those semantics as untrusted data before a separate exact proposal-and-digest
acceptance. Matching policy digests prove matching canonical definitions; they do not
claim that the two harnesses have equal effective authority.
