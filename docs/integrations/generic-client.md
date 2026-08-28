# Generic harness client

Harness-specific integrations improve lifecycle mapping and automatic delivery, but
they are not an eligibility gate. The packaged `generic.mjs` client lets any local
harness invoke the shared service through the explicit `AccountTrusted` policy.

The fallback is forbidden when a paved integration is available. In particular,
Copilot CLI must use its native tools and `/konclave` commands. A paved-operation
failure remains visible; it never authorizes profile discovery or Generic fallback.

## Security contract

The generic client:

- generates a memory-only session key;
- uses the installed account issuer only to request one finite exact-profile grant;
- pins and authenticates the installed service;
- supports authenticated deadline and caller cancellation;
- seals terminal request outcomes in the profile journal; and
- retires its exact grant on clean exit.

It proves no harness provenance. The `Generic` harness kind is bounded metadata, not
`HarnessAttested` evidence. An installation whose policy excludes `AccountTrusted`
rejects the client with no fallback.

The generic client also proves no automatic delivery, pre-tool policy gate, native
permission intersection, subagent containment, or durable turn/token accounting.
`collaboration.turn.authorize` and `collaboration.action.evaluate` are deliberately
absent from its closed operation surface. Activating a policy therefore does not turn
an unsupported harness into an autonomous collaborator; peer content remains data
that the harness may inspect and answer only through explicit operations.

## Profile selection

Pass one canonical lowercase profile alias. A user-approved alias can provide durable
continuity across invocations. If no stable subject exists, use a random
`generic-<suffix>` alias and treat it as explicitly ephemeral. Never derive continuity
from a process identifier, working directory, timestamp, model name, or agent text.
Aliases beginning with `session-` are reserved for paved harnesses and rejected by the
Generic client.

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

It accepts one closed operation name and one JSON value over stdin:

```shell
printf '%s' '{"conversation_id":"<conversation>","limit":100}' |
  node <absolute-generic.mjs> --profile <profile-alias> --operation read_messages
```

For a side-effecting call, generate one random 16-byte lowercase hexadecimal request
identifier and pass `--request-id <32-hex-characters>`. Reuse that exact identifier,
operation, and payload after a transport failure to retrieve the sealed terminal
outcome rather than creating a new operation.

PowerShell:

```powershell
'{"conversation_id":"<conversation>","limit":100}' | node <absolute-generic.mjs> --profile <profile-alias> --operation read_messages --request-id <32-hex-characters>
```

Success is one JSON value on stdout. Failure is one finite JSON object on stderr.
Credentials, paths, request payloads, and peer plaintext are never copied into an
error. If the operation succeeded but clean grant retirement failed, the successful
result is preserved and stderr receives the finite
`{"warning":"grant_retirement_failed"}` diagnostic; expiry remains the cleanup
backstop. The one-shot process is suitable for skill-driven best-effort integrations;
paved clients remain preferable when a harness exposes reliable resume, fork,
subagent, shutdown, and delivery lifecycle events.

For ongoing conversations, invoke `sync_messages`, then `read_messages` or
`watch_messages` with an explicit conversation identifier. Let each bounded wait
complete instead of busy-polling.

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
