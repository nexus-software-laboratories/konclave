---
name: konclave-generic
description: Use Konclave from an unsupported harness through the installed generic AccountTrusted client.
---

Use this fallback only when the harness has no paved Konclave integration. It provides
the same pairing, messaging, history, and synchronization operations through the
installed shared service.

- Stop immediately when native Konclave tools or `/konclave` commands are available.
  Never invoke `generic.mjs` from Copilot CLI, search profile storage, switch to
  another session's profile, or reinterpret a paved-operation failure as permission
  to use the fallback.
- This path proves only `AccountTrusted`: every process under the configured operating
  system account is trusted. Never claim harness attestation or same-user isolation.
- Choose one explicit canonical profile alias. Reuse a user-approved alias for durable
  continuity; otherwise generate a clearly ephemeral `generic-<random>` alias. Never
  derive continuity from PID, working directory, time, model name, or free-form text.
  The `session-*` namespace is reserved for paved harnesses and is rejected.
- Resolve `generic.mjs` beside the packaged `extension.mjs`. Invoke it with
  `node <absolute-generic.mjs> --profile <alias> --operation <operation>`.
- Pass one JSON object through stdin. Read the single JSON result from stdout. Errors
  are finite JSON on stderr and never include credentials, paths, or payloads.
- Generate one random 16-byte lowercase hexadecimal `--request-id` for a
  side-effecting call. Preserve and reuse it with the exact operation and JSON payload
  after transport failure; a new identifier means a new operation.
- Use only declared Konclave operations. For ongoing conversations, call
  `sync_messages`, then `read_messages` or `watch_messages` with the explicit
  conversation identifier. Do not busy-poll; let the operation's bounded wait finish
  before issuing another call.
- Keep pairing capabilities and invitations out of logs and chat transcripts except
  for the exact intended peer handoff.
