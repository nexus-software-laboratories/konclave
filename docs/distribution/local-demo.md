# Local Copilot demo

The Windows demo script prepares a real local relay and user-scoped Copilot extension
without Docker, a local Rust toolchain, or manual credential handling.

## Prerequisites

- PowerShell 7.4 or later;
- authenticated `gh` access to this public repository;
- an installed and authenticated Copilot CLI; and
- a local checkout on a named same-repository branch containing the script.

Validate prerequisites and the local safety checks without changing demo state:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Validate
```

## Start

From the repository root:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1
```

The first run:

1. dispatches an independently correlated, Windows-only package workflow on the
   current named branch;
2. waits only for the Windows candidate;
3. requires the workflow source revision to equal the local checkout, downloads
   roughly 31 MB, and checks each archive hash against its co-produced unsigned
   provenance before cancelling the remaining demo dispatch;
4. deletes every artifact belonging to that exact workflow run and confirms zero
   remain;
5. rejects unsafe or oversized ZIP entries, then extracts the CLI, shared service, relay, and
   built extension payload beneath the current user's local application-data directories;
6. generates enrollment authority directly into Windows native credential custody;
7. starts the loopback relay as a hidden process;
8. runs `init --authorization-policy account-trusted` and `doctor`;
9. creates owner-protected service/issuer state, installs the thin extension and
   sidecar-adjacent Generic client, removes any unchanged Generic skill owned by an
   earlier demo from Copilot's paved harness, and starts exactly one hidden
   shared-service process;
10. runs `doctor` through the live owner-authenticated named pipe; and
11. records the exact relay and service process identities for safe shutdown.

When upgrading from the per-session daemon build, setup replaces the extension entry
point in place so fresh sessions use the thin client. If an existing session still
holds the old executable open, setup defers deletion of only that legacy `bin`
directory and retries exact removal on later runs after the session exits.

The unsigned provenance provides digest consistency and binds the package to the
checked-out source revision. It does not establish publisher authenticity or replace
the future signing and attestation work.

`AccountTrusted` deliberately trusts every process under the current Windows account;
the demo does not claim isolation between hostile same-user sessions. Each extension
still uses a memory-only session key and a finite exact-profile grant, while the
installed account key remains issuance-only.

Later runs reuse the installed candidate. Use `-Refresh` to rebuild and replace it:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Refresh
```

Close existing Copilot sessions after setup so fresh sessions discover the extension.
The extension reads the endpoint, issuer registration, explicit policy, pinned
service key, and issuer-key path from its bounded owner-protected sidecar. It never
receives a daemon path or profile root. During this pre-release schema-v2 cut,
`-Refresh` removes only schema-v1 authorization configuration after stopping the exact
recorded service; profile and conversation state remain.

Slash-command output defaults to concise normal summaries. Run
`/konclave output verbose` in one session when diagnosing identifiers, grant capacity,
delivery state, or pairing phases; `/konclave output normal` restores the default.
This presentation setting lasts only for the current extension process.

## Pair two sessions

Open fresh Copilot CLI sessions in two repositories.

In the first session:

```text
/konclave connect
```

Keep that command running and copy its single ephemeral capability to the other
session:

```text
/konclave connect <capability>
```

Both commands complete with the same conversation identifier. Send from either side
with:

```text
/konclave send -- <message text>
```

That selection is stored in the session's durable profile, so implicit send continues
to target the same conversation after the Copilot session is restarted or resumed.
Profiles upgraded from an earlier candidate deliberately do not guess among existing
conversations. If `/konclave conversations` shows no active selection, choose the
intended identifier once with `/konclave use <conversation-id>`. Selection does not
change that conversation's automatic-delivery mute state.

The two-command flow is an explicit `AccountTrusted` convenience policy. Capability
creation and redemption are treated as the two same-account approval actions; status
states that no independent identity verification occurred, and only the `member` role
is granted. Stronger authorization policies and administrator grants use the manual
`pair`, `join`, `new`, `approve`, and `sync` commands.

The capability remains terminal-visible and may appear in local CLI input history. It
is protected by short expiry, one-time consumption, and daemon-side zeroization, not
by the ephemeral display flag. Do not paste it into logs or public artifacts.

The idle peer receives messages automatically. On resume, the extension waits through
a five-second startup grace before treating a session with no observed user, assistant,
or tool activity as idle; observed activity cancels that inference, and the next
explicit idle event remains authoritative. `/konclave messages
<conversation-id>` performs an explicit bounded sync/read when diagnosing delivery,
and `/konclave reply <conversation-id> <reply-to-message-id> [message-id] --
<message text>` records a reply relationship when desired. Both commands print the
generated message identifier before sending; reuse it in the optional position after
a transport failure to reconcile the same operation instead of creating a duplicate.

The accepting `connect` command creates a durable conversation before the remote
command completes. If the pairing is abandoned or times out, that empty conversation
remains visible in `/konclave conversations`; the command does not hide this
non-atomic boundary.

## Automated two-session smoke

The complete local agent scenario is temporarily disabled while the packaged Copilot
adapter adopts the daemon's durable directed-request handling protocol.
`Invoke-KonclaveCopilotSmoke.ps1` retains the hard CI refusal and then exits before
starting a Copilot session. This prevents the superseded ordinary-text autonomy path
from consuming credits or hanging while the follow-up integration is incomplete.

When re-enabled, the runner must continue to keep capabilities, policy annotations,
prompts, model responses, tool arguments, credentials, and user-provided content out
of its report.

This is deliberately a local development smoke. Both the PowerShell entry point and
the TypeScript runner refuse recognized CI environments. No repository workflow
invokes it, and its live result must never be uploaded as an Actions artifact. CI
only compiles, lints, and unit-tests the deterministic runner with no Copilot
inference.

Use `-SkipSetup` to reuse an already-running relay or `-Refresh` to rebuild the
packaged Windows candidate before the smoke.

## Stop

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Stop
```

Stop mode terminates the recorded shared service and relay only after verifying each
executable and start time. Profile, relay state, installed files, and the user-scoped
extension remain for the next demo run.

To remove the user-scoped extension explicitly:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Stop -UninstallExtension
```

If setup enabled Copilot's experimental setting, explicit extension removal restores
the prior setting. The script also removes the obsolete direct-plugin registration
created by earlier demo versions. Setup and uninstall remove a Generic skill installed
by an earlier demo only when its ownership record and exact installed hash still
match. A pre-existing or modified user skill is never overwritten or recursively
removed.

The demo uses an HTTP loopback relay. Packaged acceptance separately proves the same
flows through trusted TLS and the Docker-loaded relay candidate.
