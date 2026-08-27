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
9. creates owner-protected service/issuer state, installs the thin extension,
   sidecar-adjacent generic client, and user-local generic skill in place, and starts
   exactly one hidden shared-service process;
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

## Pair two sessions

Open fresh Copilot CLI sessions in two repositories.

In the first session:

> Use Konclave to create a pairing capability requesting member role.

Give the single returned capability to the other session:

> Redeem this Konclave pairing capability. Create a conversation and authorize the
> observed joiner as a member.

Back in the first session:

> Review the pending pairing and authorize the observed inviter.

After both sides report completion, ask either session to send a message through the
conversation. The idle peer should receive it automatically.

## Automated two-session smoke

Run the complete local agent scenario with one command:

```powershell
pwsh -NoProfile -File .\scripts\demo\Invoke-KonclaveCopilotSmoke.ps1
```

The entry point composes the deterministic installer with a typed Copilot SDK runner.
It creates two isolated headless Copilot sessions using the current developer's local
authentication, loads only the packaged shared-client SDK tools, declares no MCP
server, transfers the capability without printing it, completes both authorization
paths, and verifies an exact message plus reply through the one recorded service PID.

The final JSON report contains session, pairing, conversation, message, phase, tool,
duration, and token evidence. It never includes the capability, prompts, model
responses, tool arguments, credentials, or user content.

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
created by earlier demo versions. The demo removes the generic skill only when its
ownership record and exact installed hash still match. A pre-existing or modified
user skill is never overwritten or recursively removed.

The demo uses an HTTP loopback relay. Packaged acceptance separately proves the same
flows through trusted TLS and the Docker-loaded relay candidate.
