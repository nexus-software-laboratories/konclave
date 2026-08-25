# Local Copilot demo

The Windows demo script prepares a real local relay and packaged Copilot plugin
without Docker, a local Rust toolchain, or manual credential handling.

## Prerequisites

- PowerShell 7.4 or later;
- authenticated `gh` access to this public repository;
- an installed and authenticated Copilot CLI; and
- a local checkout of the current `main` commit containing the script.

## Start

From the repository root:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1
```

The first run:

1. dispatches an independently correlated, Windows-only package workflow on `main`;
2. waits only for the Windows candidate;
3. requires the workflow source revision to equal the local checkout, downloads
   roughly 31 MB, and checks each archive hash against its co-produced unsigned
   provenance before cancelling the remaining demo dispatch;
4. deletes every artifact belonging to that exact workflow run and confirms zero
   remain;
5. rejects unsafe or oversized ZIP entries, then extracts the CLI, daemon, relay, and
   built plugin beneath the current user's local application-data directories;
6. generates enrollment authority directly into Windows native credential custody;
7. starts the loopback relay as a hidden process;
8. runs `init` and `doctor`;
9. installs the Copilot plugin; and
10. records only non-secret process/path status for exact shutdown.

The unsigned provenance provides digest consistency and binds the package to the
checked-out source revision. It does not establish publisher authenticity or replace
the future signing and attestation work.

Later runs reuse the installed candidate. Use `-Refresh` to rebuild and replace it:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Refresh
```

Close existing Copilot processes after setup so new sessions receive the dedicated
demo profile root.

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

## Stop

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Stop
```

Stop mode terminates only the recorded relay process after verifying its executable
and restores the user profile-root environment setting from a separate no-clobber
backup created before setup. Stop fails safely rather than guessing when the demo
environment is active but that backup is unavailable. Profile, relay state, installed
files, and the cached plugin remain for the next demo run.

To remove the cached plugin explicitly:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1 -Stop -UninstallPlugin
```

The demo uses an HTTP loopback relay. Packaged acceptance separately proves the same
flows through trusted TLS and the Docker-loaded relay candidate.
