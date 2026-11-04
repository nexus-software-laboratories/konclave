# TypeScript local-service client reference

This reference describes the **v0.1.31 source and packaged client**, not a published
npm SDK or a compatibility promise. The extension and protocol TypeScript packages
are private workspace artifacts. Node.js 24 or newer is required by the extension
manifest. The authored integration barrel is
[`src/client-api.ts`](../../extensions/Konclave.HostExtension/src/client-api.ts);
the existing build bundles it as `client.mjs`, alongside `generic.mjs`.
Use an explicitly selected matching artifact or a workspace-relative source import.
Do not search plugin/profile directories for a usable identity or substitute an
invented `npm install konclave` dependency.

## Choose the boundary

| Caller | Entry point | Responsibility retained by caller |
|---|---|---|
| Copilot integration | `connectInstalledService` and existing command, tool, policy-gate and delivery factories | Native session identity, permission hooks, lifecycle and shutdown |
| Otherwise unsupported local harness | `connectInstalledGenericService` | Explicit profile selection and best-effort operation lifecycle |
| One-shot external process | [`generic.mjs`](generic-client.md) | Stdin/stdout contract, retry identity and foreground budget |
| External composition | [Recipe codec and messaging adapter](recipes.md) | Provider approval, audiences, run custody and scheduling |
| Native endpoint owning its own keys | [Rust native composition](native-client.md) | Qualified custody and durable journals, not local-service RPC |

Generic is not recovery from a denied or broken Copilot operation. Neither the
Generic label nor a successful local connection attests a harness or grants remote
work authority.

## Connect to one exact profile

Both installed connectors accept an environment record, the selected client
module's directory, and a profile or `GenericClientIdentity`. An optional platform
argument defaults to `process.platform`; it is a platform-selection seam, not a way
to bypass native evidence. They read installer-owned configuration and pin the
service key; neither starts a daemon. Missing or inconsistent installation records
are visible failures. Configuration locations and platform evidence selection are
owned by the [Generic installation contract](generic-client.md#invocation).

`GenericClientIdentity` requires all three fields:

| Field | Encoding and meaning |
|---|---|
| `profile` | Canonical lowercase ASCII letters, digits, `_`, `-`; no normalization; `session-` prefix is reserved |
| `profileMode` | Exactly `durable` for an explicitly approved continuity alias, or `ephemeral` for an isolated `generic-` plus 24 lowercase hex characters |
| `integrationLabel` | 1–64 lowercase ASCII characters, starting/ending alphanumeric; interior digits, letters, `.`, `_`, `-`; local self-declared metadata only |

Validation precedes installation/key access. A successful connection binds the
returned `LocalServiceClient.profile` immutably. It does not expose profile keys,
permit switching profiles, or prove membership in any conversation.
The installed connector uses a 2,000 ms transport startup budget; Windows
UserPresence has a separate 180,000 ms grant-ceremony budget. AccountTrusted is
preferred only when an independent policy clause permits it. Otherwise a satisfiable
Windows UserPresence clause requires the installed native helper; unavailable
evidence fails with `required_evidence_unavailable`, including on Linux/macOS.

## Request, cancellation and ownership

`request(operation, payload, options?)` returns `Promise<unknown>`: validate the
operation's result before using it. It is not a typed method for every daemon
operation. The barrel also exports `getMessageDeliveryStatus` for validated,
content-free delivery observations; see [delivery diagnostics](../development/local-delivery-diagnostics.md).

| `LocalServiceRequestOptions` field | Contract |
|---|---|
| `deadlineMs` | Integer 1–300,000 milliseconds; omitted defaults to 30,000 in the installed programmatic client |
| `signal` | Optional `AbortSignal`; abort requests authenticated cancellation |
| `requestId` | Optional **16-byte `Buffer`**, copied at admission; omitted generates fresh random bytes |

A numeric third argument is the legacy deadline shorthand. `null`, zero, an empty
buffer and an omitted option are not interchangeable. The local RPC payload limit
is 1,048,576 bytes; operation-specific limits can be smaller. No truncation occurs.

Requests serialize within an interactive lane and a separate delivery lane.
Delivery and turn-ownership operations retain their owning connection and do not
silently reconnect; ordinary operations permit one early transport reconnect by
default. A deadline or abort is a cancellation request, **not rollback** and not a
strict upper bound on terminal-result reconciliation after admission. The committed
result can still win. `reconciliation_pending` is retried finitely; if uncertainty
remains, retain the exact request identity, operation and serialized payload.
Do not create a new logical effect to make an ambiguous call disappear.

Two identifiers serve different layers: `requestId` reconciles a local RPC,
whereas a payload's `message_id` identifies the durable application message.
Protect both when retaining recovery data; across a fresh client/process, follow
the operation's application-level idempotency contract rather than assuming a new
session key preserves every old local request-ledger scope.

### Minimal read-only lifecycle

The following is an application integration fragment using a deliberately selected
`client.mjs` copied into the application's `konclave` directory from the matching
distribution. It is not a package-manager import or a Copilot fallback.

```javascript
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { connectInstalledGenericService } from './konclave/client.mjs';

const moduleDir = fileURLToPath(new URL('./konclave/', import.meta.url));
const client = await connectInstalledGenericService(process.env, moduleDir, {
  profile: '<approved-profile-alias>',
  profileMode: 'durable',
  integrationLabel: 'example.reader',
});
try {
  const result = await client.request('get_identity', {}, {
    requestId: randomBytes(16),
    deadlineMs: 30_000,
  });
  // Validate result in the application; do not log arbitrary service payloads.
} finally {
  try {
    await client.retire();
  } finally {
    client.close();
  }
}
```

Replace the angle-bracket profile placeholder with an independently selected
canonical alias. `get_identity` reads the bound device identity without pairing or
granting work authority. No remote conversation is needed. Production cleanup
should retain the operation outcome separately from a retirement failure.

`retire()` stops the client, settles its lanes and attempts exact-grant retirement.
`close()` only closes the client; calling it first makes subsequent `retire()` a
no-op. Therefore retire before close. On retirement failure, finite grant expiry
remains the backstop; do not replay a successful application operation merely to
retry cleanup. `connected` describes whether the client has been closed, not a
continuous probe of service/relay health.

## Failures and evidence

| Failure | Safe next action |
|---|---|
| `GenericClientIdentityError` (`invalid_arguments`, `paved_profile_reserved`, `ephemeral_profile_invalid`) | Correct explicit selection; do not discover another profile |
| `ServiceConfigurationError` | Repair/upgrade the installation or supply required evidence; never weaken policy |
| `LocalServiceUpgradeRequiredError` (`service_upgrade_required`) | Upgrade the installed service to match the client |
| `LocalServiceError` | Branch on finite `code`, not message text; preserve exact identity for ambiguous side effects |
| `LocalServiceProtocolError` | Stop using contradictory/malformed evidence; do not cast the result into a success type |
| Other connection/transport rejection | Surface failure and reconcile only within the relevant operation's retry contract |

Source owners are [`installed.ts`](../../extensions/Konclave.HostExtension/src/service/installed.ts)
and [`client.ts`](../../extensions/Konclave.HostExtension/src/service/client.ts).
[`service-client.test.ts`](../../extensions/Konclave.HostExtension/tests/service-client.test.ts)
owns connection, deadline, explicit-ID, cancellation and retirement examples;
[`service-config.test.ts`](../../extensions/Konclave.HostExtension/tests/service-config.test.ts)
owns installed-record validation. These are source evidence, not a claim that a
live service or current CI was exercised while reading this reference.
