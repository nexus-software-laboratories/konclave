# External recipe composition

Konclave supplies messaging primitives, not task-specific workflow modes. A recipe
is inert data for an explicitly installed, locally selected external provider.
[ADR 0030](../adr/adr-0030-correlated-response-continuation.md) carries forward that
boundary after superseding ADR 0029, which superseded ADR 0028. The packaged
v0.1.31 `client.mjs` exports the definition codec,
exact run-selection codec and a bounded messaging adapter; examples remain outside
the client implementation under `extensions/Konclave.HostExtension/examples/recipes/`.

## Definition versus authority

A definition has exactly `name`, `provider` and `configuration` string fields.
`createRecipeDefinition` produces fixed-order canonical JSON and a domain-separated
SHA-256 digest. `decodeRecipeDefinition(bytes, expectedDigest)` accepts only the
exact independently selected bytes. The returned object is immutable.

Names are display metadata. Provider identifiers are inert keys, not module paths,
URLs or instructions to download code. Configuration is opaque provider-owned data,
never collaboration-policy guidance. Unknown providers must fail rather than load
or execute anything automatically.

The definition, its digest, its publication and its selection grant no authority.
Existing local permissions, exact-profile grants and remotely effective
collaboration policies remain prerequisites. Provider code is trusted application
code, not sandboxed by this SDK; approving data is not proof of that code's integrity.

The codec accepts at most 48 KiB of Unicode-scalar configuration and 64 KiB of
canonical encoded definition. Malformed encodings, accessors, proxies, unknown or
duplicate fields, alternative canonical bytes and unexpected digests fail with
finite content-free errors.

## Exact run selection

`createRecipeRun(definitionBytes, expectedDefinitionDigest, selection)` accepts:

| Selection field | Contract |
|---|---|
| `profile` | Existing canonical local profile; must match the authenticated client |
| `nonce` | Caller-chosen 16-byte lowercase hexadecimal run nonce |
| `bindings` | One through 16 explicitly selected named request slots |
| `input` | Opaque supplied context, at most 48 KiB UTF-8 |

Each slot has exactly `name`, `conversationId` and `targetDeviceId`. Slot names are
unique. Multiple explicitly named slots may use the same already approved target.
There is no alias discovery, pairing, enrollment, policy activation or endpoint
selection here.

The immutable run contains its exact definition, profile, ordered bindings, input
and nonce. Its canonical JSON is bounded to 256 KiB. The run identifier covers all
those values, and `decodeRecipeRun(bytes, expectedRunId)` refuses a changed selection.
Definitions and run descriptors can contain confidential data. The SDK never stores,
prints or uploads them; caller-owned custody must protect any retained descriptor.

Preparing a run still does not approve it. The application separately obtains local
authorization for the exact selection, intended data flow and provider implementation.
An expected digest received beside untrusted bytes is not independent approval.

`recipeMessageId(run, slotName)` derives one stable native application message
identifier for each declared slot. Each slot represents one logical directed request,
not an unlimited loop. A genuinely new intent uses a new explicitly authorized run;
recovery uses the original approved descriptor instead of guessing a new selection.

## Bounded messaging adapter

### Construct and submit one explicitly approved run

This application fragment imports the matching selected bundle described in the
[TypeScript reference](typescript-client.md). The caller supplies an authenticated
client and already-approved conversation/device identifiers, each 64 lowercase hex
characters (32 bytes). It must inspect and authorize the exact returned descriptor
before calling `send`; a generated digest is integrity evidence, not consent.

```javascript
import { randomBytes } from 'node:crypto';
import {
  createRecipeDefinition, createRecipeRun, createRecipeMessaging,
} from './konclave/client.mjs';

export async function prepare(client, conversationId, targetDeviceId) {
  const definition = createRecipeDefinition({
    name: 'review',
    provider: 'example.review',
    configuration: 'Return bounded review findings only.',
  });
  const run = createRecipeRun(
    Buffer.from(definition.canonicalJson, 'utf8'),
    definition.digest,
    {
      profile: client.profile,
      nonce: randomBytes(16).toString('hex'),
      bindings: [{ name: 'reviewer', conversationId, targetDeviceId }],
      input: 'Review the explicitly supplied change summary.',
    },
  );
  return run;
}

export async function submitApproved(client, approvedRun) {
  const messaging = createRecipeMessaging(
    client, Buffer.from(approvedRun.canonicalJson, 'utf8'), approvedRun.runId,
  );
  const receipt = await messaging.send('reviewer', approvedRun.input, {
    deadlineMs: 30_000,
  });
  const observation = await messaging.poll('reviewer', { deadlineMs: 30_000 });
  return { receipt, observation };
}
```

`example.review` is an inert example identifier, not installed provider discovery.
An external runner must select approved code at an exact explicit path and verify
its expected provider identity; neither codec crawls directories or loads modules.
No provider runtime is needed to use these primitives directly. Persist approved
canonical bytes and independently pinned run ID in application-owned protected
storage before side effects. Restoring a run means decoding those exact bytes with
`decodeRecipeRun`; never regenerate the nonce or rebind a target during recovery.

Definition names are 1–64 lowercase alphanumeric/hyphen characters in nonempty
segments; provider identifiers are 1–128 lowercase alphanumeric segments separated
by `.`, `_` or `-`. Binding names are similarly bounded to 64 characters. `input`
and configuration must be valid Unicode scalar strings; empty is permitted.
Message text must be nonempty and at most 255 KiB UTF-8. Oversize values fail rather
than truncate.

`RecipeSubmission` returns `bindingName`, `messageId`, relay `cursor` and
`senderCounter`. `RecipeReplyPage` is either `kind: 'pending'` with `afterCursor`
and `hasMore`, or `kind: 'reply'` with binding, request/message identifiers, cursor
and untrusted `text`. Pending is not failure or remote completion. It requires the
runner's finite scheduling decision. An exact correlated answer is not another
directed request; any continuation still requires independent current local policy.

`RecipeRunError.code` distinguishes invalid input/run/profile/nonce/binding,
`duplicate_binding`, `run_too_large`, `run_mismatch`, `unknown_binding`,
`profile_mismatch`, `invalid_response`, `invalid_request`, `unsupported_provider`,
`busy`, `slot_conflict` and `request_not_submitted`. Correct malformed selection
before admission; do not bypass unknown providers or profile mismatch. Poll only
after a successful submission. For ambiguous sends retain the same run and exact
body; `slot_conflict` means stop, not create another request. Cancellation does not
retract delivered messages, revoke peer work or undo external effects.

The public codec/messaging owners are
[`definition.ts`](../../extensions/Konclave.HostExtension/src/recipes/definition.ts),
[`run.ts`](../../extensions/Konclave.HostExtension/src/recipes/run.ts),
[`client.ts`](../../extensions/Konclave.HostExtension/src/recipes/client.ts) and
[`reply.ts`](../../extensions/Konclave.HostExtension/src/recipes/reply.ts).
Validation examples live in `recipe-definition.test.ts`, `recipe-run.test.ts`,
`recipe-client.test.ts`, `recipe-reply.test.ts` and `recipe-examples.test.ts` under
the extension's tests directory. This fragment is source-checked, not a claim of
new test execution or an available package publication.

`createRecipeMessaging(client, descriptorBytes, expectedRunId)` requires an existing
authenticated `LocalServiceClient` for exactly the selected profile. It exposes:

- `send(slotName, text, options?)`: submit one bounded native directed request to the
  slot's exact conversation and target, using stable message and local request IDs;
- `poll(slotName, options?)`: inspect an already submitted request using a bounded
  history page, at most one native watch and a final bounded history read.

`send` verifies the returned conversation, message, cursor and sender counter. An
exact successful repeat reuses the observed receipt. A changed body conflicts;
unknown outcomes remain bound to the original body and identities. Across process
restart, the native journal owns idempotency, not an in-memory receipt cache.

`poll` reads one history row at a time to avoid unnecessarily materializing unrelated
content. It validates explicit content kind, conversation, authenticated sender,
request reference, chronological cursor and bounded text. Only the exact target's
ordinary-text response can complete a slot. Policy records, requests, other senders
and notifications cannot. Display-only legacy text fallbacks are not accepted.

The first matching response in native history order is terminal for that slot;
later ordinary text cannot implicitly restart it. All peer text remains untrusted
data even when its sender is authenticated.

A poll returns either an exact reply or `pending` with cursor progress. Pending is
not proof of refusal, absence, failure or cancellation. A watch can wait for the
service's configured finite interval, and concurrent background replay can affect
when an answer becomes visible. No completion-latency guarantee is inferred.

The adapter starts no scheduler or hidden retry loop. Concurrent work on one slot
fails as busy instead of creating another queue. Transport and service errors,
including capacity and encoded-frame limits, remain visible; content is never
truncated to make a request succeed. Native cancellation semantics apply: a stop
request cannot retract an already committed or delivered effect.

## Lifecycle and recovery

The caller owns the client lifetime, foreground work budget, cancellation signal
and appropriate delivery-consumer lifecycle. The adapter neither steals a consumer
lease nor changes mute settings. Sustained use must respect the existing bounded
notification journal and the [adapter lifecycle](adapter-sdk.md).

A Generic client does not acquire paved autonomous-response guarantees by executing
a recipe. A paved integration must use its existing boundary; a failure does not
authorize a Generic fallback or selection of another profile.

To resume, restore the exact original descriptor and expected run identifier,
verify the selected provider implementation independently, and repeat only identical
slot requests. Native idempotency reconciles previously committed sends. If the
original selection or appropriate custody is unavailable, stop visibly; do not
create a new nonce and call that recovery.

## Reference compositions

The typed `fanOut` and `handoff` functions in
`extensions/Konclave.HostExtension/examples/recipes/compositions.ts` share the same
adapter:

| External provider example | Behavior |
|---|---|
| `example.fan-out` | Send supplied context to the declared slots, settle all launched work, then make one bounded poll per slot |
| `example.handoff` | Visit slots in declared order, forwarding a validated previous answer as untrusted input only after explicit application approval |

The examples return completed or pending results; they do not print replies,
continue indefinitely, execute suggested tools, or interpret response prose as
authority. A fan-out failure can follow other committed submissions: reconcile
through the same descriptor rather than claiming rollback. A handoff stops before
starting later slots when the current answer is not yet observed.

These are external examples, not registered daemon modes or an SDK provider
registry. They are compiled and exercised by the existing TypeScript contract
suite, including execution through the actual adapter against a deterministic native
client fixture and reconstruction with the same identities.

## Confidentiality and disclosure

Native requests and replies retain MLS protection. The relay receives no recipe
plaintext or new workflow metadata. A provider necessarily sees data deliberately
supplied to that local application; this does not defend against a compromised
endpoint or provider.

A directed target selects the expected responder, not a private recipient within
an MLS group. Every current conversation member can read its group messages. The
run descriptor does not freeze membership. Approve the actual conversation audiences
and use appropriately scoped conversations where independent or private exchanges
are required.

Forwarding an answer to another slot is an explicit data-disclosure decision, not
permission granted by selecting a recipe. Configuration must never broaden native
permissions. Exact correlated answers may continue currently authorized local work
under ADR 0030; they do not become new directed requests or create authority from
response prose.
