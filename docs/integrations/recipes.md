# External recipe composition

Konclave supplies messaging primitives, not task-specific workflow modes. A recipe
is inert data for an explicitly installed, locally selected external provider.
ADR 0028 owns that boundary. The packaged `client.mjs` exports the definition codec,
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
permissions, and ordinary automatic response turns remain one correlated reply.
