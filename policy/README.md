# Author collaboration policies

Collaboration policies are explicit editable inputs. A file in this repository, a
checkout, or a catalog entry does not grant agent authority. ADR 0012 requires a
separate locally authorized conversation binding. The paved Copilot surface creates
or changes that binding only through explicit `/konclave policy` commands.

The source and catalog schemas are:

- `collaboration-policy-source-v2.schema.json` for newly authored deterministic policies;
- `collaboration-policy-source-v1.schema.json` for legacy source compatibility; and
- `collaboration-policy-catalog-v1.schema.json`.

Source v2 does not accept model guidance, task instructions, or conversation topics.
Legacy v1 guidance remains decodable as untrusted historical annotation and grants
no model authority.

`examples/request-reply.json` demonstrates the paved
`conversation.reply` control, unlimited duration/turn/token limits, and one
concurrent collaboration request. It is an editable example rather than a built-in
mode.
`examples/catalog.json` lists it without scanning the directory.

Create a source:

```text
konclave policy create --name request-reply --output request-reply.json
```

Edit the JSON with any editor, then validate and inspect it:

```text
konclave policy validate --source request-reply.json
konclave policy inspect --source request-reply.json
```

Compile immutable canonical bytes:

```text
konclave policy compile --source request-reply.json --output request-reply.bin
```

Compilation never overwrites an existing source or bundle. Missing source limits
inherit caller defaults; explicit `null` is unlimited; positive integers are finite.
Hard parser, frame, queue, journal, and storage bounds remain mandatory.

Catalog operations require an explicit descriptor path:

```text
konclave policy list --catalog catalog.json
konclave policy validate-catalog --catalog catalog.json
```

The CLI does not search the current repository or user directories for policies.

## Source fields and evaluation

| Field | Meaning and limits |
| --- | --- |
| `apiVersion`, `kind` | Exactly `konclave.dev/v2` and `CollaborationPolicy` for new source. Unknown fields fail closed. |
| `metadata.name` | Canonical lowercase identifier, at most 128 characters; a name is not content identity. |
| `spec.statements` | At most 256 uniquely identified statements; compilation sorts them by identifier. |
| Statement `id`, `action`, `resource` | Canonical identifiers; action/resource are namespaced. An omitted or null resource is unscoped, not a filesystem wildcard. |
| Statement `effect` | `allow`, `deny`, or `require_local_approval` in source. The canonical/wire effect spelling is separately owned by its codec. |
| `spec.requiredHarnessClaims` | At most 64 canonical namespaced claims. Unsupported or unproved requirements do not become true because a harness labels itself. |
| `durationMilliseconds`, `turns`, `tokens` | Optional positive `u64` limits; duration is milliseconds, not seconds. Omission inherits caller defaults, null means unlimited, zero is invalid. |
| `concurrentRequests` | Optional positive `u32` concurrency bound with the same inheritance/null distinction. |

These are source fields under `spec.limits`, not arbitrary tool options.
The [source schema](collaboration-policy-source-v2.schema.json) and
[policy implementation contract](../docs/development/collaboration-policies.md)
own exact grammar, evaluator precedence, bound enforcement and canonical digesting.
Matching a statement is not sufficient if required claims, limits or the harness's
ordinary permission checks refuse the action. Unsupported enforcement fails closed.
New v2 source contains no model guidance or task instructions.

## Propose and activate deliberately

With a healthy installation and an existing conversation selected:

```text
/konclave use <conversation-id>
/konclave policy status
/konclave policy propose -- policy/examples/request-reply.json
```

The path is relative to the current workspace and must identify one bounded UTF-8
regular file physically beneath it. The example grants the reply control, not
general workspace execution. Successful compilation alone creates no binding;
explicit proposal is a local activation decision and journals that decision before
its notification is submitted. The other device has its own independent decision:

```text
/konclave policy inspect <proposal-id>
/konclave policy accept <proposal-id> <policy-digest>
```

Use the full identifiers returned by the authenticated proposal. Inspect it before
accepting; peer-proposed annotations remain untrusted. Receiving a proposal,
acceptance or revocation never silently changes local authority. To refuse the
proposal, use `policy reject` with the same exact identifiers.

A new proposal cannot overwrite an active binding implicitly. Use
`/konclave policy replace <active-digest> -- <relative-source>` with explicit
replacement intent. Keep the printed proposal ID; after an ambiguous failure,
`/konclave policy resume <proposal-id>` recovers the committed bytes without rereading
the source. Do not reuse the ID after editing content.

To end local authority, run `/konclave policy revoke <policy-digest>` and keep its
printed message ID for an exact retry. Revocation removes matching local authority
before attempting network notification. It cannot retract plaintext or external
effects already admitted. Check `policy status` afterward rather than inferring the
local binding from the peer's reply. JavaScript-facing status encodes `u64` policy
limits as canonical decimal strings; do not round them through `Number`.
