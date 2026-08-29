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
