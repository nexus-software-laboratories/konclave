# Author collaboration policies

Collaboration policies are explicit editable inputs. A file in this repository, a
checkout, or a catalog entry does not grant agent authority. ADR 0011 requires a
separate locally authorized conversation binding. The paved Copilot surface creates
or changes that binding only through explicit `/konclave policy` commands.

The source and catalog schemas are:

- `collaboration-policy-source-v1.schema.json`;
- `collaboration-policy-catalog-v1.schema.json`.

`examples/contract-alignment.json` demonstrates the initial paved
`conversation.reply` control, unlimited duration/turn/token limits, and one
concurrent collaboration request. It is an editable example rather than a built-in
mode.
`examples/catalog.json` lists it without scanning the directory.

Create a source:

```text
konclave policy create --name contract-alignment --output contract-alignment.json
```

Edit the JSON with any editor, then validate and inspect it:

```text
konclave policy validate --source contract-alignment.json
konclave policy inspect --source contract-alignment.json
```

Compile immutable canonical bytes:

```text
konclave policy compile --source contract-alignment.json --output contract-alignment.bin
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
