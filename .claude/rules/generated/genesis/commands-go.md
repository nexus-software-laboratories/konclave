---
# AUTO-GENERATED from .github/instructions/genesis/commands-go.instructions.md — do not edit
paths:
  - "**/*.go"
  - "**/go.mod"
---
# Portable Go commands

## Resolve dependencies

```sh
go mod tidy
```

## Build

```sh
go build ./...
```

## Test

```sh
go test ./...
```

Use additional formatters, linters, generators, and release tools only when the
repository declares them in its manifests, workflows, or project-owned guidance.
