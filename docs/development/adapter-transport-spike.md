# Harness-neutral adapter transport spike

> **Historical spike.** ADR 0008 supersedes the selected per-session process model.
> These probes remain evidence for why extension-owned tools are feasible and why a
> harness-neutral local boundary matters; they are not the current Copilot runtime.

Issue [#26](https://github.com/nexus-software-laboratories/konclave/issues/26)
requires executable evidence before Konclave freezes a local adapter contract. This
spike compares extension-owned tool proxying with a separate adapter-owned local
capability channel.

## Evidence

### Copilot extension-owned tools

GitHub Copilot SDK 1.0.11 exposes custom tools with runtime handlers through
`joinSession({ tools })`. The committed probe registers a dynamically described tool
and launches an authenticated Copilot CLI child to invoke it:

```shell
npm --prefix ./extensions/Konclave.HostExtension run spike:sdk-proxy
```

The probe succeeds only when Copilot invokes the extension handler and returns its
exact result. It launches a real authenticated Copilot request and therefore consumes
the account's normal usage allowance; it is explicit spike evidence, not a routine CI
gate. This proves that an extension can own tools. It does not give the
extension a handle to a daemon declared through `mcpServers`; that configuration is
passed to the CLI, which owns the MCP child and routes calls directly.

An extension could therefore spawn the daemon itself, discover every MCP schema,
re-register every tool as a custom SDK handler, and forward every call. That path is
technically feasible, but it makes the Copilot adapter responsible for MCP lifecycle,
schema translation, call cancellation, result conversion, and permission parity.
Future adapters would need equivalent proxy behavior even when their harness already
supports MCP natively.

### Adapter-owned local capability channel

The second probe models an adapter that opens a local endpoint before starting or
joining its harness. It supplies the endpoint, a random 256-bit capability, and a
profile identifier to the daemon process. The daemon connects outward to that
endpoint:

```shell
npm --prefix ./extensions/Konclave.HostExtension run spike:adapter-transport
```

The Node adapter server and standalone Rust client prove:

- Rust-to-Node Unix-domain-socket connectivity without an internet listener;
- owner-only Unix directory and socket modes;
- constant-time capability and profile comparison;
- rejection of a wrong capability;
- rejection of a cross-profile attachment;
- daemon reconnection to the same adapter endpoint;
- rejection of a stale endpoint after adapter shutdown; and
- successful attachment after the adapter creates a new endpoint and capability.

The same orchestrator supports a Node client so the Windows named-pipe endpoint and
authorization behavior can be exercised on a workstation without installing a Rust
toolchain:

```powershell
$env:KONCLAVE_ADAPTER_PROBE_CLIENT='node'; npm --prefix ./extensions/Konclave.HostExtension run spike:adapter-transport
```

Production work must add Rust-to-Node Windows named-pipe coverage before the local
adapter transport is considered complete.

The probe passes its capability through process environment without writing or
logging it. That is sufficient to test transport behavior but is not the selected
Copilot launch contract: Copilot owns the MCP child, so a raw environment value would
transit harness session configuration. ADR 0005 instead selects an owner-protected
ephemeral capability file whose path, not contents, is supplied to the daemon.
Production must also zeroize secret buffers, bound concurrent peers, use versioned
frames, and apply the claim lease defined by that ADR.

## Decision

ADR 0005 originally selected native harness MCP ownership plus a separate
harness-neutral adapter channel. ADR 0008 later superseded that process model with one
per-user local service and thin harness clients.

This choice:

- preserves the current MCP tool surface without schema duplication;
- keeps Copilot SDK types outside daemon and shared-crate APIs;
- gives future harnesses the same adapter contract whether or not they support MCP;
- keeps all non-local network connectivity outbound from the agent device; and
- scopes adapter restart to a new endpoint and capability while daemon restart can
  reconnect to the existing adapter.

ADR 0008 now owns the normative process, authentication, lease, lifecycle, and
threat-model decisions. These spike files are executable historical evidence, not a
stable adapter API.
