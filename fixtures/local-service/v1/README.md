# Shared local-service fixtures

- `handshake-transcript.json` pins the authenticated local transport transcript.
- `copilot-tools.json` pins the current generated tool request and response schemas.
- `adapter-delivery.json` pins harness-neutral adapter API v1 delivery operations,
  bounds, event shapes, status, settlement, heartbeat, and crash-recovery semantics.

The adapter fixture is not Copilot-specific. Every paved harness implementation
should reproduce it; polling skills remain best-effort integrations.
