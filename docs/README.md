# Konclave documentation

This map lists the documentation contributed by the selected project shape.

## Architecture

- [Architecture decisions](architecture/decisions.md)
- [ADR 0001: Protocol trust and E2EE](adr/adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0002: Sealed local secret custody](adr/adr-0002-sealed-local-secret-custody.md)
- [ADR 0003: Relay transport authentication](adr/adr-0003-relay-transport-authentication.md)
- [ADR 0004: Daemon profile journal](adr/adr-0004-daemon-profile-journal.md)
- [ADR 0005: Harness-neutral adapter boundary](adr/adr-0005-harness-neutral-adapter-boundary.md)
- [ADR 0006: Joiner-issued pairing capabilities](adr/adr-0006-joiner-issued-pairing-capabilities.md)
- [ADR 0007: Outbound relay principal enrollment](adr/adr-0007-outbound-relay-principal-enrollment.md)
- [ADR 0008: Shared per-user local service](adr/adr-0008-shared-local-service.md)
- [ADR 0009: Evidence-bound exact-profile session grants](adr/adr-0009-evidence-bound-session-grants.md)
- [ADR 0010: AccountTrusted two-command pairing](adr/adr-0010-account-trusted-two-command-pairing.md)
- [ADR 0011: Content-addressed collaboration policies](adr/adr-0011-content-addressed-collaboration-policies.md)
- [ADR 0012: Structured directed collaboration requests](adr/adr-0012-structured-directed-collaboration-requests.md)
- [ADR 0013: A2A edge interoperability](adr/adr-0013-a2a-edge-interoperability.md)

## Protocol

- [Protocol compatibility contract](protocol/compatibility.md)
- [Identity signature encodings](protocol/identity-signatures.md)
- [Relay transport authentication](protocol/relay-authentication.md)
- [Relay principal enrollment](protocol/relay-enrollment.md)

## Security

- [Threat model](security/threat-model.md)

## Development

- [Rust engineering conventions](development/rust-engineering.md)
- [Node dependency installation](development/node-dependencies.md)
- [Rust service composition](development/rust-services.md)
- [Conformance and security evidence](development/conformance.md)
- [Sealed secret storage](development/secret-storage.md)
- [Opaque relay storage](development/relay-storage.md)
- [Outbound relay client](development/relay-client.md)
- [Daemon profiles and recovery](development/daemon-profiles.md)
- [Harness-neutral adapter transport spike](development/adapter-transport-spike.md)
- [Adapter channel authentication](development/adapter-channel-authentication.md)
- [Shared local service transport](development/local-service-transport.md)
- [Copilot delivery safety](development/copilot-delivery-safety.md)
- [Collaboration policy contracts](development/collaboration-policies.md)
- [Repository controls](development/repository-controls.md)
- [Continuous integration](development/ci.md)

## Guides

- [Author collaboration policies](../policy/README.md)
- [Install an unsigned prerelease](distribution/installation.md)
- [Verify release integrity and contents](distribution/integrity.md)
- [Packaged clean-install acceptance](distribution/acceptance.md)
- [Local Copilot demo](distribution/local-demo.md)
- [Generic harness client](integrations/generic-client.md)
- [UX and design resilience](ux-design.md)
- [Impeccable design workflow](impeccable-design.md)
