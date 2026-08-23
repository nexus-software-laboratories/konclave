---
applyTo: "crates/Konclave.AdapterTransport/**/*.rs,crates/Konclave.ProtocolContracts/**/*.rs,crates/Konclave.CryptographicCore/**/*.rs,crates/Konclave.SecretStorage/**/*.rs,crates/Konclave.DomainCore/**/*.rs,crates/Konclave.ClientLibrary/**/*.rs,apps/Konclave.LocalDaemon/**/*.rs,apps/Konclave.CommunityRelay/**/*.rs,extensions/Konclave.HostExtension/**/*.{ts,tsx},packages/Konclave.ProtocolContracts.TypeScript/**/*.{ts,tsx},**/*.proto,fixtures/adapter/**,fuzz/**"
scope: "Konclave protocol, cryptography, identity, relay, daemon, and adapter boundaries"
---

# Konclave protocol and security

- Treat accepted ADRs, the threat model, protocol compatibility contract, and
  conformance policy as normative for matching changes.
- Use MLS through the project cryptographic adapter. Never author custom group key
  agreement, signatures, AEAD, KDFs, or random generators.
- `ProtocolContracts` owns wire DTOs only. Convert untrusted wire values into validated
  domain types before authorization, allocation, persistence, or side effects.
- `CryptographicCore` owns provider integration and project cryptographic types. Raw
  provider state does not escape its boundary.
- `DomainCore` owns conversation and authorization policy without transport, storage,
  or cryptographic-provider dependencies.
- `ClientLibrary` composes domain, protocol, and cryptographic operations without
  assuming one relay deployment.
- The local daemon is the only process boundary that handles plaintext and raw secret
  state. CLI, UI, extensions, and relays never receive keys or provider state.
- The relay stores and logs only allowlisted delivery metadata plus opaque MLS bytes.
  It never parses Konclave application plaintext.
- Relay data-plane authentication stays outside protobuf. Never treat `RoutingId` as
  a credential or use stable `DeviceId` as a cross-route relay principal.
- Raw relay bearer tokens remain sealed at clients and never enter relay
  configuration, persistence, logs, or telemetry. Non-loopback bearer transport
  requires trusted TLS termination.
- Credential-bearing relay clients disable redirects and automatic proxy discovery.
  Dependency logging that can format handshakes or frames is removed at compile time
  unless the dependency proves credential and payload redaction.
- Treat relay non-equivocation as an explicit initial trust assumption. Compare-and-set
  does not defend isolated clients from a malicious split view; observed conflicts
  halt security-sensitive sending.
- Secret-bearing types are not `Clone`, `Debug`, generally serializable, logged,
  snapshotted, or persisted unsealed. Missing key custody fails closed.
- Daemon profiles acquire their exclusive lock before key custody or database open.
  Daemon and MLS schemas stay separately owned; incoming plaintext is journaled
  idempotently before receiver-ratchet persistence and relay acknowledgment.
- Membership changes are application-authorized on every client; MLS validity alone
  does not authorize them.
- Bind invitations to an independently verified expected `DeviceId` and enforce
  consumption in authenticated conversation state, not only relay storage.
- Derive sender identity from the authenticated MLS credential, never application
  payload fields.
- Root-key extraction permanently compromises that `DeviceId`; recovery removes it,
  advances the epoch, and enrolls a new identity.
- Every message and side-effecting request is idempotent and replay checked at the
  application layer.
- Apply hard pre-allocation bounds to every untrusted collection, frame, string,
  decompression, page, queue, and watch.
- Add focused negative, compatibility, and adversarial tests with every security
  behavior change. Cryptography, identity, authorization, wire parsing, secret
  persistence, and relay metadata changes require specialized security review before
  delivery.
