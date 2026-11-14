# Identifier privacy and disclosure

Use this reference before sharing a screenshot, attaching diagnostics, publishing an
example, or responding to an accidental disclosure. It owns the operator
classification of identifiers and identifier-like values, not their wire encodings
or authorization algorithms. The linked contracts and current owning code define
those details; this is not a claim that every deployment hides the same metadata.

## How to read the classification

**Non-secret does not mean safe to publish.** An identifier can grant no authority
yet reveal that two records concern the same device, conversation or task. Treat
live identifiers as privacy-sensitive metadata and disclose only what the intended
recipient needs. Public examples use placeholders.

**Possession alone** means copying the value without keys, credentials, an
authenticated connection, membership, or locally activated policy. A matching ID
does not bypass those checks. Conversely, a value called a token, nonce, digest or
code is not automatically safe: classify its actual use, not its name or length.

Widths below are decoded bytes unless text is explicitly specified. The native
operator interface generally renders 32-byte IDs as 64 lowercase hexadecimal
characters and 16-byte IDs as 32. Other boundaries can use different encodings;
relay authentication uses unpadded base64url. Do not interchange identifiers merely
because their lengths match.

## Conversation, device and transport identifiers

| Value / shape | Possession alone | Normal exposure boundary | Disclosure risk and operator response | Owning contract |
| --- | --- | --- | --- | --- |
| `ConversationId` / 32 bytes | No membership, decryption, impersonation or work authority. | Native endpoints and conversation credential bindings; not the relay routing field. | Links records to one MLS group. Redact publicly; ID-only exposure normally requires no new conversation. | [Identity binding](../protocol/identity-signatures.md#conversation-credential-binding), [domain IDs](../../crates/Konclave.DomainCore/src/identifiers.rs). |
| `RoutingId` / 32 bytes | No relay credential or MLS authority. | Relay envelope headers, route grants and native endpoints. Distinct from the conversation ID. | Links traffic to one route. Knowing the route can aid targeting; availability is not guaranteed. Redact publicly; do not treat secrecy as access control. | [Relay envelope](../protocol/compatibility.md#relay-envelope), [relay security boundaries](../protocol/relay-authentication.md#security-boundaries). |
| `DeviceId` / 32-byte public-key digest | No proof of possession of the device root key. | Credential/invitation verifiers and group members; also carried in MLS KeyPackage BasicCredentials. Short-code identity exchange is encrypted from the relay, not a guarantee for every transport. | Stable identity can link the device across conversations. Share deliberately for peer verification; root-key theft, not ID disclosure, requires replacement identity. | [Device derivation](../protocol/identity-signatures.md#device-identifier), [MLS credentials](../protocol/identity-signatures.md#mls-credential-relationship), [identity compromise](../security/threat-model.md), [short-code identity exchange](../adr/adr-0024-opaque-short-code-mutual-verification.md#exchange-identity-only-after-opaque-completes). |
| Profile identifier / at most 32 ASCII bytes; local aliases and display labels | No profile access, peer authentication or attestation. | Local configuration, filesystem/custody context, authorized clients and operator output; not a public discovery identity. | Names may expose projects or people; aliases can also be stale or misleading. Profile identity outlives a connection. Use neutral names and placeholders, not labels or empty tables as authorization/retirement evidence. | [Profiles](../development/daemon-profiles.md), [Windows key context](../adr/adr-0034-windows-profile-key-custody.md), [service profile bound](../development/local-service-transport.md), [trusted aliases](../adr/adr-0025-trusted-device-alias-bootstrap.md). |
| `MessageId` / 16 bytes; directed request ID and reply reference use this namespace | No send, read or autonomous handling authority. | Decrypted application history and permitted harness delivery; not a plaintext application index at the relay. | Links requests, replies and exact retries. Redact externally; preserve the original ID for reconciliation rather than resending under a new ID. | [Application messages](../protocol/compatibility.md#konclave-application-message), [delivery safety](../development/copilot-delivery-safety.md). |
| `EnvelopeId` / 16 bytes | No relay submission authority. | Relay and native endpoints. | Links an opaque submission to its receipt/retry. Preserve for exact retry; redact public diagnostics. | [Relay envelope](../protocol/compatibility.md#relay-envelope), [relay storage](../development/relay-storage.md). |
| Relay cursor, sender counter, epoch / bounded integers | No ordering or delivery assertion is trusted just because a number is supplied. | Relay cursors/handshake epochs are relay-visible; application sender counters are inside encrypted content. | Reveals order and activity, with timing/size correlation. Do not edit journal counters or advance cursors to repair a disclosure. | [Compatibility](../protocol/compatibility.md), [sealed journal recovery](../development/daemon-profiles.md). |
| Relay principal ID / 32-byte domain-separated bearer digest | No ability to authenticate with the bearer. | Relay authorization configuration, enrollment and bounded lookup metadata. | Links access registrations/activity. Redact externally; hashing is not a reason to publish the associated credential. | [Bearer and principal derivation](../protocol/relay-authentication.md#bearer-credential), [enrollment](../protocol/relay-enrollment.md). |

An ordinary directed request remains readable by other current members of its MLS
group. Naming a target device does not create recipient-only encryption. The relay
sees allowlisted routing metadata, not application plaintext. Konclave does not
promise to hide routing IDs, timing, payload sizes, IP addresses or all membership
metadata; see the [threat model](../security/threat-model.md).

## Local operation, policy and integration identifiers

| Value / shape | Possession alone | Normal exposure boundary | Disclosure risk and operator response | Owning contract |
| --- | --- | --- | --- | --- |
| `NotificationId`, `AdapterConsumerId`, `AdapterLeaseId` / 16 bytes each | No delivery acknowledgment or work authority without the authenticated owner, live lease and checked generation. | Local service, authorized delivery consumer and sealed journal. | Links harness activity and retry ownership. Redact publicly; do not copy lease values into another connection or change IDs to suppress redelivery. | [Delivery journal](../development/daemon-profiles.md), [local service](../development/local-service-transport.md). |
| Local RPC `RequestId`, `ClientInstanceId` / 16 bytes each | No RPC execution authority. | Authenticated local transport and its reconciliation ledger. | Links operations/connections. Exact retry binds caller instance, request, profile and bytes; a replacement connection-owned lease may require a fresh request. | [RPC retry contract](../development/local-service-transport.md), [transport IDs](../../crates/Konclave.LocalServiceTransport/src/identifiers.rs). |
| Issuer key ID, session grant ID / 16 bytes each; issuer version | No issuer/session signing authority. A complete grant still requires its matching session key and current authorization. | Local installation, issuer/session handshake and service registry. | Links an issuer or authorized session/profile. Redact diagnostics; do not revoke a healthy grant merely because its ID was seen. | [Evidence-bound grants](../development/local-service-transport.md#evidence-bound-issuer-and-session-grants), [grant implementation](../../crates/Konclave.LocalServiceTransport/src/grant.rs). |
| Harness session IDs, harness names and process IDs / owner-defined | No attestation or work authority. | Harness/local service metadata; representation is not a Konclave wire-ID guarantee. | Links activity to a session/account. Share minimally; never accept a label or process ancestry as proof of a trusted harness. | [Attestation boundary](../development/harness-attestation.md), [security reference](security-boundaries.md#trust-and-plaintext). |
| Policy proposal ID / 16 bytes; policy bundle digest / 32 bytes | No policy activation or acceptance authority. | Sealed group application history, local policy binding/index and bounded policy output. | Links a proposal or exact policy. A digest of a guessable policy can identify its contents; it is not anonymization. Redact as appropriate; activation still pins verified bytes under local authority. | [Policy identity and exchange](../development/collaboration-policies.md). |
| Invitation, pairing, pairing-message, membership-operation, repeat-pairing and short-code attempt/take IDs / 16 bytes each | No invitation redemption or membership authority from the ID alone. | Their signed/encrypted exchanges and local status; only protocol-required headers/lookups reach the relay. | Links a ceremony or retry. Redact publicly; keep stable operation IDs for recovery. An ID is not the invitation package or capability. | [Domain IDs](../../crates/Konclave.DomainCore/src/identifiers.rs), [pairing threat model](../security/threat-model.md#pairing-capabilities), [short-code retrieval](../adr/adr-0024-opaque-short-code-mutual-verification.md#require-both-explicit-confirmations). |
| Rendezvous lookup ID / 32 bytes | Cannot derive the secret token/decryption key. An authenticated lookup can still consume the one-time record. | Relay and participating endpoints. | Correlation and disruption risk even without plaintext access. Do not publish an active lookup or test its take operation casually; restart a disrupted pairing. | [Rendezvous derivation and retrieval](../adr/adr-0023-encrypted-pairing-rendezvous.md). |
| Short-code locator / 32-byte code digest; transcript/context/credential-binding hashes / 32 bytes | No membership authority; verified transcript/binding context is still required. | Only fields specified by the owning exchange. Short-code transcript/identity material is not blanket relay-visible. | Hashes can correlate data; a low-entropy code locator is guessable and does not hide the code. Keep active ceremony details within the intended exchange. | [Short-code protocol](../adr/adr-0024-opaque-short-code-mutual-verification.md), [identity encodings](../protocol/identity-signatures.md), [domain IDs](../../crates/Konclave.DomainCore/src/identifiers.rs). |
| A2A agent/context/tenant/message/artifact IDs / canonical strings at most 128 bytes; gateway task ID / 32 lowercase hex characters | No task/artifact access without caller and route authorization. | Authorized A2A API/card consumers as defined by publication policy; not interchangeable with native IDs. | Exposes tenancy, workflow and correlation. Redact private values; task-ID knowledge is not task ownership. | [A2A mapping](../development/a2a-domain-mapping.md), [A2A compatibility](../protocol/a2a-compatibility.md). |

## Identifier-like values that need stronger protection

| Value / shape | What disclosure can enable | Handling and exposure response | Owning contract |
| --- | --- | --- | --- |
| Relay bearer or enrollment credential / 32 secret bytes, boundary-specific encoding | Bearer replay within its access scope; relay bearer access is still not MLS membership/decryption. | Never log, screenshot or publish. Revoke/replace through the owning authentication control plane; existing static relay grants require removal and reload. Assess relay metadata/abuse separately from MLS membership. | [Relay authentication](../protocol/relay-authentication.md), [enrollment](../protocol/relay-enrollment.md). |
| Complete pairing capability / signed package containing secret material; compact rendezvous token / 16 secret bytes rendered as 26 Crockford Base32 characters | Starts a pairing attempt and derives pairing keys. AccountTrusted can explicitly rely on possession rather than independent identity verification. | Transfer only to the intended peer. Cancel a disclosed active pairing and create a fresh one; inspect whether membership was already committed, because expiry alone does not undo it. | [Pairing capability threat model](../security/threat-model.md#pairing-capabilities), [compact rendezvous](../adr/adr-0023-encrypted-pairing-rendezvous.md). |
| `InvitationNonce` / 32 bytes, unlike public AEAD nonces | Bearer material for an invitation; the signed package also binds the expected device, conversation, role and expiry. | Protect the whole invitation/JoinProof/Welcome handoff, not just its ID. Stop/reconcile the affected ceremony through its owning flow; nonce possession alone does not waive signature/device checks. | [Domain nonce](../../crates/Konclave.DomainCore/src/identifiers.rs), [invitation encoding](../protocol/identity-signatures.md#invitation). |
| Six-digit short pairing code; six-digit SAS / separate values | Code knowledge permits an online OPAQUE attempt, not membership. SAS is a human comparison value, not a reusable credential. | Keep the code within the intended transfer; compare SAS and peer identity independently on both endpoints. Never automate confirmation from a screenshot or matching code. Cancel a suspected raced/substituted attempt. | [Short-code and mutual verification](../adr/adr-0024-opaque-short-code-mutual-verification.md). |
| Hook-private one-use response/work authorization material | May participate in a narrowly bound authorization path; neither an ID nor generic permission to work. | Keep it out of agent arguments, examples and logs. A visible turn-binding marker is not a transferable grant; never copy it into tools or infer authority from it. | [Copilot delivery safety](../development/copilot-delivery-safety.md), [adapter session owner](../../extensions/Konclave.HostExtension/src/adapter/session.ts). |
| Device/service/issuer/session private keys, MLS state, wrapping keys; artifact URL secret fragment | Signing, decryption or access within the affected key/capability scope. Public verification keys and AEAD nonces are different. | Never publish. Follow the key/provider-specific recovery procedure; device-root extraction requires a new device identity and removal of the old one. Renaming an ID or deleting a source key file is not revocation or historical re-encryption. | [Threat model](../security/threat-model.md), [custody](../development/secret-storage.md), [artifact protection](../protocol/a2a-compatibility.md). |

Public signatures, verification keys and AEAD nonces are not private keys, but
complete signed/encrypted records can carry sensitive metadata or secret fields.
Do not dump a whole record just because one of its fields is public. In particular,
`InvitationNonce` is secret-bearing despite the word "nonce".

## Sharing and accidental exposure

For a private support exchange, choose an authenticated recipient and include only
the IDs needed to correlate the issue. For public logs, issues and documentation,
replace live values with consistent placeholders such as `<conversation-id>`,
`<device-id>` and `<request-id>`. Use `<redacted>` for secrets, not a prefix of the
secret. An ordinary unsalted hash of a name or low-entropy code is not anonymization.
Prefer existing bounded diagnostics over exporting a profile database or transcript.

Example: a public screenshot shows `<conversation-id>` and `<request-id>` but no
credentials, capability, private key or message body. That is a metadata disclosure,
not by itself a decryption or membership compromise. Remove or redact the public
copy, assess what other screenshots/logs it can link, and retain the original IDs
privately for exact reconciliation. Do not resend work under new IDs just to hide the
old ones. If the screenshot also contained `<pairing-capability>`, treat that as a
separate active-capability exposure and cancel/reconcile pairing. Removing the
screenshot does not guarantee that other copies disappeared.

## Maintaining this reference

When adding an identifier or changing its derivation, visibility, lifetime,
authorization use, retry scope or logging, update the applicable row in the same
change. Include shape, possession-alone meaning, normal observers, correlation/abuse
risk, exposure response and a current owning source. Group equivalent values, but
keep secret-bearing exceptions separate. Update the threat model or protocol owner
when its guarantee changes; do not expand a guarantee in this table alone.

Reviewers should check these classifications alongside the changed boundary and
state any deployment-dependent or unverified exposure claims. A link checker or green
build verifies neither secrecy nor completeness of this classification.
