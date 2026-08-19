# Identity signature encodings

This document is the canonical owner of the byte encodings signed or hashed by
Konclave protocol v1 device identities and invitations.

All integers use unsigned big-endian encoding. Fixed-size fields have no length
prefix. Domain separators include the trailing zero byte shown as `\0`.

## Device identifier

The protocol v1 `DeviceId` is:

```text
SHA-256(
  "konclave-device-id-v1\0" ||
  device_root_public_key[32]
)
```

The public key is the raw 32-byte Ed25519 verification key.

## Conversation credential binding

The device root signs this exact byte sequence:

```text
"konclave-device-credential-binding-v1\0" ||
protocol_major_u32 ||
protocol_minor_u32 ||
device_id[32] ||
conversation_id[32] ||
signature_scheme_u8 ||
device_root_public_key[32] ||
conversation_signature_public_key[32]
```

`signature_scheme_u8` is `1` for Ed25519. The resulting signature is the 64-byte
`device_binding_signature`.

Membership authorization identifies the exact binding with:

```text
SHA-256(
  "konclave-device-credential-binding-hash-v1\0" ||
  credential_binding_signature_input ||
  device_binding_signature[64]
)
```

Validation derives `DeviceId` from the included root key, verifies the device-root
signature, requires the conversation identifier to match the MLS group, and requires
the MLS leaf signature key to equal the bound conversation key.

## Invitation

The issuer device root signs:

```text
"konclave-invitation-v1\0" ||
protocol_major_u32 ||
protocol_minor_u32 ||
invitation_id[16] ||
conversation_id[32] ||
expected_device_id[32] ||
conversation_role_u8 ||
expires_at_unix_seconds_u64 ||
nonce[32] ||
issuer_device_id[32]
```

`conversation_role_u8` is `1` for administrator and `2` for member. An invitation is
expired when the current Unix time is greater than or equal to its expiration value.
Cryptographic validity does not establish administrator authorization or single-use
consumption; authenticated conversation policy enforces both.

## MLS credential relationship

The MLS BasicCredential identifier is exactly the 32-byte `DeviceId`. Konclave does
not rely on the library's basic identity provider for trust. Before an add Commit is
created or applied, every client verifies the external device binding and requires
the KeyPackage signing key, BasicCredential identifier, invitation, membership
authorization, and Add proposal to agree.

Every membership Commit carries this digest in MLS authenticated data:

```text
SHA-256(
  "konclave-membership-authorization-v1\0" ||
  canonical_membership_change_protobuf
)
```

Existing members recompute the digest from the independently delivered authorization
before committing candidate group state. This binds the operation identifier, parent
epoch, role, invitation, and credential hash to the encrypted MLS proposals without
exposing membership data in relay-visible authenticated data.

An add Commit also places the resulting canonical `ConversationState` protobuf in the
encrypted Welcome GroupInfo extension type `0xff00`. A joining client derives state
from that signed and encrypted extension, then requires its role, consumed invitation,
MLS roster, epoch, and every registered credential binding to agree. It never accepts
relay-supplied role state as an unauthenticated side input.

Every group epoch also carries extension type `0xff01` in the MLS GroupContext:

```text
SHA-256(
  "konclave-conversation-state-v1\0" ||
  canonical_conversation_state_protobuf
)
```

Application rules require each membership Commit to replace this digest with the
authorized next-state digest. The joining client compares the signed GroupContext
digest with the encrypted full-state extension, preventing a committer from presenting
new members with role state that existing members did not authorize.
