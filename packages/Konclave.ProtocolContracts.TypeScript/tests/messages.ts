import { create } from '@bufbuild/protobuf';

import {
  ApplicationMessageSchema,
  TextContentSchema,
  type ApplicationMessage,
} from '../src/generated/konclave/protocol/v1/application_pb.js';
import {
  ConversationIdSchema,
  ConversationRole,
  DeviceIdSchema,
  EnvelopeIdSchema,
  InvitationIdSchema,
  MessageIdSchema,
  ProtocolVersionSchema,
  RoutingIdSchema,
} from '../src/generated/konclave/protocol/v1/common_pb.js';
import {
  DeviceCredentialBindingSchema,
  InvitationSchema,
  JoinProofSchema,
  SignatureScheme,
  type DeviceCredentialBinding,
  type Invitation,
  type JoinProof,
} from '../src/generated/konclave/protocol/v1/identity_pb.js';
import {
  EnrollmentRequestIdSchema,
  RelayEnrollmentOutcome,
  RelayEnrollmentRequestSchema,
  RelayEnrollmentResponseSchema,
  RelayPrincipalIdSchema,
  type RelayEnrollmentRequest,
  type RelayEnrollmentResponse,
} from '../src/generated/konclave/protocol/v1/enrollment_pb.js';
import {
  AddMemberSchema,
  ChangeMemberRoleSchema,
  ConversationStateSchema,
  MemberSchema,
  MembershipCommitBundleSchema,
  MembershipChangeSchema,
  MembershipOperationIdSchema,
  RemoveMemberSchema,
  type ConversationState,
  type MembershipCommitBundle,
  type MembershipChange,
} from '../src/generated/konclave/protocol/v1/membership_pb.js';
import {
  AcknowledgeRequestSchema,
  DeliveryClass,
  RelayEnvelopeSchema,
  ReplayPageSchema,
  ReplayRequestSchema,
  StoredRelayEnvelopeSchema,
  type AcknowledgeRequest,
  type RelayEnvelope,
  type ReplayPage,
  type ReplayRequest,
  type StoredRelayEnvelope,
} from '../src/generated/konclave/protocol/v1/relay_pb.js';

export const bytes = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

export function enrollmentRequest(options?: {
  major?: number;
  requestIdLength?: number;
  principalIdLength?: number;
}): RelayEnrollmentRequest {
  return create(RelayEnrollmentRequestSchema, {
    version: create(ProtocolVersionSchema, {
      major: options?.major ?? 1,
      minor: 0,
    }),
    requestId: create(EnrollmentRequestIdSchema, {
      value: bytes(options?.requestIdLength ?? 16, 0x91),
    }),
    principalId: create(RelayPrincipalIdSchema, {
      value: bytes(options?.principalIdLength ?? 32, 0x92),
    }),
  });
}

export function enrollmentResponse(options?: {
  outcome?: RelayEnrollmentOutcome;
}): RelayEnrollmentResponse {
  const request = enrollmentRequest();
  return create(RelayEnrollmentResponseSchema, {
    version: request.version,
    requestId: request.requestId,
    principalId: request.principalId,
    outcome: options?.outcome ?? RelayEnrollmentOutcome.REGISTERED,
  });
}

export function membershipCommitBundle(): MembershipCommitBundle {
  return create(MembershipCommitBundleSchema, {
    encryptedControl: bytes(32, 0x81),
    mlsCommit: bytes(48, 0x82),
  });
}

export function applicationMessage(options?: {
  body?: string;
  major?: number;
  messageIdLength?: number;
  replyToLength?: number;
  senderCounter?: bigint;
  sentAt?: bigint;
  withContent?: boolean;
}): ApplicationMessage {
  return create(ApplicationMessageSchema, {
    version: create(ProtocolVersionSchema, {
      major: options?.major ?? 1,
      minor: 0,
    }),
    messageId: create(MessageIdSchema, {
      value: bytes(options?.messageIdLength ?? 16, 1),
    }),
    senderCounter: options?.senderCounter ?? 1n,
    sentAtUnixMilliseconds: options?.sentAt ?? 1_700_000_000_000n,
    replyTo:
      options?.replyToLength === undefined
        ? undefined
        : create(MessageIdSchema, {
            value: bytes(options.replyToLength, 2),
          }),
    content:
      options?.withContent === false
        ? { case: undefined }
        : {
            case: 'text',
            value: create(TextContentSchema, {
              body: options?.body ?? 'hello',
            }),
          },
  });
}

export function credential(options?: {
  conversation?: number;
  device?: number;
  deviceIdLength?: number;
  major?: number;
  signatureLength?: number;
}): DeviceCredentialBinding {
  return create(DeviceCredentialBindingSchema, {
    version: create(ProtocolVersionSchema, {
      major: options?.major ?? 1,
      minor: 0,
    }),
    deviceId: create(DeviceIdSchema, {
      value: bytes(options?.deviceIdLength ?? 32, options?.device ?? 1),
    }),
    conversationId: create(ConversationIdSchema, {
      value: bytes(32, options?.conversation ?? 6),
    }),
    signatureScheme: SignatureScheme.ED25519,
    deviceRootPublicKey: bytes(32, 2),
    conversationSignaturePublicKey: bytes(32, 3),
    deviceBindingSignature: bytes(options?.signatureLength ?? 64, 4),
  });
}

export function invitation(options?: {
  expectedDevice?: number;
  major?: number;
  nonceLength?: number;
  routingLength?: number;
  role?: ConversationRole;
}): Invitation {
  return create(InvitationSchema, {
    version: create(ProtocolVersionSchema, {
      major: options?.major ?? 1,
      minor: 0,
    }),
    invitationId: create(InvitationIdSchema, { value: bytes(16, 5) }),
    conversationId: create(ConversationIdSchema, { value: bytes(32, 6) }),
    routingId:
      options?.routingLength === undefined
        ? undefined
        : create(RoutingIdSchema, { value: bytes(options.routingLength, 10) }),
    expectedDeviceId: create(DeviceIdSchema, {
      value: bytes(32, options?.expectedDevice ?? 1),
    }),
    role: options?.role ?? ConversationRole.MEMBER,
    expiresAtUnixSeconds: 1_800_000_000n,
    nonce: bytes(options?.nonceLength ?? 32, 7),
    issuerDeviceId: create(DeviceIdSchema, { value: bytes(32, 8) }),
    issuerSignature: bytes(64, 9),
  });
}

export function joinProof(options?: {
  credentialConversation?: number;
  credentialDevice?: number;
  expectedDevice?: number;
  keyPackageLength?: number;
}): JoinProof {
  return create(JoinProofSchema, {
    invitation: invitation({ expectedDevice: options?.expectedDevice }),
    credential: credential({
      conversation: options?.credentialConversation,
      device: options?.credentialDevice,
    }),
    mlsKeyPackage: bytes(options?.keyPackageLength ?? 32, 10),
  });
}

export function conversationState(options?: {
  duplicateInvitation?: boolean;
  duplicateMember?: boolean;
  futureMember?: boolean;
  includeAdministrator?: boolean;
  memberCount?: number;
}): ConversationState {
  const count = options?.memberCount ?? 2;
  const members = Array.from({ length: count }, (_, index) =>
    create(MemberSchema, {
      deviceId: create(DeviceIdSchema, {
        value: bytes(32, options?.duplicateMember === true ? 1 : index + 1),
      }),
      role:
        index === 0 && options?.includeAdministrator !== false
          ? ConversationRole.ADMINISTRATOR
          : ConversationRole.MEMBER,
      joinedEpoch: options?.futureMember === true && index === 0 ? 3n : BigInt(index),
    }),
  );
  return create(ConversationStateSchema, {
    version: create(ProtocolVersionSchema, { major: 1, minor: 0 }),
    conversationId: create(ConversationIdSchema, { value: bytes(32, 20) }),
    epoch: 2n,
    members,
    consumedInvitationIds: [
      create(InvitationIdSchema, { value: bytes(16, 21) }),
      create(InvitationIdSchema, {
        value: bytes(16, options?.duplicateInvitation === true ? 21 : 22),
      }),
    ],
  });
}

export function membershipChange(
  change: 'add' | 'remove' | 'changeRole' | 'none' = 'add',
): MembershipChange {
  const base = {
    version: create(ProtocolVersionSchema, { major: 1, minor: 0 }),
    conversationId: create(ConversationIdSchema, { value: bytes(32, 30) }),
    parentEpoch: 2n,
    operationId: create(MembershipOperationIdSchema, {
      value: bytes(16, 31),
    }),
  };
  switch (change) {
    case 'add':
      return create(MembershipChangeSchema, {
        ...base,
        change: {
          case: 'add',
          value: create(AddMemberSchema, {
            deviceId: create(DeviceIdSchema, { value: bytes(32, 32) }),
            role: ConversationRole.MEMBER,
            invitationId: create(InvitationIdSchema, {
              value: bytes(16, 33),
            }),
            credentialBindingHash: bytes(32, 34),
          }),
        },
      });
    case 'remove':
      return create(MembershipChangeSchema, {
        ...base,
        change: {
          case: 'remove',
          value: create(RemoveMemberSchema, {
            deviceId: create(DeviceIdSchema, { value: bytes(32, 32) }),
          }),
        },
      });
    case 'changeRole':
      return create(MembershipChangeSchema, {
        ...base,
        change: {
          case: 'changeRole',
          value: create(ChangeMemberRoleSchema, {
            deviceId: create(DeviceIdSchema, { value: bytes(32, 32) }),
            role: ConversationRole.ADMINISTRATOR,
          }),
        },
      });
    case 'none':
      return create(MembershipChangeSchema, {
        ...base,
        change: { case: undefined },
      });
  }
}

export function relayEnvelope(options?: {
  deliveryClass?: DeliveryClass;
  envelope?: number;
  expectedParentEpoch?: bigint;
  payloadLength?: number;
}): RelayEnvelope {
  return create(RelayEnvelopeSchema, {
    version: create(ProtocolVersionSchema, { major: 1, minor: 0 }),
    routingId: create(RoutingIdSchema, { value: bytes(32, 40) }),
    envelopeId: create(EnvelopeIdSchema, {
      value: bytes(16, options?.envelope ?? 41),
    }),
    deliveryClass: options?.deliveryClass ?? DeliveryClass.GROUP_APPLICATION,
    expectedParentEpoch: options?.expectedParentEpoch,
    expiresAtUnixSeconds: 1_800_000_000n,
    payload: bytes(options?.payloadLength ?? 32, 42),
  });
}

export function storedEnvelope(cursor = 1n, envelope = 41): StoredRelayEnvelope {
  return create(StoredRelayEnvelopeSchema, {
    envelope: relayEnvelope({ envelope }),
    cursor,
  });
}

export function replayRequest(options?: { afterCursor?: bigint; limit?: number }): ReplayRequest {
  return create(ReplayRequestSchema, {
    routingId: create(RoutingIdSchema, { value: bytes(32, 40) }),
    afterCursor: options?.afterCursor ?? 0n,
    limit: options?.limit ?? 100,
  });
}

export function replayPage(options?: { cursors?: bigint[]; nextCursor?: bigint }): ReplayPage {
  const cursors = options?.cursors ?? [1n, 2n];
  return create(ReplayPageSchema, {
    envelopes: cursors.map((cursor, index) => storedEnvelope(cursor, 41 + index)),
    nextCursor: options?.nextCursor ?? cursors.at(-1) ?? 0n,
    hasMore: false,
  });
}

export function acknowledgment(cursor = 2n): AcknowledgeRequest {
  return create(AcknowledgeRequestSchema, {
    routingId: create(RoutingIdSchema, { value: bytes(32, 40) }),
    cursor,
  });
}
