import { create } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';

import { decodeApplicationMessage, encodeApplicationMessage } from '../src/application.js';
import {
  bytesEqual,
  bytesKey,
  encodeBounded,
  MAX_APPLICATION_MESSAGE_BYTES,
  MAX_MEMBERS,
  MAX_MLS_KEY_PACKAGE_BYTES,
  MAX_PROTOBUF_TOP_LEVEL_FIELDS,
  MAX_RELAY_PAYLOAD_BYTES,
  MAX_TEXT_BODY_BYTES,
} from '../src/common.js';
import {
  protocolErrorCodes,
  ProtocolValidationError,
  type ProtocolErrorCode,
} from '../src/error.js';
import {
  decodeDeviceCredentialBinding,
  decodeInvitation,
  decodeJoinProof,
  encodeDeviceCredentialBinding,
  encodeInvitation,
  encodeJoinProof,
} from '../src/identity.js';
import {
  decodeConversationState,
  decodeMembershipCommitBundle,
  decodeMembershipControl,
  decodeMembershipChange,
  encodeConversationState,
  encodeMembershipCommitBundle,
  encodeMembershipControl,
  encodeMembershipChange,
} from '../src/membership.js';
import {
  decodeAcknowledgeRequest,
  decodeRelayEnvelope,
  decodeReplayPage,
  decodeReplayRequest,
  decodeStoredRelayEnvelope,
  encodeAcknowledgeRequest,
  encodeRelayEnvelope,
  encodeReplayPage,
  encodeReplayRequest,
  encodeStoredRelayEnvelope,
} from '../src/relay.js';
import { ConversationRole } from '../src/generated/konclave/protocol/v1/common_pb.js';
import {
  ApplicationMessageSchema,
  TextContentSchema,
} from '../src/generated/konclave/protocol/v1/application_pb.js';
import { DeviceCredentialBindingSchema } from '../src/generated/konclave/protocol/v1/identity_pb.js';
import { MembershipControlSchema } from '../src/generated/konclave/protocol/v1/membership_pb.js';
import { DeliveryClass } from '../src/generated/konclave/protocol/v1/relay_pb.js';
import {
  acknowledgment,
  applicationMessage,
  bytes,
  conversationState,
  credential,
  invitation,
  joinProof,
  membershipChange,
  relayEnvelope,
  replayPage,
  replayRequest,
  storedEnvelope,
} from './messages.js';

function expectCode(action: () => unknown, code: ProtocolErrorCode): void {
  try {
    action();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(ProtocolValidationError);
    if (error instanceof ProtocolValidationError) {
      expect(error.code).toBe(code);
      return;
    }
  }
  throw new Error(`expected protocol error ${code}`);
}

describe('application contracts', () => {
  it('round trips a valid application message', () => {
    const value = applicationMessage({ replyToLength: 16 });
    expect(
      encodeApplicationMessage(decodeApplicationMessage(encodeApplicationMessage(value))),
    ).toEqual(encodeApplicationMessage(value));
  });

  it('safely ignores an additive field from a newer writer', () => {
    const extended = Uint8Array.from([
      ...encodeApplicationMessage(applicationMessage()),
      0x98,
      0x06,
      0x01,
    ]);
    expect(decodeApplicationMessage(extended).content.case).toBe('text');
  });

  it('rejects top-level field-count amplification before decoding', () => {
    expectCode(
      () =>
        decodeApplicationMessage(
          Uint8Array.from({ length: (MAX_PROTOBUF_TOP_LEVEL_FIELDS + 1) * 2 }, (_, index) =>
            index % 2 === 0 ? 0x78 : 0x00,
          ),
        ),
      protocolErrorCodes.outOfRange,
    );
  });

  it('rejects malformed, oversized, incomplete, and unsupported messages', () => {
    expectCode(() => decodeApplicationMessage(Uint8Array.of(0x80)), protocolErrorCodes.malformed);
    expectCode(
      () => decodeApplicationMessage(Uint8Array.of(0x52, 0x03, 0x0a, 0x01, 0xff)),
      protocolErrorCodes.malformed,
    );
    expectCode(
      () => decodeApplicationMessage(new Uint8Array(MAX_APPLICATION_MESSAGE_BYTES + 1)),
      protocolErrorCodes.encodedMessageTooLarge,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ major: 2 })),
      protocolErrorCodes.unsupportedMajor,
    );
    expectCode(
      () =>
        encodeApplicationMessage(
          create(ApplicationMessageSchema, {
            ...applicationMessage(),
            messageId: undefined,
          }),
        ),
      protocolErrorCodes.missingField,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ messageIdLength: 15 })),
      protocolErrorCodes.invalidLength,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ senderCounter: 0n })),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () =>
        encodeApplicationMessage(
          applicationMessage({
            senderCounter: 18_446_744_073_709_551_616n,
          }),
        ),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ sentAt: -1n })),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ replyToLength: 15 })),
      protocolErrorCodes.invalidLength,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ withContent: false })),
      protocolErrorCodes.missingVariant,
    );
    expectCode(
      () => encodeApplicationMessage(applicationMessage({ body: '' })),
      protocolErrorCodes.emptyValue,
    );
    expectCode(
      () =>
        encodeApplicationMessage(applicationMessage({ body: 'x'.repeat(MAX_TEXT_BODY_BYTES + 1) })),
      protocolErrorCodes.outOfRange,
    );
  });
});

describe('identity contracts', () => {
  it('round trips credential, invitation, and join proof contracts', () => {
    const credentialBytes = encodeDeviceCredentialBinding(credential());
    expect(encodeDeviceCredentialBinding(decodeDeviceCredentialBinding(credentialBytes))).toEqual(
      credentialBytes,
    );

    const invitationBytes = encodeInvitation(invitation());
    expect(encodeInvitation(decodeInvitation(invitationBytes))).toEqual(invitationBytes);

    const proofBytes = encodeJoinProof(joinProof());
    expect(encodeJoinProof(decodeJoinProof(proofBytes))).toEqual(proofBytes);
  });

  it('rejects invalid credential, invitation, and join proof shapes', () => {
    expectCode(
      () => encodeDeviceCredentialBinding(credential({ deviceIdLength: 31 })),
      protocolErrorCodes.invalidLength,
    );
    expectCode(
      () => encodeDeviceCredentialBinding(credential({ signatureLength: 63 })),
      protocolErrorCodes.invalidLength,
    );
    const unspecifiedCredential = create(DeviceCredentialBindingSchema, {
      ...credential(),
      signatureScheme: 0,
    });
    expectCode(
      () => encodeDeviceCredentialBinding(unspecifiedCredential),
      protocolErrorCodes.unsupportedEnum,
    );
    expectCode(
      () => encodeInvitation(invitation({ nonceLength: 31 })),
      protocolErrorCodes.invalidLength,
    );
    expectCode(
      () => encodeInvitation(invitation({ routingLength: 31 })),
      protocolErrorCodes.invalidLength,
    );
    expectCode(
      () => encodeInvitation(invitation({ role: ConversationRole.UNSPECIFIED })),
      protocolErrorCodes.unsupportedEnum,
    );
    expectCode(
      () => encodeJoinProof(joinProof({ expectedDevice: 1, credentialDevice: 2 })),
      protocolErrorCodes.mismatchedInvitedDevice,
    );
    expectCode(
      () => encodeJoinProof(joinProof({ credentialConversation: 7 })),
      protocolErrorCodes.mismatchedInvitedConversation,
    );
    expectCode(
      () => encodeJoinProof(joinProof({ keyPackageLength: 0 })),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => encodeJoinProof(joinProof({ keyPackageLength: MAX_MLS_KEY_PACKAGE_BYTES + 1 })),
      protocolErrorCodes.outOfRange,
    );
  });
});

describe('membership contracts', () => {
  it('round trips state and every membership transition variant', () => {
    const stateBytes = encodeConversationState(conversationState());
    expect(encodeConversationState(decodeConversationState(stateBytes))).toEqual(stateBytes);

    for (const variant of ['add', 'remove', 'changeRole'] as const) {
      const bytes = encodeMembershipChange(membershipChange(variant));
      expect(encodeMembershipChange(decodeMembershipChange(bytes))).toEqual(bytes);
    }

    const control = encodeMembershipControl(membershipChange(), joinProof());
    const decodedControl = decodeMembershipControl(control);
    expect(
      encodeMembershipControl(decodedControl.membershipChange, decodedControl.joinProof),
    ).toEqual(control);
    const controlWithoutProof = encodeMembershipControl(membershipChange('remove'));
    expect(decodeMembershipControl(controlWithoutProof).joinProof).toBeUndefined();

    const bundle = encodeMembershipCommitBundle(bytes(32, 0x81), bytes(48, 0x82));
    const decodedBundle = decodeMembershipCommitBundle(bundle);
    expect(
      encodeMembershipCommitBundle(decodedBundle.encryptedControl, decodedBundle.mlsCommit),
    ).toEqual(bundle);
  });

  it('rejects invalid state and absent transition variants', () => {
    expectCode(
      () => encodeConversationState(conversationState({ memberCount: 0 })),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => encodeConversationState(conversationState({ memberCount: MAX_MEMBERS + 1 })),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => encodeConversationState(conversationState({ duplicateMember: true })),
      protocolErrorCodes.duplicateIdentifier,
    );
    expectCode(
      () => encodeConversationState(conversationState({ futureMember: true })),
      protocolErrorCodes.memberJoinedAfterStateEpoch,
    );
    expectCode(
      () => encodeConversationState(conversationState({ includeAdministrator: false })),
      protocolErrorCodes.missingAdministrator,
    );
    expectCode(
      () => encodeConversationState(conversationState({ duplicateInvitation: true })),
      protocolErrorCodes.duplicateIdentifier,
    );
    expectCode(
      () => encodeMembershipChange(membershipChange('none')),
      protocolErrorCodes.missingVariant,
    );
    expectCode(
      () => encodeMembershipCommitBundle(new Uint8Array(), bytes(1, 1)),
      protocolErrorCodes.missingField,
    );
    const missingControl = encodeBounded(
      MembershipControlSchema,
      create(MembershipControlSchema),
      MAX_APPLICATION_MESSAGE_BYTES,
      'MembershipControl',
    );
    expectCode(() => decodeMembershipControl(missingControl), protocolErrorCodes.missingField);
    expectCode(
      () => encodeMembershipCommitBundle(bytes(MAX_RELAY_PAYLOAD_BYTES, 1), bytes(1, 1)),
      protocolErrorCodes.encodedMessageTooLarge,
    );
  });

  it('bounds repeated fields before generated messages are materialized', () => {
    expectCode(
      () =>
        decodeConversationState(
          Uint8Array.from({ length: (MAX_MEMBERS + 1) * 2 }, (_, index) =>
            index % 2 === 0 ? 0x22 : 0x00,
          ),
        ),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => decodeConversationState(Uint8Array.of(0x22, 0x80)),
      protocolErrorCodes.malformed,
    );
    expectCode(
      () => decodeConversationState(Uint8Array.of(0x7b, 0x7c)),
      protocolErrorCodes.malformed,
    );
  });
});

describe('relay contracts', () => {
  it('round trips every relay request and response contract', () => {
    const relayBytes = encodeRelayEnvelope(relayEnvelope());
    expect(encodeRelayEnvelope(decodeRelayEnvelope(relayBytes))).toEqual(relayBytes);

    const storedBytes = encodeStoredRelayEnvelope(storedEnvelope());
    expect(encodeStoredRelayEnvelope(decodeStoredRelayEnvelope(storedBytes))).toEqual(storedBytes);

    const requestBytes = encodeReplayRequest(replayRequest());
    expect(encodeReplayRequest(decodeReplayRequest(requestBytes))).toEqual(requestBytes);

    const pageBytes = encodeReplayPage(replayPage());
    expect(encodeReplayPage(decodeReplayPage(pageBytes))).toEqual(pageBytes);

    const acknowledgmentBytes = encodeAcknowledgeRequest(acknowledgment());
    expect(encodeAcknowledgeRequest(decodeAcknowledgeRequest(acknowledgmentBytes))).toEqual(
      acknowledgmentBytes,
    );
  });

  it('enforces relay metadata and payload bounds', () => {
    expect(
      encodeRelayEnvelope(
        relayEnvelope({
          deliveryClass: DeliveryClass.GROUP_PROPOSAL,
          expectedParentEpoch: 2n,
        }),
      ),
    ).toBeInstanceOf(Uint8Array);
    expect(
      encodeRelayEnvelope(
        relayEnvelope({
          deliveryClass: DeliveryClass.GROUP_COMMIT,
          expectedParentEpoch: 2n,
        }),
      ),
    ).toBeInstanceOf(Uint8Array);
    expectCode(
      () => encodeRelayEnvelope(relayEnvelope({ deliveryClass: DeliveryClass.UNSPECIFIED })),
      protocolErrorCodes.unsupportedEnum,
    );
    const unknownDeliveryClass = encodeRelayEnvelope(relayEnvelope());
    const deliveryClassOffset = unknownDeliveryClass.findIndex(
      (value, index) =>
        value === 0x20 && unknownDeliveryClass[index + 1] === DeliveryClass.GROUP_APPLICATION,
    );
    if (deliveryClassOffset < 0) {
      throw new Error('relay fixture does not contain its delivery class');
    }
    unknownDeliveryClass[deliveryClassOffset + 1] = 6;
    expectCode(() => decodeRelayEnvelope(unknownDeliveryClass), protocolErrorCodes.unsupportedEnum);
    expectCode(
      () =>
        encodeRelayEnvelope(
          relayEnvelope({
            deliveryClass: DeliveryClass.GROUP_COMMIT,
          }),
        ),
      protocolErrorCodes.invalidExpectedParentEpoch,
    );
    expectCode(
      () =>
        encodeRelayEnvelope(
          relayEnvelope({
            deliveryClass: DeliveryClass.GROUP_APPLICATION,
            expectedParentEpoch: 2n,
          }),
        ),
      protocolErrorCodes.invalidExpectedParentEpoch,
    );
    expectCode(
      () => encodeRelayEnvelope(relayEnvelope({ payloadLength: 0 })),
      protocolErrorCodes.outOfRange,
    );
    expectCode(
      () => encodeRelayEnvelope(relayEnvelope({ payloadLength: MAX_RELAY_PAYLOAD_BYTES + 1 })),
      protocolErrorCodes.outOfRange,
    );
  });

  it('enforces cursor, replay limit, and replay ordering invariants', () => {
    expectCode(() => encodeStoredRelayEnvelope(storedEnvelope(0n)), protocolErrorCodes.outOfRange);
    expectCode(
      () => encodeReplayRequest(replayRequest({ afterCursor: -1n })),
      protocolErrorCodes.outOfRange,
    );
    for (const limit of [0, 101, 1.5]) {
      expectCode(
        () => encodeReplayRequest(replayRequest({ limit })),
        protocolErrorCodes.outOfRange,
      );
    }
    expectCode(
      () => encodeReplayPage(replayPage({ cursors: [2n, 2n] })),
      protocolErrorCodes.invalidReplayOrder,
    );
    expectCode(
      () => encodeReplayPage(replayPage({ cursors: [2n], nextCursor: 1n })),
      protocolErrorCodes.invalidReplayOrder,
    );
    expect(encodeReplayPage(replayPage({ cursors: [] }))).toBeInstanceOf(Uint8Array);
    expectCode(() => encodeAcknowledgeRequest(acknowledgment(0n)), protocolErrorCodes.outOfRange);
  });

  it('bounds replay entries before generated messages are materialized', () => {
    expectCode(
      () =>
        decodeReplayPage(
          Uint8Array.from({ length: (100 + 1) * 2 }, (_, index) => (index % 2 === 0 ? 0x0a : 0x00)),
        ),
      protocolErrorCodes.outOfRange,
    );
  });
});

describe('shared contract guards', () => {
  it('compares and keys bytes deterministically', () => {
    expect(bytesEqual(bytes(2, 1), bytes(2, 1))).toBe(true);
    expect(bytesEqual(bytes(2, 1), bytes(3, 1))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(bytesKey(Uint8Array.of(65, 66))).toBe('AB');
  });

  it('rejects an encoded result beyond a caller-provided bound', () => {
    const value = create(TextContentSchema, { body: 'too large' });
    expectCode(
      () => encodeBounded(TextContentSchema, value, 1, 'TextContent'),
      protocolErrorCodes.encodedMessageTooLarge,
    );
  });
});
