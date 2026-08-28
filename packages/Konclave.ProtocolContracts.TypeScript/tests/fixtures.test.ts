import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { decodeApplicationMessage, encodeApplicationMessage } from '../src/application.js';
import {
  decodeCollaborationPolicyBundle,
  encodeCollaborationPolicyBundle,
} from '../src/collaboration-policy.js';
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
import {
  acknowledgment,
  applicationMessage,
  collaborationPolicyBundle,
  conversationState,
  credential,
  invitation,
  joinProof,
  membershipCommitBundle,
  membershipChange,
  relayEnvelope,
  replayPage,
  replayRequest,
  storedEnvelope,
} from './messages.js';

const fixture = (name: string): Uint8Array =>
  Uint8Array.from(readFileSync(new URL(`../../../fixtures/protocol/v1/${name}`, import.meta.url)));

const cases: ReadonlyArray<{
  decode: (bytes: Uint8Array) => unknown;
  expected: unknown;
  name: string;
  roundTrip: (bytes: Uint8Array) => Uint8Array;
}> = [
  {
    decode: decodeApplicationMessage,
    expected: applicationMessage({ replyToLength: 16 }),
    name: 'application-message.bin',
    roundTrip: (bytes) => encodeApplicationMessage(decodeApplicationMessage(bytes)),
  },
  {
    decode: decodeCollaborationPolicyBundle,
    expected: collaborationPolicyBundle(),
    name: 'collaboration-policy-bundle.bin',
    roundTrip: (bytes) => encodeCollaborationPolicyBundle(decodeCollaborationPolicyBundle(bytes)),
  },
  {
    decode: decodeDeviceCredentialBinding,
    expected: credential(),
    name: 'device-credential-binding.bin',
    roundTrip: (bytes) => encodeDeviceCredentialBinding(decodeDeviceCredentialBinding(bytes)),
  },
  {
    decode: decodeInvitation,
    expected: invitation(),
    name: 'invitation.bin',
    roundTrip: (bytes) => encodeInvitation(decodeInvitation(bytes)),
  },
  {
    decode: decodeInvitation,
    expected: invitation({ routingLength: 32 }),
    name: 'route-bound-invitation.bin',
    roundTrip: (bytes) => encodeInvitation(decodeInvitation(bytes)),
  },
  {
    decode: decodeJoinProof,
    expected: joinProof(),
    name: 'join-proof.bin',
    roundTrip: (bytes) => encodeJoinProof(decodeJoinProof(bytes)),
  },
  {
    decode: decodeConversationState,
    expected: conversationState(),
    name: 'conversation-state.bin',
    roundTrip: (bytes) => encodeConversationState(decodeConversationState(bytes)),
  },
  {
    decode: decodeMembershipChange,
    expected: membershipChange(),
    name: 'membership-change.bin',
    roundTrip: (bytes) => encodeMembershipChange(decodeMembershipChange(bytes)),
  },
  {
    decode: decodeMembershipControl,
    expected: {
      joinProof: joinProof(),
      membershipChange: membershipChange(),
    },
    name: 'membership-control.bin',
    roundTrip: (bytes) => {
      const value = decodeMembershipControl(bytes);
      return encodeMembershipControl(value.membershipChange, value.joinProof);
    },
  },
  {
    decode: decodeMembershipCommitBundle,
    expected: membershipCommitBundle(),
    name: 'membership-commit-bundle.bin',
    roundTrip: (bytes) => {
      const value = decodeMembershipCommitBundle(bytes);
      return encodeMembershipCommitBundle(value.encryptedControl, value.mlsCommit);
    },
  },
  {
    decode: decodeRelayEnvelope,
    expected: relayEnvelope(),
    name: 'relay-envelope.bin',
    roundTrip: (bytes) => encodeRelayEnvelope(decodeRelayEnvelope(bytes)),
  },
  {
    decode: decodeStoredRelayEnvelope,
    expected: storedEnvelope(),
    name: 'stored-relay-envelope.bin',
    roundTrip: (bytes) => encodeStoredRelayEnvelope(decodeStoredRelayEnvelope(bytes)),
  },
  {
    decode: decodeReplayRequest,
    expected: replayRequest(),
    name: 'replay-request.bin',
    roundTrip: (bytes) => encodeReplayRequest(decodeReplayRequest(bytes)),
  },
  {
    decode: decodeReplayPage,
    expected: replayPage(),
    name: 'replay-page.bin',
    roundTrip: (bytes) => encodeReplayPage(decodeReplayPage(bytes)),
  },
  {
    decode: decodeAcknowledgeRequest,
    expected: acknowledgment(),
    name: 'acknowledge-request.bin',
    roundTrip: (bytes) => encodeAcknowledgeRequest(decodeAcknowledgeRequest(bytes)),
  },
];

describe('immutable Rust-generated protocol v1 fixtures', () => {
  for (const fixtureCase of cases) {
    it(`round trips ${fixtureCase.name} byte for byte`, () => {
      const bytes = fixture(fixtureCase.name);
      expect(fixtureCase.decode(bytes)).toEqual(fixtureCase.expected);
      expect(fixtureCase.roundTrip(bytes)).toEqual(bytes);
    });
  }
});
