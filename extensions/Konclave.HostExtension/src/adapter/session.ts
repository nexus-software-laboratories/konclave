/**
 * Bounded session operations for an authenticated adapter channel.
 *
 * Mirrors the Rust implementation exactly, including every bound, so a request this
 * side considers valid is not rejected at the other end.
 */

import { Reader } from './frame.js';

/** Byte length of a notification identifier. */
export const notificationIdLength = 16;

/** Byte length of a conversation or device identifier. */
export const routedIdLength = 32;

/** Largest batch an adapter may request in one wait. */
export const maxClaimBatch = 50;

/** Longest bounded wait an adapter may request, in milliseconds. */
export const maxWaitMilliseconds = 60_000;

/** Largest accepted application text in a delivered event. */
export const maxEventTextBytes = 64 * 1024;

const kindWaitAndClaim = 16;
const kindAcknowledge = 17;
const kindRelease = 18;
const kindStatus = 19;

const kindBatch = 32;
const kindAccepted = 33;
const kindStatusReport = 34;
const kindFailure = 35;

const eventApplicationMessage = 1;
const eventMemberAdded = 2;
const eventMemberRemoved = 3;
const eventMemberRoleChanged = 4;
const eventLocalAccessRemoved = 5;

const roleAdministrator = 1;
const roleMember = 2;

const maxFailureCodeLength = 64;
const failureCodePattern = /^[a-z0-9_-]+$/;

export type DeliveredRole = 'administrator' | 'member';

export type DeliveredPayload =
  | { readonly kind: 'application-text'; readonly text: string }
  | { readonly kind: 'member-added'; readonly device: Buffer; readonly role: DeliveredRole }
  | { readonly kind: 'member-removed'; readonly device: Buffer }
  | { readonly kind: 'member-role-changed'; readonly device: Buffer; readonly role: DeliveredRole }
  | { readonly kind: 'local-access-removed'; readonly device: Buffer };

export interface DeliveredEvent {
  readonly notificationId: Buffer;
  readonly leaseGeneration: number;
  readonly sequence: number;
  readonly conversation: Buffer;
  readonly sender: Buffer;
  readonly relayCursor: number;
  readonly payload: DeliveredPayload;
}

export type AdapterRequest =
  | {
      readonly kind: 'wait-and-claim';
      readonly maxEvents: number;
      readonly waitMilliseconds: number;
    }
  | {
      readonly kind: 'acknowledge';
      readonly notificationId: Buffer;
      readonly leaseGeneration: number;
    }
  | { readonly kind: 'release'; readonly notificationId: Buffer; readonly leaseGeneration: number }
  | { readonly kind: 'status' };

export interface AdapterStatus {
  readonly pendingEvents: number;
  readonly claimedEvents: number;
  readonly watchedConversations: number;
  readonly deliveryDegraded: boolean;
}

export type AdapterResponse =
  | { readonly kind: 'batch'; readonly events: readonly DeliveredEvent[] }
  | { readonly kind: 'accepted' }
  | { readonly kind: 'status'; readonly status: AdapterStatus }
  | { readonly kind: 'failure'; readonly code: string };

/**
 * Encodes a request.
 *
 * @throws when a bound is exceeded, so an invalid request fails here rather than
 * being rejected after a round trip.
 */
export function encodeAdapterRequest(request: AdapterRequest): Buffer {
  switch (request.kind) {
    case 'wait-and-claim': {
      if (
        !Number.isInteger(request.maxEvents) ||
        request.maxEvents < 1 ||
        request.maxEvents > maxClaimBatch ||
        !Number.isInteger(request.waitMilliseconds) ||
        request.waitMilliseconds < 0 ||
        request.waitMilliseconds > maxWaitMilliseconds
      ) {
        throw new Error('adapter request is outside its bound');
      }
      const body = Buffer.alloc(6);
      body.writeUInt16BE(request.maxEvents, 0);
      body.writeUInt32BE(request.waitMilliseconds, 2);
      return Buffer.concat([Buffer.of(kindWaitAndClaim), body]);
    }
    case 'acknowledge':
      return claimTransition(kindAcknowledge, request.notificationId, request.leaseGeneration);
    case 'release':
      return claimTransition(kindRelease, request.notificationId, request.leaseGeneration);
    case 'status':
      return Buffer.of(kindStatus);
  }
}

/** Decodes a response. */
export function decodeAdapterResponse(payload: Buffer): AdapterResponse {
  const reader = new Reader(payload);
  const kind = reader.byte();

  let response: AdapterResponse;
  switch (kind) {
    case kindBatch: {
      const count = reader.uint16();
      if (count > maxClaimBatch) {
        throw new Error('adapter request is outside its bound');
      }
      const events: DeliveredEvent[] = [];
      for (let index = 0; index < count; index += 1) {
        events.push(decodeDeliveredEvent(reader));
      }
      response = { kind: 'batch', events };
      break;
    }
    case kindAccepted:
      response = { kind: 'accepted' };
      break;
    case kindStatusReport: {
      const pendingEvents = reader.uint32();
      const claimedEvents = reader.uint32();
      const watchedConversations = reader.uint32();
      const degraded = reader.byte();
      if (degraded > 1) {
        throw new Error('adapter frame is malformed');
      }
      response = {
        kind: 'status',
        status: {
          pendingEvents,
          claimedEvents,
          watchedConversations,
          deliveryDegraded: degraded === 1,
        },
      };
      break;
    }
    case kindFailure: {
      const length = reader.byte();
      if (length === 0 || length > maxFailureCodeLength) {
        throw new Error('adapter frame is malformed');
      }
      const code = reader.text(length);
      if (!failureCodePattern.test(code)) {
        throw new Error('adapter frame is malformed');
      }
      response = { kind: 'failure', code };
      break;
    }
    default:
      throw new Error('adapter message kind is unknown');
  }

  reader.finish();
  return response;
}

function claimTransition(kind: number, notificationId: Buffer, leaseGeneration: number): Buffer {
  if (notificationId.length !== notificationIdLength) {
    throw new Error('adapter notification identifier does not have its required length');
  }

  if (!Number.isSafeInteger(leaseGeneration) || leaseGeneration < 0) {
    throw new Error('adapter request is outside its bound');
  }

  const generation = Buffer.alloc(8);
  generation.writeBigUInt64BE(BigInt(leaseGeneration), 0);
  return Buffer.concat([Buffer.of(kind), notificationId, generation]);
}

function decodeDeliveredEvent(reader: Reader): DeliveredEvent {
  const notificationId = reader.take(notificationIdLength);
  const leaseGeneration = reader.uint64();
  const sequence = reader.uint64();
  const conversation = reader.take(routedIdLength);
  const sender = reader.take(routedIdLength);
  const relayCursor = reader.uint64();

  return {
    notificationId,
    leaseGeneration,
    sequence,
    conversation,
    sender,
    relayCursor,
    payload: decodePayload(reader),
  };
}

function decodePayload(reader: Reader): DeliveredPayload {
  const kind = reader.byte();
  switch (kind) {
    case eventApplicationMessage: {
      const length = reader.uint32();
      if (length === 0 || length > maxEventTextBytes) {
        throw new Error('adapter request is outside its bound');
      }
      return { kind: 'application-text', text: reader.text(length) };
    }
    case eventMemberAdded:
      return {
        kind: 'member-added',
        device: reader.take(routedIdLength),
        role: decodeRole(reader.byte()),
      };
    case eventMemberRemoved:
      return { kind: 'member-removed', device: reader.take(routedIdLength) };
    case eventMemberRoleChanged:
      return {
        kind: 'member-role-changed',
        device: reader.take(routedIdLength),
        role: decodeRole(reader.byte()),
      };
    case eventLocalAccessRemoved:
      return { kind: 'local-access-removed', device: reader.take(routedIdLength) };
    default:
      throw new Error('adapter message kind is unknown');
  }
}

function decodeRole(value: number): DeliveredRole {
  switch (value) {
    case roleAdministrator:
      return 'administrator';
    case roleMember:
      return 'member';
    default:
      throw new Error('adapter frame is malformed');
  }
}
