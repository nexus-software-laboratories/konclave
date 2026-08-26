import {
  maxClaimBatch,
  maxEventTextBytes,
  type AdapterChannel,
  type AdapterRequest,
  type AdapterResponse,
  type DeliveredEvent,
  type DeliveredPayload,
  type DeliveredRole,
} from '../adapter/session.js';
import type { LocalServiceClient } from './client.js';
import { deliveryOperations, serviceOperations, type ServiceStatusResult } from './operations.js';

const hex16 = /^[0-9a-f]{32}$/u;
const hex32 = /^[0-9a-f]{64}$/u;
const deliveryDeadlineMarginMs = 5_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function integer(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error('the local service delivery response is malformed');
  }
  return value as number;
}

function text(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('the local service delivery response is malformed');
  }
  return value;
}

function hex(value: unknown, pattern: RegExp): string {
  const decoded = text(value);
  if (!pattern.test(decoded)) {
    throw new Error('the local service delivery response is malformed');
  }
  return decoded;
}

function role(value: unknown): DeliveredRole {
  if (value !== 'administrator' && value !== 'member') {
    throw new Error('the local service delivery response is malformed');
  }
  return value;
}

function payload(value: unknown): DeliveredPayload {
  if (!isRecord(value)) {
    throw new Error('the local service delivery response is malformed');
  }
  switch (value.kind) {
    case 'application_text': {
      const message = text(value.text);
      if (message.length === 0 || Buffer.byteLength(message, 'utf8') > maxEventTextBytes) {
        throw new Error('the local service delivery response is malformed');
      }
      return { kind: 'application-text', text: message };
    }
    case 'member_added':
      return {
        kind: 'member-added',
        device: Buffer.from(hex(value.device, hex32), 'hex'),
        role: role(value.role),
      };
    case 'member_removed':
      return { kind: 'member-removed', device: Buffer.from(hex(value.device, hex32), 'hex') };
    case 'member_role_changed':
      return {
        kind: 'member-role-changed',
        device: Buffer.from(hex(value.device, hex32), 'hex'),
        role: role(value.role),
      };
    case 'local_access_removed':
      return {
        kind: 'local-access-removed',
        device: Buffer.from(hex(value.device, hex32), 'hex'),
      };
    default:
      throw new Error('the local service delivery response is malformed');
  }
}

function event(value: unknown): DeliveredEvent {
  if (!isRecord(value)) {
    throw new Error('the local service delivery response is malformed');
  }
  return {
    notificationId: Buffer.from(hex(value.notificationId, hex16), 'hex'),
    leaseGeneration: integer(value.leaseGeneration),
    sequence: integer(value.sequence),
    conversation: Buffer.from(hex(value.conversation, hex32), 'hex'),
    sender: Buffer.from(hex(value.sender, hex32), 'hex'),
    relayCursor: integer(value.relayCursor),
    payload: payload(value.payload),
  };
}

function batch(value: unknown): readonly DeliveredEvent[] {
  if (!isRecord(value) || !Array.isArray(value.events) || value.events.length > maxClaimBatch) {
    throw new Error('the local service delivery response is malformed');
  }
  return value.events.map(event);
}

export function parseServiceStatus(value: unknown): ServiceStatusResult {
  if (
    !isRecord(value) ||
    typeof value.profile !== 'string' ||
    typeof value.deviceId !== 'string' ||
    typeof value.relayConfigured !== 'boolean' ||
    typeof value.deliveryDegraded !== 'boolean'
  ) {
    throw new Error('the local service status response is malformed');
  }
  return {
    profile: value.profile,
    deviceId: value.deviceId,
    relayConfigured: value.relayConfigured,
    watchedConversations: integer(value.watchedConversations),
    pendingEvents: integer(value.pendingEvents),
    claimedEvents: integer(value.claimedEvents),
    deliveryDegraded: value.deliveryDegraded,
  };
}

/** Adapts shared-service JSON operations to the existing delivery coordinator contract. */
export function createLocalServiceDeliveryChannel(client: LocalServiceClient): AdapterChannel {
  return {
    profile: client.profile,
    async request(request: AdapterRequest): Promise<AdapterResponse> {
      switch (request.kind) {
        case 'wait-and-claim': {
          const events = batch(
            await client.request(
              deliveryOperations.claim,
              {
                maxEvents: request.maxEvents,
                waitMilliseconds: request.waitMilliseconds,
              },
              request.waitMilliseconds + deliveryDeadlineMarginMs,
            ),
          );
          return { kind: 'batch', events };
        }
        case 'acknowledge':
        case 'release':
          await client.request(
            request.kind === 'acknowledge'
              ? deliveryOperations.acknowledge
              : deliveryOperations.release,
            {
              notificationId: request.notificationId.toString('hex'),
              leaseGeneration: request.leaseGeneration,
            },
          );
          return { kind: 'accepted' };
        case 'status': {
          const result = parseServiceStatus(await client.request(serviceOperations.status, {}));
          return {
            kind: 'status',
            status: {
              pendingEvents: result.pendingEvents,
              claimedEvents: result.claimedEvents,
              watchedConversations: result.watchedConversations,
              deliveryDegraded: result.deliveryDegraded,
            },
          };
        }
      }
    },
    close() {
      client.close();
    },
  };
}
