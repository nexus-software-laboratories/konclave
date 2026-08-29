/**
 * Harness-neutral automatic-delivery contracts.
 *
 * The shared local service carries JSON RPC. These types preserve the delivery
 * coordinator's established claim/acknowledge/release policy without retaining the
 * superseded per-session daemon channel or its binary framing.
 */

/** Byte length of a notification identifier. */
export const notificationIdLength = 16;

/** Byte length of a conversation or device identifier. */
export const routedIdLength = 32;

/** Largest batch the shared local service returns in one claim. */
export const maxClaimBatch = 16;

/** Longest bounded wait a delivery claim may request, in milliseconds. */
export const maxWaitMilliseconds = 30_000;

/** Largest accepted application text in a delivered event. */
export const maxEventTextBytes = 64 * 1024;

export type DeliveredRole = 'administrator' | 'member';
export type DeliveredPolicyResponseOutcome = 'accepted' | 'rejected';

export type DeliveredPayload =
  | { readonly kind: 'application-text'; readonly text: string }
  | { readonly kind: 'directed-request'; readonly target: Buffer; readonly text: string }
  | {
      readonly kind: 'collaboration-policy-proposal';
      readonly proposalId: Buffer;
      readonly policyDigest: Buffer;
      readonly replacesPolicyDigest?: Buffer;
    }
  | {
      readonly kind: 'collaboration-policy-response';
      readonly proposalId: Buffer;
      readonly policyDigest: Buffer;
      readonly outcome: DeliveredPolicyResponseOutcome;
    }
  | { readonly kind: 'collaboration-policy-revocation'; readonly policyDigest: Buffer }
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

export interface CollaborationTurnAuthorization {
  readonly conversation: string;
  readonly policyDigest: string;
  readonly policyName: string;
  readonly turnToken: string;
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

/** One profile-bound delivery view over a harness-neutral local client. */
export interface AdapterChannel {
  readonly profile: string;
  request(request: AdapterRequest): Promise<AdapterResponse>;
  close(): void;
}
