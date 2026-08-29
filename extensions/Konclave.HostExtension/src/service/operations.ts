/**
 * The finite operation surface this client may invoke.
 *
 * The table is closed and shared with the service: an operation the service does not
 * implement is refused by name rather than routed somewhere. Agent tools, slash
 * commands, and automatic delivery all address these same operations, so there is one
 * behaviour per operation rather than one per surface.
 */

/** Operations that back the agent tool surface, named exactly as the tools are. */
export const toolOperations = [
  'set_active_conversation',
  'set_auto_delivery',
  'delivery_status',
  'get_identity',
  'create_pairing_capability',
  'redeem_pairing_capability',
  'get_pairing_status',
  'authorize_pairing_joiner',
  'authorize_pairing_inviter',
  'sync_pairing',
  'cancel_pairing',
  'create_conversation',
  'list_conversations',
  'create_invitation',
  'create_join_proof',
  'send_message',
  'propose_collaboration_policy',
  'propose_collaboration_policy_source',
  'resume_collaboration_policy_proposal',
  'get_collaboration_policy_status',
  'inspect_collaboration_policy_proposal',
  'accept_collaboration_policy',
  'reject_collaboration_policy',
  'revoke_collaboration_policy',
  'add_member',
  'accept_welcome',
  'remove_member',
  'change_member_role',
  'read_messages',
  'sync_messages',
  'watch_messages',
] as const;

export type ToolOperation = (typeof toolOperations)[number];

/** Operations that carry automatic delivery, which no agent tool exposes. */
export const deliveryOperations = {
  claim: 'delivery.claim',
  acknowledge: 'delivery.acknowledge',
  release: 'delivery.release',
} as const;

/** Paved Copilot policy decisions that remain outside the agent tool surface. */
export const collaborationOperations = {
  authorizeTurn: 'collaboration.turn.authorize',
  completeTurn: 'collaboration.turn.complete',
  evaluateAction: 'collaboration.action.evaluate',
} as const;

/** Operations that report bounded service state for deterministic commands. */
export const serviceOperations = {
  status: 'service.status',
} as const;

export const allOperations: readonly string[] = [
  ...toolOperations,
  ...Object.values(deliveryOperations),
  ...Object.values(collaborationOperations),
  ...Object.values(serviceOperations),
];

export function isKnownOperation(name: string): boolean {
  return allOperations.includes(name);
}

/** One claimed delivery record, as the service reports it. */
export interface DeliveryEventRecord {
  readonly notificationId: string;
  readonly leaseGeneration: number;
  readonly sequence: number;
  readonly conversation: string;
  readonly sender: string;
  readonly relayCursor: number;
  readonly payload:
    | { readonly kind: 'application_text'; readonly messageId: string; readonly text: string }
    | {
        readonly kind: 'directed_request';
        readonly messageId: string;
        readonly targetDeviceId: string;
        readonly text: string;
      }
    | { readonly kind: 'member_added'; readonly device: string; readonly role: string }
    | { readonly kind: 'member_removed'; readonly device: string }
    | { readonly kind: 'member_role_changed'; readonly device: string; readonly role: string }
    | { readonly kind: 'local_access_removed'; readonly device: string };
}

export interface DeliveryWaitResult {
  readonly events: readonly DeliveryEventRecord[];
}

export interface ServiceStatusResult {
  readonly profile: string;
  readonly deviceId: string;
  readonly relayConfigured: boolean;
  readonly watchedConversations: number;
  readonly pendingEvents: number;
  readonly claimedEvents: number;
  readonly deliveryDegraded: boolean;
  readonly authorizationPolicy: string;
  readonly authorizationProvider: string;
  readonly authorizationEvidence: readonly string[];
  readonly authorizationPolicyVersion: number;
  readonly grantExpiresAtUnixMilliseconds: number;
  readonly grantCapabilities: number;
  readonly activeGrants: number;
  readonly activeGrantsForIssuer: number;
  readonly activeGrantsForProfile: number;
  readonly grantLimit: number;
  readonly grantLimitPerIssuer: number;
  readonly grantLimitPerProfile: number;
}
