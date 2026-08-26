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

/** Operations that report bounded service state for deterministic commands. */
export const serviceOperations = {
  status: 'service.status',
} as const;

export const allOperations: readonly string[] = [
  ...toolOperations,
  ...Object.values(deliveryOperations),
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
    | { readonly kind: 'application_text'; readonly text: string }
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
}
