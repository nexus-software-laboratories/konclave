import {
  LocalServiceProtocolError,
  type LocalServiceClient,
  type LocalServiceRequestOptions,
} from './client.js';
import { serviceOperations } from './operations.js';
import { isRecord, requireHexIdentifier } from './validation.js';

const descriptions = {
  not_observed:
    'No inspectable authenticated local record was observed. This does not prove the message was never sent.',
  outbound_prepared: 'Local content is prepared; a ready outbound envelope was not observed.',
  awaiting_relay_acceptance: 'A sealed envelope is ready; relay acceptance has not been observed.',
  relay_accepted: 'A relay receipt was observed. This does not prove remote delivery or execution.',
  outbound_expired: 'The local outbound operation expired without observed acceptance.',
  outbound_removed: 'Authenticated membership removal stopped the local outbound operation.',
  inbound_prepared: 'Inbound content is sealed; contiguous local completion was not observed.',
  persisted_inbound: 'Inbound completion is verified; no notification remains in the local journal.',
  awaiting_harness_delivery: 'The local notification is waiting for an eligible harness consumer.',
  claimed_for_delivery: 'A local consumer claimed the notification; acknowledgment is not recorded.',
  acknowledged_by_harness: 'The harness acknowledged the notification. This does not prove model execution.',
  delivery_suppressed: 'Local delivery policy suppressed this notification.',
  request_claim_recorded:
    'A request claim has a future recorded expiry. Its consumer is not proven live by this observation.',
  request_claim_expired: 'The recorded request claim expired. This is not permission to retry.',
  response_reserved: 'One correlated response is reserved, but submission or delivery is not proven.',
  completed_without_response: 'Local request handling ended without reserving a response.',
} as const;

/** Finite locally observed milestones; none establishes a remote execution outcome. */
export type MessageDeliveryState = keyof typeof descriptions;

/** Body-free snapshot for one selected message in the client's authenticated profile. */
export interface MessageDeliveryDiagnostic {
  readonly messageStatus: MessageDeliveryState;
  readonly autoDeliveryEnabled: boolean;
  readonly profileDeliveryDegraded: boolean;
  readonly remoteOutcome: 'unknown';
}

const resultFields = [
  'message_status',
  'auto_delivery_enabled',
  'profile_delivery_degraded',
  'remote_outcome',
];

function isMessageDeliveryState(value: unknown): value is MessageDeliveryState {
  return typeof value === 'string' && Object.hasOwn(descriptions, value);
}

export function parseMessageDeliveryStatus(value: unknown): MessageDeliveryDiagnostic {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== resultFields.length ||
    !resultFields.every((field) => Object.hasOwn(value, field)) ||
    !isMessageDeliveryState(value.message_status) ||
    typeof value.auto_delivery_enabled !== 'boolean' ||
    typeof value.profile_delivery_degraded !== 'boolean' ||
    value.remote_outcome !== 'unknown'
  ) {
    throw new LocalServiceProtocolError('the local service delivery diagnostic is malformed');
  }
  return {
    messageStatus: value.message_status,
    autoDeliveryEnabled: value.auto_delivery_enabled,
    profileDeliveryDegraded: value.profile_delivery_degraded,
    remoteOutcome: value.remote_outcome,
  };
}

/**
 * Reads local evidence without sending, repairing, or activating anything.
 *
 * The client fixes the profile. Reusing an explicit request ID reconciles the
 * original read; a fresh inspection uses a fresh ID. The result contains no message
 * content and is not automatically exported.
 *
 * Throws for noncanonical selectors, a service refusal, unavailable transport, or
 * an unsupported/malformed response. There is no alternate-profile or legacy
 * operation fallback.
 */
export async function getMessageDeliveryStatus(
  client: LocalServiceClient,
  conversationId: string,
  messageId: string,
  options?: LocalServiceRequestOptions,
): Promise<MessageDeliveryDiagnostic> {
  const conversation = requireHexIdentifier(conversationId, 64, 'conversation identifier');
  const message = requireHexIdentifier(messageId, 32, 'message identifier');
  return parseMessageDeliveryStatus(
    await client.request(
      serviceOperations.messageDeliveryStatus,
      { conversation_id: conversation, message_id: message },
      options,
    ),
  );
}

export function formatMessageDeliveryStatus(
  diagnostic: MessageDeliveryDiagnostic,
): readonly string[] {
  return [
    `local message status: ${diagnostic.messageStatus}`,
    descriptions[diagnostic.messageStatus],
    `automatic delivery currently: ${diagnostic.autoDeliveryEnabled ? 'enabled' : 'muted'}`,
    `profile delivery currently: ${diagnostic.profileDeliveryDegraded ? 'degraded' : 'not degraded'}`,
    'remote outcome: unknown',
    'Inspection changes no messaging or permissions. Reconcile an uncertain send with its original identifiers.',
  ];
}
