import { randomBytes } from 'node:crypto';

import type { SessionHooks } from '@github/copilot-sdk';

import type {
  CollaborationTurnAuthorization,
  CollaborationTurnDecision,
  DeliveredEvent,
  DeliveredPayload,
} from '../adapter/session.js';
import {
  collaborationAuthorizationArgument,
  collaborationReplyToolName,
  collaborationTurnTokenLabel,
} from '../collaboration-contract.js';
import type { LocalServiceClient } from './client.js';
import { collaborationOperations } from './operations.js';

const hex16 = /^[0-9a-f]{32}$/u;
const hex32 = /^[0-9a-f]{64}$/u;
const maxPolicyNameBytes = 128;
const maxToolArgumentsBytes = 128 * 1024;
const maxMessageTextBytes = 64 * 1024;
const sendArgumentKeys = new Set(['conversation_id', 'message_id', 'reply_to_message_id', 'text']);

type ActiveCollaborationTurn =
  | {
      readonly kind: 'authorized';
      readonly authorization: CollaborationTurnAuthorization;
    }
  | {
      readonly kind: 'blocked';
      readonly authorization: CollaborationTurnAuthorization | null;
    };

interface ToolAction {
  readonly action: string;
  readonly resource?: string;
  readonly conversationBound: boolean;
}

type DirectedRequestEvent = Omit<DeliveredEvent, 'payload'> & {
  readonly payload: Extract<DeliveredPayload, { readonly kind: 'directed-request' }>;
};

export interface CopilotPolicyGate {
  readonly hooks: SessionHooks;
  authorizeTurn(events: readonly DeliveredEvent[]): Promise<CollaborationTurnDecision | null>;
  completeTurn(
    authorization: CollaborationTurnAuthorization,
  ): Promise<'completed-response' | 'completed-no-response'>;
  canCompleteTurn(authorization: CollaborationTurnAuthorization): boolean;
  activate(authorization: CollaborationTurnAuthorization): void;
  observePrompt(prompt: string): void;
  prepareToolArguments(toolName: string, toolArgs: unknown): unknown;
  clear(): void;
  readonly active: boolean;
  readonly lastDecision: string | null;
}

interface PendingSendAuthorization {
  readonly turn: CollaborationTurnAuthorization;
  readonly conversationId: string;
  readonly messageId: string;
  readonly replyToMessageId: string;
  readonly text: string;
  readonly authorization: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDirectedRequestEvent(event: DeliveredEvent): event is DirectedRequestEvent {
  return event.payload.kind === 'directed-request';
}

function boundedString(value: unknown, maximum: number, label: string): string {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value, 'utf8') === 0 ||
    Buffer.byteLength(value, 'utf8') > maximum
  ) {
    throw new Error(`the local service ${label} is malformed`);
  }
  return value;
}

function parseTurnAuthorization(
  value: unknown,
  event: DirectedRequestEvent,
): CollaborationTurnDecision | null {
  if (!isRecord(value)) {
    throw new Error('the local service collaboration authorization is malformed');
  }
  if (
    value.outcome === 'inactive' ||
    value.outcome === 'denied' ||
    value.outcome === 'approval_required'
  ) {
    if (
      value.outcome === 'denied' &&
      (value.reason === 'directed_request_claimed' ||
        value.reason === 'directed_request_claim_inactive')
    ) {
      return { kind: 'deferred' };
    }
    return null;
  }
  const requestMessageId = event.payload.messageId.toString('hex');
  if (
    value.outcome !== 'authorized' ||
    typeof value.policyDigest !== 'string' ||
    !hex32.test(value.policyDigest) ||
    value.requestMessageId !== requestMessageId ||
    !Number.isSafeInteger(value.attempt) ||
    (value.attempt as number) < 1 ||
    (value.attempt as number) > 16
  ) {
    throw new Error('the local service collaboration authorization is malformed');
  }
  return {
    conversation: event.conversation.toString('hex'),
    policyDigest: value.policyDigest,
    policyName: boundedString(value.policyName, maxPolicyNameBytes, 'policy name'),
    requestMessageId,
    attempt: value.attempt as number,
    turnToken: randomBytes(16).toString('hex'),
  };
}

function parseTurnCompletion(value: unknown): 'completed-response' | 'completed-no-response' {
  if (!isRecord(value) || typeof value.changed !== 'boolean') {
    throw new Error('the local service collaboration completion is malformed');
  }
  if (value.outcome === 'completed_response' && !value.changed) {
    return 'completed-response';
  }
  if (value.outcome === 'completed_no_response') {
    return 'completed-no-response';
  }
  throw new Error('the local service collaboration completion is malformed');
}

function parseActionDecision(value: unknown): {
  readonly decision: 'allow' | 'ask' | 'deny';
  readonly reason: string;
  readonly authorization: string | undefined;
} {
  if (
    !isRecord(value) ||
    (value.decision !== 'allow' && value.decision !== 'ask' && value.decision !== 'deny') ||
    (value.reason !== null &&
      value.reason !== undefined &&
      (typeof value.reason !== 'string' ||
        value.reason.length > 64 ||
        !/^[a-z][a-z0-9_]*$/u.test(value.reason))) ||
    (value.authorization !== null &&
      value.authorization !== undefined &&
      (typeof value.authorization !== 'string' || !/^[0-9a-f]{32}$/u.test(value.authorization)))
  ) {
    throw new Error('the local service collaboration decision is malformed');
  }
  return {
    decision: value.decision,
    reason: typeof value.reason === 'string' ? value.reason : 'policy_allowed',
    authorization: typeof value.authorization === 'string' ? value.authorization : undefined,
  };
}

function normalizedToolName(toolName: string): string {
  return toolName.startsWith('functions.') ? toolName.slice('functions.'.length) : toolName;
}

function toolArgumentRecord(value: unknown): Record<string, unknown> | null {
  if (isPlainRecord(value)) {
    return value;
  }
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value, 'utf8') === 0 ||
    Buffer.byteLength(value, 'utf8') > maxToolArgumentsBytes
  ) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return isPlainRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function withoutCallerAuthorization(
  value: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== collaborationAuthorizationArgument),
  );
}

function authorizationTokenInTrustedHeader(prompt: string, expectedToken?: string): boolean {
  if (!prompt.startsWith('Konclave delivered ')) {
    return false;
  }
  const tokenPattern = expectedToken ?? '[0-9a-f]{32}';
  const match = new RegExp(`\\n${collaborationTurnTokenLabel}: ${tokenPattern}(?:\\n|$)`, 'u').exec(
    prompt,
  );
  if (!match) {
    return false;
  }
  const untrustedBoundary = prompt.indexOf('\n--- BEGIN UNTRUSTED COLLABORATOR CONTENT ---');
  return untrustedBoundary === -1 || match.index < untrustedBoundary;
}

function toolAction(toolName: string): ToolAction | null {
  switch (normalizedToolName(toolName)) {
    case collaborationReplyToolName:
      return { action: 'conversation.reply', conversationBound: true };
    default:
      return null;
  }
}

function hasOnlySendArgumentKeys(value: Readonly<Record<string, unknown>>): boolean {
  const keys = Object.keys(value);
  return keys.length <= sendArgumentKeys.size && keys.every((key) => sendArgumentKeys.has(key));
}

function parseSendArguments(
  value: Readonly<Record<string, unknown>>,
  authorization: CollaborationTurnAuthorization,
): {
  readonly conversation_id: string;
  readonly message_id: string;
  readonly reply_to_message_id?: string | null;
  readonly text: string;
} | null {
  if (
    !hasOnlySendArgumentKeys(value) ||
    value.conversation_id !== authorization.conversation ||
    typeof value.message_id !== 'string' ||
    !hex16.test(value.message_id) ||
    typeof value.text !== 'string' ||
    Buffer.byteLength(value.text, 'utf8') === 0 ||
    Buffer.byteLength(value.text, 'utf8') > maxMessageTextBytes ||
    (value.reply_to_message_id !== undefined &&
      value.reply_to_message_id !== null &&
      (typeof value.reply_to_message_id !== 'string' ||
        !hex16.test(value.reply_to_message_id) ||
        value.reply_to_message_id !== authorization.requestMessageId))
  ) {
    return null;
  }
  return {
    conversation_id: value.conversation_id,
    message_id: value.message_id,
    ...(value.reply_to_message_id === undefined
      ? {}
      : { reply_to_message_id: value.reply_to_message_id }),
    text: value.text,
  };
}

function targetsAuthorizedConversation(
  action: ToolAction,
  toolArgs: Readonly<Record<string, unknown>>,
  conversation: string,
): boolean {
  if (!action.conversationBound) {
    return true;
  }
  return typeof toolArgs.conversation_id === 'string' && toolArgs.conversation_id === conversation;
}

function isSameTurn(
  left: CollaborationTurnAuthorization,
  right: CollaborationTurnAuthorization,
): boolean {
  return (
    left.conversation === right.conversation &&
    left.policyDigest === right.policyDigest &&
    left.requestMessageId === right.requestMessageId &&
    left.attempt === right.attempt
  );
}

export function createCopilotPolicyGate(client: LocalServiceClient): CopilotPolicyGate {
  let active: ActiveCollaborationTurn | null = null;
  let pending: CollaborationTurnAuthorization | null = null;
  let delayed: CollaborationTurnAuthorization | null = null;
  let pendingSendAuthorization: PendingSendAuthorization | null = null;
  let lastDecision: string | null = null;
  const deny = (reason: string, message: string) => {
    lastDecision = reason;
    return {
      permissionDecision: 'deny' as const,
      permissionDecisionReason: message,
    };
  };

  const gate: CopilotPolicyGate = {
    hooks: {
      async onPreToolUse(input, invocation) {
        const turn = active;
        if (!turn) {
          lastDecision = 'turn_inactive';
          return;
        }
        try {
          if (turn.kind === 'blocked') {
            return deny(
              'delayed_prompt_unbound',
              'Konclave could not bind this delayed collaboration prompt to its authorization.',
            );
          }
          if (input.sessionId !== invocation.sessionId) {
            return deny(
              'descendant_session',
              'Konclave collaboration policy does not authorize descendant sessions.',
            );
          }
          const action = toolAction(input.toolName);
          if (!action) {
            return deny('tool_unmapped', 'The active Konclave policy does not map this tool.');
          }
          const authorization = turn.authorization;
          const rawToolArguments = toolArgumentRecord(input.toolArgs);
          if (!rawToolArguments) {
            return deny('tool_arguments_malformed', 'Konclave tool arguments are malformed.');
          }
          const toolArguments = withoutCallerAuthorization(rawToolArguments);
          if (!targetsAuthorizedConversation(action, toolArguments, authorization.conversation)) {
            return deny(
              'conversation_mismatch',
              'The active Konclave turn is bound to a different conversation.',
            );
          }
          const sendArguments =
            action.action === 'conversation.reply'
              ? parseSendArguments(toolArguments, authorization)
              : null;
          if (action.action === 'conversation.reply' && sendArguments === null) {
            return deny('send_arguments_malformed', 'Konclave send arguments are malformed.');
          }
          if (pendingSendAuthorization !== null) {
            return deny(
              'send_authorization_pending',
              'Konclave already authorized one reply for this collaboration turn.',
            );
          }
          const result = parseActionDecision(
            await client.request(collaborationOperations.evaluateAction, {
              conversationId: authorization.conversation,
              policyDigest: authorization.policyDigest,
              action: action.action,
              resource: action.resource ?? null,
              messageId: sendArguments?.message_id,
              replyToMessageId: authorization.requestMessageId,
              text: sendArguments?.text,
              requestMessageId: authorization.requestMessageId,
              attempt: authorization.attempt,
            }),
          );
          if (result.decision === 'deny') {
            return deny(result.reason, `Konclave policy denied this action (${result.reason}).`);
          }
          if (result.decision === 'ask') {
            return deny(
              'approval_not_composable',
              'Konclave cannot compose policy approval with native permissions.',
            );
          }
          if (!result.authorization) {
            return deny(
              'send_authorization_missing',
              'Konclave did not issue a send authorization.',
            );
          }
          if (sendArguments === null) {
            return deny('send_arguments_malformed', 'Konclave send arguments are malformed.');
          }
          pendingSendAuthorization = {
            turn: authorization,
            conversationId: authorization.conversation,
            messageId: sendArguments.message_id,
            replyToMessageId: authorization.requestMessageId,
            text: sendArguments.text,
            authorization: result.authorization,
          };
          lastDecision = 'authorized';
          return {
            modifiedArgs: {
              ...sendArguments,
              reply_to_message_id: authorization.requestMessageId,
            },
            additionalContext:
              'Konclave policy permits this action, but normal Copilot permissions still apply.',
          };
        } catch {
          return deny('gate_unavailable', 'Konclave policy evaluation was unavailable.');
        }
      },
      onPostToolUse(input) {
        if (normalizedToolName(input.toolName) === collaborationReplyToolName) {
          pendingSendAuthorization = null;
        }
      },
      onPostToolUseFailure(input) {
        if (normalizedToolName(input.toolName) === collaborationReplyToolName) {
          pendingSendAuthorization = null;
        }
      },
    },
    authorizeTurn(events) {
      const first = events[0];
      if (!first || events.length !== 1 || !isDirectedRequestEvent(first)) {
        return Promise.resolve(null);
      }
      return client
        .request(collaborationOperations.authorizeTurn, {
          conversationId: first.conversation.toString('hex'),
          requestMessageId: first.payload.messageId.toString('hex'),
          notificationId: first.notificationId.toString('hex'),
          leaseGeneration: first.leaseGeneration,
        })
        .then((value) => parseTurnAuthorization(value, first));
    },
    async completeTurn(authorization) {
      return parseTurnCompletion(
        await client.request(collaborationOperations.completeTurn, {
          conversationId: authorization.conversation,
          policyDigest: authorization.policyDigest,
          requestMessageId: authorization.requestMessageId,
          attempt: authorization.attempt,
        }),
      );
    },
    canCompleteTurn(authorization) {
      if (!active) {
        return false;
      }
      return active.authorization !== null && isSameTurn(active.authorization, authorization);
    },
    activate(authorization) {
      active = null;
      pending = authorization;
      delayed = null;
      lastDecision = null;
    },
    observePrompt(prompt) {
      if (active) {
        active = { kind: 'blocked', authorization: active.authorization };
        return;
      }
      const authorization = pending;
      pending = null;
      if (authorization && authorizationTokenInTrustedHeader(prompt, authorization.turnToken)) {
        delayed = null;
        active = {
          kind: 'authorized',
          authorization,
        };
      } else if (authorization) {
        if (authorizationTokenInTrustedHeader(prompt)) {
          delayed = null;
          active = { kind: 'blocked', authorization: null };
        } else {
          delayed = authorization;
          active = null;
        }
      } else if (delayed) {
        if (authorizationTokenInTrustedHeader(prompt, delayed.turnToken)) {
          active = { kind: 'blocked', authorization: delayed };
          delayed = null;
        } else if (authorizationTokenInTrustedHeader(prompt)) {
          delayed = null;
          active = { kind: 'blocked', authorization: null };
        } else {
          active = null;
        }
      } else {
        active = authorizationTokenInTrustedHeader(prompt)
          ? { kind: 'blocked', authorization: null }
          : null;
      }
    },
    prepareToolArguments(toolName, toolArgs) {
      if (normalizedToolName(toolName) !== collaborationReplyToolName) {
        return toolArgs;
      }
      const pendingAuthorization = pendingSendAuthorization;
      if (pendingAuthorization === null) {
        if (active?.kind === 'authorized') {
          throw new Error('Konclave collaboration send authorization is unavailable.');
        }
        return toolArgs;
      }
      pendingSendAuthorization = null;
      const turn = active;
      if (
        !turn ||
        turn.kind !== 'authorized' ||
        !isSameTurn(turn.authorization, pendingAuthorization.turn)
      ) {
        throw new Error('Konclave collaboration turn changed after authorization.');
      }
      const record = toolArgumentRecord(toolArgs);
      if (
        record === null ||
        Object.hasOwn(record, collaborationAuthorizationArgument) ||
        record.conversation_id !== pendingAuthorization.conversationId ||
        record.message_id !== pendingAuthorization.messageId ||
        record.reply_to_message_id !== pendingAuthorization.replyToMessageId ||
        record.text !== pendingAuthorization.text
      ) {
        throw new Error('Konclave collaboration send arguments changed after authorization.');
      }
      return {
        ...record,
        [collaborationAuthorizationArgument]: pendingAuthorization.authorization,
      };
    },
    clear() {
      active = null;
      pending = null;
      delayed = null;
      lastDecision = null;
    },
    get active() {
      return active !== null;
    },
    get lastDecision() {
      return lastDecision;
    },
  };
  return gate;
}
