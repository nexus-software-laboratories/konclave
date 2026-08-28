import { randomBytes } from 'node:crypto';

import type { SessionHooks } from '@github/copilot-sdk';

import type { CollaborationTurnAuthorization, DeliveredEvent } from '../adapter/session.js';
import type { LocalServiceClient } from './client.js';
import { collaborationOperations } from './operations.js';

const hex32 = /^[0-9a-f]{64}$/u;
const maxPolicyNameBytes = 128;
const maxPolicyGuidanceBytes = 32 * 1024;

type ActiveCollaborationTurn =
  | {
      readonly kind: 'authorized';
      readonly conversation: string;
      readonly policyDigest: string;
    }
  | { readonly kind: 'blocked' };

interface ToolAction {
  readonly action: string;
  readonly resource?: string;
  readonly conversationBound: boolean;
}

export interface CopilotPolicyGate {
  readonly hooks: SessionHooks;
  authorizeTurn(events: readonly DeliveredEvent[]): Promise<CollaborationTurnAuthorization | null>;
  activate(authorization: CollaborationTurnAuthorization): void;
  observePrompt(prompt: string): void;
  clear(): void;
  readonly active: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
  conversation: string,
): CollaborationTurnAuthorization | null {
  if (!isRecord(value)) {
    throw new Error('the local service collaboration authorization is malformed');
  }
  if (
    value.outcome === 'inactive' ||
    value.outcome === 'denied' ||
    value.outcome === 'approval_required'
  ) {
    return null;
  }
  if (
    value.outcome !== 'authorized' ||
    typeof value.policyDigest !== 'string' ||
    !hex32.test(value.policyDigest)
  ) {
    throw new Error('the local service collaboration authorization is malformed');
  }
  const guidance =
    value.guidance === null || value.guidance === undefined
      ? undefined
      : boundedString(value.guidance, maxPolicyGuidanceBytes, 'policy guidance');
  return {
    conversation,
    policyDigest: value.policyDigest,
    policyName: boundedString(value.policyName, maxPolicyNameBytes, 'policy name'),
    guidance,
    turnToken: randomBytes(16).toString('hex'),
  };
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

function authorizationTokenInTrustedHeader(prompt: string, expectedToken?: string): boolean {
  if (!prompt.startsWith('Konclave delivered ')) {
    return false;
  }
  const tokenPattern = expectedToken ?? '[0-9a-f]{32}';
  const match = new RegExp(
    `\\nKonclave collaboration authorization token: ${tokenPattern}(?:\\n|$)`,
    'u',
  ).exec(prompt);
  if (!match) {
    return false;
  }
  const untrustedBoundary = prompt.indexOf('\n--- BEGIN UNTRUSTED COLLABORATOR CONTENT ---');
  return untrustedBoundary === -1 || match.index < untrustedBoundary;
}

function toolAction(toolName: string): ToolAction | null {
  switch (normalizedToolName(toolName)) {
    case 'send_message':
      return { action: 'conversation.reply', conversationBound: true };
    default:
      return null;
  }
}

function targetsAuthorizedConversation(
  action: ToolAction,
  toolArgs: unknown,
  conversation: string,
): boolean {
  if (!action.conversationBound) {
    return true;
  }
  return (
    isRecord(toolArgs) &&
    typeof toolArgs.conversation_id === 'string' &&
    toolArgs.conversation_id === conversation
  );
}

export function createCopilotPolicyGate(client: LocalServiceClient): CopilotPolicyGate {
  let active: ActiveCollaborationTurn | null = null;
  let pending: CollaborationTurnAuthorization | null = null;

  const gate: CopilotPolicyGate = {
    hooks: {
      async onPreToolUse(input, invocation) {
        const turn = active;
        if (!turn) {
          return;
        }
        if (turn.kind === 'blocked') {
          return {
            permissionDecision: 'deny',
            permissionDecisionReason:
              'Konclave could not bind this delayed collaboration prompt to its authorization.',
          };
        }
        if (input.sessionId !== invocation.sessionId) {
          return {
            permissionDecision: 'deny',
            permissionDecisionReason:
              'Konclave collaboration policy does not authorize descendant sessions.',
          };
        }
        const action = toolAction(input.toolName);
        if (!action) {
          return {
            permissionDecision: 'deny',
            permissionDecisionReason: 'The active Konclave policy does not map this tool.',
          };
        }
        if (!targetsAuthorizedConversation(action, input.toolArgs, turn.conversation)) {
          return {
            permissionDecision: 'deny',
            permissionDecisionReason:
              'The active Konclave turn is bound to a different conversation.',
          };
        }
        const toolArguments = isRecord(input.toolArgs) ? input.toolArgs : null;
        if (
          action.action === 'conversation.reply' &&
          (!toolArguments ||
            typeof toolArguments.message_id !== 'string' ||
            typeof toolArguments.text !== 'string' ||
            (toolArguments.reply_to_message_id !== undefined &&
              typeof toolArguments.reply_to_message_id !== 'string'))
        ) {
          return {
            permissionDecision: 'deny',
            permissionDecisionReason: 'Konclave send arguments are malformed.',
          };
        }
        try {
          const result = parseActionDecision(
            await client.request(collaborationOperations.evaluateAction, {
              conversationId: turn.conversation,
              policyDigest: turn.policyDigest,
              action: action.action,
              resource: action.resource ?? null,
              messageId: toolArguments?.message_id,
              replyToMessageId: toolArguments?.reply_to_message_id ?? null,
              text: toolArguments?.text,
            }),
          );
          if (result.decision === 'deny') {
            return {
              permissionDecision: 'deny',
              permissionDecisionReason: `Konclave policy denied this action (${result.reason}).`,
            };
          }
          if (result.decision === 'ask') {
            return {
              permissionDecision: 'deny',
              permissionDecisionReason:
                'Konclave cannot compose policy approval with native permissions.',
            };
          }
          if (!result.authorization || !toolArguments) {
            return {
              permissionDecision: 'deny',
              permissionDecisionReason: 'Konclave did not issue a send authorization.',
            };
          }
          return {
            modifiedArgs: {
              ...toolArguments,
              collaboration_authorization: result.authorization,
            },
            additionalContext:
              'Konclave policy permits this action, but normal Copilot permissions still apply.',
          };
        } catch {
          return {
            permissionDecision: 'deny',
            permissionDecisionReason: 'Konclave policy evaluation was unavailable.',
          };
        }
      },
    },
    async authorizeTurn(events) {
      const first = events[0];
      if (!first) {
        return null;
      }
      if (!events.some((event) => event.payload.kind === 'application-text')) {
        return null;
      }
      const conversation = first.conversation.toString('hex');
      if (events.some((event) => event.conversation.toString('hex') !== conversation)) {
        throw new Error('a collaboration turn cannot mix conversations');
      }
      return parseTurnAuthorization(
        await client.request(collaborationOperations.authorizeTurn, {
          conversationId: conversation,
        }),
        conversation,
      );
    },
    activate(authorization) {
      active = null;
      pending = authorization;
    },
    observePrompt(prompt) {
      const authorization = pending;
      pending = null;
      if (authorization && authorizationTokenInTrustedHeader(prompt, authorization.turnToken)) {
        active = {
          kind: 'authorized',
          conversation: authorization.conversation,
          policyDigest: authorization.policyDigest,
        };
      } else {
        active = authorizationTokenInTrustedHeader(prompt) ? { kind: 'blocked' } : null;
      }
    },
    clear() {
      active = null;
      pending = null;
    },
    get active() {
      return active !== null;
    },
  };
  return gate;
}
