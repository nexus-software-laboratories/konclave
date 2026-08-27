import type { CommandContext, CommandDefinition } from '@github/copilot-sdk';

import type { LocalServiceClient } from './client.js';
import { LocalServiceError } from './client.js';
import { parseServiceStatus } from './delivery.js';
import { serviceOperations } from './operations.js';

/**
 * Deterministic `/konclave` commands.
 *
 * A command runs exactly what the operator asked for: it calls the shared client and
 * renders the bounded result. Nothing here prompts a model, injects a turn, or lets
 * command text reach the agent, so a command can never become an instruction channel.
 */

export interface CommandOutput {
  write(line: string): void;
}

export interface CommandDependencies {
  readonly client: LocalServiceClient;
  readonly output: CommandOutput;
}

export interface RegisteredCommand extends CommandDefinition {
  handler(context: CommandContext): Promise<void>;
}

const maxArgumentLength = 128;
const maxArguments = 4;

/** Parses a bounded, whitespace-separated argument list. */
export function parseCommandArguments(raw: string): string[] {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return [];
  }
  if (trimmed.length > maxArgumentLength * maxArguments) {
    throw new Error('command arguments are too long');
  }
  const parts = trimmed.split(/\s+/u);
  if (parts.length > maxArguments) {
    throw new Error('command accepts at most four arguments');
  }
  for (const part of parts) {
    if (part.length > maxArgumentLength) {
      throw new Error('command argument is too long');
    }
  }
  return parts;
}

const helpLines = [
  'Konclave commands (deterministic; no model inference):',
  '  /konclave help                 Show this list.',
  '  /konclave status               Show profile, delivery, and relay state.',
  '  /konclave identity             Show this profile device identifier.',
  '  /konclave conversations        List local conversation identifiers.',
  '  /konclave mute <conversation>  Mute automatic delivery for one conversation.',
  '  /konclave unmute <conversation> Resume automatic delivery for one conversation.',
];

/** Redacts anything that is not a bounded identifier before it is rendered. */
function bounded(value: string, limit = 64): string {
  const safe = value.replace(/[^\w.:@/-]/gu, '');
  return safe.length > limit ? `${safe.slice(0, limit)}…` : safe;
}

/**
 * Renders a bounded single-line diagnostic.
 *
 * Words are preserved so a refusal stays readable, while control characters and
 * newlines are removed so no rendered line can forge additional output.
 */
function boundedMessage(value: string, limit = 96): string {
  const safe = value
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
  return safe.length > limit ? `${safe.slice(0, limit)}…` : safe;
}

function requireConversation(parts: readonly string[]): string {
  const conversation = parts[1];
  if (!conversation || !/^[0-9a-f]{32}$/u.test(conversation)) {
    throw new Error('a 32-character hex conversation identifier is required');
  }
  return conversation;
}

function identity(value: unknown): string {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('device_id' in value) ||
    typeof value.device_id !== 'string'
  ) {
    throw new Error('the local service identity response is malformed');
  }
  return value.device_id;
}

function conversations(value: unknown): readonly string[] {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('conversation_ids' in value) ||
    !Array.isArray(value.conversation_ids) ||
    !value.conversation_ids.every((item) => typeof item === 'string')
  ) {
    throw new Error('the local service conversation response is malformed');
  }
  return value.conversation_ids;
}

export function createKonclaveCommands(dependencies: CommandDependencies): RegisteredCommand[] {
  const { client, output } = dependencies;

  const run = async (args: string): Promise<void> => {
    const parts = parseCommandArguments(args);
    const subcommand = parts[0] ?? 'help';

    switch (subcommand) {
      case 'help': {
        for (const line of helpLines) {
          output.write(line);
        }
        return;
      }
      case 'status': {
        const status = parseServiceStatus(await client.request(serviceOperations.status, {}));
        output.write(`profile: ${bounded(status.profile)}`);
        output.write(`device: ${bounded(status.deviceId)}`);
        output.write(`relay configured: ${status.relayConfigured ? 'yes' : 'no'}`);
        output.write(
          `authorization: ${bounded(status.authorizationPolicy)} (${status.authorizationEvidence.map((item) => bounded(item)).join('+')})`,
        );
        output.write(`authorization provider: ${bounded(status.authorizationProvider)}`);
        if (status.authorizationPolicy === 'AccountTrusted') {
          output.write(
            'authorization boundary: same-account processes are trusted; no same-user isolation',
          );
        }
        output.write(
          `grant: expires ${status.grantExpiresAtUnixMilliseconds}, capabilities ${status.grantCapabilities}`,
        );
        output.write(
          `grant capacity: global ${status.activeGrants}/${status.grantLimit}, issuer ${status.activeGrantsForIssuer}/${status.grantLimitPerIssuer}, profile ${status.activeGrantsForProfile}/${status.grantLimitPerProfile}`,
        );
        output.write(
          `delivery: ${status.deliveryDegraded ? 'degraded' : 'healthy'}, watching ${status.watchedConversations}, pending ${status.pendingEvents}, claimed ${status.claimedEvents}`,
        );
        return;
      }
      case 'identity': {
        const deviceId = identity(await client.request('get_identity', {}));
        output.write(`device: ${bounded(deviceId)}`);
        return;
      }
      case 'conversations': {
        const list = conversations(await client.request('list_conversations', {}));
        if (list.length === 0) {
          output.write('no conversations yet');
          return;
        }
        for (const conversation of list.slice(0, 20)) {
          output.write(bounded(conversation));
        }
        return;
      }
      case 'mute':
      case 'unmute': {
        const conversation = requireConversation(parts);
        await client.request('set_auto_delivery', {
          conversation_id: conversation,
          enabled: subcommand === 'unmute',
        });
        output.write(
          `automatic delivery ${subcommand === 'unmute' ? 'resumed' : 'muted'} for ${bounded(conversation)}`,
        );
        return;
      }
      default:
        throw new Error(`unknown subcommand: ${bounded(subcommand, 24)}`);
    }
  };

  return [
    {
      name: 'konclave',
      description: 'Konclave status and deterministic profile operations.',
      async handler(context) {
        try {
          await run(context.args ?? '');
        } catch (error) {
          // A failure is rendered as a bounded line rather than thrown into the
          // session, so a command never becomes an error turn for the model.
          output.write(
            error instanceof LocalServiceError
              ? `konclave: ${error.operation} failed (${error.code})`
              : `konclave: ${boundedMessage(error instanceof Error ? error.message : 'failed')}`,
          );
        }
      },
    },
  ];
}
