import { createHash, randomBytes } from 'node:crypto';

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
  write(line: string, options?: CommandOutputOptions): Promise<void> | void;
}

export interface CommandOutputOptions {
  readonly ephemeral?: boolean;
}

export interface CommandDependencies {
  readonly client: LocalServiceClient;
  readonly output: CommandOutput;
  readonly nowUnixMilliseconds?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

export interface RegisteredCommand extends CommandDefinition {
  handler(context: CommandContext): Promise<void>;
}

const maxArgumentLength = 128;
const maxArguments = 4;
const maxCommandBytes = 16 * 1024;
const maxCapabilityBytes = 8 * 1024;
const maxMessageBytes = 8 * 1024;
const maxDisplayedMessageCharacters = 2_048;
const maxDisplayedMessages = 10;
const commandMessageRequestDomain = 'konclave:command-message-request:1\0';
const connectPollMilliseconds = 500;
const maxConnectIterations = 640;
const maxConnectWaitMilliseconds = 5 * 60 * 1_000;
const pairingIdCharacters = 32;
const messageIdCharacters = 32;
const conversationIdCharacters = 64;
const deviceIdCharacters = 64;

type ConversationRole = 'administrator' | 'member';
type PairingLocalRole = 'joiner' | 'inviter';

const pairingPhases = [
  'joiner_awaiting_invitation',
  'joiner_awaiting_inviter_authorization',
  'joiner_awaiting_welcome',
  'inviter_awaiting_authorization',
  'inviter_awaiting_join_proof',
  'inviter_awaiting_completion',
  'compensating',
  'completed',
  'cancelled',
] as const;
type PairingPhase = (typeof pairingPhases)[number];

interface PairingStatus {
  readonly pairingId: string;
  readonly localRole: PairingLocalRole;
  readonly phase: PairingPhase;
  readonly joinerDeviceId: string;
  readonly requestedRole: ConversationRole;
  readonly inviterDeviceId: string | undefined;
  readonly grantedRole: ConversationRole | undefined;
  readonly conversationId: string | undefined;
  readonly authorizationDeadlineUnixSeconds: number;
  readonly completionDeadlineUnixSeconds: number | undefined;
}

interface MessageSummary {
  readonly messageId: string;
  readonly senderDeviceId: string;
  readonly cursor: number;
  readonly direction: 'inbound' | 'outbound';
  readonly text: string;
  readonly duplicate: boolean;
}

interface ConversationSelection {
  readonly conversationIds: readonly string[];
  readonly activeConversationId: string | undefined;
}

interface ParsedCommand {
  readonly subcommand: string;
  readonly argumentsText: string;
}

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
  '  /konclave help                                      Show this list.',
  '  /konclave status                                    Show profile, delivery, and relay state.',
  '  /konclave identity                                  Show this profile device identifier.',
  '  /konclave conversations                             List local conversation identifiers.',
  '  /konclave connect                                   Create a two-session connection capability.',
  '  /konclave connect <capability>                      Join and complete an AccountTrusted connection.',
  '  /konclave pair [member|administrator]               Create a one-time pairing capability.',
  '  /konclave join <capability>                         Redeem a pairing capability.',
  '  /konclave new                                       Create a conversation for an approved peer.',
  '  /konclave pairing <pairing>                         Show authenticated pairing state.',
  '  /konclave approve <pairing> <conversation> [role]   Approve a displayed joiner.',
  '  /konclave approve <pairing> <inviter> <conversation> <role>',
  '                                                       Approve displayed inviter fields.',
  '  /konclave sync <pairing>                            Process one pairing progress page.',
  '  /konclave cancel <pairing>                          Cancel an active pairing.',
  '  /konclave send [conversation] [message-id] -- <text>',
  '                                                       Send or retry a message.',
  '  /konclave reply <conversation> <reply-to> [message-id] -- <text>',
  '                                                       Reply or retry with an explicit ID.',
  '  /konclave messages <conversation> [after-cursor]    Sync and show a bounded message page.',
  '  /konclave use <conversation>                        Select the implicit send target.',
  '  /konclave mute <conversation>                       Mute automatic delivery.',
  '  /konclave unmute <conversation>                     Resume automatic delivery.',
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

function parseCommand(raw: string): ParsedCommand {
  const trimmed = raw.trim();
  if (Buffer.byteLength(trimmed, 'utf8') > maxCommandBytes) {
    throw new Error('command is too long');
  }
  if (trimmed.length === 0) {
    return { subcommand: 'help', argumentsText: '' };
  }
  const separator = trimmed.search(/\s/u);
  if (separator === -1) {
    return { subcommand: trimmed.toLowerCase(), argumentsText: '' };
  }
  return {
    subcommand: trimmed.slice(0, separator).toLowerCase(),
    argumentsText: trimmed.slice(separator).trim(),
  };
}

function requireArgumentCount(
  parts: readonly string[],
  minimum: number,
  maximum: number,
  usage: string,
): void {
  if (parts.length < minimum || parts.length > maximum) {
    throw new Error(`usage: ${usage}`);
  }
}

function requireNoArguments(raw: string, subcommand: string): void {
  if (parseCommandArguments(raw).length !== 0) {
    throw new Error(`${subcommand} accepts no arguments`);
  }
}

function requireHexIdentifier(
  value: string | undefined,
  characters: number,
  label: string,
): string {
  if (!value || value.length !== characters || !/^[0-9a-f]+$/u.test(value)) {
    throw new Error(`a ${characters}-character hex ${label} is required`);
  }
  return value;
}

function isConversationRole(value: unknown): value is ConversationRole {
  return value === 'administrator' || value === 'member';
}

function parseRole(value: unknown, label = 'role'): ConversationRole {
  if (!isConversationRole(value)) {
    throw new Error(`${label} must be member or administrator`);
  }
  return value;
}

function isPairingLocalRole(value: string): value is PairingLocalRole {
  return value === 'joiner' || value === 'inviter';
}

function isPairingPhase(value: string): value is PairingPhase {
  return pairingPhases.some((phase) => phase === value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requiredString(
  record: Readonly<Record<string, unknown>>,
  key: string,
  error: string,
): string {
  const value = record[key];
  if (typeof value !== 'string') {
    throw new Error(error);
  }
  return value;
}

function requiredNonnegativeSafeInteger(
  record: Readonly<Record<string, unknown>>,
  key: string,
  error: string,
): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(error);
  }
  return value;
}

function optionalNonnegativeSafeInteger(
  record: Readonly<Record<string, unknown>>,
  key: string,
  error: string,
): number | undefined {
  const value = record[key];
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(error);
  }
  return value;
}

function optionalIdentifier(
  record: Readonly<Record<string, unknown>>,
  key: string,
  characters: number,
  label: string,
): string | undefined {
  const value = record[key];
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new Error(`the local service ${label} is malformed`);
  }
  return requireHexIdentifier(value, characters, label);
}

function parsePairingStatus(value: unknown): PairingStatus {
  if (!isRecord(value)) {
    throw new Error('the local service pairing response is malformed');
  }
  const localRole = requiredString(
    value,
    'local_role',
    'the local service pairing role is malformed',
  );
  const phase = requiredString(value, 'phase', 'the local service pairing phase is malformed');
  if (!isPairingLocalRole(localRole)) {
    throw new Error('the local service pairing role is malformed');
  }
  if (!isPairingPhase(phase)) {
    throw new Error('the local service pairing phase is malformed');
  }
  const grantedRole =
    value.granted_role === null || value.granted_role === undefined
      ? undefined
      : parseRole(value.granted_role, 'the local service granted role');

  return {
    pairingId: requireHexIdentifier(
      requiredString(value, 'pairing_id', 'the local service pairing identifier is malformed'),
      pairingIdCharacters,
      'pairing identifier',
    ),
    localRole,
    phase,
    joinerDeviceId: requireHexIdentifier(
      requiredString(value, 'joiner_device_id', 'the local service joiner identity is malformed'),
      deviceIdCharacters,
      'joiner device identifier',
    ),
    requestedRole: parseRole(value.requested_role, 'the local service requested role'),
    inviterDeviceId: optionalIdentifier(
      value,
      'inviter_device_id',
      deviceIdCharacters,
      'inviter device identifier',
    ),
    grantedRole,
    conversationId: optionalIdentifier(
      value,
      'conversation_id',
      conversationIdCharacters,
      'conversation identifier',
    ),
    authorizationDeadlineUnixSeconds: requiredNonnegativeSafeInteger(
      value,
      'authorization_deadline_unix_seconds',
      'the local service pairing authorization deadline is malformed',
    ),
    completionDeadlineUnixSeconds: optionalNonnegativeSafeInteger(
      value,
      'completion_deadline_unix_seconds',
      'the local service pairing completion deadline is malformed',
    ),
  };
}

function parsePairingCapability(value: unknown): {
  readonly pairing: PairingStatus;
  readonly capability: string;
} {
  if (!isRecord(value) || typeof value.capability !== 'string') {
    throw new Error('the local service pairing capability response is malformed');
  }
  if (
    Buffer.byteLength(value.capability, 'utf8') === 0 ||
    Buffer.byteLength(value.capability, 'utf8') > maxCapabilityBytes ||
    !/^[A-Za-z0-9_-]+$/u.test(value.capability)
  ) {
    throw new Error('the local service pairing capability is malformed');
  }
  return {
    pairing: parsePairingStatus(value.pairing),
    capability: value.capability,
  };
}

function requirePairingCapability(value: string): string {
  const capability = value.trim();
  if (
    Buffer.byteLength(capability, 'utf8') === 0 ||
    Buffer.byteLength(capability, 'utf8') > maxCapabilityBytes ||
    !/^[A-Za-z0-9_-]+$/u.test(capability)
  ) {
    throw new Error('a valid pairing capability is required');
  }
  return capability;
}

function parsePairingSync(value: unknown): {
  readonly pairing: PairingStatus;
  readonly processedRecords: number;
} {
  if (
    !isRecord(value) ||
    typeof value.processed_records !== 'number' ||
    !Number.isSafeInteger(value.processed_records) ||
    value.processed_records < 0
  ) {
    throw new Error('the local service pairing sync response is malformed');
  }
  return {
    pairing: parsePairingStatus(value.pairing),
    processedRecords: value.processed_records,
  };
}

function parseConversation(value: unknown): string {
  if (!isRecord(value)) {
    throw new Error('the local service conversation response is malformed');
  }
  return requireHexIdentifier(
    requiredString(
      value,
      'conversation_id',
      'the local service conversation identifier is malformed',
    ),
    conversationIdCharacters,
    'conversation identifier',
  );
}

function parseSentMessage(value: unknown): {
  readonly conversationId: string;
  readonly messageId: string;
  readonly cursor: number;
} {
  if (
    !isRecord(value) ||
    typeof value.cursor !== 'number' ||
    !Number.isSafeInteger(value.cursor) ||
    value.cursor < 0
  ) {
    throw new Error('the local service sent-message response is malformed');
  }
  return {
    conversationId: parseConversation(value),
    messageId: requireHexIdentifier(
      requiredString(value, 'message_id', 'the local service message identifier is malformed'),
      messageIdCharacters,
      'message identifier',
    ),
    cursor: value.cursor,
  };
}

function parseMessageList(value: unknown): {
  readonly messages: readonly MessageSummary[];
  readonly hasMore: boolean;
} {
  if (
    !isRecord(value) ||
    !Array.isArray(value.messages) ||
    value.messages.length > 100 ||
    typeof value.has_more !== 'boolean'
  ) {
    throw new Error('the local service message-list response is malformed');
  }
  const messages = value.messages.map((message): MessageSummary => {
    if (
      !isRecord(message) ||
      typeof message.cursor !== 'number' ||
      !Number.isSafeInteger(message.cursor) ||
      message.cursor < 0 ||
      (message.direction !== 'inbound' && message.direction !== 'outbound') ||
      typeof message.text !== 'string' ||
      typeof message.duplicate !== 'boolean'
    ) {
      throw new Error('the local service message-list response is malformed');
    }
    return {
      messageId: requireHexIdentifier(
        requiredString(message, 'message_id', 'the local service message identifier is malformed'),
        messageIdCharacters,
        'message identifier',
      ),
      senderDeviceId: requireHexIdentifier(
        requiredString(
          message,
          'sender_device_id',
          'the local service sender identity is malformed',
        ),
        deviceIdCharacters,
        'sender device identifier',
      ),
      cursor: message.cursor,
      direction: message.direction,
      text: message.text,
      duplicate: message.duplicate,
    };
  });
  return { messages, hasMore: value.has_more };
}

function parseDelimitedMessage(
  raw: string,
  minimumIdentifiers: number,
  maximumIdentifiers: number,
  usage: string,
): { readonly identifiers: readonly string[]; readonly text: string } {
  const separator = /(?:^|\s+)--\s+/u.exec(raw);
  if (!separator) {
    throw new Error(`usage: ${usage}`);
  }
  const identifiers = parseCommandArguments(raw.slice(0, separator.index));
  requireArgumentCount(identifiers, minimumIdentifiers, maximumIdentifiers, usage);
  const text = raw.slice(separator.index + separator[0].length).trim();
  if (text.length === 0 || Buffer.byteLength(text, 'utf8') > maxMessageBytes) {
    throw new Error(`message text must contain 1-${maxMessageBytes} UTF-8 bytes`);
  }
  return { identifiers, text };
}

function messageRequestId(messageId: string): Buffer {
  return createHash('sha256')
    .update(commandMessageRequestDomain)
    .update(Buffer.from(messageId, 'hex'))
    .digest()
    .subarray(0, 16);
}

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

async function requireAccountTrusted(client: LocalServiceClient): Promise<void> {
  const status = parseServiceStatus(await client.request(serviceOperations.status, {}));
  if (!status.relayConfigured) {
    throw new Error('connect requires a configured relay; run /konclave status');
  }
  if (
    status.authorizationPolicy !== 'AccountTrusted' ||
    status.authorizationProvider !== 'AccountTrusted' ||
    !status.authorizationEvidence.includes('account_trusted')
  ) {
    throw new Error('connect requires the AccountTrusted authorization policy');
  }
}

function pairingDeadlineMilliseconds(status: PairingStatus): number {
  const seconds = status.completionDeadlineUnixSeconds ?? status.authorizationDeadlineUnixSeconds;
  if (seconds > Math.floor(Number.MAX_SAFE_INTEGER / 1_000)) {
    throw new Error('the local service pairing deadline exceeds the supported range');
  }
  return seconds * 1_000;
}

function remainingPairingRequestMilliseconds(
  status: PairingStatus,
  commandDeadline: number,
  nowUnixMilliseconds: () => number,
): number {
  const remaining =
    Math.min(commandDeadline, pairingDeadlineMilliseconds(status)) - nowUnixMilliseconds();
  if (remaining <= 0) {
    throw new Error(`connect timed out for pairing ${status.pairingId}`);
  }
  return Math.min(remaining, 30_000);
}

async function completeAccountTrustedPairing(
  client: LocalServiceClient,
  initialStatus: PairingStatus,
  output: CommandOutput,
  commandDeadline: number,
  nowUnixMilliseconds: () => number,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<PairingStatus> {
  let status = initialStatus;

  try {
    for (let iteration = 0; iteration < maxConnectIterations; iteration += 1) {
      if (status.phase === 'completed') {
        return status;
      }
      if (status.phase === 'cancelled') {
        throw new Error('pairing was cancelled before connection completed');
      }
      if (
        status.localRole === 'joiner' &&
        status.phase === 'joiner_awaiting_inviter_authorization'
      ) {
        if (!status.inviterDeviceId || !status.conversationId || status.grantedRole !== 'member') {
          throw new Error('the AccountTrusted pairing authorization is malformed');
        }
        const previousPhase = status.phase;
        status = parsePairingStatus(
          await client.request(
            'authorize_pairing_inviter',
            {
              pairing_id: status.pairingId,
              inviter_device_id: status.inviterDeviceId,
              conversation_id: status.conversationId,
              granted_role: status.grantedRole,
            },
            {
              deadlineMs: remainingPairingRequestMilliseconds(
                status,
                commandDeadline,
                nowUnixMilliseconds,
              ),
            },
          ),
        );
        if (status.phase !== previousPhase) {
          await output.write(`connect phase: ${status.phase}`);
        }
        continue;
      }
      const previousPhase = status.phase;
      const synced = parsePairingSync(
        await client.request(
          'sync_pairing',
          { pairing_id: status.pairingId },
          {
            deadlineMs: remainingPairingRequestMilliseconds(
              status,
              commandDeadline,
              nowUnixMilliseconds,
            ),
          },
        ),
      );
      if (synced.pairing.pairingId !== status.pairingId) {
        throw new Error('the local service pairing sync identity is malformed');
      }
      status = synced.pairing;
      if (status.phase !== previousPhase) {
        await output.write(`connect phase: ${status.phase}`);
      } else {
        await sleep(connectPollMilliseconds);
      }
    }

    throw new Error(`connect exceeded its progress limit for pairing ${status.pairingId}`);
  } catch (error) {
    await output.write(`recovery: /konclave pairing ${status.pairingId}`);
    if (status.phase === 'cancelled') {
      await output.write('next: run /konclave connect to start a new pairing');
    } else {
      await output.write(`cancel: /konclave cancel ${status.pairingId}`);
    }
    throw error;
  }
}

async function requireSingleConversation(
  client: LocalServiceClient,
  activeConversationId: string | undefined,
): Promise<string> {
  if (activeConversationId) {
    return activeConversationId;
  }
  const selection = conversations(await client.request('list_conversations', {}));
  if (selection.activeConversationId) {
    return selection.activeConversationId;
  }
  if (selection.conversationIds.length === 0) {
    throw new Error('no conversation is available; run /konclave connect first');
  }
  throw new Error(
    'no active conversation is selected; run /konclave conversations, then /konclave use <conversation>',
  );
}

function parseCursor(value: string | undefined): number {
  if (!value || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error('after-cursor must be a non-negative integer');
  }
  const cursor = Number(value);
  if (!Number.isSafeInteger(cursor)) {
    throw new Error('after-cursor exceeds the supported integer range');
  }
  return cursor;
}

function displayText(value: string): string {
  const safe = value.replace(/[\p{Cf}\p{Zl}\p{Zp}]/gu, '\uFFFD');
  const characters = Array.from(safe);
  const boundedText =
    characters.length > maxDisplayedMessageCharacters
      ? `${characters.slice(0, maxDisplayedMessageCharacters).join('')}…`
      : safe;
  return JSON.stringify(boundedText);
}

async function renderPairing(output: CommandOutput, status: PairingStatus): Promise<void> {
  await output.write(`pairing: ${status.pairingId}`);
  await output.write(`local role: ${status.localRole}`);
  await output.write(`phase: ${status.phase}`);
  await output.write(`joiner device: ${status.joinerDeviceId}`);
  await output.write(`requested role: ${status.requestedRole}`);
  if (status.inviterDeviceId) {
    await output.write(`inviter device: ${status.inviterDeviceId}`);
  }
  if (status.grantedRole) {
    await output.write(`granted role: ${status.grantedRole}`);
  }
  if (status.conversationId) {
    await output.write(`conversation: ${status.conversationId}`);
  }
}

function identity(value: unknown): string {
  if (!isRecord(value)) {
    throw new Error('the local service identity response is malformed');
  }
  return requireHexIdentifier(
    requiredString(value, 'device_id', 'the local service identity response is malformed'),
    deviceIdCharacters,
    'device identifier',
  );
}

function conversations(value: unknown): ConversationSelection {
  if (
    !isRecord(value) ||
    !Array.isArray(value.conversation_ids) ||
    value.conversation_ids.length > 1_000 ||
    !value.conversation_ids.every(
      (item) =>
        typeof item === 'string' &&
        item.length === conversationIdCharacters &&
        /^[0-9a-f]+$/u.test(item),
    )
  ) {
    throw new Error('the local service conversation response is malformed');
  }
  const activeConversationId =
    value.active_conversation_id === null || value.active_conversation_id === undefined
      ? undefined
      : requireHexIdentifier(
          typeof value.active_conversation_id === 'string'
            ? value.active_conversation_id
            : undefined,
          conversationIdCharacters,
          'active conversation identifier',
        );
  return {
    conversationIds: value.conversation_ids,
    activeConversationId,
  };
}

function selectedConversation(value: unknown): string {
  if (!isRecord(value)) {
    throw new Error('the local service active-conversation response is malformed');
  }
  return requireHexIdentifier(
    typeof value.active_conversation_id === 'string' ? value.active_conversation_id : undefined,
    conversationIdCharacters,
    'active conversation identifier',
  );
}

function parseConversationArgument(argumentsText: string, usage: string): string {
  const parts = parseCommandArguments(argumentsText);
  requireArgumentCount(parts, 1, 1, usage);
  return requireHexIdentifier(parts[0], conversationIdCharacters, 'conversation identifier');
}

export function createKonclaveCommands(dependencies: CommandDependencies): RegisteredCommand[] {
  const { client, output } = dependencies;
  const nowUnixMilliseconds = dependencies.nowUnixMilliseconds ?? Date.now;
  const sleep = dependencies.sleep ?? defaultSleep;
  let activeConversationId: string | undefined;

  const run = async (args: string): Promise<void> => {
    const { subcommand, argumentsText } = parseCommand(args);

    switch (subcommand) {
      case 'help': {
        requireNoArguments(argumentsText, subcommand);
        for (const line of helpLines) {
          await output.write(line);
        }
        return;
      }
      case 'status': {
        requireNoArguments(argumentsText, subcommand);
        const status = parseServiceStatus(await client.request(serviceOperations.status, {}));
        await output.write(`profile: ${bounded(status.profile)}`);
        await output.write(`device: ${bounded(status.deviceId)}`);
        await output.write(`relay configured: ${status.relayConfigured ? 'yes' : 'no'}`);
        await output.write(
          `authorization: ${bounded(status.authorizationPolicy)} (${status.authorizationEvidence.map((item) => bounded(item)).join('+')})`,
        );
        await output.write(`authorization provider: ${bounded(status.authorizationProvider)}`);
        if (status.authorizationPolicy === 'AccountTrusted') {
          await output.write(
            'authorization boundary: same-account processes are trusted; no same-user isolation',
          );
        }
        await output.write(
          `grant: expires ${status.grantExpiresAtUnixMilliseconds}, capabilities ${status.grantCapabilities}`,
        );
        await output.write(
          `grant capacity: global ${status.activeGrants}/${status.grantLimit}, issuer ${status.activeGrantsForIssuer}/${status.grantLimitPerIssuer}, profile ${status.activeGrantsForProfile}/${status.grantLimitPerProfile}`,
        );
        await output.write(
          `delivery: ${status.deliveryDegraded ? 'degraded' : 'healthy'}, watching ${status.watchedConversations}, pending ${status.pendingEvents}, claimed ${status.claimedEvents}`,
        );
        return;
      }
      case 'identity': {
        requireNoArguments(argumentsText, subcommand);
        const deviceId = identity(await client.request('get_identity', {}));
        await output.write(`device: ${bounded(deviceId)}`);
        return;
      }
      case 'conversations': {
        requireNoArguments(argumentsText, subcommand);
        const selection = conversations(await client.request('list_conversations', {}));
        activeConversationId = selection.activeConversationId;
        if (selection.activeConversationId) {
          await output.write(`active: ${selection.activeConversationId}`);
        }
        if (selection.conversationIds.length === 0) {
          await output.write('no conversations yet');
          return;
        }
        for (const conversation of selection.conversationIds.slice(0, 20)) {
          await output.write(bounded(conversation));
        }
        return;
      }
      case 'connect': {
        await requireAccountTrusted(client);
        const commandDeadline = nowUnixMilliseconds() + maxConnectWaitMilliseconds;
        let status: PairingStatus;
        if (argumentsText.length === 0) {
          const created = parsePairingCapability(
            await client.request('create_pairing_capability', {
              requested_role: 'member',
            }),
          );
          await output.write(
            'approval policy: AccountTrusted capability possession; no independent identity verification',
          );
          await output.write(`pairing: ${created.pairing.pairingId}`);
          await output.write(`recovery: /konclave pairing ${created.pairing.pairingId}`);
          await output.write(`cancel: /konclave cancel ${created.pairing.pairingId}`);
          await output.write('capability (ephemeral; paste the next line in the other session):');
          await output.write(created.capability, { ephemeral: true });
          await output.write('waiting for the other session to run /konclave connect <capability>');
          status = await completeAccountTrustedPairing(
            client,
            created.pairing,
            output,
            commandDeadline,
            nowUnixMilliseconds,
            sleep,
          );
        } else {
          const capability = requirePairingCapability(argumentsText);
          const redeemed = parsePairingStatus(
            await client.request('redeem_pairing_capability', { capability }),
          );
          if (redeemed.requestedRole !== 'member') {
            throw new Error('connect accepts only member pairing requests');
          }
          await output.write(
            'approval policy: AccountTrusted capability possession; no independent identity verification',
          );
          await output.write(`pairing: ${redeemed.pairingId}`);
          await output.write(`recovery: /konclave pairing ${redeemed.pairingId}`);
          await output.write(`cancel: /konclave cancel ${redeemed.pairingId}`);
          const conversationId = parseConversation(await client.request('create_conversation', {}));
          await output.write(`conversation: ${conversationId}`);
          const approved = parsePairingStatus(
            await client.request(
              'authorize_pairing_joiner',
              {
                pairing_id: redeemed.pairingId,
                conversation_id: conversationId,
                granted_role: 'member',
              },
              {
                deadlineMs: remainingPairingRequestMilliseconds(
                  redeemed,
                  commandDeadline,
                  nowUnixMilliseconds,
                ),
              },
            ),
          );
          status = await completeAccountTrustedPairing(
            client,
            approved,
            output,
            commandDeadline,
            nowUnixMilliseconds,
            sleep,
          );
        }
        if (!status.conversationId) {
          throw new Error('completed pairing is missing its conversation');
        }
        activeConversationId = status.conversationId;
        await renderPairing(output, status);
        await output.write(`connected: ${status.conversationId}`);
        await output.write('next: /konclave send -- <message>');
        return;
      }
      case 'pair': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 0, 1, '/konclave pair [member|administrator]');
        const requestedRole = parts[0] ? parseRole(parts[0], 'requested role') : 'member';
        const created = parsePairingCapability(
          await client.request('create_pairing_capability', {
            requested_role: requestedRole,
          }),
        );
        await renderPairing(output, created.pairing);
        await output.write('capability (ephemeral; copy the next line now):');
        await output.write(created.capability, { ephemeral: true });
        await output.write('next: run /konclave join <capability> in the other session');
        return;
      }
      case 'join': {
        const capability = requirePairingCapability(argumentsText);
        const status = parsePairingStatus(
          await client.request('redeem_pairing_capability', { capability }),
        );
        await renderPairing(output, status);
        await output.write(
          `next: verify the joiner device, run /konclave new, then /konclave approve ${status.pairingId} <conversation>`,
        );
        return;
      }
      case 'new': {
        requireNoArguments(argumentsText, subcommand);
        const conversationId = parseConversation(await client.request('create_conversation', {}));
        activeConversationId = conversationId;
        await output.write(`conversation: ${conversationId}`);
        await output.write(
          'conversation created durably; it remains if the pending pairing is abandoned',
        );
        await output.write(
          'next: use this conversation when approving an inviter-side pairing or sending a message',
        );
        return;
      }
      case 'pairing': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave pairing <pairing>');
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        await renderPairing(
          output,
          parsePairingStatus(await client.request('get_pairing_status', { pairing_id: pairingId })),
        );
        return;
      }
      case 'approve': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(
          parts,
          1,
          4,
          '/konclave approve <pairing> <conversation> [role] | <pairing> <inviter> <conversation> <role>',
        );
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        const status = parsePairingStatus(
          await client.request('get_pairing_status', { pairing_id: pairingId }),
        );
        let approved: PairingStatus;
        if (status.localRole === 'inviter') {
          if (status.phase !== 'inviter_awaiting_authorization') {
            throw new Error(`pairing cannot be approved in phase ${status.phase}`);
          }
          requireArgumentCount(
            parts,
            2,
            3,
            '/konclave approve <pairing> <conversation> [member|administrator]',
          );
          const conversationId = requireHexIdentifier(
            parts[1],
            conversationIdCharacters,
            'conversation identifier',
          );
          const grantedRole = parts[2] ? parseRole(parts[2], 'granted role') : 'member';
          if (status.requestedRole === 'member' && grantedRole === 'administrator') {
            throw new Error('a member request cannot be elevated to administrator');
          }
          approved = parsePairingStatus(
            await client.request('authorize_pairing_joiner', {
              pairing_id: pairingId,
              conversation_id: conversationId,
              granted_role: grantedRole,
            }),
          );
        } else {
          requireArgumentCount(
            parts,
            4,
            4,
            '/konclave approve <pairing> <inviter> <conversation> <role>',
          );
          if (status.phase !== 'joiner_awaiting_inviter_authorization') {
            throw new Error(`pairing cannot be approved in phase ${status.phase}`);
          }
          if (!status.inviterDeviceId || !status.conversationId || !status.grantedRole) {
            throw new Error('the pairing is missing inviter authorization details');
          }
          const inviterDeviceId = requireHexIdentifier(
            parts[1],
            deviceIdCharacters,
            'inviter device identifier',
          );
          const conversationId = requireHexIdentifier(
            parts[2],
            conversationIdCharacters,
            'conversation identifier',
          );
          const grantedRole = parseRole(parts[3], 'granted role');
          if (
            inviterDeviceId !== status.inviterDeviceId ||
            conversationId !== status.conversationId ||
            grantedRole !== status.grantedRole
          ) {
            throw new Error('approval values do not match the authenticated pairing state');
          }
          approved = parsePairingStatus(
            await client.request('authorize_pairing_inviter', {
              pairing_id: pairingId,
              inviter_device_id: inviterDeviceId,
              conversation_id: conversationId,
              granted_role: grantedRole,
            }),
          );
        }
        await renderPairing(output, approved);
        await output.write(`next: run /konclave sync ${pairingId} in both sessions`);
        return;
      }
      case 'sync': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave sync <pairing>');
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        const synced = parsePairingSync(
          await client.request('sync_pairing', { pairing_id: pairingId }),
        );
        await output.write(`processed pairing records: ${synced.processedRecords}`);
        await renderPairing(output, synced.pairing);
        return;
      }
      case 'cancel': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave cancel <pairing>');
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        await renderPairing(
          output,
          parsePairingStatus(await client.request('cancel_pairing', { pairing_id: pairingId })),
        );
        return;
      }
      case 'send':
      case 'reply': {
        const isReply = subcommand === 'reply';
        const usage = isReply
          ? '/konclave reply <conversation> <reply-to> [message-id] -- <text>'
          : '/konclave send [conversation] [message-id] -- <text>';
        const parsed = parseDelimitedMessage(
          argumentsText,
          isReply ? 2 : 0,
          isReply ? 3 : 2,
          usage,
        );
        let conversationId: string;
        let suppliedMessageId: string | undefined;
        let explicitlySelectedConversation = isReply || parsed.identifiers.length === 2;
        if (isReply || parsed.identifiers.length === 2) {
          conversationId = requireHexIdentifier(
            parsed.identifiers[0],
            conversationIdCharacters,
            'conversation identifier',
          );
          suppliedMessageId = parsed.identifiers[isReply ? 2 : 1];
        } else if (parsed.identifiers.length === 1) {
          const identifier = parsed.identifiers[0];
          if (identifier?.length === conversationIdCharacters) {
            explicitlySelectedConversation = true;
            conversationId = requireHexIdentifier(
              identifier,
              conversationIdCharacters,
              'conversation identifier',
            );
          } else {
            conversationId = await requireSingleConversation(client, activeConversationId);
            suppliedMessageId = requireHexIdentifier(
              identifier,
              messageIdCharacters,
              'message identifier',
            );
          }
        } else {
          conversationId = await requireSingleConversation(client, activeConversationId);
        }
        const replyToMessageId = isReply
          ? requireHexIdentifier(
              parsed.identifiers[1],
              messageIdCharacters,
              'reply-to message identifier',
            )
          : undefined;
        const messageId = suppliedMessageId
          ? requireHexIdentifier(suppliedMessageId, messageIdCharacters, 'message identifier')
          : randomBytes(16).toString('hex');
        const payload: Record<string, unknown> = {
          conversation_id: conversationId,
          message_id: messageId,
          text: parsed.text,
        };
        if (replyToMessageId) {
          payload.reply_to_message_id = replyToMessageId;
        }
        await output.write(`message id: ${messageId}`);
        await output.write(
          `retry: /konclave ${subcommand} ${conversationId}${replyToMessageId ? ` ${replyToMessageId}` : ''} ${messageId} -- <same text>`,
        );
        const sent = parseSentMessage(
          await client.request('send_message', payload, {
            requestId: messageRequestId(messageId),
          }),
        );
        if (sent.conversationId !== conversationId || sent.messageId !== messageId) {
          throw new Error('the local service sent-message identity does not match the request');
        }
        if (explicitlySelectedConversation) {
          const selected = selectedConversation(
            await client.request('set_active_conversation', {
              conversation_id: conversationId,
            }),
          );
          if (selected !== conversationId) {
            throw new Error('the local service selected a different active conversation');
          }
        }
        activeConversationId = conversationId;
        await output.write(`conversation: ${sent.conversationId}`);
        await output.write(`relay cursor: ${sent.cursor}`);
        return;
      }
      case 'messages': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 2, '/konclave messages <conversation> [after-cursor]');
        const conversationId = requireHexIdentifier(
          parts[0],
          conversationIdCharacters,
          'conversation identifier',
        );
        const afterCursor = parts[1] ? parseCursor(parts[1]) : 0;
        const synced = parseMessageList(
          await client.request('sync_messages', { conversation_id: conversationId }),
        );
        const history = parseMessageList(
          await client.request('read_messages', {
            conversation_id: conversationId,
            after_cursor: afterCursor,
            limit: maxDisplayedMessages,
          }),
        );
        await output.write(
          `synced messages: ${synced.messages.length}, more available: ${synced.hasMore ? 'yes' : 'no'}`,
        );
        if (history.messages.length === 0) {
          await output.write('no messages after the requested cursor');
          return;
        }
        for (const message of history.messages) {
          await output.write(
            `message ${message.messageId}: ${message.direction}, sender ${message.senderDeviceId}, cursor ${message.cursor}, duplicate ${message.duplicate ? 'yes' : 'no'}`,
          );
          await output.write(
            `${message.direction === 'inbound' ? 'untrusted peer text' : 'local message text'}: ${displayText(message.text)}`,
            { ephemeral: true },
          );
        }
        const lastCursor = history.messages.at(-1)?.cursor;
        if (lastCursor !== undefined) {
          await output.write(`resume after cursor: ${lastCursor}`);
          await output.write(`next: /konclave messages ${conversationId} ${lastCursor}`);
        }
        if (history.hasMore) {
          await output.write('more messages are available');
        }
        return;
      }
      case 'use': {
        const conversation = parseConversationArgument(
          argumentsText,
          '/konclave use <conversation>',
        );
        const selected = selectedConversation(
          await client.request('set_active_conversation', {
            conversation_id: conversation,
          }),
        );
        if (selected !== conversation) {
          throw new Error('the local service selected a different active conversation');
        }
        activeConversationId = conversation;
        await output.write(`active conversation selected: ${conversation}`);
        return;
      }
      case 'mute':
      case 'unmute': {
        const conversation = parseConversationArgument(
          argumentsText,
          `/konclave ${subcommand} <conversation>`,
        );
        await client.request('set_auto_delivery', {
          conversation_id: conversation,
          enabled: subcommand === 'unmute',
        });
        await output.write(
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
      description: 'Konclave deterministic pairing, messaging, and profile operations.',
      async handler(context) {
        try {
          await run(context.args ?? '');
        } catch (error) {
          // A failure is rendered as a bounded line rather than thrown into the
          // session, so a command never becomes an error turn for the model.
          await output.write(
            error instanceof LocalServiceError
              ? `konclave: ${error.operation} failed (${error.code})`
              : `konclave: ${boundedMessage(error instanceof Error ? error.message : 'failed')}`,
          );
        }
      },
    },
  ];
}
