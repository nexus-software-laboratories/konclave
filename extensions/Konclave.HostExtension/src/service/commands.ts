import { createHash, randomBytes } from 'node:crypto';
import type { BigIntStats } from 'node:fs';
import { open, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { TextDecoder } from 'node:util';

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

export type CommandOutputMode = 'normal' | 'verbose';

interface CommandPresentation {
  readonly mode: CommandOutputMode;
  setMode(mode: CommandOutputMode): void;
  write(line: string, options?: CommandOutputOptions): Promise<void>;
  detail(line: string, options?: CommandOutputOptions): Promise<void>;
}

function createCommandPresentation(
  output: CommandOutput,
  initialMode: CommandOutputMode,
): CommandPresentation {
  let mode = initialMode;
  return {
    get mode() {
      return mode;
    },
    setMode(value) {
      mode = value;
    },
    async write(line, options) {
      await output.write(line, options);
    },
    async detail(line, options) {
      if (mode === 'verbose') {
        await output.write(line, options);
      }
    },
  };
}

export interface CommandDependencies {
  readonly client: LocalServiceClient;
  readonly output: CommandOutput;
  readonly outputMode?: CommandOutputMode;
  readonly nowUnixMilliseconds?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly readPolicySource?: (path: string) => Promise<string>;
}

export interface PolicySourceReadOptions {
  readonly workspace?: string;
  readonly afterInitialIdentity?: () => Promise<void>;
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
const maxDisplayedPolicyStatements = 20;
const maxPolicySourceBytes = 128 * 1024;
const maxPolicySourcePathBytes = 4_096;
const commandMessageRequestDomain = 'konclave:command-message-request:1\0';
const commandPolicyRequestDomain = 'konclave:command-policy-request:1\0';
const connectPollMilliseconds = 500;
const maxConnectIterations = 640;
const maxConnectWaitMilliseconds = 5 * 60 * 1_000;
const pairingIdCharacters = 32;
const messageIdCharacters = 32;
const conversationIdCharacters = 64;
const deviceIdCharacters = 64;
const policyProposalIdCharacters = 32;
const policyDigestCharacters = 64;
const uint64Maximum = 18_446_744_073_709_551_615n;

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
  readonly content: MessageContentSummary;
  readonly duplicate: boolean;
}

type MessageContentSummary =
  | { readonly kind: 'text'; readonly text: string }
  | { readonly kind: 'directed-request'; readonly targetDeviceId: string; readonly text: string }
  | {
      readonly kind: 'collaboration-policy-proposal';
      readonly proposalId: string;
      readonly policyDigest: string;
      readonly replacesPolicyDigest: string | undefined;
    }
  | {
      readonly kind: 'collaboration-policy-response';
      readonly proposalId: string;
      readonly policyDigest: string;
      readonly outcome: 'accepted' | 'rejected';
    }
  | { readonly kind: 'collaboration-policy-revocation'; readonly policyDigest: string };

interface ConversationSelection {
  readonly conversationIds: readonly string[];
  readonly activeConversationId: string | undefined;
}

interface CollaborationPolicyOperationSummary {
  readonly conversationId: string;
  readonly proposalId: string | undefined;
  readonly policyDigest: string;
  readonly messageId: string;
  readonly cursor: number;
  readonly localBindingChanged: boolean;
}

type CollaborationPolicyEffect = 'allow' | 'deny' | 'require_local_approval';

interface CollaborationPolicyBundleSummary {
  readonly name: string;
  readonly guidance: string | undefined;
  readonly statements: readonly {
    readonly statementId: string;
    readonly effect: CollaborationPolicyEffect;
    readonly action: string;
    readonly resource: string | undefined;
  }[];
  readonly requiredHarnessClaims: readonly string[];
  readonly limits: {
    readonly durationMilliseconds: string | undefined;
    readonly turns: string | undefined;
    readonly tokens: string | undefined;
    readonly concurrentRequests: number | undefined;
  };
}

interface ActiveCollaborationPolicySummary extends CollaborationPolicyBundleSummary {
  readonly policyDigest: string;
  readonly activatedAtUnixMilliseconds: string;
}

interface CollaborationPolicyProposalInspectionSummary extends CollaborationPolicyBundleSummary {
  readonly conversationId: string;
  readonly proposalId: string;
  readonly policyDigest: string;
  readonly replacesPolicyDigest: string | undefined;
  readonly proposerDeviceId: string;
  readonly messageId: string;
  readonly relayCursor: number;
}

interface CollaborationPolicyStatusSummary {
  readonly conversationId: string;
  readonly activePolicy: ActiveCollaborationPolicySummary | undefined;
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

const policyHelpLines = [
  '  /konclave policy status                             Show active policy metadata.',
  '  /konclave policy propose [proposal-id] -- <source>  Compile and propose a policy.',
  '  /konclave policy replace <digest> [proposal-id] -- <source>',
  '                                                       Replace the active policy.',
  '  /konclave policy resume <proposal-id>                Resume a committed proposal.',
  '  /konclave policy inspect <proposal-id>               Review a peer proposal.',
  '  /konclave policy accept <proposal-id> <digest>      Accept an exact proposal.',
  '  /konclave policy reject <proposal-id> <digest>      Reject an exact proposal.',
  '  /konclave policy revoke <digest> [message-id]       Revoke the active policy.',
];

const helpLines = [
  'Konclave commands (deterministic; no model inference):',
  '  /konclave help                                      Show this list.',
  '  /konclave output <normal|verbose>                   Set command detail for this session.',
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
  ...policyHelpLines,
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

function parseCollaborationPolicyOperation(value: unknown): CollaborationPolicyOperationSummary {
  if (
    !isRecord(value) ||
    typeof value.local_binding_changed !== 'boolean' ||
    typeof value.cursor !== 'number' ||
    !Number.isSafeInteger(value.cursor) ||
    value.cursor < 1
  ) {
    throw new Error('the local service policy-operation response is malformed');
  }
  return {
    conversationId: requireHexIdentifier(
      requiredString(
        value,
        'conversation_id',
        'the local service policy conversation is malformed',
      ),
      conversationIdCharacters,
      'conversation identifier',
    ),
    proposalId: optionalIdentifier(
      value,
      'proposal_id',
      policyProposalIdCharacters,
      'proposal identifier',
    ),
    policyDigest: requireHexIdentifier(
      requiredString(value, 'policy_digest', 'the local service policy digest is malformed'),
      policyDigestCharacters,
      'policy digest',
    ),
    messageId: requireHexIdentifier(
      requiredString(value, 'message_id', 'the local service policy message is malformed'),
      messageIdCharacters,
      'message identifier',
    ),
    cursor: value.cursor,
    localBindingChanged: value.local_binding_changed,
  };
}

function parseCollaborationPolicyStatus(value: unknown): CollaborationPolicyStatusSummary {
  if (!isRecord(value)) {
    throw new Error('the local service policy-status response is malformed');
  }
  const conversationId = requireHexIdentifier(
    requiredString(value, 'conversation_id', 'the local service policy conversation is malformed'),
    conversationIdCharacters,
    'conversation identifier',
  );
  if (value.active_policy === null || value.active_policy === undefined) {
    return { conversationId, activePolicy: undefined };
  }
  if (!isRecord(value.active_policy)) {
    throw new Error('the local service active-policy response is malformed');
  }
  const active = value.active_policy;
  const bundle = parseCollaborationPolicyBundleSummary(active, 'guidance');
  return {
    conversationId,
    activePolicy: {
      ...bundle,
      policyDigest: requireHexIdentifier(
        requiredString(
          active,
          'policy_digest',
          'the local service active-policy digest is malformed',
        ),
        policyDigestCharacters,
        'policy digest',
      ),
      activatedAtUnixMilliseconds: requiredDecimalU64(
        active,
        'activated_at_unix_milliseconds',
        'the local service policy activation time is malformed',
      ),
    },
  };
}

function parseCollaborationPolicyProposalInspection(
  value: unknown,
): CollaborationPolicyProposalInspectionSummary {
  if (!isRecord(value)) {
    throw new Error('the local service policy-proposal inspection is malformed');
  }
  return {
    ...parseCollaborationPolicyBundleSummary(value, 'untrusted_guidance'),
    conversationId: requireHexIdentifier(
      requiredString(value, 'conversation_id', 'the inspected conversation is malformed'),
      conversationIdCharacters,
      'conversation identifier',
    ),
    proposalId: requireHexIdentifier(
      requiredString(value, 'proposal_id', 'the inspected proposal is malformed'),
      policyProposalIdCharacters,
      'proposal identifier',
    ),
    policyDigest: requireHexIdentifier(
      requiredString(value, 'policy_digest', 'the inspected policy digest is malformed'),
      policyDigestCharacters,
      'policy digest',
    ),
    replacesPolicyDigest: optionalIdentifier(
      value,
      'replaces_policy_digest',
      policyDigestCharacters,
      'replacement policy digest',
    ),
    proposerDeviceId: requireHexIdentifier(
      requiredString(value, 'proposer_device_id', 'the inspected proposer is malformed'),
      deviceIdCharacters,
      'proposer device identifier',
    ),
    messageId: requireHexIdentifier(
      requiredString(value, 'message_id', 'the inspected proposal message is malformed'),
      messageIdCharacters,
      'message identifier',
    ),
    relayCursor: requiredNonnegativeSafeInteger(
      value,
      'relay_cursor',
      'the inspected proposal cursor is malformed',
    ),
  };
}

function parseCollaborationPolicyBundleSummary(
  active: Readonly<Record<string, unknown>>,
  guidanceKey: 'guidance' | 'untrusted_guidance',
): CollaborationPolicyBundleSummary {
  if (
    !Array.isArray(active.statements) ||
    active.statements.length > 256 ||
    !Array.isArray(active.required_harness_claims) ||
    active.required_harness_claims.length > 64 ||
    !isRecord(active.limits)
  ) {
    throw new Error('the local service active-policy response is malformed');
  }
  const statements = active.statements.map((statement) => {
    if (
      !isRecord(statement) ||
      !['allow', 'deny', 'require_local_approval'].includes(String(statement.effect))
    ) {
      throw new Error('the local service policy statement is malformed');
    }
    const resource =
      statement.resource === null || statement.resource === undefined
        ? undefined
        : requiredBoundedString(
            statement,
            'resource',
            256,
            'the local service policy resource is malformed',
          );
    return {
      statementId: requiredBoundedString(
        statement,
        'statement_id',
        128,
        'the local service policy statement identifier is malformed',
      ),
      effect: statement.effect as CollaborationPolicyEffect,
      action: requiredBoundedString(
        statement,
        'action',
        256,
        'the local service policy action is malformed',
      ),
      resource,
    };
  });
  if (
    !active.required_harness_claims.every(
      (claim) => typeof claim === 'string' && Buffer.byteLength(claim, 'utf8') <= 256,
    )
  ) {
    throw new Error('the local service policy harness claims are malformed');
  }
  return {
    name: requiredBoundedString(active, 'name', 128, 'the local service policy name is malformed'),
    guidance:
      active[guidanceKey] === null || active[guidanceKey] === undefined
        ? undefined
        : requiredBoundedString(
            active,
            guidanceKey,
            32 * 1024,
            'the local service policy guidance is malformed',
          ),
    statements,
    requiredHarnessClaims: active.required_harness_claims,
    limits: {
      durationMilliseconds: optionalPositiveDecimalU64(
        active.limits,
        'duration_milliseconds',
        'the local service policy duration limit is malformed',
      ),
      turns: optionalPositiveDecimalU64(
        active.limits,
        'turns',
        'the local service policy turn limit is malformed',
      ),
      tokens: optionalPositiveDecimalU64(
        active.limits,
        'tokens',
        'the local service policy token limit is malformed',
      ),
      concurrentRequests: optionalPositiveSafeInteger(
        active.limits,
        'concurrent_requests',
        'the local service policy concurrency limit is malformed',
      ),
    },
  };
}

function requiredBoundedString(
  record: Readonly<Record<string, unknown>>,
  key: string,
  maximumBytes: number,
  error: string,
): string {
  const value = requiredString(record, key, error);
  if (Buffer.byteLength(value, 'utf8') === 0 || Buffer.byteLength(value, 'utf8') > maximumBytes) {
    throw new Error(error);
  }
  return value;
}

function requiredDecimalU64(
  record: Readonly<Record<string, unknown>>,
  key: string,
  error: string,
): string {
  const value = record[key];
  if (
    typeof value !== 'string' ||
    value.length > 20 ||
    !/^(0|[1-9][0-9]*)$/u.test(value) ||
    BigInt(value) > uint64Maximum
  ) {
    throw new Error(error);
  }
  return value;
}

function optionalPositiveDecimalU64(
  record: Readonly<Record<string, unknown>>,
  key: string,
  error: string,
): string | undefined {
  const value = record[key];
  if (value === null || value === undefined) {
    return undefined;
  }
  const parsed = requiredDecimalU64(record, key, error);
  if (parsed === '0') {
    throw new Error(error);
  }
  return parsed;
}

function optionalPositiveSafeInteger(
  record: Readonly<Record<string, unknown>>,
  key: string,
  error: string,
): number | undefined {
  const value = optionalNonnegativeSafeInteger(record, key, error);
  if (value === 0) {
    throw new Error(error);
  }
  return value;
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
      content: parseMessageContent(message),
      duplicate: message.duplicate,
    };
  });
  return { messages, hasMore: value.has_more };
}

function parseMessageContent(message: Record<string, unknown>): MessageContentSummary {
  switch (message.content_type) {
    case undefined:
    case 'text':
      if (typeof message.text !== 'string') {
        throw new Error('the local service message-list response is malformed');
      }
      return { kind: 'text', text: message.text };
    case 'directed_request':
      if (typeof message.text !== 'string') {
        throw new Error('the local service message-list response is malformed');
      }
      return {
        kind: 'directed-request',
        targetDeviceId: requireHexIdentifier(
          requiredString(
            message,
            'target_device_id',
            'the local service directed-request target is malformed',
          ),
          deviceIdCharacters,
          'directed-request target device identifier',
        ),
        text: message.text,
      };
    case 'collaboration_policy_proposal':
      return {
        kind: 'collaboration-policy-proposal',
        proposalId: policyIdentifier(message.proposal_id, policyProposalIdCharacters, 'proposal'),
        policyDigest: policyIdentifier(
          message.policy_digest,
          policyDigestCharacters,
          'policy digest',
        ),
        replacesPolicyDigest:
          message.replaces_policy_digest === null
            ? undefined
            : policyIdentifier(
                message.replaces_policy_digest,
                policyDigestCharacters,
                'replacement policy digest',
              ),
      };
    case 'collaboration_policy_response': {
      if (message.outcome !== 'accepted' && message.outcome !== 'rejected') {
        throw new Error('the local service message-list response is malformed');
      }
      return {
        kind: 'collaboration-policy-response',
        proposalId: policyIdentifier(message.proposal_id, policyProposalIdCharacters, 'proposal'),
        policyDigest: policyIdentifier(
          message.policy_digest,
          policyDigestCharacters,
          'policy digest',
        ),
        outcome: message.outcome,
      };
    }
    case 'collaboration_policy_revocation':
      return {
        kind: 'collaboration-policy-revocation',
        policyDigest: policyIdentifier(
          message.policy_digest,
          policyDigestCharacters,
          'policy digest',
        ),
      };
    default:
      throw new Error('the local service message-list response is malformed');
  }
}

function policyIdentifier(value: unknown, length: number, label: string): string {
  if (typeof value !== 'string') {
    throw new Error('the local service message-list response is malformed');
  }
  return requireHexIdentifier(value, length, label);
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

function policyRequestId(operation: string, conversationId: string, identifier: string): Buffer {
  return createHash('sha256')
    .update(commandPolicyRequestDomain)
    .update(operation)
    .update('\0')
    .update(Buffer.from(conversationId, 'hex'))
    .update(Buffer.from(identifier, 'hex'))
    .digest()
    .subarray(0, 16);
}

function parsePolicySourceArguments(
  raw: string,
  minimumIdentifiers: number,
  maximumIdentifiers: number,
  usage: string,
): { readonly identifiers: readonly string[]; readonly sourcePath: string } {
  const separator = /(?:^|\s+)--\s+/u.exec(raw);
  if (!separator) {
    throw new Error(`usage: ${usage}`);
  }
  const identifiers = parseCommandArguments(raw.slice(0, separator.index));
  requireArgumentCount(identifiers, minimumIdentifiers, maximumIdentifiers, usage);
  const sourcePath = raw.slice(separator.index + separator[0].length).trim();
  const sourcePathBytes = Buffer.byteLength(sourcePath, 'utf8');
  if (
    sourcePathBytes === 0 ||
    sourcePathBytes > maxPolicySourcePathBytes ||
    /[\p{Cc}\p{Cf}]/u.test(sourcePath)
  ) {
    throw new Error(`policy source path must contain 1-${maxPolicySourcePathBytes} UTF-8 bytes`);
  }
  return { identifiers, sourcePath };
}

/**
 * Reads one physical UTF-8 policy source confined beneath an explicit workspace.
 *
 * @throws When the path is absolute, escapes through traversal or links, is not a
 * regular file, exceeds the source bound, or is not valid UTF-8.
 */
export async function readBoundedPolicySource(
  sourcePath: string,
  options: PolicySourceReadOptions = {},
): Promise<string> {
  if (isAbsolute(sourcePath)) {
    throw new Error('policy source path must be relative to the current workspace');
  }
  const root = await realpath(options.workspace ?? process.cwd());
  const requestedPath = resolve(root, sourcePath);
  const candidate = await confinedRealPath(root, requestedPath);
  const initialMetadata = await stat(candidate, { bigint: true });
  requirePolicySourceMetadata(initialMetadata);
  await options.afterInitialIdentity?.();
  const handle = await open(candidate, 'r');
  try {
    const openedMetadata = await handle.stat({ bigint: true });
    requirePolicySourceMetadata(openedMetadata);
    requireSamePolicySource(initialMetadata, openedMetadata);
    const bytes = Buffer.allocUnsafe(maxPolicySourceBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = await handle.read(bytes, length, bytes.length - length, length);
      if (read.bytesRead === 0) {
        break;
      }
      length += read.bytesRead;
    }
    if (length > maxPolicySourceBytes) {
      throw new Error(`policy source exceeds ${maxPolicySourceBytes} bytes`);
    }
    const completedMetadata = await handle.stat({ bigint: true });
    requireSamePolicySource(openedMetadata, completedMetadata);
    const finalCandidate = await confinedRealPath(root, requestedPath);
    if (finalCandidate !== candidate) {
      throw new Error('policy source changed while it was being read');
    }
    const finalMetadata = await stat(finalCandidate, { bigint: true });
    requireSamePolicySource(completedMetadata, finalMetadata);
    try {
      return requireBoundedPolicySource(
        new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)),
      );
    } catch {
      throw new Error('policy source must be valid UTF-8');
    }
  } finally {
    await handle.close();
  }
}

async function confinedRealPath(root: string, requestedPath: string): Promise<string> {
  const candidate = await realpath(requestedPath);
  const relativePath = relative(root, candidate);
  if (
    relativePath.length === 0 ||
    relativePath === '..' ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  ) {
    throw new Error('policy source path resolves outside the current workspace');
  }
  return candidate;
}

function requirePolicySourceMetadata(metadata: BigIntStats): void {
  if (!metadata.isFile()) {
    throw new Error('policy source must be a regular file');
  }
  if (metadata.size > BigInt(maxPolicySourceBytes)) {
    throw new Error(`policy source exceeds ${maxPolicySourceBytes} bytes`);
  }
}

function requireSamePolicySource(expected: BigIntStats, actual: BigIntStats): void {
  if (
    expected.dev !== actual.dev ||
    expected.ino !== actual.ino ||
    expected.size !== actual.size ||
    expected.mtimeNs !== actual.mtimeNs ||
    expected.ctimeNs !== actual.ctimeNs
  ) {
    throw new Error('policy source changed while it was being read');
  }
}

function requireBoundedPolicySource(source: string): string {
  if (Buffer.byteLength(source, 'utf8') > maxPolicySourceBytes) {
    throw new Error(`policy source exceeds ${maxPolicySourceBytes} bytes`);
  }
  return source;
}

function formatPolicyLimit(value: string | number | undefined): string {
  return value === undefined ? 'unlimited' : String(value);
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
  presentation: CommandPresentation,
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
          await presentation.detail(`connect phase: ${status.phase}`);
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
        await presentation.detail(`connect phase: ${status.phase}`);
      } else {
        await sleep(connectPollMilliseconds);
      }
    }

    throw new Error(`connect exceeded its progress limit for pairing ${status.pairingId}`);
  } catch (error) {
    await presentation.write(`recovery: /konclave pairing ${status.pairingId}`);
    if (status.phase === 'cancelled') {
      await presentation.write('next: run /konclave connect to start a new pairing');
    } else {
      await presentation.write(`cancel: /konclave cancel ${status.pairingId}`);
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

function displayCompleteText(value: string): string[] {
  const safe = value.replace(/[\p{Cf}\p{Zl}\p{Zp}]/gu, '\uFFFD');
  const characters = Array.from(safe);
  const chunks: string[] = [];
  for (let offset = 0; offset < characters.length; offset += maxDisplayedMessageCharacters) {
    chunks.push(
      JSON.stringify(characters.slice(offset, offset + maxDisplayedMessageCharacters).join('')),
    );
  }
  return chunks.length === 0 ? ['""'] : chunks;
}

function displayMessageContent(message: MessageSummary): string {
  const source = message.direction === 'inbound' ? 'untrusted peer' : 'local';
  switch (message.content.kind) {
    case 'text':
      return `${message.direction === 'inbound' ? 'untrusted peer text' : 'local message text'}: ${displayText(message.content.text)}`;
    case 'directed-request':
      return (
        `${source} directed request to ${message.content.targetDeviceId}: ` +
        displayText(message.content.text)
      );
    case 'collaboration-policy-proposal': {
      const replacement =
        message.content.replacesPolicyDigest === undefined
          ? ''
          : `, replacing ${message.content.replacesPolicyDigest}`;
      return (
        `${source} policy proposal: ${message.content.proposalId}, digest ` +
        `${message.content.policyDigest}${replacement}; receipt does not activate local authority`
      );
    }
    case 'collaboration-policy-response':
      return (
        `${source} policy response: proposal ${message.content.proposalId}, digest ` +
        `${message.content.policyDigest}, reported ${message.content.outcome}`
      );
    case 'collaboration-policy-revocation':
      return `${source} policy revocation: digest ${message.content.policyDigest}`;
  }
}

async function renderPairing(
  presentation: CommandPresentation,
  status: PairingStatus,
): Promise<void> {
  if (presentation.mode === 'normal') {
    await presentation.write(
      `pairing ${status.pairingId}: ${status.phase}${
        status.conversationId ? `; conversation ${status.conversationId}` : ''
      }`,
    );
    return;
  }
  await presentation.write(`pairing: ${status.pairingId}`);
  await presentation.write(`local role: ${status.localRole}`);
  await presentation.write(`phase: ${status.phase}`);
  await presentation.write(`joiner device: ${status.joinerDeviceId}`);
  await presentation.write(`requested role: ${status.requestedRole}`);
  if (status.inviterDeviceId) {
    await presentation.write(`inviter device: ${status.inviterDeviceId}`);
  }
  if (status.grantedRole) {
    await presentation.write(`granted role: ${status.grantedRole}`);
  }
  if (status.conversationId) {
    await presentation.write(`conversation: ${status.conversationId}`);
  }
}

async function renderCollaborationPolicyOperation(
  presentation: CommandPresentation,
  operation: CollaborationPolicyOperationSummary,
): Promise<void> {
  if (presentation.mode === 'normal') {
    await presentation.write(
      `policy operation complete: ${operation.policyDigest}${
        operation.proposalId ? `; proposal ${operation.proposalId}` : ''
      }`,
    );
    return;
  }
  await presentation.write(`conversation: ${operation.conversationId}`);
  if (operation.proposalId) {
    await presentation.write(`proposal id: ${operation.proposalId}`);
  }
  await presentation.write(`policy digest: ${operation.policyDigest}`);
  await presentation.write(`message id: ${operation.messageId}`);
  await presentation.write(`relay cursor: ${operation.cursor}`);
  await presentation.write(
    `local binding changed: ${operation.localBindingChanged ? 'yes' : 'no (idempotent retry)'}`,
  );
}

async function renderCollaborationPolicyStatus(
  presentation: CommandPresentation,
  status: CollaborationPolicyStatusSummary,
): Promise<void> {
  const active = status.activePolicy;
  if (presentation.mode === 'normal') {
    await presentation.write(
      active
        ? `policy ${active.name}: ${active.policyDigest}`
        : `policy inactive: conversation ${status.conversationId}`,
    );
    return;
  }
  await presentation.write(`conversation: ${status.conversationId}`);
  if (!active) {
    await presentation.write('policy: inactive');
    return;
  }
  await presentation.write(`policy: ${bounded(active.name, 128)}`);
  await presentation.write(`policy digest: ${active.policyDigest}`);
  await presentation.write(`activated at: ${active.activatedAtUnixMilliseconds}`);
  await renderCollaborationPolicyBundle(presentation, active, false);
}

async function renderCollaborationPolicyProposalInspection(
  presentation: CommandPresentation,
  proposal: CollaborationPolicyProposalInspectionSummary,
): Promise<void> {
  await presentation.write(`conversation: ${proposal.conversationId}`);
  await presentation.write(`proposal id: ${proposal.proposalId}`);
  await presentation.write(`policy digest: ${proposal.policyDigest}`);
  if (proposal.replacesPolicyDigest) {
    await presentation.write(`replaces policy digest: ${proposal.replacesPolicyDigest}`);
  }
  await presentation.write(`proposer device: ${proposal.proposerDeviceId}`);
  await presentation.write(`proposal message: ${proposal.messageId}`);
  await presentation.write(`relay cursor: ${proposal.relayCursor}`);
  await presentation.write(`peer-proposed policy: ${bounded(proposal.name, 128)}`);
  await presentation.write('peer-proposed semantics (UNTRUSTED until explicitly accepted):');
  await renderCollaborationPolicyBundle(presentation, proposal, true);
  if (proposal.guidance) {
    await presentation.write('peer-proposed guidance (UNTRUSTED; review as data):');
    for (const chunk of displayCompleteText(proposal.guidance)) {
      await presentation.write(chunk, { ephemeral: true });
    }
  }
  await presentation.write(
    `accept only after review: /konclave policy accept ${proposal.proposalId} ${proposal.policyDigest}`,
  );
  await presentation.write(
    `reject: /konclave policy reject ${proposal.proposalId} ${proposal.policyDigest}`,
  );
}

async function renderCollaborationPolicyBundle(
  presentation: CommandPresentation,
  bundle: CollaborationPolicyBundleSummary,
  complete: boolean,
): Promise<void> {
  if (!complete && presentation.mode === 'normal') {
    return;
  }
  await presentation.write(
    `required harness claims: ${
      bundle.requiredHarnessClaims.length === 0
        ? 'none'
        : bundle.requiredHarnessClaims.map((claim) => bounded(claim, 256)).join(', ')
    }`,
  );
  await presentation.write(
    `limits: duration ${formatPolicyLimit(bundle.limits.durationMilliseconds)}, turns ${formatPolicyLimit(bundle.limits.turns)}, tokens ${formatPolicyLimit(bundle.limits.tokens)}, concurrent requests ${formatPolicyLimit(bundle.limits.concurrentRequests)}`,
  );
  const statements = complete
    ? bundle.statements
    : bundle.statements.slice(0, maxDisplayedPolicyStatements);
  for (const statement of statements) {
    await presentation.write(
      `statement ${bounded(statement.statementId, 128)}: ${statement.effect} ${bounded(statement.action, 256)}${
        statement.resource ? ` ${bounded(statement.resource, 256)}` : ''
      }`,
    );
  }
  if (!complete && bundle.statements.length > maxDisplayedPolicyStatements) {
    await presentation.write(
      `${bundle.statements.length - maxDisplayedPolicyStatements} additional statements omitted`,
    );
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
  const presentation = createCommandPresentation(output, dependencies.outputMode ?? 'normal');
  const nowUnixMilliseconds = dependencies.nowUnixMilliseconds ?? Date.now;
  const sleep = dependencies.sleep ?? defaultSleep;
  const readPolicySource = dependencies.readPolicySource ?? readBoundedPolicySource;
  let activeConversationId: string | undefined;

  const runPolicy = async (raw: string): Promise<void> => {
    const parsed = parseCommand(raw);
    if (parsed.subcommand === 'help') {
      requireNoArguments(parsed.argumentsText, 'policy help');
      for (const line of policyHelpLines) {
        await output.write(line);
      }
      return;
    }
    const conversationId = await requireSingleConversation(client, activeConversationId);
    activeConversationId = conversationId;

    switch (parsed.subcommand) {
      case 'status': {
        requireNoArguments(parsed.argumentsText, 'policy status');
        const status = parseCollaborationPolicyStatus(
          await client.request('get_collaboration_policy_status', {
            conversation_id: conversationId,
          }),
        );
        if (status.conversationId !== conversationId) {
          throw new Error('the local service policy status targets a different conversation');
        }
        await renderCollaborationPolicyStatus(presentation, status);
        return;
      }
      case 'propose':
      case 'replace': {
        const replacing = parsed.subcommand === 'replace';
        const usage = replacing
          ? '/konclave policy replace <digest> [proposal-id] -- <relative-source>'
          : '/konclave policy propose [proposal-id] -- <relative-source>';
        const sourceArguments = parsePolicySourceArguments(
          parsed.argumentsText,
          replacing ? 1 : 0,
          replacing ? 2 : 1,
          usage,
        );
        const replacesPolicyDigest = replacing
          ? requireHexIdentifier(
              sourceArguments.identifiers[0],
              policyDigestCharacters,
              'policy digest',
            )
          : undefined;
        const suppliedProposalId = sourceArguments.identifiers[replacing ? 1 : 0];
        const proposalId = suppliedProposalId
          ? requireHexIdentifier(
              suppliedProposalId,
              policyProposalIdCharacters,
              'proposal identifier',
            )
          : randomBytes(16).toString('hex');
        const source = requireBoundedPolicySource(
          await readPolicySource(sourceArguments.sourcePath),
        );
        if (presentation.mode === 'normal') {
          await presentation.write(
            `policy proposal ${proposalId}; resume an ambiguous attempt with /konclave policy resume ${proposalId}`,
          );
        } else {
          await presentation.write(`proposal id: ${proposalId}`);
          await presentation.write(
            `recovery after ambiguous failure: /konclave policy resume ${proposalId}; validation failure or edit requires a new proposal id`,
          );
        }
        const payload: Record<string, unknown> = {
          conversation_id: conversationId,
          proposal_id: proposalId,
          source,
        };
        if (replacesPolicyDigest) {
          payload.replaces_policy_digest = replacesPolicyDigest;
        }
        const operation = parseCollaborationPolicyOperation(
          await client.request('propose_collaboration_policy_source', payload, {
            requestId: policyRequestId('propose', conversationId, proposalId),
          }),
        );
        if (operation.conversationId !== conversationId || operation.proposalId !== proposalId) {
          throw new Error('the local service policy proposal identity does not match the request');
        }
        await renderCollaborationPolicyOperation(presentation, operation);
        return;
      }
      case 'resume': {
        const parts = parseCommandArguments(parsed.argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave policy resume <proposal-id>');
        const proposalId = requireHexIdentifier(
          parts[0],
          policyProposalIdCharacters,
          'proposal identifier',
        );
        const operation = parseCollaborationPolicyOperation(
          await client.request(
            'resume_collaboration_policy_proposal',
            {
              conversation_id: conversationId,
              proposal_id: proposalId,
            },
            {
              requestId: policyRequestId('resume', conversationId, proposalId),
            },
          ),
        );
        if (operation.conversationId !== conversationId || operation.proposalId !== proposalId) {
          throw new Error('the resumed policy proposal identity does not match the request');
        }
        await renderCollaborationPolicyOperation(presentation, operation);
        return;
      }
      case 'inspect': {
        const parts = parseCommandArguments(parsed.argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave policy inspect <proposal-id>');
        const proposalId = requireHexIdentifier(
          parts[0],
          policyProposalIdCharacters,
          'proposal identifier',
        );
        const proposal = parseCollaborationPolicyProposalInspection(
          await client.request('inspect_collaboration_policy_proposal', {
            conversation_id: conversationId,
            proposal_id: proposalId,
          }),
        );
        if (proposal.conversationId !== conversationId || proposal.proposalId !== proposalId) {
          throw new Error('the inspected policy proposal identity does not match the request');
        }
        await renderCollaborationPolicyProposalInspection(presentation, proposal);
        return;
      }
      case 'accept':
      case 'reject': {
        const parts = parseCommandArguments(parsed.argumentsText);
        requireArgumentCount(
          parts,
          2,
          2,
          `/konclave policy ${parsed.subcommand} <proposal-id> <digest>`,
        );
        const proposalId = requireHexIdentifier(
          parts[0],
          policyProposalIdCharacters,
          'proposal identifier',
        );
        const policyDigest = requireHexIdentifier(
          parts[1],
          policyDigestCharacters,
          'policy digest',
        );
        const operationName =
          parsed.subcommand === 'accept'
            ? 'accept_collaboration_policy'
            : 'reject_collaboration_policy';
        const operation = parseCollaborationPolicyOperation(
          await client.request(
            operationName,
            {
              conversation_id: conversationId,
              proposal_id: proposalId,
              policy_digest: policyDigest,
            },
            {
              requestId: policyRequestId(parsed.subcommand, conversationId, proposalId),
            },
          ),
        );
        if (
          operation.conversationId !== conversationId ||
          operation.proposalId !== proposalId ||
          operation.policyDigest !== policyDigest
        ) {
          throw new Error('the local service policy response identity does not match the request');
        }
        await renderCollaborationPolicyOperation(presentation, operation);
        return;
      }
      case 'revoke': {
        const parts = parseCommandArguments(parsed.argumentsText);
        requireArgumentCount(parts, 1, 2, '/konclave policy revoke <digest> [message-id]');
        const policyDigest = requireHexIdentifier(
          parts[0],
          policyDigestCharacters,
          'policy digest',
        );
        const messageId = parts[1]
          ? requireHexIdentifier(parts[1], messageIdCharacters, 'message identifier')
          : randomBytes(16).toString('hex');
        if (presentation.mode === 'normal') {
          await presentation.write(
            `policy revocation ${messageId}; reuse this identifier to retry`,
          );
        } else {
          await presentation.write(`message id: ${messageId}`);
          await presentation.write(`retry: /konclave policy revoke ${policyDigest} ${messageId}`);
        }
        const operation = parseCollaborationPolicyOperation(
          await client.request(
            'revoke_collaboration_policy',
            {
              conversation_id: conversationId,
              message_id: messageId,
              policy_digest: policyDigest,
            },
            {
              requestId: policyRequestId('revoke', conversationId, messageId),
            },
          ),
        );
        if (
          operation.conversationId !== conversationId ||
          operation.proposalId !== undefined ||
          operation.policyDigest !== policyDigest ||
          operation.messageId !== messageId
        ) {
          throw new Error(
            'the local service policy revocation identity does not match the request',
          );
        }
        await renderCollaborationPolicyOperation(presentation, operation);
        return;
      }
      default:
        throw new Error(`unknown policy subcommand: ${bounded(parsed.subcommand, 24)}`);
    }
  };

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
      case 'output': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave output <normal|verbose>');
        const mode = parts[0];
        if (mode !== 'normal' && mode !== 'verbose') {
          throw new Error('output mode must be normal or verbose');
        }
        presentation.setMode(mode);
        await presentation.write(`output: ${mode}`);
        return;
      }
      case 'status': {
        requireNoArguments(argumentsText, subcommand);
        const status = parseServiceStatus(await client.request(serviceOperations.status, {}));
        if (presentation.mode === 'normal') {
          await presentation.write(
            `status: relay ${status.relayConfigured ? 'configured' : 'not configured'}; delivery ${
              status.deliveryDegraded ? 'degraded' : 'healthy'
            }; authorization ${bounded(status.authorizationPolicy)}${
              status.authorizationPolicy === 'AccountTrusted' ? ' (same-account trust)' : ''
            }; pending ${status.pendingEvents}`,
          );
          return;
        }
        await presentation.write(`profile: ${bounded(status.profile)}`);
        await presentation.write(`device: ${bounded(status.deviceId)}`);
        await presentation.write(`relay configured: ${status.relayConfigured ? 'yes' : 'no'}`);
        await presentation.write(
          `authorization: ${bounded(status.authorizationPolicy)} (${status.authorizationEvidence.map((item) => bounded(item)).join('+')})`,
        );
        await presentation.write(
          `authorization provider: ${bounded(status.authorizationProvider)}`,
        );
        if (status.authorizationPolicy === 'AccountTrusted') {
          await presentation.write(
            'authorization boundary: same-account processes are trusted; no same-user isolation',
          );
        }
        await presentation.write(
          `grant: expires ${status.grantExpiresAtUnixMilliseconds}, capabilities ${status.grantCapabilities}`,
        );
        await presentation.write(
          `grant capacity: global ${status.activeGrants}/${status.grantLimit}, issuer ${status.activeGrantsForIssuer}/${status.grantLimitPerIssuer}, profile ${status.activeGrantsForProfile}/${status.grantLimitPerProfile}`,
        );
        await presentation.write(
          `delivery: ${status.deliveryDegraded ? 'degraded' : 'healthy'}, watching ${status.watchedConversations}, pending ${status.pendingEvents}, claimed ${status.claimedEvents}`,
        );
        return;
      }
      case 'identity': {
        requireNoArguments(argumentsText, subcommand);
        const deviceId = identity(await client.request('get_identity', {}));
        await presentation.write(`device: ${bounded(deviceId)}`);
        return;
      }
      case 'conversations': {
        requireNoArguments(argumentsText, subcommand);
        const selection = conversations(await client.request('list_conversations', {}));
        activeConversationId = selection.activeConversationId;
        if (selection.conversationIds.length === 0) {
          await presentation.write(
            presentation.mode === 'normal' ? 'conversations: none' : 'no conversations yet',
          );
          return;
        }
        if (presentation.mode === 'normal') {
          if (selection.conversationIds.length === 1) {
            await presentation.write(
              `conversation: ${selection.conversationIds[0]}${
                selection.activeConversationId ? ' (active)' : ''
              }`,
            );
          } else {
            await presentation.write(
              `conversations: ${selection.conversationIds.length}; active ${
                selection.activeConversationId ?? 'none'
              }; use /konclave output verbose to list all`,
            );
          }
          return;
        }
        if (selection.activeConversationId) {
          await presentation.write(`active: ${selection.activeConversationId}`);
        }
        for (const conversation of selection.conversationIds.slice(0, 20)) {
          await presentation.write(bounded(conversation));
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
          await presentation.detail(
            'approval policy: AccountTrusted capability possession; no independent identity verification',
          );
          await presentation.detail(`pairing: ${created.pairing.pairingId}`);
          await presentation.detail(`recovery: /konclave pairing ${created.pairing.pairingId}`);
          await presentation.detail(`cancel: /konclave cancel ${created.pairing.pairingId}`);
          await presentation.write(
            presentation.mode === 'normal'
              ? `pairing ${created.pairing.pairingId} (same-account trust): paste this capability in the other session`
              : 'capability (ephemeral; paste the next line in the other session):',
          );
          await presentation.write(created.capability, { ephemeral: true });
          await presentation.detail(
            'waiting for the other session to run /konclave connect <capability>',
          );
          status = await completeAccountTrustedPairing(
            client,
            created.pairing,
            presentation,
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
          await presentation.detail(
            'approval policy: AccountTrusted capability possession; no independent identity verification',
          );
          await presentation.detail(`pairing: ${redeemed.pairingId}`);
          await presentation.detail(`recovery: /konclave pairing ${redeemed.pairingId}`);
          await presentation.detail(`cancel: /konclave cancel ${redeemed.pairingId}`);
          if (presentation.mode === 'normal') {
            await presentation.write(
              `pairing ${redeemed.pairingId} (same-account trust): connecting`,
            );
          }
          const conversationId = parseConversation(await client.request('create_conversation', {}));
          await presentation.detail(`conversation: ${conversationId}`);
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
            presentation,
            commandDeadline,
            nowUnixMilliseconds,
            sleep,
          );
        }
        if (!status.conversationId) {
          throw new Error('completed pairing is missing its conversation');
        }
        activeConversationId = status.conversationId;
        if (presentation.mode === 'verbose') {
          await renderPairing(presentation, status);
        }
        await presentation.write(`connected: ${status.conversationId}`);
        await presentation.detail('next: /konclave send -- <message>');
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
        await renderPairing(presentation, created.pairing);
        await presentation.write(
          presentation.mode === 'normal'
            ? 'capability:'
            : 'capability (ephemeral; copy the next line now):',
        );
        await presentation.write(created.capability, { ephemeral: true });
        await presentation.detail('next: run /konclave join <capability> in the other session');
        return;
      }
      case 'join': {
        const capability = requirePairingCapability(argumentsText);
        const status = parsePairingStatus(
          await client.request('redeem_pairing_capability', { capability }),
        );
        await renderPairing(presentation, status);
        await presentation.write(
          `next: verify the joiner device, run /konclave new, then /konclave approve ${status.pairingId} <conversation>`,
        );
        return;
      }
      case 'new': {
        requireNoArguments(argumentsText, subcommand);
        const conversationId = parseConversation(await client.request('create_conversation', {}));
        activeConversationId = conversationId;
        await presentation.write(`conversation created: ${conversationId}`);
        await presentation.detail(
          'conversation created durably; it remains if the pending pairing is abandoned',
        );
        await presentation.detail(
          'next: use this conversation when approving an inviter-side pairing or sending a message',
        );
        return;
      }
      case 'pairing': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave pairing <pairing>');
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        await renderPairing(
          presentation,
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
        await renderPairing(presentation, approved);
        await presentation.write(`next: run /konclave sync ${pairingId} in both sessions`);
        return;
      }
      case 'sync': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave sync <pairing>');
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        const synced = parsePairingSync(
          await client.request('sync_pairing', { pairing_id: pairingId }),
        );
        await presentation.detail(`processed pairing records: ${synced.processedRecords}`);
        await renderPairing(presentation, synced.pairing);
        return;
      }
      case 'cancel': {
        const parts = parseCommandArguments(argumentsText);
        requireArgumentCount(parts, 1, 1, '/konclave cancel <pairing>');
        const pairingId = requireHexIdentifier(parts[0], pairingIdCharacters, 'pairing identifier');
        await renderPairing(
          presentation,
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
        if (presentation.mode === 'normal') {
          await presentation.write(`message ${messageId}: sending; reuse this identifier to retry`);
        } else {
          await presentation.write(`message id: ${messageId}`);
          await presentation.write(
            `retry: /konclave ${subcommand} ${conversationId}${replyToMessageId ? ` ${replyToMessageId}` : ''} ${messageId} -- <same text>`,
          );
        }
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
        if (presentation.mode === 'normal') {
          await presentation.write(
            `sent ${sent.messageId}: conversation ${sent.conversationId}; cursor ${sent.cursor}`,
          );
        } else {
          await presentation.write(`conversation: ${sent.conversationId}`);
          await presentation.write(`relay cursor: ${sent.cursor}`);
        }
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
        await presentation.detail(
          `synced messages: ${synced.messages.length}, more available: ${synced.hasMore ? 'yes' : 'no'}`,
        );
        if (history.messages.length === 0) {
          await presentation.write('messages: none after the requested cursor');
          return;
        }
        for (const message of history.messages) {
          await presentation.detail(
            `message ${message.messageId}: ${message.direction}, sender ${message.senderDeviceId}, cursor ${message.cursor}, duplicate ${message.duplicate ? 'yes' : 'no'}`,
          );
          await presentation.write(displayMessageContent(message), { ephemeral: true });
        }
        const lastCursor = history.messages.at(-1)?.cursor;
        if (lastCursor !== undefined) {
          if (presentation.mode === 'normal') {
            await presentation.write(
              `messages: ${history.messages.length}; resume cursor ${lastCursor}${
                history.hasMore ? '; more available' : ''
              }`,
            );
          } else {
            await presentation.write(`resume after cursor: ${lastCursor}`);
            await presentation.write(`next: /konclave messages ${conversationId} ${lastCursor}`);
          }
        }
        if (history.hasMore && presentation.mode === 'verbose') {
          await presentation.write('more messages are available');
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
        await presentation.write(`active conversation selected: ${conversation}`);
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
        await presentation.write(
          `automatic delivery ${subcommand === 'unmute' ? 'resumed' : 'muted'} for ${bounded(conversation)}`,
        );
        return;
      }
      case 'policy':
        await runPolicy(argumentsText);
        return;
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
