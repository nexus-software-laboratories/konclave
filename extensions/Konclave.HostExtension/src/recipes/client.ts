import { createHash } from 'node:crypto';

import type { LocalServiceClient, LocalServiceRequestOptions } from '../service/client.js';
import { recipeDataProperty, RecipeDefinitionError, requireRecipeRecord } from './definition.js';
import {
  isRecipeCursor,
  readRecipePage,
  recipeHistoryPageSize,
  selectRecipeReply,
  validateRecipeMessageText,
  type RecipeReply,
  type RecipeReplyPage,
} from './reply.js';
import {
  decodeRecipeRun,
  recipeMessageId,
  RecipeRunError,
  type RecipeBinding,
  type RecipeRun,
} from './run.js';

/** Cancellation controls I/O; it never retracts an already committed message. */
export type RecipeCallOptions = Pick<LocalServiceRequestOptions, 'signal' | 'deadlineMs'>;

/** Observed native submission, not evidence that the target executed or answered. */
export interface RecipeSubmission {
  readonly bindingName: string;
  readonly messageId: string;
  readonly cursor: number;
  readonly senderCounter: number;
}

/**
 * Restricted composition affordance for an already authorized authenticated client.
 * It is not a sandbox for provider code or a replacement for native permissions.
 */
export interface RecipeMessaging {
  readonly run: RecipeRun;
  send(bindingName: string, text: string, options?: RecipeCallOptions): Promise<RecipeSubmission>;
  poll(bindingName: string, options?: RecipeCallOptions): Promise<RecipeReplyPage>;
}

interface SubmittedSlot {
  readonly submission: RecipeSubmission;
  cursor: number;
  reply?: RecipeReply;
  polling: boolean;
}

function response<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof RecipeDefinitionError) {
      throw new RecipeRunError('invalid_response');
    }
    throw error;
  }
}

function readOptions(options: RecipeCallOptions | undefined): LocalServiceRequestOptions {
  return { signal: options?.signal, deadlineMs: options?.deadlineMs };
}

function submission(value: unknown, binding: RecipeBinding, messageId: string): RecipeSubmission {
  return response(() => {
    requireRecipeRecord(value, ['conversation_id', 'message_id', 'sender_counter', 'cursor']);
    const cursor = recipeDataProperty(value, 'cursor');
    const counter = recipeDataProperty(value, 'sender_counter');
    if (
      recipeDataProperty(value, 'conversation_id') !== binding.conversationId ||
      recipeDataProperty(value, 'message_id') !== messageId ||
      !isRecipeCursor(cursor) ||
      cursor === 0 ||
      !isRecipeCursor(counter) ||
      counter === 0
    ) {
      throw new RecipeRunError('invalid_response');
    }
    return Object.freeze({
      bindingName: binding.name,
      messageId,
      cursor,
      senderCounter: counter,
    });
  });
}

/**
 * Connects exact, caller-approved run data to existing native messaging operations.
 * The caller supplies the appropriate paved or Generic lifecycle and permissions.
 * Each selected slot owns one stable message ID. No grants, policy, membership,
 * mute settings, provider code or profile selection are changed here.
 *
 * send retries unknown outcomes only when explicitly called again with the same
 * descriptor and bytes; native journaling owns durable idempotency across restart.
 * poll performs at most one bounded history read, one watch and a final history
 * read. It returns pending rather than inventing remote completion or cancellation.
 * No data is persisted, printed or exported by the adapter.
 *
 * @throws {RecipeRunError} For an unpinned run, wrong profile, undeclared slot,
 * changed successful request, concurrent slot work or malformed service evidence.
 * Native service/transport errors propagate without fallback.
 */
export function createRecipeMessaging(
  client: LocalServiceClient,
  descriptor: unknown,
  expectedRunId: unknown,
): RecipeMessaging {
  const run = decodeRecipeRun(descriptor, expectedRunId);
  const slots = new Map<string, SubmittedSlot>();
  const selectedBodies = new Map<string, string>();
  const sending = new Set<string>();

  const requireProfile = () => {
    if (client.profile !== run.profile) {
      throw new RecipeRunError('profile_mismatch');
    }
  };
  requireProfile();

  const selectedBinding = (name: string): RecipeBinding => {
    const selected = run.bindings.find((item) => item.name === name);
    if (!selected) {
      throw new RecipeRunError('unknown_binding');
    }
    return selected;
  };

  const observe = async (
    binding: RecipeBinding,
    slot: SubmittedSlot,
    options: RecipeCallOptions | undefined,
  ): Promise<RecipeReplyPage> => {
    requireProfile();
    const value = await client.request(
      'read_messages',
      {
        conversation_id: binding.conversationId,
        after_cursor: slot.cursor,
        limit: 1,
      },
      readOptions(options),
    );
    const page = selectRecipeReply(value, binding, slot.submission.messageId, slot.cursor, 1);
    if (page.kind === 'reply') {
      slot.reply = page;
    } else {
      slot.cursor = page.afterCursor;
    }
    return page;
  };

  return Object.freeze({
    run,
    async send(name: string, text: string, options?: RecipeCallOptions) {
      requireProfile();
      const binding = selectedBinding(name);
      const body = validateRecipeMessageText(text);
      const textDigest = createHash('sha256').update(body, 'utf8').digest('hex');
      const selectedBody = selectedBodies.get(name);
      if (selectedBody !== undefined && selectedBody !== textDigest) {
        throw new RecipeRunError('slot_conflict');
      }
      selectedBodies.set(name, textDigest);
      const existing = slots.get(name);
      if (existing) {
        return existing.submission;
      }
      if (sending.has(name)) {
        throw new RecipeRunError('busy');
      }
      sending.add(name);
      try {
        const messageId = recipeMessageId(run, name);
        const requestId = createHash('sha256')
          .update('konclave.recipe-local-request.v1\0')
          .update(Buffer.from(run.runId, 'hex'))
          .update(name, 'utf8')
          .digest()
          .subarray(0, 16);
        const value = await client.request(
          'send_directed_request',
          {
            conversation_id: binding.conversationId,
            message_id: messageId,
            target_device_id: binding.targetDeviceId,
            text: body,
          },
          { ...readOptions(options), requestId },
        );
        const sent = submission(value, binding, messageId);
        slots.set(name, { submission: sent, cursor: sent.cursor, polling: false });
        return sent;
      } finally {
        sending.delete(name);
      }
    },
    async poll(name: string, options?: RecipeCallOptions) {
      requireProfile();
      const binding = selectedBinding(name);
      const slot = slots.get(name);
      if (!slot) {
        throw new RecipeRunError('request_not_submitted');
      }
      if (slot.reply) {
        return slot.reply;
      }
      if (slot.polling) {
        throw new RecipeRunError('busy');
      }
      slot.polling = true;
      try {
        const first = await observe(binding, slot, options);
        if (first.kind === 'reply' || first.hasMore) {
          return first;
        }
        requireProfile();
        const watched = await client.request(
          'watch_messages',
          { conversation_id: binding.conversationId },
          readOptions(options),
        );
        response(() => readRecipePage(watched, recipeHistoryPageSize));
        return await observe(binding, slot, options);
      } finally {
        slot.polling = false;
      }
    },
  });
}
