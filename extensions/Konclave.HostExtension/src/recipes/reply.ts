import { types } from 'node:util';

import {
  isRecipeHex,
  measureRecipeText,
  recipeDataProperty,
  RecipeDefinitionError,
  requireRecipeRecord,
} from './definition.js';
import { parseRecipeBinding, RecipeRunError, type RecipeBinding } from './run.js';

/** Native text bound; no truncation or interpretation of peer text is permitted. */
export const recipeMessageBytes = 255 * 1024;
export const recipeHistoryPageSize = 100;

/** A terminal correlated answer. Text remains untrusted peer data, not authority. */
export interface RecipeReply {
  readonly kind: 'reply';
  readonly bindingName: string;
  readonly requestMessageId: string;
  readonly messageId: string;
  readonly cursor: number;
  readonly text: string;
}

/** A bounded observation without a reply; it is neither failure nor cancellation. */
export interface RecipePending {
  readonly kind: 'pending';
  readonly afterCursor: number;
  readonly hasMore: boolean;
}

export type RecipeReplyPage = RecipeReply | RecipePending;

const baseFields = [
  'conversation_id',
  'message_id',
  'envelope_id',
  'sender_device_id',
  'epoch',
  'sender_counter',
  'sent_at_unix_milliseconds',
  'reply_to_message_id',
  'cursor',
  'direction',
  'content_type',
  'duplicate',
];
const contentFields = {
  text: ['text'],
  directed_request: ['target_device_id', 'text'],
  collaboration_policy_proposal: ['proposal_id', 'policy_digest', 'replaces_policy_digest'],
  collaboration_policy_response: ['proposal_id', 'policy_digest', 'outcome'],
  collaboration_policy_revocation: ['policy_digest'],
} as const;

function contentType(value: unknown): value is keyof typeof contentFields {
  return typeof value === 'string' && Object.hasOwn(contentFields, value);
}

export function isRecipeCursor(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function validateRecipeMessageText(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RecipeRunError('invalid_request');
  }
  try {
    measureRecipeText(value, recipeMessageBytes);
  } catch (error) {
    if (error instanceof RecipeDefinitionError) {
      throw new RecipeRunError('invalid_request');
    }
    throw error;
  }
  return value;
}

/**
 * Selects the first exact authenticated target response in native history order.
 * Unlike display-only readers, this requires explicit content kind, conversation
 * and reply identity. Notifications, policy records and other senders cannot finish
 * the request. It performs no effects and never acts on response prose.
 * @throws {RecipeRunError} For malformed context, page shape or attribution.
 */
export function selectRecipeReply(
  value: unknown,
  selectedBinding: RecipeBinding,
  requestMessageId: string,
  afterCursor: number,
  pageLimit = recipeHistoryPageSize,
): RecipeReplyPage {
  if (
    !isRecipeHex(requestMessageId, 32) ||
    !isRecipeCursor(afterCursor) ||
    !Number.isSafeInteger(pageLimit) ||
    pageLimit < 1 ||
    pageLimit > recipeHistoryPageSize
  ) {
    throw new RecipeRunError('invalid_request');
  }
  try {
    const binding = parseRecipeBinding(selectedBinding);
    requireRecipeRecord(value, ['messages', 'has_more']);
    const messages = recipeDataProperty(value, 'messages');
    const hasMore = recipeDataProperty(value, 'has_more');
    if (
      types.isProxy(messages) ||
      !Array.isArray(messages) ||
      messages.length > pageLimit ||
      Reflect.ownKeys(messages).length !== messages.length + 1 ||
      typeof hasMore !== 'boolean' ||
      (hasMore && messages.length === 0)
    ) {
      throw new RecipeRunError('invalid_response');
    }
    let cursor = afterCursor;
    let selected: RecipeReply | undefined;
    const identifiers = new Set<string>();
    for (let index = 0; index < messages.length; index += 1) {
      const message = recipeDataProperty(messages, String(index));
      if (typeof message !== 'object' || message === null || types.isProxy(message)) {
        throw new RecipeRunError('invalid_response');
      }
      const kind = recipeDataProperty(message, 'content_type');
      if (!contentType(kind)) {
        throw new RecipeRunError('invalid_response');
      }
      requireRecipeRecord(message, [...baseFields, ...contentFields[kind]]);
      const conversation = recipeDataProperty(message, 'conversation_id');
      const identifier = recipeDataProperty(message, 'message_id');
      const envelope = recipeDataProperty(message, 'envelope_id');
      const sender = recipeDataProperty(message, 'sender_device_id');
      const replyTo = recipeDataProperty(message, 'reply_to_message_id');
      const currentCursor = recipeDataProperty(message, 'cursor');
      const direction = recipeDataProperty(message, 'direction');
      const counter = recipeDataProperty(message, 'sender_counter');
      if (
        conversation !== binding.conversationId ||
        !isRecipeHex(identifier, 32) ||
        !isRecipeHex(envelope, 32) ||
        !isRecipeHex(sender, 64) ||
        (replyTo !== null && !isRecipeHex(replyTo, 32)) ||
        !isRecipeCursor(currentCursor) ||
        currentCursor <= cursor ||
        !isRecipeCursor(counter) ||
        counter === 0 ||
        !isRecipeCursor(recipeDataProperty(message, 'epoch')) ||
        !isRecipeCursor(recipeDataProperty(message, 'sent_at_unix_milliseconds')) ||
        (direction !== 'inbound' && direction !== 'outbound') ||
        typeof recipeDataProperty(message, 'duplicate') !== 'boolean' ||
        identifiers.has(identifier)
      ) {
        throw new RecipeRunError('invalid_response');
      }
      identifiers.add(identifier);
      cursor = currentCursor;
      let text: string | undefined;
      if (kind === 'text' || kind === 'directed_request') {
        text = validateRecipeMessageText(recipeDataProperty(message, 'text'));
      }
      if (
        kind === 'directed_request' &&
        !isRecipeHex(recipeDataProperty(message, 'target_device_id'), 64)
      ) {
        throw new RecipeRunError('invalid_response');
      }
      if (kind.startsWith('collaboration_policy_')) {
        if (!isRecipeHex(recipeDataProperty(message, 'policy_digest'), 64)) {
          throw new RecipeRunError('invalid_response');
        }
        if (
          kind !== 'collaboration_policy_revocation' &&
          !isRecipeHex(recipeDataProperty(message, 'proposal_id'), 32)
        ) {
          throw new RecipeRunError('invalid_response');
        }
        if (kind === 'collaboration_policy_proposal') {
          const replacement = recipeDataProperty(message, 'replaces_policy_digest');
          if (replacement !== null && !isRecipeHex(replacement, 64)) {
            throw new RecipeRunError('invalid_response');
          }
        }
        if (kind === 'collaboration_policy_response') {
          const outcome = recipeDataProperty(message, 'outcome');
          if (outcome !== 'accepted' && outcome !== 'rejected') {
            throw new RecipeRunError('invalid_response');
          }
        }
      }
      if (
        selected === undefined &&
        kind === 'text' &&
        text !== undefined &&
        direction === 'inbound' &&
        sender === binding.targetDeviceId &&
        replyTo === requestMessageId
      ) {
        selected = Object.freeze({
          kind: 'reply',
          bindingName: binding.name,
          requestMessageId,
          messageId: identifier,
          cursor,
          text,
        });
      }
    }
    return selected ?? Object.freeze({ kind: 'pending', afterCursor: cursor, hasMore });
  } catch (error) {
    if (error instanceof RecipeDefinitionError || error instanceof RecipeRunError) {
      throw new RecipeRunError('invalid_response');
    }
    throw error;
  }
}
