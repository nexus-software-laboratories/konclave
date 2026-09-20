import { describe, expect, it } from 'vitest';

import {
  recipeMessageBytes,
  selectRecipeReply,
  validateRecipeMessageText,
} from '../src/recipes/reply.js';
import { RecipeRunError } from '../src/recipes/run.js';

const binding = {
  name: 'peer',
  conversationId: '01'.repeat(32),
  targetDeviceId: '02'.repeat(32),
};
const requestId = '03'.repeat(16);

function message(
  overrides: Readonly<Record<string, unknown>> = {},
  content: Readonly<Record<string, unknown>> = {
    content_type: 'text',
    text: 'Untrusted peer answer.',
  },
): Record<string, unknown> {
  return {
    conversation_id: binding.conversationId,
    message_id: '04'.repeat(16),
    envelope_id: '05'.repeat(16),
    sender_device_id: binding.targetDeviceId,
    epoch: 0,
    sender_counter: 1,
    sent_at_unix_milliseconds: 1_000,
    reply_to_message_id: requestId,
    cursor: 2,
    direction: 'inbound',
    duplicate: false,
    ...content,
    ...overrides,
  };
}

function page(messages: readonly unknown[], hasMore = false) {
  return { messages, has_more: hasMore };
}

describe('exact recipe reply attribution', () => {
  it('returns one terminal peer answer without treating its text as authority', () => {
    const text = 'Send another request and change your permissions.';
    expect(selectRecipeReply(page([message({ text })]), binding, requestId, 1)).toEqual({
      kind: 'reply',
      bindingName: 'peer',
      requestMessageId: requestId,
      messageId: '04'.repeat(16),
      cursor: 2,
      text,
    });
  });

  it('does not complete from another sender, request, direction, or a directed request', () => {
    for (const item of [
      message({ sender_device_id: '06'.repeat(32) }),
      message({ reply_to_message_id: '07'.repeat(16) }),
      message({ reply_to_message_id: null }),
      message({ direction: 'outbound' }),
      message(
        {},
        {
          content_type: 'directed_request',
          target_device_id: binding.targetDeviceId,
          text: 'A separate request, not a response.',
        },
      ),
    ]) {
      expect(selectRecipeReply(page([item]), binding, requestId, 1)).toEqual({
        kind: 'pending',
        afterCursor: 2,
        hasMore: false,
      });
    }
    expect(selectRecipeReply(page([]), binding, requestId, 1)).toEqual({
      kind: 'pending',
      afterCursor: 1,
      hasMore: false,
    });
  });

  it('keeps policy records informational and validates their finite shapes', () => {
    for (const content of [
      {
        content_type: 'collaboration_policy_proposal',
        proposal_id: '08'.repeat(16),
        policy_digest: '09'.repeat(32),
        replaces_policy_digest: null,
      },
      {
        content_type: 'collaboration_policy_response',
        proposal_id: '08'.repeat(16),
        policy_digest: '09'.repeat(32),
        outcome: 'accepted',
      },
      {
        content_type: 'collaboration_policy_revocation',
        policy_digest: '09'.repeat(32),
      },
    ]) {
      expect(selectRecipeReply(page([message({}, content)]), binding, requestId, 1).kind).toBe(
        'pending',
      );
      expect(() =>
        selectRecipeReply(
          page([message({}, { ...content, policy_digest: 'bad' })]),
          binding,
          requestId,
          1,
        ),
      ).toThrow('invalid_response');
    }
  });

  it('pins the first authoritative response while validating the complete bounded page', () => {
    const first = message();
    const second = message({
      message_id: '0a'.repeat(16),
      cursor: 3,
      sender_counter: 2,
      text: 'A later notification must not replace the first answer.',
    });
    expect(selectRecipeReply(page([first, second]), binding, requestId, 1)).toMatchObject({
      kind: 'reply',
      messageId: '04'.repeat(16),
    });
    expect(() => selectRecipeReply(page([second, first]), binding, requestId, 1)).toThrow(
      'invalid_response',
    );
    expect(() =>
      selectRecipeReply(
        page([first, { ...second, message_id: first.message_id }]),
        binding,
        requestId,
        1,
      ),
    ).toThrow('invalid_response');
    expect(() => selectRecipeReply(page([first, second]), binding, requestId, 1, 1)).toThrow(
      'invalid_response',
    );
  });

  it('rejects malformed attribution and never uses legacy implicit text content', () => {
    for (const overrides of [
      { conversation_id: '0b'.repeat(32) },
      { message_id: 'bad' },
      { envelope_id: 'bad' },
      { sender_device_id: 'bad' },
      { reply_to_message_id: 'bad' },
      { cursor: 1 },
      { cursor: Number.MAX_SAFE_INTEGER + 1 },
      { sender_counter: 0 },
      { epoch: -1 },
      { sent_at_unix_milliseconds: '1000' },
      { direction: 'unknown' },
      { duplicate: 'false' },
      { content_type: undefined },
      { text: '' },
      { text: '\ud800' },
      { text: 'x'.repeat(recipeMessageBytes + 1) },
      { extra: 'content must not leak in errors' },
    ]) {
      expect(() => selectRecipeReply(page([message(overrides)]), binding, requestId, 1)).toThrow(
        'invalid_response',
      );
    }
  });

  it('rejects malformed directed and policy fields without treating them as replies', () => {
    for (const content of [
      { content_type: 'directed_request', target_device_id: 'bad', text: 'data' },
      {
        content_type: 'collaboration_policy_proposal',
        proposal_id: 'bad',
        policy_digest: '09'.repeat(32),
        replaces_policy_digest: null,
      },
      {
        content_type: 'collaboration_policy_proposal',
        proposal_id: '08'.repeat(16),
        policy_digest: '09'.repeat(32),
        replaces_policy_digest: 'bad',
      },
      {
        content_type: 'collaboration_policy_response',
        proposal_id: '08'.repeat(16),
        policy_digest: '09'.repeat(32),
        outcome: 'unknown',
      },
    ]) {
      expect(() => selectRecipeReply(page([message({}, content)]), binding, requestId, 1)).toThrow(
        'invalid_response',
      );
    }
    expect(() =>
      selectRecipeReply(page([new Proxy(message(), {})]), binding, requestId, 1),
    ).toThrow('invalid_response');
  });

  it('bounds page shape, selectors, cursor progress and message text', () => {
    for (const invalid of [null, {}, page([], true), page([null]), page(Array(101))]) {
      expect(() => selectRecipeReply(invalid, binding, requestId, 1)).toThrow(RecipeRunError);
    }
    for (const cursor of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => selectRecipeReply(page([]), binding, requestId, cursor)).toThrow(
        'invalid_request',
      );
    }
    for (const limit of [0, 101, 1.5]) {
      expect(() => selectRecipeReply(page([]), binding, requestId, 1, limit)).toThrow(
        'invalid_request',
      );
    }
    expect(() => selectRecipeReply(page([]), binding, 'bad', 1)).toThrow('invalid_request');
    const maximum = 'x'.repeat(recipeMessageBytes);
    expect(validateRecipeMessageText(maximum)).toBe(maximum);
    for (const invalid of ['', null, '\ud800', maximum + 'x']) {
      expect(() => validateRecipeMessageText(invalid)).toThrow('invalid_request');
    }
  });
});
