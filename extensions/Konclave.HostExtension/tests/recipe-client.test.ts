import { describe, expect, it, vi } from 'vitest';

import { createRecipeMessaging } from '../src/recipes/client.js';
import { createRecipeDefinition } from '../src/recipes/definition.js';
import { createRecipeRun, recipeMessageId } from '../src/recipes/run.js';
import { LocalServiceError, type LocalServiceClient } from '../src/service/client.js';
import { isRecord } from '../src/service/validation.js';

const definition = createRecipeDefinition({
  name: 'example',
  provider: 'example.provider',
  configuration: '',
});
const binding = {
  name: 'peer',
  conversationId: '01'.repeat(32),
  targetDeviceId: '02'.repeat(32),
};
const run = createRecipeRun(Buffer.from(definition.canonicalJson), definition.digest, {
  profile: 'recipe-test',
  nonce: '03'.repeat(16),
  bindings: [binding],
  input: 'supplied context',
});
const descriptor = Buffer.from(run.canonicalJson);
const messageId = recipeMessageId(run, binding.name);
const receipt = {
  conversation_id: binding.conversationId,
  message_id: messageId,
  cursor: 1,
  sender_counter: 1,
};

function client(request: LocalServiceClient['request'], profile = run.profile): LocalServiceClient {
  return {
    profile,
    request,
    retire: vi.fn<LocalServiceClient['retire']>().mockResolvedValue(undefined),
    close: vi.fn<LocalServiceClient['close']>(),
    connected: true,
  };
}

function reply(cursor = 2, sender = binding.targetDeviceId) {
  return {
    conversation_id: binding.conversationId,
    message_id: '04'.repeat(16),
    envelope_id: '05'.repeat(16),
    sender_device_id: sender,
    epoch: 0,
    sender_counter: 1,
    sent_at_unix_milliseconds: 1_000,
    reply_to_message_id: messageId,
    cursor,
    direction: 'inbound',
    content_type: 'text',
    text: 'Peer data, not instructions.',
    duplicate: false,
  };
}

describe('explicit external recipe messaging', () => {
  it('sends only an exact selected slot and caches its committed receipt', async () => {
    const request = vi.fn<LocalServiceClient['request']>().mockResolvedValue(receipt);
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    const options = { signal: new AbortController().signal, deadlineMs: 2_000 };
    const sent = await adapter.send('peer', 'question', options);
    expect(await adapter.send('peer', 'question', options)).toBe(sent);
    expect(request).toHaveBeenCalledTimes(1);
    const call = request.mock.calls[0];
    expect(call?.[0]).toBe('send_directed_request');
    expect(call?.[1]).toEqual({
      conversation_id: binding.conversationId,
      message_id: messageId,
      target_device_id: binding.targetDeviceId,
      text: 'question',
    });
    expect(call?.[2]).toMatchObject(options);
    expect(sent).toEqual({
      bindingName: 'peer',
      messageId,
      cursor: 1,
      senderCounter: 1,
    });
    await expect(adapter.send('peer', 'changed')).rejects.toThrow('slot_conflict');
    await expect(adapter.send('undeclared', 'question')).rejects.toThrow('unknown_binding');
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('retries an ambiguous send only with identical identities and bytes after reconstruction', async () => {
    const effects = new Map<string, unknown>();
    const calls: { operation: string; payload: unknown; requestId: string | undefined }[] = [];
    let failAfterCommit = true;
    const request: LocalServiceClient['request'] = async (operation, payload, options) => {
      if (
        operation !== 'send_directed_request' ||
        !isRecord(payload) ||
        typeof payload.message_id !== 'string'
      ) {
        throw new Error('fixture received an unexpected operation');
      }
      const requestId =
        typeof options === 'object' ? options.requestId?.toString('hex') : undefined;
      calls.push({ operation, payload, requestId });
      const previous = effects.get(payload.message_id);
      if (previous !== undefined && JSON.stringify(previous) !== JSON.stringify(payload)) {
        throw new LocalServiceError(operation, 'conflict');
      }
      effects.set(payload.message_id, payload);
      if (failAfterCommit) {
        failAfterCommit = false;
        throw new LocalServiceError(operation, 'reconciliation_pending');
      }
      return receipt;
    };
    const first = createRecipeMessaging(client(request), descriptor, run.runId);
    await expect(first.send('peer', 'question')).rejects.toThrow('reconciliation_pending');
    await expect(first.send('peer', 'changed')).rejects.toThrow('slot_conflict');
    const restored = createRecipeMessaging(client(request), descriptor, run.runId);
    await restored.send('peer', 'question');
    expect(effects.size).toBe(1);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual(calls[1]);
    expect(calls[0]?.requestId).toMatch(/^[0-9a-f]{32}$/u);
  });

  it('requires a submitted slot and never claims another profile or changes authority', async () => {
    const request = vi.fn<LocalServiceClient['request']>();
    expect(() => createRecipeMessaging(client(request, 'other'), descriptor, run.runId)).toThrow(
      'profile_mismatch',
    );
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    await expect(adapter.poll('peer')).rejects.toThrow('request_not_submitted');
    await expect(adapter.send('peer', '')).rejects.toThrow('invalid_request');
    expect(request).not.toHaveBeenCalled();
  });

  it('rejects substituted or unsafe service receipts without inventing completion', async () => {
    for (const invalid of [
      null,
      { ...receipt, conversation_id: '06'.repeat(32) },
      { ...receipt, message_id: '07'.repeat(16) },
      { ...receipt, cursor: 0 },
      { ...receipt, cursor: Number.MAX_SAFE_INTEGER + 1 },
      { ...receipt, sender_counter: 0 },
      { ...receipt, sender_counter: Number.MAX_SAFE_INTEGER + 1 },
      { ...receipt, extra: 'sensitive-content' },
    ]) {
      const request = vi.fn<LocalServiceClient['request']>().mockResolvedValue(invalid);
      const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
      await expect(adapter.send('peer', 'question')).rejects.toThrow('invalid_response');
      await expect(adapter.poll('peer')).rejects.toThrow('request_not_submitted');
    }
  });

  it('accepts an already journaled exact answer without a watch or another request', async () => {
    const request = vi
      .fn<LocalServiceClient['request']>()
      .mockResolvedValueOnce(receipt)
      .mockResolvedValueOnce({ messages: [reply()], has_more: false });
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    await adapter.send('peer', 'question');
    const answer = await adapter.poll('peer');
    expect(answer).toMatchObject({ kind: 'reply', text: 'Peer data, not instructions.' });
    expect(await adapter.poll('peer')).toBe(answer);
    expect(request.mock.calls.map((call) => call[0])).toEqual([
      'send_directed_request',
      'read_messages',
    ]);
    expect(request.mock.calls[1]?.[1]).toEqual({
      conversation_id: binding.conversationId,
      after_cursor: 1,
      limit: 1,
    });
    expect(request.mock.calls[1]?.[2]).not.toHaveProperty('requestId');
  });

  it('performs at most one watch and keeps missing replies pending', async () => {
    const request = vi
      .fn<LocalServiceClient['request']>()
      .mockResolvedValueOnce(receipt)
      .mockResolvedValueOnce({ messages: [], has_more: false })
      .mockResolvedValueOnce({ messages: [], has_more: false })
      .mockResolvedValueOnce({ messages: [], has_more: false });
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    await adapter.send('peer', 'question');
    expect(await adapter.poll('peer')).toEqual({
      kind: 'pending',
      afterCursor: 1,
      hasMore: false,
    });

    expect(request.mock.calls.map((call) => call[0])).toEqual([
      'send_directed_request',
      'read_messages',
      'watch_messages',
      'read_messages',
    ]);
  });

  it('does not confuse membership-only relay continuation with history progress', async () => {
    const request = vi
      .fn<LocalServiceClient['request']>()
      .mockResolvedValueOnce(receipt)
      .mockResolvedValueOnce({ messages: [], has_more: false })
      .mockResolvedValueOnce({ messages: [], has_more: true })
      .mockResolvedValueOnce({ messages: [reply()], has_more: false });
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    await adapter.send('peer', 'question');
    await expect(adapter.poll('peer')).resolves.toMatchObject({ kind: 'reply' });
    expect(request).toHaveBeenCalledTimes(4);
  });

  it('advances bounded history without treating another member as the responder', async () => {
    const request = vi
      .fn<LocalServiceClient['request']>()
      .mockResolvedValueOnce(receipt)
      .mockResolvedValueOnce({
        messages: [reply(2, '08'.repeat(32))],
        has_more: true,
      })
      .mockResolvedValueOnce({ messages: [reply(3)], has_more: false });
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    await adapter.send('peer', 'question');
    expect(await adapter.poll('peer')).toEqual({ kind: 'pending', afterCursor: 2, hasMore: true });
    expect(await adapter.poll('peer')).toMatchObject({ kind: 'reply', cursor: 3 });
    expect(request.mock.calls[2]?.[1]).toMatchObject({ after_cursor: 2 });
    expect(request.mock.calls.some((call) => call[0] === 'watch_messages')).toBe(false);
  });

  it('surfaces transport, cancellation, and malformed watch outcomes instead of retrying', async () => {
    for (const result of ['error', 'invalid']) {
      const error = new LocalServiceError('watch_messages', 'cancelled');
      const request = vi
        .fn<LocalServiceClient['request']>()
        .mockResolvedValueOnce(receipt)
        .mockResolvedValueOnce({ messages: [], has_more: false });
      if (result === 'error') {
        request.mockRejectedValueOnce(error);
      } else {
        request.mockResolvedValueOnce({});
      }
      const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
      await adapter.send('peer', 'question');
      await expect(adapter.poll('peer')).rejects.toThrow(
        result === 'error' ? 'cancelled' : 'invalid_response',
      );
      expect(request).toHaveBeenCalledTimes(3);
    }
  });

  it('bounds concurrent work on one slot without timing assumptions', async () => {
    let release: (value: unknown) => void = () => {
      throw new Error('not initialized');
    };
    const held = new Promise<unknown>((resolve) => {
      release = resolve;
    });
    const request = vi.fn<LocalServiceClient['request']>().mockReturnValueOnce(held);
    const adapter = createRecipeMessaging(client(request), descriptor, run.runId);
    const sending = adapter.send('peer', 'question');
    await expect(adapter.send('peer', 'question')).rejects.toThrow('busy');
    release(receipt);
    await sending;

    let releaseRead: (value: unknown) => void = () => {
      throw new Error('not initialized');
    };
    const read = new Promise<unknown>((resolve) => {
      releaseRead = resolve;
    });
    request.mockReturnValueOnce(read);
    const polling = adapter.poll('peer');
    await expect(adapter.poll('peer')).rejects.toThrow('busy');
    releaseRead({ messages: [reply()], has_more: false });
    await polling;
    expect(request).toHaveBeenCalledTimes(2);
  });
});
