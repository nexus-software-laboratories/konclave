import { describe, expect, it, vi } from 'vitest';

import { createKonclaveCommands } from '../src/service/commands.js';
import { LocalServiceError, type LocalServiceClient } from '../src/service/client.js';
import {
  formatMessageDeliveryStatus,
  getMessageDeliveryStatus,
  parseMessageDeliveryStatus,
} from '../src/service/delivery-diagnostics.js';
import { toolOperations } from '../src/service/operations.js';
import { requireHexIdentifier } from '../src/service/validation.js';

const conversation = '01'.repeat(32);
const message = '02'.repeat(16);

function response(messageStatus = 'relay_accepted') {
  return {
    message_status: messageStatus,
    auto_delivery_enabled: true,
    profile_delivery_degraded: false,
    remote_outcome: 'unknown',
  };
}

function client(request: LocalServiceClient['request']): LocalServiceClient {
  return {
    profile: 'diagnostic-test',
    request,
    retire: vi.fn<LocalServiceClient['retire']>().mockResolvedValue(undefined),
    close: vi.fn<LocalServiceClient['close']>(),
    connected: true,
  };
}

describe('local delivery diagnostics', () => {
  it('parses and renders every finite local status without claiming remote execution', () => {
    for (const status of [
      'not_observed',
      'outbound_prepared',
      'awaiting_relay_acceptance',
      'relay_accepted',
      'outbound_expired',
      'outbound_removed',
      'inbound_prepared',
      'persisted_inbound',
      'awaiting_harness_delivery',
      'claimed_for_delivery',
      'acknowledged_by_harness',
      'delivery_suppressed',
      'request_claim_recorded',
      'request_claim_expired',
      'response_reserved',
      'completed_without_response',
    ]) {
      for (const enabled of [false, true]) {
        const parsed = parseMessageDeliveryStatus({
          ...response(status),
          auto_delivery_enabled: enabled,
          profile_delivery_degraded: !enabled,
        });
        expect(parsed).toEqual({
          messageStatus: status,
          autoDeliveryEnabled: enabled,
          profileDeliveryDegraded: !enabled,
          remoteOutcome: 'unknown',
        });
        const lines = formatMessageDeliveryStatus(parsed);
        expect(lines).toHaveLength(6);
        expect(lines[0]).toBe(`local message status: ${status}`);
        expect(lines).toContain('remote outcome: unknown');
        expect(lines[1]).not.toBeUndefined();
        expect(lines.join('\n')).not.toContain(conversation);
        expect(lines.join('\n')).not.toContain(message);
      }
    }
  });

  it('rejects malformed, extra, and invented remote evidence without disclosing values', () => {
    const sentinel = 'private-diagnostic-content-sentinel';
    for (const invalid of [
      null,
      undefined,
      [],
      {},
      'invalid',
      response(sentinel),
      response('__proto__'),
      { ...response(), auto_delivery_enabled: 'true' },
      { ...response(), profile_delivery_degraded: 0 },
      { ...response(), remote_outcome: 'completed' },
      { ...response(), text: sentinel },
      {
        message_status: 'relay_accepted',
        auto_delivery_enabled: true,
        profile_delivery_degraded: false,
        unrelated: 'unknown',
      },
    ]) {
      expect(() => parseMessageDeliveryStatus(invalid)).toThrow(
        'the local service delivery diagnostic is malformed',
      );
    }
  });

  it('uses exactly one authenticated read and preserves explicit cancellation options', async () => {
    const request = vi.fn<LocalServiceClient['request']>().mockResolvedValue(response());
    const signal = new AbortController().signal;
    const options = { signal, requestId: Buffer.alloc(16, 3), deadlineMs: 2_000 };
    await expect(
      getMessageDeliveryStatus(client(request), conversation, message, options),
    ).resolves.toMatchObject({ messageStatus: 'relay_accepted', remoteOutcome: 'unknown' });
    expect(request).toHaveBeenCalledExactlyOnceWith(
      'get_message_delivery_status',
      { conversation_id: conversation, message_id: message },
      options,
    );
    expect(toolOperations).not.toContain('get_message_delivery_status');
  });

  it('rejects noncanonical selectors before the service is invoked', async () => {
    const request = vi.fn<LocalServiceClient['request']>().mockResolvedValue(response());
    const invalidSelectors: readonly (readonly [string, string])[] = [
      ['', message],
      ['A'.repeat(64), message],
      ['g'.repeat(64), message],
      [conversation.slice(1), message],
      [conversation, ''],
      [conversation, 'A'.repeat(32)],
      [conversation, message.slice(1)],
    ];
    for (const [selectedConversation, selectedMessage] of invalidSelectors) {
      await expect(
        getMessageDeliveryStatus(client(request), selectedConversation, selectedMessage),
      ).rejects.toThrow('hex');
    }
    expect(request).not.toHaveBeenCalled();
    for (const invalid of [undefined, null, 0, {}, []]) {
      expect(() => requireHexIdentifier(invalid, 64, 'conversation identifier')).toThrow(
        'a 64-character hex conversation identifier is required',
      );
    }
  });

  it('does not fallback or fabricate an outcome when the service rejects the operation', async () => {
    const error = new LocalServiceError('get_message_delivery_status', 'unknown_operation');
    const request = vi.fn<LocalServiceClient['request']>().mockRejectedValue(error);
    await expect(getMessageDeliveryStatus(client(request), conversation, message)).rejects.toBe(
      error,
    );
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('integrates the deterministic command with ephemeral body-free output', async () => {
    const request = vi.fn<LocalServiceClient['request']>().mockResolvedValue(response());
    const write = vi.fn();
    const command = createKonclaveCommands({ client: client(request), output: { write } })[0];
    if (!command) {
      throw new Error('Konclave command is missing');
    }
    const args = `diagnose ${conversation} ${message}`;
    await command.handler({
      args,
      command: `/konclave ${args}`,
      commandName: 'konclave',
      sessionId: 'diagnostic-test',
    });
    expect(request).toHaveBeenCalledExactlyOnceWith(
      'get_message_delivery_status',
      { conversation_id: conversation, message_id: message },
      undefined,
    );
    expect(write).toHaveBeenCalledTimes(6);
    for (const call of write.mock.calls) {
      expect(call[1]).toEqual({ ephemeral: true });
      expect(call[0]).not.toContain(conversation);
      expect(call[0]).not.toContain(message);
    }
  });

  it('keeps invalid command arguments and unsupported service errors out of model turns', async () => {
    const request = vi
      .fn<LocalServiceClient['request']>()
      .mockRejectedValue(new LocalServiceError('get_message_delivery_status', 'unknown_operation'));
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: client(request),
      output: {
        write(line) {
          lines.push(line);
        },
      },
    })[0];
    if (!command) {
      throw new Error('Konclave command is missing');
    }
    for (const args of [
      'diagnose',
      `diagnose ${conversation}`,
      `diagnose ${conversation} ${message} extra`,
      `diagnose invalid ${message}`,
    ]) {
      await command.handler({
        args,
        command: `/konclave ${args}`,
        commandName: 'konclave',
        sessionId: 'diagnostic-test',
      });
    }
    expect(request).not.toHaveBeenCalled();
    await command.handler({
      args: `diagnose ${conversation} ${message}`,
      command: '/konclave diagnose',
      commandName: 'konclave',
      sessionId: 'diagnostic-test',
    });
    expect(lines.at(-1)).toBe('konclave: get_message_delivery_status failed (unknown_operation)');
    expect(request).toHaveBeenCalledTimes(1);
  });
});
