import { describe, expect, it, vi } from 'vitest';

import {
  genericCommandFailure,
  invokeGenericCommand,
  parseGenericCommandArguments,
} from '../src/generic-command.js';
import {
  LocalServiceError,
  LocalServiceUpgradeRequiredError,
  type LocalServiceClient,
} from '../src/service/client.js';
import { ServiceConfigurationError } from '../src/service/config.js';

function client(request: LocalServiceClient['request']): LocalServiceClient {
  return {
    profile: 'generic-test',
    request,
    retire: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    connected: true,
  };
}

describe('generic harness command', () => {
  it('accepts one explicit profile and closed operation', () => {
    expect(
      parseGenericCommandArguments(['--profile', 'generic-test', '--operation', 'read_messages']),
    ).toEqual({ profile: 'generic-test', operation: 'read_messages' });
    expect(
      parseGenericCommandArguments([
        '--operation',
        'service.status',
        '--profile',
        'generic-test',
        '--request-id',
        '01'.repeat(16),
      ]),
    ).toEqual({
      profile: 'generic-test',
      operation: 'service.status',
      requestId: Buffer.alloc(16, 1),
    });

    for (const invalid of [
      [],
      ['--profile', 'generic-test'],
      ['--operation', 'unknown', '--profile', 'generic-test'],
      ['--profile', 'first', '--profile', 'second', '--operation', 'get_identity'],
      ['--profile', 'generic-test', '--operation', 'get_identity', '--request-id', 'invalid'],
      ['--other', 'value'],
    ]) {
      expect(() => parseGenericCommandArguments(invalid)).toThrow('invalid_arguments');
    }
  });

  it('uses the generic connector, forwards cancellation, and retires cleanly', async () => {
    const request = vi.fn().mockResolvedValue({ messages: [] });
    const connected = client(request);
    const connect = vi.fn().mockResolvedValue(connected);
    const controller = new AbortController();
    const environment = { KONCLAVE_SERVICE_CONFIG_FILE: 'configured' };
    const reportCleanupFailure = vi.fn();

    await expect(
      invokeGenericCommand(
        { profile: 'generic-test', operation: 'read_messages' },
        { conversation_id: 'ab', limit: 10 },
        {
          environment,
          moduleDir: 'module',
          signal: controller.signal,
          reportCleanupFailure,
          connect,
        },
      ),
    ).resolves.toEqual({ messages: [] });

    expect(connect).toHaveBeenCalledWith(environment, 'module', 'generic-test');
    expect(request).toHaveBeenCalledWith(
      'read_messages',
      { conversation_id: 'ab', limit: 10 },
      { deadlineMs: 90_000, signal: controller.signal, requestId: undefined },
    );
    expect(connected.retire).toHaveBeenCalledTimes(1);
    expect(reportCleanupFailure).not.toHaveBeenCalled();
  });

  it('retires after a failed operation and emits finite error shapes', async () => {
    const operationError = new LocalServiceError('send_message', 'cancelled');
    const connected = client(vi.fn().mockRejectedValue(operationError));
    const connect = vi.fn().mockResolvedValue(connected);

    await expect(
      invokeGenericCommand(
        { profile: 'generic-test', operation: 'send_message' },
        {},
        {
          environment: {},
          moduleDir: 'module',
          signal: new AbortController().signal,
          reportCleanupFailure: vi.fn(),
          connect,
        },
      ),
    ).rejects.toBe(operationError);
    expect(connected.retire).toHaveBeenCalledTimes(1);
    expect(genericCommandFailure(operationError)).toEqual({
      error: 'cancelled',
      operation: 'send_message',
    });
    expect(
      genericCommandFailure(
        new ServiceConfigurationError('unavailable', 'required_evidence_unavailable'),
      ),
    ).toEqual({ error: 'required_evidence_unavailable' });
    expect(genericCommandFailure(new Error('private details'))).toEqual({
      error: 'generic_client_failed',
    });
    expect(genericCommandFailure(new LocalServiceUpgradeRequiredError())).toEqual({
      error: 'service_upgrade_required',
    });
  });

  it('preserves a successful operation when clean retirement fails', async () => {
    const connected = client(vi.fn().mockResolvedValue({ device_id: 'aa' }));
    vi.mocked(connected.retire).mockRejectedValueOnce(new Error('retirement failed'));
    const reportCleanupFailure = vi.fn();

    await expect(
      invokeGenericCommand(
        { profile: 'generic-test', operation: 'get_identity' },
        {},
        {
          environment: {},
          moduleDir: 'module',
          signal: new AbortController().signal,
          reportCleanupFailure,
          connect: vi.fn().mockResolvedValue(connected),
        },
      ),
    ).resolves.toEqual({ device_id: 'aa' });
    expect(connected.close).toHaveBeenCalledTimes(1);
    expect(reportCleanupFailure).toHaveBeenCalledTimes(1);
  });
});
