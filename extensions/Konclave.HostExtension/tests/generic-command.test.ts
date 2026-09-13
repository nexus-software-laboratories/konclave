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
  it('accepts bounded labels and explicit durable or ephemeral profile modes', () => {
    const durable = [
      '--profile',
      'generic-test',
      '--profile-mode',
      'durable',
      '--integration-label',
      'future-harness.v1',
    ];
    expect(parseGenericCommandArguments([...durable, '--operation', 'read_messages'])).toEqual({
      profile: 'generic-test',
      profileMode: 'durable',
      integrationLabel: 'future-harness.v1',
      operation: 'read_messages',
    });
    const ephemeral = [
      '--profile',
      `generic-${'01'.repeat(12)}`,
      '--profile-mode',
      'ephemeral',
      '--integration-label',
      'unknown-agent',
    ];
    expect(parseGenericCommandArguments([...ephemeral, '--operation', 'get_identity'])).toEqual({
      profile: `generic-${'01'.repeat(12)}`,
      profileMode: 'ephemeral',
      integrationLabel: 'unknown-agent',
      operation: 'get_identity',
    });
    for (const operation of [
      'get_collaboration_policy_status',
      'inspect_collaboration_policy_proposal',
      'propose_collaboration_policy_source',
      'resume_collaboration_policy_proposal',
      'accept_collaboration_policy',
      'reject_collaboration_policy',
      'revoke_collaboration_policy',
    ]) {
      expect(parseGenericCommandArguments([...durable, '--operation', operation])).toEqual({
        profile: 'generic-test',
        profileMode: 'durable',
        integrationLabel: 'future-harness.v1',
        operation,
      });
    }
    expect(
      parseGenericCommandArguments([
        '--operation',
        'service.status',
        '--profile',
        'generic-test',
        '--profile-mode',
        'durable',
        '--integration-label',
        'future-harness.v1',
        '--request-id',
        '01'.repeat(16),
      ]),
    ).toEqual({
      profile: 'generic-test',
      profileMode: 'durable',
      integrationLabel: 'future-harness.v1',
      operation: 'service.status',
      requestId: Buffer.alloc(16, 1),
    });
  });

  it('rejects ambiguous identity, evidence overclaim, and invalid metadata', () => {
    const valid = [
      '--profile',
      'generic-test',
      '--profile-mode',
      'durable',
      '--integration-label',
      'future-harness.v1',
      '--operation',
      'get_identity',
    ];
    const withValue = (index: number, value: string): string[] =>
      valid.map((entry, current) => (current === index ? value : entry));
    for (const invalid of [
      [],
      ['--profile', 'generic-test'],
      [...valid, '--profile', 'second'],
      [...valid, '--profile-mode', 'ephemeral'],
      [...valid, '--integration-label', 'second'],
      [...valid, '--request-id', 'invalid'],
      [...valid, '--harness', 'copilot'],
      [...valid, '--subject', 'self-asserted'],
      [...valid, '--evidence', 'harness_attested'],
      withValue(7, 'unknown'),
      withValue(5, ''),
      withValue(5, 'A'),
      withValue(5, 'a'.repeat(65)),
      withValue(1, 'invalid/profile'),
      ['--other', 'value'],
    ]) {
      expect(() => parseGenericCommandArguments(invalid)).toThrow('invalid_arguments');
    }
    expect(() =>
      parseGenericCommandArguments([
        '--profile',
        'session-0123456789abcdef01234567',
        '--profile-mode',
        'durable',
        '--integration-label',
        'future-harness.v1',
        '--operation',
        'get_identity',
      ]),
    ).toThrow('paved_profile_reserved');
    expect(() =>
      parseGenericCommandArguments([
        '--profile',
        'generic-readable-name',
        '--profile-mode',
        'ephemeral',
        '--integration-label',
        'future-harness.v1',
        '--operation',
        'get_identity',
      ]),
    ).toThrow('ephemeral_profile_invalid');
  });

  it('keeps self-declared metadata outside authorization and retires cleanly', async () => {
    const request = vi.fn().mockResolvedValue({ messages: [] });
    const connected = client(request);
    const connect = vi.fn().mockResolvedValue(connected);
    const controller = new AbortController();
    const environment = { KONCLAVE_SERVICE_CONFIG_FILE: 'configured' };
    const reportCleanupFailure = vi.fn();

    await expect(
      invokeGenericCommand(
        {
          profile: 'generic-test',
          profileMode: 'durable',
          integrationLabel: 'future-harness.v1',
          operation: 'read_messages',
        },
        { conversation_id: 'ab', limit: 10 },
        {
          environment,
          moduleDir: 'module',
          signal: controller.signal,
          reportCleanupFailure,
          connect,
        },
      ),
    ).resolves.toEqual({
      integration: {
        kind: 'generic',
        label: 'future-harness.v1',
      },
      profile: {
        alias: 'generic-test',
        mode: 'durable',
      },
      result: { messages: [] },
    });

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
        {
          profile: 'generic-test',
          profileMode: 'durable',
          integrationLabel: 'future-harness.v1',
          operation: 'send_message',
        },
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
    let reserved: unknown;
    try {
      parseGenericCommandArguments([
        '--profile',
        'session-0123456789abcdef01234567',
        '--profile-mode',
        'durable',
        '--integration-label',
        'future-harness.v1',
        '--operation',
        'get_identity',
      ]);
    } catch (error) {
      reserved = error;
    }
    expect(genericCommandFailure(reserved)).toEqual({
      error: 'paved_profile_reserved',
    });
  });

  it('preserves a successful operation when clean retirement fails', async () => {
    const connected = client(vi.fn().mockResolvedValue({ device_id: 'aa' }));
    vi.mocked(connected.retire).mockRejectedValueOnce(new Error('retirement failed'));
    const reportCleanupFailure = vi.fn();

    await expect(
      invokeGenericCommand(
        {
          profile: 'generic-test',
          profileMode: 'durable',
          integrationLabel: 'future-harness.v1',
          operation: 'get_identity',
        },
        {},
        {
          environment: {},
          moduleDir: 'module',
          signal: new AbortController().signal,
          reportCleanupFailure,
          connect: vi.fn().mockResolvedValue(connected),
        },
      ),
    ).resolves.toEqual({
      integration: {
        kind: 'generic',
        label: 'future-harness.v1',
      },
      profile: {
        alias: 'generic-test',
        mode: 'durable',
      },
      result: { device_id: 'aa' },
    });
    expect(connected.close).toHaveBeenCalledTimes(1);
    expect(reportCleanupFailure).toHaveBeenCalledTimes(1);
  });
});
