import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { EventEmitter } from 'node:events';
import { encodeFrame, FrameError, FrameReader, decodeFrameLength } from '../src/service/framing.js';
import {
  privateKeyFromSeed,
  privateKeyFromSeedAndZeroize,
  publicKeyFromRaw,
  rawPublicKey,
  signMessage,
  verifyMessage,
} from '../src/service/keys.js';
import {
  assertCanonicalProfile,
  clientSigningMessage,
  encodeIssuerTranscript,
  serviceSigningMessage,
} from '../src/service/transcript.js';
import { createKonclaveTools, konclaveTools } from '../src/service/tools.js';
import {
  createKonclaveCommands as createCommands,
  parseCommandArguments,
  type CommandDependencies,
  type CommandOutputOptions,
} from '../src/service/commands.js';
import {
  toolOperations,
  isKnownOperation,
  type ServiceStatusResult,
} from '../src/service/operations.js';
import { createLocalServiceDeliveryChannel } from '../src/service/delivery.js';
import { createExtensionJoinConfig, deriveProfileId } from '../src/runtime.js';
import { LocalServiceError, type LocalServiceClient } from '../src/service/client.js';

function createKonclaveCommands(dependencies: CommandDependencies) {
  return createCommands({ ...dependencies, outputMode: 'verbose' });
}

function stubClient(request = vi.fn().mockResolvedValue({})): LocalServiceClient {
  return {
    profile: 'session-0123456789abcdef01234567',
    request: request as unknown as LocalServiceClient['request'],
    retire: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    connected: true,
  };
}

function serviceStatus(overrides: Partial<ServiceStatusResult> = {}): ServiceStatusResult {
  return {
    profile: 'session-test',
    deviceId: 'aa'.repeat(32),
    relayConfigured: true,
    watchedConversations: 2,
    pendingEvents: 0,
    claimedEvents: 0,
    deliveryDegraded: false,
    authorizationPolicy: 'AccountTrusted',
    authorizationProvider: 'AccountTrusted',
    authorizationEvidence: ['account_trusted'],
    authorizationPolicyVersion: 1,
    grantExpiresAtUnixMilliseconds: Date.now() + 60_000,
    grantCapabilities: 15,
    activeGrants: 3,
    activeGrantsForIssuer: 3,
    activeGrantsForProfile: 1,
    grantLimit: 256,
    grantLimitPerIssuer: 128,
    grantLimitPerProfile: 32,
    ...overrides,
  };
}

const pairingId = '11'.repeat(16);
const conversationId = '22'.repeat(32);
const joinerDeviceId = '33'.repeat(32);
const inviterDeviceId = '44'.repeat(32);

function pairingStatus(overrides: Record<string, unknown> = {}) {
  return {
    pairing_id: pairingId,
    local_role: 'joiner',
    phase: 'joiner_awaiting_invitation',
    joiner_device_id: joinerDeviceId,
    requested_role: 'member',
    inviter_device_id: null,
    granted_role: null,
    conversation_id: null,
    authorization_deadline_unix_seconds: 1_787_805_388,
    completion_deadline_unix_seconds: null,
    ...overrides,
  };
}

function commandContext(args: string) {
  return {
    args,
    command: `/konclave ${args}`.trim(),
    commandName: 'konclave',
    sessionId: 'test-session',
  };
}

describe('shared local service transcript', () => {
  const fixture = JSON.parse(
    readFileSync(
      join(
        process.cwd(),
        '..',
        '..',
        'fixtures',
        'local-service',
        'v2',
        'authorization-transcript.json',
      ),
      'utf8',
    ),
  ) as Record<string, string | number>;
  const issuerKey = privateKeyFromSeed(
    Buffer.from(Array.from({ length: 32 }, (_, index) => index)),
  );
  const serviceKey = privateKeyFromSeed(
    Buffer.from(Array.from({ length: 32 }, (_, index) => index + 32)),
  );
  const parts = {
    issuerKeyId: Buffer.alloc(16, 1),
    issuerKeyVersion: 3,
    issuerPublicKey: rawPublicKey(issuerKey),
    clientInstance: Buffer.alloc(16, 2),
    harness: 'copilot' as const,
    clientChallenge: Buffer.alloc(32, 3),
    serviceChallenge: Buffer.alloc(32, 4),
    serviceKey: rawPublicKey(serviceKey),
  };

  it('reproduces deterministic protocol-v2 issuer transcript bytes', () => {
    const transcript = encodeIssuerTranscript(parts);
    const again = encodeIssuerTranscript({ ...parts });

    expect(transcript).toEqual(again);
    expect(transcript.readUInt16BE(0)).toBe(2);
    expect(transcript.readUInt8(2)).toBe(1);
    expect(clientSigningMessage(transcript).subarray(32)).toEqual(transcript);
    expect(serviceSigningMessage(transcript).subarray(32)).toEqual(transcript);
  });

  it('verifies both role-separated protocol-v2 signatures', () => {
    const transcript = encodeIssuerTranscript(parts);
    const clientSignature = signMessage(issuerKey, clientSigningMessage(transcript));
    const serviceSignature = signMessage(serviceKey, serviceSigningMessage(transcript));

    expect(
      verifyMessage(
        publicKeyFromRaw(parts.issuerPublicKey),
        clientSigningMessage(transcript),
        clientSignature,
      ),
    ).toBe(true);
    expect(
      verifyMessage(
        publicKeyFromRaw(parts.serviceKey),
        serviceSigningMessage(transcript),
        serviceSignature,
      ),
    ).toBe(true);
  });

  it('matches the shared protocol-v2 issuer vector', () => {
    const hex = (name: string): Buffer => Buffer.from(String(fixture[name]), 'hex');
    const transcript = encodeIssuerTranscript({
      issuerKeyId: hex('issuerKeyId'),
      issuerKeyVersion: Number(fixture.issuerKeyVersion),
      issuerPublicKey: hex('issuerPublicKey'),
      clientInstance: hex('issuerClientInstance'),
      harness: 'copilot',
      clientChallenge: hex('clientChallenge'),
      serviceChallenge: hex('serviceChallenge'),
      serviceKey: hex('servicePublicKey'),
    });
    expect(transcript.toString('hex')).toBe(fixture.issuerTranscript);
    expect(
      verifyMessage(
        publicKeyFromRaw(hex('issuerPublicKey')),
        clientSigningMessage(transcript),
        hex('issuerSignature'),
      ),
    ).toBe(true);
    expect(
      verifyMessage(
        publicKeyFromRaw(hex('servicePublicKey')),
        serviceSigningMessage(transcript),
        hex('issuerAcceptance'),
      ),
    ).toBe(true);
  });

  it('rejects every malformed fixed-width issuer transcript field', () => {
    const valid = {
      ...parts,
      harness: 'copilot' as const,
    };
    for (const parts of [
      { ...valid, issuerKeyId: Buffer.alloc(15) },
      { ...valid, issuerKeyVersion: 0 },
      { ...valid, issuerKeyVersion: 1.5 },
      { ...valid, issuerPublicKey: Buffer.alloc(31) },
      { ...valid, clientInstance: Buffer.alloc(15) },
      { ...valid, clientChallenge: Buffer.alloc(31) },
      { ...valid, serviceChallenge: Buffer.alloc(31) },
      { ...valid, serviceKey: Buffer.alloc(31) },
    ]) {
      expect(() => encodeIssuerTranscript(parts)).toThrow();
    }
  });

  it('refuses a profile that is not canonical lowercase', () => {
    expect(() => assertCanonicalProfile('alice')).not.toThrow();
    for (const profile of ['Alice', 'ALICE', 'alice.bob', '../escape', '', 'a'.repeat(33)]) {
      expect(() => assertCanonicalProfile(profile)).toThrow();
    }
  });

  it('derives a canonical durable profile from the session identifier', () => {
    const profile = deriveProfileId({ SESSION_ID: 'Session-With-UPPERCASE' });
    expect(profile).toMatch(/^session-[0-9a-f]{24}$/);
    expect(() => assertCanonicalProfile(profile)).not.toThrow();
    // A reload of the same session reuses the same durable profile.
    expect(deriveProfileId({ SESSION_ID: 'Session-With-UPPERCASE' })).toBe(profile);
  });
});

describe('bounded framing', () => {
  it('refuses an empty or oversized frame before allocating', () => {
    expect(() => encodeFrame(Buffer.alloc(0), 16)).toThrow(FrameError);
    expect(() => encodeFrame(Buffer.alloc(17), 16)).toThrow(FrameError);
    expect(() => decodeFrameLength(Buffer.from([0, 0, 0, 0]), 16)).toThrow(FrameError);
    expect(() => decodeFrameLength(Buffer.from([0, 0, 1, 0]), 16)).toThrow(FrameError);
  });

  it('reads one bounded frame and rejects an oversized declaration', async () => {
    const handlers = new Map<string, (value: never) => void>();
    const stream = {
      on(event: string, handler: (value: never) => void) {
        handlers.set(event, handler);
        return stream;
      },
    };
    const reader = new FrameReader(stream as never, 68);
    const pending = reader.read(64);
    handlers.get('data')?.(encodeFrame(Buffer.from('hello'), 64) as never);
    await expect(pending).resolves.toEqual(Buffer.from('hello'));

    const oversized = reader.read(4);
    handlers.get('data')?.(encodeFrame(Buffer.from('too long'), 64) as never);
    await expect(oversized).rejects.toBeInstanceOf(FrameError);
  });

  it('fails pending reads on stream errors, closure, overlap, and buffer overflow', async () => {
    for (const event of ['end', 'close'] as const) {
      const stream = new EventEmitter();
      const reader = new FrameReader(stream, 16);
      const pending = reader.read(8);
      stream.emit(event);
      await expect(pending).rejects.toMatchObject({ failure: 'closed' });
    }

    const failedStream = new EventEmitter();
    const failedReader = new FrameReader(failedStream, 16);
    const failed = failedReader.read(8);
    failedStream.emit('error', new Error('stream failed'));
    await expect(failed).rejects.toThrow('stream failed');

    const overlappingStream = new EventEmitter();
    const overlappingReader = new FrameReader(overlappingStream, 16);
    const first = overlappingReader.read(8);
    await expect(overlappingReader.read(8)).rejects.toThrow('already in flight');
    overlappingStream.emit('end');
    await expect(first).rejects.toBeInstanceOf(FrameError);

    const oversizedStream = new EventEmitter();
    const oversizedReader = new FrameReader(oversizedStream, 4);
    const oversized = oversizedReader.read(4);
    oversizedStream.emit('data', Buffer.alloc(5));
    await expect(oversized).rejects.toMatchObject({ failure: 'too-large' });

    const bufferedStream = new EventEmitter();
    const bufferedReader = new FrameReader(bufferedStream, 8);
    bufferedStream.emit('data', Buffer.from([0, 0]));
    expect(() => bufferedReader.setBufferLimit(1)).toThrow(FrameError);
  });
});

describe('agent tool surface', () => {
  it('registers every tool explicitly with no wildcard', () => {
    const names = konclaveTools.map((tool) => tool.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names.sort()).toEqual([...toolOperations].sort());
    expect(names).not.toContain('*');
    for (const tool of konclaveTools) {
      expect(tool.parameters.type).toBe('object');
      expect(isKnownOperation(tool.name)).toBe(true);
    }
  });

  it('maps a tool call onto the operation of the same name', async () => {
    const request = vi.fn().mockResolvedValue({ conversation_id: 'ab' });
    const tools = createKonclaveTools({ client: stubClient(request) });
    const send = tools.find((tool) => tool.name === 'send_message');
    const invocation = {
      sessionId: 'session-a',
      toolCallId: 'tool-call-a',
      toolName: 'send_message',
      arguments: {},
    };

    await send?.handler({ conversation_id: 'ab', message_id: 'cd', text: 'hi' }, invocation);
    await send?.handler({ conversation_id: 'ab', message_id: 'cd', text: 'hi' }, invocation);
    await send?.handler(
      { conversation_id: 'ab', message_id: 'cd', text: 'hi' },
      { ...invocation, sessionId: 'a', toolCallId: 'b\0c' },
    );
    await send?.handler(
      { conversation_id: 'ab', message_id: 'cd', text: 'hi' },
      { ...invocation, sessionId: 'a\0b', toolCallId: 'c' },
    );

    expect(request).toHaveBeenCalledWith(
      'send_message',
      { conversation_id: 'ab', message_id: 'cd', text: 'hi' },
      {
        deadlineMs: expect.any(Number),
        requestId: expect.any(Buffer),
      },
    );
    expect(request.mock.calls[0]?.[2]).toEqual(request.mock.calls[1]?.[2]);
    expect(request.mock.calls[2]?.[2]).not.toEqual(request.mock.calls[3]?.[2]);
    await expect(
      send?.handler(
        { conversation_id: 'ab', message_id: 'cd', text: 'hi' },
        { ...invocation, toolCallId: '' },
      ),
    ).rejects.toThrow('invocation identifiers are invalid');

    const identity = tools.find((tool) => tool.name === 'get_identity');
    await identity?.handler(undefined);
    expect(request).toHaveBeenCalledWith('get_identity', {}, expect.any(Number));
  });
});

describe('deterministic commands', () => {
  it('bounds parsed arguments', () => {
    expect(parseCommandArguments('  status  ')).toEqual(['status']);
    expect(parseCommandArguments('')).toEqual([]);
    expect(() => parseCommandArguments('a '.repeat(8))).toThrow();
    expect(() => parseCommandArguments('x'.repeat(129))).toThrow();
  });

  it('defaults to concise output and toggles verbose details for this command session', async () => {
    const request = vi.fn().mockResolvedValue(serviceStatus());
    const lines: string[] = [];
    const command = createCommands({
      client: stubClient(request),
      output: {
        write(line) {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('status'));
    expect(lines).toEqual([
      'status: relay configured; delivery healthy; authorization AccountTrusted (same-account trust); pending 0',
    ]);

    lines.length = 0;
    await command?.handler(commandContext('output verbose'));
    await command?.handler(commandContext('status'));
    expect(lines[0]).toBe('output: verbose');
    expect(lines).toContain('profile: session-test');
    expect(lines).toContain(`device: ${'aa'.repeat(32)}`);
    expect(lines.join('\n')).toContain('no same-user isolation');

    lines.length = 0;
    await command?.handler(commandContext('output normal'));
    await command?.handler(commandContext('status'));
    expect(lines).toEqual([
      'output: normal',
      'status: relay configured; delivery healthy; authorization AccountTrusted (same-account trust); pending 0',
    ]);
  });

  it('keeps normal pairing handoff and policy status concise', async () => {
    const request = vi.fn(async (operation: string) => {
      if (operation === 'create_pairing_capability') {
        return {
          pairing: pairingStatus(),
          capability: 'pairing_capability-1',
        };
      }
      if (operation === 'list_conversations') {
        return {
          conversation_ids: [conversationId],
          active_conversation_id: conversationId,
        };
      }
      if (operation === 'get_collaboration_policy_status') {
        return {
          conversation_id: conversationId,
          active_policy: null,
        };
      }
      throw new Error('unexpected operation');
    });
    const entries: Array<{ line: string; options: CommandOutputOptions | undefined }> = [];
    const command = createCommands({
      client: stubClient(request),
      output: {
        write(line, options) {
          entries.push({ line, options });
        },
      },
    })[0];

    await command?.handler(commandContext('pair'));
    await command?.handler(commandContext('policy status'));

    expect(entries).toEqual([
      {
        line: `pairing ${pairingId}: joiner_awaiting_invitation`,
        options: undefined,
      },
      { line: 'capability:', options: undefined },
      { line: 'pairing_capability-1', options: { ephemeral: true } },
      {
        line: `policy inactive: conversation ${conversationId}`,
        options: undefined,
      },
    ]);
  });

  it('keeps normal send output concise while preserving its retry identifier', async () => {
    const messageId = '88'.repeat(16);
    const request = vi.fn(async (operation: string, payload: unknown) => {
      if (operation === 'send_message') {
        return {
          conversation_id: conversationId,
          message_id: messageId,
          sender_counter: 1,
          cursor: 8,
        };
      }
      if (operation === 'set_active_conversation') {
        return {
          active_conversation_id:
            typeof payload === 'object' && payload !== null && 'conversation_id' in payload
              ? payload.conversation_id
              : null,
        };
      }
      throw new Error('unexpected operation');
    });
    const lines: string[] = [];
    const command = createCommands({
      client: stubClient(request),
      output: {
        write(line) {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(
      commandContext(`send ${conversationId} ${messageId} -- concise message`),
    );

    expect(lines).toEqual([
      `message ${messageId}: sending; reuse this identifier to retry`,
      `sent ${messageId}: conversation ${conversationId}; cursor 8`,
    ]);
  });

  it('renders status from the client without any model turn', async () => {
    const request = vi.fn().mockResolvedValue(
      serviceStatus({
        profile: 'session-0123456789abcdef01234567',
        deviceId: 'ffee',
      }),
    );
    const lines: string[] = [];
    const commands = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    });

    await commands[0]?.handler(commandContext('status'));

    expect(request).toHaveBeenCalledWith('service.status', {});
    expect(lines.some((line) => line.includes('session-0123456789abcdef01234567'))).toBe(true);
    expect(lines.some((line) => line.includes('relay configured: yes'))).toBe(true);
    expect(lines.some((line) => line.includes('authorization provider: AccountTrusted'))).toBe(
      true,
    );
    expect(lines.some((line) => line.includes('global 3/256'))).toBe(true);
  });

  it('reports an unknown subcommand without throwing into the session', async () => {
    const lines: string[] = [];
    const commands = createKonclaveCommands({
      client: stubClient(),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    });

    await expect(
      commands[0]?.handler({
        ...commandContext('launch-missiles'),
      }),
    ).resolves.toBeUndefined();
    expect(lines.join('\n')).toContain('unknown subcommand');
  });

  it('executes core read and delivery-control commands without creating a model turn', async () => {
    const request = vi.fn(async (operation: string, payload: unknown) => {
      switch (operation) {
        case 'get_identity':
          return { device_id: 'aa'.repeat(32) };
        case 'list_conversations':
          return { conversation_ids: [] };
        case 'set_active_conversation':
          return {
            active_conversation_id:
              typeof payload === 'object' &&
              payload !== null &&
              'conversation_id' in payload &&
              typeof payload.conversation_id === 'string'
                ? payload.conversation_id
                : '',
          };
        case 'set_auto_delivery':
          return {};
        case 'service.status':
          return serviceStatus({
            deviceId: 'bb'.repeat(32),
            relayConfigured: false,
            watchedConversations: 1,
            pendingEvents: 2,
            claimedEvents: 3,
            deliveryDegraded: true,
          });
        default:
          throw new Error('unexpected operation');
      }
    });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    for (const args of [
      '',
      'help',
      'status',
      'identity',
      'conversations',
      `use ${'01'.repeat(32)}`,
      `mute ${'01'.repeat(32)}`,
      `unmute ${'01'.repeat(32)}`,
    ]) {
      await command?.handler(commandContext(args));
    }

    expect(lines.join('\n')).toContain('Konclave commands');
    expect(lines.join('\n')).toContain('delivery: degraded');
    expect(lines.join('\n')).toContain('no conversations yet');
    expect(lines.join('\n')).toContain(`active conversation selected: ${'01'.repeat(32)}`);
    expect(request).toHaveBeenCalledWith('set_active_conversation', {
      conversation_id: '01'.repeat(32),
    });
    expect(request).toHaveBeenCalledWith('set_auto_delivery', {
      conversation_id: '01'.repeat(32),
      enabled: false,
    });
    expect(request).toHaveBeenCalledWith('set_auto_delivery', {
      conversation_id: '01'.repeat(32),
      enabled: true,
    });
    expect(
      request.mock.calls.filter(([operation]) => operation === 'set_active_conversation'),
    ).toHaveLength(1);
    expect(
      request.mock.calls.filter(([operation]) => operation === 'set_auto_delivery'),
    ).toHaveLength(2);
  });

  it('manages collaboration policies through deterministic nested commands', async () => {
    const proposalId = '55'.repeat(16);
    const replacementProposalId = '56'.repeat(16);
    const policyDigest = '66'.repeat(32);
    const messageId = '77'.repeat(16);
    const source = '{"apiVersion":"konclave.dev/v1"}';
    const peerGuidance = `${'g'.repeat(2_050)}guidance-tail`;
    const request = vi.fn(async (operation: string, payload: unknown) => {
      const record =
        typeof payload === 'object' && payload !== null ? (payload as Record<string, unknown>) : {};
      switch (operation) {
        case 'list_conversations':
          return {
            conversation_ids: [conversationId],
            active_conversation_id: conversationId,
          };
        case 'get_collaboration_policy_status':
          return {
            conversation_id: conversationId,
            active_policy: {
              policy_digest: policyDigest,
              name: 'contract-alignment',
              activated_at_unix_milliseconds: '18446744073709551615',
              statements: [
                {
                  statement_id: 'conversation-reply',
                  effect: 'allow',
                  action: 'conversation.reply',
                  resource: null,
                },
              ],
              required_harness_claims: ['harness.session-identity'],
              limits: {
                duration_milliseconds: '18446744073709551615',
                turns: '18446744073709551615',
                tokens: '18446744073709551615',
                concurrent_requests: 1,
              },
            },
          };
        case 'inspect_collaboration_policy_proposal':
          return {
            conversation_id: conversationId,
            proposal_id: record.proposal_id,
            policy_digest: policyDigest,
            replaces_policy_digest: null,
            proposer_device_id: '88'.repeat(32),
            message_id: '89'.repeat(16),
            relay_cursor: 3,
            name: 'peer-contract-alignment',
            untrusted_guidance: peerGuidance,
            statements: [
              {
                statement_id: 'conversation-reply',
                effect: 'allow',
                action: 'conversation.reply',
                resource: null,
              },
            ],
            required_harness_claims: ['harness.session-identity'],
            limits: {
              duration_milliseconds: null,
              turns: null,
              tokens: null,
              concurrent_requests: 1,
            },
          };
        case 'propose_collaboration_policy_source':
        case 'resume_collaboration_policy_proposal':
        case 'accept_collaboration_policy':
        case 'reject_collaboration_policy':
          return {
            conversation_id: conversationId,
            proposal_id: record.proposal_id,
            policy_digest: policyDigest,
            message_id: messageId,
            cursor: 1,
            local_binding_changed: true,
          };
        case 'revoke_collaboration_policy':
          return {
            conversation_id: conversationId,
            proposal_id: null,
            policy_digest: policyDigest,
            message_id: record.message_id,
            cursor: 2,
            local_binding_changed: true,
          };
        default:
          throw new Error(`unexpected operation: ${operation}`);
      }
    });
    const readPolicySource = vi.fn().mockResolvedValue(source);
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      readPolicySource,
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    for (const args of [
      'policy help',
      'policy status',
      `policy propose ${proposalId} -- policy examples/contract.json`,
      `policy resume ${proposalId}`,
      `policy inspect ${proposalId}`,
      `policy replace ${policyDigest} ${replacementProposalId} -- policy examples/replacement.json`,
      `policy accept ${proposalId} ${policyDigest}`,
      `policy reject ${replacementProposalId} ${policyDigest}`,
      `policy revoke ${policyDigest} ${messageId}`,
    ]) {
      await command?.handler(commandContext(args));
    }

    expect(readPolicySource).toHaveBeenNthCalledWith(1, 'policy examples/contract.json');
    expect(readPolicySource).toHaveBeenNthCalledWith(2, 'policy examples/replacement.json');
    expect(request).toHaveBeenCalledWith('inspect_collaboration_policy_proposal', {
      conversation_id: conversationId,
      proposal_id: proposalId,
    });
    expect(request).toHaveBeenCalledWith(
      'resume_collaboration_policy_proposal',
      {
        conversation_id: conversationId,
        proposal_id: proposalId,
      },
      { requestId: expect.any(Buffer) },
    );
    expect(request).toHaveBeenCalledWith(
      'propose_collaboration_policy_source',
      {
        conversation_id: conversationId,
        proposal_id: proposalId,
        source,
      },
      { requestId: expect.any(Buffer) },
    );
    expect(request).toHaveBeenCalledWith(
      'propose_collaboration_policy_source',
      {
        conversation_id: conversationId,
        proposal_id: replacementProposalId,
        source,
        replaces_policy_digest: policyDigest,
      },
      { requestId: expect.any(Buffer) },
    );
    expect(request).toHaveBeenCalledWith(
      'accept_collaboration_policy',
      {
        conversation_id: conversationId,
        proposal_id: proposalId,
        policy_digest: policyDigest,
      },
      { requestId: expect.any(Buffer) },
    );
    expect(request).toHaveBeenCalledWith(
      'reject_collaboration_policy',
      {
        conversation_id: conversationId,
        proposal_id: replacementProposalId,
        policy_digest: policyDigest,
      },
      { requestId: expect.any(Buffer) },
    );
    expect(request).toHaveBeenCalledWith(
      'revoke_collaboration_policy',
      {
        conversation_id: conversationId,
        message_id: messageId,
        policy_digest: policyDigest,
      },
      { requestId: expect.any(Buffer) },
    );
    expect(lines.join('\n')).toContain('policy: contract-alignment');
    expect(lines.join('\n')).toContain('18446744073709551615');
    expect(lines.join('\n')).toContain('peer-proposed guidance (UNTRUSTED; review as data)');
    expect(lines.join('\n')).toContain('guidance-tail');
    expect(lines.join('\n')).toContain('statement conversation-reply: allow conversation.reply');
    expect(lines.join('\n')).toContain('local binding changed: yes');
  });

  it('creates a bounded ephemeral pairing capability', async () => {
    const request = vi.fn(async (operation: string) => {
      if (operation !== 'create_pairing_capability') {
        throw new Error('unexpected operation');
      }
      return {
        pairing: pairingStatus({ requested_role: 'administrator' }),
        capability: 'pairing_capability-1',
      };
    });
    const entries: Array<{ line: string; options: CommandOutputOptions | undefined }> = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line, options) => {
          entries.push({ line, options });
        },
      },
    })[0];

    await command?.handler(commandContext('pair administrator'));

    expect(request).toHaveBeenCalledWith('create_pairing_capability', {
      requested_role: 'administrator',
    });
    expect(entries.some((entry) => entry.line === `pairing: ${pairingId}`)).toBe(true);
    expect(entries).toContainEqual({
      line: 'pairing_capability-1',
      options: { ephemeral: true },
    });
  });

  it('completes the joiner side of an AccountTrusted connection', async () => {
    let syncCount = 0;
    const sleep = vi.fn().mockResolvedValue(undefined);
    const request = vi.fn(async (operation: string) => {
      switch (operation) {
        case 'service.status':
          return serviceStatus();
        case 'create_pairing_capability':
          return {
            pairing: pairingStatus(),
            capability: 'pairing_capability-1',
          };
        case 'sync_pairing':
          syncCount += 1;
          if (syncCount === 1) {
            return {
              pairing: pairingStatus(),
              processed_records: 0,
            };
          }
          return syncCount === 2
            ? {
                pairing: pairingStatus({
                  phase: 'joiner_awaiting_inviter_authorization',
                  inviter_device_id: inviterDeviceId,
                  conversation_id: conversationId,
                  granted_role: 'member',
                }),
                processed_records: 1,
              }
            : {
                pairing: pairingStatus({
                  phase: 'completed',
                  inviter_device_id: inviterDeviceId,
                  conversation_id: conversationId,
                  granted_role: 'member',
                }),
                processed_records: 1,
              };
        case 'authorize_pairing_inviter':
          return pairingStatus({
            phase: 'joiner_awaiting_welcome',
            inviter_device_id: inviterDeviceId,
            conversation_id: conversationId,
            granted_role: 'member',
            completion_deadline_unix_seconds: 1_787_806_000,
          });
        default:
          throw new Error('unexpected operation');
      }
    });
    const entries: Array<{ line: string; options: CommandOutputOptions | undefined }> = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      nowUnixMilliseconds: () => 1_787_805_000_000,
      sleep,
      output: {
        write: (line, options) => {
          entries.push({ line, options });
        },
      },
    })[0];

    await command?.handler(commandContext('connect'));

    expect(request).toHaveBeenCalledWith('create_pairing_capability', {
      requested_role: 'member',
    });
    expect(request).toHaveBeenCalledWith(
      'authorize_pairing_inviter',
      {
        pairing_id: pairingId,
        inviter_device_id: inviterDeviceId,
        conversation_id: conversationId,
        granted_role: 'member',
      },
      {
        deadlineMs: expect.any(Number),
      },
    );
    expect(entries).toContainEqual({
      line: 'pairing_capability-1',
      options: { ephemeral: true },
    });
    expect(entries.some((entry) => entry.line === `connected: ${conversationId}`)).toBe(true);
    expect(entries.map((entry) => entry.line).join('\n')).toContain(
      'no independent identity verification',
    );
    expect(sleep).toHaveBeenCalledWith(500);
  });

  it('completes the inviter side of an AccountTrusted connection', async () => {
    let syncCount = 0;
    const request = vi.fn(async (operation: string) => {
      switch (operation) {
        case 'service.status':
          return serviceStatus();
        case 'redeem_pairing_capability':
          return pairingStatus({
            local_role: 'inviter',
            phase: 'inviter_awaiting_authorization',
          });
        case 'create_conversation':
          return { conversation_id: conversationId, routing_id: '55'.repeat(32), epoch: 0 };
        case 'authorize_pairing_joiner':
          return pairingStatus({
            local_role: 'inviter',
            phase: 'inviter_awaiting_join_proof',
            inviter_device_id: inviterDeviceId,
            conversation_id: conversationId,
            granted_role: 'member',
          });
        case 'sync_pairing':
          syncCount += 1;
          return {
            pairing: pairingStatus({
              local_role: 'inviter',
              phase: syncCount === 1 ? 'inviter_awaiting_completion' : 'completed',
              inviter_device_id: inviterDeviceId,
              conversation_id: conversationId,
              granted_role: 'member',
              completion_deadline_unix_seconds: 1_787_806_000,
            }),
            processed_records: 1,
          };
        default:
          throw new Error('unexpected operation');
      }
    });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      nowUnixMilliseconds: () => 1_787_805_000_000,
      sleep: vi.fn().mockResolvedValue(undefined),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('connect pairing_capability-1'));

    expect(request).toHaveBeenCalledWith('redeem_pairing_capability', {
      capability: 'pairing_capability-1',
    });
    expect(request).toHaveBeenCalledWith('create_conversation', {});
    expect(request).toHaveBeenCalledWith(
      'authorize_pairing_joiner',
      {
        pairing_id: pairingId,
        conversation_id: conversationId,
        granted_role: 'member',
      },
      {
        deadlineMs: expect.any(Number),
      },
    );
    expect(lines).toContain(`connected: ${conversationId}`);
  });

  it('refuses connection automation outside AccountTrusted policy', async () => {
    const request = vi.fn().mockResolvedValue(
      serviceStatus({
        authorizationPolicy: 'HarnessAttested',
        authorizationEvidence: ['harness_attested'],
      }),
    );
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('connect'));

    expect(lines.join('\n')).toContain('connect requires the AccountTrusted');
    expect(request).toHaveBeenCalledTimes(1);
    expect(request).not.toHaveBeenCalledWith('create_pairing_capability', expect.anything());
  });

  it('refuses connection setup before side effects when the relay is unavailable', async () => {
    const request = vi.fn().mockResolvedValue(serviceStatus({ relayConfigured: false }));
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('connect'));

    expect(lines.join('\n')).toContain('connect requires a configured relay');
    expect(request).toHaveBeenCalledTimes(1);
    expect(request).not.toHaveBeenCalledWith('create_pairing_capability', expect.anything());
  });

  it('refuses administrator capabilities in the AccountTrusted connection flow', async () => {
    const request = vi.fn(async (operation: string) => {
      if (operation === 'service.status') {
        return serviceStatus();
      }
      if (operation === 'redeem_pairing_capability') {
        return pairingStatus({
          local_role: 'inviter',
          phase: 'inviter_awaiting_authorization',
          requested_role: 'administrator',
        });
      }
      throw new Error('unexpected operation');
    });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('connect pairing_capability-1'));

    expect(lines.join('\n')).toContain('accepts only member pairing requests');
    expect(request).not.toHaveBeenCalledWith('create_conversation', expect.anything());
    expect(request).not.toHaveBeenCalledWith('authorize_pairing_joiner', expect.anything());
  });

  it('stops AccountTrusted connection progress on cancellation and deadline', async () => {
    const cancelledRequest = vi.fn(async (operation: string) => {
      if (operation === 'service.status') {
        return serviceStatus();
      }
      if (operation === 'create_pairing_capability') {
        return {
          pairing: pairingStatus(),
          capability: 'pairing_capability-1',
        };
      }
      if (operation === 'sync_pairing') {
        return {
          pairing: pairingStatus({ phase: 'cancelled' }),
          processed_records: 1,
        };
      }
      throw new Error('unexpected operation');
    });
    const cancelledLines: string[] = [];
    const cancelledCommand = createKonclaveCommands({
      client: stubClient(cancelledRequest),
      nowUnixMilliseconds: () => 1_787_805_000_000,
      sleep: vi.fn().mockResolvedValue(undefined),
      output: {
        write: (line) => {
          cancelledLines.push(line);
        },
      },
    })[0];
    await cancelledCommand?.handler(commandContext('connect'));

    const expiredRequest = vi.fn(async (operation: string) => {
      if (operation === 'service.status') {
        return serviceStatus();
      }
      if (operation === 'create_pairing_capability') {
        return {
          pairing: pairingStatus({ authorization_deadline_unix_seconds: 1_787_805_000 }),
          capability: 'pairing_capability-1',
        };
      }
      throw new Error('unexpected operation');
    });
    const expiredLines: string[] = [];
    const expiredCommand = createKonclaveCommands({
      client: stubClient(expiredRequest),
      nowUnixMilliseconds: () => 1_787_805_000_000,
      sleep: vi.fn().mockResolvedValue(undefined),
      output: {
        write: (line) => {
          expiredLines.push(line);
        },
      },
    })[0];
    await expiredCommand?.handler(commandContext('connect'));

    expect(cancelledLines.join('\n')).toContain('pairing was cancelled');
    expect(expiredLines.join('\n')).toContain('connect timed out');
    expect(expiredRequest).not.toHaveBeenCalledWith('sync_pairing', expect.anything());
  });

  it('bounds stalled and malformed AccountTrusted connection state', async () => {
    const stalledRequest = vi.fn(async (operation: string) => {
      if (operation === 'service.status') {
        return serviceStatus();
      }
      if (operation === 'create_pairing_capability') {
        return {
          pairing: pairingStatus({ authorization_deadline_unix_seconds: 1_787_806_000 }),
          capability: 'pairing_capability-1',
        };
      }
      if (operation === 'sync_pairing') {
        return {
          pairing: pairingStatus({ authorization_deadline_unix_seconds: 1_787_806_000 }),
          processed_records: 1,
        };
      }
      throw new Error('unexpected operation');
    });
    const stalledLines: string[] = [];
    const stalledCommand = createKonclaveCommands({
      client: stubClient(stalledRequest),
      nowUnixMilliseconds: () => 1_787_805_000_000,
      sleep: vi.fn().mockResolvedValue(undefined),
      output: {
        write: (line) => {
          stalledLines.push(line);
        },
      },
    })[0];
    await stalledCommand?.handler(commandContext('connect'));

    const malformedLines: string[] = [];
    const malformedCommand = createKonclaveCommands({
      client: stubClient(
        vi.fn().mockResolvedValue(
          serviceStatus({
            authorizationPolicy: 'AccountTrusted',
            authorizationEvidence: ['account_trusted'],
          }),
        ),
      ),
      output: {
        write: (line) => {
          malformedLines.push(line);
        },
      },
    })[0];
    await malformedCommand?.handler(commandContext('connect pairing_capability-1'));

    expect(stalledLines.join('\n')).toContain('connect exceeded its progress limit');
    expect(
      stalledRequest.mock.calls.filter(([operation]) => operation === 'sync_pairing'),
    ).toHaveLength(640);
    expect(malformedLines.join('\n')).toContain('pairing role is malformed');
  });

  it('redeems, creates, and approves an inviter-side pairing explicitly', async () => {
    const request = vi.fn(async (operation: string) => {
      switch (operation) {
        case 'redeem_pairing_capability':
        case 'get_pairing_status':
          return pairingStatus({
            local_role: 'inviter',
            phase: 'inviter_awaiting_authorization',
            requested_role: 'administrator',
          });
        case 'create_conversation':
          return { conversation_id: conversationId, routing_id: '55'.repeat(32), epoch: 0 };
        case 'authorize_pairing_joiner':
          return pairingStatus({
            local_role: 'inviter',
            phase: 'inviter_awaiting_join_proof',
            conversation_id: conversationId,
            granted_role: 'member',
            inviter_device_id: inviterDeviceId,
          });
        default:
          throw new Error('unexpected operation');
      }
    });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('join pairing_capability-1'));
    await command?.handler(commandContext('new'));
    await command?.handler(commandContext(`approve ${pairingId} ${conversationId}`));

    expect(request).toHaveBeenCalledWith('redeem_pairing_capability', {
      capability: 'pairing_capability-1',
    });
    expect(request).toHaveBeenCalledWith('create_conversation', {});
    expect(request).toHaveBeenCalledWith('authorize_pairing_joiner', {
      pairing_id: pairingId,
      conversation_id: conversationId,
      granted_role: 'member',
    });
    expect(lines.join('\n')).toContain(`joiner device: ${joinerDeviceId}`);
    expect(lines.join('\n')).toContain(`conversation: ${conversationId}`);
    expect(lines.join('\n')).toContain('phase: inviter_awaiting_join_proof');
  });

  it('approves a joiner-side pairing and exposes bounded progress controls', async () => {
    const awaitingInviter = pairingStatus({
      phase: 'joiner_awaiting_inviter_authorization',
      inviter_device_id: inviterDeviceId,
      conversation_id: conversationId,
      granted_role: 'member',
    });
    const request = vi.fn(async (operation: string) => {
      switch (operation) {
        case 'get_pairing_status':
          return awaitingInviter;
        case 'authorize_pairing_inviter':
          return pairingStatus({
            ...awaitingInviter,
            phase: 'joiner_awaiting_welcome',
          });
        case 'sync_pairing':
          return {
            pairing: pairingStatus({
              ...awaitingInviter,
              phase: 'completed',
            }),
            processed_records: 2,
          };
        case 'cancel_pairing':
          return pairingStatus({
            ...awaitingInviter,
            phase: 'cancelled',
          });
        default:
          throw new Error('unexpected operation');
      }
    });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext(`pairing ${pairingId}`));
    await command?.handler(
      commandContext(`approve ${pairingId} ${'55'.repeat(32)} ${conversationId} member`),
    );
    await command?.handler(
      commandContext(`approve ${pairingId} ${inviterDeviceId} ${conversationId} member`),
    );
    await command?.handler(commandContext(`sync ${pairingId}`));
    await command?.handler(commandContext(`cancel ${pairingId}`));

    expect(request).toHaveBeenCalledWith('authorize_pairing_inviter', {
      pairing_id: pairingId,
      inviter_device_id: inviterDeviceId,
      conversation_id: conversationId,
      granted_role: 'member',
    });
    expect(lines.join('\n')).toContain(
      'approval values do not match the authenticated pairing state',
    );
    expect(lines.join('\n')).toContain('processed pairing records: 2');
    expect(lines.join('\n')).toContain('phase: completed');
    expect(lines.join('\n')).toContain('phase: cancelled');
  });

  it('sends, replies, and displays synchronized peer text ephemerally', async () => {
    const replyToMessageId = '66'.repeat(16);
    const sentMessageId = '88'.repeat(16);
    const request = vi.fn(async (operation: string, payload: unknown, _options?: unknown) => {
      if (operation === 'send_message') {
        if (typeof payload !== 'object' || payload === null || !('message_id' in payload)) {
          throw new Error('missing message identifier');
        }
        return {
          conversation_id: conversationId,
          message_id: payload.message_id,
          sender_counter: 1,
          cursor: 8,
        };
      }
      if (operation === 'sync_messages') {
        return { messages: [], has_more: false };
      }
      if (operation === 'list_conversations') {
        return { conversation_ids: [conversationId] };
      }
      if (operation === 'set_active_conversation') {
        if (typeof payload !== 'object' || payload === null || !('conversation_id' in payload)) {
          throw new Error('missing conversation selection');
        }
        return { active_conversation_id: payload.conversation_id };
      }
      if (operation === 'read_messages') {
        return {
          messages: [
            {
              conversation_id: conversationId,
              message_id: replyToMessageId,
              envelope_id: '77'.repeat(16),
              sender_device_id: inviterDeviceId,
              epoch: 1,
              sender_counter: 2,
              sent_at_unix_milliseconds: 1,
              reply_to_message_id: null,
              cursor: 8,
              direction: 'inbound',
              text: 'peer line one\npeer \u202Eline two',
              duplicate: false,
            },
            {
              conversation_id: conversationId,
              message_id: '89'.repeat(16),
              envelope_id: '90'.repeat(16),
              sender_device_id: inviterDeviceId,
              epoch: 1,
              sender_counter: 3,
              sent_at_unix_milliseconds: 2,
              reply_to_message_id: null,
              cursor: 9,
              direction: 'inbound',
              content_type: 'directed_request',
              target_device_id: '91'.repeat(32),
              text: 'confirm the response contract',
              duplicate: false,
            },
          ],
          has_more: true,
        };
      }
      throw new Error('unexpected operation');
    });
    const entries: Array<{ line: string; options: CommandOutputOptions | undefined }> = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line, options) => {
          entries.push({ line, options });
        },
      },
    })[0];

    await command?.handler(
      commandContext(`send ${conversationId} ${sentMessageId} -- hello -- contract`),
    );
    await command?.handler(
      commandContext(`reply ${conversationId} ${replyToMessageId} -- acknowledged`),
    );
    await command?.handler(commandContext('send -- implicit hello'));
    await command?.handler(commandContext(`messages ${conversationId} 7`));

    const sends = request.mock.calls.filter(([operation]) => operation === 'send_message');
    expect(sends).toHaveLength(3);
    expect(sends[0]?.[1]).toMatchObject({
      conversation_id: conversationId,
      message_id: sentMessageId,
      text: 'hello -- contract',
    });
    expect(sends[1]?.[1]).toMatchObject({
      conversation_id: conversationId,
      reply_to_message_id: replyToMessageId,
      text: 'acknowledged',
    });
    expect(sends[2]?.[1]).toMatchObject({
      conversation_id: conversationId,
      text: 'implicit hello',
    });
    expect(
      request.mock.calls.filter(([operation]) => operation === 'set_active_conversation'),
    ).toHaveLength(2);
    expect(
      sends.every(
        ([, payload]) =>
          typeof payload === 'object' &&
          payload !== null &&
          'message_id' in payload &&
          typeof payload.message_id === 'string' &&
          /^[0-9a-f]{32}$/u.test(payload.message_id),
      ),
    ).toBe(true);
    const requestOptions = sends[0]?.[2];
    expect(requestOptions).toEqual({ requestId: expect.any(Buffer) });
    if (
      typeof requestOptions !== 'object' ||
      requestOptions === null ||
      !('requestId' in requestOptions) ||
      !Buffer.isBuffer(requestOptions.requestId)
    ) {
      throw new Error('command did not provide a binary request identifier');
    }
    expect(requestOptions.requestId).toHaveLength(16);
    expect(request).toHaveBeenCalledWith('read_messages', {
      conversation_id: conversationId,
      after_cursor: 7,
      limit: 10,
    });
    expect(
      entries.some(
        (entry) =>
          entry.line === 'untrusted peer text: "peer line one\\npeer �line two"' &&
          entry.options?.ephemeral === true,
      ),
    ).toBe(true);
    expect(
      entries.some(
        (entry) =>
          entry.line ===
            `untrusted peer directed request to ${'91'.repeat(32)}: "confirm the response contract"` &&
          entry.options?.ephemeral === true,
      ),
    ).toBe(true);
    expect(entries.some((entry) => entry.line === 'resume after cursor: 9')).toBe(true);
    expect(entries.some((entry) => entry.line.includes('more messages are available'))).toBe(true);
  });

  it('displays typed policy history without treating receipt as authority', async () => {
    const proposalId = '31'.repeat(16);
    const policyDigest = '32'.repeat(32);
    const replacementDigest = '33'.repeat(32);
    const baseMessage = {
      conversation_id: conversationId,
      envelope_id: '34'.repeat(16),
      sender_device_id: inviterDeviceId,
      epoch: 1,
      sender_counter: 2,
      sent_at_unix_milliseconds: 1,
      reply_to_message_id: null,
      duplicate: false,
    };
    const request = vi.fn(async (operation: string) => {
      if (operation === 'sync_messages') {
        return { messages: [], has_more: false };
      }
      if (operation === 'read_messages') {
        return {
          messages: [
            {
              ...baseMessage,
              message_id: '35'.repeat(16),
              cursor: 1,
              direction: 'inbound',
              content_type: 'collaboration_policy_proposal',
              proposal_id: proposalId,
              policy_digest: policyDigest,
              replaces_policy_digest: null,
            },
            {
              ...baseMessage,
              message_id: '36'.repeat(16),
              cursor: 2,
              direction: 'inbound',
              content_type: 'collaboration_policy_proposal',
              proposal_id: proposalId,
              policy_digest: policyDigest,
              replaces_policy_digest: replacementDigest,
            },
            {
              ...baseMessage,
              message_id: '37'.repeat(16),
              cursor: 3,
              direction: 'outbound',
              content_type: 'collaboration_policy_response',
              proposal_id: proposalId,
              policy_digest: policyDigest,
              outcome: 'accepted',
            },
            {
              ...baseMessage,
              message_id: '38'.repeat(16),
              cursor: 4,
              direction: 'inbound',
              content_type: 'collaboration_policy_revocation',
              policy_digest: policyDigest,
            },
          ],
          has_more: false,
        };
      }
      throw new Error('unexpected operation');
    });
    const entries: Array<{ line: string; options: CommandOutputOptions | undefined }> = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line, options) => {
          entries.push({ line, options });
        },
      },
    })[0];

    await command?.handler(commandContext(`messages ${conversationId}`));

    const output = entries.map((entry) => entry.line).join('\n');
    expect(output).toContain('receipt does not activate local authority');
    expect(output).toContain(`replacing ${replacementDigest}`);
    expect(output).toContain('local policy response');
    expect(output).toContain('reported accepted');
    expect(output).toContain('untrusted peer policy revocation');
    expect(
      entries
        .filter((entry) => entry.line.includes('policy '))
        .every((entry) => entry.options?.ephemeral === true),
    ).toBe(true);
  });

  it('restores the active conversation for implicit sends after restart', async () => {
    const otherConversationId = '99'.repeat(32);
    const request = vi.fn(async (operation: string, payload: unknown) => {
      if (operation === 'list_conversations') {
        return {
          conversation_ids: [otherConversationId],
          active_conversation_id: conversationId,
        };
      }
      if (operation === 'send_message') {
        if (
          typeof payload !== 'object' ||
          payload === null ||
          !('conversation_id' in payload) ||
          !('message_id' in payload)
        ) {
          throw new Error('missing message identity');
        }
        return {
          conversation_id: payload.conversation_id,
          message_id: payload.message_id,
          sender_counter: 1,
          cursor: 9,
        };
      }
      throw new Error('unexpected operation');
    });
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: { write: () => {} },
    })[0];

    await command?.handler(commandContext('send -- resumed hello'));

    expect(request).toHaveBeenCalledWith('list_conversations', {});
    expect(request).toHaveBeenCalledWith(
      'send_message',
      expect.objectContaining({
        conversation_id: conversationId,
        text: 'resumed hello',
      }),
      { requestId: expect.any(Buffer) },
    );
  });

  it('fails closed when the persisted active conversation is malformed', async () => {
    const lines: string[] = [];
    const request = vi.fn().mockResolvedValueOnce({
      conversation_ids: [conversationId],
      active_conversation_id: 'short',
    });
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('send -- malformed active'));

    expect(lines.join('\n')).toContain('active conversation identifier');
    expect(request).not.toHaveBeenCalledWith('send_message', expect.anything(), expect.anything());
  });

  it('requires explicit selection when a migrated profile has no active conversation', async () => {
    const lines: string[] = [];
    const request = vi.fn().mockResolvedValue({
      conversation_ids: [conversationId],
      active_conversation_id: null,
    });
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('send -- do not guess'));

    expect(lines.join('\n')).toContain('no active conversation is selected');
    expect(request).not.toHaveBeenCalledWith('send_message', expect.anything(), expect.anything());
  });

  it('rejects unsafe workflow arguments before their side effects', async () => {
    const request = vi.fn(async (operation: string) => {
      if (operation === 'get_pairing_status') {
        return pairingStatus({
          local_role: 'inviter',
          phase: 'inviter_awaiting_authorization',
          requested_role: 'member',
        });
      }
      throw new Error('unexpected operation');
    });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('join capability with spaces'));
    await command?.handler(commandContext(`approve ${pairingId} ${conversationId} administrator`));
    await command?.handler(commandContext(`send ${conversationId} missing-separator`));
    await command?.handler(commandContext(`messages ${conversationId} unsafe-cursor`));

    expect(lines.join('\n')).toContain('valid pairing capability is required');
    expect(lines.join('\n')).toContain('cannot be elevated');
    expect(lines.join('\n')).toContain('usage: /konclave send');
    expect(lines.join('\n')).toContain('after-cursor must be');
    expect(request).not.toHaveBeenCalledWith('authorize_pairing_joiner', expect.anything());
    expect(request).not.toHaveBeenCalledWith('send_message', expect.anything());
    expect(request).not.toHaveBeenCalledWith('sync_messages', expect.anything());
  });

  it('surfaces malformed workflow results as bounded command failures', async () => {
    const pairingLines: string[] = [];
    const pairingCommand = createKonclaveCommands({
      client: stubClient(
        vi.fn().mockResolvedValue({
          pairing: pairingStatus({ phase: 'invented_phase' }),
          capability: 'pairing_capability-1',
        }),
      ),
      output: {
        write: (line) => {
          pairingLines.push(line);
        },
      },
    })[0];
    await pairingCommand?.handler(commandContext('pair member'));

    const sentLines: string[] = [];
    const sentCommand = createKonclaveCommands({
      client: stubClient(
        vi.fn().mockResolvedValue({
          conversation_id: conversationId,
          message_id: '88'.repeat(16),
          cursor: 'not-an-integer',
        }),
      ),
      output: {
        write: (line) => {
          sentLines.push(line);
        },
      },
    })[0];
    await sentCommand?.handler(
      commandContext(`send ${conversationId} ${'88'.repeat(16)} -- hello`),
    );

    const messageLines: string[] = [];
    const messageRequest = vi
      .fn()
      .mockResolvedValueOnce({ messages: [], has_more: false })
      .mockResolvedValueOnce({
        messages: [
          {
            message_id: '99'.repeat(16),
            sender_device_id: 'short',
            cursor: 1,
            direction: 'inbound',
            text: 'hello',
            duplicate: false,
          },
        ],
        has_more: false,
      });
    const messageCommand = createKonclaveCommands({
      client: stubClient(messageRequest),
      output: {
        write: (line) => {
          messageLines.push(line);
        },
      },
    })[0];
    await messageCommand?.handler(commandContext(`messages ${conversationId}`));

    expect(pairingLines.join('\n')).toContain('pairing phase is malformed');
    expect(sentLines.join('\n')).toContain('sent-message response is malformed');
    expect(messageLines.join('\n')).toContain('sender device identifier');
  });

  it('bounds conversation output and reports malformed command results', async () => {
    const conversations = Array.from({ length: 24 }, (_, index) =>
      index.toString(16).padStart(64, '0'),
    );
    const request = vi
      .fn()
      .mockResolvedValueOnce({ conversation_ids: conversations })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ conversation_ids: [7] })
      .mockRejectedValueOnce(new LocalServiceError('service.status', 'busy'))
      .mockRejectedValueOnce({ opaque: true });
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(request),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('conversations'));
    expect(lines).toHaveLength(20);
    await command?.handler(commandContext('identity'));
    await command?.handler(commandContext('conversations'));
    await command?.handler(commandContext('status'));
    await command?.handler(commandContext('identity'));

    expect(lines.join('\n')).toContain('identity response is malformed');
    expect(lines.join('\n')).toContain('conversation response is malformed');
    expect(lines.join('\n')).toContain('service.status failed (busy)');
    expect(lines.at(-1)).toBe('konclave: failed');
  });

  it('reports invalid mute identifiers and argument bounds as command output', async () => {
    const lines: string[] = [];
    const command = createKonclaveCommands({
      client: stubClient(),
      output: {
        write: (line) => {
          lines.push(line);
        },
      },
    })[0];

    await command?.handler(commandContext('mute not-an-id'));
    await command?.handler(commandContext('one two three four five'));
    await command?.handler(commandContext(`status ${'x'.repeat(129)}`));
    await command?.handler(commandContext('x'.repeat(16 * 1024 + 1)));

    expect(lines.join('\n')).toContain('conversation identifier is required');
    expect(lines.join('\n')).toContain('unknown subcommand');
    expect(lines.join('\n')).toContain('argument is too long');
    expect(lines.join('\n')).toContain('command is too long');
  });
});

describe('session join configuration', () => {
  it('declares no MCP server and therefore starts no daemon', () => {
    const config = createExtensionJoinConfig(stubClient(), { write: () => {} });

    expect(config.mcpServers).toEqual({});
    expect(Object.keys(config.mcpServers)).toHaveLength(0);
    expect(config.hooks).toEqual({});
    expect(config.tools.map((tool) => tool.name).sort()).toEqual([...toolOperations].sort());
    expect(config.commands.map((command) => command.name)).toEqual(['konclave']);
    // Nothing in the configuration names an executable to launch.
    expect(JSON.stringify(config)).not.toContain('KonclaveLocalDaemon');
  });
});

describe('issuer key material', () => {
  it('never exposes a signing seed through an error or a key object', () => {
    const seed = Buffer.alloc(32, 7);
    const key = privateKeyFromSeed(seed);
    expect(String(key)).not.toContain(seed.toString('hex'));
    expect(() => privateKeyFromSeed(Buffer.alloc(31))).toThrow(
      'an Ed25519 seed must be exactly 32 bytes',
    );
    expect(() => publicKeyFromRaw(Buffer.alloc(31))).toThrow(
      'an Ed25519 public key must be exactly 32 bytes',
    );
    expect(rawPublicKey(key)).toHaveLength(32);
    expect(
      verifyMessage(publicKeyFromRaw(rawPublicKey(key)), Buffer.alloc(1), Buffer.alloc(63)),
    ).toBe(false);
  });

  it('clears the seed immediately after importing the key', () => {
    const seed = Buffer.alloc(32, 9);
    const key = privateKeyFromSeedAndZeroize(seed);
    expect(seed).toEqual(Buffer.alloc(32));
    expect(String(key)).not.toContain('09'.repeat(32));
  });
});

describe('shared-service delivery adaptation', () => {
  it('maps the bounded service batch onto the existing coordinator contract', async () => {
    const request = vi.fn().mockResolvedValue({
      events: [
        {
          notificationId: '01'.repeat(16),
          leaseGeneration: 2,
          sequence: 3,
          conversation: '04'.repeat(32),
          sender: '05'.repeat(32),
          relayCursor: 6,
          payload: {
            kind: 'application_text',
            messageId: '07'.repeat(16),
            text: 'hello',
          },
        },
      ],
    });

    const channel = createLocalServiceDeliveryChannel(stubClient(request));

    await expect(
      channel.request({ kind: 'wait-and-claim', maxEvents: 8, waitMilliseconds: 20 }),
    ).resolves.toEqual({
      kind: 'batch',
      events: [
        {
          notificationId: Buffer.alloc(16, 1),
          leaseGeneration: 2,
          sequence: 3,
          conversation: Buffer.alloc(32, 4),
          sender: Buffer.alloc(32, 5),
          relayCursor: 6,
          payload: {
            kind: 'application-text',
            messageId: Buffer.alloc(16, 7),
            text: 'hello',
          },
        },
      ],
    });
    expect(request).toHaveBeenCalledWith(
      'delivery.claim',
      { maxEvents: 8, waitMilliseconds: 20 },
      5_020,
    );
  });

  it('preserves directed-request target and body in the coordinator contract', async () => {
    const request = vi.fn().mockResolvedValue({
      events: [
        {
          notificationId: '01'.repeat(16),
          leaseGeneration: 2,
          sequence: 3,
          conversation: '04'.repeat(32),
          sender: '05'.repeat(32),
          relayCursor: 6,
          payload: {
            kind: 'directed_request',
            messageId: '07'.repeat(16),
            targetDeviceId: '06'.repeat(32),
            text: 'confirm the response contract',
          },
        },
      ],
    });
    const channel = createLocalServiceDeliveryChannel(stubClient(request));

    await expect(
      channel.request({ kind: 'wait-and-claim', maxEvents: 8, waitMilliseconds: 20 }),
    ).resolves.toMatchObject({
      kind: 'batch',
      events: [
        {
          payload: {
            kind: 'directed-request',
            messageId: Buffer.alloc(16, 7),
            target: Buffer.alloc(32, 6),
            text: 'confirm the response contract',
          },
        },
      ],
    });
  });

  it('rejects malformed event identifiers before they reach the coordinator', async () => {
    const request = vi.fn().mockResolvedValue({
      events: [
        {
          notificationId: 'not-hex',
          leaseGeneration: 2,
          sequence: 3,
          conversation: '04'.repeat(32),
          sender: '05'.repeat(32),
          relayCursor: 6,
          payload: {
            kind: 'application_text',
            messageId: '07'.repeat(16),
            text: 'hello',
          },
        },
      ],
    });
    const channel = createLocalServiceDeliveryChannel(stubClient(request));

    await expect(
      channel.request({ kind: 'wait-and-claim', maxEvents: 8, waitMilliseconds: 20 }),
    ).rejects.toThrow('delivery response is malformed');
  });

  it('maps membership payloads and delivery transitions', async () => {
    const events = [
      {
        notificationId: '01'.repeat(16),
        leaseGeneration: 2,
        sequence: 3,
        conversation: '04'.repeat(32),
        sender: '05'.repeat(32),
        relayCursor: 6,
        payload: {
          kind: 'member_added',
          device: '06'.repeat(32),
          role: 'administrator',
        },
      },
      {
        notificationId: '02'.repeat(16),
        leaseGeneration: 2,
        sequence: 4,
        conversation: '04'.repeat(32),
        sender: '05'.repeat(32),
        relayCursor: 7,
        payload: { kind: 'member_removed', device: '07'.repeat(32) },
      },
      {
        notificationId: '03'.repeat(16),
        leaseGeneration: 2,
        sequence: 5,
        conversation: '04'.repeat(32),
        sender: '05'.repeat(32),
        relayCursor: 8,
        payload: {
          kind: 'member_role_changed',
          device: '08'.repeat(32),
          role: 'member',
        },
      },
      {
        notificationId: '04'.repeat(16),
        leaseGeneration: 2,
        sequence: 6,
        conversation: '04'.repeat(32),
        sender: '05'.repeat(32),
        relayCursor: 9,
        payload: { kind: 'local_access_removed', device: '09'.repeat(32) },
      },
    ];
    const request = vi
      .fn()
      .mockResolvedValueOnce({ events })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce(
        serviceStatus({
          deviceId: '0a'.repeat(32),
          pendingEvents: 3,
          claimedEvents: 4,
        }),
      );
    const client = stubClient(request);
    const channel = createLocalServiceDeliveryChannel(client);
    const claimed = await channel.request({
      kind: 'wait-and-claim',
      maxEvents: 4,
      waitMilliseconds: 0,
    });
    expect(claimed).toMatchObject({
      kind: 'batch',
      events: [
        { payload: { kind: 'member-added', role: 'administrator' } },
        { payload: { kind: 'member-removed' } },
        { payload: { kind: 'member-role-changed', role: 'member' } },
        { payload: { kind: 'local-access-removed' } },
      ],
    });

    await expect(
      channel.request({
        kind: 'acknowledge',
        notificationId: Buffer.alloc(16, 1),
        leaseGeneration: 2,
      }),
    ).resolves.toEqual({ kind: 'accepted' });
    await expect(
      channel.request({
        kind: 'release',
        notificationId: Buffer.alloc(16, 2),
        leaseGeneration: 2,
      }),
    ).resolves.toEqual({ kind: 'accepted' });
    await expect(channel.request({ kind: 'status' })).resolves.toMatchObject({
      kind: 'status',
      status: {
        pendingEvents: 3,
        claimedEvents: 4,
        watchedConversations: 2,
        deliveryDegraded: false,
      },
    });
    channel.close();
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it('maps collaboration policy exchange payloads without bundle content', async () => {
    const base = {
      leaseGeneration: 2,
      conversation: '04'.repeat(32),
      sender: '05'.repeat(32),
    };
    const request = vi.fn().mockResolvedValue({
      events: [
        {
          ...base,
          notificationId: '01'.repeat(16),
          sequence: 3,
          relayCursor: 6,
          payload: {
            kind: 'collaboration_policy_proposal',
            proposalId: '06'.repeat(16),
            policyDigest: '07'.repeat(32),
            replacesPolicyDigest: null,
          },
        },
        {
          ...base,
          notificationId: '02'.repeat(16),
          sequence: 4,
          relayCursor: 7,
          payload: {
            kind: 'collaboration_policy_proposal',
            proposalId: '08'.repeat(16),
            policyDigest: '09'.repeat(32),
            replacesPolicyDigest: '0a'.repeat(32),
          },
        },
        {
          ...base,
          notificationId: '03'.repeat(16),
          sequence: 5,
          relayCursor: 8,
          payload: {
            kind: 'collaboration_policy_response',
            proposalId: '0b'.repeat(16),
            policyDigest: '0c'.repeat(32),
            outcome: 'rejected',
          },
        },
        {
          ...base,
          notificationId: '04'.repeat(16),
          sequence: 6,
          relayCursor: 9,
          payload: {
            kind: 'collaboration_policy_response',
            proposalId: '0d'.repeat(16),
            policyDigest: '0e'.repeat(32),
            outcome: 'accepted',
          },
        },
        {
          ...base,
          notificationId: '05'.repeat(16),
          sequence: 7,
          relayCursor: 10,
          payload: {
            kind: 'collaboration_policy_revocation',
            policyDigest: '0f'.repeat(32),
          },
        },
      ],
    });
    const channel = createLocalServiceDeliveryChannel(stubClient(request));

    await expect(
      channel.request({ kind: 'wait-and-claim', maxEvents: 5, waitMilliseconds: 0 }),
    ).resolves.toMatchObject({
      kind: 'batch',
      events: [
        {
          payload: {
            kind: 'collaboration-policy-proposal',
            replacesPolicyDigest: undefined,
          },
        },
        {
          payload: {
            kind: 'collaboration-policy-proposal',
            replacesPolicyDigest: Buffer.alloc(32, 10),
          },
        },
        {
          payload: {
            kind: 'collaboration-policy-response',
            outcome: 'rejected',
          },
        },
        {
          payload: {
            kind: 'collaboration-policy-response',
            outcome: 'accepted',
          },
        },
        {
          payload: {
            kind: 'collaboration-policy-revocation',
            policyDigest: Buffer.alloc(32, 15),
          },
        },
      ],
    });
  });

  it('rejects malformed batches, payloads, roles, counts, and status values', async () => {
    const validEvent = {
      notificationId: '01'.repeat(16),
      leaseGeneration: 2,
      sequence: 3,
      conversation: '04'.repeat(32),
      sender: '05'.repeat(32),
      relayCursor: 6,
      payload: {
        kind: 'application_text',
        messageId: '07'.repeat(16),
        text: 'hello',
      },
    };
    const invalid: unknown[] = [
      null,
      {},
      { events: Array.from({ length: 17 }, () => validEvent) },
      { events: [null] },
      { events: [{ ...validEvent, leaseGeneration: -1 }] },
      { events: [{ ...validEvent, sequence: 1.5 }] },
      { events: [{ ...validEvent, sender: 'bad' }] },
      { events: [{ ...validEvent, payload: null }] },
      {
        events: [
          {
            ...validEvent,
            payload: { kind: 'application_text', text: 'hello' },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'application_text',
              messageId: 'bad',
              text: 'hello',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'application_text',
              messageId: '07'.repeat(16),
              text: '',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'application_text',
              messageId: '07'.repeat(16),
              text: 'é'.repeat(40_000),
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'directed_request',
              targetDeviceId: '06'.repeat(32),
              text: 'reply',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'directed_request',
              messageId: 'bad',
              targetDeviceId: '06'.repeat(32),
              text: 'reply',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'directed_request',
              messageId: '07'.repeat(16),
              targetDeviceId: 'bad',
              text: 'reply',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'directed_request',
              messageId: '07'.repeat(16),
              targetDeviceId: '06'.repeat(32),
              text: '',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'collaboration_policy_proposal',
              proposalId: '06'.repeat(16),
              policyDigest: '07'.repeat(32),
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: {
              kind: 'collaboration_policy_response',
              proposalId: '06'.repeat(16),
              policyDigest: '07'.repeat(32),
              outcome: 'unknown',
            },
          },
        ],
      },
      {
        events: [
          {
            ...validEvent,
            payload: { kind: 'member_added', device: '06'.repeat(32), role: 'owner' },
          },
        ],
      },
      { events: [{ ...validEvent, payload: { kind: 'unknown' } }] },
    ];

    for (const value of invalid) {
      const channel = createLocalServiceDeliveryChannel(
        stubClient(vi.fn().mockResolvedValue(value)),
      );
      await expect(
        channel.request({ kind: 'wait-and-claim', maxEvents: 4, waitMilliseconds: 0 }),
      ).rejects.toThrow('delivery response is malformed');
    }

    const invalidStatus = createLocalServiceDeliveryChannel(
      stubClient(vi.fn().mockResolvedValue({ profile: 7 })),
    );
    await expect(invalidStatus.request({ kind: 'status' })).rejects.toThrow(
      'status response is malformed',
    );
  });
});
