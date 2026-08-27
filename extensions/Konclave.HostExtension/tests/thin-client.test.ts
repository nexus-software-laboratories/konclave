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
import { createKonclaveCommands, parseCommandArguments } from '../src/service/commands.js';
import {
  toolOperations,
  isKnownOperation,
  type ServiceStatusResult,
} from '../src/service/operations.js';
import { createLocalServiceDeliveryChannel } from '../src/service/delivery.js';
import { createExtensionJoinConfig, deriveProfileId } from '../src/runtime.js';
import { LocalServiceError, type LocalServiceClient } from '../src/service/client.js';

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

  it('executes every deterministic command without creating a model turn', async () => {
    const request = vi.fn(async (operation: string) => {
      switch (operation) {
        case 'get_identity':
          return { device_id: 'aa'.repeat(32) };
        case 'list_conversations':
          return { conversation_ids: [] };
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
      `mute ${'01'.repeat(16)}`,
      `unmute ${'01'.repeat(16)}`,
    ]) {
      await command?.handler(commandContext(args));
    }

    expect(lines.join('\n')).toContain('Konclave commands');
    expect(lines.join('\n')).toContain('delivery: degraded');
    expect(lines.join('\n')).toContain('no conversations yet');
    expect(request).toHaveBeenCalledWith('set_auto_delivery', {
      conversation_id: '01'.repeat(16),
      enabled: false,
    });
    expect(request).toHaveBeenCalledWith('set_auto_delivery', {
      conversation_id: '01'.repeat(16),
      enabled: true,
    });
  });

  it('bounds conversation output and reports malformed command results', async () => {
    const conversations = Array.from({ length: 24 }, (_, index) =>
      index.toString(16).padStart(32, '0'),
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
    await command?.handler(commandContext('x'.repeat(600)));

    expect(lines.join('\n')).toContain('conversation identifier is required');
    expect(lines.join('\n')).toContain('at most four arguments');
    expect(lines.join('\n')).toContain('arguments are too long');
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
          payload: { kind: 'application_text', text: 'hello' },
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
          payload: { kind: 'application-text', text: 'hello' },
        },
      ],
    });
    expect(request).toHaveBeenCalledWith(
      'delivery.claim',
      { maxEvents: 8, waitMilliseconds: 20 },
      5_020,
    );
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
          payload: { kind: 'application_text', text: 'hello' },
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

  it('rejects malformed batches, payloads, roles, counts, and status values', async () => {
    const validEvent = {
      notificationId: '01'.repeat(16),
      leaseGeneration: 2,
      sequence: 3,
      conversation: '04'.repeat(32),
      sender: '05'.repeat(32),
      relayCursor: 6,
      payload: { kind: 'application_text', text: 'hello' },
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
      { events: [{ ...validEvent, payload: { kind: 'application_text', text: '' } }] },
      {
        events: [
          {
            ...validEvent,
            payload: { kind: 'application_text', text: 'é'.repeat(40_000) },
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
