import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';

import {
  connectLocalService,
  LocalServiceError,
  LocalServiceProtocolError,
  type LocalServiceClientOptions,
} from '../src/service/client.js';
import { FrameError, FrameReader, writeFrame } from '../src/service/framing.js';
import {
  privateKeyFromSeed,
  rawPublicKey,
  signMessage,
  verifyMessage,
} from '../src/service/keys.js';
import {
  clientSigningMessage,
  encodeTranscript,
  serviceSigningMessage,
} from '../src/service/transcript.js';

const handshakeFrameLimit = 256;
const rpcFrameLimit = 1_048_662;
const clientSeed = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
const serviceSeed = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 32));
const clientKey = privateKeyFromSeed(clientSeed);
const serviceKey = privateKeyFromSeed(serviceSeed);
const servicePublicKey = rawPublicKey(serviceKey);
const temporaryDirectories: string[] = [];

type RequestAction =
  | { readonly kind: 'respond'; readonly value: unknown }
  | { readonly kind: 'failure'; readonly wireCode: number }
  | { readonly kind: 'malformed-json' }
  | { readonly kind: 'drop' }
  | { readonly kind: 'silent' };

interface ReceivedRequest {
  readonly requestId: Buffer;
  readonly operation: string;
  readonly payload: unknown;
}

interface TestService {
  readonly endpoint: string;
  close(): Promise<void>;
}

function endpoint(): string {
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\konclave-client-test-${randomBytes(12).toString('hex')}`;
  }
  const directory = mkdtempSync(join(tmpdir(), 'konclave-client-test-'));
  temporaryDirectories.push(directory);
  return join(directory, 'service.sock');
}

function decodeHello(frame: Buffer) {
  if (frame.readUInt8(0) !== 1) {
    throw new Error('expected client hello');
  }
  const adapterKeyId = Buffer.from(frame.subarray(3, 19));
  const adapterKeyVersion = frame.readUInt32BE(19);
  const clientInstance = Buffer.from(frame.subarray(23, 39));
  const profileLength = frame.readUInt16BE(41);
  const profileStart = 43;
  const challengeStart = profileStart + profileLength;
  return {
    adapterKeyId,
    adapterKeyVersion,
    clientInstance,
    profile: frame.subarray(profileStart, challengeStart).toString('ascii'),
    clientChallenge: Buffer.from(frame.subarray(challengeStart)),
  };
}

function decodeRequest(frame: Buffer): ReceivedRequest {
  if (frame.readUInt8(0) !== 16) {
    throw new Error('expected local service request');
  }
  const requestId = Buffer.from(frame.subarray(1, 17));
  const operationLength = frame.readUInt8(17);
  const operationStart = 18;
  const payloadLengthOffset = operationStart + operationLength;
  const payloadStart = payloadLengthOffset + 4;
  const payloadLength = frame.readUInt32BE(payloadLengthOffset);
  const payload = frame.subarray(payloadStart);
  if (payload.length !== payloadLength) {
    throw new Error('request payload length did not match');
  }
  return {
    requestId,
    operation: frame.subarray(operationStart, payloadLengthOffset).toString('ascii'),
    payload: JSON.parse(payload.toString('utf8')) as unknown,
  };
}

function success(requestId: Buffer, payload: Buffer): Buffer {
  const header = Buffer.alloc(21);
  header.writeUInt8(32, 0);
  requestId.copy(header, 1);
  header.writeUInt32BE(payload.length, 17);
  return Buffer.concat([header, payload]);
}

function failure(requestId: Buffer, wireCode: number): Buffer {
  const response = Buffer.alloc(19);
  response.writeUInt8(33, 0);
  requestId.copy(response, 1);
  response.writeUInt16BE(wireCode, 17);
  return response;
}

async function serveConnection(
  socket: Socket,
  action: (request: ReceivedRequest) => RequestAction,
): Promise<void> {
  const reader = new FrameReader(socket, handshakeFrameLimit + 4);
  const hello = decodeHello(await reader.read(handshakeFrameLimit));
  const serviceChallenge = randomBytes(32);
  await writeFrame(
    socket,
    Buffer.concat([Buffer.from([2]), servicePublicKey, serviceChallenge]),
    handshakeFrameLimit,
  );

  const transcript = encodeTranscript({
    ...hello,
    harness: 'copilot',
    serviceChallenge,
    serviceKey: servicePublicKey,
  });
  const auth = await reader.read(handshakeFrameLimit);
  if (
    auth.readUInt8(0) !== 3 ||
    !verifyMessage(clientKey, clientSigningMessage(transcript), auth.subarray(1))
  ) {
    throw new Error('client authentication failed');
  }
  await writeFrame(
    socket,
    Buffer.concat([Buffer.from([4]), signMessage(serviceKey, serviceSigningMessage(transcript))]),
    handshakeFrameLimit,
  );
  reader.setBufferLimit(rpcFrameLimit + 4);

  const request = decodeRequest(await reader.read(rpcFrameLimit));
  const next = action(request);
  switch (next.kind) {
    case 'respond':
      await writeFrame(
        socket,
        success(request.requestId, Buffer.from(JSON.stringify(next.value), 'utf8')),
        rpcFrameLimit,
      );
      return;
    case 'malformed-json':
      await writeFrame(socket, success(request.requestId, Buffer.from('{')), rpcFrameLimit);
      return;
    case 'failure':
      await writeFrame(socket, failure(request.requestId, next.wireCode), rpcFrameLimit);
      return;
    case 'drop':
      socket.destroy();
      return;
    case 'silent':
      await once(socket, 'close');
  }
}

async function startService(
  action: (request: ReceivedRequest, connection: number) => RequestAction,
): Promise<TestService> {
  const path = endpoint();
  const sockets = new Set<Socket>();
  const tasks: Promise<void>[] = [];
  let connections = 0;
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    const connection = connections;
    connections += 1;
    tasks.push(
      serveConnection(socket, (request) => action(request, connection)).catch((error: unknown) => {
        if (error instanceof FrameError && error.failure === 'closed') {
          return;
        }
        throw error;
      }),
    );
  });
  server.listen(path);
  await once(server, 'listening');

  return {
    endpoint: path,
    async close() {
      for (const socket of sockets) {
        socket.destroy();
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await Promise.all(tasks);
    },
  };
}

function clientOptions(service: TestService): LocalServiceClientOptions {
  return {
    endpoint: service.endpoint,
    adapterKeyId: Buffer.alloc(16, 7),
    adapterKeyVersion: 1,
    signingKey: clientKey,
    serviceKey: servicePublicKey,
    harness: 'copilot',
    profile: 'session-test',
    deadlineMs: 1_000,
    reconnectDelayMs: 0,
  };
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

describe('shared local service client', () => {
  it('redacts an unavailable endpoint from connection errors', async () => {
    const unavailable: TestService = {
      endpoint: endpoint(),
      close: async () => {},
    };
    const error = await connectLocalService({
      ...clientOptions(unavailable),
      deadlineMs: 100,
    }).catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain('connection is unavailable');
    expect(String(error)).not.toContain(unavailable.endpoint);
  });

  it('reuses one request identifier after a transport disconnect', async () => {
    const requests: ReceivedRequest[] = [];
    const service = await startService((request, connection) => {
      requests.push(request);
      return connection === 0
        ? { kind: 'drop' }
        : { kind: 'respond', value: { conversation_id: 'ab' } };
    });
    const client = await connectLocalService(clientOptions(service));

    await expect(client.request('create_conversation', {})).resolves.toEqual({
      conversation_id: 'ab',
    });
    expect(requests).toHaveLength(2);
    expect(requests[0]?.requestId).toEqual(requests[1]?.requestId);

    client.close();
    await service.close();
  });

  it('destroys a timed-out stream before a later request reconnects', async () => {
    const service = await startService((_request, connection) =>
      connection === 0 ? { kind: 'silent' } : { kind: 'respond', value: { device_id: 'cd' } },
    );
    const client = await connectLocalService(clientOptions(service));

    await expect(client.request('get_identity', {}, 25)).rejects.toMatchObject({
      code: 'deadline_exceeded',
    } satisfies Partial<LocalServiceError>);
    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'cd' });

    client.close();
    await service.close();
  });

  it('destroys a malformed-response stream before reconnecting', async () => {
    const service = await startService((_request, connection) =>
      connection === 0
        ? { kind: 'malformed-json' }
        : { kind: 'respond', value: { device_id: 'ef' } },
    );
    const client = await connectLocalService(clientOptions(service));

    await expect(client.request('get_identity', {})).rejects.toBeInstanceOf(
      LocalServiceProtocolError,
    );
    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'ef' });

    client.close();
    await service.close();
  });

  it('uses a fresh delivery claim after reconnecting a lease-bound lane', async () => {
    const requests: ReceivedRequest[] = [];
    const service = await startService((request) => {
      requests.push(request);
      return requests.length === 1 ? { kind: 'drop' } : { kind: 'respond', value: { events: [] } };
    });
    const client = await connectLocalService(clientOptions(service));

    await expect(
      client.request('delivery.claim', { maxEvents: 16, waitMilliseconds: 0 }),
    ).rejects.toThrow();
    await expect(
      client.request('delivery.claim', { maxEvents: 16, waitMilliseconds: 0 }),
    ).resolves.toEqual({ events: [] });
    expect(requests).toHaveLength(2);
    expect(requests[0]?.requestId).not.toEqual(requests[1]?.requestId);

    client.close();
    await service.close();
  });

  it('does not let a delivery wait block an interactive operation', async () => {
    const service = await startService((request) =>
      request.operation === 'delivery.claim'
        ? { kind: 'silent' }
        : { kind: 'respond', value: { device_id: 'aa' } },
    );
    const client = await connectLocalService(clientOptions(service));
    const delivery = expect(
      client.request('delivery.claim', { maxEvents: 16, waitMilliseconds: 20 }, 50),
    ).rejects.toMatchObject({ code: 'deadline_exceeded' });

    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'aa' });
    await delivery;

    client.close();
    await service.close();
  });

  it('surfaces finite service failures without treating them as protocol text', async () => {
    const service = await startService(() => ({ kind: 'failure', wireCode: 5 }));
    const client = await connectLocalService(clientOptions(service));

    await expect(client.request('get_identity', {})).rejects.toEqual(
      new LocalServiceError('get_identity', 'busy'),
    );

    client.close();
    await service.close();
  });

  it('measures every valid JSON string and primitive shape before sending', async () => {
    const observed: ReceivedRequest[] = [];
    const service = await startService((request) => {
      observed.push(request);
      return { kind: 'respond', value: { accepted: true } };
    });
    const client = await connectLocalService(clientOptions(service));
    const nullPrototype: Record<string, unknown> = Object.create(null);
    nullPrototype.value = 'plain';
    const payload = {
      ascii: 'a',
      escaped: '"\\\b\t\n\u0001',
      surrogatePair: '😀',
      unmatchedHigh: '\ud800',
      unmatchedLow: '\udc00',
      twoByte: 'é',
      threeByte: '€',
      values: [true, false, null, 1],
      nullPrototype,
    };

    await expect(client.request('get_identity', payload)).resolves.toEqual({
      accepted: true,
    });
    expect(observed[0]?.payload).toEqual(payload);

    client.close();
    await service.close();
  });

  it('rejects invalid reconnect, request, and pinned-service inputs', async () => {
    const service = await startService(() => ({ kind: 'respond', value: {} }));
    await expect(
      connectLocalService({ ...clientOptions(service), reconnectAttempts: 4 }),
    ).rejects.toThrow('reconnect settings are invalid');
    await expect(
      connectLocalService({ ...clientOptions(service), reconnectDelayMs: -1 }),
    ).rejects.toThrow('reconnect settings are invalid');
    await expect(
      connectLocalService({ ...clientOptions(service), serviceKey: Buffer.alloc(32, 9) }),
    ).rejects.toBeInstanceOf(LocalServiceProtocolError);

    const client = await connectLocalService(clientOptions(service));
    expect(() => client.request('INVALID', {})).toThrow('operation name is invalid');
    await expect(client.request('get_identity', {}, 0)).rejects.toThrow(
      'request deadline is invalid',
    );
    const circular: { self?: unknown } = {};
    circular.self = circular;
    expect(() => client.request('get_identity', circular)).toThrow();
    expect(() => client.request('get_identity', { text: 'x'.repeat(1_100_000) })).toThrow(
      'payload_too_large',
    );
    expect(() => client.request('get_identity', { value: Number.NaN })).toThrow(
      'number is invalid',
    );
    expect(() => client.request('get_identity', { value: new Date() })).toThrow(
      'object is invalid',
    );
    expect(() => client.request('get_identity', { value: undefined })).toThrow('value is invalid');
    expect(() => client.request('get_identity', Array.from({ length: 4_097 }))).toThrow(
      'payload_too_large',
    );
    let nested: unknown = null;
    for (let depth = 0; depth < 34; depth += 1) {
      nested = [nested];
    }
    expect(() => client.request('get_identity', nested)).toThrow('nesting is invalid');
    client.close();
    client.close();
    expect(client.connected).toBe(false);
    await expect(client.request('get_identity', {})).rejects.toThrow('client is closed');

    await service.close();
  });
});
