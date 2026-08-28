import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';

import {
  connectLocalService,
  LocalServiceError,
  LocalServiceProtocolError,
  LocalServiceUpgradeRequiredError,
  isDeliveryLaneOperation,
  type LocalServiceClientOptions,
} from '../src/service/client.js';
import { FrameError, FrameReader, writeFrame } from '../src/service/framing.js';
import {
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  signMessage,
  verifyMessage,
} from '../src/service/keys.js';
import {
  clientSigningMessage,
  encodeIssuerTranscript,
  encodeSessionTranscript,
  serviceSigningMessage,
  type HarnessKind,
  type SessionGrantRecord,
} from '../src/service/transcript.js';
import { connectInstalledGenericService } from '../src/service/installed.js';

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
  | { readonly kind: 'failure-drop'; readonly wireCode: number }
  | { readonly kind: 'malformed-json' }
  | { readonly kind: 'drop' }
  | { readonly kind: 'delay'; readonly milliseconds: number; readonly value: unknown }
  | { readonly kind: 'defer'; readonly release: Promise<void>; readonly value: unknown }
  | { readonly kind: 'silent' };

interface ReceivedRequest {
  readonly requestId: Buffer;
  readonly operation: string;
  readonly payload: unknown;
}

interface TestService {
  readonly endpoint: string;
  resetAuthorization(): Promise<void>;
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

function decodeIssuerHello(frame: Buffer) {
  if (frame.readUInt8(0) !== 5 || frame.readUInt16BE(1) !== 2) {
    throw new Error('expected issuer hello');
  }
  return {
    issuerKeyId: Buffer.from(frame.subarray(3, 19)),
    issuerKeyVersion: frame.readUInt32BE(19),
    issuerPublicKey: Buffer.from(frame.subarray(23, 55)),
    clientInstance: Buffer.from(frame.subarray(55, 71)),
    harness: harness(frame.readUInt16BE(71)),
    clientChallenge: Buffer.from(frame.subarray(73)),
  };
}

function decodeSessionHello(frame: Buffer): {
  grant: SessionGrantRecord;
  clientInstance: Buffer;
  clientChallenge: Buffer;
} {
  if (frame.readUInt8(0) !== 6 || frame.readUInt16BE(1) !== 2) {
    throw new Error('expected session hello');
  }
  let offset = 3;
  const grantId = Buffer.from(frame.subarray(offset, (offset += 16)));
  const issuerKeyId = Buffer.from(frame.subarray(offset, (offset += 16)));
  const issuerKeyVersion = frame.readUInt32BE(offset);
  offset += 4;
  const sessionPublicKey = Buffer.from(frame.subarray(offset, (offset += 32)));
  const grantHarness = harness(frame.readUInt16BE(offset));
  offset += 2;
  const profileLength = frame.readUInt16BE(offset);
  offset += 2;
  const profile = frame.subarray(offset, (offset += profileLength)).toString('ascii');
  const evidence = frame.readUInt8(offset);
  offset += 1;
  const policyVersion = frame.readBigUInt64BE(offset);
  offset += 8;
  const issuedAtUnixMilliseconds = frame.readBigUInt64BE(offset);
  offset += 8;
  const expiresAtUnixMilliseconds = frame.readBigUInt64BE(offset);
  offset += 8;
  const capabilities = frame.readBigUInt64BE(offset);
  offset += 8;
  return {
    grant: {
      grantId,
      issuerKeyId,
      issuerKeyVersion,
      profile,
      sessionPublicKey,
      harness: grantHarness,
      evidence,
      policyVersion,
      issuedAtUnixMilliseconds,
      expiresAtUnixMilliseconds,
      capabilities,
    },
    clientInstance: Buffer.from(frame.subarray(offset, (offset += 16))),
    clientChallenge: Buffer.from(frame.subarray(offset)),
  };
}

function harness(value: number): HarnessKind {
  switch (value) {
    case 1:
      return 'copilot';
    case 2:
      return 'claude-code';
    case 3:
      return 'codex';
    case 4:
      return 'generic';
    default:
      throw new Error('unknown harness');
  }
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
  grants: Map<string, SessionGrantRecord>,
  observeControl: ((request: ReceivedRequest) => void) | undefined,
): Promise<void> {
  const reader = new FrameReader(socket, handshakeFrameLimit + 4);
  const helloFrame = await reader.read(handshakeFrameLimit);
  const serviceChallenge = randomBytes(32);
  await writeFrame(
    socket,
    Buffer.concat([Buffer.from([2]), servicePublicKey, serviceChallenge]),
    handshakeFrameLimit,
  );

  let transcript: Buffer;
  let verificationKey = clientKey;
  let issuer = false;
  let accepted = true;
  if (helloFrame.readUInt8(0) === 5) {
    const hello = decodeIssuerHello(helloFrame);
    transcript = encodeIssuerTranscript({
      ...hello,
      serviceChallenge,
      serviceKey: servicePublicKey,
    });
    issuer = true;
  } else {
    const hello = decodeSessionHello(helloFrame);
    const known = grants.get(hello.grant.grantId.toString('hex'));
    if (!known || JSON.stringify(grantJson(known)) !== JSON.stringify(grantJson(hello.grant))) {
      accepted = false;
    }
    transcript = encodeSessionTranscript({
      ...hello,
      serviceChallenge,
      serviceKey: servicePublicKey,
    });
    verificationKey = publicKeyFromRaw(hello.grant.sessionPublicKey);
  }
  const auth = await reader.read(handshakeFrameLimit);
  if (
    auth.readUInt8(0) !== 3 ||
    !verifyMessage(verificationKey, clientSigningMessage(transcript), auth.subarray(1))
  ) {
    throw new Error('client authentication failed');
  }
  await writeFrame(
    socket,
    Buffer.concat([
      Buffer.from([accepted ? 4 : 7]),
      signMessage(serviceKey, serviceSigningMessage(transcript)),
    ]),
    handshakeFrameLimit,
  );
  if (!accepted) {
    return;
  }
  reader.setBufferLimit(rpcFrameLimit + 4);

  const request = decodeRequest(await reader.read(rpcFrameLimit));
  if (issuer) {
    if (request.operation !== 'authorization.grant.issue') {
      throw new Error('issuer requested an operational method');
    }
    if (
      typeof request.payload !== 'object' ||
      request.payload === null ||
      Array.isArray(request.payload)
    ) {
      throw new Error('grant request was malformed');
    }
    const values = request.payload as Record<string, unknown>;
    const profile = String(values.profile);
    const sessionPublicKey = Buffer.from(String(values.sessionPublicKey), 'hex');
    const grant: SessionGrantRecord = {
      grantId: randomBytes(16),
      issuerKeyId: Buffer.alloc(16, 7),
      issuerKeyVersion: 1,
      profile,
      sessionPublicKey,
      harness: String(values.harness) as HarnessKind,
      evidence: 1,
      policyVersion: 1n,
      issuedAtUnixMilliseconds: BigInt(Date.now()),
      expiresAtUnixMilliseconds: BigInt(Date.now() + 3_600_000),
      capabilities: 15n,
    };
    grants.set(grant.grantId.toString('hex'), grant);
    await writeFrame(
      socket,
      success(request.requestId, Buffer.from(JSON.stringify(grantJson(grant)), 'utf8')),
      rpcFrameLimit,
    );
    return;
  }
  if (request.operation === 'request.cancel') {
    observeControl?.(request);
    await writeFrame(
      socket,
      success(request.requestId, Buffer.from('{"state":"reconciling"}', 'utf8')),
      rpcFrameLimit,
    );
    return;
  }
  if (request.operation === 'authorization.grant.retire') {
    observeControl?.(request);
    await writeFrame(
      socket,
      success(request.requestId, Buffer.from('{"retired":true}', 'utf8')),
      rpcFrameLimit,
    );
    return;
  }
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
    case 'failure-drop':
      await writeFrame(socket, failure(request.requestId, next.wireCode), rpcFrameLimit);
      socket.destroy();
      return;
    case 'drop':
      socket.destroy();
      return;
    case 'delay':
      await new Promise((resolve) => setTimeout(resolve, next.milliseconds));
      await writeFrame(
        socket,
        success(request.requestId, Buffer.from(JSON.stringify(next.value), 'utf8')),
        rpcFrameLimit,
      );
      return;
    case 'defer':
      await next.release;
      await writeFrame(
        socket,
        success(request.requestId, Buffer.from(JSON.stringify(next.value), 'utf8')),
        rpcFrameLimit,
      );
      return;
    case 'silent':
      await once(socket, 'close');
  }

  function grantJson(grant: SessionGrantRecord): Record<string, string | number> {
    return {
      grantId: grant.grantId.toString('hex'),
      issuerKeyId: grant.issuerKeyId.toString('hex'),
      issuerKeyVersion: grant.issuerKeyVersion,
      profile: grant.profile,
      sessionPublicKey: grant.sessionPublicKey.toString('hex'),
      harness: grant.harness,
      evidence: grant.evidence,
      policyVersion: Number(grant.policyVersion),
      issuedAtUnixMilliseconds: Number(grant.issuedAtUnixMilliseconds),
      expiresAtUnixMilliseconds: Number(grant.expiresAtUnixMilliseconds),
      capabilities: Number(grant.capabilities),
    };
  }
}

async function startService(
  action: (request: ReceivedRequest, connection: number) => RequestAction,
  observeControl?: (request: ReceivedRequest) => void,
): Promise<TestService> {
  const path = endpoint();
  const sockets = new Set<Socket>();
  const tasks: Promise<void>[] = [];
  const grants = new Map<string, SessionGrantRecord>();
  let sessionConnections = 0;
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    tasks.push(
      serveConnection(
        socket,
        (request) => {
          const connection = sessionConnections;
          sessionConnections += 1;
          return action(request, connection);
        },
        grants,
        observeControl,
      ).catch((error: unknown) => {
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
    async resetAuthorization() {
      grants.clear();
      const closing = [...sockets].map(async (socket) => {
        const closed = once(socket, 'close');
        socket.destroy();
        await closed;
      });
      await Promise.all(closing);
    },
    async close() {
      for (const socket of sockets) {
        socket.destroy();
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await Promise.all(tasks);
    },
  };
}

async function startLegacyService(): Promise<TestService> {
  const path = endpoint();
  const sockets = new Set<Socket>();
  const tasks: Promise<void>[] = [];
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    tasks.push(
      (async () => {
        const reader = new FrameReader(socket, handshakeFrameLimit + 4);
        await reader.read(handshakeFrameLimit);
        socket.destroy();
      })(),
    );
  });
  server.listen(path);
  await once(server, 'listening');
  return {
    endpoint: path,
    async resetAuthorization() {},
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
    issuerKeyId: Buffer.alloc(16, 7),
    issuerKeyVersion: 1,
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
  it('connects an unsupported harness through the installed generic issuer', async () => {
    const service = await startService(() => ({
      kind: 'respond',
      value: { device_id: 'ac' },
    }));
    const directory = mkdtempSync(join(tmpdir(), 'konclave-generic-client-test-'));
    temporaryDirectories.push(directory);
    const issuerKeyFile = join(directory, 'account-issuer.key');
    const serviceConfigFile = join(directory, 'konclave.service.json');
    writeFileSync(issuerKeyFile, clientSeed, { mode: 0o600 });
    writeFileSync(
      serviceConfigFile,
      JSON.stringify({
        schemaVersion: 2,
        endpoint: service.endpoint,
        issuerKeyId: '07'.repeat(16),
        issuerKeyVersion: 1,
        harness: 'copilot',
        serviceKey: servicePublicKey.toString('hex'),
        issuerKeyFile,
        authorizationPolicy: {
          version: 1,
          acceptedEvidence: [['account_trusted']],
        },
      }),
      { mode: 0o600 },
    );

    const client = await connectInstalledGenericService(
      { KONCLAVE_SERVICE_CONFIG_FILE: serviceConfigFile },
      directory,
      'generic-test',
    );

    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'ac' });
    await client.retire();
    await service.close();
  });

  it('redacts an unavailable endpoint from connection errors', async () => {
    const unavailable: TestService = {
      endpoint: endpoint(),
      resetAuthorization: async () => {},
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

  it('reports that a reachable protocol-v1 service must be upgraded', async () => {
    const service = await startLegacyService();

    await expect(connectLocalService(clientOptions(service))).rejects.toBeInstanceOf(
      LocalServiceUpgradeRequiredError,
    );

    await service.close();
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

  it('accepts an explicit request identifier for caller-driven reconciliation', async () => {
    const requests: ReceivedRequest[] = [];
    const service = await startService((request) => {
      requests.push(request);
      return { kind: 'respond', value: { device_id: 'ae' } };
    });
    const client = await connectLocalService(clientOptions(service));
    const requestId = Buffer.alloc(16, 0x42);

    await client.request('get_identity', {}, { requestId });
    await service.resetAuthorization();
    await client.request('get_identity', {}, { requestId });

    expect(requests).toHaveLength(2);
    expect(requests[0]?.requestId).toEqual(requestId);
    expect(requests[1]?.requestId).toEqual(requestId);
    await client.retire();
    await service.close();
  });

  it('reissues a grant after service authorization state restarts', async () => {
    const service = await startService(() => ({
      kind: 'respond',
      value: { device_id: 'ad' },
    }));
    const client = await connectLocalService(clientOptions(service));
    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'ad' });

    await service.resetAuthorization();

    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'ad' });
    await client.retire();
    await service.close();
  });

  it('waits for the actual terminal outcome after the response deadline', async () => {
    const service = await startService(() => ({
      kind: 'delay',
      milliseconds: 40,
      value: { device_id: 'cd' },
    }));
    const client = await connectLocalService(clientOptions(service));

    await expect(client.request('get_identity', {}, 25)).resolves.toEqual({ device_id: 'cd' });

    client.close();
    await service.close();
  });

  it('retries the same request when durable reconciliation is pending', async () => {
    const requests: ReceivedRequest[] = [];
    const service = await startService((request) => {
      requests.push(request);
      return requests.length === 1
        ? { kind: 'failure-drop', wireCode: 11 }
        : { kind: 'respond', value: { device_id: 'cf' } };
    });
    const client = await connectLocalService(clientOptions(service));

    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'cf' });

    expect(requests).toHaveLength(2);
    expect(requests[0]?.requestId).toEqual(requests[1]?.requestId);
    await client.retire();
    await service.close();
  });

  it('propagates caller cancellation without replacing a committed outcome', async () => {
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    let releaseOperation!: () => void;
    const operationRelease = new Promise<void>((resolve) => {
      releaseOperation = resolve;
    });
    let observeCancellation!: (request: ReceivedRequest) => void;
    const cancellation = new Promise<ReceivedRequest>((resolve) => {
      observeCancellation = resolve;
    });
    const service = await startService(
      () => {
        markStarted();
        return { kind: 'defer', release: operationRelease, value: { device_id: 'ce' } };
      },
      (request) => {
        if (request.operation === 'request.cancel') {
          observeCancellation(request);
        }
      },
    );
    const client = await connectLocalService(clientOptions(service));
    const controller = new AbortController();
    const operation = client.request('get_identity', {}, { signal: controller.signal });

    await started;
    controller.abort();
    await expect(cancellation).resolves.toMatchObject({
      operation: 'request.cancel',
      payload: expect.objectContaining({ reason: 'caller' }),
    });
    releaseOperation();
    await expect(operation).resolves.toEqual({ device_id: 'ce' });

    client.close();
    await service.close();
  });

  it('retires its exact grant before closing cleanly', async () => {
    let observeRetirement!: (request: ReceivedRequest) => void;
    const retirement = new Promise<ReceivedRequest>((resolve) => {
      observeRetirement = resolve;
    });
    const service = await startService(
      () => ({ kind: 'respond', value: {} }),
      (request) => {
        if (request.operation === 'authorization.grant.retire') {
          observeRetirement(request);
        }
      },
    );
    const client = await connectLocalService(clientOptions(service));

    await client.retire();

    await expect(retirement).resolves.toMatchObject({
      operation: 'authorization.grant.retire',
      payload: {},
    });
    expect(client.connected).toBe(false);
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
    let markDeliveryStarted!: () => void;
    const deliveryStarted = new Promise<void>((resolve) => {
      markDeliveryStarted = resolve;
    });
    let releaseDelivery!: () => void;
    const deliveryRelease = new Promise<void>((resolve) => {
      releaseDelivery = resolve;
    });
    const service = await startService((request) => {
      if (request.operation === 'delivery.claim') {
        markDeliveryStarted();
        return { kind: 'defer', release: deliveryRelease, value: { events: [] } };
      }
      return { kind: 'respond', value: { device_id: 'aa' } };
    });
    const client = await connectLocalService(clientOptions(service));
    const delivery = client.request('delivery.claim', { maxEvents: 16, waitMilliseconds: 20 });

    await deliveryStarted;
    await expect(client.request('get_identity', {})).resolves.toEqual({ device_id: 'aa' });
    releaseDelivery();
    await expect(delivery).resolves.toEqual({ events: [] });

    client.close();
    await service.close();
  });

  it('routes turn authorization with delivery while action checks stay interactive', () => {
    expect(isDeliveryLaneOperation('delivery.claim')).toBe(true);
    expect(isDeliveryLaneOperation('collaboration.turn.authorize')).toBe(true);
    expect(isDeliveryLaneOperation('collaboration.action.evaluate')).toBe(false);
    expect(isDeliveryLaneOperation('get_identity')).toBe(false);
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
    await expect(
      client.request('get_identity', {}, { requestId: Buffer.alloc(15) }),
    ).rejects.toThrow('request identifier is invalid');
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
