import { randomBytes, type KeyObject } from 'node:crypto';
import { connect, type Socket } from 'node:net';

import { FrameError, FrameReader, frameHeaderLength, writeFrame } from './framing.js';
import { publicKeyFromRaw, signMessage, verifyMessage } from './keys.js';
import {
  adapterKeyIdLength,
  challengeLength,
  clientInstanceLength,
  clientSigningMessage,
  encodeTranscript,
  protocolVersion,
  serviceSigningMessage,
  harnessWireValues,
  assertCanonicalProfile,
  type HarnessKind,
} from './transcript.js';

/**
 * The thin client half of the shared local service protocol.
 *
 * One session owns one connection bound to exactly one profile. The binding is fixed
 * by the handshake and covered by both signatures, so no later request can reach a
 * different profile. Nothing here spawns a process: an unavailable service is a
 * visible failure, never a reason to start a daemon.
 */

const maxHandshakeFrameBytes = 256;
const maxRpcPayloadBytes = 1_048_576;
const maxJsonDepth = 32;
const maxJsonEntries = 4_096;
const maxOperationLength = 64;
const maxRpcFrameBytes = 1 + 16 + 1 + maxOperationLength + 4 + maxRpcPayloadBytes;
const requestIdLength = 16;

const kindClientHello = 1;
const kindServiceChallenge = 2;
const kindClientAuth = 3;
const kindServiceAccept = 4;
const kindRequest = 16;
const kindSuccess = 32;
const kindFailure = 33;

/** The closed set of failure codes the service may return. */
export const localServiceErrorCodes = {
  1: 'invalid_request',
  2: 'unknown_operation',
  3: 'not_authorized',
  4: 'profile_unavailable',
  5: 'busy',
  6: 'deadline_exceeded',
  7: 'payload_too_large',
  8: 'conflict',
  9: 'internal',
} as const;

export type LocalServiceErrorCode =
  (typeof localServiceErrorCodes)[keyof typeof localServiceErrorCodes];

/**
 * A refusal reported by the service.
 *
 * The code is a finite label. No path, credential, identifier, or payload is carried,
 * so this error is safe to surface in a diagnostic.
 */
export class LocalServiceError extends Error {
  readonly code: LocalServiceErrorCode;
  readonly operation: string;

  constructor(operation: string, code: LocalServiceErrorCode) {
    super(`konclave operation ${operation} failed: ${code}`);
    this.name = 'LocalServiceError';
    this.code = code;
    this.operation = operation;
  }
}

export class LocalServiceProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalServiceProtocolError';
  }
}

class LocalServiceConnectionError extends Error {
  constructor() {
    super('the local service connection is unavailable');
    this.name = 'LocalServiceConnectionError';
  }
}

export interface LocalServiceClientOptions {
  /** Owner-protected endpoint path installed by the service package. */
  readonly endpoint: string;
  /** Registered adapter key identifier, exactly 16 bytes. */
  readonly adapterKeyId: Buffer;
  /** Registered adapter key version, one or greater. */
  readonly adapterKeyVersion: number;
  /** Registered adapter signing key imported by the platform provider. */
  readonly signingKey: KeyObject;
  /** The service verification key this client pins. */
  readonly serviceKey: Buffer;
  /** The harness this adapter is registered for. */
  readonly harness: HarnessKind;
  /** The durable profile this connection binds to. */
  readonly profile: string;
  /** Deadline applied to the handshake and to each request. */
  readonly deadlineMs?: number;
  /** Number of reconnects attempted after an early transport failure. */
  readonly reconnectAttempts?: number;
  /** Bounded delay before reconnecting after an early transport failure. */
  readonly reconnectDelayMs?: number;
  /** Socket factory, replaced in tests by an in-process pair. */
  readonly createSocket?: (endpoint: string) => Socket;
  /** Retry delay, replaced in tests to avoid wall-clock waits. */
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

export interface LocalServiceClient {
  /** The immutable profile this connection is bound to. */
  readonly profile: string;
  /** Invokes one bounded operation and returns its decoded result. */
  request(operation: string, payload: unknown, deadlineMs?: number): Promise<unknown>;
  /** Closes the connection. */
  close(): void;
  /** Whether the connection is still usable. */
  readonly connected: boolean;
}

const defaultDeadlineMs = 30_000;
const defaultReconnectAttempts = 1;
const defaultReconnectDelayMs = 50;

function defaultCreateSocket(endpoint: string): Socket {
  return connect(endpoint);
}

function withDeadline<T>(
  work: Promise<T>,
  deadlineMs: number,
  operation: string,
  onTimeout: () => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout();
      reject(new LocalServiceError(operation, 'deadline_exceeded'));
    }, deadlineMs);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error as Error);
      },
    );
  });
}

function encodeClientHello(
  adapterKeyId: Buffer,
  adapterKeyVersion: number,
  clientInstance: Buffer,
  harness: HarnessKind,
  profile: string,
  clientChallenge: Buffer,
): Buffer {
  const profileBytes = Buffer.from(profile, 'ascii');
  const header = Buffer.alloc(1 + 2 + adapterKeyIdLength + 4 + clientInstanceLength + 2 + 2);
  let offset = header.writeUInt8(kindClientHello, 0);
  offset = header.writeUInt16BE(protocolVersion, offset);
  offset += adapterKeyId.copy(header, offset);
  offset = header.writeUInt32BE(adapterKeyVersion, offset);
  offset += clientInstance.copy(header, offset);
  offset = header.writeUInt16BE(harnessWireValues[harness], offset);
  header.writeUInt16BE(profileBytes.length, offset);
  return Buffer.concat([header, profileBytes, clientChallenge]);
}

function decodeServiceChallenge(frame: Buffer): { serviceKey: Buffer; challenge: Buffer } {
  if (frame.length !== 1 + 32 + challengeLength || frame.readUInt8(0) !== kindServiceChallenge) {
    throw new LocalServiceProtocolError('the service challenge is malformed');
  }
  return {
    serviceKey: Buffer.from(frame.subarray(1, 33)),
    challenge: Buffer.from(frame.subarray(33)),
  };
}

function decodeServiceAccept(frame: Buffer): Buffer {
  if (frame.length !== 1 + 64 || frame.readUInt8(0) !== kindServiceAccept) {
    throw new LocalServiceProtocolError('the service acceptance is malformed');
  }
  return Buffer.from(frame.subarray(1));
}

interface JsonBudget {
  readonly operation: string;
  remaining: number;
  entries: number;
  readonly seen: WeakSet<object>;
}

function consumeJsonBudget(budget: JsonBudget, bytes: number): void {
  budget.remaining -= bytes;
  if (budget.remaining < 0) {
    throw new LocalServiceError(budget.operation, 'payload_too_large');
  }
}

function isPlainJsonObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function jsonStringBytes(value: string): number {
  let bytes = 2;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x22 || code === 0x5c) {
      bytes += 2;
    } else if (code <= 0x1f) {
      bytes += [0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(code) ? 2 : 6;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 6;
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      bytes += 6;
    } else if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function measureJsonValue(
  operation: string,
  value: unknown,
  budget: JsonBudget,
  depth: number,
): void {
  if (depth > maxJsonDepth) {
    throw new Error('local service request nesting is invalid');
  }
  if (value === null) {
    consumeJsonBudget(budget, 4);
    return;
  }
  switch (typeof value) {
    case 'boolean':
      consumeJsonBudget(budget, 5);
      return;
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('local service request number is invalid');
      }
      consumeJsonBudget(budget, 32);
      return;
    case 'string':
      consumeJsonBudget(budget, jsonStringBytes(value));
      return;
    case 'object':
      break;
    default:
      throw new Error('local service request value is invalid');
  }

  if (budget.seen.has(value)) {
    throw new Error('local service request contains a cycle');
  }
  budget.seen.add(value);
  if (Array.isArray(value)) {
    budget.entries += value.length;
    if (budget.entries > maxJsonEntries) {
      throw new LocalServiceError(operation, 'payload_too_large');
    }
    consumeJsonBudget(budget, 2 + Math.max(0, value.length - 1));
    for (const item of value) {
      measureJsonValue(operation, item, budget, depth + 1);
    }
  } else {
    if (!isPlainJsonObject(value)) {
      throw new Error('local service request object is invalid');
    }
    consumeJsonBudget(budget, 2);
    let first = true;
    for (const key in value) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        continue;
      }
      budget.entries += 1;
      if (budget.entries > maxJsonEntries) {
        throw new LocalServiceError(operation, 'payload_too_large');
      }
      if (!first) {
        consumeJsonBudget(budget, 1);
      }
      first = false;
      consumeJsonBudget(budget, jsonStringBytes(key) + 1);
      measureJsonValue(operation, value[key], budget, depth + 1);
    }
  }
  budget.seen.delete(value);
}

function encodeRequestPayload(operation: string, payload: unknown): Buffer {
  measureJsonValue(
    operation,
    payload,
    {
      operation,
      remaining: maxRpcPayloadBytes,
      entries: 0,
      seen: new WeakSet(),
    },
    0,
  );
  const serialized = JSON.stringify(payload);
  if (serialized === undefined) {
    throw new Error('local service request payload is invalid');
  }
  const encoded = Buffer.from(serialized, 'utf8');
  if (encoded.length > maxRpcPayloadBytes) {
    throw new LocalServiceError(operation, 'payload_too_large');
  }
  return encoded;
}

function encodeRequest(requestId: Buffer, operation: string, payload: Buffer): Buffer {
  const operationBytes = Buffer.from(operation, 'ascii');
  if (
    operationBytes.length === 0 ||
    operationBytes.length > maxOperationLength ||
    !/^[a-z0-9._-]+$/u.test(operation)
  ) {
    throw new Error('operation name is invalid');
  }
  if (payload.length > maxRpcPayloadBytes) {
    throw new LocalServiceError(operation, 'payload_too_large');
  }
  const header = Buffer.alloc(1 + requestIdLength + 1 + operationBytes.length + 4);
  let offset = header.writeUInt8(kindRequest, 0);
  offset += requestId.copy(header, offset);
  offset = header.writeUInt8(operationBytes.length, offset);
  offset += operationBytes.copy(header, offset);
  header.writeUInt32BE(payload.length, offset);
  return Buffer.concat([header, payload]);
}

function decodeResponse(frame: Buffer, requestId: Buffer, operation: string): { payload: Buffer } {
  if (frame.length < 1 + requestIdLength) {
    throw new LocalServiceProtocolError('the service response is malformed');
  }
  const kind = frame.readUInt8(0);
  const echoed = frame.subarray(1, 1 + requestIdLength);
  if (!echoed.equals(requestId)) {
    throw new LocalServiceProtocolError('the service response does not match the request');
  }
  if (kind === kindFailure) {
    if (frame.length !== 1 + requestIdLength + 2) {
      throw new LocalServiceProtocolError('the service response is malformed');
    }
    const wire = frame.readUInt16BE(1 + requestIdLength);
    const code = (localServiceErrorCodes as Record<number, LocalServiceErrorCode>)[wire];
    if (!code) {
      throw new LocalServiceProtocolError('the service reported an unimplemented failure');
    }
    throw new LocalServiceError(operation, code);
  }
  if (kind !== kindSuccess || frame.length < 1 + requestIdLength + 4) {
    throw new LocalServiceProtocolError('the service response is malformed');
  }
  const declared = frame.readUInt32BE(1 + requestIdLength);
  const payload = frame.subarray(1 + requestIdLength + 4);
  if (declared !== payload.length || declared > maxRpcPayloadBytes) {
    throw new LocalServiceProtocolError('the service response is malformed');
  }
  return { payload: Buffer.from(payload) };
}

/**
 * Connects, authenticates, and binds one client to one profile.
 *
 * The service key is pinned by the caller: a service that cannot prove that key is
 * refused rather than trusted because it happened to own the endpoint path.
 */
interface AuthenticatedConnection {
  readonly connected: boolean;
  invoke(requestId: Buffer, operation: string, payload: Buffer): Promise<unknown>;
  close(): void;
}

interface ConnectionLane {
  connection: AuthenticatedConnection | null;
  inFlight: Promise<unknown>;
}

function parseResponse(payload: Buffer): unknown {
  if (payload.length === 0) {
    return {};
  }
  try {
    return JSON.parse(payload.toString('utf8')) as unknown;
  } catch {
    throw new LocalServiceProtocolError('the service response is not valid JSON');
  }
}

function isRetryableTransportFailure(error: unknown): boolean {
  if (error instanceof LocalServiceConnectionError) {
    return true;
  }
  if (error instanceof FrameError) {
    return error.failure === 'closed';
  }
  return false;
}

function sanitizeTransportError(error: unknown): Error {
  if (
    error instanceof FrameError ||
    error instanceof LocalServiceError ||
    error instanceof LocalServiceProtocolError
  ) {
    return error;
  }
  return new LocalServiceConnectionError();
}

async function openConnection(
  options: LocalServiceClientOptions,
  deadlineMs: number,
): Promise<AuthenticatedConnection> {
  const createSocket = options.createSocket ?? defaultCreateSocket;
  assertCanonicalProfile(options.profile);
  const socket = createSocket(options.endpoint);
  const reader = new FrameReader(socket, maxHandshakeFrameBytes + frameHeaderLength);
  let connected = true;
  socket.on('close', () => {
    connected = false;
  });
  socket.on('error', () => {
    connected = false;
  });

  const close = () => {
    connected = false;
    socket.destroy();
  };

  try {
    const clientInstance = randomBytes(clientInstanceLength);
    const clientChallenge = randomBytes(challengeLength);
    await withDeadline(
      (async () => {
        await writeFrame(
          socket,
          encodeClientHello(
            options.adapterKeyId,
            options.adapterKeyVersion,
            clientInstance,
            options.harness,
            options.profile,
            clientChallenge,
          ),
          maxHandshakeFrameBytes,
        );

        const challengeFrame = await reader.read(maxHandshakeFrameBytes);
        const challenge = decodeServiceChallenge(challengeFrame);
        if (!challenge.serviceKey.equals(options.serviceKey)) {
          throw new LocalServiceProtocolError('the local service presented an unexpected key');
        }

        const transcript = encodeTranscript({
          adapterKeyId: options.adapterKeyId,
          adapterKeyVersion: options.adapterKeyVersion,
          clientInstance,
          harness: options.harness,
          profile: options.profile,
          clientChallenge,
          serviceChallenge: challenge.challenge,
          serviceKey: challenge.serviceKey,
        });

        const signature = signMessage(options.signingKey, clientSigningMessage(transcript));
        await writeFrame(
          socket,
          Buffer.concat([Buffer.from([kindClientAuth]), signature]),
          maxHandshakeFrameBytes,
        );

        const acceptFrame = await reader.read(maxHandshakeFrameBytes);
        const accepted = decodeServiceAccept(acceptFrame);
        const serviceKey = publicKeyFromRaw(challenge.serviceKey);
        if (!verifyMessage(serviceKey, serviceSigningMessage(transcript), accepted)) {
          throw new LocalServiceProtocolError('the local service acceptance did not verify');
        }
      })(),
      deadlineMs,
      'handshake',
      close,
    );
    reader.setBufferLimit(maxRpcFrameBytes + frameHeaderLength);
  } catch (error) {
    close();
    throw sanitizeTransportError(error);
  }

  return {
    get connected() {
      return connected;
    },
    close,
    async invoke(requestId, operation, payload) {
      if (!connected) {
        throw new FrameError('closed');
      }
      try {
        await writeFrame(socket, encodeRequest(requestId, operation, payload), maxRpcFrameBytes);
        const frame = await reader.read(maxRpcFrameBytes);
        const response = decodeResponse(frame, requestId, operation);
        return parseResponse(response.payload);
      } catch (error) {
        if (!(error instanceof LocalServiceError)) {
          close();
        }
        throw sanitizeTransportError(error);
      }
    },
  };
}

/**
 * Connects, authenticates, and binds one reconnecting client to one profile.
 *
 * One request ID is allocated before any transport attempt. An early disconnect may
 * reconnect and replay that exact request, allowing the service ledger to return the
 * recorded outcome rather than executing a side effect twice.
 */
export async function connectLocalService(
  options: LocalServiceClientOptions,
): Promise<LocalServiceClient> {
  const deadlineMs = options.deadlineMs ?? defaultDeadlineMs;
  const reconnectAttempts = options.reconnectAttempts ?? defaultReconnectAttempts;
  const reconnectDelayMs = options.reconnectDelayMs ?? defaultReconnectDelayMs;
  if (
    !Number.isInteger(reconnectAttempts) ||
    reconnectAttempts < 0 ||
    reconnectAttempts > 3 ||
    !Number.isInteger(reconnectDelayMs) ||
    reconnectDelayMs < 0 ||
    reconnectDelayMs > 5_000
  ) {
    throw new Error('local service reconnect settings are invalid');
  }
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => {
        setTimeout(resolve, milliseconds);
      }));
  const interactiveLane: ConnectionLane = {
    connection: await openConnection(options, deadlineMs),
    inFlight: Promise.resolve(),
  };
  const deliveryLane: ConnectionLane = {
    connection: null,
    inFlight: Promise.resolve(),
  };
  let closed = false;

  const close = () => {
    if (closed) {
      return;
    }
    closed = true;
    interactiveLane.connection?.close();
    interactiveLane.connection = null;
    deliveryLane.connection?.close();
    deliveryLane.connection = null;
  };

  const getConnection = async (
    lane: ConnectionLane,
    remainingMs: number,
  ): Promise<AuthenticatedConnection> => {
    if (closed) {
      throw new Error('the local service client is closed');
    }
    if (lane.connection?.connected) {
      return lane.connection;
    }
    lane.connection = await openConnection(options, remainingMs);
    if (closed) {
      lane.connection.close();
      lane.connection = null;
      throw new Error('the local service client is closed');
    }
    return lane.connection;
  };

  return {
    profile: options.profile,
    get connected() {
      return !closed;
    },
    close,
    request(operation, payload, requestDeadlineMs = deadlineMs) {
      if (
        !Number.isInteger(requestDeadlineMs) ||
        requestDeadlineMs <= 0 ||
        requestDeadlineMs > 300_000
      ) {
        return Promise.reject(new Error('local service request deadline is invalid'));
      }
      const requestId = randomBytes(requestIdLength);
      const encoded = encodeRequestPayload(operation, payload ?? {});
      encodeRequest(requestId, operation, encoded);
      const deliveryOperation = operation.startsWith('delivery.');
      const lane = deliveryOperation ? deliveryLane : interactiveLane;
      const allowedReconnects = deliveryOperation ? 0 : reconnectAttempts;

      const run = lane.inFlight.then(async () => {
        const expiresAt = Date.now() + requestDeadlineMs;
        let attempt = 0;
        while (true) {
          const remainingMs = expiresAt - Date.now();
          if (remainingMs <= 0) {
            throw new LocalServiceError(operation, 'deadline_exceeded');
          }

          let active: AuthenticatedConnection;
          try {
            active = await getConnection(lane, remainingMs);
            return await withDeadline(
              active.invoke(requestId, operation, encoded),
              remainingMs,
              operation,
              active.close,
            );
          } catch (error) {
            if (lane.connection && !lane.connection.connected) {
              lane.connection = null;
            }
            if (closed || attempt >= allowedReconnects || !isRetryableTransportFailure(error)) {
              throw error;
            }
            attempt += 1;
            const delay = Math.min(reconnectDelayMs, Math.max(0, expiresAt - Date.now()));
            if (delay > 0) {
              await sleep(delay);
            }
          }
        }
      });
      lane.inFlight = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
  };
}
