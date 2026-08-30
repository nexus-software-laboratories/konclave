import { randomBytes, type KeyObject } from 'node:crypto';
import { connect, type Socket } from 'node:net';

import { FrameError, FrameReader, frameHeaderLength, writeFrame } from './framing.js';
import {
  generateSessionPrivateKey,
  publicKeyFromRaw,
  rawPublicKey,
  signMessage,
  verifyMessage,
} from './keys.js';
import {
  challengeLength,
  clientInstanceLength,
  clientSigningMessage,
  encodeGrantClaims,
  encodeIssuerTranscript,
  encodeSessionTranscript,
  grantIdLength,
  keyIdLength,
  protocolVersion,
  serviceSigningMessage,
  harnessWireValues,
  assertCanonicalProfile,
  type SessionGrantRecord,
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

const kindIssuerHello = 5;
const kindSessionHello = 6;
const kindServiceChallenge = 2;
const kindClientAuth = 3;
const kindServiceAccept = 4;
const kindServiceReject = 7;
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
  10: 'cancelled',
  11: 'reconciliation_pending',
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

export class LocalServiceUpgradeRequiredError extends Error {
  readonly code = 'service_upgrade_required';

  constructor() {
    super('the installed local service must be upgraded');
    this.name = 'LocalServiceUpgradeRequiredError';
  }
}

class LocalServiceConnectionError extends Error {
  constructor() {
    super('the local service connection is unavailable');
    this.name = 'LocalServiceConnectionError';
  }
}

class LocalServiceAuthorizationError extends Error {
  constructor() {
    super('the local service did not authorize this client');
    this.name = 'LocalServiceAuthorizationError';
  }
}

export interface LocalServiceClientOptions {
  /** Owner-protected endpoint path installed by the service package. */
  readonly endpoint: string;
  /** Installed AccountTrusted issuer key identifier, exactly 16 bytes. */
  readonly issuerKeyId: Buffer;
  /** Installed AccountTrusted issuer key version, one or greater. */
  readonly issuerKeyVersion: number;
  /** Installed AccountTrusted issuer signing key. */
  readonly signingKey: KeyObject;
  /** The service verification key this client pins. */
  readonly serviceKey: Buffer;
  /** Harness metadata included in the grant request. */
  readonly harness: HarnessKind;
  /** The durable profile this connection binds to. */
  readonly profile: string;
  /** Default handshake and request-cancellation deadline. */
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
  /** Invokes one bounded operation and reconciles its actual terminal result. */
  request(
    operation: string,
    payload: unknown,
    options?: number | LocalServiceRequestOptions,
  ): Promise<unknown>;
  /** Retires this exact grant and closes both lanes. */
  retire(): Promise<void>;
  /** Closes the connection. */
  close(): void;
  /** Whether the connection is still usable. */
  readonly connected: boolean;
}

export interface LocalServiceRequestOptions {
  /** Requests authenticated cancellation when this interval elapses. */
  readonly deadlineMs?: number;
  /** Requests authenticated cancellation when the caller aborts. */
  readonly signal?: AbortSignal;
  /** Stable 16-byte idempotency key reused for exact reconciliation. */
  readonly requestId?: Buffer;
}

const defaultDeadlineMs = 30_000;
const defaultReconnectAttempts = 1;
const defaultReconnectDelayMs = 50;

/** Returns whether an operation must share the lease-owning delivery lane. */
export function isDeliveryLaneOperation(operation: string): boolean {
  return (
    operation.startsWith('delivery.') ||
    operation === 'collaboration.turn.authorize' ||
    operation === 'collaboration.turn.complete'
  );
}

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

function encodeIssuerHello(
  issuerKeyId: Buffer,
  issuerKeyVersion: number,
  issuerPublicKey: Buffer,
  clientInstance: Buffer,
  harness: HarnessKind,
  clientChallenge: Buffer,
): Buffer {
  const header = Buffer.alloc(1 + 2 + keyIdLength + 4 + 32 + clientInstanceLength + 2);
  let offset = header.writeUInt8(kindIssuerHello, 0);
  offset = header.writeUInt16BE(protocolVersion, offset);
  offset += issuerKeyId.copy(header, offset);
  offset = header.writeUInt32BE(issuerKeyVersion, offset);
  offset += issuerPublicKey.copy(header, offset);
  offset += clientInstance.copy(header, offset);
  header.writeUInt16BE(harnessWireValues[harness], offset);
  return Buffer.concat([header, clientChallenge]);
}

function encodeSessionHello(
  grant: SessionGrantRecord,
  clientInstance: Buffer,
  clientChallenge: Buffer,
): Buffer {
  const header = Buffer.alloc(1 + 2);
  header.writeUInt8(kindSessionHello, 0);
  header.writeUInt16BE(protocolVersion, 1);
  return Buffer.concat([header, encodeGrantClaims(grant), clientInstance, clientChallenge]);
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

function decodeServiceDecision(frame: Buffer): { accepted: boolean; signature: Buffer } {
  const kind = frame.readUInt8(0);
  if (frame.length !== 1 + 64 || (kind !== kindServiceAccept && kind !== kindServiceReject)) {
    throw new LocalServiceProtocolError('the service acceptance is malformed');
  }
  return { accepted: kind === kindServiceAccept, signature: Buffer.from(frame.subarray(1)) };
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
  invoke(
    requestId: Buffer,
    operation: string,
    payload: Buffer,
    onWritten?: () => void,
  ): Promise<unknown>;
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
    error instanceof LocalServiceProtocolError ||
    error instanceof LocalServiceUpgradeRequiredError ||
    error instanceof LocalServiceAuthorizationError
  ) {
    return error;
  }
  return new LocalServiceConnectionError();
}

type ConnectionCredential =
  | {
      readonly kind: 'issuer';
      readonly key: KeyObject;
    }
  | {
      readonly kind: 'session';
      readonly key: KeyObject;
      readonly grant: SessionGrantRecord;
    };

async function readServiceHandshakeFrame(reader: FrameReader): Promise<Buffer> {
  try {
    return await reader.read(maxHandshakeFrameBytes);
  } catch (error) {
    if (error instanceof FrameError && error.failure === 'closed') {
      throw new LocalServiceUpgradeRequiredError();
    }
    throw error;
  }
}

async function openConnection(
  options: LocalServiceClientOptions,
  deadlineMs: number,
  credential: ConnectionCredential,
): Promise<AuthenticatedConnection> {
  const createSocket = options.createSocket ?? defaultCreateSocket;
  if (credential.kind === 'session') {
    assertCanonicalProfile(credential.grant.profile);
  }
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
        const publicKey = rawPublicKey(credential.key);
        await writeFrame(
          socket,
          credential.kind === 'issuer'
            ? encodeIssuerHello(
                options.issuerKeyId,
                options.issuerKeyVersion,
                publicKey,
                clientInstance,
                options.harness,
                clientChallenge,
              )
            : encodeSessionHello(credential.grant, clientInstance, clientChallenge),
          maxHandshakeFrameBytes,
        );

        const challengeFrame = await readServiceHandshakeFrame(reader);
        const challenge = decodeServiceChallenge(challengeFrame);
        if (!challenge.serviceKey.equals(options.serviceKey)) {
          throw new LocalServiceProtocolError('the local service presented an unexpected key');
        }

        const transcript =
          credential.kind === 'issuer'
            ? encodeIssuerTranscript({
                issuerKeyId: options.issuerKeyId,
                issuerKeyVersion: options.issuerKeyVersion,
                issuerPublicKey: publicKey,
                clientInstance,
                harness: options.harness,
                clientChallenge,
                serviceChallenge: challenge.challenge,
                serviceKey: challenge.serviceKey,
              })
            : encodeSessionTranscript({
                grant: credential.grant,
                clientInstance,
                clientChallenge,
                serviceChallenge: challenge.challenge,
                serviceKey: challenge.serviceKey,
              });

        const signature = signMessage(credential.key, clientSigningMessage(transcript));
        await writeFrame(
          socket,
          Buffer.concat([Buffer.from([kindClientAuth]), signature]),
          maxHandshakeFrameBytes,
        );

        const acceptFrame = await readServiceHandshakeFrame(reader);
        const decision = decodeServiceDecision(acceptFrame);
        const serviceKey = publicKeyFromRaw(challenge.serviceKey);
        if (!verifyMessage(serviceKey, serviceSigningMessage(transcript), decision.signature)) {
          throw new LocalServiceProtocolError('the local service acceptance did not verify');
        }
        if (!decision.accepted) {
          throw new LocalServiceAuthorizationError();
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
    async invoke(requestId, operation, payload, onWritten) {
      if (!connected) {
        throw new FrameError('closed');
      }
      try {
        await writeFrame(socket, encodeRequest(requestId, operation, payload), maxRpcFrameBytes);
        onWritten?.();
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

interface GrantIssueResult {
  readonly grantId: unknown;
  readonly issuerKeyId: unknown;
  readonly issuerKeyVersion: unknown;
  readonly profile: unknown;
  readonly sessionPublicKey: unknown;
  readonly harness: unknown;
  readonly evidence: unknown;
  readonly policyVersion: unknown;
  readonly issuedAtUnixMilliseconds: unknown;
  readonly expiresAtUnixMilliseconds: unknown;
  readonly capabilities: unknown;
}

async function issueSessionGrant(
  options: LocalServiceClientOptions,
  sessionKey: KeyObject,
  deadlineMs: number,
  reconnectAttempts: number,
  reconnectDelayMs: number,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<SessionGrantRecord> {
  const requestId = randomBytes(requestIdLength);
  const payload = encodeRequestPayload('authorization.grant.issue', {
    profile: options.profile,
    sessionPublicKey: rawPublicKey(sessionKey).toString('hex'),
    harness: options.harness,
  });
  const expiresAt = Date.now() + deadlineMs;
  for (let attempt = 0; ; attempt += 1) {
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      throw new LocalServiceError('authorization.grant.issue', 'deadline_exceeded');
    }
    let issuer: AuthenticatedConnection | null = null;
    try {
      issuer = await openConnection(options, remaining, {
        kind: 'issuer',
        key: options.signingKey,
      });
      const result = await withDeadline(
        issuer.invoke(requestId, 'authorization.grant.issue', payload),
        remaining,
        'authorization.grant.issue',
        issuer.close,
      );
      return parseIssuedGrant(result, options, rawPublicKey(sessionKey));
    } catch (error) {
      if (attempt >= reconnectAttempts || !isRetryableTransportFailure(error)) {
        throw error;
      }
      const delay = Math.min(reconnectDelayMs, Math.max(0, expiresAt - Date.now()));
      if (delay > 0) {
        await sleep(delay);
      }
    } finally {
      issuer?.close();
    }
  }
}

function parseIssuedGrant(
  value: unknown,
  options: LocalServiceClientOptions,
  expectedSessionKey: Buffer,
): SessionGrantRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new LocalServiceProtocolError('the issued session grant is malformed');
  }
  const result = value as GrantIssueResult;
  const grant: SessionGrantRecord = {
    grantId: parseHex(result.grantId, grantIdLength),
    issuerKeyId: parseHex(result.issuerKeyId, keyIdLength),
    issuerKeyVersion: parsePositiveInteger(result.issuerKeyVersion),
    profile: typeof result.profile === 'string' ? result.profile : '',
    sessionPublicKey: parseHex(result.sessionPublicKey, 32),
    harness: parseHarness(result.harness),
    evidence: parsePositiveInteger(result.evidence),
    policyVersion: parseUnsignedBigInt(result.policyVersion),
    issuedAtUnixMilliseconds: parseUnsignedBigInt(result.issuedAtUnixMilliseconds),
    expiresAtUnixMilliseconds: parseUnsignedBigInt(result.expiresAtUnixMilliseconds),
    capabilities: parseUnsignedBigInt(result.capabilities),
  };
  if (
    !grant.issuerKeyId.equals(options.issuerKeyId) ||
    grant.issuerKeyVersion !== options.issuerKeyVersion ||
    grant.profile !== options.profile ||
    grant.harness !== options.harness ||
    !grant.sessionPublicKey.equals(expectedSessionKey)
  ) {
    throw new LocalServiceProtocolError('the issued session grant does not match the request');
  }
  encodeGrantClaims(grant);
  return grant;
}

function parseHex(value: unknown, length: number): Buffer {
  if (typeof value !== 'string' || value.length !== length * 2 || !/^[0-9a-f]+$/u.test(value)) {
    throw new LocalServiceProtocolError('the issued session grant is malformed');
  }
  return Buffer.from(value, 'hex');
}

function parsePositiveInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new LocalServiceProtocolError('the issued session grant is malformed');
  }
  return value;
}

function parseUnsignedBigInt(value: unknown): bigint {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new LocalServiceProtocolError('the issued session grant is malformed');
  }
  return BigInt(value);
}

function parseHarness(value: unknown): HarnessKind {
  if (
    value === 'copilot' ||
    value === 'claude-code' ||
    value === 'codex' ||
    value === 'generic' ||
    value === 'a2a-gateway'
  ) {
    return value;
  }
  throw new LocalServiceProtocolError('the issued session grant is malformed');
}

interface NormalizedRequestOptions {
  readonly deadlineMs: number;
  readonly signal: AbortSignal | undefined;
  readonly requestId: Buffer | undefined;
}

function normalizeRequestOptions(
  value: number | LocalServiceRequestOptions | undefined,
  defaultValue: number,
): NormalizedRequestOptions {
  const deadlineMs = typeof value === 'number' ? value : (value?.deadlineMs ?? defaultValue);
  const signal = typeof value === 'number' ? undefined : value?.signal;
  const requestId = typeof value === 'number' ? undefined : value?.requestId;
  if (!Number.isInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > 300_000) {
    throw new Error('local service request deadline is invalid');
  }
  if (
    signal !== undefined &&
    (typeof signal.aborted !== 'boolean' ||
      typeof signal.addEventListener !== 'function' ||
      typeof signal.removeEventListener !== 'function')
  ) {
    throw new Error('local service request cancellation signal is invalid');
  }
  if (
    requestId !== undefined &&
    (!Buffer.isBuffer(requestId) || requestId.length !== requestIdLength)
  ) {
    throw new Error('local service request identifier is invalid');
  }
  return {
    deadlineMs,
    signal,
    requestId: requestId === undefined ? undefined : Buffer.from(requestId),
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
  const sessionKey = generateSessionPrivateKey();
  let grant = await issueSessionGrant(
    options,
    sessionKey,
    deadlineMs,
    reconnectAttempts,
    reconnectDelayMs,
    sleep,
  );
  let grantRefresh: Promise<SessionGrantRecord> | null = null;
  const refreshGrant = (): Promise<SessionGrantRecord> => {
    grantRefresh ??= issueSessionGrant(
      options,
      sessionKey,
      deadlineMs,
      reconnectAttempts,
      reconnectDelayMs,
      sleep,
    ).finally(() => {
      grantRefresh = null;
    });
    return grantRefresh;
  };
  const interactiveLane: ConnectionLane = {
    connection: await openConnection(options, deadlineMs, {
      kind: 'session',
      key: sessionKey,
      grant,
    }),
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
    if (grant.expiresAtUnixMilliseconds <= BigInt(Date.now() + 60_000)) {
      grant = await refreshGrant();
    }
    try {
      lane.connection = await openConnection(options, remainingMs, {
        kind: 'session',
        key: sessionKey,
        grant,
      });
    } catch (error) {
      if (
        !(error instanceof LocalServiceAuthorizationError) &&
        !isRetryableTransportFailure(error)
      ) {
        throw error;
      }
      grant = await refreshGrant();
      lane.connection = await openConnection(options, remainingMs, {
        kind: 'session',
        key: sessionKey,
        grant,
      });
    }
    if (closed) {
      lane.connection.close();
      lane.connection = null;
      throw new Error('the local service client is closed');
    }
    return lane.connection;
  };

  const invokeControl = async (operation: string, payload: unknown): Promise<unknown> => {
    const requestId = randomBytes(requestIdLength);
    const encoded = encodeRequestPayload(operation, payload);
    let refreshed = false;
    while (true) {
      let connection: AuthenticatedConnection | null = null;
      try {
        connection = await openConnection(options, deadlineMs, {
          kind: 'session',
          key: sessionKey,
          grant,
        });
        return await withDeadline(
          connection.invoke(requestId, operation, encoded),
          deadlineMs,
          operation,
          connection.close,
        );
      } catch (error) {
        if (
          refreshed ||
          (!(error instanceof LocalServiceAuthorizationError) &&
            !isRetryableTransportFailure(error))
        ) {
          throw error;
        }
        grant = await refreshGrant();
        refreshed = true;
      } finally {
        connection?.close();
      }
    }
  };

  const requestCancellation = (
    requestId: Buffer,
    reason: 'caller' | 'deadline',
  ): Promise<unknown> =>
    invokeControl('request.cancel', {
      requestId: requestId.toString('hex'),
      reason,
    });

  return {
    profile: options.profile,
    get connected() {
      return !closed;
    },
    close,
    async retire() {
      if (closed) {
        return;
      }
      try {
        await invokeControl('authorization.grant.retire', {});
      } finally {
        close();
      }
    },
    request(operation, payload, requestOptions) {
      let normalized: NormalizedRequestOptions;
      try {
        normalized = normalizeRequestOptions(requestOptions, deadlineMs);
      } catch (error) {
        return Promise.reject(error as Error);
      }
      const requestId = normalized.requestId ?? randomBytes(requestIdLength);
      const encoded = encodeRequestPayload(operation, payload ?? {});
      encodeRequest(requestId, operation, encoded);
      const deliveryOperation = isDeliveryLaneOperation(operation);
      const lane = deliveryOperation ? deliveryLane : interactiveLane;
      const allowedReconnects = deliveryOperation ? 0 : reconnectAttempts;

      const run = lane.inFlight.then(async () => {
        const expiresAt = Date.now() + normalized.deadlineMs;
        let cancellationReason: 'caller' | 'deadline' | null = normalized.signal?.aborted
          ? 'caller'
          : null;
        let admitted = false;
        let cancellationSent = false;
        const sendCancellation = (reason: 'caller' | 'deadline') => {
          cancellationReason ??= reason;
          if (!admitted || cancellationSent || closed) {
            return;
          }
          cancellationSent = true;
          void requestCancellation(requestId, cancellationReason).catch(() => {});
        };
        const abort = () => sendCancellation('caller');
        normalized.signal?.addEventListener('abort', abort, { once: true });
        const deadlineTimer = setTimeout(() => sendCancellation('deadline'), normalized.deadlineMs);
        let attempt = 0;
        let reconciliationAttempt = 0;
        try {
          while (true) {
            const remainingMs = admitted ? normalized.deadlineMs : expiresAt - Date.now();
            if (!admitted && remainingMs <= 0) {
              throw new LocalServiceError(operation, 'deadline_exceeded');
            }

            let active: AuthenticatedConnection;
            try {
              active = await getConnection(lane, remainingMs);
              if (!admitted && cancellationReason) {
                throw new LocalServiceError(
                  operation,
                  cancellationReason === 'caller' ? 'cancelled' : 'deadline_exceeded',
                );
              }
              return await active.invoke(requestId, operation, encoded, () => {
                admitted = true;
                if (cancellationReason) {
                  sendCancellation(cancellationReason);
                }
              });
            } catch (error) {
              if (lane.connection && !lane.connection.connected) {
                lane.connection = null;
              }
              if (
                error instanceof LocalServiceError &&
                error.code === 'reconciliation_pending' &&
                reconciliationAttempt < 3
              ) {
                reconciliationAttempt += 1;
                await sleep(reconnectDelayMs);
                continue;
              }
              if (closed || attempt >= allowedReconnects || !isRetryableTransportFailure(error)) {
                throw error;
              }
              attempt += 1;
              const delay = admitted
                ? reconnectDelayMs
                : Math.min(reconnectDelayMs, Math.max(0, expiresAt - Date.now()));
              if (delay > 0) {
                await sleep(delay);
              }
            }
          }
        } finally {
          clearTimeout(deadlineTimer);
          normalized.signal?.removeEventListener('abort', abort);
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
