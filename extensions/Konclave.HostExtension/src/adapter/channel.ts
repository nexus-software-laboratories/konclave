import { once } from 'node:events';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

import {
  decodeFrameLength,
  decodeHandshakeMessage,
  encodeFrame,
  encodeHandshakeMessage,
  frameHeaderLength,
  maxAuthenticatedFrameBytes,
  maxPreauthFrameBytes,
} from './frame.js';
import {
  decodeAdapterResponse,
  encodeAdapterRequest,
  type AdapterRequest,
  type AdapterResponse,
} from './session.js';
import {
  adapterProof,
  adapterProtocolVersion,
  createAuthTranscript,
  createChallenge,
  createLaunchCapability,
  encodeLaunchCapability,
  verifyDaemonProof,
} from './transcript.js';

/** Longest the daemon may take to connect and finish authenticating. */
export const handshakeTimeoutMs = 10_000;

const ownerOnlyDirectory = 0o700;
const ownerOnlyFile = 0o600;

export interface AdapterRendezvous {
  /** Endpoint the daemon connects outward to. */
  readonly endpoint: string;
  /** Path of the owner-protected launch capability file. */
  readonly capabilityFile: string;
  /** Consumer instance identifier for this adapter. */
  readonly consumerId: string;
  /** Raw capability, held only in memory. */
  readonly capability: Buffer;
  /** Removes the capability file and private directory by exact path. */
  dispose(): Promise<void>;
}

/**
 * Creates the rendezvous an adapter owns before starting its daemon.
 *
 * The directory and capability file are owner-only, and the endpoint name is random.
 * The random name is defense in depth; the capability is the authentication.
 *
 * On Windows the endpoint is a named pipe, whose access is governed by the process
 * token rather than by file permissions, so no directory mode is applied to it.
 */
export async function createAdapterRendezvous(
  platform: NodeJS.Platform = process.platform,
): Promise<AdapterRendezvous> {
  const directory = await mkdtemp(join(tmpdir(), 'konclave-adapter-'));
  await chmod(directory, ownerOnlyDirectory);

  const capability = createLaunchCapability();
  const capabilityFile = join(directory, 'capability');
  // The file is created with owner-only permission before the value is written, so
  // the capability is never briefly readable by another account.
  await writeFile(capabilityFile, encodeLaunchCapability(capability), {
    mode: ownerOnlyFile,
    flag: 'wx',
  });
  await chmod(capabilityFile, ownerOnlyFile);

  const suffix = randomBytes(12).toString('hex');
  const endpoint =
    platform === 'win32'
      ? `\\\\.\\pipe\\konclave-adapter-${suffix}`
      : join(directory, `adapter-${suffix}.sock`);

  return {
    endpoint,
    capabilityFile,
    consumerId: randomBytes(16).toString('base64url'),
    capability,
    async dispose() {
      capability.fill(0);
      await rm(directory, { recursive: true, force: true });
    },
  };
}

/** An authenticated channel to one daemon. */
export interface AdapterChannel {
  /** Profile both sides authenticated. */
  readonly profile: string;
  /** Sends one request and returns its answer. */
  request(request: AdapterRequest): Promise<AdapterResponse>;
  /** Closes the channel. */
  close(): void;
}

export interface AdapterListener {
  /** Waits for the daemon to connect and authenticate. */
  accept(profile: string): Promise<AdapterChannel>;
  /** Stops listening. */
  close(): Promise<void>;
}

/**
 * Listens on the rendezvous endpoint for the daemon's outbound connection.
 *
 * The adapter listens and the daemon connects, so the daemon never opens a socket and
 * the device exposes no inbound listener owned by the process that holds plaintext.
 */
export async function listenForDaemon(
  rendezvous: AdapterRendezvous,
  platform: NodeJS.Platform = process.platform,
): Promise<AdapterListener> {
  const server = createServer();
  server.maxConnections = 1;
  await listen(server, rendezvous.endpoint);
  if (platform !== 'win32') {
    await chmod(rendezvous.endpoint, ownerOnlyFile);
  }

  return {
    async accept(profile) {
      const socket = await acceptOne(server);
      try {
        return await authenticate(socket, profile, rendezvous);
      } catch (error) {
        socket.destroy();
        throw error;
      }
    },
    async close() {
      await closeServer(server);
    },
  };
}

async function authenticate(
  socket: Socket,
  profile: string,
  rendezvous: AdapterRendezvous,
): Promise<AdapterChannel> {
  const reader = new FrameReader(socket);
  const adapterChallenge = createChallenge();

  await withTimeout(
    (async () => {
      await writeFrame(
        socket,
        encodeHandshakeMessage({
          kind: 'adapter-hello',
          version: adapterProtocolVersion,
          consumer: rendezvous.consumerId,
          challenge: adapterChallenge,
        }),
        maxPreauthFrameBytes,
      );

      const answer = decodeHandshakeMessage(await reader.read(maxPreauthFrameBytes));
      if (answer.kind !== 'daemon-auth') {
        throw new Error('adapter message arrived out of order');
      }

      if (answer.profile !== profile) {
        throw new Error('adapter channel profile does not match');
      }

      const transcript = createAuthTranscript(
        adapterProtocolVersion,
        answer.profile,
        rendezvous.consumerId,
        adapterChallenge,
        answer.challenge,
      );

      if (!verifyDaemonProof(transcript, rendezvous.capability, answer.proof)) {
        throw new Error('adapter channel proof is not authentic');
      }

      await writeFrame(
        socket,
        encodeHandshakeMessage({
          kind: 'adapter-auth',
          proof: adapterProof(transcript, rendezvous.capability),
        }),
        maxPreauthFrameBytes,
      );
    })(),
    handshakeTimeoutMs,
  );

  return {
    profile,
    async request(request) {
      await writeFrame(socket, encodeAdapterRequest(request), maxAuthenticatedFrameBytes);
      return decodeAdapterResponse(await reader.read(maxAuthenticatedFrameBytes));
    },
    close() {
      socket.destroy();
    },
  };
}

/**
 * Reads length-prefixed frames from a socket.
 *
 * A declared length is validated against the applicable limit before the body is
 * awaited, so a peer cannot make the process buffer an oversized frame it never
 * intends to send.
 */
class FrameReader {
  private buffered: Buffer = Buffer.alloc(0);
  private ended = false;
  private waiting: (() => void) | null = null;

  constructor(socket: Socket) {
    socket.on('data', (chunk: Buffer) => {
      this.buffered = Buffer.concat([this.buffered, chunk]);
      this.wake();
    });
    socket.on('end', () => {
      this.ended = true;
      this.wake();
    });
    socket.on('close', () => {
      this.ended = true;
      this.wake();
    });
    socket.on('error', () => {
      this.ended = true;
      this.wake();
    });
  }

  async read(limit: number): Promise<Buffer> {
    const header = await this.consume(frameHeaderLength);
    const length = decodeFrameLength(header, limit);
    return this.consume(length);
  }

  private async consume(length: number): Promise<Buffer> {
    while (this.buffered.length < length) {
      if (this.ended) {
        throw new Error('adapter channel closed');
      }
      await new Promise<void>((resolve) => {
        this.waiting = resolve;
      });
    }

    const slice = this.buffered.subarray(0, length);
    this.buffered = this.buffered.subarray(length);
    return slice;
  }

  private wake(): void {
    const waiting = this.waiting;
    this.waiting = null;
    waiting?.();
  }
}

async function writeFrame(socket: Socket, payload: Buffer, limit: number): Promise<void> {
  const frame = encodeFrame(payload, limit);
  await new Promise<void>((resolve, reject) => {
    socket.write(frame, (error) => {
      if (error) {
        reject(new Error('adapter channel closed'));
        return;
      }
      resolve();
    });
  });
}

async function listen(server: Server, endpoint: string): Promise<void> {
  server.listen(endpoint);
  await Promise.race([
    once(server, 'listening'),
    once(server, 'error').then(() => {
      throw new Error('adapter endpoint is unavailable');
    }),
  ]);
}

async function acceptOne(server: Server): Promise<Socket> {
  const [socket] = (await once(server, 'connection')) as [Socket];
  return socket;
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) {
    return;
  }
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let handle: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        handle = setTimeout(() => {
          reject(new Error('adapter handshake did not complete in time'));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (handle) {
      clearTimeout(handle);
    }
  }
}
