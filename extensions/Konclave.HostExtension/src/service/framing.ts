import type { Socket } from 'node:net';

/** Bytes carried by a frame length header. */
export const frameHeaderLength = 4;

/**
 * Bounded length-prefixed framing for the shared local service channel.
 *
 * The daemon uses one framing rule for every local channel, and the limit is stated
 * by the caller for the current stage: an unauthenticated handshake reserves far less
 * than an authenticated request, so a peer cannot use a four-byte header to make this
 * process allocate a request-sized buffer before it has proved anything.
 */

export type FrameFailure = 'too-large' | 'malformed' | 'closed';

export class FrameError extends Error {
  readonly failure: FrameFailure;

  constructor(failure: FrameFailure) {
    super(`local service frame ${failure}`);
    this.name = 'FrameError';
    this.failure = failure;
  }
}

export function encodeFrame(payload: Buffer, limit: number): Buffer {
  if (payload.length === 0) {
    throw new FrameError('malformed');
  }
  if (payload.length > limit) {
    throw new FrameError('too-large');
  }
  const frame = Buffer.allocUnsafe(frameHeaderLength + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, frameHeaderLength);
  return frame;
}

export function decodeFrameLength(header: Buffer, limit: number): number {
  const declared = header.readUInt32BE(0);
  if (declared === 0) {
    throw new FrameError('malformed');
  }
  if (declared > limit) {
    throw new FrameError('too-large');
  }
  return declared;
}

/** The stream operations the reader needs, so tests do not need a real socket. */
export interface FrameStream {
  on(event: 'data', handler: (chunk: Buffer) => void): unknown;
  on(event: 'end' | 'close', handler: () => void): unknown;
  on(event: 'error', handler: (error: Error) => void): unknown;
}

interface PendingRead {
  readonly limit: number;
  resolve(frame: Buffer): void;
  reject(error: Error): void;
}

/**
 * Reads bounded frames from a stream without buffering an unbounded backlog.
 *
 * The buffer only ever holds one declared frame plus its header, because a declared
 * length above the current stage's limit is rejected before any of it is retained.
 */
export class FrameReader {
  #buffer: Buffer = Buffer.alloc(0);
  #bufferLimit: number;
  #pending: PendingRead | null = null;
  #failure: Error | null = null;
  #closed = false;

  constructor(stream: FrameStream, bufferLimit: number) {
    this.#bufferLimit = bufferLimit;
    stream.on('data', (chunk: Buffer) => {
      if (this.#failure || this.#closed) {
        return;
      }
      if (chunk.length > this.#bufferLimit - this.#buffer.length) {
        this.#failure = new FrameError('too-large');
        this.#buffer = Buffer.alloc(0);
        this.#drain();
        return;
      }
      this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
      this.#drain();
    });
    stream.on('end', () => {
      this.#closed = true;
      this.#drain();
    });
    stream.on('close', () => {
      this.#closed = true;
      this.#drain();
    });
    stream.on('error', (error: Error) => {
      this.#failure = error;
      this.#drain();
    });
  }

  /** Reads one frame whose declared length must not exceed `limit`. */
  read(limit: number): Promise<Buffer> {
    if (this.#pending) {
      return Promise.reject(new Error('a frame read is already in flight'));
    }
    return new Promise<Buffer>((resolve, reject) => {
      this.#pending = { limit, resolve, reject };
      this.#drain();
    });
  }

  /** Raises the authenticated buffer ceiling after the handshake succeeds. */
  setBufferLimit(limit: number): void {
    if (limit < this.#buffer.length) {
      throw new FrameError('too-large');
    }
    this.#bufferLimit = limit;
  }

  #drain(): void {
    const pending = this.#pending;
    if (!pending) {
      return;
    }

    if (this.#buffer.length >= frameHeaderLength) {
      let declared: number;
      try {
        declared = decodeFrameLength(this.#buffer.subarray(0, frameHeaderLength), pending.limit);
      } catch (error) {
        this.#failure = error as Error;
        this.#buffer = Buffer.alloc(0);
        this.#pending = null;
        pending.reject(this.#failure);
        return;
      }
      if (this.#buffer.length >= frameHeaderLength + declared) {
        const frame = this.#buffer.subarray(frameHeaderLength, frameHeaderLength + declared);
        this.#buffer = this.#buffer.subarray(frameHeaderLength + declared);
        this.#pending = null;
        pending.resolve(Buffer.from(frame));
        return;
      }
    }

    if (this.#failure) {
      this.#pending = null;
      pending.reject(this.#failure);
      return;
    }
    if (this.#closed) {
      this.#pending = null;
      pending.reject(new FrameError('closed'));
    }
  }
}

export function writeFrame(socket: Socket, payload: Buffer, limit: number): Promise<void> {
  const frame = encodeFrame(payload, limit);
  return new Promise((resolve, reject) => {
    socket.write(frame, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}
