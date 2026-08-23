/**
 * Bounded framing and handshake messages for the local adapter channel.
 *
 * Mirrors the Rust implementation exactly. A declared length is validated against the
 * applicable limit before any buffer is reserved, so a peer cannot force a large
 * allocation with a four-byte header it never satisfies.
 */

import { adapterProtocolVersion, challengeLength, maxIdentifierLength } from './transcript.js';

/** Bytes carried by a frame length header. */
export const frameHeaderLength = 4;

/**
 * Hard limit for a frame accepted before the peer is authenticated.
 *
 * Every handshake message is far smaller than this. Keeping the pre-authentication
 * limit well below the authenticated limit means an unauthenticated peer cannot make
 * the process reserve an event-sized buffer.
 */
export const maxPreauthFrameBytes = 1_024;

/** Hard limit for a frame accepted after both proofs verify. */
export const maxAuthenticatedFrameBytes = 1_048_576;

const kindAdapterHello = 1;
const kindDaemonAuth = 2;
const kindAdapterAuth = 3;

export interface AdapterHello {
  readonly kind: 'adapter-hello';
  readonly version: number;
  readonly consumer: string;
  readonly challenge: Buffer;
}

export interface DaemonAuth {
  readonly kind: 'daemon-auth';
  readonly profile: string;
  readonly challenge: Buffer;
  readonly proof: Buffer;
}

export interface AdapterAuth {
  readonly kind: 'adapter-auth';
  readonly proof: Buffer;
}

export type HandshakeMessage = AdapterHello | DaemonAuth | AdapterAuth;

/**
 * Reads a declared frame length and rejects it before any buffer is reserved.
 *
 * @throws when the declared length is zero or exceeds `limit`.
 */
export function decodeFrameLength(header: Buffer, limit: number): number {
  if (header.length !== frameHeaderLength) {
    throw new Error('adapter frame is malformed');
  }

  const declared = header.readUInt32BE(0);
  if (declared === 0) {
    throw new Error('adapter frame is malformed');
  }

  if (declared > limit) {
    throw new Error('adapter frame exceeds its bound');
  }

  return declared;
}

/**
 * Prefixes a payload with its length header.
 *
 * @throws when the payload is empty or exceeds `limit`.
 */
export function encodeFrame(payload: Buffer, limit: number): Buffer {
  if (payload.length === 0) {
    throw new Error('adapter frame is malformed');
  }

  if (payload.length > limit) {
    throw new Error('adapter frame exceeds its bound');
  }

  const header = Buffer.alloc(frameHeaderLength);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/** Encodes the canonical payload for a handshake message. */
export function encodeHandshakeMessage(message: HandshakeMessage): Buffer {
  switch (message.kind) {
    case 'adapter-hello': {
      const version = Buffer.alloc(2);
      version.writeUInt16BE(message.version, 0);
      return Buffer.concat([
        Buffer.of(kindAdapterHello),
        version,
        boundedString(message.consumer),
        message.challenge,
      ]);
    }
    case 'daemon-auth':
      return Buffer.concat([
        Buffer.of(kindDaemonAuth),
        boundedString(message.profile),
        message.challenge,
        message.proof,
      ]);
    case 'adapter-auth':
      return Buffer.concat([Buffer.of(kindAdapterAuth), message.proof]);
  }
}

/**
 * Decodes one handshake payload.
 *
 * Every field is read at an exact offset and the payload must end precisely at the
 * last field, so trailing bytes, short reads, and unknown tags fail before any value
 * is used.
 */
export function decodeHandshakeMessage(payload: Buffer): HandshakeMessage {
  const reader = new Reader(payload);
  const kind = reader.byte();

  let message: HandshakeMessage;
  switch (kind) {
    case kindAdapterHello: {
      const version = reader.uint16();
      if (version !== adapterProtocolVersion) {
        throw new Error('adapter protocol version is unsupported');
      }
      message = {
        kind: 'adapter-hello',
        version,
        consumer: reader.boundedString('consumer'),
        challenge: reader.take(challengeLength),
      };
      break;
    }
    case kindDaemonAuth:
      message = {
        kind: 'daemon-auth',
        profile: reader.boundedString('profile'),
        challenge: reader.take(challengeLength),
        proof: reader.take(challengeLength),
      };
      break;
    case kindAdapterAuth:
      message = { kind: 'adapter-auth', proof: reader.take(challengeLength) };
      break;
    default:
      throw new Error('adapter message kind is unknown');
  }

  reader.finish();
  return message;
}

function boundedString(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  const header = Buffer.alloc(2);
  header.writeUInt16BE(bytes.length, 0);
  return Buffer.concat([header, bytes]);
}

/** Reads fixed-width fields at exact offsets, failing closed on any short read. */
export class Reader {
  private offset = 0;

  constructor(private readonly payload: Buffer) {}

  byte(): number {
    return this.take(1).readUInt8(0);
  }

  uint16(): number {
    return this.take(2).readUInt16BE(0);
  }

  uint32(): number {
    return this.take(4).readUInt32BE(0);
  }

  /**
   * Reads a 64-bit value as a JavaScript number.
   *
   * Sequences, cursors, and lease generations are counters that stay far below the
   * safe-integer ceiling, so a value above it means the peer is not speaking this
   * protocol rather than that the counter legitimately grew that large.
   */
  uint64(): number {
    const value = this.take(8).readBigUInt64BE(0);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('adapter frame is malformed');
    }
    return Number(value);
  }

  take(length: number): Buffer {
    if (length < 0 || this.payload.length - this.offset < length) {
      throw new Error('adapter frame is malformed');
    }
    const slice = this.payload.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  boundedString(field: string): string {
    const length = this.uint16();
    if (length === 0 || length > maxIdentifierLength) {
      throw new Error(`adapter ${field} identifier is invalid`);
    }
    const bytes = this.take(length);
    const value = bytes.toString('utf8');
    // A lossy decode means the peer sent bytes that are not UTF-8, which the Rust
    // side rejects outright rather than substituting a replacement character.
    if (Buffer.from(value, 'utf8').length !== bytes.length) {
      throw new Error(`adapter ${field} identifier is invalid`);
    }
    return value;
  }

  text(length: number): string {
    const bytes = this.take(length);
    const value = bytes.toString('utf8');
    if (Buffer.from(value, 'utf8').length !== bytes.length) {
      throw new Error('adapter frame is malformed');
    }
    return value;
  }

  finish(): void {
    if (this.offset !== this.payload.length) {
      throw new Error('adapter frame is malformed');
    }
  }
}
