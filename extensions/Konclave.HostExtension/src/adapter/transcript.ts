import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Adapter local-channel protocol version implemented by this build.
 */
export const adapterProtocolVersion = 1;

/** Byte length of a handshake challenge. */
export const challengeLength = 32;

/** Byte length of a launch capability. */
export const launchCapabilityLength = 32;

/** Largest accepted length for a bounded handshake identifier. */
export const maxIdentifierLength = 64;

/**
 * Domain separator for the proof a daemon presents to an adapter.
 *
 * Both domains are exactly 32 bytes and distinct, so a captured daemon proof cannot
 * be replayed as the adapter proof.
 */
const daemonProofDomain = Buffer.from('konclave.adapter.v1.proof.daemon', 'ascii');

/** Domain separator for the proof an adapter returns to a daemon. */
const adapterProofDomain = Buffer.from('konclave.adapter.v1.proof.client', 'ascii');

const identifierPattern = /^[A-Za-z0-9._-]+$/;

export interface AuthTranscript {
  readonly version: number;
  readonly profile: string;
  readonly consumer: string;
  readonly adapterChallenge: Buffer;
  readonly daemonChallenge: Buffer;
}

/**
 * Validates and assembles a transcript.
 *
 * @throws when the version is unimplemented, an identifier is empty, oversized, or
 * carries characters outside the accepted set, or a challenge is the wrong length.
 */
export function createAuthTranscript(
  version: number,
  profile: string,
  consumer: string,
  adapterChallenge: Buffer,
  daemonChallenge: Buffer,
): AuthTranscript {
  if (version !== adapterProtocolVersion) {
    throw new Error('adapter protocol version is unsupported');
  }

  assertIdentifier(profile, 'profile');
  assertIdentifier(consumer, 'consumer');
  assertLength(adapterChallenge, challengeLength, 'adapter challenge');
  assertLength(daemonChallenge, challengeLength, 'daemon challenge');

  return { version, profile, consumer, adapterChallenge, daemonChallenge };
}

/**
 * Encodes the canonical authenticated byte string.
 *
 * Every variable-length field carries an explicit two-byte length, so no pair of
 * distinct transcripts can share an encoding. Concatenating the fields directly would
 * let a profile and consumer identifier trade characters and authenticate the same
 * bytes.
 */
export function encodeAuthTranscript(transcript: AuthTranscript): Buffer {
  const profile = Buffer.from(transcript.profile, 'utf8');
  const consumer = Buffer.from(transcript.consumer, 'utf8');
  const header = Buffer.alloc(2);
  header.writeUInt16BE(transcript.version, 0);

  return Buffer.concat([
    header,
    lengthPrefixed(profile),
    lengthPrefixed(consumer),
    transcript.adapterChallenge,
    transcript.daemonChallenge,
  ]);
}

/** Computes the proof a daemon presents to an adapter. */
export function daemonProof(transcript: AuthTranscript, capability: Buffer): Buffer {
  return proof(transcript, capability, daemonProofDomain);
}

/** Computes the proof an adapter returns to a daemon. */
export function adapterProof(transcript: AuthTranscript, capability: Buffer): Buffer {
  return proof(transcript, capability, adapterProofDomain);
}

/** Reports whether a daemon proof authenticates this transcript, in constant time. */
export function verifyDaemonProof(
  transcript: AuthTranscript,
  capability: Buffer,
  candidate: Buffer,
): boolean {
  return constantTimeEquals(daemonProof(transcript, capability), candidate);
}

/** Reports whether an adapter proof authenticates this transcript, in constant time. */
export function verifyAdapterProof(
  transcript: AuthTranscript,
  capability: Buffer,
  candidate: Buffer,
): boolean {
  return constantTimeEquals(adapterProof(transcript, capability), candidate);
}

/**
 * Creates a launch capability.
 *
 * The value never crosses the channel and never enters command arguments, logs,
 * telemetry, or persisted records; only proofs computed under it are exchanged.
 */
export function createLaunchCapability(): Buffer {
  return randomBytes(launchCapabilityLength);
}

/** Creates one handshake challenge. */
export function createChallenge(): Buffer {
  return randomBytes(challengeLength);
}

/**
 * Encodes a capability for its owner-protected launch file.
 *
 * The daemon accepts one canonical unpadded base64url value, so a padded or
 * whitespace-bearing encoding must never be written.
 */
export function encodeLaunchCapability(capability: Buffer): string {
  assertLength(capability, launchCapabilityLength, 'launch capability');
  return capability.toString('base64url');
}

function proof(transcript: AuthTranscript, capability: Buffer, domain: Buffer): Buffer {
  if (capability.length === 0) {
    throw new Error('adapter channel authentication material is unusable');
  }

  return createHmac('sha256', capability)
    .update(Buffer.concat([domain, encodeAuthTranscript(transcript)]))
    .digest();
}

function constantTimeEquals(expected: Buffer, candidate: Buffer): boolean {
  // A length mismatch is rejected before comparison, because timingSafeEqual throws
  // on unequal lengths and a thrown error would itself be an observable difference.
  if (candidate.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(expected, candidate);
}

function lengthPrefixed(value: Buffer): Buffer {
  const header = Buffer.alloc(2);
  header.writeUInt16BE(value.length, 0);
  return Buffer.concat([header, value]);
}

function assertIdentifier(value: string, field: string): void {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length === 0 || bytes.length > maxIdentifierLength) {
    throw new Error(`adapter ${field} identifier is invalid`);
  }

  if (!identifierPattern.test(value)) {
    throw new Error(`adapter ${field} identifier is invalid`);
  }
}

function assertLength(value: Buffer, expected: number, field: string): void {
  if (value.length !== expected) {
    throw new Error(`adapter ${field} does not have its required length`);
  }
}
