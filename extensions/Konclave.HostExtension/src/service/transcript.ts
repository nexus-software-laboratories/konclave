/**
 * Canonical handshake transcript for the shared local service protocol.
 *
 * Every field the two peers must agree on is covered here, and the encoding is the
 * one the service implements byte for byte. The single variable-length field carries
 * an explicit length while every other field is fixed width, so no two distinct
 * bindings can share an encoding.
 */

export const protocolVersion = 1;
export const challengeLength = 32;
export const adapterKeyIdLength = 16;
export const clientInstanceLength = 16;
export const maxProfileIdLength = 32;

/** Wire values for the harnesses this build implements. */
export const harnessWireValues = {
  copilot: 1,
  'claude-code': 2,
  codex: 3,
} as const;

export type HarnessKind = keyof typeof harnessWireValues;

/** Role domains, exactly 32 bytes each, that separate the two signatures. */
export const clientSignatureDomain = Buffer.from('konclave.local-service.v1.client', 'ascii');
export const serviceSignatureDomain = Buffer.from('konclave.local-service.v1.accept', 'ascii');

export interface TranscriptParts {
  readonly adapterKeyId: Buffer;
  readonly adapterKeyVersion: number;
  readonly clientInstance: Buffer;
  readonly harness: HarnessKind;
  readonly profile: string;
  readonly clientChallenge: Buffer;
  readonly serviceChallenge: Buffer;
  readonly serviceKey: Buffer;
}

/**
 * Rejects a profile identifier that is not canonical.
 *
 * The identifier is also a directory name on the service side, so a case variant is
 * refused rather than folded: two spellings must never reach one profile.
 */
export function assertCanonicalProfile(profile: string): void {
  if (profile.length === 0 || profile.length > maxProfileIdLength) {
    throw new Error('profile identifier is invalid');
  }
  if (!/^[a-z0-9_-]+$/.test(profile)) {
    throw new Error('profile identifier is invalid');
  }
}

export function encodeTranscript(parts: TranscriptParts): Buffer {
  assertCanonicalProfile(parts.profile);
  if (parts.adapterKeyId.length !== adapterKeyIdLength) {
    throw new Error('adapter key identifier is invalid');
  }
  if (parts.clientInstance.length !== clientInstanceLength) {
    throw new Error('client instance identifier is invalid');
  }
  if (parts.adapterKeyVersion <= 0 || !Number.isInteger(parts.adapterKeyVersion)) {
    throw new Error('adapter key version is invalid');
  }
  if (
    parts.clientChallenge.length !== challengeLength ||
    parts.serviceChallenge.length !== challengeLength
  ) {
    throw new Error('handshake challenge is invalid');
  }
  if (parts.serviceKey.length !== 32) {
    throw new Error('service key is invalid');
  }

  const profile = Buffer.from(parts.profile, 'ascii');
  const encoded = Buffer.alloc(2 + adapterKeyIdLength + 4 + clientInstanceLength + 2 + 2);
  let offset = 0;
  offset = encoded.writeUInt16BE(protocolVersion, offset);
  offset += parts.adapterKeyId.copy(encoded, offset);
  offset = encoded.writeUInt32BE(parts.adapterKeyVersion, offset);
  offset += parts.clientInstance.copy(encoded, offset);
  offset = encoded.writeUInt16BE(harnessWireValues[parts.harness], offset);
  encoded.writeUInt16BE(profile.length, offset);

  return Buffer.concat([
    encoded,
    profile,
    parts.clientChallenge,
    parts.serviceChallenge,
    parts.serviceKey,
  ]);
}

export function clientSigningMessage(transcript: Buffer): Buffer {
  return Buffer.concat([clientSignatureDomain, transcript]);
}

export function serviceSigningMessage(transcript: Buffer): Buffer {
  return Buffer.concat([serviceSignatureDomain, transcript]);
}
