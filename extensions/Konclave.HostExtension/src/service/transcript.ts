/** Canonical protocol-v2 authorization transcript shared with the Rust service. */

export const protocolVersion = 2;
export const challengeLength = 32;
export const keyIdLength = 16;
export const grantIdLength = 16;
export const clientInstanceLength = 16;
export const maxProfileIdLength = 32;

export const harnessWireValues = {
  copilot: 1,
  'claude-code': 2,
  codex: 3,
  generic: 4,
} as const;

export type HarnessKind = keyof typeof harnessWireValues;

export const clientSignatureDomain = Buffer.from('konclave.local-service.v2.client', 'ascii');
export const serviceSignatureDomain = Buffer.from('konclave.local-service.v2.accept', 'ascii');

const roleIssuer = 1;
const roleSession = 2;

export interface IssuerTranscriptParts {
  readonly issuerKeyId: Buffer;
  readonly issuerKeyVersion: number;
  readonly issuerPublicKey: Buffer;
  readonly clientInstance: Buffer;
  readonly harness: HarnessKind;
  readonly clientChallenge: Buffer;
  readonly serviceChallenge: Buffer;
  readonly serviceKey: Buffer;
}

export interface SessionGrantRecord {
  readonly grantId: Buffer;
  readonly issuerKeyId: Buffer;
  readonly issuerKeyVersion: number;
  readonly profile: string;
  readonly sessionPublicKey: Buffer;
  readonly harness: HarnessKind;
  readonly evidence: number;
  readonly policyVersion: bigint;
  readonly issuedAtUnixMilliseconds: bigint;
  readonly expiresAtUnixMilliseconds: bigint;
  readonly capabilities: bigint;
}

export interface SessionTranscriptParts {
  readonly grant: SessionGrantRecord;
  readonly clientInstance: Buffer;
  readonly clientChallenge: Buffer;
  readonly serviceChallenge: Buffer;
  readonly serviceKey: Buffer;
}

export function assertCanonicalProfile(profile: string): void {
  if (profile.length === 0 || profile.length > maxProfileIdLength) {
    throw new Error('profile identifier is invalid');
  }
  if (!/^[a-z0-9_-]+$/u.test(profile)) {
    throw new Error('profile identifier is invalid');
  }
}

export function encodeIssuerTranscript(parts: IssuerTranscriptParts): Buffer {
  assertFixed(parts.issuerKeyId, keyIdLength, 'issuer key identifier');
  assertFixed(parts.issuerPublicKey, 32, 'issuer public key');
  assertFixed(parts.clientInstance, clientInstanceLength, 'client instance');
  assertChallenges(parts.clientChallenge, parts.serviceChallenge);
  assertFixed(parts.serviceKey, 32, 'service key');
  if (!Number.isInteger(parts.issuerKeyVersion) || parts.issuerKeyVersion <= 0) {
    throw new Error('issuer key version is invalid');
  }

  const encoded = Buffer.alloc(2 + 1 + keyIdLength + 4 + 32 + clientInstanceLength + 2);
  let offset = encoded.writeUInt16BE(protocolVersion, 0);
  offset = encoded.writeUInt8(roleIssuer, offset);
  offset += parts.issuerKeyId.copy(encoded, offset);
  offset = encoded.writeUInt32BE(parts.issuerKeyVersion, offset);
  offset += parts.issuerPublicKey.copy(encoded, offset);
  offset += parts.clientInstance.copy(encoded, offset);
  encoded.writeUInt16BE(harnessWireValues[parts.harness], offset);
  return Buffer.concat([encoded, parts.clientChallenge, parts.serviceChallenge, parts.serviceKey]);
}

export function encodeSessionTranscript(parts: SessionTranscriptParts): Buffer {
  const grant = parts.grant;
  assertGrant(grant);
  assertFixed(parts.clientInstance, clientInstanceLength, 'client instance');
  assertChallenges(parts.clientChallenge, parts.serviceChallenge);
  assertFixed(parts.serviceKey, 32, 'service key');
  const profile = Buffer.from(grant.profile, 'ascii');
  const fixed = Buffer.alloc(
    2 + 1 + grantIdLength + keyIdLength + 4 + 32 + clientInstanceLength + 2 + 2,
  );
  let offset = fixed.writeUInt16BE(protocolVersion, 0);
  offset = fixed.writeUInt8(roleSession, offset);
  offset += grant.grantId.copy(fixed, offset);
  offset += grant.issuerKeyId.copy(fixed, offset);
  offset = fixed.writeUInt32BE(grant.issuerKeyVersion, offset);
  offset += grant.sessionPublicKey.copy(fixed, offset);
  offset += parts.clientInstance.copy(fixed, offset);
  offset = fixed.writeUInt16BE(harnessWireValues[grant.harness], offset);
  fixed.writeUInt16BE(profile.length, offset);
  const claims = Buffer.alloc(1 + 8 * 4);
  let claimsOffset = claims.writeUInt8(grant.evidence, 0);
  claimsOffset = claims.writeBigUInt64BE(grant.policyVersion, claimsOffset);
  claimsOffset = claims.writeBigUInt64BE(grant.issuedAtUnixMilliseconds, claimsOffset);
  claimsOffset = claims.writeBigUInt64BE(grant.expiresAtUnixMilliseconds, claimsOffset);
  claims.writeBigUInt64BE(grant.capabilities, claimsOffset);
  return Buffer.concat([
    fixed,
    profile,
    claims,
    parts.clientChallenge,
    parts.serviceChallenge,
    parts.serviceKey,
  ]);
}

export function encodeGrantClaims(grant: SessionGrantRecord): Buffer {
  assertGrant(grant);
  const profile = Buffer.from(grant.profile, 'ascii');
  const fixed = Buffer.alloc(grantIdLength + keyIdLength + 4 + 32 + 2 + 2);
  let offset = grant.grantId.copy(fixed, 0);
  offset += grant.issuerKeyId.copy(fixed, offset);
  offset = fixed.writeUInt32BE(grant.issuerKeyVersion, offset);
  offset += grant.sessionPublicKey.copy(fixed, offset);
  offset = fixed.writeUInt16BE(harnessWireValues[grant.harness], offset);
  fixed.writeUInt16BE(profile.length, offset);
  const claims = Buffer.alloc(1 + 8 * 4);
  let claimsOffset = claims.writeUInt8(grant.evidence, 0);
  claimsOffset = claims.writeBigUInt64BE(grant.policyVersion, claimsOffset);
  claimsOffset = claims.writeBigUInt64BE(grant.issuedAtUnixMilliseconds, claimsOffset);
  claimsOffset = claims.writeBigUInt64BE(grant.expiresAtUnixMilliseconds, claimsOffset);
  claims.writeBigUInt64BE(grant.capabilities, claimsOffset);
  return Buffer.concat([fixed, profile, claims]);
}

export function clientSigningMessage(transcript: Buffer): Buffer {
  return Buffer.concat([clientSignatureDomain, transcript]);
}

export function serviceSigningMessage(transcript: Buffer): Buffer {
  return Buffer.concat([serviceSignatureDomain, transcript]);
}

function assertGrant(grant: SessionGrantRecord): void {
  assertFixed(grant.grantId, grantIdLength, 'grant identifier');
  assertFixed(grant.issuerKeyId, keyIdLength, 'issuer key identifier');
  assertFixed(grant.sessionPublicKey, 32, 'session public key');
  assertCanonicalProfile(grant.profile);
  if (!Number.isInteger(grant.issuerKeyVersion) || grant.issuerKeyVersion <= 0) {
    throw new Error('issuer key version is invalid');
  }
  if (
    grant.evidence <= 0 ||
    (grant.evidence & ~0x0f) !== 0 ||
    grant.policyVersion <= 0n ||
    grant.issuedAtUnixMilliseconds < 0n ||
    grant.expiresAtUnixMilliseconds <= grant.issuedAtUnixMilliseconds ||
    grant.capabilities <= 0n ||
    (grant.capabilities & ~0x0fn) !== 0n
  ) {
    throw new Error('session grant is invalid');
  }
}

function assertFixed(value: Buffer, length: number, name: string): void {
  if (value.length !== length) {
    throw new Error(`${name} is invalid`);
  }
}

function assertChallenges(client: Buffer, service: Buffer): void {
  if (client.length !== challengeLength || service.length !== challengeLength) {
    throw new Error('handshake challenge is invalid');
  }
}
