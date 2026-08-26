import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';

/**
 * Ed25519 key handling for the shared local service handshake.
 *
 * Node exposes Ed25519 only through key objects, while the protocol carries raw
 * 32-byte values. The fixed DER prefixes below are the standard PKCS#8 and SPKI
 * envelopes for Ed25519, so a raw value can be wrapped without implementing any
 * cryptography here: signing and verification stay inside the platform provider.
 */

const privateKeyPrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const publicKeyPrefix = Buffer.from('302a300506032b6570032100', 'hex');

/** Raw byte length of an Ed25519 seed, public key, and signature. */
export const seedLength = 32;
export const publicKeyLength = 32;
export const signatureLength = 64;

export function privateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.length !== seedLength) {
    throw new Error('an Ed25519 seed must be exactly 32 bytes');
  }
  const encoded = Buffer.alloc(privateKeyPrefix.length + seed.length);
  privateKeyPrefix.copy(encoded);
  seed.copy(encoded, privateKeyPrefix.length);
  try {
    return createPrivateKey({
      key: encoded,
      format: 'der',
      type: 'pkcs8',
    });
  } finally {
    encoded.fill(0);
  }
}

/** Imports an Ed25519 seed and clears the caller's buffer before returning. */
export function privateKeyFromSeedAndZeroize(seed: Buffer): KeyObject {
  try {
    return privateKeyFromSeed(seed);
  } finally {
    seed.fill(0);
  }
}

export function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== publicKeyLength) {
    throw new Error('an Ed25519 public key must be exactly 32 bytes');
  }
  return createPublicKey({
    key: Buffer.concat([publicKeyPrefix, raw]),
    format: 'der',
    type: 'spki',
  });
}

export function rawPublicKey(key: KeyObject): Buffer {
  const publicKey = key.type === 'public' ? key : createPublicKey(key);
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(der.subarray(der.length - publicKeyLength));
}

export function signMessage(key: KeyObject, message: Buffer): Buffer {
  return sign(null, message, key);
}

export function verifyMessage(key: KeyObject, message: Buffer, signature: Buffer): boolean {
  if (signature.length !== signatureLength) {
    return false;
  }
  return verify(null, message, key, signature);
}
