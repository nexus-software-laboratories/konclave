import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  adapterProof,
  adapterProtocolVersion,
  challengeLength,
  createAuthTranscript,
  createChallenge,
  createLaunchCapability,
  daemonProof,
  encodeAuthTranscript,
  encodeLaunchCapability,
  launchCapabilityLength,
  maxIdentifierLength,
  verifyAdapterProof,
  verifyDaemonProof,
} from '../src/adapter/transcript.js';

interface AuthVectors {
  readonly protocolVersion: number;
  readonly profile: string;
  readonly consumer: string;
  readonly launchCapability: string;
  readonly adapterChallenge: string;
  readonly daemonChallenge: string;
  readonly encodedTranscript: string;
  readonly daemonProof: string;
  readonly adapterProof: string;
}

// The fixture is the contract every adapter implementation must satisfy, so this
// reads it as data rather than restating the expected bytes here. A change that
// alters the transcript layout or a proof domain fails in both languages instead of
// silently desynchronizing one of them.
const vectors = JSON.parse(
  readFileSync(
    join(
      import.meta.dirname,
      '..',
      '..',
      '..',
      'fixtures',
      'adapter',
      'v1',
      'auth-transcript.json',
    ),
    'utf8',
  ),
) as AuthVectors;

const capability = Buffer.from(vectors.launchCapability, 'hex');

function fixtureTranscript() {
  return createAuthTranscript(
    adapterProtocolVersion,
    vectors.profile,
    vectors.consumer,
    Buffer.from(vectors.adapterChallenge, 'hex'),
    Buffer.from(vectors.daemonChallenge, 'hex'),
  );
}

describe('adapter authentication parity', () => {
  it('implements the protocol version the vectors were generated for', () => {
    expect(adapterProtocolVersion).toBe(vectors.protocolVersion);
  });

  it('reproduces the canonical transcript encoding byte for byte', () => {
    expect(encodeAuthTranscript(fixtureTranscript()).toString('hex')).toBe(
      vectors.encodedTranscript,
    );
  });

  it('reproduces both role proofs byte for byte', () => {
    const transcript = fixtureTranscript();
    expect(daemonProof(transcript, capability).toString('hex')).toBe(vectors.daemonProof);
    expect(adapterProof(transcript, capability).toString('hex')).toBe(vectors.adapterProof);
  });

  it('verifies proofs produced by the other implementation', () => {
    const transcript = fixtureTranscript();
    expect(verifyDaemonProof(transcript, capability, Buffer.from(vectors.daemonProof, 'hex'))).toBe(
      true,
    );
    expect(
      verifyAdapterProof(transcript, capability, Buffer.from(vectors.adapterProof, 'hex')),
    ).toBe(true);
  });

  it('encodes the launch capability the way the daemon parses it', () => {
    const encoded = encodeLaunchCapability(capability);
    expect(encoded).not.toContain('=');
    expect(Buffer.from(encoded, 'base64url')).toEqual(capability);
  });
});

describe('adapter authentication rejections', () => {
  it('rejects a proof replayed across roles', () => {
    const transcript = fixtureTranscript();
    const daemon = daemonProof(transcript, capability);
    expect(verifyAdapterProof(transcript, capability, daemon)).toBe(false);
  });

  it('rejects a proof under a different capability', () => {
    const transcript = fixtureTranscript();
    const proof = daemonProof(transcript, capability);
    expect(verifyDaemonProof(transcript, Buffer.alloc(32, 8), proof)).toBe(false);
  });

  it('rejects a truncated or padded proof without throwing', () => {
    const transcript = fixtureTranscript();
    const proof = daemonProof(transcript, capability);
    expect(verifyDaemonProof(transcript, capability, proof.subarray(0, 31))).toBe(false);
    expect(verifyDaemonProof(transcript, capability, Buffer.concat([proof, Buffer.of(0)]))).toBe(
      false,
    );
    expect(verifyDaemonProof(transcript, capability, Buffer.alloc(0))).toBe(false);
  });

  it('produces distinct encodings when identifiers trade characters', () => {
    const adapterChallenge = Buffer.from(vectors.adapterChallenge, 'hex');
    const daemonChallenge = Buffer.from(vectors.daemonChallenge, 'hex');
    const first = createAuthTranscript(
      adapterProtocolVersion,
      'alice',
      'consumer',
      adapterChallenge,
      daemonChallenge,
    );
    const second = createAuthTranscript(
      adapterProtocolVersion,
      'alicec',
      'onsumer',
      adapterChallenge,
      daemonChallenge,
    );
    expect(encodeAuthTranscript(first)).not.toEqual(encodeAuthTranscript(second));
  });

  it('rejects an unimplemented version and invalid identifiers', () => {
    const adapterChallenge = Buffer.from(vectors.adapterChallenge, 'hex');
    const daemonChallenge = Buffer.from(vectors.daemonChallenge, 'hex');

    expect(() =>
      createAuthTranscript(
        adapterProtocolVersion + 1,
        'alice',
        'consumer',
        adapterChallenge,
        daemonChallenge,
      ),
    ).toThrow();

    for (const [profile, consumer] of [
      ['', 'consumer'],
      ['alice', ''],
      ['alice/../bob', 'consumer'],
      ['a'.repeat(maxIdentifierLength + 1), 'consumer'],
    ] as const) {
      expect(() =>
        createAuthTranscript(
          adapterProtocolVersion,
          profile,
          consumer,
          adapterChallenge,
          daemonChallenge,
        ),
      ).toThrow();
    }
  });

  it('rejects a challenge of the wrong length', () => {
    expect(() =>
      createAuthTranscript(
        adapterProtocolVersion,
        'alice',
        'consumer',
        Buffer.alloc(16),
        Buffer.from(vectors.daemonChallenge, 'hex'),
      ),
    ).toThrow();
  });

  it('refuses to compute a proof under empty key material', () => {
    expect(() => daemonProof(fixtureTranscript(), Buffer.alloc(0))).toThrow();
  });

  it('refuses to encode a capability of the wrong length', () => {
    expect(() => encodeLaunchCapability(Buffer.alloc(16))).toThrow();
  });
});

describe('adapter secret generation', () => {
  it('produces capabilities and challenges of the required length that do not repeat', () => {
    const capabilities = new Set<string>();
    const challenges = new Set<string>();
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const generated = createLaunchCapability();
      const challenge = createChallenge();
      expect(generated).toHaveLength(launchCapabilityLength);
      expect(challenge).toHaveLength(challengeLength);
      capabilities.add(generated.toString('hex'));
      challenges.add(challenge.toString('hex'));
    }

    // A repeat here would mean the source is not random, which would make a proof
    // predictable rather than merely weak.
    expect(capabilities.size).toBe(32);
    expect(challenges.size).toBe(32);
  });
});
