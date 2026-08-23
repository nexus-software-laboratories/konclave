import { connect, type Socket } from 'node:net';
import { stat } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

import {
  createAdapterRendezvous,
  listenForDaemon,
  type AdapterRendezvous,
} from '../src/adapter/channel.js';
import {
  decodeFrameLength,
  decodeHandshakeMessage,
  encodeFrame,
  encodeHandshakeMessage,
  frameHeaderLength,
  maxAuthenticatedFrameBytes,
  maxPreauthFrameBytes,
} from '../src/adapter/frame.js';
import { decodeAdapterResponse } from '../src/adapter/session.js';
import {
  adapterProtocolVersion,
  createAuthTranscript,
  createChallenge,
  daemonProof,
  verifyAdapterProof,
} from '../src/adapter/transcript.js';

const profile = 'alice';
const isWindows = process.platform === 'win32';

/**
 * Drives the daemon half of the exchange.
 *
 * The real daemon is Rust; this stands in so the extension's own listener, handshake,
 * and request path can be exercised without a compiled binary. Cross-language byte
 * agreement is pinned separately by the shared fixtures.
 */
async function connectAsDaemon(
  rendezvous: AdapterRendezvous,
  capability: Buffer,
  answeringProfile = profile,
): Promise<{ socket: Socket; authenticated: Promise<boolean> }> {
  const socket = connect(rendezvous.endpoint);
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => {
      resolve();
    });
    socket.once('error', reject);
  });

  const reader = createReader(socket);
  const authenticated = (async () => {
    const hello = decodeHandshakeMessage(await reader(maxPreauthFrameBytes));
    if (hello.kind !== 'adapter-hello') {
      throw new Error('expected an adapter hello');
    }

    const daemonChallenge = createChallenge();
    const transcript = createAuthTranscript(
      adapterProtocolVersion,
      answeringProfile,
      hello.consumer,
      hello.challenge,
      daemonChallenge,
    );

    socket.write(
      encodeFrame(
        encodeHandshakeMessage({
          kind: 'daemon-auth',
          profile: answeringProfile,
          challenge: daemonChallenge,
          proof: daemonProof(transcript, capability),
        }),
        maxPreauthFrameBytes,
      ),
    );

    const answer = decodeHandshakeMessage(await reader(maxPreauthFrameBytes));
    if (answer.kind !== 'adapter-auth') {
      throw new Error('expected an adapter authentication');
    }

    return verifyAdapterProof(transcript, capability, answer.proof);
  })();

  return { socket, authenticated };
}

function createReader(socket: Socket): (limit: number) => Promise<Buffer> {
  let buffered = Buffer.alloc(0);
  let wake: (() => void) | null = null;
  let ended = false;

  socket.on('data', (chunk: Buffer) => {
    buffered = Buffer.concat([buffered, chunk]);
    wake?.();
    wake = null;
  });
  socket.on('close', () => {
    ended = true;
    wake?.();
    wake = null;
  });

  const consume = async (length: number): Promise<Buffer> => {
    while (buffered.length < length) {
      if (ended) {
        throw new Error('closed');
      }
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
    const slice = buffered.subarray(0, length);
    buffered = buffered.subarray(length);
    return slice;
  };

  return async (limit) => {
    const header = await consume(frameHeaderLength);
    return consume(decodeFrameLength(header, limit));
  };
}

describe('adapter rendezvous', () => {
  it('creates an owner-protected private directory and capability file', async () => {
    const rendezvous = await createAdapterRendezvous();
    try {
      const capabilityStats = await stat(rendezvous.capabilityFile);
      expect(capabilityStats.isFile()).toBe(true);

      if (!isWindows) {
        // Group and other must have no access at all; the endpoint name is only
        // defense in depth, so the capability file is the real boundary.
        expect(capabilityStats.mode & 0o077).toBe(0);
      }

      expect(rendezvous.consumerId.length).toBeGreaterThan(0);
      expect(rendezvous.capability).toHaveLength(32);
    } finally {
      await rendezvous.dispose();
    }
  });

  it('removes its directory and clears the capability on dispose', async () => {
    const rendezvous = await createAdapterRendezvous();
    const held = rendezvous.capability;
    await rendezvous.dispose();

    await expect(stat(rendezvous.capabilityFile)).rejects.toThrow();
    // A retained reference must not still expose the secret after disposal.
    expect(held.every((byte) => byte === 0)).toBe(true);
  });

  it('produces a distinct endpoint and consumer for each adapter', async () => {
    const first = await createAdapterRendezvous();
    const second = await createAdapterRendezvous();
    try {
      expect(first.endpoint).not.toBe(second.endpoint);
      expect(first.consumerId).not.toBe(second.consumerId);
      expect(first.capability.equals(second.capability)).toBe(false);
    } finally {
      await first.dispose();
      await second.dispose();
    }
  });

  it('uses a named pipe on Windows and a socket path elsewhere', async () => {
    const windows = await createAdapterRendezvous('win32');
    const posix = await createAdapterRendezvous('linux');
    try {
      // A Windows named pipe is governed by the process token rather than by file
      // permissions, so it deliberately does not live inside the private directory.
      expect(windows.endpoint.startsWith('\\\\.\\pipe\\')).toBe(true);
      expect(posix.endpoint.endsWith('.sock')).toBe(true);
      expect(posix.endpoint.startsWith(posix.capabilityFile.replace(/capability$/, ''))).toBe(true);
    } finally {
      await windows.dispose();
      await posix.dispose();
    }
  });
});

describe('adapter channel', () => {
  it('authenticates an inbound daemon and exchanges a request', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);
    const capability = Buffer.from(rendezvous.capability);

    try {
      const accepted = listener.accept(profile);
      const daemon = await connectAsDaemon(rendezvous, capability);
      const channel = await accepted;

      expect(await daemon.authenticated).toBe(true);
      expect(channel.profile).toBe(profile);

      const reader = createReader(daemon.socket);
      const pending = channel.request({ kind: 'status' });
      const request = await reader(maxAuthenticatedFrameBytes);
      expect(request).toEqual(Buffer.of(19));

      daemon.socket.write(encodeFrame(Buffer.of(33), maxAuthenticatedFrameBytes));
      expect(await pending).toEqual({ kind: 'accepted' });

      channel.close();
      daemon.socket.destroy();
    } finally {
      await listener.close();
      await rendezvous.dispose();
    }
  });

  it('rejects a daemon holding a different capability', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);

    try {
      const accepted = listener.accept(profile);
      const daemon = await connectAsDaemon(rendezvous, Buffer.alloc(32, 8));
      // The adapter closes on rejection, so the daemon side ends mid-exchange. That
      // is the expected outcome here rather than a failure to report.
      daemon.authenticated.catch(() => undefined);

      await expect(accepted).rejects.toThrow(/not authentic/);
      daemon.socket.destroy();
    } finally {
      await listener.close();
      await rendezvous.dispose();
    }
  });

  it('rejects a daemon answering for another profile', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);
    const capability = Buffer.from(rendezvous.capability);

    try {
      const accepted = listener.accept(profile);
      const daemon = await connectAsDaemon(rendezvous, capability, 'bob');
      daemon.authenticated.catch(() => undefined);

      await expect(accepted).rejects.toThrow(/profile does not match/);
      daemon.socket.destroy();
    } finally {
      await listener.close();
      await rendezvous.dispose();
    }
  });

  it('rejects a message arriving out of handshake order', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);

    try {
      const accepted = listener.accept(profile);
      const socket = connect(rendezvous.endpoint);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      });

      // A structurally valid message in the wrong position must be refused rather
      // than treated as the expected one.
      socket.write(
        encodeFrame(
          encodeHandshakeMessage({ kind: 'adapter-auth', proof: Buffer.alloc(32) }),
          maxPreauthFrameBytes,
        ),
      );

      await expect(accepted).rejects.toThrow(/out of order/);
      socket.destroy();
    } finally {
      await listener.close();
      await rendezvous.dispose();
    }
  });

  it('fails a request when the channel closes', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);
    const capability = Buffer.from(rendezvous.capability);

    try {
      const accepted = listener.accept(profile);
      const daemon = await connectAsDaemon(rendezvous, capability);
      const channel = await accepted;
      expect(await daemon.authenticated).toBe(true);

      daemon.socket.destroy();
      await expect(channel.request({ kind: 'status' })).rejects.toThrow();
    } finally {
      await listener.close();
      await rendezvous.dispose();
    }
  });

  it('decodes a response the daemon codec produced', () => {
    // Guards against the channel accidentally bypassing the shared codec.
    expect(decodeAdapterResponse(Buffer.of(33))).toEqual({ kind: 'accepted' });
  });

  it('rejects an oversized declared frame before its body arrives', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);

    try {
      const accepted = listener.accept(profile);
      const socket = connect(rendezvous.endpoint);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      });

      // Only the header is sent. The reader must refuse it on the declared length
      // alone rather than waiting for a body that never comes.
      const header = Buffer.alloc(frameHeaderLength);
      header.writeUInt32BE(maxPreauthFrameBytes + 1, 0);
      socket.write(header);

      await expect(accepted).rejects.toThrow(/exceeds its bound/);
      socket.destroy();
    } finally {
      await listener.close();
      await rendezvous.dispose();
    }
  });

  it('closes idempotently', async () => {
    const rendezvous = await createAdapterRendezvous();
    const listener = await listenForDaemon(rendezvous);
    await listener.close();
    await expect(listener.close()).resolves.toBeUndefined();
    await rendezvous.dispose();
  });
});
