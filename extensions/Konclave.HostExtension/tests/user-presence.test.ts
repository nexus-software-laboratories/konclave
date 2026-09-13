import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  NativeUserPresenceError,
  requestNativeUserPresence,
} from '../src/service/user-presence.js';

interface FakeHelper {
  readonly child: ChildProcessWithoutNullStreams;
  readonly stdin: PassThrough;
  readonly stdout: PassThrough;
  readonly stderr: PassThrough;
  readonly kill: ReturnType<typeof vi.fn>;
}

function createFakeHelper(): FakeHelper {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const kill = vi.fn(() => true);
  const child = Object.assign(new EventEmitter(), {
    stdin,
    stdout,
    stderr,
    kill,
  }) as unknown as ChildProcessWithoutNullStreams;
  return { child, stdin, stdout, stderr, kill };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('native user-presence helper', () => {
  it('writes bounded JSON and accepts one object response', async () => {
    const helper = createFakeHelper();
    const input: Buffer[] = [];
    helper.stdin.on('data', (chunk: Buffer) => input.push(Buffer.from(chunk)));
    const spawnHelper = vi.fn(() => helper.child);

    const response = requestNativeUserPresence(
      'C:\\Program Files\\Konclave\\konclave.exe',
      { publicKey: { challenge: 'challenge' } },
      'win32',
      spawnHelper,
    );
    helper.stderr.write('provider diagnostic');
    helper.stdout.write('{"credential');
    helper.stdout.write('":"approved"}');
    helper.child.emit('close', 0, null);

    await expect(response).resolves.toEqual({ credential: 'approved' });
    expect(spawnHelper).toHaveBeenCalledWith('C:\\Program Files\\Konclave\\konclave.exe', [
      'user-presence-helper',
      'authenticate',
    ]);
    expect(JSON.parse(Buffer.concat(input).toString('utf8'))).toEqual({
      publicKey: { challenge: 'challenge' },
    });
    expect(helper.kill).not.toHaveBeenCalled();
  });

  it('rejects unsupported, unserializable, and oversized requests before spawning', () => {
    const spawnHelper = vi.fn();
    expect(() => requestNativeUserPresence('konclave', {}, 'linux', spawnHelper)).toThrowError(
      NativeUserPresenceError,
    );
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => requestNativeUserPresence('konclave', circular, 'win32', spawnHelper)).toThrow(
      'request is invalid',
    );
    expect(() =>
      requestNativeUserPresence('konclave', { value: 'x'.repeat(64 * 1024) }, 'win32', spawnHelper),
    ).toThrow('request is invalid');
    expect(spawnHelper).not.toHaveBeenCalled();
  });

  it('maps process startup and input failures to finite errors', async () => {
    await expect(
      requestNativeUserPresence('konclave', {}, 'win32', () => {
        throw new Error('sensitive startup detail');
      }),
    ).rejects.toThrow('could not start');

    const processError = createFakeHelper();
    const processFailure = requestNativeUserPresence(
      'konclave',
      {},
      'win32',
      () => processError.child,
    );
    processError.child.emit('error', new Error('sensitive process detail'));
    await expect(processFailure).rejects.toThrow('could not start');

    const inputError = createFakeHelper();
    const inputFailure = requestNativeUserPresence('konclave', {}, 'win32', () => inputError.child);
    inputError.stdin.emit('error', new Error('sensitive input detail'));
    await expect(inputFailure).rejects.toThrow('could not receive its request');
  });

  it('rejects failed, malformed, and non-object responses', async () => {
    for (const testCase of [
      { output: '{"ignored":true}', code: 1, message: 'was not approved' },
      { output: '{', code: 0, message: 'response is invalid' },
      { output: '[]', code: 0, message: 'response is invalid' },
      { output: 'null', code: 0, message: 'response is invalid' },
    ]) {
      const helper = createFakeHelper();
      const response = requestNativeUserPresence('konclave', {}, 'win32', () => helper.child);
      helper.stdout.write(testCase.output);
      helper.child.emit('close', testCase.code, null);
      await expect(response).rejects.toThrow(testCase.message);
    }
  });

  it('kills helpers that exceed stdout or stderr bounds', async () => {
    for (const stream of ['stdout', 'stderr'] as const) {
      const helper = createFakeHelper();
      const response = requestNativeUserPresence('konclave', {}, 'win32', () => helper.child);
      helper[stream].write(Buffer.alloc(64 * 1024 + 1));

      await expect(response).rejects.toThrow('response is invalid');
      expect(helper.kill).toHaveBeenCalledOnce();
      helper.child.emit('close', 0, null);
    }
  });

  it('kills a helper that does not finish within the ceremony deadline', async () => {
    vi.useFakeTimers();
    const helper = createFakeHelper();
    const response = requestNativeUserPresence('konclave', {}, 'win32', () => helper.child);
    const rejection = expect(response).rejects.toThrow('timed out');

    await vi.advanceTimersByTimeAsync(115_000);

    await rejection;
    expect(helper.kill).toHaveBeenCalledOnce();
  });
});
