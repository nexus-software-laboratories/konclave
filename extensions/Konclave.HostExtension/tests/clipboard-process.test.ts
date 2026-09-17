import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { runClipboardCommand, type ClipboardProcessSpawner } from '../src/service/clipboard.js';

class FakeClipboardProcess extends EventEmitter {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly kill = vi.fn(() => true);
}

function fakeSpawner(child: FakeClipboardProcess): ClipboardProcessSpawner {
  return () => child;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('clipboard process runner', () => {
  it('returns unavailable for oversized input and pre-spawn failures', async () => {
    const spawn = vi.fn<ClipboardProcessSpawner>();
    await expect(runClipboardCommand('/unused', [], 'x'.repeat(513), spawn)).resolves.toBe(
      'unavailable',
    );
    expect(spawn).not.toHaveBeenCalled();

    await expect(
      runClipboardCommand('/missing', [], '', () => {
        throw new Error('missing');
      }),
    ).resolves.toBe('unavailable');
  });

  it('writes stdin and accepts only a clean zero exit', async () => {
    const child = new FakeClipboardProcess();
    const input: Buffer[] = [];
    child.stdin.on('data', (chunk: Buffer) => input.push(Buffer.from(chunk)));
    const result = runClipboardCommand('/trusted/provider', [], 'TOKEN', fakeSpawner(child));

    child.emit('spawn');
    child.emit('close', 0);
    child.emit('close', 0);

    await expect(result).resolves.toBe('success');
    expect(Buffer.concat(input).toString('utf8')).toBe('TOKEN');
    expect(child.kill).not.toHaveBeenCalled();
  });

  it('distinguishes pre-spawn and spawned process errors', async () => {
    const unavailable = new FakeClipboardProcess();
    const unavailableResult = runClipboardCommand(
      '/trusted/provider',
      [],
      'TOKEN',
      fakeSpawner(unavailable),
    );
    unavailable.emit('error', new Error('spawn failed'));
    await expect(unavailableResult).resolves.toBe('unavailable');

    const indeterminate = new FakeClipboardProcess();
    const indeterminateResult = runClipboardCommand(
      '/trusted/provider',
      [],
      'TOKEN',
      fakeSpawner(indeterminate),
    );
    indeterminate.emit('spawn');
    indeterminate.emit('error', new Error('runtime failure'));
    let resolved = false;
    void indeterminateResult.then(() => {
      resolved = true;
    });
    await Promise.resolve();
    expect(resolved).toBe(false);
    indeterminate.emit('close', 0);
    await expect(indeterminateResult).resolves.toBe('indeterminate');
  });

  it('kills and waits for close after timeout, output overflow, or stdin failure', async () => {
    vi.useFakeTimers();
    const timedOut = new FakeClipboardProcess();
    const timeoutResult = runClipboardCommand(
      '/trusted/provider',
      [],
      'TOKEN',
      fakeSpawner(timedOut),
    );
    timedOut.emit('spawn');
    await vi.advanceTimersByTimeAsync(5_000);
    expect(timedOut.kill).toHaveBeenCalledWith('SIGKILL');
    timedOut.emit('close', null);
    await expect(timeoutResult).resolves.toBe('indeterminate');

    const overflow = new FakeClipboardProcess();
    const overflowResult = runClipboardCommand(
      '/trusted/provider',
      [],
      'TOKEN',
      fakeSpawner(overflow),
    );
    overflow.emit('spawn');
    overflow.stdout.write(Buffer.alloc(4 * 1024 + 1));
    overflow.stderr.write(Buffer.from('ignored'));
    expect(overflow.kill).toHaveBeenCalledWith('SIGKILL');
    overflow.emit('close', 0);
    await expect(overflowResult).resolves.toBe('indeterminate');

    const stdinFailure = new FakeClipboardProcess();
    const stdinResult = runClipboardCommand(
      '/trusted/provider',
      [],
      'TOKEN',
      fakeSpawner(stdinFailure),
    );
    stdinFailure.emit('spawn');
    stdinFailure.stdin.emit('error', new Error('write failed'));
    stdinFailure.stdin.emit('error', new Error('already terminating'));
    expect(stdinFailure.kill).toHaveBeenCalledWith('SIGKILL');
    stdinFailure.emit('close', 1);
    await expect(stdinResult).resolves.toBe('indeterminate');
  });

  it('uses the real bounded spawn path for a missing absolute executable', async () => {
    const missing =
      process.platform === 'win32'
        ? String.raw`Z:\__konclave_missing_clipboard_provider__.exe`
        : '/__konclave_missing_clipboard_provider__';
    await expect(runClipboardCommand(missing, [], '')).resolves.toBe('unavailable');
  });
});
