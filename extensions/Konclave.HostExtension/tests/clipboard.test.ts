import { describe, expect, it, vi } from 'vitest';

import { createPairingClipboard } from '../src/service/clipboard.js';

const token = '000G40R40M30E209185GR38E1W';

describe('pairing clipboard', () => {
  it('writes Windows clipboard content through stdin with a hidden fixed command', async () => {
    const run = vi.fn().mockResolvedValue('success');
    const clipboard = createPairingClipboard('win32', {}, run);

    await expect(clipboard.writeToken(token)).resolves.toEqual({
      copied: true,
      providers: ['windows'],
    });
    expect(run).toHaveBeenCalledWith(String.raw`C:\Windows\System32\clip.exe`, [], token);
    expect(run.mock.calls[0]?.[1].join(' ')).not.toContain(token);
    await expect(clipboard.clear({ copied: true, providers: ['windows'] })).resolves.toBe(true);
    expect(run.mock.calls[1]?.[2]).toBe('');
  });

  it('falls back between bounded Linux clipboard providers', async () => {
    const run = vi
      .fn()
      .mockResolvedValueOnce('indeterminate')
      .mockResolvedValueOnce('success')
      .mockResolvedValueOnce('success')
      .mockResolvedValueOnce('success');
    const clipboard = createPairingClipboard(
      'linux',
      { WAYLAND_DISPLAY: 'wayland-0', DISPLAY: ':0' },
      run,
    );

    await expect(clipboard.writeToken(token)).resolves.toEqual({
      copied: true,
      providers: ['wayland', 'x11'],
    });
    expect(run.mock.calls.slice(0, 2).map(([file]) => file)).toEqual([
      '/usr/bin/wl-copy',
      '/usr/bin/xclip',
    ]);
    await expect(clipboard.clear({ copied: true, providers: ['wayland', 'x11'] })).resolves.toBe(
      true,
    );
    expect(run.mock.calls.slice(2).map(([file, args]) => [file, args])).toEqual([
      ['/usr/bin/wl-copy', ['--clear']],
      ['/usr/bin/xclip', ['-selection', 'clipboard', '-in']],
    ]);
  });

  it('reports unsupported headless environments without invoking a process', async () => {
    const run = vi.fn().mockResolvedValue('success');
    const clipboard = createPairingClipboard('linux', {}, run);

    await expect(clipboard.writeToken(token)).resolves.toEqual({
      copied: false,
      providers: [],
    });
    await expect(clipboard.clear({ copied: false, providers: [] })).resolves.toBe(false);
    expect(run).not.toHaveBeenCalled();
  });

  it('retains clear eligibility after an indeterminate provider failure', async () => {
    const clipboard = createPairingClipboard(
      'darwin',
      {},
      vi.fn().mockResolvedValue('indeterminate'),
    );

    await expect(clipboard.writeToken(token)).resolves.toEqual({
      copied: false,
      providers: ['macos'],
    });
  });
});
