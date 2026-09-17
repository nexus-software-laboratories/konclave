import { describe, expect, it, vi } from 'vitest';

import { createPairingClipboard } from '../src/service/clipboard.js';

const token = '000G40R40M30E209185GR38E1W';

describe('pairing clipboard', () => {
  it('writes Windows clipboard content through stdin with a hidden fixed command', async () => {
    const run = vi.fn().mockResolvedValue(true);
    const clipboard = createPairingClipboard('win32', {}, run);

    await expect(clipboard.writeToken(token)).resolves.toBe(true);
    expect(run).toHaveBeenCalledWith(
      'powershell.exe',
      expect.arrayContaining(['-NoProfile', '-NonInteractive']),
      token,
    );
    expect(run.mock.calls[0]?.[1].join(' ')).not.toContain(token);
    await expect(clipboard.clear()).resolves.toBe(true);
    expect(run.mock.calls[1]?.[2]).toBe('');
  });

  it('falls back between bounded Linux clipboard providers', async () => {
    const run = vi
      .fn()
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true);
    const clipboard = createPairingClipboard(
      'linux',
      { WAYLAND_DISPLAY: 'wayland-0', DISPLAY: ':0' },
      run,
    );

    await expect(clipboard.writeToken(token)).resolves.toBe(true);
    expect(run.mock.calls.slice(0, 2).map(([file]) => file)).toEqual(['wl-copy', 'xclip']);
    await expect(clipboard.clear()).resolves.toBe(true);
    expect(run.mock.calls[2]?.slice(0, 2)).toEqual(['wl-copy', ['--clear']]);
  });

  it('reports unsupported headless environments without invoking a process', async () => {
    const run = vi.fn().mockResolvedValue(true);
    const clipboard = createPairingClipboard('linux', {}, run);

    await expect(clipboard.writeToken(token)).resolves.toBe(false);
    await expect(clipboard.clear()).resolves.toBe(false);
    expect(run).not.toHaveBeenCalled();
  });
});
