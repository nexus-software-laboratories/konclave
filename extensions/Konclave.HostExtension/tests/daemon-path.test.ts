import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  checkRegularFile,
  pluginRootFromModuleDir,
  resolveBundledDaemonPath,
  resolveDaemonCommand,
  resolveUserExtensionDaemonPath,
} from '../src/daemon-path.js';

const linuxModuleDir = join(
  'cache',
  'plugins',
  'konclave-abc123',
  'extensions',
  'Konclave.Extension',
);

describe('resolveDaemonCommand', () => {
  it('prefers an explicit non-empty KONCLAVE_DAEMON_PATH override over everything else', () => {
    const isRegularFile = vi.fn().mockReturnValue(true);

    const command = resolveDaemonCommand(
      { KONCLAVE_DAEMON_PATH: '/opt/custom/KonclaveLocalDaemon' },
      'linux',
      linuxModuleDir,
      isRegularFile,
    );

    expect(command).toBe('/opt/custom/KonclaveLocalDaemon');
    expect(isRegularFile).not.toHaveBeenCalled();
  });

  it('trims the override and treats a whitespace-only value as absent', () => {
    const isRegularFile = vi.fn().mockReturnValue(false);

    const trimmed = resolveDaemonCommand(
      { KONCLAVE_DAEMON_PATH: '  /opt/custom/KonclaveLocalDaemon  ' },
      'linux',
      linuxModuleDir,
      isRegularFile,
    );
    const blank = resolveDaemonCommand(
      { KONCLAVE_DAEMON_PATH: '   ' },
      'linux',
      linuxModuleDir,
      isRegularFile,
    );

    expect(trimmed).toBe('/opt/custom/KonclaveLocalDaemon');
    expect(blank).toBe('KonclaveLocalDaemon');
  });

  it('selects a daemon bundled beside a user-scoped extension first', () => {
    const isRegularFile = vi.fn().mockReturnValue(true);

    const command = resolveDaemonCommand({}, 'linux', linuxModuleDir, isRegularFile);

    expect(command).toBe(resolveUserExtensionDaemonPath(linuxModuleDir, 'linux'));
    expect(isRegularFile).toHaveBeenCalledWith(
      resolveUserExtensionDaemonPath(linuxModuleDir, 'linux'),
    );
  });

  it('selects the plugin-bundled daemon when no user-extension daemon exists', () => {
    const isRegularFile = vi.fn(
      (path: string) => path === resolveBundledDaemonPath(linuxModuleDir, 'linux'),
    );

    const command = resolveDaemonCommand({}, 'linux', linuxModuleDir, isRegularFile);

    expect(command).toBe(resolveBundledDaemonPath(linuxModuleDir, 'linux'));
  });

  it('falls back to the system PATH binary name when the bundled path is not a regular file', () => {
    const isRegularFile = vi.fn().mockReturnValue(false);

    const linux = resolveDaemonCommand({}, 'linux', linuxModuleDir, isRegularFile);
    const windows = resolveDaemonCommand({}, 'win32', linuxModuleDir, isRegularFile);

    expect(linux).toBe('KonclaveLocalDaemon');
    expect(windows).toBe('KonclaveLocalDaemon.exe');
  });

  it('only probes the two fixed package layouts', () => {
    const isRegularFile = vi.fn().mockReturnValue(false);

    resolveDaemonCommand({}, 'linux', linuxModuleDir, isRegularFile);

    expect(isRegularFile).toHaveBeenCalledTimes(2);
    expect(isRegularFile.mock.calls.map(([path]) => path)).toEqual([
      join(linuxModuleDir, 'bin', 'KonclaveLocalDaemon'),
      join('cache', 'plugins', 'konclave-abc123', 'bin', 'KonclaveLocalDaemon'),
    ]);
  });
});

describe('resolveBundledDaemonPath', () => {
  it('resolves the plugin root relative to the module directory, ignoring process.cwd()', () => {
    // The module directory here shares nothing with the real working directory
    // that vitest executes from, proving resolution is a pure function of the
    // module's own on-disk location rather than of process.cwd().
    expect(linuxModuleDir.startsWith(process.cwd())).toBe(false);

    const path = resolveBundledDaemonPath(linuxModuleDir, 'linux');

    expect(path).toBe(join('cache', 'plugins', 'konclave-abc123', 'bin', 'KonclaveLocalDaemon'));
  });

  describe('resolveUserExtensionDaemonPath', () => {
    it('resolves a daemon directly beside a user-scoped extension', () => {
      const moduleDir = join('home', 'tester', '.copilot', 'extensions', 'konclave');

      expect(resolveUserExtensionDaemonPath(moduleDir, 'win32')).toBe(
        join(moduleDir, 'bin', 'KonclaveLocalDaemon.exe'),
      );
    });
  });

  it('produces the Windows binary name under a Windows-shaped cached plugin path', () => {
    const windowsModuleDir = join(
      'C:',
      'Users',
      'tester',
      'AppData',
      'copilot-cli',
      'plugins',
      'konclave-abc123',
      'extensions',
      'Konclave.Extension',
    );

    const path = resolveBundledDaemonPath(windowsModuleDir, 'win32');

    expect(path).toBe(
      join(
        'C:',
        'Users',
        'tester',
        'AppData',
        'copilot-cli',
        'plugins',
        'konclave-abc123',
        'bin',
        'KonclaveLocalDaemon.exe',
      ),
    );
  });

  it('produces the Unix binary name under a Unix-shaped cached plugin path', () => {
    const unixModuleDir = join(
      '/',
      'home',
      'tester',
      '.copilot',
      'plugins',
      'konclave-abc123',
      'extensions',
      'Konclave.Extension',
    );

    const path = resolveBundledDaemonPath(unixModuleDir, 'linux');

    expect(path).toBe(
      join(
        '/',
        'home',
        'tester',
        '.copilot',
        'plugins',
        'konclave-abc123',
        'bin',
        'KonclaveLocalDaemon',
      ),
    );
  });
});

describe('pluginRootFromModuleDir', () => {
  it('climbs exactly two directories from the compiled extension module', () => {
    expect(pluginRootFromModuleDir(linuxModuleDir)).toBe(
      join('cache', 'plugins', 'konclave-abc123'),
    );
  });
});

describe('resolveDaemonCommand cache-relative integration', () => {
  const thisDir = dirname(fileURLToPath(import.meta.url));
  const fixtureRoots: string[] = [];

  afterEach(() => {
    while (fixtureRoots.length > 0) {
      const root = fixtureRoots.pop();
      if (root) {
        rmSync(root, { recursive: true, force: true });
      }
    }
  });

  function createFixturePluginRoot(): string {
    const root = mkdtempSync(join(thisDir, 'fixture-plugin-'));
    fixtureRoots.push(root);
    mkdirSync(join(root, 'extensions', 'Konclave.Extension'), { recursive: true });
    return root;
  }

  it('selects a real bundled daemon file on disk over the PATH fallback', () => {
    const pluginRoot = createFixturePluginRoot();
    const moduleDir = join(pluginRoot, 'extensions', 'Konclave.Extension');
    const binDir = join(pluginRoot, 'bin');
    mkdirSync(binDir, { recursive: true });
    const bundledDaemonPath = join(binDir, 'KonclaveLocalDaemon');
    writeFileSync(bundledDaemonPath, '');

    const command = resolveDaemonCommand({}, 'linux', moduleDir);

    expect(command).toBe(bundledDaemonPath);
  });

  it('selects a real user-extension daemon file on disk', () => {
    const root = mkdtempSync(join(thisDir, 'fixture-user-extension-'));
    fixtureRoots.push(root);
    const binDir = join(root, 'bin');
    mkdirSync(binDir, { recursive: true });
    const bundledDaemonPath = join(binDir, 'KonclaveLocalDaemon');
    writeFileSync(bundledDaemonPath, '');

    const command = resolveDaemonCommand({}, 'linux', root);

    expect(command).toBe(bundledDaemonPath);
  });

  it('falls back to the PATH binary name when the plugin cache has no bundled daemon', () => {
    const pluginRoot = createFixturePluginRoot();
    const moduleDir = join(pluginRoot, 'extensions', 'Konclave.Extension');

    const command = resolveDaemonCommand({}, 'linux', moduleDir);

    expect(command).toBe('KonclaveLocalDaemon');
  });

  it('still honors the override even when a bundled daemon file is present', () => {
    const pluginRoot = createFixturePluginRoot();
    const moduleDir = join(pluginRoot, 'extensions', 'Konclave.Extension');
    const binDir = join(pluginRoot, 'bin');
    mkdirSync(binDir, { recursive: true });
    writeFileSync(join(binDir, 'KonclaveLocalDaemon'), '');

    const command = resolveDaemonCommand(
      { KONCLAVE_DAEMON_PATH: '/opt/custom/KonclaveLocalDaemon' },
      'linux',
      moduleDir,
    );

    expect(command).toBe('/opt/custom/KonclaveLocalDaemon');
  });
});

describe('checkRegularFile', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const thisDir = dirname(thisFile);

  it('returns false for a path that does not exist instead of throwing', () => {
    expect(checkRegularFile(join(thisDir, 'does-not-exist-KonclaveLocalDaemon'))).toBe(false);
  });

  it('returns true for a real regular file on disk', () => {
    expect(checkRegularFile(thisFile)).toBe(true);
  });

  it('returns false for a directory', () => {
    expect(checkRegularFile(thisDir)).toBe(false);
  });

  it.runIf(process.platform !== 'win32')('returns false for a symbolic link', () => {
    const root = mkdtempSync(join(thisDir, 'fixture-link-'));
    try {
      const link = join(root, 'KonclaveLocalDaemon');
      symlinkSync(thisFile, link);
      expect(checkRegularFile(link)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
