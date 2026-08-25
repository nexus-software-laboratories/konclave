import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import { resolveInstalledProfileRoot } from '../src/runtime-config.js';

const roots: string[] = [];

function createRoot(): string {
  const root = mkdtempSync(join(process.cwd(), 'runtime-config-'));
  roots.push(root);
  return root;
}

afterEach(() => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root) {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

describe('resolveInstalledProfileRoot', () => {
  it('prefers and trims the environment override', () => {
    const root = createRoot();
    writeFileSync(
      join(root, 'konclave.runtime.json'),
      JSON.stringify({ schemaVersion: 1, profileRoot: '/sidecar/profiles' }),
    );

    expect(
      resolveInstalledProfileRoot({ KONCLAVE_PROFILE_ROOT: ' /override/profiles ' }, root),
    ).toBe('/override/profiles');
  });

  it('loads an absolute profile root from the bounded sidecar', () => {
    const root = createRoot();
    const profileRoot = join(root, 'profiles');
    writeFileSync(
      join(root, 'konclave.runtime.json'),
      JSON.stringify({ schemaVersion: 1, profileRoot }),
    );

    expect(resolveInstalledProfileRoot({}, root)).toBe(profileRoot);
  });

  it('returns undefined when no sidecar or override exists', () => {
    expect(resolveInstalledProfileRoot({}, createRoot())).toBeUndefined();
  });

  it.each([
    '{}',
    '{"schemaVersion":2,"profileRoot":"/profiles"}',
    '{"schemaVersion":1,"profileRoot":""}',
    '{"schemaVersion":1,"profileRoot":"relative/profiles"}',
  ])('rejects malformed sidecar content: %s', (content) => {
    const root = createRoot();
    writeFileSync(join(root, 'konclave.runtime.json'), content);

    expect(() => resolveInstalledProfileRoot({}, root)).toThrow();
  });

  it('rejects oversized sidecars', () => {
    const oversizedRoot = createRoot();
    writeFileSync(join(oversizedRoot, 'konclave.runtime.json'), 'x'.repeat(4097));
    expect(() => resolveInstalledProfileRoot({}, oversizedRoot)).toThrow();
  });

  it.runIf(process.platform !== 'win32')('rejects linked sidecars', () => {
    const linkedRoot = createRoot();
    const target = join(linkedRoot, 'target.json');
    writeFileSync(target, JSON.stringify({ schemaVersion: 1, profileRoot: '/profiles' }));
    symlinkSync(target, join(linkedRoot, 'konclave.runtime.json'), 'file');
    expect(() => resolveInstalledProfileRoot({}, linkedRoot)).toThrow();
  });
});
