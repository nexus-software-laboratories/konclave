import { chmodSync, constants, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import {
  nodeFileOperations,
  readAdapterSigningSeed,
  resolveLocalServiceConfig,
  ServiceConfigurationError,
  type SecureFileOperations,
} from '../src/service/config.js';

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'konclave-service-config-'));
  temporaryDirectories.push(directory);
  return directory;
}

function writeOwnerOnly(path: string, contents: string | Buffer): void {
  writeFileSync(path, contents, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function serviceConfigRecord(signingKeyFile: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    endpoint: join(tmpdir(), 'konclave.sock'),
    adapterKeyId: '00'.repeat(16),
    adapterKeyVersion: 1,
    harness: 'copilot',
    serviceKey: '11'.repeat(32),
    signingKeyFile,
  };
}

function serviceConfig(signingKeyFile: string): string {
  return JSON.stringify(serviceConfigRecord(signingKeyFile));
}

function fakeFiles(
  contents: Buffer | string,
  overrides: {
    readonly uid?: number;
    readonly mode?: number;
    readonly size?: number;
    readonly file?: boolean;
    readonly currentUid?: number;
    readonly noFollowFlag?: number;
    readonly openError?: Error;
  } = {},
): SecureFileOperations & {
  readonly buffers: Buffer[];
  readonly closed: number[];
  readonly opened: string[];
} {
  const bytes = typeof contents === 'string' ? Buffer.from(contents) : contents;
  const buffers: Buffer[] = [];
  const closed: number[] = [];
  const opened: string[] = [];
  let position = 0;
  return {
    noFollowFlag: overrides.noFollowFlag ?? 0x20_000,
    currentUid: () => overrides.currentUid ?? 1_000,
    open(path) {
      opened.push(path);
      if (overrides.openError) {
        throw overrides.openError;
      }
      return 7;
    },
    stat: () => ({
      uid: overrides.uid ?? 1_000,
      mode: overrides.mode ?? 0o100600,
      size: overrides.size ?? bytes.length,
      isFile: () => overrides.file ?? true,
    }),
    read(_descriptor, buffer, offset, length) {
      if (!buffers.includes(buffer)) {
        buffers.push(buffer);
      }
      const count = Math.min(length, bytes.length - position);
      if (count <= 0) {
        return 0;
      }
      bytes.copy(buffer, offset, position, position + count);
      position += count;
      return count;
    },
    close: (descriptor) => closed.push(descriptor),
    buffers,
    closed,
    opened,
  };
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

describe('installed service custody', () => {
  it('reads the installer-protected Windows record through one bounded descriptor', () => {
    const directory = tmpdir();
    const signingKeyFile = join(directory, 'adapter.key');
    const files = fakeFiles(serviceConfig(signingKeyFile), {
      currentUid: Number.NaN,
      noFollowFlag: 0,
    });
    expect(
      resolveLocalServiceConfig(
        { KONCLAVE_SERVICE_CONFIG_FILE: join(directory, 'service.json') },
        directory,
        'win32',
        files,
      ),
    ).toMatchObject({ signingKeyFile });
    expect(files.closed).toEqual([7]);
  });

  it('parses a valid bounded config through the verified descriptor', () => {
    const directory = tmpdir();
    const signingKeyFile = join(directory, 'adapter.key');
    const files = fakeFiles(serviceConfig(signingKeyFile));
    const config = resolveLocalServiceConfig(
      { KONCLAVE_SERVICE_CONFIG_FILE: `  ${join(directory, 'service.json')}  ` },
      directory,
      'linux',
      files,
    );

    expect(config).toMatchObject({
      adapterKeyVersion: 1,
      endpoint: join(tmpdir(), 'konclave.sock'),
      harness: 'copilot',
      signingKeyFile,
    });
    expect(config.adapterKeyId).toEqual(Buffer.alloc(16));
    expect(config.serviceKey).toEqual(Buffer.alloc(32, 0x11));
    expect(files.closed).toEqual([7]);
  });

  it('uses the installed sidecar when no override is present', () => {
    const files = fakeFiles(serviceConfig(join(tmpdir(), 'adapter.key')));
    resolveLocalServiceConfig({}, tmpdir(), 'linux', files);
    expect(files.opened).toEqual([join(tmpdir(), 'konclave.service.json')]);
  });

  it('rejects unverifiable, missing, unsafe, empty, and oversized files', () => {
    const path = join(tmpdir(), 'service.json');
    const missing = Object.assign(new Error('missing'), { code: 'ENOENT' });
    const cases: SecureFileOperations[] = [
      fakeFiles('{}', { currentUid: Number.NaN }),
      { ...fakeFiles('{}'), currentUid: () => undefined },
      { ...fakeFiles('{}'), noFollowFlag: undefined },
      fakeFiles('{}', { openError: missing }),
      fakeFiles('{}', { openError: new Error('denied') }),
      fakeFiles('{}', { file: false }),
      fakeFiles('{}', { uid: 1_001 }),
      fakeFiles('{}', { mode: 0o100640 }),
      fakeFiles('{}', { size: 0 }),
      fakeFiles('{}', { size: 4_097 }),
      fakeFiles(Buffer.alloc(4_097), { size: 1 }),
    ];

    for (const files of cases) {
      expect(() =>
        resolveLocalServiceConfig({ KONCLAVE_SERVICE_CONFIG_FILE: path }, tmpdir(), 'linux', files),
      ).toThrow(ServiceConfigurationError);
    }
  });

  it('rejects malformed or unsafe configuration fields', () => {
    const signingKeyFile = join(tmpdir(), 'adapter.key');
    const valid = serviceConfigRecord(signingKeyFile);
    const invalid: unknown[] = [
      '{',
      [],
      { ...valid, schemaVersion: 2 },
      { ...valid, endpoint: '' },
      { ...valid, endpoint: 'a'.repeat(201) },
      { ...valid, endpoint: 'https://localhost/socket' },
      { ...valid, endpoint: 'localhost:1234' },
      { ...valid, harness: 'other' },
      { ...valid, adapterKeyVersion: 0 },
      { ...valid, adapterKeyVersion: 1.5 },
      { ...valid, signingKeyFile: 'relative.key' },
      { ...valid, adapterKeyId: 'zz' },
      { ...valid, serviceKey: '00' },
    ];

    for (const value of invalid) {
      const contents = typeof value === 'string' ? value : JSON.stringify(value);
      expect(() =>
        resolveLocalServiceConfig(
          { KONCLAVE_SERVICE_CONFIG_FILE: join(tmpdir(), 'service.json') },
          tmpdir(),
          'linux',
          fakeFiles(contents),
        ),
      ).toThrow(ServiceConfigurationError);
    }
  });

  it('reads only the exact raw seed format installed by Konclave', () => {
    const raw = Buffer.alloc(32, 3);
    expect(readAdapterSigningSeed('/adapter.key', 'linux', fakeFiles(raw))).toEqual(raw);

    for (const invalid of [Buffer.alloc(31), Buffer.alloc(33), Buffer.from('04'.repeat(32))]) {
      expect(() => readAdapterSigningSeed('/adapter.key', 'linux', fakeFiles(invalid))).toThrow(
        'adapter key is invalid',
      );
    }
  });

  it('uses the Node descriptor adapter without path-based follow-up reads', () => {
    const directory = temporaryDirectory();
    const path = join(directory, 'bounded.txt');
    writeOwnerOnly(path, 'bounded');
    const descriptor = nodeFileOperations.open(path, constants.O_RDONLY);
    try {
      expect(nodeFileOperations.stat(descriptor).isFile()).toBe(true);
      const buffer = Buffer.alloc(7);
      expect(nodeFileOperations.read(descriptor, buffer, 0, buffer.length)).toBe(7);
      expect(buffer.toString('utf8')).toBe('bounded');
      expect(nodeFileOperations.currentUid()).toBe(
        typeof process.getuid === 'function' ? process.getuid() : undefined,
      );
    } finally {
      nodeFileOperations.close(descriptor);
    }
  });

  it.runIf(process.platform !== 'win32')(
    'reads owner-only regular files through the opened descriptor',
    () => {
      const directory = temporaryDirectory();
      const signingKeyFile = join(directory, 'adapter.key');
      const configFile = join(directory, 'service.json');
      writeOwnerOnly(signingKeyFile, Buffer.alloc(32, 7));
      writeOwnerOnly(configFile, serviceConfig(signingKeyFile));

      const config = resolveLocalServiceConfig(
        { KONCLAVE_SERVICE_CONFIG_FILE: configFile },
        directory,
      );
      expect(config.adapterKeyId).toEqual(Buffer.alloc(16));
      expect(readAdapterSigningSeed(signingKeyFile)).toEqual(Buffer.alloc(32, 7));
    },
  );

  it.runIf(process.platform !== 'win32')(
    'rejects group-readable files and symbolic-link substitution',
    () => {
      const directory = temporaryDirectory();
      const signingKeyFile = join(directory, 'adapter.key');
      const configFile = join(directory, 'service.json');
      const linkedConfig = join(directory, 'linked-service.json');
      writeOwnerOnly(signingKeyFile, Buffer.alloc(32, 7));
      writeOwnerOnly(configFile, serviceConfig(signingKeyFile));

      chmodSync(configFile, 0o640);
      expect(() =>
        resolveLocalServiceConfig({ KONCLAVE_SERVICE_CONFIG_FILE: configFile }, directory),
      ).toThrow(ServiceConfigurationError);

      chmodSync(configFile, 0o600);
      symlinkSync(configFile, linkedConfig);
      expect(() =>
        resolveLocalServiceConfig({ KONCLAVE_SERVICE_CONFIG_FILE: linkedConfig }, directory),
      ).toThrow(ServiceConfigurationError);
    },
  );
});
