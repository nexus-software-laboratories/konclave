import { chmodSync, constants, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import {
  nodeFileOperations,
  readIssuerSigningSeed,
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

function serviceConfigRecord(issuerKeyFile: string): Record<string, unknown> {
  return {
    schemaVersion: 2,
    endpoint: join(tmpdir(), 'konclave.sock'),
    issuerKeyId: '00'.repeat(16),
    issuerKeyVersion: 1,
    harness: 'copilot',
    serviceKey: '11'.repeat(32),
    issuerKeyFile,
    authorizationPolicy: {
      version: 1,
      acceptedEvidence: [['account_trusted']],
    },
  };
}

function serviceConfig(issuerKeyFile: string): string {
  return JSON.stringify(serviceConfigRecord(issuerKeyFile));
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
    const issuerKeyFile = join(directory, 'account-issuer.key');
    const files = fakeFiles(serviceConfig(issuerKeyFile), {
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
    ).toMatchObject({ issuerKeyFile });
    expect(files.closed).toEqual([7]);
  });

  it('parses a valid bounded config through the verified descriptor', () => {
    const directory = tmpdir();
    const issuerKeyFile = join(directory, 'account-issuer.key');
    const files = fakeFiles(serviceConfig(issuerKeyFile));
    const config = resolveLocalServiceConfig(
      { KONCLAVE_SERVICE_CONFIG_FILE: `  ${join(directory, 'service.json')}  ` },
      directory,
      'linux',
      files,
    );

    expect(config).toMatchObject({
      issuerKeyVersion: 1,
      endpoint: join(tmpdir(), 'konclave.sock'),
      harness: 'copilot',
      issuerKeyFile,
    });
    expect(config.issuerKeyId).toEqual(Buffer.alloc(16));
    expect(config.serviceKey).toEqual(Buffer.alloc(32, 0x11));
    expect(files.closed).toEqual([7]);
  });

  it('uses the installed sidecar when no override is present', () => {
    const files = fakeFiles(serviceConfig(join(tmpdir(), 'account-issuer.key')));
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
    const issuerKeyFile = join(tmpdir(), 'account-issuer.key');
    const valid = serviceConfigRecord(issuerKeyFile);
    const invalid: unknown[] = [
      '{',
      [],
      { ...valid, schemaVersion: 3 },
      { ...valid, endpoint: '' },
      { ...valid, endpoint: 'a'.repeat(201) },
      { ...valid, endpoint: 'https://localhost/socket' },
      { ...valid, endpoint: 'localhost:1234' },
      { ...valid, harness: 'other' },
      { ...valid, issuerKeyVersion: 0 },
      { ...valid, issuerKeyVersion: 1.5 },
      { ...valid, issuerKeyFile: 'relative.key' },
      { ...valid, issuerKeyId: 'zz' },
      { ...valid, serviceKey: '00' },
      { ...valid, authorizationPolicy: null },
      { ...valid, authorizationPolicy: { version: 1, acceptedEvidence: [] } },
      {
        ...valid,
        authorizationPolicy: { version: 1, acceptedEvidence: [['harness_attested']] },
      },
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

    const strongerOnly = {
      ...valid,
      authorizationPolicy: { version: 1, acceptedEvidence: [['harness_attested']] },
    };
    const error = (() => {
      try {
        resolveLocalServiceConfig(
          { KONCLAVE_SERVICE_CONFIG_FILE: join(tmpdir(), 'service.json') },
          tmpdir(),
          'linux',
          fakeFiles(JSON.stringify(strongerOnly)),
        );
      } catch (failure) {
        return failure;
      }
      return undefined;
    })();
    expect(error).toBeInstanceOf(ServiceConfigurationError);
    if (!(error instanceof ServiceConfigurationError)) {
      throw new Error('expected a service configuration error');
    }
    expect(error.code).toBe('required_evidence_unavailable');
  });

  it('reads only the exact raw seed format installed by Konclave', () => {
    const raw = Buffer.alloc(32, 3);
    expect(readIssuerSigningSeed('/account-issuer.key', 'linux', fakeFiles(raw))).toEqual(raw);

    for (const invalid of [Buffer.alloc(31), Buffer.alloc(33), Buffer.from('04'.repeat(32))]) {
      expect(() =>
        readIssuerSigningSeed('/account-issuer.key', 'linux', fakeFiles(invalid)),
      ).toThrow('issuer key is invalid');
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
      const issuerKeyFile = join(directory, 'account-issuer.key');
      const configFile = join(directory, 'service.json');
      writeOwnerOnly(issuerKeyFile, Buffer.alloc(32, 7));
      writeOwnerOnly(configFile, serviceConfig(issuerKeyFile));

      const config = resolveLocalServiceConfig(
        { KONCLAVE_SERVICE_CONFIG_FILE: configFile },
        directory,
      );
      expect(config.issuerKeyId).toEqual(Buffer.alloc(16));
      expect(readIssuerSigningSeed(issuerKeyFile)).toEqual(Buffer.alloc(32, 7));
    },
  );

  it.runIf(process.platform !== 'win32')(
    'rejects group-readable files and symbolic-link substitution',
    () => {
      const directory = temporaryDirectory();
      const issuerKeyFile = join(directory, 'adapter.key');
      const configFile = join(directory, 'service.json');
      const linkedConfig = join(directory, 'linked-service.json');
      writeOwnerOnly(issuerKeyFile, Buffer.alloc(32, 7));
      writeOwnerOnly(configFile, serviceConfig(issuerKeyFile));

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
