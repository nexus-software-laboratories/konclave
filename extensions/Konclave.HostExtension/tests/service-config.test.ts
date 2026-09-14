import { chmodSync, constants, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, posix } from 'node:path';
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
    userPresenceHelper: join(tmpdir(), 'konclave'),
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

function mappedFiles(
  entries: ReadonlyMap<
    string,
    {
      readonly contents: string | Buffer;
      readonly mode?: number;
      readonly uid?: number;
      readonly file?: boolean;
    }
  >,
): SecureFileOperations & { readonly opened: string[]; readonly closed: number[] } {
  const opened: string[] = [];
  const closed: number[] = [];
  const descriptors = new Map<
    number,
    {
      readonly bytes: Buffer;
      readonly mode: number;
      readonly uid: number;
      readonly file: boolean;
      position: number;
    }
  >();
  let nextDescriptor = 10;
  return {
    noFollowFlag: 0x20_000,
    currentUid: () => 1_000,
    open(path) {
      opened.push(path);
      const entry = entries.get(path);
      if (entry === undefined) {
        throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      }
      const descriptor = nextDescriptor;
      nextDescriptor += 1;
      descriptors.set(descriptor, {
        bytes: typeof entry.contents === 'string' ? Buffer.from(entry.contents) : entry.contents,
        mode: entry.mode ?? 0o100600,
        uid: entry.uid ?? 1_000,
        file: entry.file ?? true,
        position: 0,
      });
      return descriptor;
    },
    stat(descriptor) {
      const entry = descriptors.get(descriptor);
      if (entry === undefined) {
        throw new Error('unknown descriptor');
      }
      return {
        uid: entry.uid,
        mode: entry.mode,
        size: entry.bytes.length,
        isFile: () => entry.file,
      };
    },
    read(descriptor, buffer, offset, length) {
      const entry = descriptors.get(descriptor);
      if (entry === undefined) {
        throw new Error('unknown descriptor');
      }
      const count = Math.min(length, entry.bytes.length - entry.position);
      if (count <= 0) {
        return 0;
      }
      entry.bytes.copy(buffer, offset, entry.position, entry.position + count);
      entry.position += count;
      return count;
    },
    close(descriptor) {
      closed.push(descriptor);
    },
    opened,
    closed,
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
      userPresenceHelper: join(tmpdir(), 'konclave'),
    });
    expect(config.issuerKeyId).toEqual(Buffer.alloc(16));
    expect(config.serviceKey).toEqual(Buffer.alloc(32, 0x11));
    expect(files.closed).toEqual([7]);
  });

  it('prefers canonical platform data and accepts an equivalent legacy encoding', () => {
    const moduleDir = '/plugin/cache';
    const canonical = '/var/lib/user/konclave/service/konclave.service.json';
    const legacy = posix.join(moduleDir, 'konclave.service.json');
    const record = {
      ...serviceConfigRecord('/var/lib/user/konclave/service/account-issuer.key'),
      authorizationPolicy: {
        version: 1,
        acceptedEvidence: [['account_trusted'], ['user_presence', 'account_trusted']],
      },
    };
    const legacyRecord = {
      ...record,
      authorizationPolicy: {
        version: 1,
        acceptedEvidence: [['account_trusted', 'user_presence'], ['account_trusted']],
      },
    };
    const files = mappedFiles(
      new Map([
        [canonical, { contents: JSON.stringify(record) }],
        [legacy, { contents: JSON.stringify(legacyRecord, null, 2) }],
      ]),
    );

    resolveLocalServiceConfig(
      { XDG_DATA_HOME: '/var/lib/user', HOME: '/home/example' },
      moduleDir,
      'linux',
      files,
    );

    expect(files.opened).toEqual([canonical, legacy]);
    expect(files.closed).toEqual([10, 11]);
  });

  it.each([
    {
      platform: 'win32' as const,
      environment: { LOCALAPPDATA: 'C:\\Users\\example\\AppData\\Local' },
      moduleDir: 'C:\\plugin\\cache',
      expected: 'C:\\Users\\example\\AppData\\Local\\Konclave\\service\\konclave.service.json',
    },
    {
      platform: 'darwin' as const,
      environment: { HOME: '/Users/example' },
      moduleDir: '/plugin/cache',
      expected: '/Users/example/Library/Application Support/Konclave/service/konclave.service.json',
    },
    {
      platform: 'linux' as const,
      environment: { XDG_DATA_HOME: '/srv/example', HOME: '/home/example' },
      moduleDir: '/plugin/cache',
      expected: '/srv/example/konclave/service/konclave.service.json',
    },
    {
      platform: 'linux' as const,
      environment: { HOME: '/home/example' },
      moduleDir: '/plugin/cache',
      expected: '/home/example/.local/share/konclave/service/konclave.service.json',
    },
  ])(
    'resolves the canonical $platform client configuration path',
    ({ platform, environment, moduleDir, expected }) => {
      const record = serviceConfigRecord(
        platform === 'win32' ? 'C:\\owner\\account-issuer.key' : '/owner/account-issuer.key',
      );
      if (platform === 'win32') {
        record.userPresenceHelper = 'C:\\owner\\konclave.exe';
      }
      const files = mappedFiles(new Map([[expected, { contents: JSON.stringify(record) }]]));

      resolveLocalServiceConfig(environment, moduleDir, platform, files);

      expect(files.opened[0]).toBe(expected);
    },
  );

  it('falls back to one valid legacy sidecar only when canonical state is absent', () => {
    const moduleDir = '/plugin/cache';
    const canonical = '/home/example/.local/share/konclave/service/konclave.service.json';
    const legacy = posix.join(moduleDir, 'konclave.service.json');
    const files = mappedFiles(
      new Map([
        [
          legacy,
          {
            contents: serviceConfig(
              '/home/example/.local/share/konclave/service/account-issuer.key',
            ),
          },
        ],
      ]),
    );

    resolveLocalServiceConfig({ HOME: '/home/example' }, moduleDir, 'linux', files);

    expect(files.opened).toEqual([canonical, legacy]);
    expect(files.closed).toEqual([10]);
  });

  it('accepts a legacy sidecar that only omits the newer UserPresence helper', () => {
    const moduleDir = '/plugin/cache';
    const canonical = '/home/example/.local/share/konclave/service/konclave.service.json';
    const legacy = posix.join(moduleDir, 'konclave.service.json');
    const record = serviceConfigRecord(
      '/home/example/.local/share/konclave/service/account-issuer.key',
    );
    const oldRecord = { ...record };
    delete oldRecord.userPresenceHelper;
    const files = mappedFiles(
      new Map([
        [canonical, { contents: JSON.stringify(record) }],
        [legacy, { contents: JSON.stringify(oldRecord) }],
      ]),
    );

    const config = resolveLocalServiceConfig({ HOME: '/home/example' }, moduleDir, 'linux', files);

    expect(config.userPresenceHelper).toBe(record.userPresenceHelper);
  });

  it('rejects conflicting or unsafe canonical state without trusting legacy fallback', () => {
    const moduleDir = '/plugin/cache';
    const canonical = '/home/example/.local/share/konclave/service/konclave.service.json';
    const legacy = posix.join(moduleDir, 'konclave.service.json');
    const record = serviceConfigRecord(
      '/home/example/.local/share/konclave/service/account-issuer.key',
    );
    const conflicting = mappedFiles(
      new Map([
        [canonical, { contents: JSON.stringify(record) }],
        [legacy, { contents: JSON.stringify({ ...record, endpoint: '/tmp/other.sock' }) }],
      ]),
    );
    expect(() =>
      resolveLocalServiceConfig({ HOME: '/home/example' }, moduleDir, 'linux', conflicting),
    ).toThrow('conflicts with the legacy extension sidecar');

    const unsafe = mappedFiles(
      new Map([
        [canonical, { contents: JSON.stringify(record), mode: 0o100640 }],
        [legacy, { contents: JSON.stringify(record) }],
      ]),
    );
    expect(() =>
      resolveLocalServiceConfig({ HOME: '/home/example' }, moduleDir, 'linux', unsafe),
    ).toThrow('service configuration is invalid');
    expect(unsafe.opened).toEqual([canonical]);
  });

  it('rejects missing, relative, oversized, or unsupported platform locations', () => {
    const contents = serviceConfig('/owner/account-issuer.key');
    for (const [environment, platform, moduleDir] of [
      [{}, 'linux', '/plugin/cache'],
      [{ HOME: 'relative' }, 'linux', '/plugin/cache'],
      [{ XDG_DATA_HOME: 'relative', HOME: '/home/example' }, 'linux', '/plugin/cache'],
      [{ LOCALAPPDATA: 'relative' }, 'win32', 'C:\\plugin\\cache'],
      [{ HOME: '/home/example' }, 'freebsd', '/plugin/cache'],
      [{ HOME: '/home/example' }, 'linux', 'relative'],
      [{ HOME: `/${'a'.repeat(4097)}` }, 'linux', '/plugin/cache'],
    ] as const) {
      expect(() =>
        resolveLocalServiceConfig(environment, moduleDir, platform, fakeFiles(contents)),
      ).toThrow(ServiceConfigurationError);
    }
  });

  it('accepts an older AccountTrusted sidecar without a native helper', () => {
    const record = serviceConfigRecord(join(tmpdir(), 'account-issuer.key'));
    delete record.userPresenceHelper;
    const config = resolveLocalServiceConfig(
      { KONCLAVE_SERVICE_CONFIG_FILE: join(tmpdir(), 'service.json') },
      tmpdir(),
      'linux',
      fakeFiles(JSON.stringify(record)),
    );

    expect(config.userPresenceHelper).toBeUndefined();
    expect(config.authorizationPolicy.acceptedEvidence).toEqual([['account_trusted']]);
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
      { ...valid, userPresenceHelper: null },
      { ...valid, userPresenceHelper: '' },
      { ...valid, userPresenceHelper: 'relative-helper' },
      { ...valid, issuerKeyId: 'zz' },
      { ...valid, serviceKey: '00' },
      { ...valid, authorizationPolicy: null },
      { ...valid, authorizationPolicy: { version: 1, acceptedEvidence: [] } },
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

    const strongerOnly = resolveLocalServiceConfig(
      { KONCLAVE_SERVICE_CONFIG_FILE: join(tmpdir(), 'service.json') },
      tmpdir(),
      'linux',
      fakeFiles(
        JSON.stringify({
          ...valid,
          authorizationPolicy: { version: 1, acceptedEvidence: [['harness_attested']] },
        }),
      ),
    );
    expect(strongerOnly.authorizationPolicy.acceptedEvidence).toEqual([['harness_attested']]);
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
