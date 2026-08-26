import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

import type { HarnessKind } from './transcript.js';

/**
 * The bounded runtime configuration contract for the shared local service.
 *
 * Installation owns this file: it names the endpoint the service listens on, the
 * adapter registration this extension authenticates with, and the service key this
 * client pins. Nothing here is discovered, guessed, or defaulted, and a missing or
 * malformed record fails visibly. There is no path that starts a daemon instead.
 */

const serviceConfigFileName = 'konclave.service.json';
const maxServiceConfigBytes = 4096;
const maxKeyFileBytes = 32;
const hex32 = /^[0-9a-f]{32}$/;
const hex64 = /^[0-9a-f]{64}$/;

export interface LocalServiceRuntimeConfig {
  /** Owner-protected endpoint the per-user service listens on. */
  readonly endpoint: string;
  /** Registered adapter key identifier. */
  readonly adapterKeyId: Buffer;
  /** Registered adapter key version. */
  readonly adapterKeyVersion: number;
  /** Harness this adapter registration is authorized for. */
  readonly harness: HarnessKind;
  /** Service verification key this client pins. */
  readonly serviceKey: Buffer;
  /** Owner-protected file holding the adapter signing seed. */
  readonly signingKeyFile: string;
}

export class ServiceConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ServiceConfigurationError';
  }
}

interface SecureFileStats {
  readonly uid: number;
  readonly mode: number;
  readonly size: number;
  isFile(): boolean;
}

export interface SecureFileOperations {
  readonly noFollowFlag: number | undefined;
  currentUid(): number | undefined;
  open(path: string, flags: number): number;
  stat(descriptor: number): SecureFileStats;
  read(descriptor: number, buffer: Buffer, offset: number, length: number): number;
  close(descriptor: number): void;
}

export const nodeFileOperations: SecureFileOperations = {
  noFollowFlag: constants.O_NOFOLLOW,
  currentUid: () => (typeof process.getuid === 'function' ? process.getuid() : undefined),
  open: openSync,
  stat: fstatSync,
  read: (descriptor, buffer, offset, length) => readSync(descriptor, buffer, offset, length, null),
  close: closeSync,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

function readBoundedFile(
  path: string,
  maxBytes: number,
  what: string,
  platform: NodeJS.Platform,
  operations: SecureFileOperations,
): Buffer {
  const currentUid = operations.currentUid();
  if (platform !== 'win32' && (currentUid === undefined || operations.noFollowFlag === undefined)) {
    throw new ServiceConfigurationError(`Konclave ${what} ownership cannot be verified.`);
  }

  let descriptor: number;
  try {
    descriptor = operations.open(
      path,
      constants.O_RDONLY | (platform === 'win32' ? 0 : (operations.noFollowFlag ?? 0)),
    );
  } catch (error) {
    if (isMissingFile(error)) {
      throw new ServiceConfigurationError(`Konclave ${what} is not installed.`);
    }
    throw new ServiceConfigurationError(`Konclave ${what} cannot be opened safely.`);
  }

  try {
    const stats = operations.stat(descriptor);
    if (
      !stats.isFile() ||
      (platform !== 'win32' && (stats.uid !== currentUid || (stats.mode & 0o077) !== 0)) ||
      stats.size > maxBytes ||
      stats.size === 0
    ) {
      throw new ServiceConfigurationError(`Konclave ${what} is invalid.`);
    }

    const contents = Buffer.alloc(maxBytes + 1);
    let offset = 0;
    while (offset < contents.length) {
      const read = operations.read(descriptor, contents, offset, contents.length - offset);
      if (read === 0) {
        break;
      }
      offset += read;
    }
    if (offset === 0 || offset > maxBytes) {
      throw new ServiceConfigurationError(`Konclave ${what} is invalid.`);
    }
    return contents.subarray(0, offset);
  } finally {
    operations.close(descriptor);
  }
}

function requireHex(value: unknown, pattern: RegExp, what: string): Buffer {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new ServiceConfigurationError(`Konclave ${what} is invalid.`);
  }
  return Buffer.from(value, 'hex');
}

/**
 * Reads the installed service configuration.
 *
 * The location is the installed sidecar beside this module, or an explicit override
 * used by deterministic tests and local development.
 */
export function resolveLocalServiceConfig(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  platform: NodeJS.Platform = process.platform,
  operations: SecureFileOperations = nodeFileOperations,
): LocalServiceRuntimeConfig {
  const override = environment.KONCLAVE_SERVICE_CONFIG_FILE?.trim();
  const configPath =
    override && override.length > 0 ? override : join(moduleDir, serviceConfigFileName);
  if (!isAbsolute(configPath)) {
    throw new ServiceConfigurationError('Konclave service configuration path must be absolute.');
  }

  const raw = readBoundedFile(
    configPath,
    maxServiceConfigBytes,
    'service configuration',
    platform,
    operations,
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new ServiceConfigurationError('Konclave service configuration is malformed.');
  }
  if (!isRecord(parsed) || parsed.schemaVersion !== 1) {
    throw new ServiceConfigurationError('Konclave service configuration is malformed.');
  }

  const endpoint = typeof parsed.endpoint === 'string' ? parsed.endpoint.trim() : '';
  if (!endpoint || endpoint.length > 200) {
    throw new ServiceConfigurationError('Konclave service endpoint is invalid.');
  }
  // The endpoint is a local pipe or socket path. A host, port, or URL would mean a
  // network listener, which this protocol never uses.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(endpoint) || /:\d+$/.test(endpoint)) {
    throw new ServiceConfigurationError('Konclave service endpoint must be a local path.');
  }

  const harness = parsed.harness;
  if (harness !== 'copilot') {
    throw new ServiceConfigurationError('Konclave service harness is invalid.');
  }

  const adapterKeyVersion = parsed.adapterKeyVersion;
  if (
    typeof adapterKeyVersion !== 'number' ||
    !Number.isInteger(adapterKeyVersion) ||
    adapterKeyVersion < 1
  ) {
    throw new ServiceConfigurationError('Konclave adapter key version is invalid.');
  }

  const signingKeyFile =
    typeof parsed.signingKeyFile === 'string' ? parsed.signingKeyFile.trim() : '';
  if (!signingKeyFile || !isAbsolute(signingKeyFile)) {
    throw new ServiceConfigurationError('Konclave adapter key file must be absolute.');
  }

  return {
    endpoint,
    adapterKeyId: requireHex(parsed.adapterKeyId, hex32, 'adapter key identifier'),
    adapterKeyVersion,
    harness,
    serviceKey: requireHex(parsed.serviceKey, hex64, 'service key'),
    signingKeyFile,
  };
}

/**
 * Reads the adapter signing seed from its owner-protected file.
 *
 * The seed never appears in configuration, arguments, environment, or diagnostics: it
 * is read from the file at connect time and handed straight to the platform key
 * provider.
 */
export function readAdapterSigningSeed(
  signingKeyFile: string,
  platform: NodeJS.Platform = process.platform,
  operations: SecureFileOperations = nodeFileOperations,
): Buffer {
  const contents = readBoundedFile(
    signingKeyFile,
    maxKeyFileBytes,
    'adapter key',
    platform,
    operations,
  );
  if (contents.length === 32) {
    return contents;
  }
  contents.fill(0);
  throw new ServiceConfigurationError('Konclave adapter key is invalid.');
}
