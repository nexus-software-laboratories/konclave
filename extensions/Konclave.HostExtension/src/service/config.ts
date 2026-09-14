import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { posix, win32 } from 'node:path';

import type { HarnessKind } from './transcript.js';

/**
 * The bounded runtime configuration contract for the shared local service.
 *
 * Installation owns this file: it names the endpoint the service listens on, the
 * issuer registration this extension authenticates with, and the service key this
 * client pins. Nothing here is discovered, guessed, or defaulted, and a missing or
 * malformed record fails visibly. There is no path that starts a daemon instead.
 */

const serviceConfigFileName = 'konclave.service.json';
const maxServiceConfigBytes = 4096;
const maxKeyFileBytes = 32;
const maxPathCharacters = 4096;
const hex32 = /^[0-9a-f]{32}$/;
const hex64 = /^[0-9a-f]{64}$/;

export interface LocalServiceRuntimeConfig {
  /** Owner-protected endpoint the per-user service listens on. */
  readonly endpoint: string;
  /** Installed AccountTrusted issuer key identifier. */
  readonly issuerKeyId: Buffer;
  /** Installed AccountTrusted issuer key version. */
  readonly issuerKeyVersion: number;
  /** Harness metadata this paved client requests. */
  readonly harness: HarnessKind;
  /** Service verification key this client pins. */
  readonly serviceKey: Buffer;
  /** Owner-protected file holding the AccountTrusted issuer seed. */
  readonly issuerKeyFile: string;
  /** Installed native helper used only for a UserPresence ceremony. */
  readonly userPresenceHelper?: string;
  /** Effective installation policy accepted by this client build. */
  readonly authorizationPolicy: {
    readonly version: number;
    readonly acceptedEvidence: readonly (readonly string[])[];
  };
}

export class ServiceConfigurationError extends Error {
  readonly code: 'invalid_configuration' | 'required_evidence_unavailable';

  constructor(
    message: string,
    code: 'invalid_configuration' | 'required_evidence_unavailable' = 'invalid_configuration',
  ) {
    super(message);
    this.name = 'ServiceConfigurationError';
    this.code = code;
  }
}

class MissingInstalledFileError extends Error {}

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
      throw new MissingInstalledFileError();
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

function readRequiredBoundedFile(
  path: string,
  maxBytes: number,
  what: string,
  platform: NodeJS.Platform,
  operations: SecureFileOperations,
): Buffer {
  try {
    return readBoundedFile(path, maxBytes, what, platform, operations);
  } catch (error) {
    if (error instanceof MissingInstalledFileError) {
      throw new ServiceConfigurationError(`Konclave ${what} is not installed.`);
    }
    throw error;
  }
}

function readOptionalBoundedFile(
  path: string,
  maxBytes: number,
  what: string,
  platform: NodeJS.Platform,
  operations: SecureFileOperations,
): Buffer | undefined {
  try {
    return readBoundedFile(path, maxBytes, what, platform, operations);
  } catch (error) {
    if (error instanceof MissingInstalledFileError) {
      return undefined;
    }
    throw error;
  }
}

function environmentPath(
  environment: Readonly<Record<string, string | undefined>>,
  name: string,
): string | undefined {
  const value = environment[name]?.trim();
  return value && value.length > 0 ? value : undefined;
}

function pathApi(platform: NodeJS.Platform): typeof posix | typeof win32 {
  if (platform === 'win32') {
    return win32;
  }
  if (platform === 'linux' || platform === 'darwin') {
    return posix;
  }
  throw new ServiceConfigurationError('Konclave client platform is unsupported.');
}

function requireAbsolutePath(value: string, what: string, platform: NodeJS.Platform): string {
  if (
    value.length === 0 ||
    value.length > maxPathCharacters ||
    value.includes('\0') ||
    value.includes('\r') ||
    value.includes('\n') ||
    !pathApi(platform).isAbsolute(value)
  ) {
    throw new ServiceConfigurationError(`Konclave ${what} path is invalid.`);
  }
  return value;
}

function defaultServiceConfigPath(
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): string {
  const paths = pathApi(platform);
  if (platform === 'win32') {
    const root = environmentPath(environment, 'LOCALAPPDATA');
    if (root === undefined) {
      throw new ServiceConfigurationError(
        'Konclave canonical service configuration location is unavailable.',
      );
    }
    return paths.join(
      requireAbsolutePath(root, 'local application data', platform),
      'Konclave',
      'service',
      serviceConfigFileName,
    );
  }
  const home = environmentPath(environment, 'HOME');
  if (platform === 'darwin') {
    if (home === undefined) {
      throw new ServiceConfigurationError(
        'Konclave canonical service configuration location is unavailable.',
      );
    }
    return paths.join(
      requireAbsolutePath(home, 'home', platform),
      'Library',
      'Application Support',
      'Konclave',
      'service',
      serviceConfigFileName,
    );
  }
  const xdgDataHome = environmentPath(environment, 'XDG_DATA_HOME');
  if (xdgDataHome !== undefined) {
    return paths.join(
      requireAbsolutePath(xdgDataHome, 'XDG data', platform),
      'konclave',
      'service',
      serviceConfigFileName,
    );
  }
  if (home === undefined) {
    throw new ServiceConfigurationError(
      'Konclave canonical service configuration location is unavailable.',
    );
  }
  return paths.join(
    requireAbsolutePath(home, 'home', platform),
    '.local',
    'share',
    'konclave',
    'service',
    serviceConfigFileName,
  );
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
 * The canonical location is independent of the replaceable plugin cache. An equal
 * legacy module-adjacent sidecar remains readable during migration, while conflicting
 * or unsafe canonical state fails closed. An explicit absolute override is reserved
 * for deterministic tests and declared development scenarios.
 */
export function resolveLocalServiceConfig(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  platform: NodeJS.Platform = process.platform,
  operations: SecureFileOperations = nodeFileOperations,
): LocalServiceRuntimeConfig {
  const override = environmentPath(environment, 'KONCLAVE_SERVICE_CONFIG_FILE');
  if (override !== undefined) {
    const raw = readRequiredBoundedFile(
      requireAbsolutePath(override, 'service configuration', platform),
      maxServiceConfigBytes,
      'service configuration',
      platform,
      operations,
    );
    return parseLocalServiceConfig(raw, platform);
  }

  const paths = pathApi(platform);
  const canonicalPath = defaultServiceConfigPath(environment, platform);
  const legacyPath = paths.join(
    requireAbsolutePath(moduleDir, 'plugin module', platform),
    serviceConfigFileName,
  );
  const canonicalRaw = readOptionalBoundedFile(
    canonicalPath,
    maxServiceConfigBytes,
    'service configuration',
    platform,
    operations,
  );
  const legacyRaw =
    canonicalPath === legacyPath
      ? undefined
      : readOptionalBoundedFile(
          legacyPath,
          maxServiceConfigBytes,
          'service configuration',
          platform,
          operations,
        );
  const canonical =
    canonicalRaw === undefined ? undefined : parseLocalServiceConfig(canonicalRaw, platform);
  const legacy = legacyRaw === undefined ? undefined : parseLocalServiceConfig(legacyRaw, platform);
  if (
    canonical !== undefined &&
    legacy !== undefined &&
    !legacyMatchesCanonical(legacy, canonical)
  ) {
    throw new ServiceConfigurationError(
      'Konclave service configuration conflicts with the legacy extension sidecar.',
    );
  }
  const selected = canonical ?? legacy;
  if (selected === undefined) {
    throw new ServiceConfigurationError('Konclave service configuration is not installed.');
  }
  return selected;
}

function parseLocalServiceConfig(
  raw: Buffer,
  platform: NodeJS.Platform,
): LocalServiceRuntimeConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new ServiceConfigurationError('Konclave service configuration is malformed.');
  }
  if (!isRecord(parsed) || parsed.schemaVersion !== 2) {
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

  const issuerKeyVersion = parsed.issuerKeyVersion;
  if (
    typeof issuerKeyVersion !== 'number' ||
    !Number.isInteger(issuerKeyVersion) ||
    issuerKeyVersion < 1
  ) {
    throw new ServiceConfigurationError('Konclave issuer key version is invalid.');
  }

  const issuerKeyFile = typeof parsed.issuerKeyFile === 'string' ? parsed.issuerKeyFile.trim() : '';
  if (!issuerKeyFile) {
    throw new ServiceConfigurationError('Konclave issuer key file must be absolute.');
  }
  requireAbsolutePath(issuerKeyFile, 'issuer key file', platform);
  const userPresenceHelper =
    typeof parsed.userPresenceHelper === 'string' ? parsed.userPresenceHelper.trim() : undefined;
  if (parsed.userPresenceHelper !== undefined && !userPresenceHelper) {
    throw new ServiceConfigurationError('Konclave user-presence helper must be absolute.');
  }
  if (userPresenceHelper !== undefined) {
    requireAbsolutePath(userPresenceHelper, 'user-presence helper', platform);
  }
  const authorizationPolicy = parseAuthorizationPolicy(parsed.authorizationPolicy);

  return {
    endpoint,
    issuerKeyId: requireHex(parsed.issuerKeyId, hex32, 'issuer key identifier'),
    issuerKeyVersion,
    harness,
    serviceKey: requireHex(parsed.serviceKey, hex64, 'service key'),
    issuerKeyFile,
    userPresenceHelper,
    authorizationPolicy,
  };
}

function legacyMatchesCanonical(
  legacy: LocalServiceRuntimeConfig,
  canonical: LocalServiceRuntimeConfig,
): boolean {
  return (
    legacy.endpoint === canonical.endpoint &&
    legacy.issuerKeyId.equals(canonical.issuerKeyId) &&
    legacy.issuerKeyVersion === canonical.issuerKeyVersion &&
    legacy.harness === canonical.harness &&
    legacy.serviceKey.equals(canonical.serviceKey) &&
    legacy.issuerKeyFile === canonical.issuerKeyFile &&
    (legacy.userPresenceHelper === undefined ||
      legacy.userPresenceHelper === canonical.userPresenceHelper) &&
    policiesEqual(legacy.authorizationPolicy, canonical.authorizationPolicy)
  );
}

function policiesEqual(
  left: LocalServiceRuntimeConfig['authorizationPolicy'],
  right: LocalServiceRuntimeConfig['authorizationPolicy'],
): boolean {
  const leftClauses = canonicalPolicyClauses(left);
  const rightClauses = canonicalPolicyClauses(right);
  return (
    left.version === right.version &&
    leftClauses.length === rightClauses.length &&
    leftClauses.every((clause, index) => clause === rightClauses[index])
  );
}

function canonicalPolicyClauses(
  policy: LocalServiceRuntimeConfig['authorizationPolicy'],
): string[] {
  return policy.acceptedEvidence.map((clause) => [...clause].sort().join('|')).sort();
}

/**
 * Reads the AccountTrusted issuer seed from its owner-protected file.
 *
 * The seed never appears in configuration, arguments, environment, or diagnostics: it
 * is read from the file at connect time and handed straight to the platform key
 * provider.
 */
export function readIssuerSigningSeed(
  signingKeyFile: string,
  platform: NodeJS.Platform = process.platform,
  operations: SecureFileOperations = nodeFileOperations,
): Buffer {
  const contents = readRequiredBoundedFile(
    signingKeyFile,
    maxKeyFileBytes,
    'issuer key',
    platform,
    operations,
  );
  if (contents.length === 32) {
    return contents;
  }

  contents.fill(0);
  throw new ServiceConfigurationError('Konclave issuer key is invalid.');
}

function parseAuthorizationPolicy(
  value: unknown,
): LocalServiceRuntimeConfig['authorizationPolicy'] {
  if (!isRecord(value)) {
    throw new ServiceConfigurationError('Konclave authorization policy is invalid.');
  }
  const version = value.version;
  const acceptedEvidence = value.acceptedEvidence;
  if (
    typeof version !== 'number' ||
    !Number.isSafeInteger(version) ||
    version <= 0 ||
    !Array.isArray(acceptedEvidence) ||
    acceptedEvidence.length === 0 ||
    acceptedEvidence.length > 8
  ) {
    throw new ServiceConfigurationError('Konclave authorization policy is invalid.');
  }
  const clauses = acceptedEvidence.map((clause) => {
    if (
      !Array.isArray(clause) ||
      clause.length === 0 ||
      clause.some(
        (kind) =>
          kind !== 'account_trusted' &&
          kind !== 'user_presence' &&
          kind !== 'harness_attested' &&
          kind !== 'workload_identity',
      )
    ) {
      throw new ServiceConfigurationError('Konclave authorization policy is invalid.');
    }
    return [...clause] as readonly string[];
  });
  return { version, acceptedEvidence: clauses };
}
