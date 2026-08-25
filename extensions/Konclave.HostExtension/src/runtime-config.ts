import { lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

const runtimeConfigFileName = 'konclave.runtime.json';
const maxRuntimeConfigBytes = 4096;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

/**
 * Resolves the profile root from an explicit environment override or the bounded
 * non-secret sidecar installed beside a user-scoped extension.
 */
export function resolveInstalledProfileRoot(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
): string | undefined {
  const override = environment.KONCLAVE_PROFILE_ROOT?.trim();
  if (override) {
    return override;
  }

  const configPath = join(moduleDir, runtimeConfigFileName);
  let stats;
  try {
    stats = lstatSync(configPath);
  } catch (error) {
    if (isMissingFile(error)) {
      return undefined;
    }
    throw error;
  }
  if (!stats.isFile() || stats.size > maxRuntimeConfigBytes) {
    throw new Error('Konclave extension runtime configuration is invalid.');
  }

  const parsed: unknown = JSON.parse(readFileSync(configPath, 'utf8'));
  if (!isRecord(parsed) || parsed.schemaVersion !== 1 || typeof parsed.profileRoot !== 'string') {
    throw new Error('Konclave extension runtime configuration is malformed.');
  }
  const profileRoot = parsed.profileRoot.trim();
  if (!profileRoot || !isAbsolute(profileRoot)) {
    throw new Error('Konclave extension profile root must be absolute.');
  }
  return profileRoot;
}
