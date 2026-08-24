import { lstatSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** Checks whether `path` exists and is a regular file, never throwing. */
export type RegularFileCheck = (path: string) => boolean;

export const checkRegularFile: RegularFileCheck = (path) => {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
};

const defaultDaemonCommand = (platform: NodeJS.Platform): string =>
  platform === 'win32' ? 'KonclaveLocalDaemon.exe' : 'KonclaveLocalDaemon';

/**
 * Derives the installed plugin root from the compiled extension module's own
 * directory.
 *
 * Copilot CLI copies an installed plugin into its own cache at an unpredictable
 * path and can launch the extension from an unrelated working directory, so the
 * root must be derived from where this module lives on disk
 * (`<plugin-root>/extensions/Konclave.Extension/extension.mjs`) rather than from
 * `process.cwd()` or any ancestor-probing search.
 */
export function pluginRootFromModuleDir(moduleDir: string): string {
  return dirname(dirname(moduleDir));
}

/** Computes the daemon path bundled inside the installed plugin, if one exists. */
export function resolveBundledDaemonPath(moduleDir: string, platform: NodeJS.Platform): string {
  const pluginRoot = pluginRootFromModuleDir(moduleDir);
  return join(pluginRoot, 'bin', defaultDaemonCommand(platform));
}

/**
 * Resolves the daemon command the extension should launch.
 *
 * Priority order: an explicit non-empty `KONCLAVE_DAEMON_PATH` override, then the
 * daemon bundled inside the installed plugin, then the bare binary name resolved
 * against the system `PATH`.
 */
export function resolveDaemonCommand(
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
  moduleDir: string,
  isRegularFile: RegularFileCheck = checkRegularFile,
): string {
  const override = environment.KONCLAVE_DAEMON_PATH?.trim();
  if (override) {
    return override;
  }

  const bundledPath = resolveBundledDaemonPath(moduleDir, platform);
  if (isRegularFile(bundledPath)) {
    return bundledPath;
  }

  return defaultDaemonCommand(platform);
}
