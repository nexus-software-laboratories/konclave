import type { LocalServiceClient } from './service/client.js';
import { LocalServiceError, LocalServiceUpgradeRequiredError } from './service/client.js';
import { ServiceConfigurationError } from './service/config.js';
import { connectInstalledGenericService } from './service/installed.js';
import { serviceOperations, toolOperations } from './service/operations.js';

const requestDeadlineMs = 90_000;
const allowedOperations = new Set<string>([...toolOperations, serviceOperations.status]);

class GenericCommandUsageError extends Error {
  readonly code: 'paved_profile_reserved';

  constructor(code: 'paved_profile_reserved') {
    super(code);
    this.name = 'GenericCommandUsageError';
    this.code = code;
  }
}

export interface GenericCommandArguments {
  readonly profile: string;
  readonly operation: string;
  readonly requestId?: Buffer;
}

export interface GenericCommandDependencies {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly moduleDir: string;
  readonly signal: AbortSignal;
  readonly reportCleanupFailure: () => void;
  readonly connect?: typeof connectInstalledGenericService;
}

export function parseGenericCommandArguments(values: readonly string[]): GenericCommandArguments {
  let profile: string | undefined;
  let operation: string | undefined;
  let requestId: Buffer | undefined;
  for (let index = 0; index < values.length; index += 1) {
    const name = values[index];
    const value = values[index + 1];
    if ((name === '--profile' || name === '--operation' || name === '--request-id') && value) {
      if (name === '--profile') {
        if (profile !== undefined) {
          throw new Error('invalid_arguments');
        }
        profile = value;
      } else if (name === '--operation') {
        if (operation !== undefined) {
          throw new Error('invalid_arguments');
        }
        operation = value;
      } else if (requestId === undefined && /^[0-9a-f]{32}$/u.test(value)) {
        requestId = Buffer.from(value, 'hex');
      } else {
        throw new Error('invalid_arguments');
      }
      index += 1;
      continue;
    }
    throw new Error('invalid_arguments');
  }
  if (!profile || !operation || !allowedOperations.has(operation)) {
    throw new Error('invalid_arguments');
  }
  if (profile.startsWith('session-')) {
    throw new GenericCommandUsageError('paved_profile_reserved');
  }
  return requestId ? { profile, operation, requestId } : { profile, operation };
}

export async function invokeGenericCommand(
  args: GenericCommandArguments,
  payload: unknown,
  dependencies: GenericCommandDependencies,
): Promise<unknown> {
  const connect = dependencies.connect ?? connectInstalledGenericService;
  const client: LocalServiceClient = await connect(
    dependencies.environment,
    dependencies.moduleDir,
    args.profile,
  );
  let operationSucceeded = false;
  try {
    const result = await client.request(args.operation, payload, {
      deadlineMs: requestDeadlineMs,
      signal: dependencies.signal,
      requestId: args.requestId,
    });
    operationSucceeded = true;
    return result;
  } finally {
    try {
      await client.retire();
    } catch {
      client.close();
      if (operationSucceeded) {
        dependencies.reportCleanupFailure();
      }
    }
  }
}

export function genericCommandFailure(error: unknown): {
  readonly error: string;
  readonly operation?: string;
} {
  if (error instanceof LocalServiceError) {
    return { error: error.code, operation: error.operation };
  }
  if (error instanceof ServiceConfigurationError) {
    return { error: error.code };
  }
  if (error instanceof LocalServiceUpgradeRequiredError) {
    return { error: error.code };
  }
  if (error instanceof GenericCommandUsageError) {
    return { error: error.code };
  }
  return { error: 'generic_client_failed' };
}
