import type { LocalServiceClient } from './service/client.js';
import { LocalServiceError, LocalServiceUpgradeRequiredError } from './service/client.js';
import { ServiceConfigurationError } from './service/config.js';
import {
  connectInstalledGenericService,
  GenericClientIdentityError,
  validateGenericClientIdentity,
  type GenericClientIdentity,
  type GenericProfileMode,
} from './service/installed.js';
import { serviceOperations, toolOperations } from './service/operations.js';

const requestDeadlineMs = 90_000;
const allowedOperations = new Set<string>([...toolOperations, serviceOperations.status]);

export interface GenericCommandArguments extends GenericClientIdentity {
  readonly operation: string;
  readonly requestId?: Buffer;
}

export interface GenericCommandResult {
  readonly integration: {
    readonly kind: 'generic';
    readonly label: string;
  };
  readonly profile: {
    readonly alias: string;
    readonly mode: GenericClientIdentity['profileMode'];
  };
  readonly result: unknown;
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
  let profileMode: GenericProfileMode | undefined;
  let integrationLabel: string | undefined;
  let operation: string | undefined;
  let requestId: Buffer | undefined;
  for (let index = 0; index < values.length; index += 1) {
    const name = values[index];
    const value = values[index + 1];
    if (
      (name === '--profile' ||
        name === '--profile-mode' ||
        name === '--integration-label' ||
        name === '--operation' ||
        name === '--request-id') &&
      value
    ) {
      if (name === '--profile') {
        if (profile !== undefined) {
          throw new GenericClientIdentityError('invalid_arguments');
        }
        profile = value;
      } else if (name === '--profile-mode') {
        if (profileMode !== undefined || (value !== 'durable' && value !== 'ephemeral')) {
          throw new GenericClientIdentityError('invalid_arguments');
        }
        profileMode = value;
      } else if (name === '--integration-label') {
        if (integrationLabel !== undefined) {
          throw new GenericClientIdentityError('invalid_arguments');
        }
        integrationLabel = value;
      } else if (name === '--operation') {
        if (operation !== undefined) {
          throw new GenericClientIdentityError('invalid_arguments');
        }
        operation = value;
      } else if (requestId === undefined && /^[0-9a-f]{32}$/u.test(value)) {
        requestId = Buffer.from(value, 'hex');
      } else {
        throw new GenericClientIdentityError('invalid_arguments');
      }
      index += 1;
      continue;
    }
    throw new GenericClientIdentityError('invalid_arguments');
  }
  if (
    !profile ||
    !profileMode ||
    !integrationLabel ||
    !operation ||
    !allowedOperations.has(operation)
  ) {
    throw new GenericClientIdentityError('invalid_arguments');
  }
  const identity = validateGenericClientIdentity({ profile, profileMode, integrationLabel });
  const parsed = { ...identity, operation };
  return requestId ? { ...parsed, requestId } : parsed;
}

export async function invokeGenericCommand(
  args: GenericCommandArguments,
  payload: unknown,
  dependencies: GenericCommandDependencies,
): Promise<GenericCommandResult> {
  const connect = dependencies.connect ?? connectInstalledGenericService;
  const client: LocalServiceClient = await connect(
    dependencies.environment,
    dependencies.moduleDir,
    {
      profile: args.profile,
      profileMode: args.profileMode,
      integrationLabel: args.integrationLabel,
    },
  );
  let operationSucceeded = false;
  try {
    const result = await client.request(args.operation, payload, {
      deadlineMs: requestDeadlineMs,
      signal: dependencies.signal,
      requestId: args.requestId,
    });
    operationSucceeded = true;
    return {
      integration: {
        kind: 'generic',
        label: args.integrationLabel,
      },
      profile: {
        alias: args.profile,
        mode: args.profileMode,
      },
      result,
    };
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
  if (error instanceof GenericClientIdentityError) {
    return { error: error.code };
  }
  return { error: 'generic_client_failed' };
}
