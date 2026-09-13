import type { LocalServiceClient } from './client.js';
import { connectLocalService } from './client.js';
import { readIssuerSigningSeed, resolveLocalServiceConfig } from './config.js';
import { privateKeyFromSeedAndZeroize } from './keys.js';
import { assertCanonicalProfile, type HarnessKind } from './transcript.js';

const genericIntegrationLabelPattern = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const ephemeralProfilePattern = /^generic-[0-9a-f]{24}$/u;

/** Whether a Generic profile is an explicit continuity alias or an isolated session. */
export type GenericProfileMode = 'durable' | 'ephemeral';

/** Self-declared Generic integration metadata that never becomes authorization evidence. */
export interface GenericClientIdentity {
  readonly profile: string;
  readonly profileMode: GenericProfileMode;
  readonly integrationLabel: string;
}

/** Finite caller-correctable failure in Generic identity metadata. */
export class GenericClientIdentityError extends Error {
  readonly code: 'invalid_arguments' | 'paved_profile_reserved' | 'ephemeral_profile_invalid';

  constructor(code: 'invalid_arguments' | 'paved_profile_reserved' | 'ephemeral_profile_invalid') {
    super(code);
    this.name = 'GenericClientIdentityError';
    this.code = code;
  }
}

/**
 * Validates Generic metadata before configuration, key, or service access.
 *
 * @throws {GenericClientIdentityError} When the label, profile, or mode is invalid.
 */
export function validateGenericClientIdentity(
  identity: GenericClientIdentity,
): GenericClientIdentity {
  const profile: unknown = identity.profile;
  const profileMode: unknown = identity.profileMode;
  const integrationLabel: unknown = identity.integrationLabel;
  if (
    typeof profile !== 'string' ||
    typeof integrationLabel !== 'string' ||
    (profileMode !== 'durable' && profileMode !== 'ephemeral') ||
    !genericIntegrationLabelPattern.test(integrationLabel)
  ) {
    throw new GenericClientIdentityError('invalid_arguments');
  }
  try {
    assertCanonicalProfile(profile);
  } catch {
    throw new GenericClientIdentityError('invalid_arguments');
  }
  if (profile.startsWith('session-')) {
    throw new GenericClientIdentityError('paved_profile_reserved');
  }
  if (profileMode === 'ephemeral' && !ephemeralProfilePattern.test(profile)) {
    throw new GenericClientIdentityError('ephemeral_profile_invalid');
  }
  return { profile, profileMode, integrationLabel };
}

/**
 * Connects one profile to the installed shared service.
 *
 * The installer-protected sidecar supplies the endpoint, AccountTrusted issuer, policy,
 * and pinned service key. There is no process-launch fallback.
 */
export async function connectInstalledService(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  profile: string,
  platform: NodeJS.Platform = process.platform,
): Promise<LocalServiceClient> {
  return connectInstalledHarnessService(environment, moduleDir, profile, 'copilot', platform);
}

/**
 * Connects an otherwise unsupported harness through the universal AccountTrusted path.
 *
 * The harness label is integration metadata. It does not upgrade the evidence kind or
 * satisfy an attested policy.
 */
export async function connectInstalledGenericService(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  identity: GenericClientIdentity,
  platform: NodeJS.Platform = process.platform,
): Promise<LocalServiceClient> {
  const validated = validateGenericClientIdentity(identity);
  return connectInstalledHarnessService(
    environment,
    moduleDir,
    validated.profile,
    'generic',
    platform,
  );
}

async function connectInstalledHarnessService(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  profile: string,
  harness: HarnessKind,
  platform: NodeJS.Platform,
): Promise<LocalServiceClient> {
  const config = resolveLocalServiceConfig(environment, moduleDir, platform);
  const signingKey = privateKeyFromSeedAndZeroize(
    readIssuerSigningSeed(config.issuerKeyFile, platform),
  );
  return connectLocalService({
    endpoint: config.endpoint,
    issuerKeyId: config.issuerKeyId,
    issuerKeyVersion: config.issuerKeyVersion,
    signingKey,
    serviceKey: config.serviceKey,
    harness,
    profile,
  });
}
