import type { LocalServiceClient } from './client.js';
import { connectLocalService } from './client.js';
import { readIssuerSigningSeed, resolveLocalServiceConfig } from './config.js';
import { privateKeyFromSeedAndZeroize } from './keys.js';
import type { HarnessKind } from './transcript.js';

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
  profile: string,
  platform: NodeJS.Platform = process.platform,
): Promise<LocalServiceClient> {
  return connectInstalledHarnessService(environment, moduleDir, profile, 'generic', platform);
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
