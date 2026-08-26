import type { LocalServiceClient } from './client.js';
import { connectLocalService } from './client.js';
import { readAdapterSigningSeed, resolveLocalServiceConfig } from './config.js';
import { privateKeyFromSeedAndZeroize } from './keys.js';

/**
 * Connects one profile to the installed shared service.
 *
 * The installer-protected sidecar supplies the endpoint, registered adapter identity,
 * and pinned service key. There is no process-launch fallback.
 */
export async function connectInstalledService(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  profile: string,
  platform: NodeJS.Platform = process.platform,
): Promise<LocalServiceClient> {
  const config = resolveLocalServiceConfig(environment, moduleDir, platform);
  const signingKey = privateKeyFromSeedAndZeroize(
    readAdapterSigningSeed(config.signingKeyFile, platform),
  );
  return connectLocalService({
    endpoint: config.endpoint,
    adapterKeyId: config.adapterKeyId,
    adapterKeyVersion: config.adapterKeyVersion,
    signingKey,
    serviceKey: config.serviceKey,
    harness: config.harness,
    profile,
  });
}
