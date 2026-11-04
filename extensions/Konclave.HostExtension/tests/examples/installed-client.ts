import { randomBytes } from 'node:crypto';

import { connectInstalledGenericService } from '../../src/client-api.js';

/**
 * Reads a validated public identity from one independently approved installation/profile.
 * The caller supplies the installation environment and selected client module directory.
 * Rejects connection, result-validation and retirement failures; always closes the client.
 */
export async function readInstalledIdentity(
  environment: Readonly<Record<string, string | undefined>>,
  moduleDir: string,
  approvedProfile: string,
): Promise<string> {
  const client = await connectInstalledGenericService(environment, moduleDir, {
    profile: approvedProfile,
    profileMode: 'durable',
    integrationLabel: 'example.reader',
  });
  try {
    const result = await client.request(
      'get_identity',
      {},
      {
        requestId: randomBytes(16),
        deadlineMs: 30_000,
      },
    );
    if (
      typeof result !== 'object' ||
      result === null ||
      !('device_id' in result) ||
      typeof result.device_id !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(result.device_id)
    ) {
      throw new Error('Invalid identity result');
    }
    return result.device_id;
  } finally {
    try {
      await client.retire();
    } finally {
      client.close();
    }
  }
}
