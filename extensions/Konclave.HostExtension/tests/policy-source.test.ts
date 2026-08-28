import { mkdtemp, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { readBoundedPolicySource } from '../src/service/commands.js';

const temporaryRoots: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'konclave-policy-source-'));
  temporaryRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe('policy source confinement', () => {
  it('reads only bounded UTF-8 regular files inside the selected workspace', async () => {
    const root = await temporaryRoot();
    const workspace = join(root, 'workspace');
    await mkdir(workspace);
    const source = '{"apiVersion":"konclave.dev/v1"}';
    await writeFile(join(workspace, 'policy.json'), source, 'utf8');

    await expect(readBoundedPolicySource('policy.json', { workspace })).resolves.toBe(source);
    await expect(
      readBoundedPolicySource(join(workspace, 'policy.json'), { workspace }),
    ).rejects.toThrow('must be relative');

    await writeFile(join(root, 'outside.json'), source, 'utf8');
    await expect(
      readBoundedPolicySource(join('..', 'outside.json'), { workspace }),
    ).rejects.toThrow('outside');

    await mkdir(join(workspace, 'directory'));
    await expect(readBoundedPolicySource('directory', { workspace })).rejects.toThrow(
      'regular file',
    );

    await writeFile(join(workspace, 'oversized.json'), Buffer.alloc(128 * 1024 + 1));
    await expect(readBoundedPolicySource('oversized.json', { workspace })).rejects.toThrow(
      'exceeds',
    );

    await writeFile(join(workspace, 'invalid.json'), Buffer.from([0xff]));
    await expect(readBoundedPolicySource('invalid.json', { workspace })).rejects.toThrow(
      'valid UTF-8',
    );
  });

  it('rejects final-file and parent-directory replacement after identity capture', async () => {
    const root = await temporaryRoot();
    const workspace = join(root, 'workspace');
    const parent = join(workspace, 'policies');
    await mkdir(parent, { recursive: true });
    await writeFile(join(parent, 'policy.json'), '{"name":"initial"}', 'utf8');

    await expect(
      readBoundedPolicySource(join('policies', 'policy.json'), {
        workspace,
        afterInitialIdentity: async () => {
          await rename(join(parent, 'policy.json'), join(parent, 'original.json'));
          await writeFile(join(parent, 'policy.json'), '{"name":"replacement"}', 'utf8');
        },
      }),
    ).rejects.toThrow('changed while it was being read');

    await rm(parent, { recursive: true });
    await mkdir(parent);
    await writeFile(join(parent, 'policy.json'), '{"name":"initial"}', 'utf8');
    await expect(
      readBoundedPolicySource(join('policies', 'policy.json'), {
        workspace,
        afterInitialIdentity: async () => {
          await rename(parent, join(workspace, 'original-policies'));
          await mkdir(parent);
          await writeFile(join(parent, 'policy.json'), '{"name":"replacement"}', 'utf8');
        },
      }),
    ).rejects.toThrow('changed while it was being read');
  });
});
