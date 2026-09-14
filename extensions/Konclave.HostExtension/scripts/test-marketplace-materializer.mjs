import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { zipSync } from 'fflate';

import { MarketplaceContractError, marketplaceOutputPaths } from './marketplace-contract.mjs';
import { materializeMarketplace } from './materialize-marketplace.mjs';
import {
  agentPluginExtensionEntryPath,
  agentPluginExtensionPackagePath,
} from './package-contract.mjs';

const version = '0.1.2';
const root = mkdtempSync(join(tmpdir(), 'konclave-marketplace-'));

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function writeRelease(releaseRoot, mutateArchive = null, mutateManifest = null) {
  mkdirSync(releaseRoot, { recursive: true });
  const entries = {
    'plugin.json': jsonBytes({
      $schema: 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json',
      name: 'konclave',
      version,
    }),
    [agentPluginExtensionPackagePath]: jsonBytes({
      name: 'konclave',
      version,
      type: 'module',
      main: 'extension.mjs',
    }),
    [agentPluginExtensionEntryPath]: Buffer.from('export default {};\n'),
  };
  mutateArchive?.(entries);
  const archive = Buffer.from(zipSync(entries, { level: 9 }));
  const fileName = `konclave-${version}.zip`;
  writeFileSync(join(releaseRoot, fileName), archive);
  const digest = createHash('sha256').update(archive).digest('hex');
  writeFileSync(join(releaseRoot, 'SHA256SUMS'), `${digest}  ${fileName}\n`);
  writeFileSync(
    join(releaseRoot, `${fileName}.intoto.jsonl`),
    `${JSON.stringify({
      _type: 'https://in-toto.io/Statement/v1',
      subject: [
        {
          name: fileName,
          digest: {
            sha256: digest,
          },
        },
      ],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: {
        buildDefinition: {
          externalParameters: {
            artifactId: 'konclave-agent-plugin',
            buildKind: 'plugin',
            target: 'portable',
            version,
          },
          resolvedDependencies: [
            {
              uri: 'git+https://github.com/nexus-software-laboratories/konclave',
              digest: {
                gitCommit: 'a'.repeat(40),
              },
            },
          ],
        },
      },
    })}\n`,
  );
  const manifest = {
    release: {
      version,
    },
    artifacts: [
      {
        id: 'konclave-agent-plugin',
        kind: 'plugin',
        fileName,
      },
    ],
  };
  mutateManifest?.(manifest);
  writeFileSync(join(releaseRoot, 'RELEASE.json'), jsonBytes(manifest));
}

function expectFailure(name, action, expectedCode) {
  assert.throws(
    action,
    (error) =>
      error instanceof MarketplaceContractError &&
      error.code === expectedCode &&
      error.message.length > 0,
    name,
  );
}

try {
  const releaseRoot = join(root, 'release');
  const outputRoot = join(root, 'output');
  writeRelease(releaseRoot);
  const plan = materializeMarketplace({
    releaseDirectory: releaseRoot,
    outputRoot,
  });
  assert.equal(plan.sourceCommit, 'a'.repeat(40));
  assert.deepEqual(
    plan.files.map((file) => file.path),
    marketplaceOutputPaths,
  );
  materializeMarketplace({
    releaseDirectory: releaseRoot,
    outputRoot,
    checkOnly: true,
  });
  for (const file of plan.files) {
    assert.ok(readFileSync(join(outputRoot, ...file.path.split('/'))).equals(file.bytes));
  }

  const pluginPath = join(outputRoot, 'plugins', 'konclave', 'plugin.json');
  writeFileSync(pluginPath, '{}\n');
  expectFailure(
    'changed tracked bytes',
    () =>
      materializeMarketplace({
        releaseDirectory: releaseRoot,
        outputRoot,
        checkOnly: true,
      }),
    'marketplace_bytes_mismatch',
  );
  materializeMarketplace({
    releaseDirectory: releaseRoot,
    outputRoot,
  });

  const unexpectedPath = join(outputRoot, 'plugins', 'konclave', 'src.ts');
  writeFileSync(unexpectedPath, 'export {};\n');
  expectFailure(
    'unexpected output file',
    () =>
      materializeMarketplace({
        releaseDirectory: releaseRoot,
        outputRoot,
      }),
    'marketplace_tree_invalid',
  );
  rmSync(unexpectedPath);

  if (process.platform !== 'win32') {
    const linkPath = join(outputRoot, 'plugins', 'konclave', 'linked');
    symlinkSync(pluginPath, linkPath);
    expectFailure(
      'symbolic link output',
      () =>
        materializeMarketplace({
          releaseDirectory: releaseRoot,
          outputRoot,
          checkOnly: true,
        }),
      'marketplace_tree_invalid',
    );
    rmSync(linkPath);
  }

  const badChecksumRoot = join(root, 'bad-checksum');
  writeRelease(badChecksumRoot);
  writeFileSync(
    join(badChecksumRoot, 'SHA256SUMS'),
    `${'0'.repeat(64)}  konclave-${version}.zip\n`,
  );
  expectFailure(
    'checksum mismatch',
    () =>
      materializeMarketplace({
        releaseDirectory: badChecksumRoot,
        outputRoot: join(root, 'bad-checksum-output'),
      }),
    'release_checksum_mismatch',
  );

  const badManifestRoot = join(root, 'bad-manifest');
  writeRelease(badManifestRoot, null, (manifest) => {
    manifest.artifacts[0].fileName = 'other.zip';
  });
  expectFailure(
    'release artifact mismatch',
    () =>
      materializeMarketplace({
        releaseDirectory: badManifestRoot,
        outputRoot: join(root, 'bad-manifest-output'),
      }),
    'release_contract_invalid',
  );

  const missingChecksumRoot = join(root, 'missing-checksum');
  writeRelease(missingChecksumRoot);
  rmSync(join(missingChecksumRoot, 'SHA256SUMS'));
  expectFailure(
    'missing checksum manifest',
    () =>
      materializeMarketplace({
        releaseDirectory: missingChecksumRoot,
        outputRoot: join(root, 'missing-checksum-output'),
      }),
    'release_contract_invalid',
  );

  const invalidArchiveRoot = join(root, 'invalid-archive');
  writeRelease(invalidArchiveRoot);
  const invalidArchive = Buffer.from('not a zip');
  const invalidArchiveName = `konclave-${version}.zip`;
  const invalidArchiveDigest = createHash('sha256').update(invalidArchive).digest('hex');
  writeFileSync(join(invalidArchiveRoot, invalidArchiveName), invalidArchive);
  writeFileSync(
    join(invalidArchiveRoot, 'SHA256SUMS'),
    `${invalidArchiveDigest}  ${invalidArchiveName}\n`,
  );
  const invalidArchiveProvenancePath = join(
    invalidArchiveRoot,
    `${invalidArchiveName}.intoto.jsonl`,
  );
  const invalidArchiveProvenance = JSON.parse(readFileSync(invalidArchiveProvenancePath, 'utf8'));
  invalidArchiveProvenance.subject[0].digest.sha256 = invalidArchiveDigest;
  writeFileSync(invalidArchiveProvenancePath, `${JSON.stringify(invalidArchiveProvenance)}\n`);
  expectFailure(
    'invalid release archive',
    () =>
      materializeMarketplace({
        releaseDirectory: invalidArchiveRoot,
        outputRoot: join(root, 'invalid-archive-output'),
      }),
    'release_archive_invalid',
  );

  const invalidProvenanceRoot = join(root, 'invalid-provenance');
  writeRelease(invalidProvenanceRoot);
  writeFileSync(join(invalidProvenanceRoot, `konclave-${version}.zip.intoto.jsonl`), '{}\n');
  expectFailure(
    'invalid release provenance',
    () =>
      materializeMarketplace({
        releaseDirectory: invalidProvenanceRoot,
        outputRoot: join(root, 'invalid-provenance-output'),
      }),
    'release_provenance_invalid',
  );

  const unsafeArchiveRoot = join(root, 'unsafe-archive');
  writeRelease(unsafeArchiveRoot, (entries) => {
    entries['../plugin.json'] = entries['plugin.json'];
  });
  expectFailure(
    'unsafe archive entry',
    () =>
      materializeMarketplace({
        releaseDirectory: unsafeArchiveRoot,
        outputRoot: join(root, 'unsafe-output'),
      }),
    'archive_layout_mismatch',
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log('Marketplace materializer boundary tests passed.');
