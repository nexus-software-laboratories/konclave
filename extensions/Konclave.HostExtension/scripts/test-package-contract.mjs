import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { strToU8, unzipSync, zipSync } from 'fflate';

import { agentPluginExtensionEntryPath, getArchivePath } from './package-contract.mjs';

const plugin = JSON.parse(readFileSync('plugin.json', 'utf8'));
const archivePath = getArchivePath(plugin);
const originalArchive = readFileSync(archivePath);
const archiveMtime = new Date('1980-01-01T00:00:00.000Z');

function createArchive(mutator) {
  const entries = unzipSync(new Uint8Array(originalArchive));
  mutator(entries);
  return zipSync(entries, { level: 9, mtime: archiveMtime });
}

function expectFailure(name, archive, expectedMessage) {
  writeFileSync(archivePath, archive);
  const result = spawnSync(process.execPath, ['scripts/verify-package.mjs'], {
    encoding: 'utf8',
  });
  const diagnostics = `${result.stdout}\n${result.stderr}`;
  if (result.status === 0) {
    throw new Error(`${name}: package verification unexpectedly succeeded.`);
  }
  if (!diagnostics.includes(expectedMessage)) {
    throw new Error(
      `${name}: expected "${expectedMessage}" in verifier diagnostics:\n${diagnostics}`,
    );
  }
}

try {
  expectFailure(
    'extra source file',
    createArchive((entries) => {
      entries['src/runtime.ts'] = strToU8('export {};\n');
    }),
    'Packaged archive must contain exactly',
  );
  expectFailure(
    'stale manifest version',
    createArchive((entries) => {
      const manifest = JSON.parse(new TextDecoder().decode(entries['plugin.json']));
      manifest.version = '9.9.9';
      entries['plugin.json'] = strToU8(`${JSON.stringify(manifest, null, 2)}\n`);
    }),
    'does not match its deterministic source: plugin.json',
  );
  expectFailure(
    'missing extension entry',
    createArchive((entries) => {
      delete entries[agentPluginExtensionEntryPath];
    }),
    'Packaged archive must contain exactly',
  );
  expectFailure(
    'legacy extension layout',
    createArchive((entries) => {
      const extension = entries[agentPluginExtensionEntryPath];
      delete entries[agentPluginExtensionEntryPath];
      entries['extensions/Konclave.Extension/extension.mjs'] = extension;
    }),
    'Packaged archive must contain exactly',
  );
} finally {
  writeFileSync(archivePath, originalArchive);
}

console.log('Package rejection contract passed.');
