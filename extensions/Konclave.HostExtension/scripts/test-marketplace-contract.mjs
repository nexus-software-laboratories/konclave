import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import {
  MarketplaceContractError,
  createMarketplacePlan,
  marketplaceOutputPaths,
} from './marketplace-contract.mjs';
import {
  agentPluginExtensionEntryPath,
  agentPluginExtensionPackagePath,
} from './package-contract.mjs';

const version = '0.1.2';

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function validEntries() {
  return {
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
}

function createInput() {
  return {
    releaseVersion: version,
    artifactFileName: `konclave-${version}.zip`,
    entries: validEntries(),
  };
}

function expectFailure(name, mutate, expectedCode) {
  const input = createInput();
  mutate(input);
  assert.throws(
    () => createMarketplacePlan(input),
    (error) =>
      error instanceof MarketplaceContractError &&
      error.code === expectedCode &&
      error.message.length > 0,
    name,
  );
}

const input = createInput();
const plan = createMarketplacePlan(input);
assert.equal(plan.version, version);
assert.deepEqual(
  plan.files.map((file) => file.path),
  marketplaceOutputPaths,
);
const catalog = JSON.parse(plan.files[0].bytes.toString('utf8'));
assert.equal(catalog.name, 'konclave');
assert.equal(catalog.metadata.version, version);
assert.deepEqual(catalog.owner, {
  name: 'Nexus Software Laboratories',
  email: 'github@nexussoftwarelabs.com',
});
assert.deepEqual(catalog.plugins, [
  {
    name: 'konclave',
    source: 'plugins/konclave',
    description: 'Secure, durable agent-to-agent communication for GitHub Copilot CLI',
    version,
  },
]);
plan.files[1].bytes.fill(0);
assert.notDeepEqual(plan.files[1].bytes, input.entries['plugin.json']);

const cases = [
  {
    name: 'non-semver release',
    code: 'release_version_invalid',
    mutate: (value) => {
      value.releaseVersion = 'latest';
    },
  },
  {
    name: 'wrong archive name',
    code: 'artifact_name_mismatch',
    mutate: (value) => {
      value.artifactFileName = 'konclave.zip';
    },
  },
  {
    name: 'missing archive map',
    code: 'archive_layout_mismatch',
    mutate: (value) => {
      value.entries = null;
    },
  },
  {
    name: 'extra archive entry',
    code: 'archive_layout_mismatch',
    mutate: (value) => {
      value.entries['src/index.ts'] = Buffer.from('export {};\n');
    },
  },
  {
    name: 'missing archive entry',
    code: 'archive_layout_mismatch',
    mutate: (value) => {
      delete value.entries[agentPluginExtensionEntryPath];
    },
  },
  {
    name: 'empty archive entry',
    code: 'archive_entry_invalid',
    mutate: (value) => {
      value.entries[agentPluginExtensionEntryPath] = Buffer.alloc(0);
    },
  },
  {
    name: 'oversized extension',
    code: 'archive_entry_invalid',
    mutate: (value) => {
      value.entries[agentPluginExtensionEntryPath] = Buffer.alloc(1024 * 1024 + 1);
    },
  },
  {
    name: 'non-byte manifest',
    code: 'archive_entry_invalid',
    mutate: (value) => {
      value.entries['plugin.json'] = '{}';
    },
  },
  {
    name: 'invalid plugin JSON',
    code: 'manifest_json_invalid',
    mutate: (value) => {
      value.entries['plugin.json'] = Buffer.from('{');
    },
  },
  {
    name: 'wrong plugin schema',
    code: 'plugin_manifest_mismatch',
    mutate: (value) => {
      value.entries['plugin.json'] = jsonBytes({
        name: 'konclave',
        version,
      });
    },
  },
  {
    name: 'wrong plugin name',
    code: 'plugin_manifest_mismatch',
    mutate: (value) => {
      const plugin = JSON.parse(value.entries['plugin.json']);
      plugin.name = 'other';
      value.entries['plugin.json'] = jsonBytes(plugin);
    },
  },
  {
    name: 'wrong plugin version',
    code: 'plugin_manifest_mismatch',
    mutate: (value) => {
      const plugin = JSON.parse(value.entries['plugin.json']);
      plugin.version = '9.9.9';
      value.entries['plugin.json'] = jsonBytes(plugin);
    },
  },
  {
    name: 'invalid package JSON',
    code: 'manifest_json_invalid',
    mutate: (value) => {
      value.entries[agentPluginExtensionPackagePath] = Buffer.from('{');
    },
  },
  ...[
    ['name', 'other'],
    ['version', '9.9.9'],
    ['type', 'commonjs'],
    ['main', 'other.mjs'],
  ].map(([field, fieldValue]) => ({
    name: `wrong package ${field}`,
    code: 'extension_package_mismatch',
    mutate: (value) => {
      const extensionPackage = JSON.parse(value.entries[agentPluginExtensionPackagePath]);
      extensionPackage[field] = fieldValue;
      value.entries[agentPluginExtensionPackagePath] = jsonBytes(extensionPackage);
    },
  })),
];

for (const testCase of cases) {
  expectFailure(testCase.name, testCase.mutate, testCase.code);
}

console.log(`Marketplace contract passed: ${cases.length + 1} finite cases.`);
