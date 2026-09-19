import { Buffer } from 'node:buffer';

import {
  agentPluginArchivePaths,
  agentPluginExtensionEntryPath,
  agentPluginExtensionPackagePath,
} from './package-contract.mjs';

export const marketplaceCatalogPath = '.github/plugin/marketplace.json';
export const marketplacePluginRoot = 'plugins/konclave';
export const marketplacePluginPaths = [
  `${marketplacePluginRoot}/plugin.json`,
  `${marketplacePluginRoot}/${agentPluginExtensionPackagePath}`,
  `${marketplacePluginRoot}/${agentPluginExtensionEntryPath}`,
];
export const marketplaceOutputPaths = [marketplaceCatalogPath, ...marketplacePluginPaths];

const semverPattern = /^\d+\.\d+\.\d+$/;
const pluginSchema = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';
const maximumManifestBytes = 64 * 1024;
const maximumExtensionBytes = 1024 * 1024;

export class MarketplaceContractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'MarketplaceContractError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new MarketplaceContractError(code, message);
}

function copyEntry(entries, path, maximumBytes) {
  const value = entries[path];
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > maximumBytes) {
    fail('archive_entry_invalid', `Marketplace archive entry is invalid: ${path}`);
  }
  return Buffer.from(value);
}

function parseJson(bytes, path) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('manifest_json_invalid', `Marketplace manifest is invalid JSON: ${path}`);
  }
}

function createCatalog(version) {
  return {
    name: 'konclave',
    metadata: {
      description: 'Secure, durable agent-to-agent communication for GitHub Copilot CLI',
      version,
    },
    owner: {
      name: 'Nexus Software Laboratories',
      email: 'github@nexussoftwarelabs.com',
    },
    plugins: [
      {
        name: 'konclave',
        source: 'plugins/konclave',
        description: 'Secure, durable agent-to-agent communication for GitHub Copilot CLI',
        version,
      },
    ],
  };
}

export function createMarketplacePlan({ releaseVersion, artifactFileName, entries }) {
  if (typeof releaseVersion !== 'string' || !semverPattern.test(releaseVersion)) {
    fail('release_version_invalid', `Marketplace release version is invalid: ${releaseVersion}`);
  }
  if (artifactFileName !== `konclave-${releaseVersion}.zip`) {
    fail(
      'artifact_name_mismatch',
      `Marketplace artifact does not match release version: ${artifactFileName}`,
    );
  }
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    fail('archive_layout_mismatch', 'Marketplace archive entries are unavailable.');
  }

  const actualPaths = Object.keys(entries).sort();
  const expectedPaths = [...agentPluginArchivePaths].sort();
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    fail(
      'archive_layout_mismatch',
      `Marketplace archive must contain exactly: ${expectedPaths.join(', ')}`,
    );
  }

  const pluginBytes = copyEntry(entries, 'plugin.json', maximumManifestBytes);
  const packageBytes = copyEntry(entries, agentPluginExtensionPackagePath, maximumManifestBytes);
  const extensionBytes = copyEntry(entries, agentPluginExtensionEntryPath, maximumExtensionBytes);
  const plugin = parseJson(pluginBytes, 'plugin.json');
  const extensionPackage = parseJson(packageBytes, agentPluginExtensionPackagePath);

  if (
    plugin?.$schema !== pluginSchema ||
    plugin?.name !== 'konclave' ||
    plugin?.version !== releaseVersion
  ) {
    fail('plugin_manifest_mismatch', 'Marketplace plugin manifest does not match the release.');
  }
  if (
    extensionPackage?.name !== 'konclave' ||
    extensionPackage?.version !== releaseVersion ||
    extensionPackage?.type !== 'module' ||
    extensionPackage?.main !== 'extension.mjs'
  ) {
    fail('extension_package_mismatch', 'Marketplace extension package does not match the release.');
  }

  const catalogBytes = Buffer.from(`${JSON.stringify(createCatalog(releaseVersion), null, 2)}\n`);
  const files = [
    {
      path: marketplaceCatalogPath,
      bytes: catalogBytes,
    },
    {
      path: `${marketplacePluginRoot}/plugin.json`,
      bytes: pluginBytes,
    },
    {
      path: `${marketplacePluginRoot}/${agentPluginExtensionPackagePath}`,
      bytes: packageBytes,
    },
    {
      path: `${marketplacePluginRoot}/${agentPluginExtensionEntryPath}`,
      bytes: extensionBytes,
    },
  ];

  return {
    version: releaseVersion,
    files: files.map((file) => ({
      path: file.path,
      bytes: Buffer.from(file.bytes),
    })),
  };
}
