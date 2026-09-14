import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { zipSync } from 'fflate';
import {
  agentPluginExtensionEntryPath,
  agentPluginExtensionPackagePath,
  createAgentExtensionPackage,
  extensionEntryPath,
  fixedMtime,
  getArchivePath,
} from './package-contract.mjs';

const pluginManifest = JSON.parse(readFileSync('plugin.json', 'utf8'));
const packageManifest = JSON.parse(readFileSync('package.json', 'utf8'));
const archivePath = getArchivePath(pluginManifest);
const extensionPackage = createAgentExtensionPackage(pluginManifest, packageManifest);

mkdirSync(dirname(archivePath), { recursive: true });

const zipInput = {
  'plugin.json': [readFileSync('plugin.json'), { mtime: fixedMtime }],
  [agentPluginExtensionEntryPath]: [readFileSync(extensionEntryPath), { mtime: fixedMtime }],
  [agentPluginExtensionPackagePath]: [
    Buffer.from(`${JSON.stringify(extensionPackage, null, 2)}\n`),
    { mtime: fixedMtime },
  ],
};

writeFileSync(archivePath, zipSync(zipInput, { level: 9 }));

console.log(`Packaged ${archivePath}`);
