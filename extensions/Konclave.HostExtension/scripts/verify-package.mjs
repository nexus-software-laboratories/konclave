import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { unzipSync } from 'fflate';
import {
  extensionEntryPath,
  clientEntryPath,
  genericEntryPath,
  genericSkillPath,
  getArchivePath,
  maintainerSkillPath,
  manifestExtensionPath,
  packageFiles,
} from './package-contract.mjs';

const errors = [];
const semverPattern = /^\d+\.\d+\.\d+$/;
const pluginNamePattern = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

function check(condition, message) {
  if (!condition) {
    errors.push(message);
  }
}

function optionValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) {
    return null;
  }

  const value = process.argv[index + 1];
  if (!value) {
    errors.push(`${name} requires a value.`);
    return null;
  }

  return value;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

const packageManifest = readJson('package.json');
const pluginManifest = readJson('plugin.json');

check(packageManifest.private === true, 'package.json must stay private.');
check(packageManifest.type === 'module', 'package.json must set type to "module".');
check(
  packageManifest.engines?.node === '>=24.0.0',
  'package.json engines.node must be ">=24.0.0".',
);
check(
  typeof pluginManifest.name === 'string' && pluginNamePattern.test(pluginManifest.name),
  `plugin.json name must be kebab-case and at most 64 characters: "${pluginManifest.name}"`,
);
check(
  typeof pluginManifest.description === 'string' && pluginManifest.description.trim().length > 0,
  'plugin.json description is required.',
);
check(
  packageManifest.name === pluginManifest.name,
  `package.json name (${packageManifest.name}) does not match plugin.json name (${pluginManifest.name}).`,
);
check(
  typeof pluginManifest.version === 'string' && semverPattern.test(pluginManifest.version),
  `plugin.json version must be bare SemVer: "${pluginManifest.version}"`,
);
check(
  packageManifest.version === pluginManifest.version,
  `package.json version (${packageManifest.version}) does not match plugin.json version (${pluginManifest.version}).`,
);
check(
  pluginManifest.extensions === manifestExtensionPath,
  `plugin.json extensions must be "${manifestExtensionPath}".`,
);
check(
  Array.isArray(pluginManifest.skills) && pluginManifest.skills.length === 0,
  'plugin.json skills must be empty so the unsupported-harness fallback is not auto-loaded.',
);

for (const filePath of packageFiles) {
  check(existsSync(filePath), `Missing installable plugin asset: ${filePath}`);
}

const compiledExtension = existsSync(extensionEntryPath)
  ? readFileSync(extensionEntryPath, 'utf8')
  : '';
const compiledClient = existsSync(clientEntryPath) ? readFileSync(clientEntryPath, 'utf8') : '';
const compiledGeneric = existsSync(genericEntryPath) ? readFileSync(genericEntryPath, 'utf8') : '';

check(
  compiledExtension.includes('joinSession'),
  'Compiled extension is missing the joinSession lifecycle.',
);
check(
  compiledClient.includes('connectInstalledService') &&
    compiledClient.includes('connectInstalledGenericService') &&
    compiledClient.includes('request.cancel') &&
    compiledClient.includes('createKonclaveTools'),
  'Compiled client bundle is missing the paved/generic connector, cancellation, or SDK tools.',
);
check(
  !compiledClient.includes('KonclaveLocalDaemon') && !compiledClient.includes('type: "stdio"'),
  'Compiled client bundle must not contain a per-session daemon path.',
);
check(
  !compiledClient.includes('console.log(') && !compiledClient.includes('process.stdout'),
  'Compiled client bundle must not write to stdout.',
);
check(
  compiledGeneric.includes('connectInstalledGenericService') &&
    compiledGeneric.includes('request.cancel') &&
    compiledGeneric.includes('account_trusted'),
  'Compiled generic client is missing the generic grant or cancellation path.',
);
check(
  !compiledGeneric.includes('KonclaveLocalDaemon') && !compiledGeneric.includes('type: "stdio"'),
  'Compiled generic client must not contain a per-session daemon path.',
);
check(
  compiledExtension.includes('delivery.claim'),
  'Compiled extension is missing shared-service automatic delivery.',
);
check(
  compiledExtension.includes('name: "konclave"'),
  'Compiled extension is missing deterministic Konclave commands.',
);
check(
  compiledExtension.includes('createKonclaveTools'),
  'Compiled extension is missing native SDK tool registration.',
);
check(
  !compiledExtension.includes('console.log('),
  'Compiled extension must not call console.log().',
);
check(
  !compiledExtension.includes('process.stdout'),
  'Compiled extension must not write to process.stdout.',
);
check(
  !compiledExtension.includes('KonclaveLocalDaemon'),
  'Compiled extension must not name or launch a per-session daemon.',
);
check(
  !compiledExtension.includes('type: "stdio"'),
  'Compiled extension must not declare a stdio MCP server.',
);

const skillText = existsSync(maintainerSkillPath) ? readFileSync(maintainerSkillPath, 'utf8') : '';
const genericSkillText = existsSync(genericSkillPath) ? readFileSync(genericSkillPath, 'utf8') : '';
check(
  skillText.includes('name: copilot-cli-extension-maintainer'),
  'The maintainer skill frontmatter name is missing or incorrect.',
);
check(
  skillText.includes('description:'),
  'The maintainer skill frontmatter description is missing.',
);
check(
  skillText.includes('schedulePromptSend'),
  'The maintainer skill should point contributors at schedulePromptSend().',
);
check(
  genericSkillText.includes('name: konclave-generic') &&
    genericSkillText.includes('AccountTrusted') &&
    genericSkillText.includes('generic.mjs'),
  'The generic skill must describe the packaged AccountTrusted fallback.',
);

const releaseTag = optionValue('--tag');
if (releaseTag !== null) {
  check(semverPattern.test(releaseTag), `Release tag must be bare SemVer: ${releaseTag}`);
  check(
    releaseTag === pluginManifest.version,
    `Release tag (${releaseTag}) does not match plugin.json version (${pluginManifest.version}).`,
  );
}

const archivePath = getArchivePath(pluginManifest);
check(existsSync(archivePath), `Packaged archive not found: ${archivePath}`);

if (errors.length === 0) {
  const firstArchiveHash = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  const archiveEntries = unzipSync(new Uint8Array(readFileSync(archivePath)));
  const entryNames = Object.keys(archiveEntries).sort();
  const expectedEntries = [...packageFiles].sort();

  check(
    JSON.stringify(entryNames) === JSON.stringify(expectedEntries),
    `Packaged archive must contain exactly: ${expectedEntries.join(', ')}`,
  );

  for (const filePath of expectedEntries) {
    const archivedFile = archiveEntries[filePath];
    if (!archivedFile) {
      continue;
    }

    const sourceBytes = readFileSync(filePath);
    check(
      Buffer.from(archivedFile).equals(sourceBytes),
      `Packaged archive entry does not match source asset: ${filePath}`,
    );
  }

  const repeatedPackage = spawnSync(process.execPath, ['scripts/package-plugin.mjs'], {
    encoding: 'utf8',
  });
  check(
    repeatedPackage.status === 0,
    `Repeated package creation failed: ${repeatedPackage.stderr.trim()}`,
  );
  if (repeatedPackage.status === 0) {
    const repeatedArchiveHash = createHash('sha256')
      .update(readFileSync(archivePath))
      .digest('hex');
    check(
      repeatedArchiveHash === firstArchiveHash,
      'Repeated package creation was not byte-identical.',
    );
  }
}

if (errors.length > 0) {
  console.error('Package verification failed:');
  for (const error of errors) {
    console.error(`  - ${error}`);
  }
  process.exit(1);
}

console.log(`Package verification passed: ${archivePath}`);
